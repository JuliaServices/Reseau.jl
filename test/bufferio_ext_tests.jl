# Tests for the ReseauBufferIOExt package extension.
#
# BufferIO.jl requires Julia >= 1.11 while Reseau supports 1.10, so BufferIO
# cannot be a regular test-target dependency: on 1.10 the test environment
# would fail to resolve. Instead it is added to the ephemeral test environment
# here, and this whole file no-ops on older Julia versions.

if VERSION >= v"1.11"
    import Pkg
    _log_test_progress("[bufferio_ext] installing BufferIO into the test environment")
    Pkg.add(
        [
            Pkg.PackageSpec(name = "BufferIO", version = "0.2.5"),
            Pkg.PackageSpec(name = "MemoryViews"),
        ];
        preserve = Pkg.PRESERVE_ALL,
    )
    _log_test_progress("[bufferio_ext] BufferIO installed")

    using BufferIO: BufferIO,
        AbstractBufReader,
        AbstractBufWriter,
        IOError,
        IOErrorKinds,
        get_buffer,
        fill_buffer,
        get_nonempty_buffer,
        consume,
        shallow_flush,
        get_unflushed,
        line_views
    using MemoryViews: MemoryView, ImmutableMemoryView, MutableMemoryView

    @test Base.get_extension(Reseau, :ReseauBufferIOExt) isa Module

    function _bufio_pair()
        listener = TCP.listen(TCP.loopback_addr(0))
        client = TCP.connect(TCP.addr(listener))
        server = TCP.accept(listener)
        close(listener)
        return client, server
    end

    # Read exactly `n` bytes from `conn` through repeated short view reads.
    function _bufio_read_exact_via_views(conn::TCP.Conn, n::Int)::Vector{UInt8}
        out = zeros(UInt8, n)
        view = MemoryView(out)
        filled = 0
        while filled < n
            got = readbytes!(conn, view[(filled + 1):n])
            @assert got > 0
            filled += got
        end
        return out
    end

    @testset "bridge readbytes! short-read default" begin
        client, server = _bufio_pair()
        write(server, "hello")
        # The default all=false contract: each call returns as soon as at
        # least one byte is available. Termination of this loop without the
        # server writing more than 5 bytes (or closing) is the proof; an
        # all=true default would park forever waiting to fill 64 bytes.
        buf = zeros(UInt8, 64)
        view = MemoryView(buf)
        filled = 0
        while filled < 5
            n = readbytes!(client, view[(filled + 1):64])
            @test n >= 1
            filled += n
        end
        @test buf[1:5] == b"hello"
        close(client)
        close(server)
    end

    @testset "bridge readbytes! all=true and nb clamp" begin
        client, server = _bufio_pair()
        write(server, "abc")
        write(server, "defgh")
        buf = zeros(UInt8, 8)
        n = readbytes!(client, MemoryView(buf), 8; all = true)
        @test n == 8
        @test buf == b"abcdefgh"
        # nb larger than the view is clamped to the view length.
        write(server, "xy")
        small = zeros(UInt8, 2)
        n = readbytes!(client, MemoryView(small), 100; all = true)
        @test n == 2
        @test small == b"xy"
        @test_throws ArgumentError readbytes!(client, MemoryView(small), -1)
        # EOF drains to a zero count.
        closewrite(server)
        @test readbytes!(client, MemoryView(buf)) == 0
        close(client)
        close(server)
    end

    @testset "bridge write of memory views" begin
        client, server = _bufio_pair()
        data = collect(b"view-payload")
        @test write(client, ImmutableMemoryView(data)) == length(data)
        @test write(client, MemoryView(data)) == length(data)
        @test write(client, ImmutableMemoryView(UInt8[])) == 0
        received = _bufio_read_exact_via_views(server, 2 * length(data))
        @test received == vcat(data, data)
        close(client)
        close(server)
    end

    @testset "stock BufferIO.BufReader over Conn" begin
        client, server = _bufio_pair()
        write(server, "line one\nline two\r\nrest")
        closewrite(server)
        # Tiny buffer forces refills and buffer growth across line boundaries.
        reader = BufferIO.BufReader(client, 4)
        @test readline(reader) == "line one"
        @test readline(reader) == "line two"
        @test readline(reader) == "rest"
        @test eof(reader)
        @test readline(reader) == ""
        close(reader)
        @test !isopen(client)
        close(server)
    end

    @testset "stock BufferIO.BufWriter over Conn" begin
        client, server = _bufio_pair()
        writer = BufferIO.BufWriter(client, 8)
        write(writer, "hi")
        @test length(get_unflushed(writer)) == 2
        flush(writer)
        @test isempty(get_unflushed(writer))
        @test _bufio_read_exact_via_views(server, 2) == b"hi"
        close(writer)
        @test !isopen(client)
        close(server)
    end

    @testset "native bufreader: interface contract" begin
        client, server = _bufio_pair()
        reader = TCP.bufreader(client; buffer_size = 8)
        @test reader isa AbstractBufReader
        @test isempty(get_buffer(reader))
        @test bytesavailable(reader) == 0
        write(server, "abcde")
        n = fill_buffer(reader)
        @test n >= 1
        first_buffer = get_buffer(reader)
        @test !isempty(first_buffer)
        @test first_buffer[1] == UInt8('a')
        # consume past the buffered window is a checked error.
        err = try
            consume(reader, 100)
            nothing
        catch e
            e
        end
        @test err isa IOError
        @test err.kind == IOErrorKinds.ConsumeBufferError
        # Byte-by-byte read of the exact payload through BufferIO generics.
        bytes = UInt8[]
        for _ in 1:5
            push!(bytes, read(reader, UInt8))
        end
        @test bytes == b"abcde"
        # EOF: half-close surfaces as fill_buffer() == 0, then IOError(EOF).
        closewrite(server)
        @test fill_buffer(reader) == 0
        @test get_nonempty_buffer(reader) === nothing
        @test eof(reader)
        err = try
            read(reader, UInt8)
            nothing
        catch e
            e
        end
        @test err isa IOError
        @test err.kind == IOErrorKinds.EOF
        close(reader)
        @test !isopen(client)
        close(server)
    end

    @testset "native bufreader: growth, readline, line_views" begin
        client, server = _bufio_pair()
        long_line = "x"^100
        write(server, long_line * "\nshort\r\ntail")
        closewrite(server)
        reader = TCP.bufreader(client; buffer_size = 8)
        @test readline(reader) == long_line
        @test [String(line) for line in line_views(reader)] == ["short", "tail"]
        close(reader)
        close(server)
    end

    @testset "native bufreader: fill slide and grow paths" begin
        client, server = _bufio_pair()
        reader = TCP.bufreader(client; buffer_size = 8)
        # Fill the 8-byte buffer exactly full.
        write(server, "01234567")
        while bytesavailable(reader) < 8
            @test fill_buffer(reader) >= 1
        end
        # Consume a prefix, then force a fill with the window at the buffer
        # end: exercises the slide-to-front branch.
        consume(reader, 3)
        write(server, "abc")
        while bytesavailable(reader) < 8
            @test fill_buffer(reader) >= 1
        end
        @test String([read(reader, UInt8) for _ in 1:8]) == "34567abc"
        # Unconsumed full-from-start buffer: exercises the grow branch.
        write(server, "ABCDEFGHIJKL")
        while bytesavailable(reader) < 12
            @test fill_buffer(reader) >= 1
        end
        @test String([read(reader, UInt8) for _ in 1:12]) == "ABCDEFGHIJKL"
        close(reader)
        close(server)
    end

    @testset "native bufreader: deadline and close errors" begin
        client, server = _bufio_pair()
        reader = TCP.bufreader(client)
        # House sentinel: an already-expired absolute deadline.
        TCP.set_read_deadline!(client, Int64(1))
        @test_throws TCP.DeadlineExceededError readline(reader)
        TCP.set_read_deadline!(client, 0)
        close(client)
        @test_throws Reseau.IOPoll.NetClosingError readline(reader)
        close(server)
    end

    @testset "native bufwriter" begin
        client, server = _bufio_pair()
        writer = TCP.bufwriter(client; buffer_size = 8)
        @test writer isa AbstractBufWriter
        write(writer, "hi")
        @test get_unflushed(writer) == b"hi"
        @test shallow_flush(writer) == 2
        @test _bufio_read_exact_via_views(server, 2) == b"hi"
        # Larger than the buffer: BufferIO's generic write path flushes and
        # refills as needed; close flushes the remainder and closes the conn.
        payload = "0123456789abcdefghij"
        write(writer, payload)
        # An unsigned integer written through the generic PlainTypes path.
        write(writer, 0x11223344)
        close(writer)
        @test !isopen(client)
        received = read(server)
        @test received[1:length(payload)] == codeunits(payload)
        @test reinterpret(UInt32, received[(length(payload) + 1):end])[1] == 0x11223344
        err = try
            shallow_flush(writer)
            nothing
        catch e
            e
        end
        @test err isa IOError
        @test err.kind == IOErrorKinds.ClosedIO
        close(server)
    end
else
    _log_test_progress("[bufferio_ext] skipped: BufferIO requires Julia >= 1.11 (running $(VERSION))")
end
