using Test
using Reseau

function collect_stream_bytes(stream, read_buf_size::Integer)
    read_buf = Reseau.ByteBuffer(read_buf_size)
    result = UInt8[]
    status = Reseau.StreamStatus.OK

    while status != Reseau.StreamStatus.END_OF_STREAM
        read_buf.len = 0
        read_result = Reseau.stream_read(stream, read_buf, read_buf_size)
        @test !(read_result isa Reseau.ErrorResult)
        bytes, status = read_result
        if bytes > 0
            append!(result, read_buf.mem[1:Int(read_buf.len)])
        end
    end

    return result
end

function assert_stream_contents(stream, expected::Vector{UInt8}, read_buf_size::Integer)
    result = collect_stream_bytes(stream, read_buf_size)
    @test result == expected
    return nothing
end

@testset "ByteBufferInputStream" begin
    data = Vector{UInt8}("hello")
    stream = Reseau.ByteBufferInputStream(data; owns_buffer = false)

    @test Reseau.stream_is_seekable(stream)
    @test Reseau.stream_has_known_length(stream)
    @test Reseau.stream_get_length(stream) == 5
    @test Reseau.stream_get_position(stream) == 0

    buf = Reseau.ByteBuffer(2)
    bytes, status = Reseau.stream_read(stream, buf, 2)
    @test bytes == 2
    @test status == Reseau.StreamStatus.OK
    @test Reseau.stream_get_position(stream) == 2
    @test String(Reseau.byte_cursor_from_buf(buf)) == "he"

    buf2 = Reseau.ByteBuffer(10)
    bytes2, status2 = Reseau.stream_read(stream, buf2, 10)
    @test bytes2 == 3
    @test status2 == Reseau.StreamStatus.END_OF_STREAM
    @test String(Reseau.byte_cursor_from_buf(buf2)) == "llo"

    @test Reseau.stream_reset(stream) === nothing
    @test Reseau.stream_get_position(stream) == 0

    all_buf = Reseau.stream_read_all(stream)
    @test all_buf isa Reseau.ByteBuffer
    @test String(Reseau.byte_cursor_from_buf(all_buf)) == "hello"
end

@testset "CursorInputStream" begin
    cursor = Reseau.ByteCursor("world")
    stream = Reseau.CursorInputStream(cursor)

    @test Reseau.stream_is_seekable(stream)
    @test Reseau.stream_has_known_length(stream)
    @test Reseau.stream_get_length(stream) == 5
    @test Reseau.stream_get_position(stream) == 0

    buf = Reseau.ByteBuffer(3)
    bytes, status = Reseau.stream_read(stream, buf, 3)
    @test bytes == 3
    @test status == Reseau.StreamStatus.OK
    @test String(Reseau.byte_cursor_from_buf(buf)) == "wor"

    @test Reseau.stream_seek(stream, -1, Reseau.StreamSeekBasis.END) === nothing
    @test Reseau.stream_get_position(stream) == 4

    buf2 = Reseau.ByteBuffer(2)
    bytes2, status2 = Reseau.stream_read(stream, buf2, 2)
    @test bytes2 == 1
    @test status2 == Reseau.StreamStatus.END_OF_STREAM
    @test String(Reseau.byte_cursor_from_buf(buf2)) == "d"
end

@testset "FileInputStream" begin
    mktemp() do path, io
        write(io, "filedata")
        close(io)

        stream = Reseau.FileInputStream(path)
        @test stream isa Reseau.FileInputStream
        stream isa Reseau.ErrorResult && return

        @test Reseau.stream_is_seekable(stream)
        @test Reseau.stream_has_known_length(stream)
        @test Reseau.stream_get_length(stream) == 8
        @test Reseau.stream_get_position(stream) == 0

        buf = Reseau.ByteBuffer(4)
        bytes, status = Reseau.stream_read(stream, buf, 4)
        @test bytes == 4
        @test status == Reseau.StreamStatus.OK
        @test String(Reseau.byte_cursor_from_buf(buf)) == "file"

        @test Reseau.stream_seek(stream, 0, Reseau.StreamSeekBasis.END) === nothing
        @test Reseau.stream_get_position(stream) == 8

        buf2 = Reseau.ByteBuffer(4)
        bytes2, status2 = Reseau.stream_read(stream, buf2, 4)
        @test bytes2 == 0
        @test status2 == Reseau.StreamStatus.END_OF_STREAM

        Reseau.stream_destroy!(stream)
    end
end

@testset "InputStream constructors" begin
    mktemp() do path, io
        write(io, "openfile")
        flush(io)
        seek(io, 0)

        stream = Reseau.input_stream_new_from_file(path)
        @test stream isa Reseau.FileInputStream
        Reseau.stream_destroy!(stream)

        file = Libc.FILE(io)
        stream2 = Reseau.input_stream_new_from_open_file(file)
        buf = Reseau.ByteBuffer(16)
        bytes, status = Reseau.stream_read(stream2, buf, 16)
        @test status == Reseau.StreamStatus.OK || status == Reseau.StreamStatus.END_OF_STREAM
        @test bytes == 8
        @test String(Reseau.byte_cursor_from_buf(buf)) == "openfile"
        Reseau.stream_destroy!(stream2)
        close(file)
    end
end

@testset "Stream copy" begin
    data = Vector{UInt8}("copyme")
    stream = Reseau.ByteBufferInputStream(data; owns_buffer = false)
    dest = Reseau.ByteBuffer(16)

    copied = Reseau.stream_copy(stream, dest)
    @test copied == 6
    @test String(Reseau.byte_cursor_from_buf(dest)) == "copyme"
end

@testset "stream read/seek scenarios" begin
    test_data = Vector{UInt8}("SimpleTest")

    @testset "memory simple/iterate" begin
        stream = Reseau.CursorInputStream(Reseau.ByteCursor(test_data))
        status = Reseau.stream_get_status(stream)
        @test status.is_valid
        @test !status.is_end_of_stream
        assert_stream_contents(stream, test_data, 100)
        status = Reseau.stream_get_status(stream)
        @test status.is_valid
        @test status.is_end_of_stream
        Reseau.stream_reset(stream)
        status = Reseau.stream_get_status(stream)
        @test status.is_valid
        @test !status.is_end_of_stream
        assert_stream_contents(stream, test_data, 2)
    end

    @testset "file simple/iterate" begin
        mktemp() do path, io
            write(io, test_data)
            close(io)
            stream = Reseau.FileInputStream(path)
            @test !(stream isa Reseau.ErrorResult)
            status = Reseau.stream_get_status(stream)
            @test status.is_valid
            @test !status.is_end_of_stream
            assert_stream_contents(stream, test_data, 100)
            status = Reseau.stream_get_status(stream)
            @test status.is_valid
            @test status.is_end_of_stream
            Reseau.stream_reset(stream)
            status = Reseau.stream_get_status(stream)
            @test status.is_valid
            @test !status.is_end_of_stream
            assert_stream_contents(stream, test_data, 2)
            Reseau.stream_destroy!(stream)
        end
    end

    @testset "seek beginning/end" begin
        stream = Reseau.CursorInputStream(Reseau.ByteCursor(test_data))
        seek_offset = 5
        expected = test_data[seek_offset + 1:end]
        @test Reseau.stream_seek(stream, seek_offset, Reseau.StreamSeekBasis.BEGIN) === nothing
        read_buf = Reseau.ByteBuffer(1024)
        bytes, status = Reseau.stream_read(stream, read_buf, 1024)
        @test status == Reseau.StreamStatus.END_OF_STREAM
        @test bytes == length(expected)
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == String(expected)

        end_offset = -3
        expected = test_data[end + end_offset + 1:end]
        @test Reseau.stream_seek(stream, end_offset, Reseau.StreamSeekBasis.END) === nothing
        read_buf = Reseau.ByteBuffer(1024)
        bytes, status = Reseau.stream_read(stream, read_buf, 1024)
        @test status == Reseau.StreamStatus.END_OF_STREAM
        @test bytes == length(expected)
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == String(expected)
    end

    @testset "seek multiple times" begin
        src = Vector{UInt8}("0123456789")
        stream = Reseau.CursorInputStream(Reseau.ByteCursor(src))
        read_buf = Reseau.ByteBuffer(1)

        @test Reseau.stream_seek(stream, 2, Reseau.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = Reseau.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == "2"

        @test Reseau.stream_seek(stream, 4, Reseau.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = Reseau.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == "4"

        @test Reseau.stream_seek(stream, -1, Reseau.StreamSeekBasis.END) === nothing
        read_buf.len = 0
        bytes, _ = Reseau.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == "9"

        @test Reseau.stream_seek(stream, -1, Reseau.StreamSeekBasis.END) === nothing
        read_buf.len = 0
        bytes, _ = Reseau.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == "9"

        @test Reseau.stream_seek(stream, 4, Reseau.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = Reseau.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(Reseau.byte_cursor_from_buf(read_buf)) == "4"
    end

    @testset "seek invalid positions" begin
        stream = Reseau.CursorInputStream(Reseau.ByteCursor(test_data))
        result = Reseau.stream_seek(stream, 13, Reseau.StreamSeekBasis.BEGIN)
        @test result isa Reseau.ErrorResult
        @test result.code == Reseau.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = Reseau.stream_seek(stream, 1, Reseau.StreamSeekBasis.END)
        @test result isa Reseau.ErrorResult
        @test result.code == Reseau.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = Reseau.stream_seek(stream, -13, Reseau.StreamSeekBasis.END)
        @test result isa Reseau.ErrorResult
        @test result.code == Reseau.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = Reseau.stream_seek(stream, -1, Reseau.StreamSeekBasis.BEGIN)
        @test result isa Reseau.ErrorResult
        @test result.code == Reseau.ERROR_IO_STREAM_INVALID_SEEK_POSITION
    end

    @testset "stream length invariant under seek" begin
        stream = Reseau.CursorInputStream(Reseau.ByteCursor(test_data))
        len = Reseau.stream_get_length(stream)
        @test len == length(test_data)
        @test Reseau.stream_seek(stream, 3, Reseau.StreamSeekBasis.BEGIN) === nothing
        @test Reseau.stream_get_length(stream) == length(test_data)

        mktemp() do path, io
            write(io, test_data)
            close(io)
            fstream = Reseau.FileInputStream(path)
            @test !(fstream isa Reseau.ErrorResult)
            @test Reseau.stream_get_length(fstream) == length(test_data)
            @test Reseau.stream_seek(fstream, 3, Reseau.StreamSeekBasis.BEGIN) === nothing
            @test Reseau.stream_get_length(fstream) == length(test_data)
            Reseau.stream_destroy!(fstream)
        end
    end

    @testset "binary file stream" begin
        binary = UInt8['a', 'b', 'c', 'd', 'e', 'f', 0x1a, 'g', 'h', 'i', 'j', 'k']
        mktemp() do path, io
            write(io, binary)
            close(io)
            stream = Reseau.FileInputStream(path)
            @test !(stream isa Reseau.ErrorResult)
            assert_stream_contents(stream, binary, 100)
            Reseau.stream_destroy!(stream)
        end
    end

    @testset "read-only file stream" begin
        mktemp() do path, io
            write(io, test_data)
            close(io)
            @static if Sys.isunix()
                chmod(path, 0o444)
            end
            stream = Reseau.FileInputStream(path)
            @test !(stream isa Reseau.ErrorResult)
            assert_stream_contents(stream, test_data, 100)
            Reseau.stream_destroy!(stream)
        end
    end
end
