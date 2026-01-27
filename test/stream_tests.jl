using Test
using AwsIO

function collect_stream_bytes(stream, read_buf_size::Integer)
    read_buf = AwsIO.ByteBuffer(read_buf_size)
    result = UInt8[]
    status = AwsIO.StreamStatus.OK

    while status != AwsIO.StreamStatus.END_OF_STREAM
        read_buf.len = 0
        read_result = AwsIO.stream_read(stream, read_buf, read_buf_size)
        @test !(read_result isa AwsIO.ErrorResult)
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
    stream = AwsIO.ByteBufferInputStream(data; owns_buffer = false)

    @test AwsIO.stream_is_seekable(stream)
    @test AwsIO.stream_has_known_length(stream)
    @test AwsIO.stream_get_length(stream) == 5
    @test AwsIO.stream_get_position(stream) == 0

    buf = AwsIO.ByteBuffer(2)
    bytes, status = AwsIO.stream_read(stream, buf, 2)
    @test bytes == 2
    @test status == AwsIO.StreamStatus.OK
    @test AwsIO.stream_get_position(stream) == 2
    @test String(AwsIO.byte_cursor_from_buf(buf)) == "he"

    buf2 = AwsIO.ByteBuffer(10)
    bytes2, status2 = AwsIO.stream_read(stream, buf2, 10)
    @test bytes2 == 3
    @test status2 == AwsIO.StreamStatus.END_OF_STREAM
    @test String(AwsIO.byte_cursor_from_buf(buf2)) == "llo"

    @test AwsIO.stream_reset(stream) === nothing
    @test AwsIO.stream_get_position(stream) == 0

    all_buf = AwsIO.stream_read_all(stream)
    @test all_buf isa AwsIO.ByteBuffer
    @test String(AwsIO.byte_cursor_from_buf(all_buf)) == "hello"
end

@testset "CursorInputStream" begin
    cursor = AwsIO.ByteCursor("world")
    stream = AwsIO.CursorInputStream(cursor)

    @test AwsIO.stream_is_seekable(stream)
    @test AwsIO.stream_has_known_length(stream)
    @test AwsIO.stream_get_length(stream) == 5
    @test AwsIO.stream_get_position(stream) == 0

    buf = AwsIO.ByteBuffer(3)
    bytes, status = AwsIO.stream_read(stream, buf, 3)
    @test bytes == 3
    @test status == AwsIO.StreamStatus.OK
    @test String(AwsIO.byte_cursor_from_buf(buf)) == "wor"

    @test AwsIO.stream_seek(stream, -1, AwsIO.StreamSeekBasis.END) === nothing
    @test AwsIO.stream_get_position(stream) == 4

    buf2 = AwsIO.ByteBuffer(2)
    bytes2, status2 = AwsIO.stream_read(stream, buf2, 2)
    @test bytes2 == 1
    @test status2 == AwsIO.StreamStatus.END_OF_STREAM
    @test String(AwsIO.byte_cursor_from_buf(buf2)) == "d"
end

@testset "FileInputStream" begin
    mktemp() do path, io
        write(io, "filedata")
        close(io)

        stream = AwsIO.FileInputStream(path)
        @test stream isa AwsIO.FileInputStream
        stream isa AwsIO.ErrorResult && return

        @test AwsIO.stream_is_seekable(stream)
        @test AwsIO.stream_has_known_length(stream)
        @test AwsIO.stream_get_length(stream) == 8
        @test AwsIO.stream_get_position(stream) == 0

        buf = AwsIO.ByteBuffer(4)
        bytes, status = AwsIO.stream_read(stream, buf, 4)
        @test bytes == 4
        @test status == AwsIO.StreamStatus.OK
        @test String(AwsIO.byte_cursor_from_buf(buf)) == "file"

        @test AwsIO.stream_seek(stream, 0, AwsIO.StreamSeekBasis.END) === nothing
        @test AwsIO.stream_get_position(stream) == 8

        buf2 = AwsIO.ByteBuffer(4)
        bytes2, status2 = AwsIO.stream_read(stream, buf2, 4)
        @test bytes2 == 0
        @test status2 == AwsIO.StreamStatus.END_OF_STREAM

        AwsIO.stream_destroy!(stream)
    end
end

@testset "Stream copy" begin
    data = Vector{UInt8}("copyme")
    stream = AwsIO.ByteBufferInputStream(data; owns_buffer = false)
    dest = AwsIO.ByteBuffer(16)

    copied = AwsIO.stream_copy(stream, dest)
    @test copied == 6
    @test String(AwsIO.byte_cursor_from_buf(dest)) == "copyme"
end

@testset "stream read/seek scenarios" begin
    test_data = Vector{UInt8}("SimpleTest")

    @testset "memory simple/iterate" begin
        stream = AwsIO.CursorInputStream(AwsIO.ByteCursor(test_data))
        assert_stream_contents(stream, test_data, 100)
        AwsIO.stream_reset(stream)
        assert_stream_contents(stream, test_data, 2)
    end

    @testset "file simple/iterate" begin
        mktemp() do path, io
            write(io, test_data)
            close(io)
            stream = AwsIO.FileInputStream(path)
            @test !(stream isa AwsIO.ErrorResult)
            assert_stream_contents(stream, test_data, 100)
            AwsIO.stream_reset(stream)
            assert_stream_contents(stream, test_data, 2)
            AwsIO.stream_destroy!(stream)
        end
    end

    @testset "seek beginning/end" begin
        stream = AwsIO.CursorInputStream(AwsIO.ByteCursor(test_data))
        seek_offset = 5
        expected = test_data[seek_offset + 1:end]
        @test AwsIO.stream_seek(stream, seek_offset, AwsIO.StreamSeekBasis.BEGIN) === nothing
        read_buf = AwsIO.ByteBuffer(1024)
        bytes, status = AwsIO.stream_read(stream, read_buf, 1024)
        @test status == AwsIO.StreamStatus.END_OF_STREAM
        @test bytes == length(expected)
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == String(expected)

        end_offset = -3
        expected = test_data[end + end_offset + 1:end]
        @test AwsIO.stream_seek(stream, end_offset, AwsIO.StreamSeekBasis.END) === nothing
        read_buf = AwsIO.ByteBuffer(1024)
        bytes, status = AwsIO.stream_read(stream, read_buf, 1024)
        @test status == AwsIO.StreamStatus.END_OF_STREAM
        @test bytes == length(expected)
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == String(expected)
    end

    @testset "seek multiple times" begin
        src = Vector{UInt8}("0123456789")
        stream = AwsIO.CursorInputStream(AwsIO.ByteCursor(src))
        read_buf = AwsIO.ByteBuffer(1)

        @test AwsIO.stream_seek(stream, 2, AwsIO.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = AwsIO.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == "2"

        @test AwsIO.stream_seek(stream, 4, AwsIO.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = AwsIO.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == "4"

        @test AwsIO.stream_seek(stream, -1, AwsIO.StreamSeekBasis.END) === nothing
        read_buf.len = 0
        bytes, _ = AwsIO.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == "9"

        @test AwsIO.stream_seek(stream, -1, AwsIO.StreamSeekBasis.END) === nothing
        read_buf.len = 0
        bytes, _ = AwsIO.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == "9"

        @test AwsIO.stream_seek(stream, 4, AwsIO.StreamSeekBasis.BEGIN) === nothing
        read_buf.len = 0
        bytes, _ = AwsIO.stream_read(stream, read_buf, 1)
        @test bytes == 1
        @test String(AwsIO.byte_cursor_from_buf(read_buf)) == "4"
    end

    @testset "seek invalid positions" begin
        stream = AwsIO.CursorInputStream(AwsIO.ByteCursor(test_data))
        result = AwsIO.stream_seek(stream, 13, AwsIO.StreamSeekBasis.BEGIN)
        @test result isa AwsIO.ErrorResult
        @test result.code == AwsIO.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = AwsIO.stream_seek(stream, 1, AwsIO.StreamSeekBasis.END)
        @test result isa AwsIO.ErrorResult
        @test result.code == AwsIO.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = AwsIO.stream_seek(stream, -13, AwsIO.StreamSeekBasis.END)
        @test result isa AwsIO.ErrorResult
        @test result.code == AwsIO.ERROR_IO_STREAM_INVALID_SEEK_POSITION

        result = AwsIO.stream_seek(stream, -1, AwsIO.StreamSeekBasis.BEGIN)
        @test result isa AwsIO.ErrorResult
        @test result.code == AwsIO.ERROR_IO_STREAM_INVALID_SEEK_POSITION
    end

    @testset "stream length invariant under seek" begin
        stream = AwsIO.CursorInputStream(AwsIO.ByteCursor(test_data))
        len = AwsIO.stream_get_length(stream)
        @test len == length(test_data)
        @test AwsIO.stream_seek(stream, 3, AwsIO.StreamSeekBasis.BEGIN) === nothing
        @test AwsIO.stream_get_length(stream) == length(test_data)

        mktemp() do path, io
            write(io, test_data)
            close(io)
            fstream = AwsIO.FileInputStream(path)
            @test !(fstream isa AwsIO.ErrorResult)
            @test AwsIO.stream_get_length(fstream) == length(test_data)
            @test AwsIO.stream_seek(fstream, 3, AwsIO.StreamSeekBasis.BEGIN) === nothing
            @test AwsIO.stream_get_length(fstream) == length(test_data)
            AwsIO.stream_destroy!(fstream)
        end
    end

    @testset "binary file stream" begin
        binary = UInt8['a', 'b', 'c', 'd', 'e', 'f', 0x1a, 'g', 'h', 'i', 'j', 'k']
        mktemp() do path, io
            write(io, binary)
            close(io)
            stream = AwsIO.FileInputStream(path)
            @test !(stream isa AwsIO.ErrorResult)
            assert_stream_contents(stream, binary, 100)
            AwsIO.stream_destroy!(stream)
        end
    end

    @testset "read-only file stream" begin
        mktemp() do path, io
            write(io, test_data)
            close(io)
            @static if Sys.isunix()
                chmod(path, 0o444)
            end
            stream = AwsIO.FileInputStream(path)
            @test !(stream isa AwsIO.ErrorResult)
            assert_stream_contents(stream, test_data, 100)
            AwsIO.stream_destroy!(stream)
        end
    end
end
