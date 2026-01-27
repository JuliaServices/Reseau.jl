using Test
using AwsIO

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
