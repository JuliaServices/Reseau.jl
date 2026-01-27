using Test
using AwsIO

@testset "Common containers" begin
    @testset "ArrayList" begin
        list = AwsIO.ArrayList{Int}(2)
        @test AwsIO.push_back!(list, 1) == AwsIO.OP_SUCCESS
        @test AwsIO.push_back!(list, 2) == AwsIO.OP_SUCCESS
        @test length(list) == 2
        @test list[1] == 1
        @test list[2] == 2
        @test AwsIO.pop_back!(list) == 2
        @test AwsIO.pop_front!(list) == 1
        @test isempty(list)
    end

    @testset "Deque" begin
        dq = AwsIO.Deque{Int}(2)
        AwsIO.push_back!(dq, 1)
        AwsIO.push_back!(dq, 2)
        AwsIO.push_front!(dq, 0)
        @test length(dq) == 3
        @test AwsIO.pop_front!(dq) == 0
        @test AwsIO.pop_back!(dq) == 2
        @test AwsIO.pop_back!(dq) == 1
        @test isempty(dq)
    end

    @testset "PriorityQueue" begin
        pq = AwsIO.PriorityQueue{Int}((a, b) -> a < b; capacity = 2)
        push!(pq, 3)
        push!(pq, 1)
        push!(pq, 2)
        @test AwsIO.peek(pq) == 1
        @test pop!(pq) == 1
        @test pop!(pq) == 2
        @test pop!(pq) == 3
        @test isempty(pq)
    end

    @testset "HashTable" begin
        ht = AwsIO.HashTable{Int, String}((x) -> x, (a, b) -> a == b; capacity = 4)
        @test AwsIO.hash_table_put!(ht, 1, "one") == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_put!(ht, 2, "two") == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_get(ht, 1) == "one"
        @test AwsIO.hash_table_get(ht, 3) === nothing
        @test AwsIO.hash_table_remove!(ht, 2) == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_get(ht, 2) === nothing
        AwsIO.hash_table_clear!(ht)
        @test length(ht) == 0
    end
end

@testset "Byte buffers" begin
    buf_ref = Ref(AwsIO.ByteBuffer(8))
    cur = AwsIO.ByteCursor("hi")
    @test AwsIO.byte_buf_write_from_whole_cursor(buf_ref, cur) == true
    @test buf_ref[].len == 2
    @test String(unsafe_wrap(Vector{UInt8}, pointer(buf_ref[].mem), Int(buf_ref[].len); own = false)) == "hi"
end

@testset "Error handling" begin
    AwsIO._common_init()
    AwsIO.raise_error(AwsIO.ERROR_INVALID_ARGUMENT)
    @test AwsIO.last_error() == AwsIO.ERROR_INVALID_ARGUMENT
end

@testset "UUID" begin
    u = Ref{AwsIO.uuid}()
    @test AwsIO.uuid_init(u) == AwsIO.OP_SUCCESS
    out = Ref(AwsIO.ByteBuffer(AwsIO.UUID_STR_LEN))
    @test AwsIO.uuid_to_str(u, out) == AwsIO.OP_SUCCESS
    @test out[].len == AwsIO.UUID_STR_LEN - 1
end

@testset "byte buffer init from file" begin
    mktemp() do path, io
        write(io, "filedata")
        close(io)

        buf_ref = Ref{AwsIO.ByteBuffer}()
        @test AwsIO.byte_buf_init_from_file(buf_ref, path) == AwsIO.AWS_OP_SUCCESS
        buf = buf_ref[]
        @test buf.len == 8
        @test String(AwsIO.byte_cursor_from_buf(buf)) == "filedata"
        @test buf.mem[Int(buf.len) + 1] == 0x00
    end
end
