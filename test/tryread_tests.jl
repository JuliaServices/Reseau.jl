using Test, Reseau
isdefined(@__MODULE__, :_RESEAU_TLS_TEST_UTILS_LOADED) || include("tls_test_utils.jl")

function _tryread_tcp_pair()
    listener = NC.listen(NC.loopback_addr(0))
    task = @async NC.accept(listener)
    client = NC.connect(NC.loopback_addr(Int(NC.addr(listener).port)))
    server = fetch(task)
    close(listener)
    return client, server
end

# Encode with the live peer's keys and sequence number, but capture the wire
# bytes on a separate socket so the test can control each fragment's arrival.
function _tryread_record(peer, payload; content_type=TL._TLS_RECORD_TYPE_APPLICATION_DATA)
    sender, receiver = _tryread_tcp_pair()
    try
        state = peer.native_state
        if state isa TL._TLS13NativeClientState
            TL._tls13_write_record!(sender, state, content_type, payload)
        else
            TL._tls12_write_record!(sender, state, content_type, payload)
        end
        header = read(receiver, 5)
        return vcat(header, read(receiver, (Int(header[4]) << 8) | Int(header[5])))
    finally
        close(sender)
        close(receiver)
    end
end

@testset "TCP tryread!" begin
    client, server = _tryread_tcp_pair()
    try
        buf = fill(0xff, 8)
        @test NC.tryread!(client, buf) === nothing
        @test_throws ArgumentError NC.tryread!(client, UInt8[])
        @test_throws MethodError NC.tryread!(client, @view(buf[1:2:7]))
        write(server, UInt8[0x41, 0x42])
        @test !eof(client)
        @test NC.tryread!(client, @view(buf[2:3])) == 2
        @test buf == UInt8[0xff, 0x41, 0x42, 0xff, 0xff, 0xff, 0xff, 0xff]
        @test NC.tryread!(client, buf) === nothing
        NC.set_read_deadline!(client, 1)
        @test_throws IP.DeadlineExceededError NC.tryread!(client, buf)
        NC.set_read_deadline!(client, 0)
        locked = Channel{Nothing}(1)
        release = Base.Event()
        reader = @async begin
            IP._fd_read_lock!(client.fd.pfd)
            try
                put!(locked, nothing)
                wait(release)
            finally
                IP._fd_read_unlock!(client.fd.pfd)
            end
        end
        take!(locked)
        try
            @test NC.tryread!(client, buf) === nothing
        finally
            notify(release)
            wait(reader)
        end
        close(server)
        @test eof(client)
        @test NC.tryread!(client, buf) == 0
        close(client)
        @test NC.tryread!(client, buf) == 0
    finally
        close(client)
        close(server)
    end
end

@testset "TLS tryread! preserves partial records" begin
    for version in (TL.TLS1_2_VERSION, TL.TLS1_3_VERSION)
        listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(min_version=version, max_version=version))
        task = @async begin
            server = TL.accept(listener)
            TL.handshake!(server)
            server
        end
        client = TL.connect(NC.loopback_addr(Int(TL.addr(listener).port)),
                            TL.Config(verify_peer=false, server_name="localhost", min_version=version, max_version=version))
        server = fetch(task)
        try
            buf = fill(0xff, 8)
            @test TL.tryread!(client, buf) === nothing
            for completion in (:tryread, :read, :eof)
                payload = UInt8[0x41, 0x42, 0x43]
                wire = _tryread_record(server, payload)
                start = 1
                for stop in (1, 4, 5, length(wire)-1)
                    write(server.tcp, wire[start:stop])
                    @test !eof(client.tcp) # raw arrival only; never decrypts
                    @test TL.tryread!(client, buf) === nothing
                    @test client.native_state.record_received == stop
                    if stop == 4
                        TL.set_read_deadline!(client, 1)
                        @test_throws TL.TLSError TL.tryread!(client, buf)
                        @test client.native_state.record_received == stop
                        TL.set_read_deadline!(client, 0)
                    end
                    @test all(==(0xff), buf)
                    start = stop + 1
                end
                write(server.tcp, wire[start:end])
                @test !eof(client.tcp)
                if completion == :tryread
                    @test TL.tryread!(client, @view(buf[2:3])) == 2
                    @test buf[2:3] == payload[1:2]
                    @test read(client, UInt8) == payload[3]
                else
                    completion == :eof && @test !eof(client)
                    @test read(client, 3) == payload
                end
                @test TL.tryread!(client, buf) === nothing
                fill!(buf, 0xff)
            end
            if version == TL.TLS1_3_VERSION
                wire = _tryread_record(server, TL._tls13_key_update_message(true); content_type=TL._TLS_RECORD_TYPE_HANDSHAKE)
                TL._tls13_advance_write_cipher!(server.native_state)
                locked = Channel{Nothing}(1)
                release = Base.Event()
                writer = @async lock(client.write_lock) do
                    put!(locked, nothing)
                    wait(release)
                end
                take!(locked)
                try
                    write(server.tcp, wire)
                    @test !eof(client.tcp)
                    @test TL.tryread!(client, buf) === nothing
                    @test (@atomic client.native_state.key_update_pending)
                    @test NC.tryread!(server.tcp, buf) === nothing
                finally
                    notify(release)
                    wait(writer)
                end
                write(server, UInt8[0x55])
                @test !eof(client.tcp)
                @test TL.tryread!(client, buf) == 1
                @test buf[1] == 0x55
                write(client, UInt8[0x66]) # flushes KeyUpdate before application output
                @test read(server, UInt8) == 0x66
                @test !(@atomic client.native_state.key_update_pending)
                # Expired session tickets carry no plaintext. The attempt
                # must stop after its record budget, even with data queued.
                ticket = TL._marshal_new_session_ticket_tls13(TL._NewSessionTicketMsgTLS13())
                records = reduce(vcat, [_tryread_record(server, ticket; content_type=TL._TLS_RECORD_TYPE_HANDSHAKE) for _ in 1:16])
                append!(records, _tryread_record(server, UInt8[0x77]))
                write(server.tcp, records)
                @test !eof(client.tcp)
                @test TL.tryread!(client, buf) === nothing
                @test read(client, UInt8) == 0x77
            end
            # Partial-record EOF is an error, not a clean end of stream.
            write(server.tcp, UInt8[0x17])
            @test !eof(client.tcp)
            @test TL.tryread!(client, buf) === nothing
            close(server.tcp)
            @test eof(client.tcp)
            @test_throws TL.TLSError TL.tryread!(client, buf)
        finally
            _tls_close_quiet!(client)
            _tls_close_quiet!(server)
            _tls_close_quiet!(listener)
        end
    end
end
