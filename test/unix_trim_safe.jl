using Reseau

const U = Reseau.Unix
const IP = Reseau.IOPoll

@static if Sys.islinux() || Sys.isapple() || Sys.isfreebsd()
    include("unix_helpers.jl")

    const _UNIX_TRIM_CLIENT = Ref{Union{Nothing, U.Conn}}(nothing)

    function _unix_trim_deadline_read()::Cint
        client = _UNIX_TRIM_CLIENT[]::U.Conn
        try
            read(client, UInt8)
            return 0
        catch err
            err isa U.DeadlineExceededError || rethrow()
            return 1
        end
    end

    Base.Experimental.entrypoint(_unix_trim_deadline_read, ())

    function run_unix_trim_sample()::Nothing
        mktempdir("/tmp"; prefix = "reseau-unix-trim-") do dir
            path = joinpath(dir, "s")
            listener = UnixTestHelpers.listener(path)
            client::Union{Nothing, U.Conn} = nothing
            server::Union{Nothing, U.Conn} = nothing
            try
                client = U.connect(path; timeout_ns = typemax(Int64))
                server = UnixTestHelpers.accept(listener, path)
                (@atomic client.fd.pfd.pd.wd_ns) == 0 || error("connect budget leaked into writes")
                U._wait_connected!(client.fd)
                buffer = zeros(UInt8, 8)
                U.tryread!(client, buffer) === nothing || error("expected idle stream")
                write(client, "abc") == 3 || error("short write")
                read!(server, @view(buffer[2:4]))
                buffer[2:4] == codeunits("abc") || error("Unix payload mismatch")
                write(server, @view(buffer[2:4])) == 3 || error("short reply")
                read(client, 3) == codeunits("abc") || error("Unix reply mismatch")

                # Arm the product deadline only after the native task parks;
                # an already-expired fast path cannot satisfy this check.
                _UNIX_TRIM_CLIENT[] = client
                reader = Task(_unix_trim_deadline_read)
                schedule(reader)
                waiter = IP._poll_registration(client.fd.pfd.pd).read_waiter
                UnixTestHelpers.wait_parked(reader, waiter) || error("reader did not park")
                U.set_read_deadline!(client, Int64(time_ns()) + 100_000_000)
                (fetch(reader)::Cint) == 1 || error("expected read deadline")
                U.set_read_deadline!(client, 0)
                write(server, 0x64) == 1 || error("short recovery write")
                read(client, UInt8) == 0x64 || error("deadline recovery failed")
                closewrite(server)
                eof(client) || error("expected peer EOF")
                U.tryread!(client, buffer) === 0 || error("expected tryread EOF")
                close(client)
                close(client)
                isopen(client) && error("client stayed open")
                ispath(path) || error("client removed server path")
            finally
                _UNIX_TRIM_CLIENT[] = nothing
                server === nothing || close(server)
                client === nothing || close(client)
                close(listener)
            end
        end
        return nothing
    end
else
    function run_unix_trim_sample()::Nothing
        try
            U.connect("unsupported.sock")
            error("expected unsupported platform error")
        catch err
            err isa ArgumentError || rethrow()
        end
        return nothing
    end
end

function @main(args::Vector{String})::Cint
    _ = args
    run_unix_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
