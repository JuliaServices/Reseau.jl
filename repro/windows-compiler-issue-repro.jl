module WindowsCompilerIssueRepro

abstract type AbstractBody end
struct EmptyBody <: AbstractBody end
struct BytesBody <: AbstractBody
    data::Vector{UInt8}
end
struct CallbackBody{F,G} <: AbstractBody
    reader::F
    closer::G
end

mutable struct Request{B<:AbstractBody}
    method::String
    target::String
    body::B
end

struct Response{B<:AbstractBody}
    status_code::Int
    body::B
end

struct Transport end
struct Client
    transport::Transport
end

struct HostResolver end
struct DNSRaceState end
struct SocketAddrV4 end

body_close!(::AbstractBody) = nothing

function _wait_connect_complete!(fd, remote_addr; cancel_state=nothing)
    _ = fd
    _ = remote_addr
    _ = cancel_state
    return nothing
end

function connect_tcp_fd!(remote_addr::SocketAddrV4; local_addr=nothing, connect_deadline_ns::Int64=0, cancel_state=nothing)
    try
        if local_addr !== nothing
            nothing
        else
            try
                _wait_connect_complete!(nothing, remote_addr; cancel_state=cancel_state)
            finally
                if connect_deadline_ns != 0
                    try
                        nothing
                    catch
                    end
                end
            end
        end
        return 1
    catch
        rethrow()
    end
end

function _resolve_serial(
        d::HostResolver,
        network::String,
        address::String,
        addrs::Vector{SocketAddrV4},
        deadline_ns::Int64,
        state::DNSRaceState,
    )
    _ = d
    _ = network
    _ = deadline_ns
    first_err = nothing
    for (i, remote_addr) in pairs(addrs)
        attempt_deadline = try
            Int64(i)
        catch
            return nothing, first_err
        end
        try
            max_attempts = 3
            for attempt in 1:max_attempts
                try
                    fd = connect_tcp_fd!(
                        remote_addr;
                        local_addr = nothing,
                        connect_deadline_ns = attempt_deadline,
                        cancel_state = state,
                    )
                    _ = fd
                    return 1, nothing
                catch err
                    first_err === nothing && (first_err = err)
                    attempt < max_attempts && continue
                    break
                end
            end
        catch err
            first_err === nothing && (first_err = err)
        end
    end
    return nothing, first_err
end

function connect(d::HostResolver, network::String, address::String)
    addrs = SocketAddrV4[SocketAddrV4()]
    conn, err = _resolve_serial(d, network, address, addrs, Int64(0), DNSRaceState())
    err === nothing || throw(err)
    return conn
end

function _new_conn!(transport::Transport, key::String, address::String; secure::Bool=false, server_name::Union{Nothing,String}=nothing)
    _ = transport
    _ = key
    _ = secure
    _ = server_name
    return connect(HostResolver(), "tcp", address)
end

function _acquire_conn!(transport::Transport, key::String, address::String; secure::Bool=false, server_name::Union{Nothing,String}=nothing)
    return _new_conn!(transport, key, address; secure=secure, server_name=server_name)
end

function _roundtrip_impl(transport::Transport, address::String, request::Request, secure::Bool, server_name::String)
    key = string(secure ? "https://" : "http://", address)
    current_request = request
    attempt = 1
    while true
        conn = _acquire_conn!(transport, key, address; secure = secure, server_name = server_name)
        try
            try
                nothing
            finally
                try
                    body_close!(current_request.body)
                catch
                end
            end
            raw_response = Response(200, current_request.body)
            while false
                try
                    body_close!(raw_response.body)
                catch
                end
            end
            return raw_response
        catch err
            _ = conn
            if attempt == 1 && false
                attempt = 2
                continue
            end
            rethrow(err)
        end
    end
end

function roundtrip!(transport::Transport, address::String, request::Request; secure::Bool=false, server_name::String="")
    return _roundtrip_impl(transport, address, request, secure, server_name)
end

function do!(client::Client, address::String, request::Request; secure::Bool=false, server_name::Union{Nothing,String}=nothing, protocol::Symbol=:auto)
    _ = protocol
    resolved_server_name = server_name === nothing ? address : server_name
    return roundtrip!(client.transport, address, request; secure = secure, server_name = resolved_server_name)
end

function trigger_empty_body()
    client = Client(Transport())
    request = Request("GET", "/", EmptyBody())
    return do!(client, "127.0.0.1:8080", request)
end

function trigger_callback_body()
    client = Client(Transport())
    request = Request("POST", "/", CallbackBody(() -> nothing, () -> nothing))
    return do!(client, "127.0.0.1:8080", request)
end

end

using .WindowsCompilerIssueRepro

# Force compiler entry through the same high-level signatures the Windows CI log shows.
Base.return_types(WindowsCompilerIssueRepro.roundtrip!, Tuple{WindowsCompilerIssueRepro.Transport, String, WindowsCompilerIssueRepro.Request{WindowsCompilerIssueRepro.EmptyBody}})
Base.return_types(WindowsCompilerIssueRepro.connect, Tuple{WindowsCompilerIssueRepro.HostResolver, String, String})
Base.return_types(WindowsCompilerIssueRepro.do!, Tuple{WindowsCompilerIssueRepro.Client, String, WindowsCompilerIssueRepro.Request{WindowsCompilerIssueRepro.EmptyBody}})
Base.return_types(WindowsCompilerIssueRepro.do!, Tuple{WindowsCompilerIssueRepro.Client, String, WindowsCompilerIssueRepro.Request{WindowsCompilerIssueRepro.CallbackBody{typeof(() -> nothing), typeof(() -> nothing)}}})
