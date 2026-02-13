using Reseau
import Reseau: Sockets, EventLoops

mode = get(ENV, "MODE", "none")
println("mode=", mode)

opts = Sockets.SocketOptions(
    type = Sockets.SocketType.STREAM,
    domain = Sockets.SocketDomain.IPV4,
    connect_timeout_ms = 3000,
    keepalive = true,
    keep_alive_interval_sec = 1000,
    keep_alive_timeout_sec = 60000,
    network_interface_name = "lo",
)

el = EventLoops.event_loop_new()
println("run", EventLoops.event_loop_run!(el))
el_val = el isa EventLoops.EventLoop ? el : nothing

server = Sockets.socket_init(opts)
server_socket = server isa Sockets.Socket ? server : nothing
Sockets.socket_bind(server_socket, Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0)))
Sockets.socket_listen(server_socket, 1024)
bound = Sockets.socket_get_bound_address(server_socket)
port = Int(bound.port)

accept_err = Ref{Int}(0)
read_done = Threads.Atomic{Bool}(false)
connect_err = Ref{Int}(0)
connect_done = Threads.Atomic{Bool}(false)
write_err = Ref{Int}(0)
write_done = Threads.Atomic{Bool}(false)

accepted = Ref{Any}(nothing)

on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
    accept_err[] = err
    accepted[] = new_sock
    if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
        read_done[] = true
        return nothing
    end
    Sockets.socket_assign_to_event_loop(new_sock, el_val)
    Sockets.socket_subscribe_to_readable_events(
        new_sock, Reseau.EventCallable(err -> begin
            read_done[] = true
            if err != Reseau.AWS_OP_SUCCESS
                return nothing
            end
            buf = Reseau.ByteBuffer(64)
            try
                Sockets.socket_read(new_sock, buf)
            catch e
                @show e
            end
            read_done[] = true
        end)
    )
end)

Sockets.socket_start_accept(server_socket, el_val, Sockets.SocketListenerOptions(on_accept_result = on_accept))

client = Sockets.socket_init(opts)
client_socket = client isa Sockets.Socket ? client : nothing

on_conn = Reseau.EventCallable(err -> begin
    connect_err[] = err
    connect_done[] = true
    if err != Reseau.AWS_OP_SUCCESS
        return nothing
    end
    cursor = Reseau.ByteCursor("ping")
    Sockets.socket_write(client_socket, cursor, Reseau.WriteCallable((e, n) -> begin
        write_err[] = e
        write_done[] = true
    end))
end)
Sockets.socket_connect(
    client_socket,
    Sockets.SocketConnectOptions(Sockets.SocketEndpoint("127.0.0.1", port); event_loop = el_val, on_connection_result = on_conn),
)

for _ in 1:600
    connect_done[] && write_done[] && read_done[] && break
    sleep(0.01)
end

println("io_done ", connect_done[], " ", write_done[], " ", read_done[])
if mode == "client"
    println("cleanup client")
    Sockets.socket_cleanup!(client_socket)
    println("cleanup client done")
elseif mode == "server"
    println("cleanup server")
    Sockets.socket_cleanup!(server_socket)
    println("cleanup server done")
elseif mode == "both"
    println("cleanup both")
    Sockets.socket_cleanup!(client_socket)
    println("cleanup client done")
    Sockets.socket_cleanup!(server_socket)
    println("cleanup server done")
elseif mode == "el"
    println("destroy el")
    EventLoops.event_loop_destroy!(el_val)
    println("destroy el done")
else
    println("none")
end
println("end")
