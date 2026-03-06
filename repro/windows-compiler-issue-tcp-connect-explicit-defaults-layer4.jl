using Reseau
const NC = Reseau.TCP

function trigger(remote_addr::NC.SocketAddrV4)
    return NC.connect_tcp_fd!(
        remote_addr;
        local_addr = nothing,
        connect_deadline_ns = Int64(0),
        cancel_state = nothing,
    )
end

Base.return_types(trigger, Tuple{NC.SocketAddrV4})
