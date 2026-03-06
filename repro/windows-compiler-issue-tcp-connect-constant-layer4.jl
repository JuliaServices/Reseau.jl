using Reseau
const NC = Reseau.TCP
const ADDR = NC.SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), 8080)

function trigger()
    return NC.connect_tcp_fd!(
        ADDR;
        local_addr = nothing,
        connect_deadline_ns = Int64(0),
        cancel_state = nothing,
    )
end

Base.return_types(trigger, Tuple{})
