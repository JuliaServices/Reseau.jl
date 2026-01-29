# AWS IO Library - Winsock sockets (stub)
# Port of aws-c-io/source/windows/winsock_init.c and iocp/socket.c (not yet implemented)

function socket_init_winsock(options::SocketOptions)::Union{Socket, ErrorResult}
    _ = options
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
