# AWS IO Library - Apple Network Framework sockets (stub)
# Port of aws-c-io/source/darwin/nw_socket.c (not yet implemented)

function socket_init_apple_nw(options::SocketOptions)::Union{Socket, ErrorResult}
    _ = options
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
