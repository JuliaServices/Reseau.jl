# AWS IO Library - IOCP Event Loop (stub)
# Port of aws-c-io/source/windows/iocp/iocp_event_loop.c (not yet implemented)

function event_loop_new_with_iocp(options::EventLoopOptions)::Union{EventLoop, ErrorResult}
    _ = options
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
