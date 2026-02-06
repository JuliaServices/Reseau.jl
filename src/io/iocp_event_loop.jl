# AWS IO Library - IOCP Event Loop (stub)
# Port of aws-c-io/source/windows/iocp/iocp_event_loop.c (not yet implemented)

@static if Sys.iswindows()
    mutable struct IocpEventLoop end
end

function event_loop_new_with_iocp(options)::Union{Any, ErrorResult}
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
