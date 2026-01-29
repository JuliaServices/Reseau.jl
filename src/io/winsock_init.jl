# AWS IO Library - Winsock init helpers (stub)
# Port of aws-c-io/source/windows/winsock_init.c (not yet implemented)

function winsock_check_and_init!()::Union{Nothing, ErrorResult}
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function winsock_get_connectex_fn()::Union{Ptr{Cvoid}, ErrorResult}
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function winsock_get_acceptex_fn()::Union{Ptr{Cvoid}, ErrorResult}
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
