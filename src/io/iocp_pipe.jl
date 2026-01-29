# AWS IO Library - IOCP pipe backend (stub)
# Port of aws-c-io/source/windows/iocp/pipe.c (not yet implemented)

function pipe_create_iocp()::Union{Tuple{PipeReadEnd, PipeWriteEnd}, ErrorResult}
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
