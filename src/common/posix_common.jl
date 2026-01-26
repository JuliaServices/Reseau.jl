function private_convert_and_raise_error_code(error_code::Integer)
    if error_code == 0
        return OP_SUCCESS
    elseif error_code == Base.Libc.EINVAL
        return raise_error(ERROR_MUTEX_NOT_INIT)
    elseif error_code == Base.Libc.EBUSY
        return raise_error(ERROR_MUTEX_TIMEOUT)
    elseif error_code == Base.Libc.EPERM
        return raise_error(ERROR_MUTEX_CALLER_NOT_OWNER)
    elseif error_code == Base.Libc.ENOMEM
        return raise_error(ERROR_OOM)
    elseif error_code == Base.Libc.EDEADLK
        return raise_error(ERROR_THREAD_DEADLOCK_DETECTED)
    else
        return raise_error(ERROR_MUTEX_FAILED)
    end
end
