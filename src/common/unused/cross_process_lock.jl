# C memory allocation helpers for cross-process locks
@inline function _cpl_calloc(num::Integer, size::Integer)
    num <= 0 && return Ptr{UInt8}(0)
    size <= 0 && return Ptr{UInt8}(0)
    mem = Libc.calloc(num, size)
    mem == C_NULL && error("calloc failed to allocate memory")
    return Ptr{UInt8}(mem)
end

@inline function _cpl_free(ptr::Ptr{UInt8})
    ptr == Ptr{UInt8}(0) && return nothing
    Libc.free(ptr)
    return nothing
end

@inline function _nonce_string(nonce::ByteCursor)
    if nonce.len == 0
        return ""
    end
    return unsafe_string(Ptr{UInt8}(pointer(nonce.ptr)), Int(nonce.len))
end

@static if _PLATFORM_WINDOWS
    struct cross_process_lock
        mutex::Ptr{Cvoid}
    end

    const _ERROR_ALREADY_EXISTS = 183

    function cross_process_lock_try_acquire(instance_nonce::ByteCursor)
        to_find = byte_cursor_from_c_str("\\")
        found = Ref{ByteCursor}()
        zero_struct!(found)
        if byte_cursor_find_exact(Ref(instance_nonce), Ref(to_find), found) == OP_SUCCESS
            logf(
                Cint(LL_ERROR),
                LS_COMMON_GENERAL,string("static: Lock %s creation has illegal character \\", " ", string(_nonce_string(instance_nonce)), " ", ))
            raise_error(ERROR_INVALID_ARGUMENT)
            return Ptr{cross_process_lock}(C_NULL)
        end

        path_prefix = byte_cursor_from_c_str("Local\\crt_cross_process_lock/")
        nonce_buf = Ref{ByteBuffer}(ByteBuffer(0))
        byte_buf_init_copy_from_cursor(nonce_buf, path_prefix)
        byte_buf_append_dynamic(nonce_buf, Ref(instance_nonce))
        byte_buf_append_null_terminator(nonce_buf)

        mutex = ccall((:CreateMutexA, "kernel32"), Ptr{Cvoid}, (Ptr{Cvoid}, UInt8, Ptr{UInt8}), C_NULL, 0, pointer(nonce_buf[].mem))
        if mutex == C_NULL
            last_error = ccall((:GetLastError, "kernel32"), UInt32, ())
            logf(
                Cint(LL_WARN),
                LS_COMMON_GENERAL,string("static: Lock %s creation failed with error %d", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", string(last_error), " ", ))
            translate_and_raise_io_error_or(last_error, ERROR_MUTEX_FAILED)
            byte_buf_clean_up(nonce_buf)
            return Ptr{cross_process_lock}(C_NULL)
        end

        if ccall((:GetLastError, "kernel32"), UInt32, ()) == _ERROR_ALREADY_EXISTS
            logf(
                Cint(LL_TRACE),
                LS_COMMON_GENERAL,string("static: Lock %s is already acquired by another instance", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", ))
            ccall((:CloseHandle, "kernel32"), UInt8, (Ptr{Cvoid},), mutex)
            raise_error(ERROR_MUTEX_CALLER_NOT_OWNER)
            byte_buf_clean_up(nonce_buf)
            return Ptr{cross_process_lock}(C_NULL)
        end

        instance_lock = Ptr{cross_process_lock}(_cpl_calloc(1, sizeof(cross_process_lock)))
        if instance_lock == C_NULL
            ccall((:CloseHandle, "kernel32"), UInt8, (Ptr{Cvoid},), mutex)
            byte_buf_clean_up(nonce_buf)
            return Ptr{cross_process_lock}(C_NULL)
        end

        unsafe_store!(instance_lock, cross_process_lock(mutex))
        logf(
            Cint(LL_TRACE),
            LS_COMMON_GENERAL,string("static: Lock %s acquired by this instance with HANDLE %p", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", string(mutex), " ", ))

        byte_buf_clean_up(nonce_buf)
        return instance_lock
    end

    function cross_process_lock_release(instance_lock::Ptr{cross_process_lock})
        if instance_lock == C_NULL
            return nothing
        end
        ccall((:CloseHandle, "kernel32"), UInt8, (Ptr{Cvoid},), unsafe_load(instance_lock).mutex)
        logf(
            Cint(LL_TRACE),
            LS_COMMON_GENERAL,string("static: Lock released for handle %p", " ", string(unsafe_load(instance_lock).mutex), " ", ))
        _cpl_free(Ptr{UInt8}(instance_lock))
        return nothing
    end
else
    struct cross_process_lock
        locked_fd::Cint
    end

    const _O_CREAT = Cint(Base.Filesystem.JL_O_CREAT)
    const _O_EXCL = Cint(Base.Filesystem.JL_O_EXCL)
    const _O_RDONLY = Cint(Base.Filesystem.JL_O_RDONLY)
    const _O_RDWR = Cint(Base.Filesystem.JL_O_RDWR)
    const _LOCK_EX = Cint(2)
    const _LOCK_NB = Cint(4)
    const _LOCK_FILE_MODE = Cint(0o666)

    @inline function _lock_file_mode()
        # Mirror open(2) behavior by applying the current umask.
        mask = ccall(:umask, Cint, (Cint,), 0)
        _ = ccall(:umask, Cint, (Cint,), mask)
        return Cint(_LOCK_FILE_MODE & ~mask)
    end

    function cross_process_lock_try_acquire(instance_nonce::ByteCursor)
        to_find = byte_cursor_from_c_str("/")
        found = Ref{ByteCursor}()
        zero_struct!(found)
        if byte_cursor_find_exact(Ref(instance_nonce), Ref(to_find), found) == OP_SUCCESS
            logf(
                Cint(LL_ERROR),
                LS_COMMON_GENERAL,string("static: Lock %s creation has illegal character /", " ", string(_nonce_string(instance_nonce)), " ", ))
            raise_error(ERROR_INVALID_ARGUMENT)
            return Ptr{cross_process_lock}(C_NULL)
        end

        path_prefix = byte_cursor_from_c_str("/tmp/crt_cross_process_lock/")
        path_to_create = string_new_from_cursor(path_prefix)
        path_to_create === nothing && return Ptr{cross_process_lock}(C_NULL)

        path_str = unsafe_string(string_c_str(path_to_create))
        if !isdir(path_str)
            mkpath(path_str)
            ccall(:chmod, Cint, (Ptr{UInt8}, Cint), string_c_str(path_to_create), 0o777)
        end
        string_destroy(path_to_create)

        path_suffix = byte_cursor_from_c_str(".lock")
        nonce_buf = Ref{ByteBuffer}(ByteBuffer(0))
        byte_buf_init_copy_from_cursor(nonce_buf, path_prefix)
        byte_buf_append_dynamic(nonce_buf, Ref(instance_nonce))
        byte_buf_append_dynamic(nonce_buf, Ref(path_suffix))
        byte_buf_append_null_terminator(nonce_buf)

        mode = _lock_file_mode()
        created = false
        err = Cint(0)
        fd = ccall(:open, Cint, (Ptr{UInt8}, Cint, Cint), pointer(nonce_buf[].mem), _O_CREAT | _O_EXCL | _O_RDWR, _LOCK_FILE_MODE)
        if fd < 0
            err = Libc.errno()
            if err == Libc.EEXIST
                fd = ccall(:open, Cint, (Ptr{UInt8}, Cint, Cint), pointer(nonce_buf[].mem), _O_CREAT | _O_RDWR, _LOCK_FILE_MODE)
                if fd < 0
                    err = Libc.errno()
                end
            end
        else
            created = true
        end
        if fd < 0
            logf(
                Cint(LL_DEBUG),
                LS_COMMON_GENERAL,string("static: Lock file %s failed to open with errno %d", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", string(err), " ", ))
            translate_and_raise_io_error_or(err, ERROR_MUTEX_FAILED)
            if last_error() == ERROR_NO_PERMISSION
                if ccall(:chmod, Cint, (Ptr{UInt8}, Cint), pointer(nonce_buf[].mem), mode) == 0
                    fd = ccall(:open, Cint, (Ptr{UInt8}, Cint, Cint), pointer(nonce_buf[].mem), _O_CREAT | _O_RDWR, _LOCK_FILE_MODE)
                end
                if fd < 0
                    logf(
                        Cint(LL_DEBUG),
                        LS_COMMON_GENERAL,string("static: Lock file %s couldn't be opened due to file ownership permissions. Attempting to open as read only", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", ))
                    fd = ccall(:open, Cint, (Ptr{UInt8}, Cint), pointer(nonce_buf[].mem), _O_RDONLY)
                end
                if fd < 0
                    err = Libc.errno()
                    logf(
                        Cint(LL_ERROR),
                        LS_COMMON_GENERAL,string("static: Lock file %s failed to open with read-only permissions with errno %d", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", string(err), " ", ))
                    translate_and_raise_io_error_or(err, ERROR_MUTEX_FAILED)
                    byte_buf_clean_up(nonce_buf)
                    return Ptr{cross_process_lock}(C_NULL)
                end
            else
                logf(
                    Cint(LL_ERROR),
                    LS_COMMON_GENERAL,string("static: Lock file %s failed to open. The lock cannot be acquired.", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", ))
                byte_buf_clean_up(nonce_buf)
                return Ptr{cross_process_lock}(C_NULL)
            end
        end
        if created
            _ = ccall(:fchmod, Cint, (Cint, Cint), fd, mode)
        end

        if ccall(:flock, Cint, (Cint, Cint), fd, _LOCK_EX | _LOCK_NB) == -1
            logf(
                Cint(LL_TRACE),
                LS_COMMON_GENERAL,string("static: Lock file %s already acquired by another instance", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", ))
            ccall(:close, Cint, (Cint,), fd)
            raise_error(ERROR_MUTEX_CALLER_NOT_OWNER)
            byte_buf_clean_up(nonce_buf)
            return Ptr{cross_process_lock}(C_NULL)
        end

        instance_lock = Ptr{cross_process_lock}(_cpl_calloc(1, sizeof(cross_process_lock)))
        if instance_lock == C_NULL
            ccall(:close, Cint, (Cint,), fd)
            byte_buf_clean_up(nonce_buf)
            return Ptr{cross_process_lock}(C_NULL)
        end

        unsafe_store!(instance_lock, cross_process_lock(fd))
        logf(
            Cint(LL_TRACE),
            LS_COMMON_GENERAL,string("static: Lock file %s acquired by this instance with fd %d", " ", string(unsafe_string(pointer(nonce_buf[].mem))), " ", string(fd), " ", ))

        byte_buf_clean_up(nonce_buf)
        return instance_lock
    end

    function cross_process_lock_release(instance_lock::Ptr{cross_process_lock})
        if instance_lock == C_NULL
            return nothing
        end
        ccall(:close, Cint, (Cint,), unsafe_load(instance_lock).locked_fd)
        logf(
            Cint(LL_TRACE),
            LS_COMMON_GENERAL,string("static: Lock file released for fd %d", " ", string(unsafe_load(instance_lock).locked_fd), " ", ))
        _cpl_free(Ptr{UInt8}(instance_lock))
        return nothing
    end
end
