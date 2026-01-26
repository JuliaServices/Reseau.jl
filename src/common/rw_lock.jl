@static if _PLATFORM_WINDOWS
    const _RWLOCK_HANDLE_WORDS = _WINDOWS_SRWLOCK_WORDS
else
    const _RWLOCK_HANDLE_WORDS = _PTHREAD_RWLOCK_WORDS
end

const _RWLOCK_HANDLE_SIZE = _RWLOCK_HANDLE_WORDS * sizeof(UInt)
const _RWLOCK_PAD = align_round_up(_RWLOCK_HANDLE_SIZE, sizeof(UInt)) - _RWLOCK_HANDLE_SIZE
const _RWLOCK_PAD_BYTES = ntuple(_ -> UInt8(0), _RWLOCK_PAD)
const _RWLOCK_ZERO_HANDLE = ntuple(_ -> UInt(0), _RWLOCK_HANDLE_WORDS)

struct rw_lock
    lock_handle::NTuple{_RWLOCK_HANDLE_WORDS, UInt}
    _padding::NTuple{_RWLOCK_PAD, UInt8}
end

const _RWLOCK_HANDLE_OFFSET = fieldoffset(rw_lock, 1)

@inline function _rwlock_handle_ptr(lock::Ptr{rw_lock})
    return Ptr{Cvoid}(Ptr{UInt8}(lock) + _RWLOCK_HANDLE_OFFSET)
end

@static if _PLATFORM_WINDOWS
    const _RWLOCK_INIT_HANDLE = _RWLOCK_ZERO_HANDLE
elseif _PLATFORM_APPLE
    const _RWLOCK_INIT_HANDLE = _PTHREAD_RWLOCK_INIT_WORDS
elseif _PLATFORM_LINUX
    const _RWLOCK_INIT_HANDLE = _RWLOCK_ZERO_HANDLE
else
    error("platform not supported")
end

const RW_LOCK_INIT = rw_lock(_RWLOCK_INIT_HANDLE, _RWLOCK_PAD_BYTES)

function rw_lock_init(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        ccall((:InitializeSRWLock, "kernel32"), Cvoid, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_init, Cint, (Ptr{Cvoid}, Ptr{Cvoid}), _rwlock_handle_ptr(lock), C_NULL),
        )
    end
end

function rw_lock_init(lock::Base.RefValue{rw_lock})
    return rw_lock_init(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_clean_up(lock::Ptr{rw_lock})
    @static if !_PLATFORM_WINDOWS
        ccall(:pthread_rwlock_destroy, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
    end
    return nothing
end

function rw_lock_clean_up(lock::Base.RefValue{rw_lock})
    return rw_lock_clean_up(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_rlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        ccall((:AcquireSRWLockShared, "kernel32"), Cvoid, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_rdlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_rlock(lock::Base.RefValue{rw_lock})
    return rw_lock_rlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_wlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        ccall((:AcquireSRWLockExclusive, "kernel32"), Cvoid, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_wrlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_wlock(lock::Base.RefValue{rw_lock})
    return rw_lock_wlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

@static if _PLATFORM_WINDOWS
    const _rwlock_try_shared_fn = Ref{Ptr{Cvoid}}(C_NULL)
    const _rwlock_try_exclusive_fn = Ref{Ptr{Cvoid}}(C_NULL)
    const _rwlock_try_checked = Ref{Bool}(false)

    function _rwlock_try_load()
        if !_rwlock_try_checked[]
            _rwlock_try_checked[] = true
            handle = Libdl.dlopen("kernel32"; throw_error=false)
            if handle != C_NULL
                shared_ptr = Libdl.dlsym(handle, "TryAcquireSRWLockShared"; throw_error=false)
                exclusive_ptr = Libdl.dlsym(handle, "TryAcquireSRWLockExclusive"; throw_error=false)
                if shared_ptr != C_NULL
                    _rwlock_try_shared_fn[] = shared_ptr
                end
                if exclusive_ptr != C_NULL
                    _rwlock_try_exclusive_fn[] = exclusive_ptr
                end
            end
        end
    end
end

function rw_lock_try_rlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        _rwlock_try_load()
        fn = _rwlock_try_shared_fn[]
        if fn == C_NULL
            return raise_error(ERROR_UNSUPPORTED_OPERATION)
        end
        res = ccall(fn, UInt8, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return res == 0 ? raise_error(ERROR_MUTEX_TIMEOUT) : OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_tryrdlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_try_rlock(lock::Base.RefValue{rw_lock})
    return rw_lock_try_rlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_try_wlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        _rwlock_try_load()
        fn = _rwlock_try_exclusive_fn[]
        if fn == C_NULL
            return raise_error(ERROR_UNSUPPORTED_OPERATION)
        end
        res = ccall(fn, UInt8, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return res == 0 ? raise_error(ERROR_MUTEX_TIMEOUT) : OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_trywrlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_try_wlock(lock::Base.RefValue{rw_lock})
    return rw_lock_try_wlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_runlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        ccall((:ReleaseSRWLockShared, "kernel32"), Cvoid, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_unlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_runlock(lock::Base.RefValue{rw_lock})
    return rw_lock_runlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end

function rw_lock_wunlock(lock::Ptr{rw_lock})
    @static if _PLATFORM_WINDOWS
        ccall((:ReleaseSRWLockExclusive, "kernel32"), Cvoid, (Ptr{Cvoid},), _rwlock_handle_ptr(lock))
        return OP_SUCCESS
    else
        return private_convert_and_raise_error_code(
            ccall(:pthread_rwlock_unlock, Cint, (Ptr{Cvoid},), _rwlock_handle_ptr(lock)),
        )
    end
end

function rw_lock_wunlock(lock::Base.RefValue{rw_lock})
    return rw_lock_wunlock(Base.unsafe_convert(Ptr{rw_lock}, lock))
end
