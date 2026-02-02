const Mutex = Base.ReentrantLock

function mutex_init(mutex_ref::Base.RefValue{Mutex})
    mutex_ref[] = ReentrantLock()
    return OP_SUCCESS
end

function mutex_clean_up(mutex_ref::Base.RefValue{Mutex})
    mutex_ref[] = ReentrantLock()
    return nothing
end

function mutex_lock(mutex::Mutex)
    lock(mutex)
    return OP_SUCCESS
end

function mutex_lock(mutex_ref::Base.RefValue{Mutex})
    return mutex_lock(mutex_ref[])
end

function mutex_try_lock(mutex::Mutex)
    if trylock(mutex)
        return OP_SUCCESS
    end
    return raise_error(ERROR_MUTEX_TIMEOUT)
end

function mutex_try_lock(mutex_ref::Base.RefValue{Mutex})
    return mutex_try_lock(mutex_ref[])
end

function mutex_unlock(mutex::Mutex)
    unlock(mutex)
    return OP_SUCCESS
end

function mutex_unlock(mutex_ref::Base.RefValue{Mutex})
    return mutex_unlock(mutex_ref[])
end
