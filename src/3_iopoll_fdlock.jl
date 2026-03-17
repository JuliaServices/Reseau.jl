"""
    RuntimeSema

Small counting semaphore used by `FDLock` slow paths.

Unlike `PollWaiter`, this is deliberately unbounded: repeated wakeups must not
be lost while a goroutine-like lock waiter is still making progress through the
`FDLock` state machine.
"""
mutable struct RuntimeSema
    lock::ReentrantLock
    cond::Base.Threads.Condition
    count::Int
    function RuntimeSema()
        lock = ReentrantLock()
        return new(lock, Base.Threads.Condition(lock), 0)
    end
end

"""
    _runtime_sema_acquire!(sema)

Block until one semaphore unit is available, then consume it.

Returns `nothing`.
"""
function _runtime_sema_acquire!(sema::RuntimeSema)
    lock(sema.lock)
    try
        while sema.count == 0
            wait(sema.cond)
        end
        sema.count -= 1
    finally
        unlock(sema.lock)
    end
    return nothing
end

"""
    _runtime_sema_release!(sema)

Add one semaphore unit and notify one blocked waiter.

Returns `nothing`.
"""
function _runtime_sema_release!(sema::RuntimeSema)
    lock(sema.lock)
    try
        sema.count += 1
        notify(sema.cond)
    finally
        unlock(sema.lock)
    end
    return nothing
end

function _new_binary_semaphore0()
    sema = Base.Semaphore(1)
    Base.acquire(sema)
    return sema
end

"""
Atomic lock/reference state for an `FD`, mirroring Go's `internal/poll` approach.

The bitfield tracks:
- whether close has started
- read/write lock ownership
- shared references
- queued waiters for read and write locks
"""
mutable struct FDLock
    @atomic state::UInt64
    const rsema::RuntimeSema
    const wsema::RuntimeSema
    function FDLock()
        return new(UInt64(0), RuntimeSema(), RuntimeSema())
    end
end

"""
    _fdlock_incref!(mu)

Acquire one shared descriptor reference.

Returns `true` on success and `false` if close has already started.

Throws `ArgumentError` if the reference count overflows, which would indicate an
unreasonable number of concurrent operations on one descriptor.
"""
function _fdlock_incref!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = old + _MUTEX_REF
        (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        _, ok = @atomicreplace(mu.state, old => new)
        ok && return true
    end
end

"""
    _fdlock_incref_and_close!(mu)

Start close, acquire one final shared reference, and wake all queued lock
waiters.

Returns `true` if this call successfully initiated close and `false` if another
task had already done so.
"""
function _fdlock_incref_and_close!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = (old | _MUTEX_CLOSED) + _MUTEX_REF
        (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        new &= ~(_MUTEX_RMASK | _MUTEX_WMASK)
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        wake = old
        # Close wakes all queued read waiters.
        while (wake & _MUTEX_RMASK) != 0
            wake -= _MUTEX_RWAIT
            _runtime_sema_release!(mu.rsema)
        end
        # Close wakes all queued write waiters.
        while (wake & _MUTEX_WMASK) != 0
            wake -= _MUTEX_WWAIT
            _runtime_sema_release!(mu.wsema)
        end
        return true
    end
end

"""
    _fdlock_decref!(mu)

Release one shared descriptor reference.

Returns `true` exactly when the descriptor has already been marked closed and
this call released the final outstanding reference, meaning the underlying OS
handle may now be destroyed.
"""
function _fdlock_decref!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("inconsistent fd mutex state"))
        new = old - _MUTEX_REF
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        return (new & (_MUTEX_CLOSED | _MUTEX_REF_MASK)) == _MUTEX_CLOSED
    end
end

"""
    _fdlock_rwlock!(mu, read_lock, wait_lock)

Acquire the descriptor's read or write operation lock.

Arguments:
- `read_lock`: `true` for the read lock, `false` for the write lock
- `wait_lock`: whether to queue and block if the lock is already held

Returns `true` on success and `false` if the descriptor is closed or if
`wait_lock == false` and the lock is already held.
"""
function _fdlock_rwlock!(mu::FDLock, read_lock::Bool, wait_lock::Bool)::Bool
    mutex_bit = read_lock ? _MUTEX_RLOCK : _MUTEX_WLOCK
    mutex_wait = read_lock ? _MUTEX_RWAIT : _MUTEX_WWAIT
    mutex_mask = read_lock ? _MUTEX_RMASK : _MUTEX_WMASK
    mutex_sema = read_lock ? mu.rsema : mu.wsema
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = UInt64(0)
        if (old & mutex_bit) == 0
            new = (old | mutex_bit) + _MUTEX_REF
            (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        else
            wait_lock || return false
            new = old + mutex_wait
            (new & mutex_mask) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        end
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        if (old & mutex_bit) == 0
            return true
        end
        _runtime_sema_acquire!(mutex_sema)
    end
end

"""
    _fdlock_rwunlock!(mu, read_lock)

Release the descriptor's read or write operation lock.

Returns `true` when the descriptor has already been marked closed and this call
released the final reference, so destruction should proceed.
"""
function _fdlock_rwunlock!(mu::FDLock, read_lock::Bool)::Bool
    mutex_bit = read_lock ? _MUTEX_RLOCK : _MUTEX_WLOCK
    mutex_wait = read_lock ? _MUTEX_RWAIT : _MUTEX_WWAIT
    mutex_mask = read_lock ? _MUTEX_RMASK : _MUTEX_WMASK
    mutex_sema = read_lock ? mu.rsema : mu.wsema
    while true
        old = @atomic :acquire mu.state
        ((old & mutex_bit) == 0 || (old & _MUTEX_REF_MASK) == 0) && throw(ArgumentError("inconsistent fd mutex state"))
        new = (old & ~mutex_bit) - _MUTEX_REF
        if (old & mutex_mask) != 0
            new -= mutex_wait
        end
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        if (old & mutex_mask) != 0
            _runtime_sema_release!(mutex_sema)
        end
        return (new & (_MUTEX_CLOSED | _MUTEX_REF_MASK)) == _MUTEX_CLOSED
    end
end
