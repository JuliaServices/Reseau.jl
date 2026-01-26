const _managed_thread_lock = Ref{Mutex}(Mutex())
const _managed_thread_signal = Ref{ConditionVariable}(ConditionVariable())
const _default_managed_join_timeout_ns = Ref{UInt64}(0)
const _unjoined_thread_count = Ref{UInt32}(0)
const _pending_join_managed_threads = Ref{Deque{ThreadHandle}}(Deque{ThreadHandle}())

function thread_increment_unjoined_count()
    mutex_lock(_managed_thread_lock)
    _unjoined_thread_count[] += UInt32(1)
    mutex_unlock(_managed_thread_lock)
    return nothing
end

function thread_decrement_unjoined_count()
    mutex_lock(_managed_thread_lock)
    _unjoined_thread_count[] -= UInt32(1)
    condition_variable_notify_one(_managed_thread_signal)
    mutex_unlock(_managed_thread_lock)
    return nothing
end

function thread_get_managed_thread_count()
    mutex_lock(_managed_thread_lock)
    count = _unjoined_thread_count[]
    mutex_unlock(_managed_thread_lock)
    return Csize_t(count)
end

function _pending_join_ready(ctx)
    _ = ctx
    return _unjoined_thread_count[] == 0 || !isempty(_pending_join_managed_threads[])
end

function thread_set_managed_join_timeout_ns(timeout_in_ns::UInt64)
    mutex_lock(_managed_thread_lock)
    _default_managed_join_timeout_ns[] = timeout_in_ns
    mutex_unlock(_managed_thread_lock)
    if thread_get_managed_thread_count() > 0
        thread_join_all_managed()
    end
    return nothing
end

function _drain_pending_joins()
    done = Deque{ThreadHandle}()
    mutex_lock(_managed_thread_lock)
    while !isempty(_pending_join_managed_threads[])
        handle = pop_front!(_pending_join_managed_threads[])
        handle === nothing && break
        push_back!(done, handle)
    end
    mutex_unlock(_managed_thread_lock)

    for handle in done
        handle.task === nothing && continue
        wait(handle.task)
        handle.detach_state = ThreadDetachState.JOIN_COMPLETED
        thread_clean_up(handle)
    end
    return nothing
end

function thread_join_all_managed()
    timeout_in_ns = _default_managed_join_timeout_ns[]
    timeout_timestamp_ns = UInt64(0)
    if timeout_in_ns > 0
        now_ref = Ref{UInt64}(0)
        if sys_clock_get_ticks(now_ref) != OP_SUCCESS
            return OP_ERR
        end
        timeout_timestamp_ns = now_ref[] + timeout_in_ns
    end

    while true
        _drain_pending_joins()
        if thread_get_managed_thread_count() == 0
            return OP_SUCCESS
        end

        if timeout_timestamp_ns > 0
            now_ref = Ref{UInt64}(0)
            if sys_clock_get_ticks(now_ref) != OP_SUCCESS
                return OP_ERR
            end
            if now_ref[] >= timeout_timestamp_ns
                return OP_ERR
            end
        end

        Base.yield()
    end
    return
end

function thread_pending_join_add(handle::ThreadHandle)
    mutex_lock(_managed_thread_lock)
    push_back!(_pending_join_managed_threads[], handle)
    condition_variable_notify_one(_managed_thread_signal)
    mutex_unlock(_managed_thread_lock)
    return nothing
end

function thread_initialize_thread_management()
    clear!(_pending_join_managed_threads[])
    return nothing
end
