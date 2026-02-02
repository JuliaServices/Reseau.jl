const _managed_thread_lock = Ref{ReentrantLock}(ReentrantLock())
const _managed_thread_signal = Ref{ConditionVariable}(ConditionVariable())
const _default_managed_join_timeout_ns = Ref{UInt64}(0)
const _unjoined_thread_count = Ref{UInt32}(0)
const _pending_join_managed_threads = Ref{Deque{ThreadHandle}}(Deque{ThreadHandle}())

function thread_increment_unjoined_count()
    lock(_managed_thread_lock[])
    _unjoined_thread_count[] += UInt32(1)
    unlock(_managed_thread_lock[])
    return nothing
end

function thread_decrement_unjoined_count()
    lock(_managed_thread_lock[])
    _unjoined_thread_count[] -= UInt32(1)
    condition_variable_notify_one(_managed_thread_signal)
    unlock(_managed_thread_lock[])
    return nothing
end

function thread_get_managed_thread_count()
    lock(_managed_thread_lock[])
    count = _unjoined_thread_count[]
    unlock(_managed_thread_lock[])
    return Csize_t(count)
end

function _one_or_fewer_managed_threads_unjoined(ctx)
    _ = ctx
    return _unjoined_thread_count[] <= 1
end

function thread_set_managed_join_timeout_ns(timeout_in_ns::UInt64)
    lock(_managed_thread_lock[])
    _default_managed_join_timeout_ns[] = timeout_in_ns
    unlock(_managed_thread_lock[])
    if thread_get_managed_thread_count() > 0
        thread_join_all_managed()
    end
    return nothing
end

function thread_join_all_managed()
    lock(_managed_thread_lock[])
    timeout_in_ns = _default_managed_join_timeout_ns[]
    unlock(_managed_thread_lock[])
    now_in_ns = UInt64(0)
    timeout_timestamp_ns = UInt64(0)
    if timeout_in_ns > 0
        now_ref = Ref{UInt64}(0)
        if sys_clock_get_ticks(now_ref) != OP_SUCCESS
            return OP_ERR
        end
        now_in_ns = now_ref[]
        timeout_timestamp_ns = now_in_ns + timeout_in_ns
    end
    successful = true
    done = false
    while !done
        lock(_managed_thread_lock[])
        if timeout_timestamp_ns > 0
            wait_ns = UInt64(0)
            if now_in_ns <= timeout_timestamp_ns
                wait_ns = timeout_timestamp_ns - now_in_ns
            end
            condition_variable_wait_for_pred(
                _managed_thread_signal,
                _managed_thread_lock,
                wait_ns,
                _one_or_fewer_managed_threads_unjoined,
                nothing,
            )
        else
            condition_variable_wait_pred(
                _managed_thread_signal,
                _managed_thread_lock,
                _one_or_fewer_managed_threads_unjoined,
                nothing,
            )
        end
        done = _unjoined_thread_count[] == 0
        if timeout_timestamp_ns > 0
            now_ref = Ref{UInt64}(0)
            if sys_clock_get_ticks(now_ref) != OP_SUCCESS
                unlock(_managed_thread_lock[])
                return OP_ERR
            end
            now_in_ns = now_ref[]
            if now_in_ns >= timeout_timestamp_ns
                done = true
                successful = false
            end
        end
        join_list = Deque{ThreadHandle}()
        while !isempty(_pending_join_managed_threads[])
            handle = pop_front!(_pending_join_managed_threads[])
            handle === nothing && break
            push_back!(join_list, handle)
        end
        unlock(_managed_thread_lock[])
        for handle in join_list
            handle.task === nothing && continue
            wait(handle.task)
            handle.detach_state = ThreadDetachState.JOIN_COMPLETED
            thread_clean_up(handle)
        end
    end
    return successful ? OP_SUCCESS : OP_ERR
end

function thread_pending_join_add(handle::ThreadHandle)
    lock(_managed_thread_lock[])
    push_back!(_pending_join_managed_threads[], handle)
    condition_variable_notify_one(_managed_thread_signal)
    unlock(_managed_thread_lock[])
    return nothing
end

function thread_initialize_thread_management()
    clear!(_pending_join_managed_threads[])
    return nothing
end
