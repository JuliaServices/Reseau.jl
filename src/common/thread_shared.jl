const _managed_thread_lock = Ref{ReentrantLock}(ReentrantLock())
const _managed_thread_signal = Ref{ConditionVariable}(ConditionVariable())
const _default_managed_join_timeout_ns = Ref{UInt64}(0)
const _unjoined_thread_count = Ref{UInt32}(0)
const _pending_join_managed_threads = Ref{Vector{ThreadHandle}}(ThreadHandle[])

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

function _managed_thread_join_threshold()::UInt32
    # If called from a managed thread we can never join ourselves, so consider "done" when only one
    # managed thread remains.
    handle = _thread_tls_handle()
    return (handle !== nothing && handle.managed) ? UInt32(1) : UInt32(0)
end

struct _JoinAllManagedCtx
    threshold::UInt32
end

function _managed_threads_done_or_pending_pred(ctx::_JoinAllManagedCtx)
    # Called with `_managed_thread_lock` held.
    #
    # Wake up when either:
    # - there are thread handles ready to join, or
    # - the remaining managed-thread count is at/below the "done" threshold.
    return !isempty(_pending_join_managed_threads[]) || (_unjoined_thread_count[] <= ctx.threshold)
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
    threshold = _managed_thread_join_threshold()
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
    ctx = _JoinAllManagedCtx(threshold)
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
                _managed_threads_done_or_pending_pred,
                ctx,
            )
        else
            condition_variable_wait_pred(
                _managed_thread_signal,
                _managed_thread_lock,
                _managed_threads_done_or_pending_pred,
                ctx,
            )
        end
        # Pull any threads that have finished into a local join list.
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
        join_list = ThreadHandle[]
        while !isempty(_pending_join_managed_threads[])
            handle = popfirst!(_pending_join_managed_threads[])
            handle === nothing && break
            push!(join_list, handle)
        end
        done = done || (_unjoined_thread_count[] <= threshold && isempty(_pending_join_managed_threads[]))
        unlock(_managed_thread_lock[])
        for handle in join_list
            _thread_join_os_thread!(handle)
            handle.detach_state = ThreadDetachState.JOIN_COMPLETED
            thread_clean_up(handle)
        end
    end
    return successful ? OP_SUCCESS : OP_ERR
end

function thread_pending_join_add(handle::ThreadHandle)
    lock(_managed_thread_lock[])
    push!(_pending_join_managed_threads[], handle)
    condition_variable_notify_one(_managed_thread_signal)
    unlock(_managed_thread_lock[])
    return nothing
end

function thread_initialize_thread_management()
    empty!(_pending_join_managed_threads[])
    return nothing
end
