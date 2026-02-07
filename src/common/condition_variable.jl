mutable struct ConditionVariable
    cond::Threads.Condition
    @atomic seq::UInt64
end

ConditionVariable() = ConditionVariable(Threads.Condition(), UInt64(0))

function condition_variable_init(cond_ref::Base.RefValue{ConditionVariable})
    cond_ref[] = ConditionVariable()
    return OP_SUCCESS
end

function condition_variable_clean_up(::Base.RefValue{ConditionVariable})
    return nothing
end

function condition_variable_notify_one(cond::ConditionVariable)
    lock(cond.cond)
    try
        @atomic cond.seq += 1
        notify(cond.cond)
    finally
        unlock(cond.cond)
    end
    return OP_SUCCESS
end

function condition_variable_notify_one(cond_ref::Base.RefValue{ConditionVariable})
    return condition_variable_notify_one(cond_ref[])
end

function condition_variable_notify_all(cond::ConditionVariable)
    lock(cond.cond)
    try
        @atomic cond.seq += 1
        notify(cond.cond, all = true)
    finally
        unlock(cond.cond)
    end
    return OP_SUCCESS
end

function condition_variable_notify_all(cond_ref::Base.RefValue{ConditionVariable})
    return condition_variable_notify_all(cond_ref[])
end

@inline function _cond_predicate(pred, ctx)
    return pred(ctx)
end

function condition_variable_wait_pred(
        cond::ConditionVariable,
        mutex::ReentrantLock,
        pred,
        pred_ctx,
    )
    local_seq = @atomic cond.seq
    while !_cond_predicate(pred, pred_ctx)
        unlock(mutex)
        lock(cond.cond)
        try
            while (@atomic cond.seq) == local_seq
                wait(cond.cond)
            end
            local_seq = @atomic cond.seq
        finally
            unlock(cond.cond)
        end
        lock(mutex)
    end
    return OP_SUCCESS
end

function condition_variable_wait_pred(
        cond_ref::Base.RefValue{ConditionVariable},
        mutex_ref::Base.RefValue{ReentrantLock},
        pred,
        pred_ctx,
    )
    return condition_variable_wait_pred(cond_ref[], mutex_ref[], pred, pred_ctx)
end

function condition_variable_wait_for_pred(
        cond::ConditionVariable,
        mutex::ReentrantLock,
        time_to_wait::Integer,
        pred,
        pred_ctx,
    )
    start_ref = Ref{UInt64}(0)
    if sys_clock_get_ticks(start_ref) != OP_SUCCESS
        return OP_ERR
    end
    deadline = start_ref[] + UInt64(max(time_to_wait, 0))
    local_seq = @atomic cond.seq

    while !_cond_predicate(pred, pred_ctx)
        now_ref = Ref{UInt64}(0)
        if sys_clock_get_ticks(now_ref) != OP_SUCCESS
            return OP_ERR
        end
        if now_ref[] >= deadline
            return raise_error(ERROR_COND_VARIABLE_TIMED_OUT)
        end
        remaining = deadline - now_ref[]
        unlock(mutex)
        ok = timedwait_poll_ns(() -> (@atomic cond.seq) != local_seq, remaining)
        lock(mutex)
        if ok == :timed_out
            return raise_error(ERROR_COND_VARIABLE_TIMED_OUT)
        end
        local_seq = @atomic cond.seq
    end
    return OP_SUCCESS
end

function condition_variable_wait_for_pred(
        cond_ref::Base.RefValue{ConditionVariable},
        mutex_ref::Base.RefValue{ReentrantLock},
        time_to_wait::Integer,
        pred,
        pred_ctx,
    )
    return condition_variable_wait_for_pred(cond_ref[], mutex_ref[], time_to_wait, pred, pred_ctx)
end
