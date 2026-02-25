# Integration helpers for `Reseau.EventLoops.Future` that require channel/socket
# types. This file lives in `Reseau.Sockets` to avoid making `Reseau.EventLoops`
# depend on the channel stack.

import ..EventLoops: Future, OnFutureCompleteFn, future_is_done, future_on_complete!
import ..EventLoops: future_on_event_loop!, future_on_channel!

function future_on_event_loop!(
        future::Future,
        event_loop::EventLoop,
        callback::OnFutureCompleteFn,
    )
    schedule_callback = () -> begin
        schedule_task_now!(event_loop; type_tag = "future_event_loop_callback") do _
            try
                callback(future)
            catch e
                Core.println("future_event_loop_callback task errored")
            end
            return nothing
        end
    end

    if future_is_done(future)
        schedule_callback()
        return nothing
    end

    future_on_complete!(future, (_f, _ud) -> schedule_callback(), nothing)
    return nothing
end

function future_on_channel!(
        future::Future,
        channel::Channel,
        callback::OnFutureCompleteFn,
    )
    schedule_callback = () -> begin
        schedule_task_now!(channel.event_loop; type_tag = "future_channel_callback") do _
            try
                callback(future)
            catch e
                Core.println("future_channel_callback task errored")
            end
            return nothing
        end
    end

    if future_is_done(future)
        schedule_callback()
        return nothing
    end

    future_on_complete!(future, (_f, _ud) -> schedule_callback(), nothing)
    return nothing
end
