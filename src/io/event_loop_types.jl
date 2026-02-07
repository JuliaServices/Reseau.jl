# Event loop shared types - included before platform backends

# Event types for IO event subscriptions (bitmask)
@enumx IoEventType::UInt32 begin
    READABLE = 1
    WRITABLE = 2
    REMOTE_HANG_UP = 4
    CLOSED = 8
    ERROR = 16
end

# Callback type for IO events
const OnEventCallback = Function  # signature: (event_loop, io_handle, events::Int, user_data) -> Nothing

# Event loop local object for event-loop-local storage.
#
# This is intentionally *not* parametric: local objects are stored in an
# `IdDict{Any, EventLoopLocalObject}` and typically handled without specialization.
mutable struct EventLoopLocalObject
    key::Any
    object::Any
    on_object_removed::Union{Function, Nothing}
end

EventLoopLocalObject(key, object) = EventLoopLocalObject(key, object, nothing)

function _event_loop_local_object_destroy(obj)
    if obj isa EventLoopLocalObject && obj.on_object_removed !== nothing
        obj.on_object_removed(obj)
    end
    return nothing
end
