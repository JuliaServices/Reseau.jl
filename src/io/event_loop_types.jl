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

# Event loop local object for thread-local storage
mutable struct EventLoopLocalObject{T}
    key::Any
    object::T
    on_object_removed::Union{Function, Nothing}
end

function EventLoopLocalObject(key, object::T) where {T}
    return EventLoopLocalObject{T}(key, object, nothing)
end

function _event_loop_local_object_destroy(obj)
    if obj isa EventLoopLocalObject && obj.on_object_removed !== nothing
        obj.on_object_removed(obj)
    end
    return nothing
end
