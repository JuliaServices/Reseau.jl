# Trim-safe handler dispatch wrappers so hot channel send paths can avoid
# abstract-method dispatch on handler reference types.
struct _ChannelSlotReadCallWrapper <: Function end
@inline function (::_ChannelSlotReadCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    f(slot, message)
    return nothing
end

@generated function _channel_slot_read_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotReadCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct ChannelHandlerReadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerReadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_read_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerReadCallable(ptr, objptr, objref)
end

function ChannelHandlerReadCallable(handler::H) where {H}
    return ChannelHandlerReadCallable(_ChannelHandlerReadDispatch(handler))
end

@inline function (f::ChannelHandlerReadCallable)(slot, message)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    message_ptr, message_root = _callback_obj_to_ptr_and_root(message)
    GC.@preserve slot_root message_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), f.objptr, slot_ptr, message_ptr)
    end
    return nothing
end

struct _ChannelSlotWriteCallWrapper <: Function end
@inline function (::_ChannelSlotWriteCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    f(slot, message)
    return nothing
end

@generated function _channel_slot_write_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotWriteCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct ChannelHandlerWriteCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerWriteCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_write_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerWriteCallable(ptr, objptr, objref)
end

function ChannelHandlerWriteCallable(handler::H) where {H}
    return ChannelHandlerWriteCallable(_ChannelHandlerWriteDispatch(handler))
end

@inline function (f::ChannelHandlerWriteCallable)(slot, message)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    message_ptr, message_root = _callback_obj_to_ptr_and_root(message)
    GC.@preserve slot_root message_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), f.objptr, slot_ptr, message_ptr)
    end
    return nothing
end

struct _ChannelSlotIncrementWindowCallWrapper <: Function end
@inline function (::_ChannelSlotIncrementWindowCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        size::Csize_t,
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    f(slot, size)
    return nothing
end

@generated function _channel_slot_increment_window_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotIncrementWindowCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Csize_t))
    end
end

struct ChannelHandlerIncrementWindowCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerIncrementWindowCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_increment_window_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerIncrementWindowCallable(ptr, objptr, objref)
end

function ChannelHandlerIncrementWindowCallable(handler::H) where {H}
    return ChannelHandlerIncrementWindowCallable(_ChannelHandlerIncrementWindowDispatch(handler))
end

@inline function (f::ChannelHandlerIncrementWindowCallable)(slot, size::Csize_t)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    GC.@preserve slot_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t), f.objptr, slot_ptr, size)
    end
    return nothing
end

struct _ChannelSlotShutdownCallWrapper <: Function end
@inline function (::_ChannelSlotShutdownCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        direction::UInt8,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    f(
        slot,
        ChannelDirection.T(direction),
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

@generated function _channel_slot_shutdown_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotShutdownCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, UInt8, Int, Bool))
    end
end

struct ChannelHandlerShutdownCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerShutdownCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_shutdown_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerShutdownCallable(ptr, objptr, objref)
end

function ChannelHandlerShutdownCallable(handler::H) where {H}
    return ChannelHandlerShutdownCallable(_ChannelHandlerShutdownDispatch(handler))
end

@inline function (f::ChannelHandlerShutdownCallable)(
        slot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    GC.@preserve slot_root begin
        ccall(
            f.ptr,
            Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt8, Int, Bool),
            f.objptr,
            slot_ptr,
            UInt8(direction),
            error_code,
            free_scarce_resources_immediately,
        )
    end
    return nothing
end

struct _ChannelSlotMessageOverheadCallWrapper <: Function end
@inline function (::_ChannelSlotMessageOverheadCallWrapper)(f::F)::Csize_t where {F <: Function}
    return f()
end

@generated function _channel_slot_message_overhead_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotMessageOverheadCallWrapper()), Csize_t, (Ref{$F},))
    end
end

struct ChannelHandlerMessageOverheadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerMessageOverheadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_message_overhead_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerMessageOverheadCallable(ptr, objptr, objref)
end

function ChannelHandlerMessageOverheadCallable(handler::H) where {H}
    return ChannelHandlerMessageOverheadCallable(_ChannelHandlerMessageOverheadDispatch(handler))
end

@inline function (f::ChannelHandlerMessageOverheadCallable)()::Csize_t
    return ccall(f.ptr, Csize_t, (Ptr{Cvoid},), f.objptr)
end

struct _ChannelSlotDestroyCallWrapper <: Function end
@inline function (::_ChannelSlotDestroyCallWrapper)(f::F)::Nothing where {F <: Function}
    f()
    return nothing
end

@generated function _channel_slot_destroy_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotDestroyCallWrapper()), Cvoid, (Ref{$F},))
    end
end

struct ChannelHandlerDestroyCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerDestroyCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_destroy_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerDestroyCallable(ptr, objptr, objref)
end

function ChannelHandlerDestroyCallable(handler::H) where {H}
    return ChannelHandlerDestroyCallable(_ChannelHandlerDestroyDispatch(handler))
end

@inline function (f::ChannelHandlerDestroyCallable)()::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid},), f.objptr)
    return nothing
end

struct _ChannelSlotTriggerReadCallWrapper <: Function end
@inline function (::_ChannelSlotTriggerReadCallWrapper)(f::F)::Nothing where {F <: Function}
    f()
    return nothing
end

@generated function _channel_slot_trigger_read_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotTriggerReadCallWrapper()), Cvoid, (Ref{$F},))
    end
end

struct ChannelHandlerTriggerReadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerTriggerReadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_trigger_read_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerTriggerReadCallable(ptr, objptr, objref)
end

function ChannelHandlerTriggerReadCallable(handler::H) where {H}
    return ChannelHandlerTriggerReadCallable(_ChannelHandlerTriggerReadDispatch(handler))
end

@inline function (f::ChannelHandlerTriggerReadCallable)()::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid},), f.objptr)
    return nothing
end
