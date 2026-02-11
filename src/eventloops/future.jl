# Reseau Future — trim-safe, zero-callback future
# Adapted from Agentif Future pattern. Stores no callbacks —
# callers use `wait(f)` to block, `notify(f, value)` to complete.

mutable struct Future{T}
    const cond::Base.Threads.Condition
    @atomic set::Int8 # 0 = pending, 1 = result is T, 2 = result is Exception
    result::Union{Exception, T}
    Future{T}() where {T} = new{T}(Base.Threads.Condition(), Int8(0))
end

Future() = Future{Nothing}()
Base.pointer(f::Future) = pointer_from_objref(f)
Future(ptr::Ptr) = unsafe_pointer_to_objref(ptr)::Future
Future{T}(ptr::Ptr) where {T} = unsafe_pointer_to_objref(ptr)::Future{T}

function Base.wait(f::Future{T}) where {T}
    set = @atomic f.set
    set == Int8(1) && return f.result::T
    set == Int8(2) && throw(f.result::Exception)
    lock(f.cond)
    try
        set = f.set
        set == Int8(1) && return f.result::T
        set == Int8(2) && throw(f.result::Exception)
        wait(f.cond)
    finally
        unlock(f.cond)
    end
    if f.set == Int8(1)
        return f.result::T
    else
        @assert isdefined(f, :result)
        throw(f.result::Exception)
    end
end

Base.notify(f::Future{Nothing}) = notify(f, nothing)

function Base.notify(f::Future{T}, x) where {T}
    lock(f.cond)
    try
        if f.set == Int8(0)
            if x isa Exception
                f.result = x
                @atomic :release f.set = Int8(2)
            else
                f.result = convert(T, x)
                @atomic :release f.set = Int8(1)
            end
            notify(f.cond)
        end
    finally
        unlock(f.cond)
    end
    return nothing
end

function cancel!(f::Future)
    notify(f, ReseauError(ERROR_IO_OPERATION_CANCELLED))
end
