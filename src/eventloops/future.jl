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

"""
Create/dereference raw pointers for `Future`.

The returned pointer is only valid as long as the `Future` remains strongly
reachable from Julia code.
"""
function Base.wait(f::Future{T}) where {T}
    while true
        set = @atomic f.set
        set == Int8(1) && return f.result::T
        set == Int8(2) && throw(f.result::Exception)

        lock(f.cond)
        try
            while (@atomic f.set) == Int8(0)
                wait(f.cond)
            end
        finally
            unlock(f.cond)
        end

        set = @atomic f.set
        if set == Int8(1)
            return f.result::T
        elseif set == Int8(2)
            throw(f.result::Exception)
        end
    end
end

Base.notify(f::Future{Nothing}) = notify(f, nothing)

function Base.notify(f::Future{T}, x) where {T}
    lock(f.cond)
    try
        if (@atomic f.set) == Int8(0)
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
