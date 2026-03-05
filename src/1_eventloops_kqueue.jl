@static if Sys.isapple()

const EVFILT_READ = Int16(-1)
const EVFILT_WRITE = Int16(-2)
const EVFILT_USER = Int16(-10)
const EV_ADD = UInt16(0x0001)
const EV_DELETE = UInt16(0x0002)
const EV_ENABLE = UInt16(0x0004)
const EV_CLEAR = UInt16(0x0020)
const EV_EOF = UInt16(0x8000)
const EV_ERROR = UInt16(0x4000)
const NOTE_TRIGGER = UInt32(0x01000000)
const F_GETFD = Cint(1)
const F_SETFD = Cint(2)
const FD_CLOEXEC = Cint(0x0001)
const WAKE_IDENT = UInt(1)
const MAX_KQUEUE_EVENTS = 64

"""
Mirror of Darwin's `struct kevent`.
"""
struct Kevent
    ident::UInt
    filter::Int16
    flags::UInt16
    fflags::UInt32
    data::Int
    udata::Ptr{Cvoid}
end

"""
Mirror of `struct timespec`.
"""
struct Timespec
    tv_sec::Clong
    tv_nsec::Clong
end

"""
Per-poller reusable backend buffers to avoid steady-state allocations.
"""
mutable struct KqueueBackendScratch
    events::Vector{Kevent}
    timeout_ref::Base.RefValue{Timespec}
end

@inline function _make_kevent(
        ident::UInt,
        filter::Int16,
        flags::UInt16,
        fflags::UInt32,
        data::Int,
        udata::Ptr{Cvoid},
    )
    return Kevent(ident, filter, flags, fflags, data, udata)
end

function _fcntl(fd::Cint, cmd::Cint)::Cint
    return @ccall fcntl(fd::Cint, cmd::Cint)::Cint
end

function _fcntl(fd::Cint, cmd::Cint, arg::Cint)::Cint
    return @ccall fcntl(fd::Cint, cmd::Cint, arg::Cint)::Cint
end

function _set_close_on_exec!(fd::Cint)::Int32
    flags = _fcntl(fd, F_GETFD)
    flags == -1 && return Int32(Base.Libc.errno())
    _fcntl(fd, F_SETFD, Cint(flags | FD_CLOEXEC)) == -1 && return Int32(Base.Libc.errno())
    return Int32(0)
end

"""
Initialize the kqueue fd and wakeup event.
"""
function _backend_init!(state::Poller)::Int32
    kq = @ccall kqueue()::Cint
    kq == -1 && return Int32(Base.Libc.errno())
    errno = _set_close_on_exec!(kq)
    if errno != Int32(0)
        @ccall close(kq::Cint)::Cint
        return errno
    end
    state.kq = kq
    state.wake_ident = WAKE_IDENT
    change = Ref(_make_kevent(state.wake_ident, EVFILT_USER, EV_ADD | EV_CLEAR | EV_ENABLE, UInt32(0), 0, C_NULL))
    while true
        n = @ccall kevent(
            kq::Cint,
            change::Ref{Kevent},
            1::Cint,
            C_NULL::Ptr{Kevent},
            0::Cint,
            C_NULL::Ptr{Timespec},
        )::Cint
        if n == -1
            errno = Int32(Base.Libc.errno())
            errno == Int32(Base.Libc.EINTR) && continue
            @ccall close(kq::Cint)::Cint
            state.kq = Cint(-1)
            return errno
        end
        break
    end
    state.backend_scratch = KqueueBackendScratch(Vector{Kevent}(undef, MAX_KQUEUE_EVENTS), Ref(Timespec(0, 0)))
    return Int32(0)
end

"""
Close backend resources.
"""
function _backend_close!(state::Poller)
    if state.kq != Cint(-1)
        @ccall close(state.kq::Cint)::Cint
        state.kq = Cint(-1)
    end
    state.backend_scratch = nothing
    return nothing
end

"""
Register read/write readiness filters for `fd`.
"""
function _backend_open_fd!(
        state::Poller,
        fd::Cint,
        mode::PollMode.T,
        token::UInt64,
    )::Int32
    changes = Kevent[]
    udata = Ptr{Cvoid}(UInt(token))
    if _mode_has_read(mode)
        push!(changes, _make_kevent(UInt(fd), EVFILT_READ, EV_ADD | EV_CLEAR, UInt32(0), 0, udata))
    end
    if _mode_has_write(mode)
        push!(changes, _make_kevent(UInt(fd), EVFILT_WRITE, EV_ADD | EV_CLEAR, UInt32(0), 0, udata))
    end
    isempty(changes) && return Int32(Base.Libc.EINVAL)
    n = GC.@preserve changes begin
        @ccall kevent(
            state.kq::Cint,
            pointer(changes)::Ptr{Kevent},
            Cint(length(changes))::Cint,
            C_NULL::Ptr{Kevent},
            0::Cint,
            C_NULL::Ptr{Timespec},
        )::Cint
    end
    n == -1 && return Int32(Base.Libc.errno())
    return Int32(0)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    _ = state
    _ = registration
    _ = mode
    return Int32(0)
end

"""
Unregister read/write filters for `fd`.
"""
function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    _ = state
    _ = fd
    # Follow Go's kqueue path: close(fd) implicitly removes attached knotes.
    # Explicit EV_DELETE here adds syscall/load without correctness benefit.
    return Int32(0)
end

"""
Wake a blocking `kevent` call via EVFILT_USER + NOTE_TRIGGER.
"""
function _backend_wake!(state::Poller)::Int32
    state.kq == Cint(-1) && return Int32(0)
    _, ok = @atomicreplace(state.wak_sig, UInt32(0) => UInt32(1))
    ok || return Int32(0)
    trigger = Ref(_make_kevent(state.wake_ident, EVFILT_USER, UInt16(0), NOTE_TRIGGER, 0, C_NULL))
    while true
        n = @ccall kevent(
            state.kq::Cint,
            trigger::Ref{Kevent},
            1::Cint,
            C_NULL::Ptr{Kevent},
            0::Cint,
            C_NULL::Ptr{Timespec},
        )::Cint
        if n == -1
            errno = Int32(Base.Libc.errno())
            errno == Int32(Base.Libc.EINTR) && continue
            @atomic :release state.wak_sig = UInt32(0)
            return errno
        end
        break
    end
    return Int32(0)
end

"""
Poll kqueue once and dispatch decoded events through `_dispatch_ready_event!`.
"""
# TODO(phase-2): Revisit this `delay_ns` polling contract if we see scheduler or
# throughput issues; Go's `runtime.netpoll(delay)` is tightly integrated with its
# runtime timer/scheduler loop, while we currently drive polling from a foreign thread.
function _backend_poll_once!(state::Poller, delay_ns::Int64)::Int32
    scratch_any = state.backend_scratch
    scratch_any isa KqueueBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::KqueueBackendScratch
    events = scratch.events
    timeout_ref = scratch.timeout_ref
    timeout_ptr = Ptr{Timespec}(C_NULL)
    if delay_ns == 0
        timeout_ref[] = Timespec(0, 0)
        timeout_ptr = Base.unsafe_convert(Ptr{Timespec}, timeout_ref)
    elseif delay_ns > 0
        timeout_ref[] = _ns_to_timespec(delay_ns)
        timeout_ptr = Base.unsafe_convert(Ptr{Timespec}, timeout_ref)
    end
    n = GC.@preserve events timeout_ref begin
        @ccall gc_safe = true kevent(
            state.kq::Cint,
            C_NULL::Ptr{Kevent},
            0::Cint,
            pointer(events)::Ptr{Kevent},
            Cint(length(events))::Cint,
            timeout_ptr::Ptr{Timespec},
        )::Cint
    end
    if n == -1
        errno = Int32(Base.Libc.errno())
        errno == Int32(Base.Libc.EINTR) && return Int32(0)
        errno == Int32(Base.Libc.ETIMEDOUT) && return Int32(0)
        return errno
    end
    for i in 1:n
        ev = events[i]
        if ev.filter == EVFILT_USER && ev.ident == state.wake_ident
            delay_ns != 0 && (@atomic :release state.wak_sig = UInt32(0))
            continue
        end
        mode = _decode_event_mode(ev.filter, ev.flags)
        mode === nothing && continue
        fd = Cint(ev.ident)
        token = UInt64(UInt(ev.udata))
        # Match Go semantics: treat exactly-EV_ERROR as a poller error event.
        errored = ev.flags == EV_ERROR
        _dispatch_ready_event!(state, PollEvent(fd, token, mode, errored))
    end
    return Int32(0)
end

function _decode_event_mode(filter::Int16, flags::UInt16)
    if filter == EVFILT_READ
        if (flags & EV_EOF) != 0
            return PollMode.READWRITE
        end
        return PollMode.READ
    end
    if filter == EVFILT_WRITE
        return PollMode.WRITE
    end
    return nothing
end

function _ns_to_timespec(delay_ns::Int64)::Timespec
    clamped_ns = min(delay_ns, Int64(1_000_000_000_000_000))
    sec = clamped_ns ÷ Int64(1_000_000_000)
    nsec = clamped_ns % Int64(1_000_000_000)
    return Timespec(Clong(sec), Clong(nsec))
end

else

function _backend_init!(state::Poller)::Int32
    _ = state
    return Int32(Base.Libc.ENOSYS)
end

function _backend_close!(state::Poller)
    _ = state
    return nothing
end

function _backend_open_fd!(state::Poller, fd::Cint, mode::PollMode.T, token::UInt64)::Int32
    _ = state
    _ = fd
    _ = mode
    _ = token
    return Int32(Base.Libc.ENOSYS)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    _ = state
    _ = registration
    _ = mode
    return Int32(Base.Libc.ENOSYS)
end

function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    _ = state
    _ = fd
    return Int32(Base.Libc.ENOSYS)
end

function _backend_wake!(state::Poller)::Int32
    _ = state
    return Int32(Base.Libc.ENOSYS)
end

function _backend_poll_once!(state::Poller, delay_ns::Int64)::Int32
    _ = state
    _ = delay_ns
    return Int32(Base.Libc.ENOSYS)
end

end
