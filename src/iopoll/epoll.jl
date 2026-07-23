const EPOLLIN = UInt32(0x001)
const EPOLLOUT = UInt32(0x004)
const EPOLLERR = UInt32(0x008)
const EPOLLHUP = UInt32(0x010)
const EPOLLRDHUP = UInt32(0x2000)
const EPOLLET = UInt32(0x80000000)
const EPOLL_CTL_ADD = Cint(1)
const EPOLL_CTL_DEL = Cint(2)
const EPOLL_CLOEXEC = Cint(0x80000)
const EFD_NONBLOCK = Cint(0x800)
const EFD_CLOEXEC = Cint(0x80000)
const MAX_EPOLL_EVENTS = 128
const MAX_GC_UNSAFE_EPOLL_WAIT_MS = Cint(25)
const _WAKE_TOKEN = UInt64(0)

# Mirror of Linux `struct epoll_event`.
# Go carries architecture-specific layouts here as well:
# amd64/386 use unaligned data payload at offset 4, while most other
# architectures use a 4-byte pad and place the payload at offset 8.
@static if Sys.ARCH == :x86_64 || Sys.ARCH == :i686
struct EpollEvent
    events::UInt32
    data_lo::UInt32
    data_hi::UInt32
end
@inline function _epoll_event_data(data::UInt64)::Tuple{UInt32, UInt32}
    return UInt32(data & UInt64(0xffff_ffff)), UInt32(data >> 32)
end
@inline function _epoll_event_data(ev::EpollEvent)::UInt64
    return UInt64(ev.data_lo) | (UInt64(ev.data_hi) << 32)
end
@inline function _make_epoll_event(events::UInt32, data::UInt64)::EpollEvent
    data_lo, data_hi = _epoll_event_data(data)
    return EpollEvent(events, data_lo, data_hi)
end
else
struct EpollEvent
    events::UInt32
    _pad::UInt32
    data::UInt64
end
@inline function _make_epoll_event(events::UInt32, data::UInt64)::EpollEvent
    return EpollEvent(events, UInt32(0), data)
end
@inline function _epoll_event_data(ev::EpollEvent)::UInt64
    return ev.data
end
end

"""
Typed epoll backend state attached to the shared poller.
"""
mutable struct EpollBackendState <: BackendState
    epfd::Cint
    wakefd::Cint
    # C-allocated (`Libc.malloc`) buffer with room for MAX_EPOLL_EVENTS
    # entries, freed in `_backend_close!`. The buffer must live off the Julia
    # heap: `epoll_wait` runs as a GC-safe ccall, so the GC can run while the
    # kernel fills the buffer, and gVisor's userspace epoll has crashed
    # writing into Julia-heap memory during concurrent GC. Plain C memory
    # keeps event delivery entirely outside GC-managed pages.
    events::Ptr{EpollEvent}
    wait_gc_safe::Bool
    @atomic wake_sig::UInt32
end

@inline function _epoll_wait_gc_safe_enabled()::Bool
    value = strip(lowercase(get(ENV, "RESEAU_EPOLL_WAIT_GCSAFE", "1")))
    return !(isempty(value) || value == "0" || value == "false" || value == "no" || value == "off")
end

"""
Initialize epoll fd and eventfd wake source.
"""
function _backend_init!(state::Poller)::Int32
    epfd = @ccall epoll_create1(EPOLL_CLOEXEC::Cint)::Cint
    epfd == -1 && return Int32(Base.Libc.errno())
    efd = @ccall eventfd(UInt32(0)::Cuint, (EFD_CLOEXEC | EFD_NONBLOCK)::Cint)::Cint
    if efd == -1
        @ccall close(epfd::Cint)::Cint
        return Int32(Base.Libc.errno())
    end
    ev = Ref(_make_epoll_event(EPOLLIN, _WAKE_TOKEN))
    ctl = @ccall epoll_ctl(
        epfd::Cint,
        EPOLL_CTL_ADD::Cint,
        efd::Cint,
        ev::Ref{EpollEvent},
    )::Cint
    if ctl == -1
        errno = Int32(Base.Libc.errno())
        @ccall close(efd::Cint)::Cint
        @ccall close(epfd::Cint)::Cint
        return errno
    end
    events = convert(Ptr{EpollEvent}, Base.Libc.malloc(MAX_EPOLL_EVENTS * sizeof(EpollEvent)))
    if events == C_NULL
        @ccall close(efd::Cint)::Cint
        @ccall close(epfd::Cint)::Cint
        return Int32(Base.Libc.ENOMEM)
    end
    state.backend_state = EpollBackendState(epfd, efd, events, _epoll_wait_gc_safe_enabled(), UInt32(0))
    return Int32(0)
end

"""
Close epoll backend resources.

Only safe after the poller thread has exited (`shutdown!` waits on
`shutdown_event` before calling this): the default backend wait has no timeout
cap, so the thread can be parked in `epoll_wait` indefinitely, and freeing the
event buffer under a live wait would hand the kernel a dangling pointer.
"""
function _backend_close!(state::Poller)
    backend = state.backend_state
    if backend isa EpollBackendState
        epoll = backend::EpollBackendState
        epoll.wakefd > 0 && (@ccall close(epoll.wakefd::Cint)::Cint)
        if epoll.epfd != Cint(-1)
            @ccall close(epoll.epfd::Cint)::Cint
            epoll.epfd = Cint(-1)
        end
        epoll.wakefd = Cint(-1)
        if epoll.events != C_NULL
            Base.Libc.free(epoll.events)
            epoll.events = Ptr{EpollEvent}(C_NULL)
        end
    end
    state.backend_state = nothing
    return nothing
end

"""
Register fd interest with epoll.
"""
function _backend_open_fd!(
        state::Poller,
        fd::Cint,
        mode::PollMode.T,
        token::UInt64,
    )::Int32
    backend = state.backend_state
    backend isa EpollBackendState || return Int32(Base.Libc.ENOSYS)
    epoll = backend::EpollBackendState
    events = UInt32(0)
    _mode_has_read(mode) && (events |= EPOLLIN)
    _mode_has_write(mode) && (events |= EPOLLOUT)
    events == UInt32(0) && return Int32(Base.Libc.EINVAL)
    events |= (EPOLLRDHUP | EPOLLET)
    ev = Ref(_make_epoll_event(events, token))
    ctl = @ccall epoll_ctl(
        epoll.epfd::Cint,
        EPOLL_CTL_ADD::Cint,
        fd::Cint,
        ev::Ref{EpollEvent},
    )::Cint
    ctl == -1 && return Int32(Base.Libc.errno())
    return Int32(0)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    _ = state
    _ = registration
    _ = mode
    return Int32(0)
end

"""
Remove fd from epoll interest set.
"""
function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    backend = state.backend_state
    backend isa EpollBackendState || return Int32(Base.Libc.ENOSYS)
    epoll = backend::EpollBackendState
    ev = Ref(_make_epoll_event(UInt32(0), UInt64(0)))
    ctl = @ccall epoll_ctl(
        epoll.epfd::Cint,
        EPOLL_CTL_DEL::Cint,
        fd::Cint,
        ev::Ref{EpollEvent},
    )::Cint
    if ctl == -1
        errno = Int32(Base.Libc.errno())
        # Linux can race with implicit fd removal; treat as already-gone.
        (errno == Int32(Base.Libc.ENOENT) || errno == Int32(Base.Libc.EBADF)) && return Int32(0)
        return errno
    end
    return Int32(0)
end

"""
Wake a blocking epoll_wait via eventfd.

The write stays a plain (GC-unsafe) ccall on purpose: the eventfd is
EFD_NONBLOCK so the write cannot stall GC, and keeping the thread GC-unsafe
means the kernel never reads the Julia-heap `Ref` while the GC runs — the
same gVisor hazard the C-allocated event buffer avoids on the wait side.
See `_maybe_wake_for_earlier_time!` for the wake coalescing contract.
"""
function _backend_wake!(state::Poller)::Int32
    backend = state.backend_state
    backend isa EpollBackendState || return Int32(Base.Libc.ENOSYS)
    epoll = backend::EpollBackendState
    epoll.epfd == Cint(-1) && return Int32(0)
    _, ok = @atomicreplace(epoll.wake_sig, UInt32(0) => UInt32(1))
    ok || return Int32(0)
    one = Ref{UInt64}(1)
    while true
        n = @ccall write(
            epoll.wakefd::Cint,
            one::Ref{UInt64},
            Csize_t(sizeof(UInt64))::Csize_t,
        )::Cssize_t
        if n == Cssize_t(sizeof(UInt64))
            return Int32(0)
        end
        if n == Cssize_t(-1)
            errno = Int32(Base.Libc.errno())
            errno == Int32(Base.Libc.EINTR) && continue
            errno == Int32(Base.Libc.EAGAIN) && return Int32(0)
            @atomic :release epoll.wake_sig = UInt32(0)
            return errno
        end
    end
end

@inline function _epoll_wait_timeout_ms(delay_ns::Int64)::Cint
    if delay_ns < 0
        return Cint(-1)
    end
    if delay_ns == 0
        return Cint(0)
    end
    if delay_ns < Int64(1_000_000)
        return Cint(1)
    end
    if delay_ns < Int64(1_000_000_000_000_000)
        return Cint(delay_ns ÷ Int64(1_000_000))
    end
    return Cint(1_000_000_000)
end

@inline function _epoll_effective_wait_timeout_ms(waitms::Cint, wait_gc_safe::Bool)::Cint
    wait_gc_safe && return waitms
    return waitms < 0 ? MAX_GC_UNSAFE_EPOLL_WAIT_MS : min(waitms, MAX_GC_UNSAFE_EPOLL_WAIT_MS)
end

@inline function _epoll_wait!(
        epoll::EpollBackendState,
        events::Ptr{EpollEvent},
        waitms::Cint,
    )::Cint
    if epoll.wait_gc_safe
        return @gcsafe_ccall epoll_wait(
            epoll.epfd::Cint,
            events::Ptr{EpollEvent},
            Cint(MAX_EPOLL_EVENTS)::Cint,
            waitms::Cint,
        )::Cint
    end
    return @ccall epoll_wait(
        epoll.epfd::Cint,
        events::Ptr{EpollEvent},
        Cint(MAX_EPOLL_EVENTS)::Cint,
        waitms::Cint,
    )::Cint
end

@inline function _decode_epoll_mode(events::UInt32)
    mode = UInt8(0x00)
    (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != UInt32(0) && (mode |= UInt8(PollMode.READ))
    (events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != UInt32(0) && (mode |= UInt8(PollMode.WRITE))
    mode == 0x00 && return nothing
    return PollMode.T(mode)
end

"""
Poll epoll once and dispatch decoded events.
"""
function _backend_poll_once!(state::Poller, delay_ns::Int64)::Int32
    backend = state.backend_state
    backend isa EpollBackendState || return Int32(Base.Libc.ENOSYS)
    epoll = backend::EpollBackendState
    events = epoll.events
    events == C_NULL && return Int32(Base.Libc.EBADF)
    waitms = _epoll_effective_wait_timeout_ms(
        _epoll_wait_timeout_ms(delay_ns),
        epoll.wait_gc_safe,
    )
    # GC-safe waiting is the default and lets an idle poller sleep until its
    # eventfd wakes. Trimmed or embedded runtimes that cannot safely return
    # from a GC-safe call on this foreign pthread can set
    # RESEAU_EPOLL_WAIT_GCSAFE=0. That path stays GC-unsafe and caps each wait
    # so the poller can delay a collection by at most 25ms.
    while true
        n = _epoll_wait!(epoll, events, waitms)
        if n == Cint(-1)
            # The GC-safe path can wait for a running collection before it
            # returns here. Its glibc/musl futex wait does not clobber errno.
            errno = Int32(Base.Libc.errno())
            if errno == Int32(Base.Libc.EINTR)
                waitms > 0 && return Int32(0)
                continue
            end
            return errno
        end
        for i in 1:n
            ev = unsafe_load(events, i)
            ev.events == UInt32(0) && continue
            event_data = _epoll_event_data(ev)
            if event_data == _WAKE_TOKEN
                # Match the IOCP wake path: once the eventfd wake is consumed,
                # always drain it and clear the coalescing latch. Leaving the
                # latch set after a zero-timeout poll can suppress the next
                # real wake and strand later timers/deadline updates. The
                # drain stays a plain ccall: the counter is known nonzero, so
                # the read cannot block, and the kernel must not write the
                # Julia-heap `Ref` while this thread is GC-safe.
                one = Ref{UInt64}(0)
                _ = @ccall read(
                    epoll.wakefd::Cint,
                    one::Ref{UInt64},
                    Csize_t(sizeof(UInt64))::Csize_t,
                )::Cssize_t
                @atomic :release epoll.wake_sig = UInt32(0)
                continue
            end
            mode = _decode_epoll_mode(ev.events)
            mode === nothing && continue
            errored = ev.events == EPOLLERR
            _dispatch_ready_event!(state, PollEvent(Cint(-1), event_data, mode, errored))
        end
        return Int32(0)
    end
end
