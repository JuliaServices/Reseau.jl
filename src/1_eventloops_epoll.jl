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
Per-poller reusable Linux backend buffers.
"""
mutable struct EpollBackendScratch
    events::Vector{EpollEvent}
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
    state.kq = epfd
    state.wake_ident = UInt(efd)
    state.backend_scratch = EpollBackendScratch(Vector{EpollEvent}(undef, MAX_EPOLL_EVENTS))
    return Int32(0)
end

"""
Close epoll backend resources.
"""
function _backend_close!(state::Poller)
    wakefd = Cint(state.wake_ident)
    wakefd > 0 && (@ccall close(wakefd::Cint)::Cint)
    if state.kq != Cint(-1)
        @ccall close(state.kq::Cint)::Cint
        state.kq = Cint(-1)
    end
    state.wake_ident = UInt(0)
    state.backend_scratch = nothing
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
    events = UInt32(0)
    _mode_has_read(mode) && (events |= EPOLLIN)
    _mode_has_write(mode) && (events |= EPOLLOUT)
    events == UInt32(0) && return Int32(Base.Libc.EINVAL)
    events |= (EPOLLRDHUP | EPOLLET)
    ev = Ref(_make_epoll_event(events, token))
    ctl = @ccall epoll_ctl(
        state.kq::Cint,
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
    ev = Ref(_make_epoll_event(UInt32(0), UInt64(0)))
    ctl = @ccall epoll_ctl(
        state.kq::Cint,
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
"""
function _backend_wake!(state::Poller)::Int32
    state.kq == Cint(-1) && return Int32(0)
    _, ok = @atomicreplace(state.wak_sig, UInt32(0) => UInt32(1))
    ok || return Int32(0)
    wakefd = Cint(state.wake_ident)
    one = Ref{UInt64}(1)
    while true
        n = @ccall gc_safe = true write(
            wakefd::Cint,
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
            @atomic :release state.wak_sig = UInt32(0)
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
    scratch_any = state.backend_scratch
    scratch_any isa EpollBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::EpollBackendScratch
    events = scratch.events
    waitms = _epoll_wait_timeout_ms(delay_ns)
    while true
        n = GC.@preserve events begin
            @ccall gc_safe = true epoll_wait(
                state.kq::Cint,
                pointer(events)::Ptr{EpollEvent},
                Cint(length(events))::Cint,
                waitms::Cint,
            )::Cint
        end
        if n == -1
            errno = Int32(Base.Libc.errno())
            if errno == Int32(Base.Libc.EINTR)
                waitms > 0 && return Int32(0)
                continue
            end
            return errno
        end
        for i in 1:n
            ev = events[i]
            ev.events == UInt32(0) && continue
            event_data = _epoll_event_data(ev)
            if event_data == _WAKE_TOKEN
                if delay_ns != 0
                    one = Ref{UInt64}(0)
                    _ = @ccall gc_safe = true read(
                        Cint(state.wake_ident)::Cint,
                        one::Ref{UInt64},
                        Csize_t(sizeof(UInt64))::Csize_t,
                    )::Cssize_t
                    @atomic :release state.wak_sig = UInt32(0)
                end
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
