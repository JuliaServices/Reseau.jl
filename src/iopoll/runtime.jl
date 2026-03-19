"""
Global singleton state for the runtime poller.
"""
const POLLER = Ref{Poller}()
const _POLLER_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _pthread_t = UInt

@inline function _is_generating_output()::Bool
    return ccall(:jl_generating_output, Cint, ()) == 1
end

function _throw_errno(op::AbstractString, errno::Int32)
    throw(SystemError(op, Int(errno)))
end

@inline function _next_token!(state::Poller)::UInt64
    return @atomic state.next_token += UInt64(1)
end

@inline function _runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux() || Sys.iswindows()
end

function _new_registration(fd::Cint, token::UInt64, mode::PollMode.T)::Registration
    return Registration(fd, token, mode, PollWaiter(), PollWaiter(), false)
end

"""
    current_registration(pd)

Return the active `Registration` corresponding to `pd`, or `nothing` if `pd`
has been deregistered or replaced.

This extra indirection is what lets higher layers validate descriptor identity
without trusting a cached registration reference through close/re-register
races.
"""
function current_registration(pd::PollState)
    isassigned(POLLER) || return nothing
    state = POLLER[]
    lock(state.lock)
    try
        registration = get(() -> nothing, state.registrations_by_token, pd.token)
        if registration === nothing
            return nothing
        end
        registration.fd == pd.sysfd || return nothing
        registration.pollstate === pd || return nothing
        return registration
    finally
        unlock(state.lock)
    end
end

function _notify_registration!(
        registration::Registration,
        mode::PollMode.T,
        reason::PollWakeReason.T = PollWakeReason.READY,
    )
    if _mode_has_read(mode) && _mode_has_read(registration.mode)
        pollnotify!(registration.read_waiter, reason)
    end
    if _mode_has_write(mode) && _mode_has_write(registration.mode)
        pollnotify!(registration.write_waiter, reason)
    end
    return nothing
end

"""
    _spawn_detached_thread(name, thread_fn, arg=nothing)

Start a detached native OS thread that runs `thread_fn(::Ptr{Cvoid})`.
This intentionally does not keep a join handle; shutdown is coordinated via
poller state (`running`) and backend wakeups.
"""
function _spawn_detached_thread(
        name::AbstractString,
        thread_fn::Ref{Ptr{Cvoid}},
        arg = nothing,
    )
    _ = name
    thread_arg = arg === nothing ? C_NULL : pointer_from_objref(arg)
    @static if Sys.iswindows()
        handle = ccall(
            (:CreateThread, "kernel32"), Ptr{Cvoid},
            (Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}),
            C_NULL, Csize_t(0), thread_fn[], thread_arg, UInt32(0), C_NULL,
        )
        handle == C_NULL && throw(ArgumentError("error creating poller thread"))
        _ = ccall((:CloseHandle, "kernel32"), Int32, (Ptr{Cvoid},), handle)
    else
        pthread_ref = Ref{_pthread_t}(0)
        create_ret = ccall(
            :pthread_create, Cint,
            (Ref{_pthread_t}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            pthread_ref, C_NULL, thread_fn[], thread_arg,
        )
        create_ret != 0 && throw(SystemError("pthread_create", Int(create_ret)))
        detach_ret = ccall(:pthread_detach, Cint, (_pthread_t,), pthread_ref[])
        detach_ret != 0 && throw(SystemError("pthread_detach", Int(detach_ret)))
    end
    return nothing
end

"""
    init!()

Initialize the runtime poller state and start the dedicated poller thread.

Returns the live `Poller` singleton.

Throws `ArgumentError` if the current platform is unsupported and `SystemError`
if backend initialization or thread creation fails.
"""
function init!()::Poller
    if isassigned(POLLER)
        state = POLLER[]
        (@atomic state.running) && return state
    end
    _runtime_supported() || throw(ArgumentError("iopoll backend is currently supported on macOS, Linux, and Windows"))
    new_state = Poller()
    errno = _backend_init!(new_state)
    errno == Int32(0) || _throw_errno("iopoll backend init", errno)
    @atomic new_state.running = true
    POLLER[] = new_state
    try
        _spawn_detached_thread(
            "reseau-iopoll-poller",
            _POLLER_THREAD_ENTRY_C,
            new_state,
        )
    catch
        @atomic :release new_state.running = false
        _backend_close!(new_state)
        POLLER[] = Poller()
        rethrow()
    end
    return new_state
end

"""
    shutdown!()

Stop the dedicated poller thread and tear down backend resources.

Returns `nothing`.

Waiting registrations are notified so blocked Julia tasks can observe close or
shutdown on their next state check instead of remaining parked forever.
"""
function shutdown!()
    isassigned(POLLER) || return nothing
    state = POLLER[]
    registrations = Registration[]
    stop_requested = false
    lock(state.lock)
    try
        append!(registrations, values(state.registrations))
        empty!(state.registrations)
        empty!(state.registrations_by_token)
        if @atomic :acquire state.running
            @atomic :release state.running = false
            stop_requested = true
        end
    finally
        unlock(state.lock)
    end
    for registration in registrations
        _notify_registration!(registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    end
    if stop_requested
        wake_errno = _backend_wake!(state)
        wake_errno == Int32(0) || _throw_errno("iopoll wake", wake_errno)
        wait(state.shutdown_event)
    end
    _backend_close!(state)
    return nothing
end

"""
    register!(fd; mode=PollMode.READWRITE, pollstate=nothing)

Register an fd with the runtime poller and return its `Registration`.

Keyword arguments:
- `mode`: readiness directions to subscribe to
- `pollstate`: optional pre-existing `PollState` to attach to the registration;
  fd wrappers use this so the poller and descriptor wrapper share one state
  object

Returns the created `Registration`.

Throws `ArgumentError` if `mode` is empty, or `SystemError` if the descriptor is
already registered or the backend registration syscall fails.
"""
function register!(fd::Integer; mode::PollMode.T = PollMode.READWRITE, pollstate::Union{Nothing, PollState} = nothing)::Registration
    _mode_is_empty(mode) && throw(ArgumentError("register! requires READ and/or WRITE mode"))
    state = init!()
    cfd = Cint(fd)
    token = UInt64(0)
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || throw(SystemError("iopoll register", Int(Base.Libc.EBADF)))
        existing = get(state.registrations, cfd, nothing)
        existing === nothing || throw(SystemError("iopoll register", Int(Base.Libc.EEXIST)))
        token = _next_token!(state)
        errno = _backend_open_fd!(state, cfd, mode, token)
        if errno == Int32(0)
            registration = _new_registration(cfd, token, mode)
            if pollstate !== nothing
                registration.pollstate = pollstate::PollState
            end
            registration.pollstate.sysfd = cfd
            registration.pollstate.token = token
            state.registrations[cfd] = registration
            state.registrations_by_token[token] = registration
        end
    finally
        unlock(state.lock)
    end
    errno == Int32(0) || _throw_errno("iopoll register", errno)
    return registration::Registration
end

"""
    deregister!(fd)

Unregister an fd from the runtime poller.

Returns `nothing`.

Any parked waiters are notified so they can re-check descriptor state and see
the close/eviction condition promptly.
"""
function deregister!(fd::Integer)
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    cfd = Cint(fd)
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || return nothing
        registration = pop!(state.registrations, cfd, nothing)
        registration === nothing || delete!(state.registrations_by_token, registration.token)
        errno = _backend_close_fd!(state, cfd)
    finally
        unlock(state.lock)
    end
    registration === nothing || _notify_registration!(registration::Registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    errno == Int32(0) || _throw_errno("iopoll deregister", errno)
    return nothing
end

"""
    deregister!(pd)

Unregister the active runtime-poller registration that matches `pd`'s full
descriptor identity.

Unlike `deregister!(fd)`, this overload validates the current registration by
token and `PollState` object identity before removing it. That prevents a stale
`PollState` close from tearing down a newer registration that happens to reuse
the same raw fd value after a shutdown/re-register cycle.
"""
function deregister!(pd::PollState)
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || return nothing
        registration = get(state.registrations_by_token, pd.token, nothing)
        if registration === nothing
            return nothing
        end
        current = registration::Registration
        current.fd == pd.sysfd || return nothing
        current.pollstate === pd || return nothing
        registered = get(state.registrations, pd.sysfd, nothing)
        registered === current || return nothing
        delete!(state.registrations, pd.sysfd)
        delete!(state.registrations_by_token, current.token)
        errno = _backend_close_fd!(state, pd.sysfd)
    finally
        unlock(state.lock)
    end
    registration === nothing || _notify_registration!(registration::Registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    errno == Int32(0) || _throw_errno("iopoll deregister", errno)
    return nothing
end

"""
    arm_waiter!(registration, mode)

Backend hook invoked immediately before waiting so platforms that need explicit
arming (such as IOCP readiness probes) can submit a wait operation.
"""
function arm_waiter!(registration::Registration, mode::PollMode.T)
    _mode_is_empty(mode) && return nothing
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || return nothing
        current = get(state.registrations, registration.fd, nothing)
        current === registration || return nothing
        errno = _backend_arm_waiter!(state, registration, mode)
    finally
        unlock(state.lock)
    end
    errno == Int32(0) || _throw_errno("iopoll arm", errno)
    return nothing
end

"""
    _dispatch_ready_event!(state, event)

Route decoded backend events to registered waiter(s).
"""
function _dispatch_ready_event!(state::Poller, event::PollEvent)
    registration = nothing
    lock(state.lock)
    try
        registration = get(state.registrations_by_token, event.token, nothing)
        if registration === nothing
            return nothing
        end
        if event.fd != Cint(-1)
            registration.fd == event.fd || return nothing
        end
        event.errored && (@atomic :release registration.event_err = true)
    finally
        unlock(state.lock)
    end
    _notify_registration!(registration::Registration, event.mode, PollWakeReason.READY)
    return nothing
end

function _notify_all_waiters!(state::Poller)
    registrations = Registration[]
    timers = TimerState[]
    lock(state.lock)
    try
        append!(registrations, values(state.registrations))
        _discard_stale_time_entries_locked!(state)
        for entry in state.time_heap
            entry.kind == TimeEntryKind.TIMER || continue
            push!(timers, entry.timer::TimerState)
        end
    finally
        unlock(state.lock)
    end
    for registration in registrations
        _notify_registration!(registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    end
    for timer in timers
        _close_timer!(timer)
    end
    return nothing
end

function _poller_thread_main!(state::Poller)
    while @atomic state.running
        delay_ns = _poll_delay_ns(state)
        errno = _backend_poll_once!(state, delay_ns)
        @atomic :release state.poll_until_ns = Int64(0)
        _drain_expired_time_entries!(state, Int64(time_ns()))
        errno == Int32(0) && continue
        if errno == Int32(Base.Libc.EINTR)
            continue
        end
        _notify_all_waiters!(state)
        @atomic :release state.running = false
    end
    notify(state.shutdown_event)
    return nothing
end

function _poller_thread_entry(arg::Ptr{Cvoid})::Ptr{Cvoid}
    state = unsafe_pointer_to_objref(arg)::Poller
    try
        _poller_thread_main!(state)
    catch
        _notify_all_waiters!(state)
        notify(state.shutdown_event)
    end
    return C_NULL
end

function __init__()
    _POLLER_THREAD_ENTRY_C[] = @cfunction(_poller_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
    if _is_generating_output()
        POLLER[] = Poller()
    elseif _runtime_supported()
        @static if Sys.iswindows()
            # Avoid eager foreign-thread startup during module load on Windows.
            # Runtime initialization remains lazy via `init!()` at first use.
            POLLER[] = Poller()
        else
            init!()
        end
    else
        POLLER[] = Poller()
    end
    @assert isassigned(POLLER)
    return nothing
end
