"""
    EventLoops

Cross-platform event loop abstraction for socket readiness polling.
Current phase targets kqueue on macOS.
"""
module EventLoops

using EnumX

@enumx PollMode::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end

@enumx PollWaiterState::UInt8 begin
    EMPTY = 0x00
    WAITING = 0x01
    NOTIFIED = 0x02
end

"""
    PollWaiter

Go-style binary wake semaphore for one read waiter and one write waiter per fd.
It uses the low-level `wait()` + `schedule(task)` ownership protocol documented in
Julia's scheduler docs.
"""
mutable struct PollWaiter
    @atomic state::PollWaiterState.T
    task::Union{Nothing, Task}
    function PollWaiter()
        return new(PollWaiterState.EMPTY, nothing)
    end
end

"""
    pollwait!(waiter)

Park the current Julia task until the waiter is notified.
Concurrent waits on the same `PollWaiter` are forbidden.
"""
function pollwait!(waiter::PollWaiter)
    task = current_task()
    task.sticky && (task.sticky = false)
    waiter.task = task
    try
        state, ok = @atomicreplace(waiter.state, PollWaiterState.EMPTY => PollWaiterState.WAITING)
        if ok
            wait()
        else
            state == PollWaiterState.NOTIFIED || throw(ArgumentError("concurrent wait on PollWaiter"))
        end
        while true
            state, ok = @atomicreplace(waiter.state, PollWaiterState.NOTIFIED => PollWaiterState.EMPTY)
            ok && return nothing
            state == PollWaiterState.EMPTY && return nothing
            state == PollWaiterState.WAITING || throw(ArgumentError("invalid PollWaiter state"))
            wait()
        end
    finally
        waiter.task = nothing
    end
end

"""
    pollnotify!(waiter)

Mark waiter as notified and wake the waiter task if it has already parked.
Returns `true` if a parked waiter was woken.
"""
function pollnotify!(waiter::PollWaiter)::Bool
    state = @atomic :acquire waiter.state
    while state != PollWaiterState.NOTIFIED
        state, ok = @atomicreplace(waiter.state, state => PollWaiterState.NOTIFIED)
        ok || continue
        if state == PollWaiterState.WAITING
            task = waiter.task
            task isa Task || throw(ArgumentError("invalid PollWaiter task state"))
            schedule(task)
            return true
        end
        state == PollWaiterState.EMPTY || throw(ArgumentError("invalid PollWaiter state"))
        return false
    end
    return false
end

"""
    PollEvent

Readiness event decoded from the platform backend.
"""
struct PollEvent
    fd::Cint
    token::UInt64
    mode::PollMode.T
    errored::Bool
end

"""
    Registration

Per-fd registration state stored by the poller.
"""
mutable struct Registration
    fd::Cint
    token::UInt64
    mode::PollMode.T
    read_waiter::PollWaiter
    write_waiter::PollWaiter
    @atomic event_err::Bool
    deadline_owner::Ptr{Cvoid}
end

function Registration(
        fd::Cint,
        token::UInt64,
        mode::PollMode.T,
        read_waiter::PollWaiter,
        write_waiter::PollWaiter,
        event_err::Bool,
    )
    return Registration(fd, token, mode, read_waiter, write_waiter, event_err, C_NULL)
end

struct DeadlineEntry
    deadline_ns::Int64
    registration::Registration
    mode::PollMode.T
    rseq::UInt64
    wseq::UInt64
end

"""
    Poller

Global event loop subsystem state. `lock` is a regular mutex because registration
updates can run adjacent to syscalls where spin waiting would be wasteful.
"""
mutable struct Poller
    lock::ReentrantLock
    registrations::Dict{Cint, Registration}
    registrations_by_token::Dict{UInt64, Registration}
    deadline_heap::Vector{DeadlineEntry}
    shutdown_event::Base.Threads.Event
    kq::Cint
    wake_ident::UInt
    backend_scratch::Any
    @atomic wak_sig::UInt32
    @atomic next_token::UInt64
    @atomic poll_until_ns::Int64
    @atomic running::Bool
end

function Poller()
    return Poller(
        ReentrantLock(),
        Dict{Cint, Registration}(),
        Dict{UInt64, Registration}(),
        DeadlineEntry[],
        Base.Threads.Event(),
        Cint(-1),
        UInt(1),
        nothing,
        UInt32(0),
        UInt64(0),
        Int64(0),
        false,
    )
end

"""
Global singleton state for the runtime event loop poller.
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

@inline function _mode_has_read(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.READ)) != 0
end

@inline function _mode_has_write(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.WRITE)) != 0
end

@inline function _mode_is_empty(mode::PollMode.T)::Bool
    return UInt8(mode) == 0x00
end

@inline function _runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux() || Sys.iswindows()
end

function _new_registration(fd::Cint, token::UInt64, mode::PollMode.T)::Registration
    return Registration(fd, token, mode, PollWaiter(), PollWaiter(), false)
end

function attach_deadline_owner!(registration::Registration, owner)
    registration.deadline_owner = owner === nothing ? C_NULL : pointer_from_objref(owner)
    return registration
end

function deadline_fire!(owner, registration::Registration, mode::PollMode.T, rseq::UInt64, wseq::UInt64)
    _ = owner
    _ = registration
    _ = mode
    _ = rseq
    _ = wseq
    return nothing
end

@inline function _deadline_less(a::DeadlineEntry, b::DeadlineEntry)::Bool
    if a.deadline_ns != b.deadline_ns
        return a.deadline_ns < b.deadline_ns
    end
    if a.registration.token != b.registration.token
        return a.registration.token < b.registration.token
    end
    return UInt8(a.mode) < UInt8(b.mode)
end

@inline function _heap_parent_index(i::Int)::Int
    return i >>> 1
end

@inline function _heap_left_index(i::Int)::Int
    return i << 1
end

@inline function _heap_right_index(i::Int)::Int
    return (i << 1) + 1
end

function _deadline_swap!(heap::Vector{DeadlineEntry}, i::Int, j::Int)
    heap[i], heap[j] = heap[j], heap[i]
    return nothing
end

function _deadline_sift_up!(heap::Vector{DeadlineEntry}, i::Int)
    while i > 1
        parent = _heap_parent_index(i)
        _deadline_less(heap[i], heap[parent]) || break
        _deadline_swap!(heap, i, parent)
        i = parent
    end
    return nothing
end

function _deadline_sift_down!(heap::Vector{DeadlineEntry}, i::Int)
    len = length(heap)
    while true
        left = _heap_left_index(i)
        left > len && break
        smallest = left
        right = _heap_right_index(i)
        if right <= len && _deadline_less(heap[right], heap[left])
            smallest = right
        end
        _deadline_less(heap[smallest], heap[i]) || break
        _deadline_swap!(heap, i, smallest)
        i = smallest
    end
    return nothing
end

function _deadline_push_locked!(state::Poller, entry::DeadlineEntry)
    heap = state.deadline_heap
    push!(heap, entry)
    _deadline_sift_up!(heap, length(heap))
    return nothing
end

function _deadline_pop_locked!(state::Poller)::DeadlineEntry
    heap = state.deadline_heap
    isempty(heap) && throw(ArgumentError("deadline heap is empty"))
    entry = heap[1]
    last = pop!(heap)
    if !isempty(heap)
        heap[1] = last
        _deadline_sift_down!(heap, 1)
    end
    return entry
end

@inline function _registration_active_locked(state::Poller, registration::Registration)::Bool
    current = get(() -> nothing, state.registrations_by_token, registration.token)
    return current === registration
end

function _discard_stale_deadlines_locked!(state::Poller)
    while !isempty(state.deadline_heap)
        entry = state.deadline_heap[1]
        _registration_active_locked(state, entry.registration) && return nothing
        _ = _deadline_pop_locked!(state)
    end
    return nothing
end

function _deadline_peek_locked(state::Poller)
    _discard_stale_deadlines_locked!(state)
    isempty(state.deadline_heap) && return nothing
    return state.deadline_heap[1]
end

function _build_deadline_entries(
        registration::Registration,
        rd_ns::Int64,
        wd_ns::Int64,
        rseq::UInt64,
        wseq::UInt64,
    )::Vector{DeadlineEntry}
    entries = DeadlineEntry[]
    if rd_ns > 0 && wd_ns > 0 && rd_ns == wd_ns
        push!(entries, DeadlineEntry(rd_ns, registration, PollMode.READWRITE, rseq, wseq))
        return entries
    end
    rd_ns > 0 && push!(entries, DeadlineEntry(rd_ns, registration, PollMode.READ, rseq, UInt64(0)))
    wd_ns > 0 && push!(entries, DeadlineEntry(wd_ns, registration, PollMode.WRITE, UInt64(0), wseq))
    return entries
end

function schedule_deadlines!(
        registration::Registration,
        rd_ns::Int64,
        wd_ns::Int64,
        rseq::UInt64,
        wseq::UInt64,
    )
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    new_earliest = Int64(0)
    lock(state.lock)
    try
        _registration_active_locked(state, registration) || return nothing
        for entry in _build_deadline_entries(registration, rd_ns, wd_ns, rseq, wseq)
            _deadline_push_locked!(state, entry)
            if new_earliest == 0 || entry.deadline_ns < new_earliest
                new_earliest = entry.deadline_ns
            end
        end
    finally
        unlock(state.lock)
    end
    if new_earliest > 0
        poll_until_ns = @atomic :acquire state.poll_until_ns
        if poll_until_ns == 0 || new_earliest < poll_until_ns
            errno = _backend_wake!(state)
            errno == Int32(0) || _throw_errno("event loop wake", errno)
        end
    end
    return nothing
end

function _poll_delay_ns(state::Poller)::Int64
    deadline_ns = Int64(0)
    lock(state.lock)
    try
        entry = _deadline_peek_locked(state)
        deadline_ns = entry === nothing ? Int64(0) : entry.deadline_ns
        @atomic :release state.poll_until_ns = deadline_ns
    finally
        unlock(state.lock)
    end
    deadline_ns == 0 && return Int64(-1)
    now_ns = Int64(time_ns())
    remaining_ns = deadline_ns - now_ns
    remaining_ns <= 0 && return Int64(0)
    return remaining_ns
end

function _drain_expired_deadlines!(state::Poller, now_ns::Int64)
    expired = DeadlineEntry[]
    lock(state.lock)
    try
        while true
            entry = _deadline_peek_locked(state)
            (entry === nothing || entry.deadline_ns > now_ns) && break
            push!(expired, _deadline_pop_locked!(state))
        end
    finally
        unlock(state.lock)
    end
    for entry in expired
        owner_ref = entry.registration.deadline_owner
        owner_ref == C_NULL && continue
        owner = unsafe_pointer_to_objref(owner_ref)
        deadline_fire!(owner, entry.registration, entry.mode, entry.rseq, entry.wseq)
    end
    return nothing
end

function _notify_registration!(registration::Registration, mode::PollMode.T)
    if _mode_has_read(mode) && _mode_has_read(registration.mode)
        pollnotify!(registration.read_waiter)
    end
    if _mode_has_write(mode) && _mode_has_write(registration.mode)
        pollnotify!(registration.write_waiter)
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
        handle == C_NULL && throw(ArgumentError("error creating event loop thread"))
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

Initialize the runtime poller state and start the dedicated foreign kqueue thread.
"""
function init!()::Poller
    if isassigned(POLLER)
        state = POLLER[]
        (@atomic state.running) && return state
    end
    _runtime_supported() || throw(ArgumentError("eventloops backend is currently supported on macOS, Linux, and Windows"))
    new_state = Poller()
    errno = _backend_init!(new_state)
    errno == Int32(0) || _throw_errno("eventloops backend init", errno)
    @atomic new_state.running = true
    POLLER[] = new_state
    try
        _spawn_detached_thread(
            "reseau-eventloops-poller",
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

Stop the dedicated poller thread and tear down kqueue resources.
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
        _notify_registration!(registration, PollMode.READWRITE)
    end
    if stop_requested
        wake_errno = _backend_wake!(state)
        wake_errno == Int32(0) || _throw_errno("event loop wake", wake_errno)
        wait(state.shutdown_event)
    end
    _backend_close!(state)
    return nothing
end

"""
    register!(fd; mode=PollMode.READWRITE)

Register an fd with the runtime poller and return its `Registration`.
"""
function register!(fd::Integer; mode::PollMode.T = PollMode.READWRITE)::Registration
    _mode_is_empty(mode) && throw(ArgumentError("register! requires READ and/or WRITE mode"))
    state = init!()
    cfd = Cint(fd)
    token = UInt64(0)
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || throw(SystemError("event loop register", Int(Base.Libc.EBADF)))
        existing = get(state.registrations, cfd, nothing)
        existing === nothing || throw(SystemError("event loop register", Int(Base.Libc.EEXIST)))
        token = _next_token!(state)
        errno = _backend_open_fd!(state, cfd, mode, token)
        if errno == Int32(0)
            registration = _new_registration(cfd, token, mode)
            state.registrations[cfd] = registration
            state.registrations_by_token[token] = registration
        end
    finally
        unlock(state.lock)
    end
    errno == Int32(0) || _throw_errno("event loop register", errno)
    return registration::Registration
end

"""
    deregister!(fd)

Unregister an fd from the runtime poller.
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
        registration === nothing || (registration.deadline_owner = C_NULL)
        errno = _backend_close_fd!(state, cfd)
    finally
        unlock(state.lock)
    end
    registration === nothing || _notify_registration!(registration::Registration, PollMode.READWRITE)
    errno == Int32(0) || _throw_errno("event loop deregister", errno)
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
    errno == Int32(0) || _throw_errno("event loop arm", errno)
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
    _notify_registration!(registration::Registration, event.mode)
    return nothing
end

function _notify_all_waiters!(state::Poller)
    registrations = Registration[]
    lock(state.lock)
    try
        append!(registrations, values(state.registrations))
    finally
        unlock(state.lock)
    end
    for registration in registrations
        _notify_registration!(registration, PollMode.READWRITE)
    end
    return nothing
end

function _poller_thread_main!(state::Poller)
    while @atomic state.running
        delay_ns = _poll_delay_ns(state)
        errno = _backend_poll_once!(state, delay_ns)
        @atomic :release state.poll_until_ns = Int64(0)
        _drain_expired_deadlines!(state, Int64(time_ns()))
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

@static if Sys.isapple()
    include("1_eventloops_kqueue.jl")
elseif Sys.islinux()
    include("1_eventloops_epoll.jl")
elseif Sys.iswindows()
    include("1_eventloops_iocp.jl")
else
    include("1_eventloops_kqueue.jl")
end

end
