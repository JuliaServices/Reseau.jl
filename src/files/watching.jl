# File watching APIs for `Reseau.Files`, intended to mirror the stdlib
# `FileWatching` surface without relying on libuv.
#
# Backends:
# - Linux: inotify (fd readable notifications on epoll)
# - macOS/BSD: kqueue vnode notifications via a dedicated kqueue fd
# - Windows: polling fallback (CI-stable v1)

module Watching

export
    FileEvent,
    FDEvent,
    FileMonitor,
    FolderMonitor,
    PollingFileWatcher,
    FDWatcher,
    watch_file,
    watch_folder,
    unwatch_folder,
    poll_file,
    poll_fd

using ...Reseau: ErrorResult
using ...Reseau: EventLoop, EventLoopGroup, EventLoopGroupOptions
using ...Reseau: ScheduledTask, TaskStatus
using ...Reseau: event_loop_group_get_next_loop
using ...Reseau: event_loop_schedule_task_now!, event_loop_schedule_task_future!
using ...Reseau: event_loop_cancel_task!
using ...Reseau: event_loop_current_clock_time, event_loop_thread_is_callers_thread
using ...Reseau: event_loop_subscribe_to_io_events!, event_loop_unsubscribe_from_io_events!
using ...Reseau: IoHandle, IoEventType

using ..Files: StatStruct, stat, lstat
using ..Backend: AbstractFilesBackend, default_backend, submit!

const _UV_RENAME = Int32(1)
const _UV_CHANGE = Int32(2)

struct FileEvent
    renamed::Bool
    changed::Bool
    timedout::Bool
    FileEvent(r::Bool, c::Bool, t::Bool) = new(r, c, t)
end

FileEvent() = FileEvent(false, false, true)
FileEvent(flags::Integer) = FileEvent((flags & _UV_RENAME) != 0, (flags & _UV_CHANGE) != 0, iszero(flags))

Base.:|(a::FileEvent, b::FileEvent) = FileEvent(a.renamed | b.renamed, a.changed | b.changed, a.timedout | b.timedout)

const _UV_READABLE = Int32(1)
const _UV_WRITABLE = Int32(2)
const _UV_DISCONNECT = Int32(4)
const _UV_PRIORITIZED = Int32(8)

struct FDEvent
    events::Int32
    FDEvent(flags::Integer = 0) = new(Int32(flags))
end

function Base.getproperty(f::FDEvent, field::Symbol)
    events = getfield(f, :events)
    field === :readable && return (events & _UV_READABLE) != 0
    field === :writable && return (events & _UV_WRITABLE) != 0
    field === :disconnect && return (events & _UV_DISCONNECT) != 0
    field === :prioritized && return (events & _UV_PRIORITIZED) != 0
    field === :timedout && return events == 0
    field === :events && return Int(events)
    return getfield(f, field)::Union{}
end

Base.propertynames(::FDEvent) = (:readable, :writable, :disconnect, :prioritized, :timedout, :events)

Base.isreadable(f::FDEvent) = f.readable
Base.iswritable(f::FDEvent) = f.writable
Base.:|(a::FDEvent, b::FDEvent) = FDEvent(getfield(a, :events) | getfield(b, :events))

# -----------------------------------------------------------------------------
# Default event loop (watchers are loop-integrated).
# -----------------------------------------------------------------------------

const _DEFAULT_ELG_LOCK = ReentrantLock()
const _DEFAULT_ELG = Ref{Union{EventLoopGroup, Nothing}}(nothing)

function _default_event_loop()::EventLoop
    lock(_DEFAULT_ELG_LOCK)
    try
        if _DEFAULT_ELG[] === nothing
            elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
            elg isa ErrorResult && error("Failed to create EventLoopGroup: $(elg.code)")
            _DEFAULT_ELG[] = elg
        end
        elg = _DEFAULT_ELG[]::EventLoopGroup
        loop = event_loop_group_get_next_loop(elg)
        loop === nothing && error("No event loop available")
        return loop
    finally
        unlock(_DEFAULT_ELG_LOCK)
    end
end

@inline function _schedule_on_event_loop_sync(event_loop::EventLoop, fn::Function)
    if event_loop_thread_is_callers_thread(event_loop)
        return fn()
    end
    done = Base.Threads.Event()
    out = Ref{Any}(nothing)
    task = ScheduledTask(
        (ctx, status) -> begin
            status == TaskStatus.RUN_READY || (notify(ctx.done); return nothing)
            ctx.out[] = fn()
            notify(ctx.done)
            return nothing
        end,
        (done = done, out = out);
        type_tag = "files_watching_sync",
    )
    event_loop_schedule_task_now!(event_loop, task)
    wait(done)
    return out[]
end

@inline function _run_at_ns(event_loop::EventLoop, delta_ns::UInt64)::UInt64
    now = event_loop_current_clock_time(event_loop)
    base = now isa ErrorResult ? UInt64(time_ns()) : now
    return base + delta_ns
end

# -----------------------------------------------------------------------------
# Polling watcher (portable; used on Windows in v1 and for poll_file()).
# -----------------------------------------------------------------------------

mutable struct PollingFileWatcher
    path::String
    interval_s::Float64
    event_loop::EventLoop
    backend::AbstractFilesBackend
    lock::ReentrantLock
    cond::Base.Threads.Condition
    closed::Bool
    events::Vector{Any} # eltype = Tuple{StatStruct, Any}
    last_success::StatStruct
    last_result::Any
    poll_task::Union{Nothing, ScheduledTask}
end

function _safe_stat(path::String)::Any
    try
        return stat(path)
    catch ex
        return ex
    end
end

function _result_equal(a, b)::Bool
    if a isa StatStruct && b isa StatStruct
        return a == b
    end
    if !(a isa StatStruct) && !(b isa StatStruct)
        return typeof(a) == typeof(b)
    end
    return false
end

function _polling_schedule_next!(pfw::PollingFileWatcher)::Nothing
    pfw.closed && return nothing
    interval_ns = UInt64(max(1, round(Int64, pfw.interval_s * 1.0e9)))
    run_at = _run_at_ns(pfw.event_loop, interval_ns)
    pfw.poll_task = ScheduledTask(
        (ctx, status) -> begin
            status == TaskStatus.RUN_READY || return nothing
            _polling_kick!(ctx)
            return nothing
        end,
        pfw;
        type_tag = "files_polling",
    )
    event_loop_schedule_task_future!(pfw.event_loop, pfw.poll_task, run_at)
    return nothing
end

function _polling_kick!(pfw::PollingFileWatcher)::Nothing
    pfw.closed && return nothing
    submit!(pfw.backend, () -> begin
        res = _safe_stat(pfw.path)
        event_loop_task = () -> begin
            if pfw.closed
                return nothing
            end
            lock(pfw.lock)
            try
                changed = !_result_equal(pfw.last_result, res)
                if changed
                    prev = pfw.last_success
                    push!(pfw.events, (prev, res))
                    notify(pfw.cond)
                    if res isa StatStruct
                        pfw.last_success = res
                        pfw.last_result = res
                    else
                        pfw.last_success = StatStruct()
                        pfw.last_result = res
                    end
                end
            finally
                unlock(pfw.lock)
            end
            _polling_schedule_next!(pfw)
            return nothing
        end
        event_loop_schedule_task_now!(pfw.event_loop, ScheduledTask((_ctx, st) -> (st == TaskStatus.RUN_READY && event_loop_task(); nothing), nothing; type_tag = "files_poll_complete"))
        return nothing
    end)
    return nothing
end

function PollingFileWatcher(path::AbstractString, interval_s::Real = 5.007; event_loop::Union{EventLoop, Nothing} = nothing, backend::Union{AbstractFilesBackend, Nothing} = nothing)
    el = event_loop === nothing ? _default_event_loop() : event_loop
    b = backend === nothing ? default_backend() : backend
    p = String(path)
    initial = _safe_stat(p)
    last_success = initial isa StatStruct ? initial : StatStruct()
    lock = ReentrantLock()
    pfw = PollingFileWatcher(
        p,
        Float64(interval_s),
        el,
        b,
        lock,
        Base.Threads.Condition(lock),
        false,
        Any[],
        last_success,
        initial,
        nothing,
    )
    # Kick the polling loop.
    event_loop_schedule_task_now!(el, ScheduledTask((ctx, st) -> (st == TaskStatus.RUN_READY && _polling_kick!(ctx); nothing), pfw; type_tag = "files_poll_start"))
    return pfw
end

function Base.close(pfw::PollingFileWatcher)::Nothing
    pfw.closed && return nothing
    lock(pfw.lock)
    try
        pfw.closed = true
        notify(pfw.cond; all = true)
    finally
        unlock(pfw.lock)
    end
    return nothing
end

function Base.wait(pfw::PollingFileWatcher)
    lock(pfw.lock)
    try
        while isempty(pfw.events) && !pfw.closed
            wait(pfw.cond)
        end
        if !isempty(pfw.events)
            return popfirst!(pfw.events)
        end
        return (pfw.last_success, EOFError())
    finally
        unlock(pfw.lock)
    end
end

function poll_file(path::AbstractString, interval_s::Real = 5.007, timeout_s::Real = -1)
    pfw = PollingFileWatcher(path, interval_s)
    local timer
    try
        if timeout_s >= 0
            el = pfw.event_loop
            run_at = _run_at_ns(el, UInt64(round(Int64, Float64(timeout_s) * 1.0e9)))
            timer = ScheduledTask(
                (ctx, status) -> begin
                    status == TaskStatus.RUN_READY || return nothing
                    close(ctx)
                    return nothing
                end,
                pfw;
                type_tag = "files_poll_timeout",
            )
            event_loop_schedule_task_future!(el, timer, run_at)
        end
        return wait(pfw)
    finally
        if @isdefined(timer)
            _schedule_on_event_loop_sync(pfw.event_loop, () -> event_loop_cancel_task!(pfw.event_loop, timer))
        end
        close(pfw)
    end
end

# -----------------------------------------------------------------------------
# File/folder monitors (platform backends).
# -----------------------------------------------------------------------------

mutable struct FileMonitor
    path::String
    event_loop::EventLoop
    cond::Base.Threads.Condition
    events::Int32
    closed::Bool
    io_handle::IoHandle
    impl::Any
end

mutable struct FolderMonitor
    path::String
    event_loop::EventLoop
    cond::Base.Threads.Condition
    queue::Vector{Any} # eltype = Pair{String, FileEvent}
    closed::Bool
    io_handle::IoHandle
    impl::Any
end

@static if Sys.islinux()
    const _IN_NONBLOCK = Cint(0x800)
    const _IN_CLOEXEC = Cint(0x80000)

    const _IN_ATTRIB = UInt32(0x00000004)
    const _IN_MODIFY = UInt32(0x00000002)
    const _IN_CLOSE_WRITE = UInt32(0x00000008)
    const _IN_CREATE = UInt32(0x00000100)
    const _IN_DELETE = UInt32(0x00000200)
    const _IN_MOVED_FROM = UInt32(0x00000040)
    const _IN_MOVED_TO = UInt32(0x00000080)
    const _IN_MOVE_SELF = UInt32(0x00000800)
    const _IN_DELETE_SELF = UInt32(0x00000400)

    struct _inotify_event
        wd::Int32
        mask::UInt32
        cookie::UInt32
        len::UInt32
    end

    @inline function _inotify_init1(flags::Cint)::Cint
        fd = @ccall inotify_init1(flags::Cint)::Cint
        fd < 0 && throw(SystemError("inotify_init1", Libc.errno()))
        return fd
    end

    @inline function _inotify_add_watch(fd::Cint, path::AbstractString, mask::UInt32)::Cint
        wd = @ccall inotify_add_watch(fd::Cint, path::Cstring, mask::UInt32)::Cint
        wd < 0 && throw(SystemError("inotify_add_watch", Libc.errno()))
        return wd
    end

    @inline function _inotify_event_to_flags(mask::UInt32)::Int32
        renamed = (mask & (_IN_MOVED_FROM | _IN_MOVED_TO | _IN_MOVE_SELF | _IN_DELETE_SELF)) != 0
        changed = (mask & (_IN_ATTRIB | _IN_MODIFY | _IN_CLOSE_WRITE | _IN_CREATE | _IN_DELETE)) != 0
        return (renamed ? _UV_RENAME : 0) | (changed ? _UV_CHANGE : 0)
    end

    function _inotify_on_event(event_loop, handle::IoHandle, events::Int, user_data)
        _ = event_loop
        (events & Int(IoEventType.READABLE)) == 0 && return nothing
        mon = user_data
        fd = handle.fd
        buf = Vector{UInt8}(undef, 8192)
        while true
            nread = GC.@preserve buf begin
                @ccall gc_safe = true read(fd::Cint, pointer(buf)::Ptr{Cvoid}, Csize_t(length(buf))::Csize_t)::Cssize_t
            end
            if nread < 0
                err = Libc.errno()
                err == Libc.EINTR && continue
                err == Libc.EAGAIN && break
                break
            end
            nread == 0 && break
            i = 1
            while i + sizeof(_inotify_event) - 1 <= nread
                ev = GC.@preserve buf begin
                    unsafe_load(Ptr{_inotify_event}(pointer(buf, i)))
                end
                flags = _inotify_event_to_flags(ev.mask)
                name = ""
                if ev.len > 0
                    start = i + sizeof(_inotify_event)
                    stop = start + Int(ev.len) - 1
                    stop <= nread || (stop = nread)
                    raw = buf[start:stop]
                    z = findfirst(==(0x00), raw)
                    if z !== nothing && z > 1
                        name = String(copy(raw[1:(z - 1)]))
                    elseif z === nothing
                        name = String(copy(raw))
                    end
                end

                if mon isa FileMonitor
                    lock(mon.cond)
                    try
                        mon.events |= flags
                        notify(mon.cond)
                    finally
                        unlock(mon.cond)
                    end
                else
                    fm = mon::FolderMonitor
                    lock(fm.cond)
                    try
                        push!(fm.queue, name => FileEvent(flags))
                        notify(fm.cond)
                    finally
                        unlock(fm.cond)
                    end
                end
                i += sizeof(_inotify_event) + Int(ev.len)
            end
        end
        return nothing
    end

    function _new_inotify_monitor(path::AbstractString; is_folder::Bool)::Tuple{Cint, Cint}
        fd = _inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
        mask = is_folder ?
            (_IN_ATTRIB | _IN_MODIFY | _IN_CLOSE_WRITE | _IN_CREATE | _IN_DELETE | _IN_MOVED_FROM | _IN_MOVED_TO) :
            (_IN_ATTRIB | _IN_MODIFY | _IN_CLOSE_WRITE | _IN_MOVE_SELF | _IN_DELETE_SELF)
        wd = _inotify_add_watch(fd, path, mask)
        return fd, wd
    end
end

@static if Sys.isapple() || Sys.isbsd()
    using ...Reseau: Kevent, Timespec

    const _EVFILT_VNODE = Int16(-4)
    const _EV_ADD = UInt16(0x0001)
    const _EV_DELETE = UInt16(0x0002)
    const _EV_CLEAR = UInt16(0x0020)

    const _NOTE_DELETE = UInt32(0x00000001)
    const _NOTE_WRITE = UInt32(0x00000002)
    const _NOTE_EXTEND = UInt32(0x00000004)
    const _NOTE_ATTRIB = UInt32(0x00000008)
    const _NOTE_LINK = UInt32(0x00000010)
    const _NOTE_RENAME = UInt32(0x00000020)
    const _NOTE_REVOKE = UInt32(0x00000040)

    const _O_EVTONLY = Cint(0x8000)
    const _O_CLOEXEC = Cint(0x1000000)

    @inline function _kqueue()::Cint
        kq = @ccall kqueue()::Cint
        kq < 0 && throw(SystemError("kqueue", Libc.errno()))
        return kq
    end

    @inline function _open_evtonly(path::AbstractString)::Cint
        fd = @ccall open(path::Cstring, (_O_EVTONLY | _O_CLOEXEC)::Cint)::Cint
        fd < 0 && throw(SystemError("open($(repr(path)))", Libc.errno()))
        return fd
    end

    @inline function _kevent_register(kq::Cint, fd::Cint)::Nothing
        flags = _NOTE_DELETE | _NOTE_WRITE | _NOTE_EXTEND | _NOTE_ATTRIB | _NOTE_LINK | _NOTE_RENAME | _NOTE_REVOKE
        kev = Kevent(fd, _EVFILT_VNODE, _EV_ADD | _EV_CLEAR, flags, 0, C_NULL)
        kev_ref = Ref(kev)
        rc = @ccall kevent(kq::Cint, kev_ref::Ptr{Kevent}, 1::Cint, C_NULL::Ptr{Kevent}, 0::Cint, C_NULL::Ptr{Cvoid})::Cint
        rc == 0 || throw(SystemError("kevent(register)", Libc.errno()))
        return nothing
    end

    @inline function _kevent_drain(kq::Cint, out::Vector{Kevent})::Int
        ts = Ref(Timespec(0, 0))
        return @ccall gc_safe = true kevent(kq::Cint, C_NULL::Ptr{Kevent}, 0::Cint, out::Ptr{Kevent}, length(out)::Cint, ts::Ref{Timespec})::Cint
    end

    @inline function _vnode_fflags_to_flags(fflags::UInt32)::Int32
        renamed = (fflags & (_NOTE_DELETE | _NOTE_RENAME | _NOTE_REVOKE)) != 0
        changed = (fflags & (_NOTE_WRITE | _NOTE_EXTEND | _NOTE_ATTRIB | _NOTE_LINK)) != 0
        return (renamed ? _UV_RENAME : 0) | (changed ? _UV_CHANGE : 0)
    end

    function _kqueue_vnode_on_event(event_loop, handle::IoHandle, events::Int, user_data)
        _ = event_loop
        (events & Int(IoEventType.READABLE)) == 0 && return nothing
        mon = user_data
        kq = handle.fd
        out = Vector{Kevent}(undef, 64)
        while true
            n = _kevent_drain(kq, out)
            n < 0 && break
            n == 0 && break
            for i in 1:n
                ev = out[i]
                flags = _vnode_fflags_to_flags(ev.fflags)
                if mon isa FileMonitor
                    lock(mon.cond)
                    try
                        mon.events |= flags
                        notify(mon.cond)
                    finally
                        unlock(mon.cond)
                    end
                else
                    fm = mon::FolderMonitor
                    lock(fm.cond)
                    try
                        push!(fm.queue, "" => FileEvent(flags))
                        notify(fm.cond)
                    finally
                        unlock(fm.cond)
                    end
                end
            end
        end
        return nothing
    end

    function _new_kqueue_vnode_monitor(path::AbstractString)::Tuple{Cint, Cint}
        kq = _kqueue()
        fd = _open_evtonly(path)
        _kevent_register(kq, fd)
        return kq, fd
    end
end

function FileMonitor(path::AbstractString; event_loop::Union{EventLoop, Nothing} = nothing)
    el = event_loop === nothing ? _default_event_loop() : event_loop
    mon = FileMonitor(String(path), el, Base.Threads.Condition(), Int32(0), false, IoHandle(), nothing)

    @static if Sys.islinux()
        fd, wd = _new_inotify_monitor(path; is_folder = false)
        mon.io_handle = IoHandle(fd)
        mon.impl = (fd = fd, wd = wd)
        _ = event_loop_subscribe_to_io_events!(el, mon.io_handle, Int(IoEventType.READABLE), _inotify_on_event, mon)
    elseif Sys.isapple() || Sys.isbsd()
        kq, fd = _new_kqueue_vnode_monitor(path)
        mon.io_handle = IoHandle(kq)
        mon.impl = (kq = kq, fd = fd)
        _ = event_loop_subscribe_to_io_events!(el, mon.io_handle, Int(IoEventType.READABLE), _kqueue_vnode_on_event, mon)
    else
        # Windows: polling fallback with small interval.
        pfw = PollingFileWatcher(path, 0.05; event_loop = el)
        mon.impl = pfw
    end

    return mon
end

function FolderMonitor(path::AbstractString; event_loop::Union{EventLoop, Nothing} = nothing)
    el = event_loop === nothing ? _default_event_loop() : event_loop
    mon = FolderMonitor(String(path), el, Base.Threads.Condition(), Any[], false, IoHandle(), nothing)

    @static if Sys.islinux()
        fd, wd = _new_inotify_monitor(path; is_folder = true)
        mon.io_handle = IoHandle(fd)
        mon.impl = (fd = fd, wd = wd)
        _ = event_loop_subscribe_to_io_events!(el, mon.io_handle, Int(IoEventType.READABLE), _inotify_on_event, mon)
    elseif Sys.isapple() || Sys.isbsd()
        kq, fd = _new_kqueue_vnode_monitor(path)
        mon.io_handle = IoHandle(kq)
        mon.impl = (kq = kq, fd = fd)
        _ = event_loop_subscribe_to_io_events!(el, mon.io_handle, Int(IoEventType.READABLE), _kqueue_vnode_on_event, mon)
    else
        pfw = PollingFileWatcher(path, 0.1; event_loop = el)
        mon.impl = pfw
    end

    return mon
end

function Base.close(mon::FileMonitor)::Nothing
    mon.closed && return nothing
    mon.closed = true
    lock(mon.cond)
    try
        notify(mon.cond; all = true)
    finally
        unlock(mon.cond)
    end

    @static if Sys.islinux() || Sys.isapple() || Sys.isbsd()
        _schedule_on_event_loop_sync(mon.event_loop, () -> begin
            try
                event_loop_unsubscribe_from_io_events!(mon.event_loop, mon.io_handle)
            catch
            end
            if mon.impl !== nothing
                if mon.impl isa NamedTuple
                    if haskey(mon.impl, :fd)
                        @ccall close(mon.impl.fd::Cint)::Cint
                    end
                    if haskey(mon.impl, :kq)
                        @ccall close(mon.impl.kq::Cint)::Cint
                    end
                end
            end
            return nothing
        end)
    else
        if mon.impl isa PollingFileWatcher
            close(mon.impl)
        end
    end

    return nothing
end

function Base.close(mon::FolderMonitor)::Nothing
    mon.closed && return nothing
    mon.closed = true
    lock(mon.cond)
    try
        notify(mon.cond; all = true)
    finally
        unlock(mon.cond)
    end

    @static if Sys.islinux() || Sys.isapple() || Sys.isbsd()
        _schedule_on_event_loop_sync(mon.event_loop, () -> begin
            try
                event_loop_unsubscribe_from_io_events!(mon.event_loop, mon.io_handle)
            catch
            end
            if mon.impl !== nothing
                if mon.impl isa NamedTuple
                    if haskey(mon.impl, :fd)
                        @ccall close(mon.impl.fd::Cint)::Cint
                    end
                    if haskey(mon.impl, :kq)
                        @ccall close(mon.impl.kq::Cint)::Cint
                    end
                end
            end
            return nothing
        end)
    else
        if mon.impl isa PollingFileWatcher
            close(mon.impl)
        end
    end

    return nothing
end

function Base.wait(mon::FileMonitor)
    @static if !(Sys.islinux() || Sys.isapple() || Sys.isbsd())
        # Windows: convert polling change event into FileEvent.
        pfw = mon.impl::PollingFileWatcher
        prev, cur = wait(pfw)
        cur isa EOFError && return FileEvent()
        renamed = !(cur isa StatStruct)
        changed = true
        return FileEvent(renamed, changed, false)
    end

    lock(mon.cond)
    try
        while mon.events == 0 && !mon.closed
            wait(mon.cond)
        end
        if mon.closed
            return FileEvent()
        end
        flags = mon.events
        mon.events = 0
        return FileEvent(flags)
    finally
        unlock(mon.cond)
    end
end

function Base.wait(mon::FolderMonitor)
    @static if !(Sys.islinux() || Sys.isapple() || Sys.isbsd())
        pfw = mon.impl::PollingFileWatcher
        prev, cur = wait(pfw)
        cur isa EOFError && return ("" => FileEvent())
        return ("" => FileEvent(false, true, false))
    end

    lock(mon.cond)
    try
        while isempty(mon.queue) && !mon.closed
            wait(mon.cond)
        end
        if mon.closed
            return "" => FileEvent()
        end
        return popfirst!(mon.queue)
    finally
        unlock(mon.cond)
    end
end

# -----------------------------------------------------------------------------
# One-shot wrappers with timeout support (stdlib-like).
# -----------------------------------------------------------------------------

function watch_file(path::AbstractString, timeout_s::Real = -1)
    fm = FileMonitor(path)
    local timer
    try
        if timeout_s >= 0
            el = fm.event_loop
            run_at = _run_at_ns(el, UInt64(round(Int64, Float64(timeout_s) * 1.0e9)))
            timer = ScheduledTask(
                (ctx, status) -> begin
                    status == TaskStatus.RUN_READY || return nothing
                    close(ctx)
                    return nothing
                end,
                fm;
                type_tag = "files_watch_timeout",
            )
            event_loop_schedule_task_future!(el, timer, run_at)
        end
        return wait(fm)
    finally
        if @isdefined(timer)
            _schedule_on_event_loop_sync(fm.event_loop, () -> event_loop_cancel_task!(fm.event_loop, timer))
        end
        close(fm)
    end
end

const _WATCHED_FOLDERS_LOCK = ReentrantLock()
const _WATCHED_FOLDERS = Dict{String, FolderMonitor}()

function watch_folder(path::AbstractString, timeout_s::Real = -1)
    p = String(path)
    fm = lock(_WATCHED_FOLDERS_LOCK) do
        get!(_WATCHED_FOLDERS, p) do
            FolderMonitor(p)
        end
    end

    local timer
    timed_out = Ref(false)
    if timeout_s >= 0
        el = fm.event_loop
        run_at = _run_at_ns(el, UInt64(round(Int64, Float64(timeout_s) * 1.0e9)))
        timer = ScheduledTask(
            (ctx, status) -> begin
                status == TaskStatus.RUN_READY || return nothing
                lock(ctx.fm.cond)
                try
                    ctx.timed_out[] = true
                    notify(ctx.fm.cond)
                finally
                    unlock(ctx.fm.cond)
                end
                return nothing
            end,
            (fm = fm, timed_out = timed_out);
            type_tag = "files_watch_folder_timeout",
        )
        event_loop_schedule_task_future!(el, timer, run_at)
    end

    try
        # Inline `wait` with timeout check.
        lock(fm.cond)
        try
            while isempty(fm.queue) && !fm.closed
                timeout_s >= 0 && timed_out[] && return "" => FileEvent()
                wait(fm.cond)
                timeout_s >= 0 && timed_out[] && isempty(fm.queue) && return "" => FileEvent()
            end
            fm.closed && return "" => FileEvent()
            return popfirst!(fm.queue)
        finally
            unlock(fm.cond)
        end
    finally
        if @isdefined(timer)
            _schedule_on_event_loop_sync(fm.event_loop, () -> event_loop_cancel_task!(fm.event_loop, timer))
        end
    end
end

function unwatch_folder(path::AbstractString)::Nothing
    p = String(path)
    fm = lock(_WATCHED_FOLDERS_LOCK) do
        pop!(_WATCHED_FOLDERS, p, nothing)
    end
    fm === nothing || close(fm)
    return nothing
end

# -----------------------------------------------------------------------------
# FD polling (POSIX-only in v1).
# -----------------------------------------------------------------------------

mutable struct FDWatcher
    event_loop::EventLoop
    io_handle::IoHandle
    cond::Base.Threads.Condition
    events::Int32
    closed::Bool
end

function _fdwatcher_on_event(event_loop, handle::IoHandle, events::Int, user_data)
    _ = event_loop
    w = user_data::FDWatcher
    flags = Int32(0)
    (events & Int(IoEventType.READABLE)) != 0 && (flags |= _UV_READABLE)
    (events & Int(IoEventType.WRITABLE)) != 0 && (flags |= _UV_WRITABLE)
    (events & Int(IoEventType.REMOTE_HANG_UP)) != 0 && (flags |= _UV_DISCONNECT)
    (events & Int(IoEventType.CLOSED)) != 0 && (flags |= _UV_DISCONNECT)
    (events & Int(IoEventType.ERROR)) != 0 && (flags |= _UV_DISCONNECT)
    lock(w.cond)
    try
        w.events |= flags
        notify(w.cond)
    finally
        unlock(w.cond)
    end
    return nothing
end

function FDWatcher(fd::Base.RawFD; readable::Bool = false, writable::Bool = false, event_loop::Union{EventLoop, Nothing} = nothing)
    (!readable && !writable) && throw(ArgumentError("must specify at least one of readable or writable"))
    el = event_loop === nothing ? _default_event_loop() : event_loop
    fd_i = Int(reinterpret(Cint, fd))
    h = IoHandle(fd_i)
    w = FDWatcher(el, h, Base.Threads.Condition(), Int32(0), false)
    mask = (readable ? Int(IoEventType.READABLE) : 0) | (writable ? Int(IoEventType.WRITABLE) : 0)
    _ = event_loop_subscribe_to_io_events!(el, h, mask, _fdwatcher_on_event, w)
    return w
end

function Base.close(w::FDWatcher)::Nothing
    w.closed && return nothing
    w.closed = true
    lock(w.cond)
    try
        notify(w.cond; all = true)
    finally
        unlock(w.cond)
    end
    _schedule_on_event_loop_sync(w.event_loop, () -> begin
        try
            event_loop_unsubscribe_from_io_events!(w.event_loop, w.io_handle)
        catch
        end
        return nothing
    end)
    return nothing
end

function Base.wait(w::FDWatcher)
    lock(w.cond)
    try
        while w.events == 0 && !w.closed
            wait(w.cond)
        end
        if w.closed
            return FDEvent()
        end
        flags = w.events
        w.events = 0
        return FDEvent(flags)
    finally
        unlock(w.cond)
    end
end

function poll_fd(fd::Base.RawFD, timeout_s::Real = -1; readable::Bool = false, writable::Bool = false)
    @static if Sys.iswindows()
        throw(ArgumentError("poll_fd is not supported on Windows in Reseau.Files v1"))
    end
    w = FDWatcher(fd; readable = readable, writable = writable)
    local timer
    try
        if timeout_s >= 0
            el = w.event_loop
            run_at = _run_at_ns(el, UInt64(round(Int64, Float64(timeout_s) * 1.0e9)))
            timer = ScheduledTask(
                (ctx, status) -> begin
                    status == TaskStatus.RUN_READY || return nothing
                    close(ctx)
                    return nothing
                end,
                w;
                type_tag = "files_poll_fd_timeout",
            )
            event_loop_schedule_task_future!(el, timer, run_at)
        end
        return wait(w)
    finally
        close(w)
    end
end

end # module Watching
