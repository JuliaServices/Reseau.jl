const TIMESTAMP_SECS = 1
const TIMESTAMP_MILLIS = 1000
const TIMESTAMP_MICROS = 1000000
const TIMESTAMP_NANOS = 1000000000

@inline function _set_remainder!(remainder::Ptr{T}, value::Integer) where {T}
    if remainder != C_NULL
        unsafe_store!(Ptr{UInt64}(remainder), UInt64(value))
    end
    return nothing
end

@inline function _set_remainder!(remainder::Base.RefValue{UInt64}, value::Integer)
    remainder[] = UInt64(value)
    return nothing
end

@inline function _set_remainder!(remainder::Nothing, value::Integer)
    _ = value
    return nothing
end

@inline function _remainder_provided(remainder::Ptr{T}) where {T}
    return remainder != C_NULL
end

@inline function _remainder_provided(remainder::Base.RefValue{UInt64})
    return true
end

@inline function _remainder_provided(remainder::Nothing)
    return false
end

function timestamp_convert_u64(
        ticks::UInt64,
        old_frequency::UInt64,
        new_frequency::UInt64,
        remainder,
    )
    fatal_assert_bool(old_frequency > 0 && new_frequency > 0, "old_frequency > 0 && new_frequency > 0", "<unknown>", 0)

    if _remainder_provided(remainder)
        _set_remainder!(remainder, 0)
        if new_frequency < old_frequency
            frequency_remainder = old_frequency % new_frequency
            if frequency_remainder == 0
                frequency_ratio = old_frequency ÷ new_frequency
                _set_remainder!(remainder, ticks % frequency_ratio)
            end
        end
    end

    old_seconds_elapsed = ticks ÷ old_frequency
    old_remainder = ticks - old_seconds_elapsed * old_frequency

    new_ticks_whole_part = mul_u64_saturating(old_seconds_elapsed, new_frequency)
    new_ticks_remainder_part = mul_u64_saturating(old_remainder, new_frequency) ÷ old_frequency

    return add_u64_saturating(new_ticks_whole_part, new_ticks_remainder_part)
end

function timestamp_convert_u64(
        ticks::Integer,
        old_frequency::Integer,
        new_frequency::Integer,
        remainder,
    )
    return timestamp_convert_u64(
        UInt64(ticks),
        UInt64(old_frequency),
        UInt64(new_frequency),
        remainder,
    )
end

function timestamp_convert(
        timestamp::UInt64,
        convert_from::Integer,
        convert_to::Integer,
        remainder,
    )
    return timestamp_convert_u64(timestamp, UInt64(convert_from), UInt64(convert_to), remainder)
end

function timestamp_convert(
        timestamp::Integer,
        convert_from::Integer,
        convert_to::Integer,
        remainder,
    )
    return timestamp_convert(UInt64(timestamp), convert_from, convert_to, remainder)
end

struct _timespec
    tv_sec::Clong
    tv_nsec::Clong
end

struct _timeval
    tv_sec::Clong
    tv_usec::Clong
end

@static if _PLATFORM_WINDOWS
    struct _large_integer
        QuadPart::Int64
    end

    struct _filetime
        dwLowDateTime::UInt32
        dwHighDateTime::UInt32
    end

    const _FILE_TIME_TO_NS = UInt64(100)
    const _EC_TO_UNIX_EPOCH = UInt64(11644473600)
    const _WINDOWS_TICK = UInt64(10000000)
end

function high_res_clock_get_ticks(timestamp::Ptr{UInt64})
    if timestamp == C_NULL
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    @static if _PLATFORM_WINDOWS
        ticks = Ref{_large_integer}()
        freq = Ref{_large_integer}()
        if ccall((:QueryPerformanceFrequency, "kernel32"), UInt8, (Ref{_large_integer},), freq) == 0 ||
                ccall((:QueryPerformanceCounter, "kernel32"), UInt8, (Ref{_large_integer},), ticks) == 0
            return raise_error(ERROR_CLOCK_FAILURE)
        end
        converted = timestamp_convert_u64(
            UInt64(ticks[].QuadPart),
            UInt64(freq[].QuadPart),
            UInt64(TIMESTAMP_NANOS),
            nothing,
        )
        unsafe_store!(timestamp, converted)
        return OP_SUCCESS
    else
        ts = Ref{_timespec}()
        clock_ids = _CLOCK_BOOTTIME == Cint(-1) ?
            (_CLOCK_MONOTONIC_RAW, _CLOCK_MONOTONIC) :
            (_CLOCK_BOOTTIME, _CLOCK_MONOTONIC_RAW, _CLOCK_MONOTONIC)
        for clock_id in clock_ids
            if ccall(:clock_gettime, Cint, (Cint, Ref{_timespec}), clock_id, ts) == 0
                secs = UInt64(ts[].tv_sec)
                nsecs = UInt64(ts[].tv_nsec)
                unsafe_store!(timestamp, secs * UInt64(TIMESTAMP_NANOS) + nsecs)
                return OP_SUCCESS
            end
        end
        return raise_error(ERROR_CLOCK_FAILURE)
    end
end

function high_res_clock_get_ticks(timestamp::Base.RefValue{UInt64})
    return high_res_clock_get_ticks(Base.unsafe_convert(Ptr{UInt64}, timestamp))
end

function sys_clock_get_ticks(timestamp::Ptr{UInt64})
    if timestamp == C_NULL
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    @static if _PLATFORM_WINDOWS
        ft = Ref{_filetime}()
        ccall((:GetSystemTimeAsFileTime, "kernel32"), Cvoid, (Ref{_filetime},), ft)
        quad = (UInt64(ft[].dwHighDateTime) << 32) | UInt64(ft[].dwLowDateTime)
        unsafe_store!(timestamp, (quad - (_WINDOWS_TICK * _EC_TO_UNIX_EPOCH)) * _FILE_TIME_TO_NS)
        return OP_SUCCESS
    else
        ts = Ref{_timespec}()
        if ccall(:clock_gettime, Cint, (Cint, Ref{_timespec}), _CLOCK_REALTIME, ts) != 0
            tv = Ref{_timeval}()
            if ccall(:gettimeofday, Cint, (Ref{_timeval}, Ptr{Cvoid}), tv, C_NULL) != 0
                return raise_error(ERROR_CLOCK_FAILURE)
            end
            secs = UInt64(tv[].tv_sec)
            usecs = UInt64(tv[].tv_usec)
            unsafe_store!(timestamp, secs * UInt64(TIMESTAMP_NANOS) + usecs * 1000)
            return OP_SUCCESS
        end
        secs = UInt64(ts[].tv_sec)
        nsecs = UInt64(ts[].tv_nsec)
        unsafe_store!(timestamp, secs * UInt64(TIMESTAMP_NANOS) + nsecs)
        return OP_SUCCESS
    end
end

function sys_clock_get_ticks(timestamp::Base.RefValue{UInt64})
    return sys_clock_get_ticks(Base.unsafe_convert(Ptr{UInt64}, timestamp))
end

# -----------------------------------------------------------------------------
# Libuv-free clock/timer replacements
#
# Julia Base `time_ns()` and `sleep()/Timer/timedwait` drive libuv. For our IO
# stack we want monotonic time + delays without libuv-backed timers.
# -----------------------------------------------------------------------------

"""
    monotonic_time_ns()::UInt64

High-resolution monotonic timestamp in nanoseconds.

This is a libuv-free replacement for `Base.time_ns()`.
"""
function monotonic_time_ns()::UInt64
    ts = Ref{UInt64}(0)
    high_res_clock_get_ticks(ts)
    return ts[]
end

"""
    thread_sleep_ns(ns::Integer)::Nothing

Block the *current OS thread* for `ns` nanoseconds.

This must only be used on dedicated threads that are not expected to run other
Julia tasks. Use `task_sleep_ns` when you need task-friendly sleeping.
"""
function thread_sleep_ns(ns::Integer)::Nothing
    ns <= 0 && return nothing
    remaining = UInt64(ns)
    @static if _PLATFORM_WINDOWS
        while remaining > 0
            # Sleep(ms) is millisecond granularity; round up so we don't under-sleep.
            ms = (remaining + 999_999) ÷ 1_000_000
            if ms > typemax(UInt32)
                ccall((:Sleep, "kernel32"), Cvoid, (UInt32,), typemax(UInt32))
                remaining -= UInt64(typemax(UInt32)) * 1_000_000
            else
                ccall((:Sleep, "kernel32"), Cvoid, (UInt32,), UInt32(ms))
                break
            end
        end
        return nothing
    else
        req = Ref{_timespec}()
        rem = Ref{_timespec}()
        while remaining > 0
            req[] = _timespec(
                Clong(remaining ÷ UInt64(TIMESTAMP_NANOS)),
                Clong(remaining % UInt64(TIMESTAMP_NANOS)),
            )
            ret = @ccall gc_safe = true nanosleep(req::Ref{_timespec}, rem::Ref{_timespec})::Cint
            if ret == 0
                break
            end
            err = Libc.errno()
            if err == Libc.EINTR
                remaining = UInt64(rem[].tv_sec) * UInt64(TIMESTAMP_NANOS) + UInt64(rem[].tv_nsec)
                continue
            end
            translate_and_raise_io_error(err)
            break
        end
        return nothing
    end
end

"""
    thread_sleep_s(seconds::Real)::Nothing

Thin wrapper over `thread_sleep_ns`.
"""
function thread_sleep_s(seconds::Real)::Nothing
    seconds <= 0 && return nothing
    isfinite(seconds) || return (raise_error(ERROR_INVALID_ARGUMENT); nothing)
    ns_f = Float64(seconds) * Float64(TIMESTAMP_NANOS)
    ns_f <= 0 && return nothing
    ns = ns_f >= Float64(typemax(UInt64)) ? typemax(UInt64) : UInt64(round(ns_f))
    thread_sleep_ns(ns)
    return nothing
end

function timedwait_poll_ns(
        testcb,
        timeout_ns::Integer;
        poll_ns::Integer = 1_000_000, # 1ms
    )::Symbol
    testcb() && return :ok
    timeout_ns <= 0 && return :timed_out

    start = monotonic_time_ns()
    deadline = add_u64_saturating(start, UInt64(timeout_ns))
    poll = UInt64(max(poll_ns, 0))

    while true
        testcb() && return :ok
        now = monotonic_time_ns()
        now >= deadline && return :timed_out

        remaining = deadline - now
        sleep_ns = poll == 0 ? remaining : min(remaining, poll)
        thread_sleep_ns(sleep_ns)
    end
end

"""
    timedwait_poll(testcb, timeout_s; poll_s=0.001) -> (:ok | :timed_out)

Libuv-free replacement for `Base.timedwait`. Polls `testcb()` until it returns
true or the timeout expires.
"""
function timedwait_poll(testcb, timeout_s::Real; poll_s::Real = 0.001)::Symbol
    testcb() && return :ok
    timeout_s <= 0 && return :timed_out

    timeout_ns = UInt64(round(Float64(timeout_s) * Float64(TIMESTAMP_NANOS)))
    poll_ns = poll_s <= 0 ? 0 : Int(round(Float64(poll_s) * Float64(TIMESTAMP_NANOS)))
    return timedwait_poll_ns(testcb, timeout_ns; poll_ns = poll_ns)
end
