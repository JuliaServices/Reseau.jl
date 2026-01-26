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
        const FILE_TIME_TO_NS = UInt64(100)
        const EC_TO_UNIX_EPOCH = UInt64(11644473600)
        const WINDOWS_TICK = UInt64(10000000)

        ft = Ref{_filetime}()
        ccall((:GetSystemTimeAsFileTime, "kernel32"), Cvoid, (Ref{_filetime},), ft)
        quad = (UInt64(ft[].dwHighDateTime) << 32) | UInt64(ft[].dwLowDateTime)
        unsafe_store!(timestamp, (quad - (WINDOWS_TICK * EC_TO_UNIX_EPOCH)) * FILE_TIME_TO_NS)
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
