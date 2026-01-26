@static if _PLATFORM_WINDOWS
    const time_t = Int64
else
    const time_t = Clong
end

@static if _PLATFORM_WINDOWS
    struct tm
        tm_sec::Cint
        tm_min::Cint
        tm_hour::Cint
        tm_mday::Cint
        tm_mon::Cint
        tm_year::Cint
        tm_wday::Cint
        tm_yday::Cint
        tm_isdst::Cint
    end
else
    struct tm
        tm_sec::Cint
        tm_min::Cint
        tm_hour::Cint
        tm_mday::Cint
        tm_mon::Cint
        tm_year::Cint
        tm_wday::Cint
        tm_yday::Cint
        tm_isdst::Cint
        tm_gmtoff::Clong
        tm_zone::Ptr{UInt8}
    end
end

function timegm(t::Ptr{tm})
    precondition(t != C_NULL)
    @static if _PLATFORM_WINDOWS
        return ccall(:_mkgmtime, time_t, (Ptr{tm},), t)
    else
        return ccall(:timegm, time_t, (Ptr{tm},), t)
    end
end

function timegm(t::Base.RefValue{tm})
    return timegm(Base.unsafe_convert(Ptr{tm}, t))
end

function localtime(time::time_t, t::Ptr{tm})
    precondition(t != C_NULL)
    time_ref = Ref{time_t}(time)
    @static if _PLATFORM_WINDOWS
        ccall(:localtime_s, Cint, (Ptr{tm}, Ref{time_t}), t, time_ref)
    else
        ccall(:localtime_r, Ptr{tm}, (Ref{time_t}, Ptr{tm}), time_ref, t)
    end
    return nothing
end

function localtime(time::time_t, t::Base.RefValue{tm})
    return localtime(time, Base.unsafe_convert(Ptr{tm}, t))
end

function gmtime(time::time_t, t::Ptr{tm})
    precondition(t != C_NULL)
    time_ref = Ref{time_t}(time)
    @static if _PLATFORM_WINDOWS
        ccall(:gmtime_s, Cint, (Ptr{tm}, Ref{time_t}), t, time_ref)
    else
        ccall(:gmtime_r, Ptr{tm}, (Ref{time_t}, Ptr{tm}), time_ref, t)
    end
    return nothing
end

function gmtime(time::time_t, t::Base.RefValue{tm})
    return gmtime(time, Base.unsafe_convert(Ptr{tm}, t))
end
