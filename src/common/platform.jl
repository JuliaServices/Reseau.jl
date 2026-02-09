const _PLATFORM_WINDOWS = Sys.iswindows()
const _PLATFORM_LINUX = Sys.islinux()
const _PLATFORM_APPLE = Sys.isapple()

const _IS_LITTLE_ENDIAN = Base.ENDIAN_BOM == 0x04030201

@static if !(_PLATFORM_WINDOWS || _PLATFORM_APPLE || _PLATFORM_LINUX)
    error("platform not supported")
end

@static if _PLATFORM_APPLE
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(6)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(-1)
elseif _PLATFORM_LINUX
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(1)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(7)
end

@inline function _fcntl(fd::Cint, cmd::Cint, arg::Cint = Cint(0))::Cint
    @static if _PLATFORM_WINDOWS
        return Cint(-1)
    else
        return @ccall fcntl(fd::Cint, cmd::Cint; arg::Cint)::Cint
    end
end
