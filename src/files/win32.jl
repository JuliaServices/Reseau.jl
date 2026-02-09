# Shared Win32 helpers for the root `Reseau.Files` module.

using ..Reseau: _PLATFORM_WINDOWS

@static if _PLATFORM_WINDOWS
    const _INVALID_HANDLE_VALUE = Ptr{Cvoid}(-1)

    @inline function _win_get_last_error()::UInt32
        return @ccall "kernel32".GetLastError()::UInt32
    end

    @inline function _win_throw(func::AbstractString)
        throw(Base.windowserror(func, _win_get_last_error()))
    end

    struct _FILETIME
        dwLowDateTime::UInt32
        dwHighDateTime::UInt32
    end
end

