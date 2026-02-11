# AWS IO Library - Shared Library Loading
# Port of aws-c-io/source/shared_library.c

# Shared library handle
mutable struct SharedLibrary
    handle::Ptr{Cvoid}
    path::String
end

SharedLibrary() = SharedLibrary(C_NULL, "")

function shared_library_init!(lib::SharedLibrary, path::AbstractString)::Nothing
    res = shared_library_load(path)
    lib.handle = res.handle
    lib.path = res.path
    return nothing
end

function shared_library_clean_up!(lib::SharedLibrary)::Nothing
    return shared_library_unload!(lib)
end

# Load a shared library from path
function shared_library_load(path::AbstractString)::SharedLibrary
    # SECURITY: callers should avoid passing untrusted/relative paths (especially on Windows),
    # since platform loader search rules can enable DLL hijacking.
    logf(LogLevel.DEBUG, LS_IO_SHARED_LIBRARY, "SharedLib: loading '$path'")

    handle = @static if Sys.iswindows()
        # Windows: LoadLibraryW
        ccall(:LoadLibraryW, Ptr{Cvoid}, (Cwstring,), path)
    else
        # POSIX: dlopen
        ccall(:dlopen, Ptr{Cvoid}, (Cstring, Cint), path, Cint(1))  # RTLD_LAZY = 1
    end

    if handle == C_NULL
        @static if Sys.iswindows()
            logf(
                LogLevel.ERROR, LS_IO_SHARED_LIBRARY,
                "SharedLib: failed to load '$path'"
            )
        else
            err_msg = unsafe_string(ccall(:dlerror, Cstring, ()))
            logf(
                LogLevel.ERROR, LS_IO_SHARED_LIBRARY,
                "SharedLib: failed to load '$path': $err_msg"
            )
        end
        throw_error(ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE)
    end

    logf(
        LogLevel.DEBUG, LS_IO_SHARED_LIBRARY,
        "SharedLib: loaded '$path' at handle $handle"
    )

    return SharedLibrary(handle, String(path))
end

# Load a shared library with default system search
function shared_library_load_default()::SharedLibrary
    logf(LogLevel.DEBUG, LS_IO_SHARED_LIBRARY, "SharedLib: loading default library")

    handle = @static if Sys.iswindows()
        # Windows: get current module
        ccall(:GetModuleHandleW, Ptr{Cvoid}, (Ptr{Cvoid},), C_NULL)
    else
        # POSIX: dlopen with NULL path gets the main program
        ccall(:dlopen, Ptr{Cvoid}, (Ptr{Cvoid}, Cint), C_NULL, Cint(1))
    end

    if handle == C_NULL
        throw_error(ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE)
    end

    return SharedLibrary(handle, "")
end

# Find a symbol in the shared library
function shared_library_find_symbol(lib::SharedLibrary, symbol_name::AbstractString)::Ptr{Cvoid}
    if lib.handle == C_NULL
        throw_error(ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE)
    end

    sym = @static if Sys.iswindows()
        ccall(:GetProcAddress, Ptr{Cvoid}, (Ptr{Cvoid}, Cstring), lib.handle, symbol_name)
    else
        ccall(:dlsym, Ptr{Cvoid}, (Ptr{Cvoid}, Cstring), lib.handle, symbol_name)
    end

    if sym == C_NULL
        @static if Sys.iswindows()
            logf(
                LogLevel.ERROR, LS_IO_SHARED_LIBRARY,
                "SharedLib: symbol '$symbol_name' not found in '$(lib.path)'"
            )
        else
            err_msg = unsafe_string(ccall(:dlerror, Cstring, ()))
            logf(
                LogLevel.ERROR, LS_IO_SHARED_LIBRARY,
                "SharedLib: symbol '$symbol_name' not found: $err_msg"
            )
        end
        throw_error(ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE)
    end

    logf(
        LogLevel.TRACE, LS_IO_SHARED_LIBRARY,
        "SharedLib: found symbol '$symbol_name' at $sym"
    )

    return sym
end

# Find a symbol and cast to function pointer
function shared_library_find_function(lib::SharedLibrary, symbol_name::AbstractString, ::Type{T})::Ptr{T} where {T}
    sym = shared_library_find_symbol(lib, symbol_name)
    return Ptr{T}(sym)
end

# Check if a symbol exists in the library
function shared_library_has_symbol(lib::SharedLibrary, symbol_name::AbstractString)::Bool
    try
        shared_library_find_symbol(lib, symbol_name)
        return true
    catch
        return false
    end
end

# Unload a shared library
function shared_library_unload!(lib::SharedLibrary)::Nothing
    if lib.handle == C_NULL
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_SHARED_LIBRARY,
        "SharedLib: unloading '$(lib.path)'"
    )

    result = @static if Sys.iswindows()
        ccall(:FreeLibrary, Cint, (Ptr{Cvoid},), lib.handle)
    else
        ccall(:dlclose, Cint, (Ptr{Cvoid},), lib.handle)
    end

    lib.handle = C_NULL

    if result != 0
        logf(
            LogLevel.WARN, LS_IO_SHARED_LIBRARY,
            "SharedLib: unload returned non-zero: $result"
        )
    end

    return nothing
end

# Check if library is loaded
shared_library_is_loaded(lib::SharedLibrary) = lib.handle != C_NULL

# Get platform-specific library extension
function shared_library_extension()::String
    @static if Sys.iswindows()
        return ".dll"
    elseif Sys.isapple()
        return ".dylib"
    else
        return ".so"
    end
end

# Build platform-specific library name from base name
function shared_library_name(base_name::AbstractString)::String
    @static if Sys.iswindows()
        return string(base_name, ".dll")
    elseif Sys.isapple()
        return string("lib", base_name, ".dylib")
    else
        return string("lib", base_name, ".so")
    end
end
