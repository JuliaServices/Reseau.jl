const _TLS_TEST_ENV = "RESEAU_RUN_TLS_TESTS"

function tls_tests_enabled()::Bool
    val = lowercase(get(ENV, _TLS_TEST_ENV, ""))
    return !isempty(val) && (val == "1" || val == "true" || val == "yes" || val == "y" || val == "on")
end

function test_resource_path(name::AbstractString)::String
    root = dirname(@__DIR__)
    roots = (
        joinpath(root, "test", "resources"),
        joinpath(root, "aws-c-io", "tests", "resources"),
    )
    for resource_root in roots
        path = joinpath(resource_root, name)
        isfile(path) && return path
    end
    return joinpath(first(roots), name)
end

const _TEST_KEYCHAIN_PATH = Ref{Union{String, Nothing}}(nothing)
const _TEST_KEYCHAIN_DIR = Ref{Union{String, Nothing}}(nothing)
const _TEST_KEYCHAIN_REF = Ref{Ptr{Cvoid}}(C_NULL)
const _SECURITY_LIB = "/System/Library/Frameworks/Security.framework/Security"
const _errSecSuccess = Int32(0)
const _TEMP_CLEANUP_RETRY_DELAY_SEC = 0.05
const _TEMP_CLEANUP_MAX_RETRIES = Sys.iswindows() ? 120 : 1

function _is_retryable_temp_cleanup_error(err)::Bool
    if err isa Base.IOError
        return err.code == Base.UV_EBUSY || err.code == Base.UV_EACCES || err.code == Base.UV_EPERM
    end
    return false
end

function cleanup_temp_path!(path::AbstractString)::Nothing
    if !ispath(path)
        return nothing
    end

    for attempt in 1:_TEMP_CLEANUP_MAX_RETRIES
        try
            rm(path; recursive = true, force = true)
            return nothing
        catch err
            if !(Sys.iswindows() && _is_retryable_temp_cleanup_error(err) && attempt < _TEMP_CLEANUP_MAX_RETRIES)
                rethrow()
            end
            # Windows can keep transient handles open briefly after process/file teardown.
            GC.gc(false)
            yield()
            sleep(_TEMP_CLEANUP_RETRY_DELAY_SEC)
        end
    end
    return nothing
end

function with_tempdir(f::F) where {F <: Function}
    temp_dir = mktempdir(; cleanup = false)
    try
        return f(temp_dir)
    finally
        cleanup_temp_path!(temp_dir)
    end
end

function _create_test_keychain!(path::AbstractString)::Bool
    if !Sys.isapple()
        return false
    end
    keychain_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = ccall(
        (:SecKeychainCreate, _SECURITY_LIB),
        Int32,
        (Cstring, UInt32, Cstring, UInt8, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        path,
        UInt32(0),
        "",
        UInt8(0),
        C_NULL,
        keychain_ref,
    )
    if status != _errSecSuccess || keychain_ref[] == C_NULL
        return false
    end
    unlock_status = ccall(
        (:SecKeychainUnlock, _SECURITY_LIB),
        Int32,
        (Ptr{Cvoid}, UInt32, Cstring, UInt8),
        keychain_ref[],
        UInt32(0),
        "",
        UInt8(1),
    )
    if unlock_status != _errSecSuccess
        _ = ccall((:CFRelease, "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"), Cvoid, (Ptr{Cvoid},), keychain_ref[])
        return false
    end
    _TEST_KEYCHAIN_REF[] = keychain_ref[]
    return true
end

function setup_test_keychain!()::Nothing
    if !Sys.isapple() || !tls_tests_enabled()
        return nothing
    end
    _TEST_KEYCHAIN_PATH[] !== nothing && return nothing
    temp_dir = mktempdir()
    path = joinpath(temp_dir, "reseau-test.keychain")
    if !_create_test_keychain!(path)
        _TEST_KEYCHAIN_DIR[] = nothing
        _TEST_KEYCHAIN_PATH[] = nothing
        return nothing
    end
    _TEST_KEYCHAIN_DIR[] = temp_dir
    _TEST_KEYCHAIN_PATH[] = path
    return nothing
end

function cleanup_test_keychain!()::Nothing
    if !Sys.isapple()
        return nothing
    end
    if _TEST_KEYCHAIN_REF[] != C_NULL
        _ = ccall((:SecKeychainDelete, _SECURITY_LIB), Int32, (Ptr{Cvoid},), _TEST_KEYCHAIN_REF[])
        _ = ccall((:CFRelease, "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"), Cvoid, (Ptr{Cvoid},), _TEST_KEYCHAIN_REF[])
    end
    if _TEST_KEYCHAIN_PATH[] !== nothing && isfile(_TEST_KEYCHAIN_PATH[])
        rm(_TEST_KEYCHAIN_PATH[]; force = true)
    end
    if _TEST_KEYCHAIN_DIR[] !== nothing && isdir(_TEST_KEYCHAIN_DIR[])
        rm(_TEST_KEYCHAIN_DIR[]; recursive = true, force = true)
    end
    _TEST_KEYCHAIN_PATH[] = nothing
    _TEST_KEYCHAIN_DIR[] = nothing
    _TEST_KEYCHAIN_REF[] = C_NULL
    return nothing
end

function test_keychain_path()::Union{String, Nothing}
    return _TEST_KEYCHAIN_PATH[]
end

function maybe_apply_test_keychain!(opts)
    if Sys.isapple() && !Sockets.is_using_secitem()
        path = test_keychain_path()
        if path !== nothing && opts isa Sockets.TlsContextOptions
            _ = Sockets.tls_ctx_options_set_keychain_path!(opts, path)
        end
    end
    return opts
end

function cleanup_test_sockets!()::Nothing
    root = dirname(@__DIR__)
    for name in readdir(root)
        if startswith(name, "testsock") && endswith(name, ".sock")
            path = joinpath(root, name)
            try
                rm(path; force = true)
            catch
                # Best-effort cleanup. Ignore errors for files that were already removed.
            end
        end
    end
    return nothing
end
