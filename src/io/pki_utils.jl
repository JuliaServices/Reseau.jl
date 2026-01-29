# AWS IO Library - PKI Utilities
# Port of aws-c-io/include/aws/io/private/pki_utils.h (partial: default paths)

const _PKI_DIR_CANDIDATES = (
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/system/etc/security/cacerts",
    "/usr/local/share/certs",
    "/etc/openssl/certs",
)

const _PKI_CA_FILE_CANDIDATES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
)

@inline function _path_exists(path::AbstractString)::Bool
    @static if Sys.iswindows()
        rc = ccall(:_access, Cint, (Cstring, Cint), path, 0)
    else
        rc = ccall(:access, Cint, (Cstring, Cint), path, 0)
    end
    return rc == 0
end

function determine_default_pki_dir(; path_exists::Function = _path_exists)::Union{String, Nothing}
    for candidate in _PKI_DIR_CANDIDATES
        if path_exists(candidate)
            return candidate
        end
    end
    return nothing
end

function determine_default_pki_ca_file(; path_exists::Function = _path_exists)::Union{String, Nothing}
    for candidate in _PKI_CA_FILE_CANDIDATES
        if path_exists(candidate)
            return candidate
        end
    end
    return nothing
end

# Platform-specific PKI helpers (stubs until implemented).

function import_public_and_private_keys_to_identity(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        keychain_path::Union{String, Nothing} = nothing,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = public_cert_chain
    _ = private_key
    _ = keychain_path
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function import_pkcs12_to_identity(
        pkcs12_cursor::ByteCursor,
        password::ByteCursor,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = pkcs12_cursor
    _ = password
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function import_trusted_certificates(
        certificates_blob::ByteCursor,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = certificates_blob
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function secitem_import_cert_and_key(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        cert_label::Union{String, Nothing} = nothing,
        key_label::Union{String, Nothing} = nothing,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = public_cert_chain
    _ = private_key
    _ = cert_label
    _ = key_label
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function secitem_import_pkcs12(
        pkcs12_cursor::ByteCursor,
        password::ByteCursor;
        cert_label::Union{String, Nothing} = nothing,
        key_label::Union{String, Nothing} = nothing,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = pkcs12_cursor
    _ = password
    _ = cert_label
    _ = key_label
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function load_cert_from_system_cert_store(
        cert_path::AbstractString,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = cert_path
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function close_cert_store(cert_store::Ptr{Cvoid})::Nothing
    _ = cert_store
    return nothing
end

function import_key_pair_to_cert_context(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        is_client_mode::Bool = true,
    )::Union{Ptr{Cvoid}, ErrorResult}
    _ = public_cert_chain
    _ = private_key
    _ = is_client_mode
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end
