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
