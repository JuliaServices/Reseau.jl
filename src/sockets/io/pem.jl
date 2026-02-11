# AWS IO Library - PEM Parsing Utilities
# Port of aws-c-io/source/pem.c
using Base64: base64decode, base64encode

# PEM object types
@enumx PemObjectType::UInt8 begin
    UNKNOWN = 0
    X509_OLD = 1
    X509 = 2
    X509_TRUSTED = 3
    X509_REQ_OLD = 4
    X509_REQ = 5
    X509_CRL = 6
    EVP_PKEY = 7
    PUBLIC_KEY = 8
    RSA_PRIVATE_KEY = 9
    RSA_PUBLIC_KEY = 10
    DSA_PRIVATE_KEY = 11
    DSA_PUBLIC_KEY = 12
    PKCS7 = 13
    PKCS7_SIGNED_DATA = 14
    ENCRYPTED_PRIVATE_KEY = 15
    PRIVATE_KEY = 16
    DH_PARAMETERS = 17
    DH_PARAMETERS_X942 = 18
    SSL_SESSION_PARAMETERS = 19
    DSA_PARAMETERS = 20
    ECDSA_PUBLIC_KEY = 21
    EC_PARAMETERS = 22
    EC_PRIVATE_KEY = 23
    PARAMETERS = 24
    CMS = 25
    SM2_PARAMETERS = 26
end

const PEM_BEGIN_PREFIX = "-----BEGIN "
const PEM_END_PREFIX = "-----END "
const PEM_DELIM = "-----"

const PEM_LABELS = [
    ("X509 CERTIFICATE", PemObjectType.X509_OLD),
    ("CERTIFICATE", PemObjectType.X509),
    ("TRUSTED CERTIFICATE", PemObjectType.X509_TRUSTED),
    ("NEW CERTIFICATE REQUEST", PemObjectType.X509_REQ_OLD),
    ("CERTIFICATE REQUEST", PemObjectType.X509_REQ),
    ("X509 CRL", PemObjectType.X509_CRL),
    ("ANY PRIVATE KEY", PemObjectType.EVP_PKEY),
    ("PUBLIC KEY", PemObjectType.PUBLIC_KEY),
    ("RSA PRIVATE KEY", PemObjectType.RSA_PRIVATE_KEY),
    ("RSA PUBLIC KEY", PemObjectType.RSA_PUBLIC_KEY),
    ("DSA PRIVATE KEY", PemObjectType.DSA_PRIVATE_KEY),
    ("DSA PUBLIC KEY", PemObjectType.DSA_PUBLIC_KEY),
    ("PKCS7", PemObjectType.PKCS7),
    ("PKCS #7 SIGNED DATA", PemObjectType.PKCS7_SIGNED_DATA),
    ("ENCRYPTED PRIVATE KEY", PemObjectType.ENCRYPTED_PRIVATE_KEY),
    ("PRIVATE KEY", PemObjectType.PRIVATE_KEY),
    ("DH PARAMETERS", PemObjectType.DH_PARAMETERS),
    ("X9.42 DH PARAMETERS", PemObjectType.DH_PARAMETERS_X942),
    ("SSL SESSION PARAMETERS", PemObjectType.SSL_SESSION_PARAMETERS),
    ("DSA PARAMETERS", PemObjectType.DSA_PARAMETERS),
    ("ECDSA PUBLIC KEY", PemObjectType.ECDSA_PUBLIC_KEY),
    ("EC PARAMETERS", PemObjectType.EC_PARAMETERS),
    ("EC PRIVATE KEY", PemObjectType.EC_PRIVATE_KEY),
    ("PARAMETERS", PemObjectType.PARAMETERS),
    ("CMS", PemObjectType.CMS),
    ("SM2 PARAMETERS", PemObjectType.SM2_PARAMETERS),
]

const PEM_LABEL_TO_TYPE = Dict{String, PemObjectType.T}(
    label => obj_type for (label, obj_type) in PEM_LABELS
)
const PEM_TYPE_TO_LABEL = Dict{PemObjectType.T, String}(
    obj_type => label for (label, obj_type) in PEM_LABELS
)

# A single PEM object
struct PemObject
    object_type::PemObjectType.T
    type_string::String  # The label from the PEM header (e.g., "CERTIFICATE")
    data::ByteBuffer  # Decoded binary data (DER format)
end

@inline function _extract_pem_label(line::AbstractString)::Union{String, Nothing}
    if !startswith(line, PEM_BEGIN_PREFIX) || !endswith(line, PEM_DELIM)
        return nothing
    end
    label_start = length(PEM_BEGIN_PREFIX) + 1
    label_end = lastindex(line) - length(PEM_DELIM)
    if label_end < label_start
        return nothing
    end
    label = strip(line[label_start:label_end])
    return isempty(label) ? nothing : label
end

# Parse a PEM-encoded string into a list of PEM objects
function pem_parse(pem_data::AbstractString)::Vector{PemObject}
    return pem_parse(Vector{UInt8}(pem_data))
end

function pem_parse(pem_data::AbstractVector{UInt8})::Vector{PemObject}
    objects = Vector{PemObject}()
    data_str = String(copy(pem_data))

    logf(LogLevel.TRACE, LS_IO_PEM, "PEM: parsing $(length(data_str)) bytes")

    state = :BEGIN
    current_label = ""
    current_obj_type = PemObjectType.UNKNOWN
    base64_lines = String[]

    for line in split(data_str, '\n'; keepempty = true)
        trimmed = strip(line)
        if state === :BEGIN
            if startswith(trimmed, PEM_BEGIN_PREFIX)
                label = _extract_pem_label(trimmed)
                if label === nothing
                    logf(LogLevel.ERROR, LS_IO_PEM, "PEM: malformed - invalid BEGIN header")
                    throw_error(ERROR_IO_PEM_MALFORMED)
                end
                current_label = label
                current_obj_type = get(() -> PemObjectType.UNKNOWN, PEM_LABEL_TO_TYPE, label)
                empty!(base64_lines)
                state = :ON_DATA
            end
        else
            if startswith(trimmed, "-----END")
                base64_clean = join(base64_lines)
                decoded = try
                    base64decode(base64_clean)
                catch e
                    logf(LogLevel.ERROR, LS_IO_PEM, "PEM: base64 decode failed: $e")
                    throw_error(ERROR_IO_PEM_MALFORMED)
                end

                buf = ByteBuffer(length(decoded))
                if !isempty(decoded)
                    copyto!(buf.mem, 1, decoded, 1, length(decoded))
                    setfield!(buf, :len, Csize_t(length(decoded)))
                end

                pem_obj = PemObject(current_obj_type, current_label, buf)
                push!(objects, pem_obj)

                logf(
                    LogLevel.TRACE, LS_IO_PEM,
                    "PEM: parsed object type=$(current_obj_type), label='$current_label', size=$(length(decoded))"
                )

                state = :BEGIN
                current_label = ""
                current_obj_type = PemObjectType.UNKNOWN
            else
                if !isempty(trimmed)
                    push!(base64_lines, trimmed)
                end
            end
        end
    end

    if state === :BEGIN && !isempty(objects)
        logf(LogLevel.DEBUG, LS_IO_PEM, "PEM: parsed $(length(objects)) objects")
        return objects
    end

    logf(LogLevel.ERROR, LS_IO_PEM, "PEM: malformed - invalid PEM buffer")
    throw_error(ERROR_IO_PEM_MALFORMED)
end

# Read and parse PEM from a file
function pem_parse_from_file(path::AbstractString)::Vector{PemObject}
    if !isfile(path)
        logf(LogLevel.ERROR, LS_IO_PEM, "PEM: file not found: $path")
        throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    end

    data = try
        read(path)
    catch e
        logf(LogLevel.ERROR, LS_IO_PEM, "PEM: failed to read file $path: $e")
        throw_error(ERROR_IO_STREAM_READ_FAILED)
    end

    return pem_parse(data)
end

# Check if PEM object is a certificate
function pem_is_certificate(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.X509 ||
        obj.object_type == PemObjectType.X509_OLD ||
        obj.object_type == PemObjectType.X509_TRUSTED
end

# Check if PEM object is a private key
function pem_is_private_key(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.RSA_PRIVATE_KEY ||
        obj.object_type == PemObjectType.EC_PRIVATE_KEY ||
        obj.object_type == PemObjectType.DSA_PRIVATE_KEY ||
        obj.object_type == PemObjectType.PRIVATE_KEY ||
        obj.object_type == PemObjectType.ENCRYPTED_PRIVATE_KEY ||
        obj.object_type == PemObjectType.EVP_PKEY
end

# Check if PEM object is a public key
function pem_is_public_key(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.PUBLIC_KEY ||
        obj.object_type == PemObjectType.RSA_PUBLIC_KEY ||
        obj.object_type == PemObjectType.DSA_PUBLIC_KEY ||
        obj.object_type == PemObjectType.ECDSA_PUBLIC_KEY
end

# Filter PEM objects by type
function pem_filter_certificates(objects::Vector{PemObject})
    return filter(pem_is_certificate, objects)
end

function pem_filter_private_keys(objects::Vector{PemObject})
    return filter(pem_is_private_key, objects)
end

# Encode a DER buffer back to PEM format
function pem_encode(
        der_data::AbstractVector{UInt8},
        object_type::PemObjectType.T,
    )::String
    label = get(() -> "UNKNOWN", PEM_TYPE_TO_LABEL, object_type)
    begin_marker = PEM_BEGIN_PREFIX * label * PEM_DELIM
    end_marker = PEM_END_PREFIX * label * PEM_DELIM

    # Base64 encode
    encoded = base64encode(der_data)

    # Split into 64-character lines
    lines = String[]
    push!(lines, begin_marker)

    for i in 1:64:length(encoded)
        end_idx = min(i + 63, length(encoded))
        push!(lines, encoded[i:end_idx])
    end

    push!(lines, end_marker)

    return join(lines, "\n") * "\n"
end

function pem_encode(obj::PemObject)::String
    return pem_encode(
        unsafe_wrap(Array, pointer(getfield(obj.data, :mem)), obj.data.len; own = false),
        obj.object_type
    )
end
