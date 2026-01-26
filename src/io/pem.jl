# AWS IO Library - PEM Parsing Utilities
# Port of aws-c-io/source/pem.c

# PEM object types
@enumx PemObjectType::UInt8 begin
    UNKNOWN = 0
    X509_OLD = 1           # -----BEGIN X509 CERTIFICATE-----
    X509 = 2               # -----BEGIN CERTIFICATE-----
    PUBLIC_KEY = 3         # -----BEGIN PUBLIC KEY-----
    RSA_PRIVATE_KEY = 4    # -----BEGIN RSA PRIVATE KEY-----
    EC_PRIVATE_KEY = 5     # -----BEGIN EC PRIVATE KEY-----
    DSA_PRIVATE_KEY = 6    # -----BEGIN DSA PRIVATE KEY-----
    PRIVATE_KEY = 7        # -----BEGIN PRIVATE KEY-----
    ENCRYPTED_PRIVATE_KEY = 8  # -----BEGIN ENCRYPTED PRIVATE KEY-----
    DH_PARAMETERS = 9      # -----BEGIN DH PARAMETERS-----
    EC_PARAMETERS = 10     # -----BEGIN EC PARAMETERS-----
    CRL = 11               # -----BEGIN X509 CRL-----
end

# Mapping of PEM begin/end markers to object types
const PEM_MARKERS = [
    ("-----BEGIN X509 CERTIFICATE-----", "-----END X509 CERTIFICATE-----", PemObjectType.X509_OLD),
    ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", PemObjectType.X509),
    ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", PemObjectType.PUBLIC_KEY),
    ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", PemObjectType.RSA_PRIVATE_KEY),
    ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", PemObjectType.EC_PRIVATE_KEY),
    ("-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----", PemObjectType.DSA_PRIVATE_KEY),
    ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", PemObjectType.PRIVATE_KEY),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----", PemObjectType.ENCRYPTED_PRIVATE_KEY),
    ("-----BEGIN DH PARAMETERS-----", "-----END DH PARAMETERS-----", PemObjectType.DH_PARAMETERS),
    ("-----BEGIN EC PARAMETERS-----", "-----END EC PARAMETERS-----", PemObjectType.EC_PARAMETERS),
    ("-----BEGIN X509 CRL-----", "-----END X509 CRL-----", PemObjectType.CRL),
]

# A single PEM object
struct PemObject
    object_type::PemObjectType.T
    type_string::String  # The label from the PEM header (e.g., "CERTIFICATE")
    data::ByteBuffer  # Decoded binary data (DER format)
end

# Parse a PEM-encoded string into a list of PEM objects
function pem_parse(pem_data::AbstractString)::Union{Vector{PemObject}, ErrorResult}
    return pem_parse(Vector{UInt8}(pem_data))
end

function pem_parse(pem_data::AbstractVector{UInt8})::Union{Vector{PemObject}, ErrorResult}
    objects = Vector{PemObject}()
    data_str = String(copy(pem_data))

    logf(LogLevel.TRACE, LS_IO_PEM, "PEM: parsing $(length(data_str)) bytes")

    pos = 1
    while pos <= length(data_str)
        # Find next BEGIN marker
        begin_idx = findfirst("-----BEGIN ", SubString(data_str, pos))

        if begin_idx === nothing
            break  # No more PEM objects
        end

        begin_start = pos + first(begin_idx) - 1

        # Find the end of the BEGIN line
        begin_end = findnext('\n', data_str, begin_start)
        if begin_end === nothing
            logf(LogLevel.ERROR, LS_IO_PEM, "PEM: malformed - no newline after BEGIN")
            raise_error(ERROR_IO_PEM_MALFORMED)
            return ErrorResult(ERROR_IO_PEM_MALFORMED)
        end

        begin_line = strip(data_str[begin_start:begin_end-1])

        # Extract type label
        type_label = ""
        for (begin_marker, end_marker, obj_type) in PEM_MARKERS
            if startswith(begin_line, begin_marker)
                type_label = replace(begin_marker, "-----BEGIN " => "", "-----" => "")
                break
            end
        end

        # Find matching END marker
        expected_end = replace(begin_line, "BEGIN" => "END")
        end_idx = findfirst(expected_end, SubString(data_str, begin_end))

        if end_idx === nothing
            logf(LogLevel.ERROR, LS_IO_PEM, "PEM: malformed - no matching END marker for $begin_line")
            raise_error(ERROR_IO_PEM_MALFORMED)
            return ErrorResult(ERROR_IO_PEM_MALFORMED)
        end

        end_start = begin_end + first(end_idx) - 1

        # Extract Base64 content between markers
        content_start = begin_end + 1
        content_end = end_start - 1
        base64_content = data_str[content_start:content_end]

        # Remove whitespace from base64 content
        base64_clean = filter(c -> !isspace(c), base64_content)

        # Decode base64
        decoded = try
            base64decode(base64_clean)
        catch e
            logf(LogLevel.ERROR, LS_IO_PEM, "PEM: base64 decode failed: $e")
            raise_error(ERROR_IO_PEM_MALFORMED)
            return ErrorResult(ERROR_IO_PEM_MALFORMED)
        end

        # Determine object type
        obj_type = PemObjectType.UNKNOWN
        for (begin_marker, end_marker, marker_type) in PEM_MARKERS
            if startswith(begin_line, begin_marker)
                obj_type = marker_type
                break
            end
        end

        # Create ByteBuffer with decoded data
        buf = ByteBuffer(length(decoded))
        if !isempty(decoded)
            unsafe_copyto!(pointer(getfield(buf, :mem)), pointer(decoded), length(decoded))
            setfield!(buf, :len, Csize_t(length(decoded)))
        end

        pem_obj = PemObject(obj_type, type_label, buf)
        push!(objects, pem_obj)

        logf(LogLevel.TRACE, LS_IO_PEM,
            "PEM: parsed object type=$(obj_type), label='$type_label', size=$(length(decoded))")

        # Move past this object
        end_line = findnext('\n', data_str, end_start)
        pos = end_line === nothing ? length(data_str) + 1 : end_line + 1
    end

    logf(LogLevel.DEBUG, LS_IO_PEM, "PEM: parsed $(length(objects)) objects")

    return objects
end

# Read and parse PEM from a file
function pem_parse_from_file(path::AbstractString)::Union{Vector{PemObject}, ErrorResult}
    if !isfile(path)
        logf(LogLevel.ERROR, LS_IO_PEM, "PEM: file not found: $path")
        raise_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        return ErrorResult(ERROR_IO_FILE_VALIDATION_FAILURE)
    end

    data = try
        read(path)
    catch e
        logf(LogLevel.ERROR, LS_IO_PEM, "PEM: failed to read file $path: $e")
        raise_error(ERROR_IO_STREAM_READ_FAILED)
        return ErrorResult(ERROR_IO_STREAM_READ_FAILED)
    end

    return pem_parse(data)
end

# Check if PEM object is a certificate
function pem_is_certificate(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.X509 || obj.object_type == PemObjectType.X509_OLD
end

# Check if PEM object is a private key
function pem_is_private_key(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.RSA_PRIVATE_KEY ||
           obj.object_type == PemObjectType.EC_PRIVATE_KEY ||
           obj.object_type == PemObjectType.DSA_PRIVATE_KEY ||
           obj.object_type == PemObjectType.PRIVATE_KEY ||
           obj.object_type == PemObjectType.ENCRYPTED_PRIVATE_KEY
end

# Check if PEM object is a public key
function pem_is_public_key(obj::PemObject)::Bool
    return obj.object_type == PemObjectType.PUBLIC_KEY
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
    # Find markers for this type
    begin_marker = ""
    end_marker = ""

    for (bm, em, ot) in PEM_MARKERS
        if ot == object_type
            begin_marker = bm
            end_marker = em
            break
        end
    end

    if isempty(begin_marker)
        # Use generic format
        begin_marker = "-----BEGIN UNKNOWN-----"
        end_marker = "-----END UNKNOWN-----"
    end

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
        unsafe_wrap(Array, pointer(getfield(obj.data, :mem)), obj.data.len; own=false),
        obj.object_type
    )
end
