# AWS IO Library - PKI Utilities
# Port of aws-c-io/include/aws/io/private/pki_utils.h (partial: default paths)

using Libdl

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

const _PKI_SECURITY_LIB = "/System/Library/Frameworks/Security.framework/Security"
const _PKI_COREFOUNDATION_LIB = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

@static if Sys.isapple()
    @inline function _cf_const(sym::Symbol, lib::AbstractString)::Ptr{Cvoid}
        return unsafe_load(cglobal((sym, lib), Ptr{Cvoid}))
    end

    const _kCFTypeDictionaryKeyCallBacks = cglobal((:kCFTypeDictionaryKeyCallBacks, _PKI_COREFOUNDATION_LIB), Cvoid)
    const _kCFTypeDictionaryValueCallBacks = cglobal((:kCFTypeDictionaryValueCallBacks, _PKI_COREFOUNDATION_LIB), Cvoid)

    const _kSecClass = _cf_const(:kSecClass, _PKI_SECURITY_LIB)
    const _kSecClassCertificate = _cf_const(:kSecClassCertificate, _PKI_SECURITY_LIB)
    const _kSecClassKey = _cf_const(:kSecClassKey, _PKI_SECURITY_LIB)
    const _kSecClassIdentity = _cf_const(:kSecClassIdentity, _PKI_SECURITY_LIB)
    const _kSecAttrSerialNumber = _cf_const(:kSecAttrSerialNumber, _PKI_SECURITY_LIB)
    const _kSecAttrLabel = _cf_const(:kSecAttrLabel, _PKI_SECURITY_LIB)
    const _kSecValueRef = _cf_const(:kSecValueRef, _PKI_SECURITY_LIB)
    const _kSecAttrKeyClass = _cf_const(:kSecAttrKeyClass, _PKI_SECURITY_LIB)
    const _kSecAttrKeyClassPrivate = _cf_const(:kSecAttrKeyClassPrivate, _PKI_SECURITY_LIB)
    const _kSecAttrApplicationLabel = _cf_const(:kSecAttrApplicationLabel, _PKI_SECURITY_LIB)
    const _kSecAttrKeyType = _cf_const(:kSecAttrKeyType, _PKI_SECURITY_LIB)
    const _kSecAttrKeyTypeRSA = _cf_const(:kSecAttrKeyTypeRSA, _PKI_SECURITY_LIB)
    const _kSecAttrKeyTypeEC = _cf_const(:kSecAttrKeyTypeEC, _PKI_SECURITY_LIB)
    const _kSecReturnRef = _cf_const(:kSecReturnRef, _PKI_SECURITY_LIB)
    const _kCFBooleanTrue = _cf_const(:kCFBooleanTrue, _PKI_COREFOUNDATION_LIB)
else
    const _kCFTypeDictionaryKeyCallBacks = C_NULL
    const _kCFTypeDictionaryValueCallBacks = C_NULL
    const _kSecClass = C_NULL
    const _kSecClassCertificate = C_NULL
    const _kSecClassKey = C_NULL
    const _kSecClassIdentity = C_NULL
    const _kSecAttrSerialNumber = C_NULL
    const _kSecAttrLabel = C_NULL
    const _kSecValueRef = C_NULL
    const _kSecAttrKeyClass = C_NULL
    const _kSecAttrKeyClassPrivate = C_NULL
    const _kSecAttrApplicationLabel = C_NULL
    const _kSecAttrKeyType = C_NULL
    const _kSecAttrKeyTypeRSA = C_NULL
    const _kSecAttrKeyTypeEC = C_NULL
    const _kSecReturnRef = C_NULL
    const _kCFBooleanTrue = C_NULL
end

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

const _pki_sec_lock = ReentrantLock()
const _errSecMissingEntitlement = Int32(-34018)

struct SecItemImportExportKeyParameters
    version::UInt32
    flags::UInt32
    passphrase::Ptr{Cvoid}
    alertTitle::Ptr{Cvoid}
    alertPrompt::Ptr{Cvoid}
    accessRef::Ptr{Cvoid}
    keyUsage::Ptr{Cvoid}
    keyAttributes::Ptr{Cvoid}
end

const _SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION = UInt32(0)

@inline function _cursor_ptr(cursor::ByteCursor)::Ptr{UInt8}
    mem = memref_parent(cursor.ptr)
    offset = memref_offset(cursor.ptr)
    return pointer(mem) + (offset - 1)
end

function _cursor_to_memory(cursor::ByteCursor)::Memory{UInt8}
    if cursor.len == 0
        return Memory{UInt8}(undef, 0)
    end
    data = Memory{UInt8}(undef, Int(cursor.len))
    unsafe_copyto!(pointer(data), _cursor_ptr(cursor), Int(cursor.len))
    return data
end

function _pki_cf_dict_create()
    @static if Sys.isapple()
        return ccall(
            (:CFDictionaryCreateMutable, _COREFOUNDATION_LIB),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Clong, Ptr{Cvoid}, Ptr{Cvoid}),
            C_NULL,
            0,
            C_NULL,
            C_NULL,
        )
    else
        return C_NULL
    end
end

function _pki_cf_dict_create_typed()
    @static if Sys.isapple()
        return ccall(
            (:CFDictionaryCreateMutable, _COREFOUNDATION_LIB),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Clong, Ptr{Cvoid}, Ptr{Cvoid}),
            C_NULL,
            0,
            _kCFTypeDictionaryKeyCallBacks,
            _kCFTypeDictionaryValueCallBacks,
        )
    else
        return C_NULL
    end
end

function _pki_cf_dict_add_value(dict::Ptr{Cvoid}, key::Ptr{Cvoid}, value::Ptr{Cvoid})
    @static if Sys.isapple()
        ccall((:CFDictionaryAddValue, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), dict, key, value)
    end
    return nothing
end

function _pki_cf_array_create(values::Memory{Ptr{Cvoid}}, count::Integer)::Ptr{Cvoid}
    @static if Sys.isapple()
        for i in 1:Int(count)
            values[i] == C_NULL && return C_NULL
        end
        return ccall(
            (:CFArrayCreate, _COREFOUNDATION_LIB),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Clong, Ptr{Cvoid}),
            C_NULL,
            pointer(values),
            count,
            _kCFTypeArrayCallBacks,
        )
    else
        return C_NULL
    end
end

function _pki_secitem_import(
        data_ref::Ptr{Cvoid},
        format::UInt32,
        item_type::UInt32,
        keychain::Ptr{Cvoid},
        out_items::Base.RefValue{Ptr{Cvoid}},
    )::Int32
    @static if Sys.isapple()
        fmt = Ref{UInt32}(format)
        typ = Ref{UInt32}(item_type)
        empty_cursor = null_cursor()
        params = SecItemImportExportKeyParameters(
            _SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
            UInt32(0),
            _cf_string_create(_cursor_ptr(empty_cursor), Csize_t(0), _kCFStringEncodingUTF8),
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
        )
        status = ccall(
            (:SecItemImport, _SECURITY_LIB),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt32}, Ref{UInt32}, UInt32, Ref{SecItemImportExportKeyParameters}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
            data_ref,
            C_NULL,
            fmt,
            typ,
            UInt32(0),
            params,
            keychain,
            out_items,
        )
        _cf_release(params.passphrase)
        return status
    else
        return Int32(-1)
    end
end

function _pki_import_ecc_key_into_keychain(private_key::ByteCursor, keychain::Ptr{Cvoid})::Nothing
    pem_objs = pem_parse(_cursor_to_memory(private_key))

    for obj in pem_objs
        data = obj.data
        data_ref = _cf_data_create(pointer(data.mem), data.len)
        data_ref == C_NULL && continue
        out_items = Ref{Ptr{Cvoid}}(C_NULL)
        format = _kSecFormatOpenSSL
        if obj.object_type == PemObjectType.PRIVATE_KEY ||
                obj.object_type == PemObjectType.ENCRYPTED_PRIVATE_KEY ||
                obj.object_type == PemObjectType.EVP_PKEY
            format = _kSecFormatWrappedPKCS8
        end
        status = let
            lock(_pki_sec_lock)
            try
                _pki_secitem_import(data_ref, format, _kSecItemTypePrivateKey, keychain, out_items)
            finally
                unlock(_pki_sec_lock)
            end
        end
        if status != _errSecSuccess && status != _errSecDuplicateItem && format == _kSecFormatWrappedPKCS8
            out_items[] != C_NULL && _cf_release(out_items[])
            out_items[] = C_NULL
            status = let
                lock(_pki_sec_lock)
                try
                    _pki_secitem_import(data_ref, _kSecFormatOpenSSL, _kSecItemTypePrivateKey, keychain, out_items)
                finally
                    unlock(_pki_sec_lock)
                end
            end
        end
        _cf_release(data_ref)
        if status == _errSecSuccess || status == _errSecDuplicateItem
            out_items[] != C_NULL && _cf_release(out_items[])
            return nothing
        end
        out_items[] != C_NULL && _cf_release(out_items[])
    end

    throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
end

# Platform-specific PKI helpers.

function import_public_and_private_keys_to_identity(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        keychain_path::Union{String, Nothing} = nothing,
    )::Ptr{Cvoid}
    @static if !Sys.isapple()
        _ = public_cert_chain
        _ = private_key
        _ = keychain_path
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    cert_data = _cf_data_create(_cursor_ptr(public_cert_chain), public_cert_chain.len)
    cert_data == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)
    key_data = _cf_data_create(_cursor_ptr(private_key), private_key.len)
    if key_data == C_NULL
        _cf_release(cert_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    import_keychain = Ref{Ptr{Cvoid}}(C_NULL)
    if keychain_path !== nothing
        status = ccall((:SecKeychainOpen, _SECURITY_LIB), Int32, (Cstring, Ref{Ptr{Cvoid}}), keychain_path, import_keychain)
        if status != _errSecSuccess
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        status = ccall((:SecKeychainUnlock, _SECURITY_LIB), Int32, (Ptr{Cvoid}, UInt32, Cstring, UInt8), import_keychain[], 0, "", 1)
        if status != _errSecSuccess
            _cf_release(cert_data)
            _cf_release(key_data)
            _cf_release(import_keychain[])
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
    else
        status = ccall((:SecKeychainCopyDefault, _SECURITY_LIB), Int32, (Ref{Ptr{Cvoid}},), import_keychain)
        if status != _errSecSuccess
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
    end

    cert_import_output = Ref{Ptr{Cvoid}}(C_NULL)
    key_import_output = Ref{Ptr{Cvoid}}(C_NULL)
    cert_objects = nothing
    cert_status = let
        lock(_pki_sec_lock)
        try
            _pki_secitem_import(cert_data, _kSecFormatUnknown, _kSecItemTypeCertificate, import_keychain[], cert_import_output)
        finally
            unlock(_pki_sec_lock)
        end
    end
    if cert_status == _errSecUnknownFormat || cert_status == _errSecUnsupportedFormat
        cert_objects = pem_parse(_cursor_to_memory(public_cert_chain))
        if isempty(cert_objects)
            _cf_release(cert_import_output[])
            _cf_release(key_import_output[])
            _cf_release(import_keychain[])
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        end

        root_cert = cert_objects[1].data
        root_data = _cf_data_create(pointer(root_cert.mem), root_cert.len)
        if root_data == C_NULL
            _cf_release(cert_import_output[])
            _cf_release(key_import_output[])
            _cf_release(import_keychain[])
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        cert_import_output[] != C_NULL && _cf_release(cert_import_output[])
        cert_import_output[] = C_NULL
        cert_status = let
            lock(_pki_sec_lock)
            try
                _pki_secitem_import(root_data, _kSecFormatX509Cert, _kSecItemTypeCertificate, import_keychain[], cert_import_output)
            finally
                unlock(_pki_sec_lock)
            end
        end
        _cf_release(root_data)
    end

    key_status = let
        lock(_pki_sec_lock)
        try
            _pki_secitem_import(key_data, _kSecFormatUnknown, _kSecItemTypePrivateKey, import_keychain[], key_import_output)
        finally
            unlock(_pki_sec_lock)
        end
    end

    if cert_status != _errSecSuccess && cert_status != _errSecDuplicateItem
        _cf_release(cert_import_output[])
        _cf_release(key_import_output[])
        _cf_release(import_keychain[])
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    end

    if key_status == _errSecUnknownFormat || key_status == _errSecUnsupportedFormat
        try
            _pki_import_ecc_key_into_keychain(private_key, import_keychain[])
        catch
            _cf_release(cert_import_output[])
            _cf_release(key_import_output[])
            _cf_release(import_keychain[])
            _cf_release(cert_data)
            _cf_release(key_data)
            rethrow()
        end
    elseif key_status != _errSecSuccess && key_status != _errSecDuplicateItem
        _cf_release(cert_import_output[])
        _cf_release(key_import_output[])
        _cf_release(import_keychain[])
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    end

    certificate_ref = Ref{Ptr{Cvoid}}(C_NULL)
    if cert_status == _errSecDuplicateItem
        cert_objects === nothing && (cert_objects = pem_parse(_cursor_to_memory(public_cert_chain)))
        if isempty(cert_objects)
            _cf_release(cert_import_output[])
            _cf_release(key_import_output[])
            _cf_release(import_keychain[])
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        end
        root_cert = cert_objects[1].data
        root_data = _cf_data_create(pointer(root_cert.mem), root_cert.len)
        root_data == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)
        certificate_ref[] = ccall((:SecCertificateCreateWithData, _SECURITY_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), C_NULL, root_data)
        _cf_release(root_data)
        certificate_ref[] == C_NULL && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    else
        if cert_import_output[] == C_NULL
            _cf_release(cert_import_output[])
            _cf_release(key_import_output[])
            _cf_release(import_keychain[])
            _cf_release(cert_data)
            _cf_release(key_data)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        certificate_ref[] = ccall((:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Clong), cert_import_output[], 0)
        _cf_retain(certificate_ref[])
    end

    identity_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = ccall(
        (:SecIdentityCreateWithCertificate, _SECURITY_LIB),
        Int32,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        import_keychain[],
        certificate_ref[],
        identity_ref,
    )
    if status != _errSecSuccess || identity_ref[] == C_NULL
        _cf_release(certificate_ref[])
        _cf_release(cert_import_output[])
        _cf_release(key_import_output[])
        _cf_release(import_keychain[])
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    values_ref = Ref{Ptr{Cvoid}}(identity_ref[])
    identity_array = ccall(
        (:CFArrayCreate, _COREFOUNDATION_LIB),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Clong, Ptr{Cvoid}),
        C_NULL,
        values_ref,
        1,
        _kCFTypeArrayCallBacks,
    )

    _cf_release(certificate_ref[])
    _cf_release(cert_import_output[])
    _cf_release(key_import_output[])
    _cf_release(import_keychain[])
    _cf_release(cert_data)
    _cf_release(key_data)
    if identity_array == C_NULL
        _cf_release(identity_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    return identity_array
end

function import_pkcs12_to_identity(
        pkcs12_cursor::ByteCursor,
        password::ByteCursor,
    )::Ptr{Cvoid}
    @static if !Sys.isapple()
        _ = pkcs12_cursor
        _ = password
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    pkcs12_data = _cf_data_create(_cursor_ptr(pkcs12_cursor), pkcs12_cursor.len)
    pkcs12_data == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    dict = _pki_cf_dict_create()
    dict == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    pass_ref = if password.len == 0
        ccall(
            (:CFStringCreateWithCString, _COREFOUNDATION_LIB),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Cstring, UInt32),
            C_NULL,
            "",
            _kCFStringEncodingUTF8,
        )
    else
        _cf_string_create(_cursor_ptr(password), Csize_t(password.len), _kCFStringEncodingUTF8)
    end
    if pass_ref == C_NULL
        _cf_release(pkcs12_data)
        _cf_release(dict)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end
    _pki_cf_dict_add_value(dict, _kSecImportExportPassphrase, pass_ref)

    items_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = lock(_pki_sec_lock) do
        ccall((:SecPKCS12Import, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}), pkcs12_data, dict, items_ref)
    end

    _cf_release(pkcs12_data)
    _cf_release(pass_ref)
    _cf_release(dict)

    if status != _errSecSuccess
        items_ref[] != C_NULL && _cf_release(items_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    item = ccall((:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Clong), items_ref[], 0)
    identity = ccall((:CFDictionaryGetValue, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), item, _kSecImportItemIdentity)
    identity == C_NULL && begin
        _cf_release(items_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    # SecureTransport expects an array where:
    # - index 0 is a SecIdentityRef
    # - subsequent entries are any intermediate SecCertificateRefs to send.
    #
    # SecPKCS12Import also yields a certificate chain. Include it so the server can
    # present intermediates during the handshake (required for the certificate-chain test).
    cert_chain = _kSecImportItemCertChain == C_NULL ? C_NULL :
        ccall((:CFDictionaryGetValue, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), item, _kSecImportItemCertChain)
    chain_count = cert_chain == C_NULL ? Clong(0) :
        ccall((:CFArrayGetCount, _COREFOUNDATION_LIB), Clong, (Ptr{Cvoid},), cert_chain)

    extra = chain_count > 1 ? (chain_count - 1) : 0
    total = Clong(1 + extra)
    values = Vector{Ptr{Cvoid}}(undef, Int(total))
    values[1] = identity
    if extra > 0
        # Skip the leaf cert (index 0); the identity already contains it.
        for j in 1:extra
            cert = ccall((:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Clong), cert_chain, j)
            values[Int(1 + j)] = cert
        end
    end

    identity_array = GC.@preserve values ccall(
        (:CFArrayCreate, _COREFOUNDATION_LIB),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Clong, Ptr{Cvoid}),
        C_NULL,
        pointer(values),
        total,
        _kCFTypeArrayCallBacks,
    )
    _cf_release(items_ref[])
    if identity_array == C_NULL
        throw_error(ERROR_SYS_CALL_FAILURE)
    end
    return identity_array
end

function import_trusted_certificates(
        certificates_blob::ByteCursor,
    )::Ptr{Cvoid}
    @static if Sys.iswindows()
        pem_objs = pem_parse(_cursor_to_memory(certificates_blob))
        cert_count = length(pem_objs)
        cert_count == 0 && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)

        cert_store = _win_open_memory_cert_store()
        try
            for obj in pem_objs
                data = obj.data
                cert_ctx = GC.@preserve data _win_query_certificate_blob(pointer(data.mem), _win_to_dword(data.len))
                add_ok = ccall(
                    (:CertAddCertificateContextToStore, _WIN_CRYPT32),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{Ptr{Cvoid}}),
                    cert_store,
                    cert_ctx,
                    _WIN_CERT_STORE_ADD_ALWAYS,
                    C_NULL,
                )
                _win_free_certificate_context(cert_ctx)
                add_ok == 0 && throw_error(ERROR_SYS_CALL_FAILURE)
            end
            return cert_store
        catch
            _win_close_cert_store_raw(cert_store)
            rethrow()
        end
    end

    @static if !Sys.isapple()
        _ = certificates_blob
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    pem_objs = pem_parse(_cursor_to_memory(certificates_blob))

    cert_count = length(pem_objs)
    cert_array = ccall(
        (:CFArrayCreateMutable, _COREFOUNDATION_LIB),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Clong, Ptr{Cvoid}),
        C_NULL,
        cert_count,
        _kCFTypeArrayCallBacks,
    )
    cert_array == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    lock(_pki_sec_lock) do
        for obj in pem_objs
            data = obj.data
            data_ref = _cf_data_create(pointer(data.mem), data.len)
            data_ref == C_NULL && continue
            cert_ref = ccall((:SecCertificateCreateWithData, _SECURITY_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), C_NULL, data_ref)
            if cert_ref != C_NULL
                ccall((:CFArrayAppendValue, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}), cert_array, cert_ref)
                _cf_release(cert_ref)
            end
            _cf_release(data_ref)
        end
    end

    return cert_array
end

function _secitem_add_certificate_to_keychain(
        cert_ref::Ptr{Cvoid},
        serial_data::Ptr{Cvoid},
        label::Ptr{Cvoid},
    )::Nothing
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    add_attributes = _pki_cf_dict_create_typed()
    add_attributes == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    delete_query = C_NULL
    _pki_cf_dict_add_value(add_attributes, _kSecClass, _kSecClassCertificate)
    _pki_cf_dict_add_value(add_attributes, _kSecAttrSerialNumber, serial_data)
    _pki_cf_dict_add_value(add_attributes, _kSecAttrLabel, label)
    _pki_cf_dict_add_value(add_attributes, _kSecValueRef, cert_ref)

    status = ccall((:SecItemAdd, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), add_attributes, C_NULL)
    if status != _errSecSuccess && status != _errSecDuplicateItem
        if status == _errSecMissingEntitlement
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd certificate failed: missing entitlement")
        else
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd certificate failed with OSStatus $status")
        end
        _cf_release(add_attributes)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    if status == _errSecDuplicateItem
        logf(LogLevel.INFO, LS_IO_PKI, "Keychain contains existing certificate. Deleting and re-adding.")
        delete_query = _pki_cf_dict_create_typed()
        delete_query == C_NULL && begin
            _cf_release(add_attributes)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        _pki_cf_dict_add_value(delete_query, _kSecClass, _kSecClassCertificate)
        _pki_cf_dict_add_value(delete_query, _kSecAttrSerialNumber, serial_data)

        del_status = ccall((:SecItemDelete, _SECURITY_LIB), Int32, (Ptr{Cvoid},), delete_query)
        if del_status != _errSecSuccess
            _cf_release(add_attributes)
            _cf_release(delete_query)
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemDelete certificate failed with OSStatus $del_status")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        status = ccall((:SecItemAdd, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), add_attributes, C_NULL)
        if status != _errSecSuccess
            _cf_release(add_attributes)
            _cf_release(delete_query)
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd certificate failed with OSStatus $status")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
    end

    _cf_release(add_attributes)
    delete_query != C_NULL && _cf_release(delete_query)
    return nothing
end

function _secitem_add_private_key_to_keychain(
        key_ref::Ptr{Cvoid},
        label::Ptr{Cvoid},
        application_label::Ptr{Cvoid},
    )::Nothing
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    add_attributes = _pki_cf_dict_create_typed()
    add_attributes == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    delete_query = C_NULL
    _pki_cf_dict_add_value(add_attributes, _kSecClass, _kSecClassKey)
    _pki_cf_dict_add_value(add_attributes, _kSecAttrKeyClass, _kSecAttrKeyClassPrivate)
    _pki_cf_dict_add_value(add_attributes, _kSecAttrApplicationLabel, application_label)
    _pki_cf_dict_add_value(add_attributes, _kSecAttrLabel, label)
    _pki_cf_dict_add_value(add_attributes, _kSecValueRef, key_ref)

    status = ccall((:SecItemAdd, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), add_attributes, C_NULL)
    if status != _errSecSuccess && status != _errSecDuplicateItem
        if status == _errSecMissingEntitlement
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd private key failed: missing entitlement")
        else
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd private key failed with OSStatus $status")
        end
        _cf_release(add_attributes)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    if status == _errSecDuplicateItem
        logf(LogLevel.INFO, LS_IO_PKI, "Keychain contains existing private key. Deleting and re-adding.")
        delete_query = _pki_cf_dict_create_typed()
        delete_query == C_NULL && begin
            _cf_release(add_attributes)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        _pki_cf_dict_add_value(delete_query, _kSecClass, _kSecClassKey)
        _pki_cf_dict_add_value(delete_query, _kSecAttrKeyClass, _kSecAttrKeyClassPrivate)
        _pki_cf_dict_add_value(delete_query, _kSecAttrApplicationLabel, application_label)

        del_status = ccall((:SecItemDelete, _SECURITY_LIB), Int32, (Ptr{Cvoid},), delete_query)
        if del_status != _errSecSuccess
            _cf_release(add_attributes)
            _cf_release(delete_query)
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemDelete private key failed with OSStatus $del_status")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        status = ccall((:SecItemAdd, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), add_attributes, C_NULL)
        if status != _errSecSuccess
            _cf_release(add_attributes)
            _cf_release(delete_query)
            logf(LogLevel.ERROR, LS_IO_PKI, "SecItemAdd private key failed with OSStatus $status")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
    end

    _cf_release(add_attributes)
    delete_query != C_NULL && _cf_release(delete_query)
    return nothing
end

function _secitem_get_identity(serial_data::Ptr{Cvoid})::Ptr{Cvoid}
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    search_query = _pki_cf_dict_create_typed()
    search_query == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    _pki_cf_dict_add_value(search_query, _kSecClass, _kSecClassIdentity)
    _pki_cf_dict_add_value(search_query, _kSecAttrSerialNumber, serial_data)
    _pki_cf_dict_add_value(search_query, _kSecReturnRef, _kCFBooleanTrue)

    identity_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = ccall((:SecItemCopyMatching, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ref{Ptr{Cvoid}}), search_query, identity_ref)
    _cf_release(search_query)

    if status != _errSecSuccess || identity_ref[] == C_NULL
        logf(LogLevel.ERROR, LS_IO_PKI, "SecItemCopyMatching identity failed with OSStatus $status")
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    logf(LogLevel.INFO, LS_IO_PKI, "Successfully retrieved identity from keychain.")
    return identity_ref[]
end

function _secitem_key_type_from_pem(pem_obj::PemObject)::Ptr{Cvoid}
    if pem_obj.object_type == PemObjectType.RSA_PRIVATE_KEY
        return _kSecAttrKeyTypeRSA
    elseif pem_obj.object_type == PemObjectType.EC_PRIVATE_KEY
        return _kSecAttrKeyTypeEC
    elseif pem_obj.object_type == PemObjectType.PRIVATE_KEY
        logf(LogLevel.ERROR, LS_IO_PKI, "PKCS8 private key format unsupported for SecItem.")
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    logf(LogLevel.ERROR, LS_IO_PKI, "Unsupported private key format for SecItem.")
    throw_error(ERROR_INVALID_ARGUMENT)
end

function secitem_import_cert_and_key(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        cert_label::Union{String, Nothing} = nothing,
        key_label::Union{String, Nothing} = nothing,
    )::Ptr{Cvoid}
    @static if !Sys.isapple()
        _ = public_cert_chain
        _ = private_key
        _ = cert_label
        _ = key_label
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    if cert_label === nothing || key_label === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    cert_objects = pem_parse(_cursor_to_memory(public_cert_chain))
    key_objects = pem_parse(_cursor_to_memory(private_key))

    if length(cert_objects) != 1
        logf(LogLevel.ERROR, LS_IO_PKI, "Certificate chains not currently supported for SecItem.")
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if isempty(key_objects)
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    cert_obj = cert_objects[1]
    if !pem_is_certificate(cert_obj)
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    key_obj = key_objects[1]

    key_type = _secitem_key_type_from_pem(key_obj)

    cert_data = _cf_data_create(pointer(cert_obj.data.mem), cert_obj.data.len)
    cert_data == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    key_data = _cf_data_create(pointer(key_obj.data.mem), key_obj.data.len)
    if key_data == C_NULL
        _cf_release(cert_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    error_ref = Ref{Ptr{Cvoid}}(C_NULL)
    cert_ref = ccall((:SecCertificateCreateWithData, _SECURITY_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), C_NULL, cert_data)
    if cert_ref == C_NULL
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    serial_data = ccall(
        (:SecCertificateCopySerialNumberData, _SECURITY_LIB),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        cert_ref,
        error_ref,
    )
    if error_ref[] != C_NULL || serial_data == C_NULL
        _cf_release(error_ref[])
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    cert_label_cur = ByteCursor(cert_label)
    cert_label_ref = _cf_string_create(_cursor_ptr(cert_label_cur), Csize_t(cert_label_cur.len), _kCFStringEncodingUTF8)
    if cert_label_ref == C_NULL
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    key_attributes = _pki_cf_dict_create_typed()
    if key_attributes == C_NULL
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end
    _pki_cf_dict_add_value(key_attributes, _kSecAttrKeyClass, _kSecAttrKeyClassPrivate)
    _pki_cf_dict_add_value(key_attributes, _kSecAttrKeyType, key_type)

    key_ref = ccall(
        (:SecKeyCreateWithData, _SECURITY_LIB),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        key_data,
        key_attributes,
        error_ref,
    )
    if key_ref == C_NULL
        _cf_release(error_ref[])
        _cf_release(key_attributes)
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    key_copied_attributes = ccall((:SecKeyCopyAttributes, _SECURITY_LIB), Ptr{Cvoid}, (Ptr{Cvoid},), key_ref)
    application_label = key_copied_attributes == C_NULL ? C_NULL :
        ccall((:CFDictionaryGetValue, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), key_copied_attributes, _kSecAttrApplicationLabel)
    if application_label == C_NULL
        _cf_release(key_copied_attributes)
        _cf_release(key_ref)
        _cf_release(key_attributes)
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    key_label_cur = ByteCursor(key_label)
    key_label_ref = _cf_string_create(_cursor_ptr(key_label_cur), Csize_t(key_label_cur.len), _kCFStringEncodingUTF8)
    if key_label_ref == C_NULL
        _cf_release(key_copied_attributes)
        _cf_release(key_ref)
        _cf_release(key_attributes)
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    try
        _secitem_add_certificate_to_keychain(cert_ref, serial_data, cert_label_ref)
        _secitem_add_private_key_to_keychain(key_ref, key_label_ref, application_label)
        identity = _secitem_get_identity(serial_data)

        _cf_release(key_label_ref)
        _cf_release(key_copied_attributes)
        _cf_release(key_ref)
        _cf_release(key_attributes)
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)

        return identity
    catch
        _cf_release(key_label_ref)
        _cf_release(key_copied_attributes)
        _cf_release(key_ref)
        _cf_release(key_attributes)
        _cf_release(cert_label_ref)
        _cf_release(serial_data)
        _cf_release(cert_ref)
        _cf_release(cert_data)
        _cf_release(key_data)
        rethrow()
    end
end

function secitem_import_pkcs12(
        pkcs12_cursor::ByteCursor,
        password::ByteCursor;
        cert_label::Union{String, Nothing} = nothing,
        key_label::Union{String, Nothing} = nothing,
    )::Ptr{Cvoid}
    @static if !Sys.isapple()
        _ = pkcs12_cursor
        _ = password
        _ = cert_label
        _ = key_label
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    _ = cert_label
    _ = key_label

    pkcs12_data = _cf_data_create(_cursor_ptr(pkcs12_cursor), pkcs12_cursor.len)
    pkcs12_data == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    dict = _pki_cf_dict_create()
    if dict == C_NULL
        _cf_release(pkcs12_data)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    pass_ref = password.len == 0 ? _cf_string_create(C_NULL, Csize_t(0), _kCFStringEncodingUTF8) :
        _cf_string_create(_cursor_ptr(password), Csize_t(password.len), _kCFStringEncodingUTF8)
    _pki_cf_dict_add_value(dict, _kSecImportExportPassphrase, pass_ref)

    items_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = lock(_pki_sec_lock) do
        ccall((:SecPKCS12Import, _SECURITY_LIB), Int32, (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}), pkcs12_data, dict, items_ref)
    end

    _cf_release(pkcs12_data)
    _cf_release(pass_ref)
    _cf_release(dict)

    if status != _errSecSuccess || items_ref[] == C_NULL
        items_ref[] != C_NULL && _cf_release(items_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    count = ccall((:CFArrayGetCount, _COREFOUNDATION_LIB), Clong, (Ptr{Cvoid},), items_ref[])
    if count == 0
        _cf_release(items_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    item = ccall((:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Clong), items_ref[], 0)
    identity = ccall((:CFDictionaryGetValue, _COREFOUNDATION_LIB), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), item, _kSecImportItemIdentity)
    if identity == C_NULL
        _cf_release(items_ref[])
        throw_error(ERROR_SYS_CALL_FAILURE)
    end
    _cf_retain(identity)
    _cf_release(items_ref[])
    return identity
end

@static if Sys.iswindows()
    const _WIN_CRYPT32 = "Crypt32"
    const _WIN_ADVAPI32 = "Advapi32"
    const _WIN_KERNEL32 = "Kernel32"
    const _WIN_NCRYPT = "Ncrypt"

    const _WIN_X509_ASN_ENCODING = UInt32(0x00000001)
    const _WIN_PKCS7_ASN_ENCODING = UInt32(0x00010000)

    const _WIN_CERT_STORE_PROV_MEMORY = Ptr{UInt8}(2)
    const _WIN_CERT_STORE_PROV_SYSTEM_A = Ptr{UInt8}(9)
    const _WIN_CERT_STORE_CREATE_NEW_FLAG = UInt32(0x00002000)
    const _WIN_CERT_STORE_OPEN_EXISTING_FLAG = UInt32(0x00004000)
    const _WIN_CERT_STORE_ADD_ALWAYS = UInt32(4)
    const _WIN_CERT_FIND_HASH = UInt32(0x00010000)

    const _WIN_CRYPT_STRING_HEX = UInt32(0x00000004)
    const _WIN_CRYPT_DECODE_ALLOC_FLAG = UInt32(0x00008000)

    const _WIN_CERT_QUERY_OBJECT_BLOB = UInt32(2)
    const _WIN_CERT_QUERY_CONTENT_FLAG_CERT = UInt32(0x00000002)
    const _WIN_CERT_QUERY_FORMAT_FLAG_ALL = UInt32(0x0000000E)

    const _WIN_PKCS_RSA_PRIVATE_KEY = Ptr{UInt8}(43)
    const _WIN_PKCS_PRIVATE_KEY_INFO = Ptr{UInt8}(44)
    const _WIN_X509_ECC_PRIVATE_KEY = Ptr{UInt8}(82)

    const _WIN_PROV_RSA_FULL = UInt32(1)
    const _WIN_CRYPT_NEWKEYSET = UInt32(0x00000008)
    const _WIN_CRYPT_MACHINE_KEYSET = UInt32(0x00000020)
    const _WIN_CERT_KEY_PROV_HANDLE_PROP_ID = UInt32(1)
    const _WIN_CERT_KEY_PROV_INFO_PROP_ID = UInt32(2)
    const _WIN_AT_KEYEXCHANGE = UInt32(1)

    const _WIN_CERT_HASH_STR_LEN = 40
    const _WIN_CERT_HASH_LEN = UInt32(20)
    const _WIN_BCRYPT_ECDSA_PRIVATE_P256_MAGIC = UInt32(0x32534345)
    const _WIN_BCRYPT_ECDSA_PRIVATE_P384_MAGIC = UInt32(0x34534345)
    const _WIN_BCRYPT_ECDSA_PRIVATE_P521_MAGIC = UInt32(0x36534345)
    const _WIN_NCRYPTBUFFER_VERSION = UInt32(0)
    const _WIN_NCRYPTBUFFER_PKCS_KEY_NAME = UInt32(45)
    const _WIN_NCRYPT_OVERWRITE_KEY_FLAG = UInt32(0x00000080)
    const _WIN_MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider"
    const _WIN_BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB"

    const _WIN_CERT_STORE_LOCATIONS = Dict{String, UInt32}(
        "currentuser" => UInt32(0x00010000),
        "localmachine" => UInt32(0x00020000),
        "currentservice" => UInt32(0x00040000),
        "services" => UInt32(0x00050000),
        "users" => UInt32(0x00060000),
        "currentusergrouppolicy" => UInt32(0x00070000),
        "localmachinegrouppolicy" => UInt32(0x00080000),
        "localmachineenterprise" => UInt32(0x00090000),
    )

    struct _WinCryptBlob
        cbData::UInt32
        pbData::Ptr{UInt8}
    end

    struct _WinCryptAlgorithmIdentifier
        pszObjId::Ptr{UInt8}
        Parameters::_WinCryptBlob
    end

    struct _WinCryptPrivateKeyInfo
        Version::UInt32
        Algorithm::_WinCryptAlgorithmIdentifier
        PrivateKey::_WinCryptBlob
        Attributes::Ptr{Cvoid}
    end

    struct _WinFileTime
        dwLowDateTime::UInt32
        dwHighDateTime::UInt32
    end

    struct _WinCryptBitBlob
        cbData::UInt32
        pbData::Ptr{UInt8}
        cUnusedBits::UInt32
    end

    struct _WinCertPublicKeyInfo
        Algorithm::_WinCryptAlgorithmIdentifier
        PublicKey::_WinCryptBitBlob
    end

    struct _WinCertInfo
        dwVersion::UInt32
        SerialNumber::_WinCryptBlob
        SignatureAlgorithm::_WinCryptAlgorithmIdentifier
        Issuer::_WinCryptBlob
        NotBefore::_WinFileTime
        NotAfter::_WinFileTime
        Subject::_WinCryptBlob
        SubjectPublicKeyInfo::_WinCertPublicKeyInfo
        IssuerUniqueId::_WinCryptBitBlob
        SubjectUniqueId::_WinCryptBitBlob
        cExtension::UInt32
        rgExtension::Ptr{Cvoid}
    end

    struct _WinCertContext
        dwCertEncodingType::UInt32
        pbCertEncoded::Ptr{UInt8}
        cbCertEncoded::UInt32
        pCertInfo::Ptr{_WinCertInfo}
        hCertStore::Ptr{Cvoid}
    end

    struct _WinCryptEccPrivateKeyInfo
        dwVersion::UInt32
        PrivateKey::_WinCryptBlob
        szCurveOid::Ptr{UInt8}
        PublicKey::_WinCryptBitBlob
    end

    struct _WinBcryptBuffer
        cbBuffer::UInt32
        BufferType::UInt32
        pvBuffer::Ptr{Cvoid}
    end

    struct _WinBcryptBufferDesc
        ulVersion::UInt32
        cBuffers::UInt32
        pBuffers::Ptr{_WinBcryptBuffer}
    end

    struct _WinBcryptEccKeyBlob
        dwMagic::UInt32
        cbKey::UInt32
    end

    struct _WinCryptKeyProvInfo
        pwszContainerName::Ptr{UInt16}
        pwszProvName::Ptr{UInt16}
        dwProvType::UInt32
        dwFlags::UInt32
        cProvParam::UInt32
        rgProvParam::Ptr{Cvoid}
        dwKeySpec::UInt32
    end

    const _win_cert_store_by_context_lock = ReentrantLock()
    const _win_cert_store_by_context = Dict{Ptr{Cvoid}, Ptr{Cvoid}}()
    const _win_key_handles_by_context = Dict{Ptr{Cvoid}, Tuple{Ptr{Cvoid}, Ptr{Cvoid}}}()

    @inline function _win_to_dword(len::Integer)::UInt32
        (len < 0 || len > typemax(UInt32)) && throw_error(ERROR_INVALID_ARGUMENT)
        return UInt32(len)
    end

    @inline function _win_local_free(ptr::Ptr{Cvoid})::Nothing
        ptr == C_NULL && return nothing
        _ = ccall((:LocalFree, _WIN_KERNEL32), Ptr{Cvoid}, (Ptr{Cvoid},), ptr)
        return nothing
    end

    @inline function _win_free_certificate_context(cert_ctx::Ptr{Cvoid})::Nothing
        cert_ctx == C_NULL && return nothing
        _ = ccall((:CertFreeCertificateContext, _WIN_CRYPT32), Int32, (Ptr{Cvoid},), cert_ctx)
        return nothing
    end

    @inline function _win_close_cert_store_raw(cert_store::Ptr{Cvoid})::Nothing
        cert_store == C_NULL && return nothing
        _ = ccall((:CertCloseStore, _WIN_CRYPT32), Int32, (Ptr{Cvoid}, UInt32), cert_store, UInt32(0))
        return nothing
    end

    @inline function _win_release_key_handles(
            crypto_provider::Ptr{Cvoid},
            private_key::Ptr{Cvoid},
        )::Nothing
        private_key != C_NULL && ccall((:CryptDestroyKey, _WIN_ADVAPI32), Int32, (Ptr{Cvoid},), private_key)
        crypto_provider != C_NULL && ccall((:CryptReleaseContext, _WIN_ADVAPI32), Int32, (Ptr{Cvoid}, UInt32), crypto_provider, UInt32(0))
        return nothing
    end

    function _win_bind_cert_context_store!(cert_ctx::Ptr{Cvoid}, cert_store::Ptr{Cvoid})::Nothing
        cert_ctx == C_NULL && return nothing
        lock(_win_cert_store_by_context_lock) do
            _win_cert_store_by_context[cert_ctx] = cert_store
        end
        return nothing
    end

    function _win_take_store_for_context!(cert_ctx::Ptr{Cvoid})::Ptr{Cvoid}
        lock(_win_cert_store_by_context_lock) do
            return pop!(_win_cert_store_by_context, cert_ctx, C_NULL)
        end
    end

    function _win_take_contexts_for_store!(cert_store::Ptr{Cvoid})::Vector{Ptr{Cvoid}}
        lock(_win_cert_store_by_context_lock) do
            contexts = Ptr{Cvoid}[]
            for (ctx, bound_store) in collect(_win_cert_store_by_context)
                if bound_store == cert_store
                    push!(contexts, ctx)
                    delete!(_win_cert_store_by_context, ctx)
                end
            end
            return contexts
        end
    end

    function _win_bind_cert_context_key_handles!(
            cert_ctx::Ptr{Cvoid},
            crypto_provider::Ptr{Cvoid},
            private_key::Ptr{Cvoid},
        )::Nothing
        cert_ctx == C_NULL && return nothing
        if crypto_provider == C_NULL && private_key == C_NULL
            return nothing
        end
        lock(_win_cert_store_by_context_lock) do
            _win_key_handles_by_context[cert_ctx] = (crypto_provider, private_key)
        end
        return nothing
    end

    function _win_take_key_handles_for_context!(cert_ctx::Ptr{Cvoid})::Tuple{Ptr{Cvoid}, Ptr{Cvoid}}
        lock(_win_cert_store_by_context_lock) do
            return pop!(_win_key_handles_by_context, cert_ctx, (C_NULL, C_NULL))
        end
    end

    function _win_release_key_handles_for_context!(cert_ctx::Ptr{Cvoid})::Nothing
        crypto_provider, private_key = _win_take_key_handles_for_context!(cert_ctx)
        _win_release_key_handles(crypto_provider, private_key)
        return nothing
    end

    function _win_split_system_cert_path(cert_path::AbstractString)::NTuple{3, String}
        splits = split(cert_path, '\\'; keepempty = true)
        if length(splits) != 3 || any(isempty, splits)
            throw_error(ERROR_FILE_INVALID_PATH)
        end
        return (String(splits[1]), String(splits[2]), String(splits[3]))
    end

    @inline function _win_is_hex_hash(s::AbstractString)::Bool
        ncodeunits(s) == _WIN_CERT_HASH_STR_LEN || return false
        for ch in codeunits(s)
            if !((UInt8('0') <= ch <= UInt8('9')) || (UInt8('a') <= ch <= UInt8('f')) || (UInt8('A') <= ch <= UInt8('F')))
                return false
            end
        end
        return true
    end

    function _win_open_memory_cert_store()::Ptr{Cvoid}
        cert_store = ccall(
            (:CertOpenStore, _WIN_CRYPT32),
            Ptr{Cvoid},
            (Ptr{UInt8}, UInt32, Ptr{Cvoid}, UInt32, Ptr{Cvoid}),
            _WIN_CERT_STORE_PROV_MEMORY,
            UInt32(0),
            C_NULL,
            _WIN_CERT_STORE_CREATE_NEW_FLAG,
            C_NULL,
        )
        cert_store == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)
        return cert_store
    end

    function _win_query_certificate_blob(data_ptr::Ptr{UInt8}, data_len::UInt32)::Ptr{Cvoid}
        cert_blob = _WinCryptBlob(data_len, data_ptr)
        cert_ctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
        ok = ccall(
            (:CryptQueryObject, _WIN_CRYPT32),
            Int32,
            (UInt32, Ref{_WinCryptBlob}, UInt32, UInt32, UInt32, Ptr{UInt32}, Ptr{UInt32}, Ptr{UInt32}, Ptr{Ptr{Cvoid}}, Ptr{Ptr{Cvoid}}, Ref{Ptr{Cvoid}}),
            _WIN_CERT_QUERY_OBJECT_BLOB,
            cert_blob,
            _WIN_CERT_QUERY_CONTENT_FLAG_CERT,
            _WIN_CERT_QUERY_FORMAT_FLAG_ALL,
            UInt32(0),
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            C_NULL,
            cert_ctx_ref,
        )
        (ok == 0 || cert_ctx_ref[] == C_NULL) && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        return cert_ctx_ref[]
    end

    function _win_decode_object_alloc(
            encoding::UInt32,
            struct_type::Ptr{UInt8},
            data_ptr::Ptr{UInt8},
            data_len::UInt32,
        )::Tuple{Bool, Ptr{Cvoid}, UInt32}
        out_ptr = Ref{Ptr{Cvoid}}(C_NULL)
        out_len = Ref{UInt32}(UInt32(0))
        ok = ccall(
            (:CryptDecodeObjectEx, _WIN_CRYPT32),
            Int32,
            (UInt32, Ptr{UInt8}, Ptr{UInt8}, UInt32, UInt32, Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Ref{UInt32}),
            encoding,
            struct_type,
            data_ptr,
            data_len,
            _WIN_CRYPT_DECODE_ALLOC_FLAG,
            C_NULL,
            out_ptr,
            out_len,
        )
        return (ok != 0, out_ptr[], out_len[])
    end

    function _win_decode_private_key(private_key_objects::Vector{PemObject})::Tuple{Symbol, Ptr{UInt8}, UInt32, Ptr{Cvoid}}
        for obj in private_key_objects
            data = obj.data
            decoded_rsa = GC.@preserve data _win_decode_object_alloc(
                _WIN_X509_ASN_ENCODING | _WIN_PKCS7_ASN_ENCODING,
                _WIN_PKCS_RSA_PRIVATE_KEY,
                pointer(data.mem),
                _win_to_dword(data.len),
            )

            if decoded_rsa[1]
                return (:rsa, Ptr{UInt8}(decoded_rsa[2]), decoded_rsa[3], C_NULL)
            end

            decoded_wrapper = GC.@preserve data _win_decode_object_alloc(
                _WIN_X509_ASN_ENCODING,
                _WIN_PKCS_PRIVATE_KEY_INFO,
                pointer(data.mem),
                _win_to_dword(data.len),
            )
            if decoded_wrapper[1]
                wrapper_ptr = decoded_wrapper[2]
                pk_info = unsafe_load(Ptr{_WinCryptPrivateKeyInfo}(wrapper_ptr))
                decoded_inner = _win_decode_object_alloc(
                    _WIN_X509_ASN_ENCODING,
                    _WIN_PKCS_RSA_PRIVATE_KEY,
                    pk_info.PrivateKey.pbData,
                    pk_info.PrivateKey.cbData,
                )
                if decoded_inner[1]
                    return (:rsa, Ptr{UInt8}(decoded_inner[2]), decoded_inner[3], wrapper_ptr)
                end

                _win_local_free(wrapper_ptr)
            end

            decoded_ecc = GC.@preserve data _win_decode_object_alloc(
                _WIN_X509_ASN_ENCODING | _WIN_PKCS7_ASN_ENCODING,
                _WIN_X509_ECC_PRIVATE_KEY,
                pointer(data.mem),
                _win_to_dword(data.len),
            )
            if decoded_ecc[1]
                return (:ecc, Ptr{UInt8}(decoded_ecc[2]), decoded_ecc[3], C_NULL)
            end
        end

        return (:none, Ptr{UInt8}(C_NULL), UInt32(0), C_NULL)
    end

    function _win_attach_rsa_private_key!(
            cert_ctx::Ptr{Cvoid},
            key_ptr::Ptr{UInt8},
            key_len::UInt32;
            is_client_mode::Bool,
        )::Tuple{Ptr{Cvoid}, Ptr{Cvoid}}
        container_name = transcode(UInt16, string(UUIDs.uuid4()) * "\0")
        flags_to_try = is_client_mode ?
            (_WIN_CRYPT_NEWKEYSET, _WIN_CRYPT_NEWKEYSET | _WIN_CRYPT_MACHINE_KEYSET, UInt32(0)) :
            (_WIN_CRYPT_NEWKEYSET, _WIN_CRYPT_NEWKEYSET | _WIN_CRYPT_MACHINE_KEYSET)

        for acquire_flags in flags_to_try
            container_ptr = acquire_flags == UInt32(0) ? Ptr{UInt16}(C_NULL) : pointer(container_name)
            crypto_provider = Ref{Ptr{Cvoid}}(C_NULL)
            acquired = GC.@preserve container_name ccall(
                (:CryptAcquireContextW, _WIN_ADVAPI32),
                Int32,
                (Ref{Ptr{Cvoid}}, Ptr{UInt16}, Ptr{UInt16}, UInt32, UInt32),
                crypto_provider,
                container_ptr,
                C_NULL,
                _WIN_PROV_RSA_FULL,
                acquire_flags,
            )
            acquired == 0 && continue

            private_key = Ref{Ptr{Cvoid}}(C_NULL)
            imported = ccall(
                (:CryptImportKey, _WIN_ADVAPI32),
                Int32,
                (Ptr{Cvoid}, Ptr{UInt8}, UInt32, Ptr{Cvoid}, UInt32, Ref{Ptr{Cvoid}}),
                crypto_provider[],
                key_ptr,
                key_len,
                C_NULL,
                UInt32(0),
                private_key,
            )
            if imported == 0
                _win_release_key_handles(crypto_provider[], C_NULL)
                continue
            end

            set_ok = Int32(0)
            if acquire_flags == UInt32(0)
                set_ok = ccall(
                    (:CertSetCertificateContextProperty, _WIN_CRYPT32),
                    Int32,
                    (Ptr{Cvoid}, UInt32, UInt32, Ptr{Cvoid}),
                    cert_ctx,
                    _WIN_CERT_KEY_PROV_HANDLE_PROP_ID,
                    UInt32(0),
                    crypto_provider[],
                )
            else
                key_prov_info = GC.@preserve container_name _WinCryptKeyProvInfo(
                    pointer(container_name),
                    C_NULL,
                    _WIN_PROV_RSA_FULL,
                    acquire_flags & _WIN_CRYPT_MACHINE_KEYSET,
                    UInt32(0),
                    C_NULL,
                    _WIN_AT_KEYEXCHANGE,
                )
                key_prov_info_ref = Ref(key_prov_info)
                set_ok = GC.@preserve container_name key_prov_info_ref ccall(
                    (:CertSetCertificateContextProperty, _WIN_CRYPT32),
                    Int32,
                    (Ptr{Cvoid}, UInt32, UInt32, Ref{_WinCryptKeyProvInfo}),
                    cert_ctx,
                    _WIN_CERT_KEY_PROV_INFO_PROP_ID,
                    UInt32(0),
                    key_prov_info_ref,
                )
            end

            if set_ok != 0
                return (crypto_provider[], private_key[])
            end

            _win_release_key_handles(crypto_provider[], private_key[])
        end

        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    @inline function _win_ecc_magic_from_private_len(private_key_len::UInt32)::UInt32
        if private_key_len == UInt32(0x20)
            return _WIN_BCRYPT_ECDSA_PRIVATE_P256_MAGIC
        elseif private_key_len == UInt32(0x30)
            return _WIN_BCRYPT_ECDSA_PRIVATE_P384_MAGIC
        else
            return _WIN_BCRYPT_ECDSA_PRIVATE_P521_MAGIC
        end
    end

    function _win_attach_ecc_private_key!(
            cert_ctx::Ptr{Cvoid},
            key_ptr::Ptr{UInt8},
            key_len::UInt32,
        )::Nothing
        _ = key_len
        cert_ctx == C_NULL && throw_error(ERROR_INVALID_ARGUMENT)
        key_ptr == C_NULL && throw_error(ERROR_INVALID_ARGUMENT)

        cert_context = unsafe_load(Ptr{_WinCertContext}(cert_ctx))
        cert_info_ptr = cert_context.pCertInfo
        cert_info_ptr == C_NULL && throw_error(ERROR_INVALID_ARGUMENT)
        cert_info = unsafe_load(cert_info_ptr)

        public_key_blob = cert_info.SubjectPublicKeyInfo.PublicKey
        public_key_blob.cbData == 0 && throw_error(ERROR_INVALID_ARGUMENT)
        public_key_blob.pbData == C_NULL && throw_error(ERROR_INVALID_ARGUMENT)
        unsafe_load(public_key_blob.pbData) == 0x04 || throw_error(ERROR_INVALID_ARGUMENT)

        public_key_len = Int(public_key_blob.cbData) - 1
        public_key_len > 0 || throw_error(ERROR_INVALID_ARGUMENT)

        private_key_info = unsafe_load(Ptr{_WinCryptEccPrivateKeyInfo}(key_ptr))
        private_key_blob = private_key_info.PrivateKey
        private_key_blob.pbData == C_NULL && throw_error(ERROR_INVALID_ARGUMENT)
        private_key_blob.cbData == 0 && throw_error(ERROR_INVALID_ARGUMENT)

        key_blob_size = sizeof(_WinBcryptEccKeyBlob) + public_key_len + Int(private_key_blob.cbData)
        key_blob = Memory{UInt8}(undef, key_blob_size)
        key_blob_header = _WinBcryptEccKeyBlob(
            _win_ecc_magic_from_private_len(private_key_blob.cbData),
            private_key_blob.cbData,
        )

        GC.@preserve key_blob begin
            unsafe_store!(Ptr{_WinBcryptEccKeyBlob}(pointer(key_blob)), key_blob_header)
            key_blob_body = pointer(key_blob) + sizeof(_WinBcryptEccKeyBlob)
            unsafe_copyto!(key_blob_body, public_key_blob.pbData + 1, public_key_len)
            unsafe_copyto!(
                key_blob_body + public_key_len,
                private_key_blob.pbData,
                Int(private_key_blob.cbData),
            )
        end

        provider_name = transcode(UInt16, _WIN_MS_KEY_STORAGE_PROVIDER * "\0")
        key_name = transcode(UInt16, string(UUIDs.uuid4()) * "\0")
        blob_type = transcode(UInt16, _WIN_BCRYPT_ECCPRIVATE_BLOB * "\0")

        crypto_provider = Ref{Ptr{Cvoid}}(C_NULL)
        imported_private_key = Ref{Ptr{Cvoid}}(C_NULL)

        try
            status = GC.@preserve provider_name ccall(
                (:NCryptOpenStorageProvider, _WIN_NCRYPT),
                Int32,
                (Ref{Ptr{Cvoid}}, Ptr{UInt16}, UInt32),
                crypto_provider,
                pointer(provider_name),
                UInt32(0),
            )
            status == 0 || throw_error(ERROR_SYS_CALL_FAILURE)

            ncrypt_buffer = _WinBcryptBuffer[
                _WinBcryptBuffer(
                    _win_to_dword(sizeof(UInt16) * length(key_name)),
                    _WIN_NCRYPTBUFFER_PKCS_KEY_NAME,
                    Ptr{Cvoid}(pointer(key_name)),
                ),
            ]
            ncrypt_buffer_desc = Ref(_WinBcryptBufferDesc(
                _WIN_NCRYPTBUFFER_VERSION,
                UInt32(length(ncrypt_buffer)),
                pointer(ncrypt_buffer),
            ))

            status = GC.@preserve key_name blob_type ncrypt_buffer ncrypt_buffer_desc key_blob begin
                ccall(
                    (:NCryptImportKey, _WIN_NCRYPT),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt16}, Ref{_WinBcryptBufferDesc}, Ref{Ptr{Cvoid}}, Ptr{UInt8}, UInt32, UInt32),
                    crypto_provider[],
                    C_NULL,
                    pointer(blob_type),
                    ncrypt_buffer_desc,
                    imported_private_key,
                    pointer(key_blob),
                    _win_to_dword(length(key_blob)),
                    _WIN_NCRYPT_OVERWRITE_KEY_FLAG,
                )
            end
            status == 0 || throw_error(ERROR_SYS_CALL_FAILURE)

            key_prov_info = Ref(_WinCryptKeyProvInfo(
                pointer(key_name),
                pointer(provider_name),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                C_NULL,
                UInt32(0),
            ))
            set_ok = GC.@preserve key_name provider_name key_prov_info ccall(
                (:CertSetCertificateContextProperty, _WIN_CRYPT32),
                Int32,
                (Ptr{Cvoid}, UInt32, UInt32, Ref{_WinCryptKeyProvInfo}),
                cert_ctx,
                _WIN_CERT_KEY_PROV_INFO_PROP_ID,
                UInt32(0),
                key_prov_info,
            )
            set_ok == 0 && throw_error(ERROR_SYS_CALL_FAILURE)
        finally
            imported_private_key[] != C_NULL &&
                ccall((:NCryptFreeObject, _WIN_NCRYPT), Int32, (Ptr{Cvoid},), imported_private_key[])
            crypto_provider[] != C_NULL &&
                ccall((:NCryptFreeObject, _WIN_NCRYPT), Int32, (Ptr{Cvoid},), crypto_provider[])
        end

        return nothing
    end
end

function load_cert_from_system_cert_store(
        cert_path::AbstractString,
    )::Ptr{Cvoid}
    @static if Sys.iswindows()
        store_location, store_path, cert_hash = _win_split_system_cert_path(cert_path)
        store_val = get(() -> UInt32(0), _WIN_CERT_STORE_LOCATIONS, lowercase(store_location))
        store_val == UInt32(0) && throw_error(ERROR_FILE_INVALID_PATH)
        ncodeunits(store_path) >= 128 && throw_error(ERROR_FILE_INVALID_PATH)
        _win_is_hex_hash(cert_hash) || throw_error(ERROR_FILE_INVALID_PATH)

        cert_store = ccall(
            (:CertOpenStore, _WIN_CRYPT32),
            Ptr{Cvoid},
            (Ptr{UInt8}, UInt32, Ptr{Cvoid}, UInt32, Cstring),
            _WIN_CERT_STORE_PROV_SYSTEM_A,
            UInt32(0),
            C_NULL,
            _WIN_CERT_STORE_OPEN_EXISTING_FLAG | store_val,
            store_path,
        )
        cert_store == C_NULL && throw_error(ERROR_FILE_INVALID_PATH)

        cert_hash_data = Vector{UInt8}(undef, Int(_WIN_CERT_HASH_LEN))
        cert_hash_len_ref = Ref{UInt32}(_WIN_CERT_HASH_LEN)
        parsed_ok = GC.@preserve cert_hash_data ccall(
            (:CryptStringToBinaryA, _WIN_CRYPT32),
            Int32,
            (Cstring, UInt32, UInt32, Ptr{UInt8}, Ref{UInt32}, Ptr{UInt32}, Ptr{UInt32}),
            cert_hash,
            UInt32(_WIN_CERT_HASH_STR_LEN),
            _WIN_CRYPT_STRING_HEX,
            pointer(cert_hash_data),
            cert_hash_len_ref,
            C_NULL,
            C_NULL,
        )
        if parsed_ok == 0 || cert_hash_len_ref[] != _WIN_CERT_HASH_LEN
            _win_close_cert_store_raw(cert_store)
            throw_error(ERROR_FILE_INVALID_PATH)
        end

        cert_ctx = GC.@preserve cert_hash_data begin
            hash_blob = _WinCryptBlob(cert_hash_len_ref[], pointer(cert_hash_data))
            ccall(
                (:CertFindCertificateInStore, _WIN_CRYPT32),
                Ptr{Cvoid},
                (Ptr{Cvoid}, UInt32, UInt32, UInt32, Ref{_WinCryptBlob}, Ptr{Cvoid}),
                cert_store,
                _WIN_X509_ASN_ENCODING | _WIN_PKCS7_ASN_ENCODING,
                UInt32(0),
                _WIN_CERT_FIND_HASH,
                hash_blob,
                C_NULL,
            )
        end

        if cert_ctx == C_NULL
            _win_close_cert_store_raw(cert_store)
            throw_error(ERROR_FILE_INVALID_PATH)
        end

        _win_bind_cert_context_store!(cert_ctx, cert_store)
        return cert_ctx
    end

    _ = cert_path
    throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
end

function close_cert_store(cert_store::Ptr{Cvoid})::Nothing
    @static if Sys.iswindows()
        cert_store == C_NULL && return nothing

        bound_store = _win_take_store_for_context!(cert_store)
        if bound_store != C_NULL
            _win_release_key_handles_for_context!(cert_store)
            _win_close_cert_store_raw(bound_store)
            return nothing
        end

        for cert_ctx in _win_take_contexts_for_store!(cert_store)
            _win_release_key_handles_for_context!(cert_ctx)
        end
        _win_close_cert_store_raw(cert_store)
        return nothing
    end

    _ = cert_store
    return nothing
end

function import_key_pair_to_cert_context(
        public_cert_chain::ByteCursor,
        private_key::ByteCursor;
        is_client_mode::Bool = true,
    )::Ptr{Cvoid}
    @static if Sys.iswindows()
        certificates = pem_parse(_cursor_to_memory(public_cert_chain))
        private_keys = pem_parse(_cursor_to_memory(private_key))

        cert_store = _win_open_memory_cert_store()
        cert_ctx = Ptr{Cvoid}(C_NULL)
        decoded_key_kind = :none
        decoded_key = Ptr{UInt8}(C_NULL)
        decoded_key_len = UInt32(0)
        decoded_key_wrapper = Ptr{Cvoid}(C_NULL)
        crypto_provider = Ptr{Cvoid}(C_NULL)
        imported_private_key = Ptr{Cvoid}(C_NULL)

        try
            for (i, obj) in pairs(certificates)
                data = obj.data
                parsed_cert_ctx = GC.@preserve data _win_query_certificate_blob(pointer(data.mem), _win_to_dword(data.len))

                add_ok = ccall(
                    (:CertAddCertificateContextToStore, _WIN_CRYPT32),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{Ptr{Cvoid}}),
                    cert_store,
                    parsed_cert_ctx,
                    _WIN_CERT_STORE_ADD_ALWAYS,
                    C_NULL,
                )
                if add_ok == 0
                    _win_free_certificate_context(parsed_cert_ctx)
                    throw_error(ERROR_SYS_CALL_FAILURE)
                end

                if i == 1
                    cert_ctx = parsed_cert_ctx
                else
                    _win_free_certificate_context(parsed_cert_ctx)
                end
            end

            cert_ctx == C_NULL && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)

            decoded_key_kind, decoded_key, decoded_key_len, decoded_key_wrapper = _win_decode_private_key(private_keys)
            decoded_key == C_NULL && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)

            if decoded_key_kind == :rsa
                crypto_provider, imported_private_key = _win_attach_rsa_private_key!(
                    cert_ctx,
                    decoded_key,
                    decoded_key_len;
                    is_client_mode = is_client_mode,
                )
            elseif decoded_key_kind == :ecc
                _win_attach_ecc_private_key!(cert_ctx, decoded_key, decoded_key_len)
            else
                throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
            end

            _win_bind_cert_context_store!(cert_ctx, cert_store)
            if decoded_key_kind == :rsa
                _win_bind_cert_context_key_handles!(cert_ctx, crypto_provider, imported_private_key)
            end
            crypto_provider = C_NULL
            imported_private_key = C_NULL
            return cert_ctx
        catch
            cert_ctx != C_NULL && _win_free_certificate_context(cert_ctx)
            _win_close_cert_store_raw(cert_store)
            rethrow()
        finally
            _win_release_key_handles(crypto_provider, imported_private_key)
            decoded_key != C_NULL && _win_local_free(Ptr{Cvoid}(decoded_key))
            decoded_key_wrapper != C_NULL && _win_local_free(decoded_key_wrapper)
        end
    end

    _ = public_cert_chain
    _ = private_key
    _ = is_client_mode
    throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
end

# === X509 helpers (aws-lc) ===

const _aws_lc_lock = ReentrantLock()
const _aws_lc_lib = Ref{Any}(nothing)
const _aws_lc_available = Ref(false)
const _aws_lc_symbol_cache = Dict{Symbol, Ptr{Cvoid}}()

function _aws_lc_init_once()::Bool
    _aws_lc_available[] && return true
    lock(_aws_lc_lock) do
        _aws_lc_available[] && return true
        if Base.find_package("aws_lc_jll") === nothing
            return false
        end
        try
            @eval import aws_lc_jll
            lib = aws_lc_jll.libcrypto
            handle = lib isa String ? Libdl.dlopen(lib) : lib
            _aws_lc_lib[] = handle
            _aws_lc_available[] = true
            return true
        catch
            _aws_lc_lib[] = nothing
            _aws_lc_available[] = false
            return false
        end
    end
end

function aws_lc_available()::Bool
    return _aws_lc_init_once()
end

function _aws_lc_symbol(sym::Symbol)::Ptr{Cvoid}
    _aws_lc_init_once() || return C_NULL
    return get!(_aws_lc_symbol_cache, sym) do
        try
            return Libdl.dlsym(_aws_lc_lib[], sym)
        catch
            return C_NULL
        end
    end
end

struct X509Ref
    handle::Ptr{Cvoid}
end

@inline function _x509_ref(handle::Ptr{Cvoid})::X509Ref
    ref = X509Ref(handle)
    finalizer(ref) do r
        if r.handle != C_NULL && _aws_lc_available[]
            fptr = _aws_lc_symbol(:X509_free)
            fptr != C_NULL && ccall(fptr, Cvoid, (Ptr{Cvoid},), r.handle)
        end
    end
    return ref
end

@inline function _x509_err_to_tls_error(err::Int, depth::Int)::Int
    err == 0 && return OP_SUCCESS
    if err == 10
        return depth == 0 ? ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED : ERROR_IO_TLS_CERTIFICATE_EXPIRED
    elseif err == 9
        return ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID
    elseif err == 23
        return ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED
    elseif err == 18 || err == 19 || err == 2 || err == 20 || err == 21
        return ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE
    elseif err == 4 || err == 6 || err == 7
        return ERROR_IO_TLS_BAD_PEER_CERTIFICATE
    elseif err == 24 || err == 25 || err == 26 || err == 27 || err == 28 || err == 32
        return ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN
    end
    return ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
end

function x509_parse_pem_chain(pem_cursor::ByteCursor)::Vector{X509Ref}
    _aws_lc_init_once() || throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    bio_new = _aws_lc_symbol(:BIO_new_mem_buf)
    pem_read = _aws_lc_symbol(:PEM_read_bio_X509)
    bio_free = _aws_lc_symbol(:BIO_free)
    err_clear = _aws_lc_symbol(:ERR_clear_error)
    if bio_new == C_NULL || pem_read == C_NULL || bio_free == C_NULL
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    certs = X509Ref[]
    ptr = _cursor_ptr(pem_cursor)
    bio = ccall(bio_new, Ptr{Cvoid}, (Ptr{UInt8}, Cint), ptr, Cint(pem_cursor.len))
    bio == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)
    try
        while true
            x509 = ccall(pem_read, Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), bio, C_NULL, C_NULL, C_NULL)
            x509 == C_NULL && break
            push!(certs, _x509_ref(x509))
        end
    finally
        ccall(bio_free, Cint, (Ptr{Cvoid},), bio)
        err_clear != C_NULL && ccall(err_clear, Cvoid, ())
    end
    isempty(certs) && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    return certs
end

function x509_load_der(der_cursor::ByteCursor)::X509Ref
    _aws_lc_init_once() || throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    d2i = _aws_lc_symbol(:d2i_X509)
    d2i == C_NULL && throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    ptr_ref = Ref{Ptr{UInt8}}(_cursor_ptr(der_cursor))
    x509 = ccall(d2i, Ptr{Cvoid}, (Ptr{Cvoid}, Ref{Ptr{UInt8}}, Clong), C_NULL, ptr_ref, Clong(der_cursor.len))
    x509 == C_NULL && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
    return _x509_ref(x509)
end

function x509_check_host(cert::X509Ref, host::AbstractString)::Bool
    _aws_lc_init_once() || throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    check_host = _aws_lc_symbol(:X509_check_host)
    check_host == C_NULL && throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    res = ccall(check_host, Cint, (Ptr{Cvoid}, Cstring, Csize_t, Cuint, Ptr{Ptr{Cchar}}), cert.handle, host, ncodeunits(host), UInt32(0), C_NULL)
    if res < 0
        throw_error(ERROR_SYS_CALL_FAILURE)
    end
    return res == 1
end

function x509_verify_chain(
        chain_cursor::ByteCursor;
        trust_store_cursor::Union{ByteCursor, Nothing} = nothing,
        host::Union{String, Nothing} = nothing,
    )::Nothing
    _aws_lc_init_once() || throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    store_new = _aws_lc_symbol(:X509_STORE_new)
    store_free = _aws_lc_symbol(:X509_STORE_free)
    store_add = _aws_lc_symbol(:X509_STORE_add_cert)
    store_load = _aws_lc_symbol(:X509_STORE_load_locations)
    ctx_new = _aws_lc_symbol(:X509_STORE_CTX_new)
    ctx_free = _aws_lc_symbol(:X509_STORE_CTX_free)
    ctx_init = _aws_lc_symbol(:X509_STORE_CTX_init)
    ctx_err = _aws_lc_symbol(:X509_STORE_CTX_get_error)
    ctx_depth = _aws_lc_symbol(:X509_STORE_CTX_get_error_depth)
    verify_cert = _aws_lc_symbol(:X509_verify_cert)
    sk_new = _aws_lc_symbol(:OPENSSL_sk_new_null)
    sk_free = _aws_lc_symbol(:OPENSSL_sk_free)
    sk_push = _aws_lc_symbol(:OPENSSL_sk_push)
    if store_new == C_NULL || store_free == C_NULL || store_add == C_NULL || ctx_new == C_NULL ||
            ctx_free == C_NULL || ctx_init == C_NULL || ctx_err == C_NULL || verify_cert == C_NULL ||
            sk_new == C_NULL || sk_free == C_NULL || sk_push == C_NULL
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    chain = x509_parse_pem_chain(chain_cursor)
    leaf = chain[1]

    store = ccall(store_new, Ptr{Cvoid}, ())
    store == C_NULL && throw_error(ERROR_SYS_CALL_FAILURE)

    trust_certs = trust_store_cursor === nothing ? X509Ref[] :
        x509_parse_pem_chain(trust_store_cursor)

    for cert in trust_certs
        _ = ccall(store_add, Cint, (Ptr{Cvoid}, Ptr{Cvoid}), store, cert.handle)
    end

    if trust_store_cursor === nothing
        if store_load == C_NULL
            ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
            throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
        end
        ca_file = determine_default_pki_ca_file()
        ca_dir = determine_default_pki_dir()
        if ca_file === nothing && ca_dir === nothing
            ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
            throw_error(ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
        end
        ca_file_ptr = ca_file === nothing ? Ptr{UInt8}(C_NULL) : ca_file
        ca_dir_ptr = ca_dir === nothing ? Ptr{UInt8}(C_NULL) : ca_dir
        if ccall(store_load, Cint, (Ptr{Cvoid}, Cstring, Cstring), store, ca_file_ptr, ca_dir_ptr) != 1
            ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
            throw_error(ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
        end
    end

    chain_stack = C_NULL
    if length(chain) > 1
        chain_stack = ccall(sk_new, Ptr{Cvoid}, ())
        if chain_stack == C_NULL
            ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        for cert in chain[2:end]
            _ = ccall(sk_push, Cint, (Ptr{Cvoid}, Ptr{Cvoid}), chain_stack, cert.handle)
        end
    end

    ctx = ccall(ctx_new, Ptr{Cvoid}, ())
    if ctx == C_NULL
        chain_stack != C_NULL && ccall(sk_free, Cvoid, (Ptr{Cvoid},), chain_stack)
        ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    try
        if ccall(ctx_init, Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), ctx, store, leaf.handle, chain_stack) != 1
            throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        end
        verify_res = ccall(verify_cert, Cint, (Ptr{Cvoid},), ctx)
        if verify_res != 1
            err = ccall(ctx_err, Cint, (Ptr{Cvoid},), ctx)
            depth = ccall(ctx_depth, Cint, (Ptr{Cvoid},), ctx)
            mapped = _x509_err_to_tls_error(Int(err), Int(depth))
            throw_error(mapped)
        end
        if host !== nothing
            host_ok = x509_check_host(leaf, host)
            if !host_ok
                throw_error(ERROR_IO_TLS_HOST_NAME_MISMATCH)
            end
        end
    finally
        ccall(ctx_free, Cvoid, (Ptr{Cvoid},), ctx)
        chain_stack != C_NULL && ccall(sk_free, Cvoid, (Ptr{Cvoid},), chain_stack)
        ccall(store_free, Cvoid, (Ptr{Cvoid},), store)
    end

    return nothing
end
