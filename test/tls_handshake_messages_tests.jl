using Test
using Random
using SHA
using Reseau

const TLH = Reseau.TLS

_tls_hm_hexbytes(s::AbstractString) = hex2bytes(replace(s, r"\s+" => ""))

function _rand_ascii(rng::AbstractRNG, n::Int)
    chars = Vector{Char}(undef, n)
    for i in eachindex(chars)
        chars[i] = Char(rand(rng, UInt8('a'):UInt8('z')))
    end
    return String(chars)
end

function _rand_optional_bytes(rng::AbstractRNG, max_len::Int; present::Bool = rand(rng, Bool), allow_empty::Bool = true)
    present || return nothing
    len = allow_empty ? rand(rng, 0:max_len) : rand(rng, 1:max_len)
    return rand(rng, UInt8, len)
end

_copy_tls_key_shares(key_shares::Vector{TLH._TLSKeyShare}) = [TLH._TLSKeyShare(share.group, copy(share.data)) for share in key_shares]
_copy_tls_psk_identities(psk_identities::Vector{TLH._TLSPSKIdentity}) = [TLH._TLSPSKIdentity(copy(identity.label), identity.obfuscated_ticket_age) for identity in psk_identities]
_copy_tls_byte_vectors(byte_vectors::Vector{Vector{UInt8}}) = [copy(bytes) for bytes in byte_vectors]

function _client_hello_msg(;
    original::Union{Nothing, AbstractVector{UInt8}} = nothing,
    vers::UInt16 = TLH.TLS1_2_VERSION,
    random::AbstractVector{UInt8} = zeros(UInt8, 32),
    session_id::AbstractVector{UInt8} = UInt8[],
    cipher_suites::Vector{UInt16} = UInt16[],
    compression_methods::AbstractVector{UInt8} = UInt8[TLH._TLS_COMPRESSION_NONE],
    server_name::AbstractString = "",
    ocsp_stapling::Bool = false,
    supported_curves::Vector{UInt16} = UInt16[],
    supported_points::AbstractVector{UInt8} = UInt8[],
    ticket_supported::Bool = false,
    session_ticket::AbstractVector{UInt8} = UInt8[],
    supported_signature_algorithms::Vector{UInt16} = UInt16[],
    supported_signature_algorithms_cert::Vector{UInt16} = UInt16[],
    secure_renegotiation_supported::Bool = false,
    secure_renegotiation::AbstractVector{UInt8} = UInt8[],
    extended_master_secret::Bool = false,
    alpn_protocols::Vector{String} = String[],
    scts::Bool = false,
    supported_versions::Vector{UInt16} = UInt16[],
    cookie::AbstractVector{UInt8} = UInt8[],
    key_shares::Vector{TLH._TLSKeyShare} = TLH._TLSKeyShare[],
    early_data::Bool = false,
    psk_modes::AbstractVector{UInt8} = UInt8[],
    psk_identities::Vector{TLH._TLSPSKIdentity} = TLH._TLSPSKIdentity[],
    psk_binders::Vector{Vector{UInt8}} = Vector{UInt8}[],
    quic_transport_parameters::Union{Nothing, AbstractVector{UInt8}} = nothing,
    encrypted_client_hello::AbstractVector{UInt8} = UInt8[],
    extensions::Vector{UInt16} = UInt16[],
)
    return TLH._ClientHelloMsg(
        original === nothing ? nothing : Vector{UInt8}(original),
        vers,
        Vector{UInt8}(random),
        Vector{UInt8}(session_id),
        copy(cipher_suites),
        Vector{UInt8}(compression_methods),
        String(server_name),
        ocsp_stapling,
        copy(supported_curves),
        Vector{UInt8}(supported_points),
        ticket_supported,
        Vector{UInt8}(session_ticket),
        copy(supported_signature_algorithms),
        copy(supported_signature_algorithms_cert),
        secure_renegotiation_supported,
        Vector{UInt8}(secure_renegotiation),
        extended_master_secret,
        copy(alpn_protocols),
        scts,
        copy(supported_versions),
        Vector{UInt8}(cookie),
        _copy_tls_key_shares(key_shares),
        early_data,
        Vector{UInt8}(psk_modes),
        _copy_tls_psk_identities(psk_identities),
        _copy_tls_byte_vectors(psk_binders),
        quic_transport_parameters === nothing ? nothing : Vector{UInt8}(quic_transport_parameters),
        Vector{UInt8}(encrypted_client_hello),
        copy(extensions),
    )
end

function _server_hello_msg(;
    original::Union{Nothing, AbstractVector{UInt8}} = nothing,
    vers::UInt16 = TLH.TLS1_2_VERSION,
    random::AbstractVector{UInt8} = zeros(UInt8, 32),
    session_id::AbstractVector{UInt8} = UInt8[],
    cipher_suite::UInt16 = UInt16(0),
    compression_method::UInt8 = TLH._TLS_COMPRESSION_NONE,
    ocsp_stapling::Bool = false,
    ticket_supported::Bool = false,
    secure_renegotiation_supported::Bool = false,
    secure_renegotiation::AbstractVector{UInt8} = UInt8[],
    extended_master_secret::Bool = false,
    alpn_protocol::AbstractString = "",
    scts::Vector{Vector{UInt8}} = Vector{UInt8}[],
    supported_version::UInt16 = UInt16(0),
    server_share::Union{Nothing, TLH._TLSKeyShare} = nothing,
    selected_identity_present::Bool = false,
    selected_identity::UInt16 = UInt16(0),
    supported_points::AbstractVector{UInt8} = UInt8[],
    encrypted_client_hello::AbstractVector{UInt8} = UInt8[],
    server_name_ack::Bool = false,
    cookie::AbstractVector{UInt8} = UInt8[],
    selected_group::UInt16 = UInt16(0),
)
    return TLH._ServerHelloMsg(
        original === nothing ? nothing : Vector{UInt8}(original),
        vers,
        Vector{UInt8}(random),
        Vector{UInt8}(session_id),
        cipher_suite,
        compression_method,
        ocsp_stapling,
        ticket_supported,
        secure_renegotiation_supported,
        Vector{UInt8}(secure_renegotiation),
        extended_master_secret,
        String(alpn_protocol),
        _copy_tls_byte_vectors(scts),
        supported_version,
        server_share === nothing ? nothing : TLH._TLSKeyShare(server_share.group, copy(server_share.data)),
        selected_identity_present,
        selected_identity,
        Vector{UInt8}(supported_points),
        Vector{UInt8}(encrypted_client_hello),
        server_name_ack,
        Vector{UInt8}(cookie),
        selected_group,
    )
end

function _encrypted_extensions_msg(;
    alpn_protocol::AbstractString = "",
    quic_transport_parameters::Union{Nothing, AbstractVector{UInt8}} = nothing,
    early_data::Bool = false,
    ech_retry_configs::AbstractVector{UInt8} = UInt8[],
    server_name_ack::Bool = false,
)
    return TLH._EncryptedExtensionsMsg(
        String(alpn_protocol),
        quic_transport_parameters === nothing ? nothing : Vector{UInt8}(quic_transport_parameters),
        early_data,
        Vector{UInt8}(ech_retry_configs),
        server_name_ack,
    )
end

function _certificate_msg_tls12(; certificates::Vector{Vector{UInt8}} = Vector{UInt8}[])
    return TLH._CertificateMsgTLS12(_copy_tls_byte_vectors(certificates))
end

function _server_key_exchange_msg_tls12(; key::AbstractVector{UInt8} = UInt8[])
    return TLH._ServerKeyExchangeMsgTLS12(Vector{UInt8}(key))
end

function _certificate_request_msg_tls12(;
    certificate_types::AbstractVector{UInt8} = UInt8[],
    supported_signature_algorithms::Vector{UInt16} = UInt16[],
    certificate_authorities::Vector{Vector{UInt8}} = Vector{UInt8}[],
)
    return TLH._CertificateRequestMsgTLS12(
        Vector{UInt8}(certificate_types),
        copy(supported_signature_algorithms),
        _copy_tls_byte_vectors(certificate_authorities),
    )
end

function _certificate_request_msg_tls13(;
    ocsp_stapling::Bool = false,
    scts::Bool = false,
    supported_signature_algorithms::Vector{UInt16} = UInt16[],
    supported_signature_algorithms_cert::Vector{UInt16} = UInt16[],
    certificate_authorities::Vector{Vector{UInt8}} = Vector{UInt8}[],
)
    return TLH._CertificateRequestMsgTLS13(
        ocsp_stapling,
        scts,
        copy(supported_signature_algorithms),
        copy(supported_signature_algorithms_cert),
        _copy_tls_byte_vectors(certificate_authorities),
    )
end

function _certificate_msg_tls13(;
    certificates::Vector{Vector{UInt8}} = Vector{UInt8}[],
    ocsp_stapling::Bool = false,
    ocsp_staple::Union{Nothing, AbstractVector{UInt8}} = nothing,
    scts::Bool = false,
    signed_certificate_timestamps::Vector{Vector{UInt8}} = Vector{UInt8}[],
)
    return TLH._CertificateMsgTLS13(
        _copy_tls_byte_vectors(certificates),
        ocsp_stapling,
        ocsp_staple === nothing ? nothing : Vector{UInt8}(ocsp_staple),
        scts,
        _copy_tls_byte_vectors(signed_certificate_timestamps),
    )
end

function _certificate_verify_msg(;
    signature_algorithm::UInt16 = UInt16(0),
    signature::AbstractVector{UInt8} = UInt8[],
)
    return TLH._CertificateVerifyMsg(signature_algorithm, Vector{UInt8}(signature))
end

_server_hello_done_msg_tls12() = TLH._ServerHelloDoneMsgTLS12()

function _client_key_exchange_msg_tls12(; ciphertext::AbstractVector{UInt8} = UInt8[])
    return TLH._ClientKeyExchangeMsgTLS12(Vector{UInt8}(ciphertext))
end

function _new_session_ticket_msg_tls13(;
    lifetime::UInt32 = UInt32(0),
    age_add::UInt32 = UInt32(0),
    nonce::AbstractVector{UInt8} = UInt8[],
    label::AbstractVector{UInt8} = UInt8[],
    max_early_data::UInt32 = UInt32(0),
)
    return TLH._NewSessionTicketMsgTLS13(
        lifetime,
        age_add,
        Vector{UInt8}(nonce),
        Vector{UInt8}(label),
        max_early_data,
    )
end

_finished_msg(; verify_data::AbstractVector{UInt8} = UInt8[]) = TLH._FinishedMsg(Vector{UInt8}(verify_data))

function _random_client_hello(rng::AbstractRNG)
    cipher_suites = rand(rng, UInt16, rand(rng, 1:6))
    for i in eachindex(cipher_suites)
        cipher_suites[i] == TLH._TLS_SCSV_RENEGOTIATION && (cipher_suites[i] = UInt16(cipher_suites[i] + 1))
    end

    secure_renegotiation_supported = rand(rng, Bool)
    ticket_supported = rand(rng, Bool)
    psk_count = rand(rng, 0:2)
    psk_identities = TLH._TLSPSKIdentity[]
    psk_binders = Vector{UInt8}[]
    for _ in 1:psk_count
        push!(psk_identities, TLH._TLSPSKIdentity(rand(rng, UInt8, rand(rng, 1:12)), rand(rng, UInt32)))
        push!(psk_binders, rand(rng, UInt8, rand(rng, 32:48)))
    end

    quic_transport_parameters = _rand_optional_bytes(rng, 10)

    return _client_hello_msg(
        vers = rand(rng, UInt16),
        random = rand(rng, UInt8, 32),
        session_id = rand(rng, UInt8, rand(rng, 0:32)),
        cipher_suites = cipher_suites,
        compression_methods = rand(rng, UInt8, rand(rng, 1:4)),
        server_name = rand(rng, Bool) ? _rand_ascii(rng, rand(rng, 1:12)) : "",
        ocsp_stapling = rand(rng, Bool),
        supported_curves = rand(rng, UInt16, rand(rng, 0:4)),
        supported_points = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:4)) : UInt8[],
        ticket_supported = ticket_supported,
        session_ticket = ticket_supported ? rand(rng, UInt8, rand(rng, 0:12)) : UInt8[],
        supported_signature_algorithms = rand(rng, UInt16, rand(rng, 0:4)),
        supported_signature_algorithms_cert = rand(rng, UInt16, rand(rng, 0:4)),
        secure_renegotiation_supported = secure_renegotiation_supported,
        secure_renegotiation = secure_renegotiation_supported ? rand(rng, UInt8, rand(rng, 0:8)) : UInt8[],
        extended_master_secret = rand(rng, Bool),
        alpn_protocols = [_rand_ascii(rng, rand(rng, 1:8)) for _ in 1:rand(rng, 0:3)],
        scts = rand(rng, Bool),
        supported_versions = rand(rng, UInt16, rand(rng, 0:4)),
        cookie = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:10)) : UInt8[],
        key_shares = [TLH._TLSKeyShare(rand(rng, UInt16), rand(rng, UInt8, rand(rng, 1:18))) for _ in 1:rand(rng, 0:3)],
        early_data = rand(rng, Bool),
        psk_modes = rand(rng, 0:2) == 0 ? UInt8[] : rand(rng, UInt8[TLH._TLS_PSK_MODE_DHE, TLH._TLS_PSK_MODE_PLAIN], rand(rng, 1:2)),
        psk_identities = psk_identities,
        psk_binders = psk_binders,
        quic_transport_parameters = quic_transport_parameters,
        encrypted_client_hello = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:10)) : UInt8[],
    )
end

function _random_server_hello(rng::AbstractRNG)
    with_server_share = rand(rng, Bool)
    secure_renegotiation_supported = rand(rng, Bool)
    return _server_hello_msg(
        vers = rand(rng, UInt16),
        random = rand(rng, UInt8, 32),
        session_id = rand(rng, UInt8, rand(rng, 0:32)),
        cipher_suite = rand(rng, UInt16),
        compression_method = rand(rng, UInt8),
        ocsp_stapling = rand(rng, Bool),
        ticket_supported = rand(rng, Bool),
        secure_renegotiation_supported = secure_renegotiation_supported,
        secure_renegotiation = secure_renegotiation_supported ? rand(rng, UInt8, rand(rng, 0:8)) : UInt8[],
        extended_master_secret = rand(rng, Bool),
        alpn_protocol = rand(rng, Bool) ? _rand_ascii(rng, rand(rng, 1:8)) : "",
        scts = [rand(rng, UInt8, rand(rng, 1:10)) for _ in 1:rand(rng, 0:2)],
        supported_version = rand(rng, Bool) ? rand(rng, UInt16) : UInt16(0),
        server_share = with_server_share && rand(rng, Bool) ? TLH._TLSKeyShare(rand(rng, UInt16), rand(rng, UInt8, rand(rng, 1:16))) : nothing,
        selected_identity_present = rand(rng, Bool),
        selected_identity = rand(rng, UInt16),
        supported_points = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:4)) : UInt8[],
        encrypted_client_hello = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:10)) : UInt8[],
        server_name_ack = rand(rng, Bool),
        cookie = !with_server_share && rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:10)) : UInt8[],
        selected_group = with_server_share ? UInt16(0) : (rand(rng, Bool) ? rand(rng, UInt16) : UInt16(0)),
    )
end

function _random_encrypted_extensions(rng::AbstractRNG)
    return _encrypted_extensions_msg(
        alpn_protocol = rand(rng, Bool) ? _rand_ascii(rng, rand(rng, 1:8)) : "",
        quic_transport_parameters = _rand_optional_bytes(rng, 10),
        early_data = rand(rng, Bool),
        ech_retry_configs = rand(rng, Bool) ? rand(rng, UInt8, rand(rng, 1:10)) : UInt8[],
        server_name_ack = rand(rng, Bool),
    )
end

function _random_certificate_request_tls13(rng::AbstractRNG)
    return _certificate_request_msg_tls13(
        ocsp_stapling = rand(rng, Bool),
        scts = rand(rng, Bool),
        supported_signature_algorithms = rand(rng, UInt16, rand(rng, 0:4)),
        supported_signature_algorithms_cert = rand(rng, UInt16, rand(rng, 0:4)),
        certificate_authorities = [rand(rng, UInt8, rand(rng, 1:10)) for _ in 1:rand(rng, 0:3)],
    )
end

function _random_certificate_tls13(rng::AbstractRNG)
    ocsp_stapling = rand(rng, Bool)
    scts = rand(rng, Bool)
    return _certificate_msg_tls13(
        certificates = [rand(rng, UInt8, rand(rng, 1:32)) for _ in 1:rand(rng, 1:3)],
        ocsp_stapling = ocsp_stapling,
        ocsp_staple = ocsp_stapling ? rand(rng, UInt8, rand(rng, 1:20)) : nothing,
        scts = scts,
        signed_certificate_timestamps = scts ? [rand(rng, UInt8, rand(rng, 1:20)) for _ in 1:rand(rng, 1:3)] : Vector{UInt8}[],
    )
end

function _random_certificate_verify(rng::AbstractRNG)
    return _certificate_verify_msg(
        signature_algorithm = rand(rng, UInt16),
        signature = rand(rng, UInt8, rand(rng, 1:24)),
    )
end

function _random_new_session_ticket_tls13(rng::AbstractRNG)
    return _new_session_ticket_msg_tls13(
        lifetime = rand(rng, UInt32),
        age_add = rand(rng, UInt32),
        nonce = rand(rng, UInt8, rand(rng, 0:12)),
        label = rand(rng, UInt8, rand(rng, 0:32)),
        max_early_data = rand(rng, Bool) ? rand(rng, UInt32) : UInt32(0),
    )
end

_random_finished(rng::AbstractRNG) = _finished_msg(verify_data = rand(rng, UInt8, rand(rng, 12:48)))

function _find_subsequence(haystack::AbstractVector{UInt8}, needle::AbstractVector{UInt8})
    isempty(needle) && return 1
    length(needle) > length(haystack) && return nothing
    last_start = length(haystack) - length(needle) + 1
    for start in 1:last_start
        haystack[start:(start + length(needle) - 1)] == needle && return start
    end
    return nothing
end

function _rewrite_u16!(bytes::Vector{UInt8}, index::Int, value::Int)
    value <= typemax(UInt16) || throw(ArgumentError("uint16 overflow"))
    bytes[index] = UInt8(value >> 8)
    bytes[index + 1] = UInt8(value & 0xff)
    return nothing
end

function _rewrite_u24!(bytes::Vector{UInt8}, index::Int, value::Int)
    value <= 0x00ff_ffff || throw(ArgumentError("uint24 overflow"))
    bytes[index] = UInt8(value >> 16)
    bytes[index + 1] = UInt8((value >> 8) & 0xff)
    bytes[index + 2] = UInt8(value & 0xff)
    return nothing
end

function _server_hello_extensions_range(bytes::Vector{UInt8})
    idx = 1
    idx += 1 # type
    idx += 3 # length
    idx += 2 # version
    idx += 32 # random
    session_id_len = Int(bytes[idx])
    idx += 1 + session_id_len
    idx += 2 # cipher suite
    idx += 1 # compression method
    extensions_len = (Int(bytes[idx]) << 8) | Int(bytes[idx + 1])
    start = idx + 2
    stop = start + extensions_len - 1
    return idx, start, stop
end

function _replace_server_hello_sct_with_empty_list(bytes::Vector{UInt8})
    ext_len_index, ext_start, ext_stop = _server_hello_extensions_range(bytes)
    idx = ext_start
    while idx <= ext_stop
        extension = (UInt16(bytes[idx]) << 8) | UInt16(bytes[idx + 1])
        ext_len = (Int(bytes[idx + 2]) << 8) | Int(bytes[idx + 3])
        ext_data_start = idx + 4
        ext_data_stop = ext_data_start + ext_len - 1
        if extension == TLH._HANDSHAKE_EXTENSION_SCT
            replacement = UInt8[
                UInt8(extension >> 8),
                UInt8(extension & 0xff),
                0x00, 0x02,
                0x00, 0x00,
            ]
            out = vcat(bytes[1:(idx - 1)], replacement, bytes[(ext_data_stop + 1):end])
            new_ext_len = (ext_stop - ext_start + 1) - ext_len + 2
            _rewrite_u16!(out, ext_len_index, new_ext_len)
            _rewrite_u24!(out, 2, length(out) - 4)
            return out
        end
        idx = ext_data_stop + 1
    end
    error("SCT extension not found")
end

@testset "TLS handshake messages phases 1-2" begin
    @testset "rich ClientHello roundtrips and binder helpers follow Go ordering" begin
        client_hello = _client_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x00):UInt8(0x1f)),
            session_id = UInt8[0xaa, 0xbb, 0xcc],
            cipher_suites = UInt16[0x1301, 0x1302, 0xc02f],
            compression_methods = UInt8[TLH._TLS_COMPRESSION_NONE],
            server_name = "reseau-phase1",
            ocsp_stapling = true,
            supported_curves = UInt16[0x001d, 0x0017],
            supported_points = UInt8[0x00],
            ticket_supported = true,
            session_ticket = UInt8[0x10, 0x11, 0x12],
            supported_signature_algorithms = UInt16[0x0403, 0x0804],
            supported_signature_algorithms_cert = UInt16[0x0403],
            secure_renegotiation_supported = true,
            secure_renegotiation = UInt8[0x20, 0x21],
            extended_master_secret = true,
            alpn_protocols = ["h2", "http/1.1"],
            scts = true,
            supported_versions = UInt16[TLH.TLS1_3_VERSION, TLH.TLS1_2_VERSION],
            cookie = UInt8[0x30, 0x31, 0x32],
            key_shares = [TLH._TLSKeyShare(0x001d, UInt8[0x40, 0x41, 0x42])],
            early_data = true,
            psk_modes = UInt8[TLH._TLS_PSK_MODE_DHE, TLH._TLS_PSK_MODE_PLAIN],
            psk_identities = [TLH._TLSPSKIdentity(UInt8[0x50, 0x51], 0x01020304)],
            psk_binders = [UInt8[0x60, 0x61, 0x62, 0x63]],
            quic_transport_parameters = UInt8[0x70, 0x71],
            encrypted_client_hello = UInt8[0x80, 0x81],
        )

        bytes = TLH._marshal_handshake_message(client_hello)
        parsed = TLH._unmarshal_handshake_message(bytes)

        @test parsed isa TLH._ClientHelloMsg
        parsed_client = parsed::TLH._ClientHelloMsg
        @test parsed_client == client_hello
        @test parsed_client.original == bytes
        @test parsed_client.extensions == UInt16[
            TLH._HANDSHAKE_EXTENSION_SERVER_NAME,
            TLH._HANDSHAKE_EXTENSION_SUPPORTED_POINTS,
            TLH._HANDSHAKE_EXTENSION_SESSION_TICKET,
            TLH._HANDSHAKE_EXTENSION_RENEGOTIATION_INFO,
            TLH._HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET,
            TLH._HANDSHAKE_EXTENSION_SCT,
            TLH._HANDSHAKE_EXTENSION_EARLY_DATA,
            TLH._HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS,
            TLH._HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO,
            TLH._HANDSHAKE_EXTENSION_STATUS_REQUEST,
            TLH._HANDSHAKE_EXTENSION_SUPPORTED_CURVES,
            TLH._HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS,
            TLH._HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT,
            TLH._HANDSHAKE_EXTENSION_ALPN,
            TLH._HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS,
            TLH._HANDSHAKE_EXTENSION_COOKIE,
            TLH._HANDSHAKE_EXTENSION_KEY_SHARE,
            TLH._HANDSHAKE_EXTENSION_PSK_MODES,
            TLH._HANDSHAKE_EXTENSION_PRE_SHARED_KEY,
        ]
        @test TLH._handshake_transcript_bytes(parsed_client) == bytes

        without_binders = TLH._marshal_client_hello_without_binders(client_hello)
        binder_prefix_len = 2 + sum(1 + length(binder) for binder in client_hello.psk_binders)
        @test without_binders == bytes[1:(end - binder_prefix_len)]
        @test TLH._marshal_client_hello_without_binders(parsed_client) == without_binders

        TLH._update_client_hello_binders!(parsed_client, [UInt8[0xa0, 0xa1, 0xa2, 0xa3]])
        rebound = TLH._marshal_handshake_message(parsed_client)
        reparsed = TLH._unmarshal_handshake_message(rebound)
        @test reparsed isa TLH._ClientHelloMsg
        @test (reparsed::TLH._ClientHelloMsg).psk_binders == [UInt8[0xa0, 0xa1, 0xa2, 0xa3]]
        @test TLH._marshal_client_hello_without_binders(parsed_client) == without_binders

        @test_throws ArgumentError TLH._update_client_hello_binders!(parsed_client, Vector{Vector{UInt8}}())
        @test_throws ArgumentError TLH._update_client_hello_binders!(parsed_client, [UInt8[0x01, 0x02]])
    end

    @testset "ServerHello variants roundtrip and preserve original bytes" begin
        server_hello = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x80):UInt8(0x9f)),
            session_id = UInt8[0x01, 0x02],
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            ocsp_stapling = true,
            ticket_supported = true,
            secure_renegotiation_supported = true,
            secure_renegotiation = UInt8[0x03, 0x04],
            extended_master_secret = true,
            alpn_protocol = "h2",
            scts = [UInt8[0x05, 0x06, 0x07]],
            supported_version = TLH.TLS1_3_VERSION,
            server_share = TLH._TLSKeyShare(0x001d, UInt8[0x08, 0x09]),
            selected_identity_present = true,
            selected_identity = 0x0001,
            supported_points = UInt8[0x00],
            encrypted_client_hello = UInt8[0x0a, 0x0b],
            server_name_ack = true,
        )

        bytes = TLH._marshal_handshake_message(server_hello)
        parsed = TLH._unmarshal_handshake_message(bytes)
        @test parsed isa TLH._ServerHelloMsg
        parsed_server = parsed::TLH._ServerHelloMsg
        @test parsed_server == server_hello
        @test parsed_server.original == bytes
        @test TLH._handshake_transcript_bytes(parsed_server) == bytes

        hello_retry = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = fill(UInt8(0xee), 32),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            supported_version = TLH.TLS1_3_VERSION,
            cookie = UInt8[0x11, 0x12, 0x13],
            selected_group = 0x001d,
        )
        hrr_bytes = TLH._marshal_handshake_message(hello_retry)
        hrr_parsed = TLH._unmarshal_handshake_message(hrr_bytes)
        @test hrr_parsed isa TLH._ServerHelloMsg
        @test (hrr_parsed::TLH._ServerHelloMsg) == hello_retry

        invalid = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = fill(UInt8(0xaa), 32),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            server_share = TLH._TLSKeyShare(0x001d, UInt8[0x01]),
            selected_group = 0x001d,
        )
        @test_throws ArgumentError TLH._marshal_handshake_message(invalid)
    end

    @testset "EncryptedExtensions and Finished roundtrip" begin
        encrypted_extensions = _encrypted_extensions_msg(
            alpn_protocol = "http/1.1",
            quic_transport_parameters = UInt8[0x01, 0x02, 0x03],
            early_data = true,
            ech_retry_configs = UInt8[0x04, 0x05],
            server_name_ack = true,
        )
        finished = _finished_msg(verify_data = UInt8[0x10, 0x11, 0x12, 0x13])

        ee_bytes = TLH._marshal_handshake_message(encrypted_extensions)
        fin_bytes = TLH._marshal_handshake_message(finished)
        @test TLH._unmarshal_handshake_message(ee_bytes) == encrypted_extensions
        @test TLH._unmarshal_handshake_message(fin_bytes) == finished
        @test TLH._handshake_transcript_bytes(encrypted_extensions) == ee_bytes
        @test TLH._handshake_transcript_bytes(finished) == fin_bytes
    end

    @testset "TLS 1.2 Certificate*, ServerKeyExchange, and hello-done roundtrip" begin
        certificate_request = _certificate_request_msg_tls12(
            certificate_types = UInt8[0x01, 0x40],
            supported_signature_algorithms = UInt16[
                TLH._TLS_SIGNATURE_RSA_PKCS1_SHA256,
                TLH._TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
            ],
            certificate_authorities = [UInt8[0x01, 0x02], UInt8[0x30, 0x31, 0x32]],
        )
        certificate = _certificate_msg_tls12(
            certificates = [UInt8[0x10, 0x11, 0x12], UInt8[0x20, 0x21]],
        )
        server_key_exchange = _server_key_exchange_msg_tls12(
            key = UInt8[0x03, 0x00, 0x17, 0x41, fill(UInt8(0x22), 65)..., 0x04, 0x01, 0x00, 0x02, 0xaa, 0xbb],
        )
        certificate_verify = _certificate_verify_msg(
            signature_algorithm = TLH._TLS_SIGNATURE_RSA_PKCS1_SHA256,
            signature = UInt8[0x60, 0x61, 0x62, 0x63],
        )
        server_hello_done = _server_hello_done_msg_tls12()
        client_key_exchange = _client_key_exchange_msg_tls12(ciphertext = UInt8[0x41, 0x04, fill(UInt8(0x33), 65)...])

        cert_req_bytes = TLH._marshal_handshake_message(certificate_request)
        cert_bytes = TLH._marshal_handshake_message(certificate)
        server_key_exchange_bytes = TLH._marshal_handshake_message(server_key_exchange)
        cert_verify_bytes = TLH._marshal_handshake_message(certificate_verify)
        server_hello_done_bytes = TLH._marshal_handshake_message(server_hello_done)
        client_key_exchange_bytes = TLH._marshal_handshake_message(client_key_exchange)

        @test TLH._unmarshal_handshake_message(cert_req_bytes, nothing, TLH.TLS1_2_VERSION) == certificate_request
        @test TLH._unmarshal_handshake_message(cert_bytes, nothing, TLH.TLS1_2_VERSION) == certificate
        @test TLH._unmarshal_handshake_message(server_key_exchange_bytes, nothing, TLH.TLS1_2_VERSION) == server_key_exchange
        @test TLH._unmarshal_handshake_message(cert_verify_bytes, nothing, TLH.TLS1_2_VERSION) == certificate_verify
        @test TLH._unmarshal_handshake_message(server_hello_done_bytes, nothing, TLH.TLS1_2_VERSION) == server_hello_done
        @test TLH._unmarshal_handshake_message(client_key_exchange_bytes, nothing, TLH.TLS1_2_VERSION) == client_key_exchange
    end

    @testset "TLS 1.3 Certificate*, CertificateRequest, and NewSessionTicket roundtrip" begin
        certificate_request = _certificate_request_msg_tls13(
            ocsp_stapling = true,
            scts = true,
            supported_signature_algorithms = UInt16[0x0403, 0x0804],
            supported_signature_algorithms_cert = UInt16[0x0403],
            certificate_authorities = [UInt8[0x01, 0x02, 0x03], UInt8[0x04, 0x05]],
        )
        certificate = _certificate_msg_tls13(
            certificates = [UInt8[0x10, 0x11, 0x12], UInt8[0x20, 0x21]],
            ocsp_stapling = true,
            ocsp_staple = UInt8[0x30, 0x31, 0x32],
            scts = true,
            signed_certificate_timestamps = [UInt8[0x40, 0x41], UInt8[0x50, 0x51, 0x52]],
        )
        certificate_verify = _certificate_verify_msg(
            signature_algorithm = 0x0804,
            signature = UInt8[0x60, 0x61, 0x62, 0x63],
        )
        new_session_ticket = _new_session_ticket_msg_tls13(
            lifetime = 0x01020304,
            age_add = 0x05060708,
            nonce = UInt8[0x70, 0x71],
            label = UInt8[0x80, 0x81, 0x82],
            max_early_data = 0x0a0b0c0d,
        )

        cert_req_bytes = TLH._marshal_handshake_message(certificate_request)
        cert_bytes = TLH._marshal_handshake_message(certificate)
        cert_verify_bytes = TLH._marshal_handshake_message(certificate_verify)
        ticket_bytes = TLH._marshal_handshake_message(new_session_ticket)

        @test TLH._unmarshal_handshake_message(cert_req_bytes) == certificate_request
        @test TLH._unmarshal_handshake_message(cert_bytes) == certificate
        @test TLH._unmarshal_handshake_message(cert_verify_bytes) == certificate_verify
        @test TLH._unmarshal_handshake_message(ticket_bytes) == new_session_ticket
        @test TLH._handshake_transcript_bytes(certificate_request) == cert_req_bytes
        @test TLH._handshake_transcript_bytes(certificate) == cert_bytes
        @test TLH._handshake_transcript_bytes(certificate_verify) == cert_verify_bytes
        @test TLH._handshake_transcript_bytes(new_session_ticket) == ticket_bytes
    end

    @testset "Transcript hooks match raw wire bytes" begin
        client_hello = _client_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x01):UInt8(0x20)),
            cipher_suites = UInt16[0x1301],
            compression_methods = UInt8[TLH._TLS_COMPRESSION_NONE],
            supported_versions = UInt16[TLH.TLS1_3_VERSION],
        )
        server_hello = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x21):UInt8(0x40)),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            supported_version = TLH.TLS1_3_VERSION,
            server_share = TLH._TLSKeyShare(0x001d, UInt8[0x01, 0x02, 0x03]),
        )
        encrypted_extensions = _encrypted_extensions_msg(alpn_protocol = "h2")
        finished = _finished_msg(verify_data = UInt8[0xaa, 0xbb, 0xcc, 0xdd])

        transcript_write = TLH._TranscriptHash(TLH._HASH_SHA256)
        client_bytes = TLH._write_handshake_message(client_hello, transcript_write)
        server_bytes = TLH._write_handshake_message(server_hello, transcript_write)
        ee_bytes = TLH._write_handshake_message(encrypted_extensions, transcript_write)
        fin_bytes = TLH._write_handshake_message(finished, transcript_write)
        expected = SHA.sha256(vcat(client_bytes, server_bytes, ee_bytes, fin_bytes))
        @test TLH._transcript_digest(transcript_write) == expected

        transcript_read = TLH._TranscriptHash(TLH._HASH_SHA256)
        @test TLH._unmarshal_handshake_message(client_bytes, transcript_read) isa TLH._ClientHelloMsg
        @test TLH._unmarshal_handshake_message(server_bytes, transcript_read) isa TLH._ServerHelloMsg
        @test TLH._unmarshal_handshake_message(ee_bytes, transcript_read) isa TLH._EncryptedExtensionsMsg
        @test TLH._unmarshal_handshake_message(fin_bytes, transcript_read) isa TLH._FinishedMsg
        @test TLH._transcript_digest(transcript_read) == expected

        transcript_parsed = TLH._TranscriptHash(TLH._HASH_SHA256)
        parsed_client = TLH._unmarshal_handshake_message(client_bytes)::TLH._ClientHelloMsg
        parsed_server = TLH._unmarshal_handshake_message(server_bytes)::TLH._ServerHelloMsg
        TLH._transcript_update_handshake!(transcript_parsed, parsed_client)
        TLH._transcript_update_handshake!(transcript_parsed, parsed_server)
        TLH._transcript_update_handshake!(transcript_parsed, encrypted_extensions)
        TLH._transcript_update_handshake!(transcript_parsed, finished)
        @test TLH._transcript_digest(transcript_parsed) == expected
    end

    @testset "Parsed handshake messages own copied frame bytes" begin
        client_hello = _client_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x01):UInt8(0x20)),
            cipher_suites = UInt16[0x1301],
            compression_methods = UInt8[TLH._TLS_COMPRESSION_NONE],
            supported_versions = UInt16[TLH.TLS1_3_VERSION],
        )
        server_hello = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = collect(UInt8(0x21):UInt8(0x40)),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            supported_version = TLH.TLS1_3_VERSION,
            server_share = TLH._TLSKeyShare(0x001d, UInt8[0x01, 0x02, 0x03]),
        )

        client_bytes = TLH._marshal_handshake_message(client_hello)
        server_bytes = TLH._marshal_handshake_message(server_hello)
        expected_client_bytes = copy(client_bytes)
        expected_server_bytes = copy(server_bytes)

        parsed_client = TLH._unmarshal_handshake_message(client_bytes)::TLH._ClientHelloMsg
        parsed_server = TLH._unmarshal_handshake_message(server_bytes)::TLH._ServerHelloMsg

        client_bytes[5] = xor(client_bytes[5], 0xff)
        server_bytes[5] = xor(server_bytes[5], 0xff)

        @test parsed_client.original == expected_client_bytes
        @test parsed_server.original == expected_server_bytes
        @test TLH._handshake_transcript_bytes(parsed_client) == expected_client_bytes
        @test TLH._handshake_transcript_bytes(parsed_server) == expected_server_bytes
    end

    @testset "Go-derived malformed vectors are rejected" begin
        client_hello_duplicate = _tls_hm_hexbytes("010000440303000000000000000000000000000000000000000000000000000000000000000000000000001c0000000a000800000568656c6c6f0000000a000800000568656c6c6f")
        server_hello_duplicate = _tls_hm_hexbytes("02000030030300000000000000000000000000000000000000000000000000000000000000000000000000080005000000050000")

        @test TLH._unmarshal_handshake_message(client_hello_duplicate) === nothing
        @test TLH._unmarshal_handshake_message(server_hello_duplicate) === nothing

        valid_server_hello = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = zeros(UInt8, 32),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            scts = [UInt8[0x42, 0x42, 0x42, 0x42]],
        )
        valid_server_hello_bytes = TLH._marshal_handshake_message(valid_server_hello)
        @test TLH._unmarshal_handshake_message(valid_server_hello_bytes) isa TLH._ServerHelloMsg

        empty_sct_list = _replace_server_hello_sct_with_empty_list(valid_server_hello_bytes)
        @test TLH._unmarshal_handshake_message(empty_sct_list) === nothing

        zero_length_sct = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = zeros(UInt8, 32),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            scts = [UInt8[]],
        )
        @test TLH._unmarshal_handshake_message(TLH._marshal_handshake_message(zero_length_sct)) === nothing

        empty_server_share = _server_hello_msg(
            vers = TLH.TLS1_2_VERSION,
            random = zeros(UInt8, 32),
            cipher_suite = 0x1301,
            compression_method = TLH._TLS_COMPRESSION_NONE,
            supported_version = TLH.TLS1_3_VERSION,
            server_share = TLH._TLSKeyShare(0x001d, UInt8[]),
        )
        @test_throws ArgumentError TLH._marshal_handshake_message(empty_server_share)

        empty_certificate_scts = _certificate_msg_tls13(
            certificates = [UInt8[0x01, 0x02, 0x03]],
            scts = true,
            signed_certificate_timestamps = [UInt8[]],
        )
        @test TLH._unmarshal_handshake_message(TLH._marshal_handshake_message(empty_certificate_scts)) === nothing

        empty_certificate_verify = _certificate_verify_msg(
            signature_algorithm = 0x0804,
            signature = UInt8[],
        )
        @test TLH._unmarshal_handshake_message(TLH._marshal_handshake_message(empty_certificate_verify)) === nothing

        bad_certificate = _tls_hm_hexbytes("0b000006010000020102")
        @test TLH._unmarshal_handshake_message(bad_certificate) === nothing
    end

    @testset "Framing rejects truncation, oversize messages, and unknown types" begin
        finished = _finished_msg(verify_data = UInt8[0x01, 0x02, 0x03])
        finished_bytes = TLH._marshal_handshake_message(finished)

        @test TLH._unmarshal_handshake_message(finished_bytes[1:(end - 1)]) === nothing
        @test TLH._unmarshal_handshake_message(UInt8[0xff, 0x00, 0x00, 0x00]) === nothing
        @test_throws ArgumentError TLH._unmarshal_handshake_message(UInt8[TLH._HANDSHAKE_TYPE_FINISHED, 0x01, 0x00, 0x01])
    end

    @testset "Randomized roundtrip coverage" begin
        rng = MersenneTwister(0x5eed1)
        for _ in 1:30
            client_hello = _random_client_hello(rng)
            client_hello_bytes = TLH._marshal_handshake_message(client_hello)
            parsed_client = TLH._unmarshal_handshake_message(client_hello_bytes)
            @test parsed_client isa TLH._ClientHelloMsg
            @test (parsed_client::TLH._ClientHelloMsg) == client_hello

            server_hello = _random_server_hello(rng)
            server_hello_bytes = TLH._marshal_handshake_message(server_hello)
            parsed_server = TLH._unmarshal_handshake_message(server_hello_bytes)
            @test parsed_server isa TLH._ServerHelloMsg
            @test (parsed_server::TLH._ServerHelloMsg) == server_hello

            encrypted_extensions = _random_encrypted_extensions(rng)
            encrypted_extensions_bytes = TLH._marshal_handshake_message(encrypted_extensions)
            parsed_ee = TLH._unmarshal_handshake_message(encrypted_extensions_bytes)
            @test parsed_ee isa TLH._EncryptedExtensionsMsg
            @test (parsed_ee::TLH._EncryptedExtensionsMsg) == encrypted_extensions

            certificate_request = _random_certificate_request_tls13(rng)
            certificate_request_bytes = TLH._marshal_handshake_message(certificate_request)
            parsed_certificate_request = TLH._unmarshal_handshake_message(certificate_request_bytes)
            @test parsed_certificate_request isa TLH._CertificateRequestMsgTLS13
            @test (parsed_certificate_request::TLH._CertificateRequestMsgTLS13) == certificate_request

            certificate = _random_certificate_tls13(rng)
            certificate_bytes = TLH._marshal_handshake_message(certificate)
            parsed_certificate = TLH._unmarshal_handshake_message(certificate_bytes)
            @test parsed_certificate isa TLH._CertificateMsgTLS13
            @test (parsed_certificate::TLH._CertificateMsgTLS13) == certificate

            certificate_verify = _random_certificate_verify(rng)
            certificate_verify_bytes = TLH._marshal_handshake_message(certificate_verify)
            parsed_certificate_verify = TLH._unmarshal_handshake_message(certificate_verify_bytes)
            @test parsed_certificate_verify isa TLH._CertificateVerifyMsg
            @test (parsed_certificate_verify::TLH._CertificateVerifyMsg) == certificate_verify

            new_session_ticket = _random_new_session_ticket_tls13(rng)
            new_session_ticket_bytes = TLH._marshal_handshake_message(new_session_ticket)
            parsed_new_session_ticket = TLH._unmarshal_handshake_message(new_session_ticket_bytes)
            @test parsed_new_session_ticket isa TLH._NewSessionTicketMsgTLS13
            @test (parsed_new_session_ticket::TLH._NewSessionTicketMsgTLS13) == new_session_ticket

            finished = _random_finished(rng)
            finished_bytes = TLH._marshal_handshake_message(finished)
            parsed_finished = TLH._unmarshal_handshake_message(finished_bytes)
            @test parsed_finished isa TLH._FinishedMsg
            @test (parsed_finished::TLH._FinishedMsg) == finished
        end
    end

    @testset "Random garbage does not crash handshake parsing" begin
        rng = MersenneTwister(0x5eed2)
        for _ in 1:1000
            bytes = rand(rng, UInt8, rand(rng, 0:1000))
            parsed = try
                TLH._unmarshal_handshake_message(bytes)
            catch err
                @test err isa ArgumentError
                continue
            end
            parsed === nothing || @test parsed isa TLH._HandshakeMessage
        end
    end
end
