"""
    QUIC

QUIC transport (RFC 9000/9001/9002), the transport for HTTP/3. `connect`
and `listen`/`accept` give a `Connection`, whose streams (`open_stream`,
`accept_stream`) are `IO`. Connections have flow control, loss recovery, and
congestion control, and interoperate with quic-go. The TLS handshake for QUIC
lives in `TLS.QUICConn`. Not exported: use it as `Reseau.QUIC`.
"""
module QUIC

using Random
using ..Reseau: TLS, UDP, IOPoll
using ..Reseau.IOPoll: _monotonic_ns
using ..Reseau.TLS:
    _HASH_SHA256,
    _LIBCRYPTO_PATH,
    _OpenSSLAEADState,
    _TLS13CipherSpec,
    _TLS13_AES_128_GCM_SHA256,
    _TLS13_AES_128_GCM_SHA256_ID,
    _TLS13_CHACHA20_POLY1305_SHA256_ID,
    _constant_time_equals,
    _free_evp_cipher_ctx!,
    _free_openssl_aead_state!,
    _hash_len,
    _hkdf_extract,
    _openssl_decrypt_record_aead!,
    _openssl_encrypt_record_aead!,
    _openssl_require_nonnull,
    _openssl_require_ok,
    _securezero!,
    _tls13_cipher_spec,
    _tls13_encrypt_record_aead,
    _tls13_expand_label,
    _tls13_record_cipher

include("quic/packet_protection.jl")
include("quic/packets.jl")
include("quic/frames.jl")
include("quic/transport_parameters.jl")
include("quic/buffers.jl")
include("quic/stream_state.jl")
include("quic/connection.jl")
include("quic/streams.jl")
include("quic/api.jl")

end
