using Test
using Reseau

# Ported from quic-go v0.48.2, internal/handshake:
#   handshake_helpers_test.go, aead_test.go, initial_aead_test.go,
#   updatable_aead_test.go, retry_test.go, hkdf_test.go, crypto_setup_test.go
# (~/go/pkg/mod/github.com/quic-go/quic-go@v0.48.2/internal/handshake/*_test.go).
# Each @testset is named after the Go test it ports, with the same inputs and
# expectations adapted to Reseau's API. Where Go's behavior differs from ours,
# the Go expectation is kept as @test_broken with a `# BUG?:` note, or, where
# the difference is deliberate, our behavior is tested under a
# `# Differs from quic-go:` note.
#
# Adaptations:
# - Go's Seal(msg, pn, ad) authenticates arbitrary associated data; our AEAD
#   authenticates the packet header, so `ad` is laid out as the header
#   (first byte || ad || 4-byte packet number) and opened with
#   `_remove_header_protection!` + `_decrypt_payload!`.
# - Go's updatableAEAD tests (key updates) run against a real server
#   `_Connection` after an in-memory handshake, with fresh 1-RTT keys installed
#   from random traffic secrets (Go's setupEndpoints). Go's "client" AEAD is a
#   key chain that seals packets at chosen packet numbers and key phases. Go's
#   server.Open is `_open_1rtt_packet!` (or `_receive_datagram!` when timing or
#   packet-number tracking matters), server.Seal sends a real PING packet,
#   server.SetLargestAcked(pn) delivers a real ACK frame from the peer, and
#   rollKeys is `_rotate_keys!`. Go's setKeyUpdateIntervals sets the
#   connection's `first_key_update_interval`/`key_update_interval`. Go's
#   KeyPhase() starts a due key update when the next packet is packed; ours
#   starts once the packet that makes it due is sent or opened, or the ACK that
#   allows it arrives. Our ACKs arrive in real packets, which count as
#   received; where that would make an update due early, the test keeps the
#   default intervals and starts the update with `_initiate_key_update!`.
# - crypto_setup tests drive two `TLS.QUICConn`s, the layer under our QUIC
#   connection that corresponds to Go's CryptoSetup.
#
# N/A (features we deliberately lack, or Go API helpers):
# - QUIC version 2 subtests of every test (we implement only QUIC v1).
# - session_ticket_test.go (all 7 tests): quic-go's own session ticket payload
#   (RTT + 0-RTT transport parameters); we carry no QUIC data in tickets.
# - token_generator_test.go, token_protector_test.go (all 12 tests): no
#   address-validation tokens / Retry generation.
# - Test0RTT, Test0RTTRejectionOnTransportParametersChanged: no 0-RTT.
# - TestSessionResumption's RTT-restoration assertions (RTT stored in the
#   session ticket, a quic-go ticket feature); the DidResume parts are ported.
# - Benchmarks (BenchmarkInitialAEAD*, BenchmarkPacket*, BenchmarkRollKeys,
#   BenchmarkHKDF*).

@isdefined(_QcnHarness) || include("quic_harness.jl")

const _QGH_APP = QCN._APPLICATION_SPACE
# Go's cipherSuites (handshake_helpers_test.go).
const _QGH_CIPHER_SUITES = (
    TLC._TLS13_AES_128_GCM_SHA256_ID,
    TLC._TLS13_AES_256_GCM_SHA384_ID,
    TLC._TLS13_CHACHA20_POLY1305_SHA256_ID,
)
const _QGH_MSG = Vector{UInt8}(codeunits("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."))
const _QGH_AD = Vector{UInt8}(codeunits("Donec in velit neque."))
const _QGH_RFC9001_DCID_HEX = "0x8394c8f03e515708"

# Go's splitHexString.
function _qgh_hex(s::AbstractString)::Vector{UInt8}
    out = UInt8[]
    for part in split(s, ' '; keepempty = false)
        startswith(part, "0x") && (part = part[3:end])
        append!(out, hex2bytes(part))
    end
    return out
end

_qgh_pn_bytes(pn::Integer, n::Int) = UInt8[UInt8((pn >> (8 * (n - i))) & 0xff) for i in 1:n]

# Go's sealer.Seal(nil, msg, pn, ad) + EncryptHeader, with `ad` as the header.
function _qgh_seal(keys::QCN._PacketKeys, msg::Vector{UInt8}, pn::Integer, ad::Vector{UInt8}; first_byte::UInt8 = 0x43)
    header = vcat(UInt8[first_byte], ad, _qgh_pn_bytes(pn, 4))
    buf = vcat(header, msg, zeros(UInt8, 16))
    pn_offset = 2 + length(ad)
    QCN._seal_packet!(keys, buf, 1, pn_offset, 4, length(header) + length(msg), Int64(pn))
    return (buf = buf, pn_offset = pn_offset)
end

# Go's opener.DecryptHeader + Open(nil, ciphertext, pn, ad): the plaintext, or
# nothing for ErrDecryptionFailed. `ad` replaces the associated data.
function _qgh_open(keys::QCN._PacketKeys, sealed; pn::Integer, ad::Union{Nothing, Vector{UInt8}} = nothing, truncate::Int = 0)
    buf = sealed.buf[1:(end - truncate)]
    unmasked = QCN._remove_header_protection!(keys.hp, buf, 1, sealed.pn_offset, length(buf))
    unmasked === nothing && return nothing
    pn_len, _ = unmasked
    ad === nothing || copyto!(buf, 2, ad, 1, length(ad))
    last = QCN._decrypt_payload!(keys, buf, 1, sealed.pn_offset, pn_len, Int64(pn), length(buf))
    last === nothing && return nothing
    return buf[(sealed.pn_offset + pn_len):last]
end

# Go's EncryptHeader/DecryptHeader(sample, &hdr[0], hdr[pn_offset:]): applies
# the mask for `sample`, which our API reads at pn_offset + 4.
function _qgh_xor_header!(hp::QCN._HeaderProtector, header::Vector{UInt8}, pn_offset::Int, sample::Vector{UInt8})
    pn_len = length(header) - pn_offset + 1
    @assert length(header) + 1 == pn_offset + 4
    buf = vcat(header, sample)
    mask = QCN._header_protection_mask!(hp, buf, length(header) + 1)
    QCN._xor_header_mask!(buf, 1, pn_offset, pn_len, mask)
    copyto!(header, 1, buf, 1, length(header))
    return header
end

# Go's "client" updatableAEAD in the key update tests: seals packets to the
# server with its current keys and key phase, at chosen packet numbers.
mutable struct _QghPeer
    keys::QCN._PacketKeys
    phase::Bool
    dcid::Vector{UInt8}
    # Packet numbers for the packets carrying ACK frames, clear of Go's.
    next_ack_pn::Int64
end

function _qgh_roll!(p::_QghPeer)
    p.keys = QCN._next_packet_keys(p.keys)
    p.phase = !p.phase
    return p
end

function _qgh_peer_seal(p::_QghPeer, pn::Integer; frames::Vector{UInt8} = UInt8[0x01], phase::Bool = p.phase, keys::QCN._PacketKeys = p.keys)
    buf = UInt8[]
    layout = QCN._begin_short_packet!(buf, p.dcid, Int64(pn), 4; key_phase = phase)
    append!(buf, frames)
    payload_last = QCN._end_packet!(buf, layout)
    QCN._seal_packet!(keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, Int64(pn))
    return buf
end

# Go's setupEndpoints: a Confirmed server connection with fresh 1-RTT keys
# from random 16-byte traffic secrets and a random cipher suite, as a new
# updatableAEAD would have: key phase 0, nothing sent or received with them.
function _qgh_endpoints(; suite::UInt16 = rand(_QGH_CIPHER_SUITES), rtt_ms::Union{Nothing, Int} = nothing)
    h = _QcnHarness()
    _qcn_run!(h) || error("handshake failed")
    server = h.server::QCN._Connection
    QCN._pmtu_stop!(server)
    secret1 = rand(UInt8, 16)
    secret2 = rand(UInt8, 16)
    space = server.spaces[_QGH_APP]
    space.read_keys = QCN._PacketKeys(suite, secret1)
    space.write_keys = QCN._PacketKeys(suite, secret2)
    server.key_phase = false
    server.prev_read_keys = nothing
    server.next_read_keys = nothing
    server.prev_read_keys_expiry = typemax(Int64)
    server.key_phase_first_sent = Int64(-1)
    server.key_phase_first_received = typemax(Int64)
    server.key_phase_sent = 0
    server.key_phase_received = 0
    server.key_updates = 0
    server.invalid_packets = 0
    space.largest_received = Int64(-1)
    space.received = QCN._RangeSet()
    if rtt_ms !== nothing
        # Go's rttStats.UpdateRTT(rtt, 0, now) on a fresh RTTStats.
        server.smoothed_rtt = Int64(rtt_ms) * 1_000_000
        server.rttvar = server.smoothed_rtt ÷ 2
        server.latest_rtt = server.smoothed_rtt
        server.min_rtt = server.smoothed_rtt
        server.has_rtt_sample = true
    end
    client = _QghPeer(QCN._PacketKeys(suite, secret1), false, copy(server.local_cid), Int64(0x10000))
    return h, server, client
end

# Go's server.Open for a 1-RTT packet, received at `now`: whether it opened.
function _qgh_open!(conn::QCN._Connection, pkt::Vector{UInt8}; now::Int64 = conn.last_activity)::Bool
    buf = copy(pkt)
    header = first(QCN._datagram_packets(buf, 1, length(buf), QCN._LOCAL_CID_LEN))
    space = conn.spaces[_QGH_APP]
    return QCN._open_1rtt_packet!(conn, space, space.read_keys, buf, header, now) !== nothing
end

# Go's setKeyUpdateIntervals.
function _qgh_set_key_update_intervals!(conn::QCN._Connection, first_interval::Integer, interval::Integer)
    conn.first_key_update_interval = first_interval
    conn.key_update_interval = interval
    return conn
end

# Delivers `pkt` (packet number `pn`) as a datagram at `now`; whether it was accepted.
function _qgh_receive!(conn::QCN._Connection, pkt::Vector{UInt8}, pn::Integer, now::Int64)::Bool
    QCN._receive_datagram!(conn, copy(pkt), now)
    return Int64(pn) in conn.spaces[_QGH_APP].received
end

# Go's server.Seal: the server sends one 1-RTT packet. Returns its number.
function _qgh_send!(conn::QCN._Connection, now::Int64)::Int64
    space = conn.spaces[_QGH_APP]
    pn = space.next_pn
    space.probes += 1
    dgram = QCN._next_datagram!(conn, now)
    (dgram !== nothing && space.next_pn == pn + 1) || error("server did not send a 1-RTT packet")
    return pn
end

# Go's server.SetLargestAcked(pn): the peer acknowledges `pn` in a packet
# protected with its current keys.
function _qgh_ack!(conn::QCN._Connection, peer::_QghPeer, pn::Integer, now::Int64)
    frames = UInt8[]
    QCN._append_ack_frame!(frames, [UInt64(pn):UInt64(pn)], UInt64(0))
    ack_pn = peer.next_ack_pn
    peer.next_ack_pn += 1
    QCN._receive_datagram!(conn, _qgh_peer_seal(peer, ack_pn; frames), now)
    return nothing
end

# ---- crypto_setup_test.go helpers ----

const _QGH_SERVER_CERT = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _QGH_SERVER_KEY = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _QGH_CA = joinpath(@__DIR__, "resources", "native_tls_ca.crt")

# Go's getTLSConfigs.
function _qgh_tls_configs()
    client = TLC.Config(; server_name = "localhost", verify_peer = true, ca_file = _QGH_CA, alpn_protocols = ["crypto-setup"])
    server = TLC.Config(; verify_peer = false, cert_file = _QGH_SERVER_CERT, key_file = _QGH_SERVER_KEY, alpn_protocols = ["crypto-setup"])
    return client, server
end

_qgh_client_tp(; kw...) = QCN._encode_transport_parameters(QCN._TransportParameters(;
    active_connection_id_limit = UInt64(2), initial_source_connection_id = UInt8[], kw...))
_qgh_server_tp(; kw...) = QCN._encode_transport_parameters(QCN._TransportParameters(;
    active_connection_id_limit = UInt64(2), initial_source_connection_id = UInt8[],
    original_destination_connection_id = UInt8[], stateless_reset_token = zeros(UInt8, 16), kw...))

function _qgh_feed(conn::TLC.QUICConn, level, data)
    try
        TLC.handle_data!(conn, level, data)
    catch ex
        ex isa TLC.TLSError || rethrow()
        return ex
    end
    return nothing
end

# Go's handshake(): client and server pass handshake data until both complete.
# Events other than WriteData and HandshakeDone are returned. When the server
# completes it issues a session ticket (Go's GetSessionTicket), which reaches
# the client at the Application level; `tickets` counts them.
function _qgh_handshake(client::TLC.QUICConn, server::TLC.QUICConn)
    client_events = TLC.QUICEvent[]
    server_events = TLC.QUICEvent[]
    client_err = nothing
    server_err = nothing
    tickets = 0
    result() = (; client_events, client_err, server_events, server_err, tickets)
    TLC.start!(client)
    TLC.start!(server)
    client_done = false
    server_done = false
    while true
        progressed = false
        while true
            ev = TLC.next_event!(client)
            ev.kind == TLC.QUICEventKind.NoEvent && break
            progressed = true
            if ev.kind == TLC.QUICEventKind.WriteData
                server_err = _qgh_feed(server, ev.level, ev.data)
                server_err === nothing || return result()
            elseif ev.kind == TLC.QUICEventKind.HandshakeDone
                client_done = true
            elseif ev.kind == TLC.QUICEventKind.Error
                client_err = ev.err
                return result()
            else
                push!(client_events, ev)
            end
        end
        while true
            ev = TLC.next_event!(server)
            ev.kind == TLC.QUICEventKind.NoEvent && break
            progressed = true
            if ev.kind == TLC.QUICEventKind.WriteData
                ev.level == TLC.QUICEncryptionLevel.Application && (tickets += 1)
                client_err = _qgh_feed(client, ev.level, ev.data)
                client_err === nothing || return result()
            elseif ev.kind == TLC.QUICEventKind.HandshakeDone
                server_done = true
                TLC.send_session_ticket!(server)
            elseif ev.kind == TLC.QUICEventKind.Error
                server_err = ev.err
                return result()
            else
                push!(server_events, ev)
            end
        end
        client_done && server_done && return result()
        progressed || error("handshake stalled")
    end
end

# Go's handshakeWithTLSConf.
function _qgh_handshake_with_conf(client_conf, server_conf; client_tp = _qgh_client_tp(), server_tp = _qgh_server_tp())
    client = TLC.quic_client(client_conf)
    TLC.set_transport_parameters!(client, client_tp)
    server = TLC.quic_server(server_conf)
    TLC.set_transport_parameters!(server, server_tp)
    r = _qgh_handshake(client, server)
    return (; client, server, r...)
end

function _qgh_close(rs...)
    for r in rs
        close(r.client)
        close(r.server)
    end
end

function _qgh_received_tp(events; from_server::Bool)
    for ev in events
        ev.kind == TLC.QUICEventKind.TransportParameters || continue
        return QCN._decode_transport_parameters(ev.data; from_server)
    end
    return nothing
end

@testset "quic_go_handshake_tests.jl" begin
    # ---------------- handshake_helpers_test.go ----------------
    @testset "TestSplitHexString" begin
        @test _qgh_hex("0xdeadbeef") == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test _qgh_hex("deadbeef") == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test _qgh_hex("dead beef") == UInt8[0xde, 0xad, 0xbe, 0xef]
    end

    # ---------------- aead_test.go ----------------
    @testset "TestEncryptAndDecryptMessage" begin
        for cs in _QGH_CIPHER_SUITES
            @testset "QUIC v1/$(string(cs; base = 16))" begin
                secret = rand(UInt8, 16)
                sealer = QCN._PacketKeys(cs, secret)
                opener = QCN._PacketKeys(cs, secret)
                encrypted = _qgh_seal(sealer, _QGH_MSG, 0x1337, _QGH_AD; first_byte = 0xc3)
                @test _qgh_open(opener, encrypted; pn = 0x1337) == _QGH_MSG
                # incorrect associated data
                @test _qgh_open(opener, encrypted; pn = 0x1337, ad = Vector{UInt8}(codeunits("wrong ad"))) === nothing
                # incorrect packet number
                @test _qgh_open(opener, encrypted; pn = 0x42) === nothing
            end
        end
    end

    @testset "TestDecodePacketNumber" begin
        # Our long header opener leaves the largest packet number to its caller
        # (the connection), which only advances it for packets that open.
        msg = Vector{UInt8}(codeunits("Lorem ipsum dolor sit amet"))
        secret = rand(UInt8, 16)
        sealer = QCN._PacketKeys(TLC._TLS13_AES_128_GCM_SHA256_ID, secret)
        opener = QCN._PacketKeys(TLC._TLS13_AES_128_GCM_SHA256_ID, secret)
        encrypted = _qgh_seal(sealer, msg, 0x1337, _QGH_AD; first_byte = 0xc3)
        largest = Int64(-1)
        # can't decode the packet number if encryption failed
        buf = encrypted.buf[1:(end - 1)]
        @test QCN._open_packet!(opener, buf, 1, encrypted.pn_offset, length(buf), largest) === nothing
        @test QCN._decode_packet_number(largest, UInt64(0x38), 8) == 0x38
        buf = copy(encrypted.buf)
        opened = QCN._open_packet!(opener, buf, 1, encrypted.pn_offset, length(buf), largest)
        @test opened !== nothing
        opened === nothing || (largest = max(largest, opened[1]))
        @test QCN._decode_packet_number(largest, UInt64(0x38), 8) == 0x1338
    end

    @testset "TestEncryptAndDecryptHeader" begin
        for cs in _QGH_CIPHER_SUITES
            @testset "QUIC v1/$(string(cs; base = 16))" begin
                secret = rand(UInt8, 16)
                sealer = QCN._PacketKeys(cs, secret).hp
                opener = QCN._PacketKeys(cs, secret).hp
                orig = UInt8[0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef]
                last_four_bits_different = 0
                ok = true
                for _ in 1:100
                    sample = rand(UInt8, 16)
                    header = copy(orig)
                    _qgh_xor_header!(sealer, header, 10, sample)
                    header[1] & 0x0f != 0xb5 & 0x0f && (last_four_bits_different += 1)
                    ok &= header[1] & 0xf0 == 0xb5 & 0xf0
                    ok &= header[2:9] == UInt8[1, 2, 3, 4, 5, 6, 7, 8]
                    ok &= header[10:13] != UInt8[0xde, 0xad, 0xbe, 0xef]
                    _qgh_xor_header!(opener, header, 10, sample)
                    ok &= header == orig
                end
                @test ok
                @test last_four_bits_different > 75
                # decryption failure with different sample
                header = copy(orig)
                _qgh_xor_header!(sealer, header, 10, rand(UInt8, 16))
                _qgh_xor_header!(opener, header, 10, rand(UInt8, 16))
                @test header != orig
            end
        end
    end

    # ---------------- initial_aead_test.go ----------------
    @testset "TestComputeClientKeyAndIV" begin
        conn_id = _qgh_hex(_QGH_RFC9001_DCID_HEX)
        client_secret, _ = QCN._initial_secrets(conn_id)
        @test client_secret == _qgh_hex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")
        keys = QCN._PacketKeys(TLC._TLS13_AES_128_GCM_SHA256_ID, client_secret)
        @test keys.key == _qgh_hex("1f369613dd76d5467730efcbe3b1a22d")
        @test keys.iv == _qgh_hex("fa044b2f42a3fd3b46fb255c")
    end

    @testset "TestComputeServerKeyAndIV" begin
        conn_id = _qgh_hex(_QGH_RFC9001_DCID_HEX)
        _, server_secret = QCN._initial_secrets(conn_id)
        @test server_secret == _qgh_hex("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b")
        keys = QCN._PacketKeys(TLC._TLS13_AES_128_GCM_SHA256_ID, server_secret)
        @test keys.key == _qgh_hex("cf3a5331653c364c88f0f379b6067e37")
        @test keys.iv == _qgh_hex("0ac1493ca1905853b0bba03e")
    end

    @testset "TestClientInitial" begin
        conn_id = _qgh_hex(_QGH_RFC9001_DCID_HEX)
        header = _qgh_hex("c300000001088394c8f03e5157080000449e00000002")
        data = _qgh_hex("060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868 04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578 616d706c652e636f6dff01000100000a 00080006001d00170018001000070005 04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400 0d0010000e0403050306030203080408 050806002d00020101001c0002400100 3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000 75300901100f088394c8f03e51570806 048000ffff")
        expected_sample = _qgh_hex("d1b1c98dd7689fb8ec11d242b123dc9b")
        expected_hdr = _qgh_hex("7b9aec34")
        expected_packet = _qgh_hex("c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11 d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399 1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c 8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212 30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5 457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208 4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec 4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3 485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db 059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c 7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8 9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556 be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74 68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00 f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632 291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964 25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd 14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198 e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73 203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047 90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2 162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4 40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0 6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e 8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0 be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400 54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab 760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9 f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4 056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064 7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241 e221af44860018ab0856972e194cd934")
        sealer, _ = QCN._initial_packet_keys(conn_id)
        append!(data, zeros(UInt8, 1162 - length(data)))  # add PADDING
        buf = vcat(header, data, zeros(UInt8, 16))
        pn_offset = length(header) - 3
        @test QCN._seal_packet!(sealer, buf, 1, pn_offset, 4, length(header) + length(data), Int64(2)) == length(buf)
        @test buf[(length(header) + 1):(length(header) + 16)] == expected_sample
        @test buf[1] == 0xc0
        @test buf[pn_offset:length(header)] == expected_hdr
        @test buf == expected_packet
    end

    @testset "TestServersInitial" begin
        conn_id = _qgh_hex(_QGH_RFC9001_DCID_HEX)
        header = _qgh_hex("c1000000010008f067a5502a4262b50040750001")
        data = _qgh_hex("02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304")
        expected_sample = _qgh_hex("2cd0991cd25b0aac406a5816b6394100")
        expected_hdr = _qgh_hex("cf000000010008f067a5502a4262b5004075c0d9")
        expected_packet = _qgh_hex("cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee")
        _, sealer = QCN._initial_packet_keys(conn_id)
        buf = vcat(header, data, zeros(UInt8, 16))
        pn_offset = length(header) - 1
        QCN._seal_packet!(sealer, buf, 1, pn_offset, 2, length(header) + length(data), Int64(1))
        # Go's sample is sealed[2:2+16]: 4 bytes past the 2-byte packet number.
        @test buf[(length(header) + 3):(length(header) + 18)] == expected_sample
        @test buf[1:length(header)] == expected_hdr
        @test buf == expected_packet
    end

    @testset "TestInitialAEADSealsAndOpens" begin
        connection_id = UInt8[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
        client_sealer, client_opener = QCN._initial_packet_keys(connection_id)
        server_opener, server_sealer = QCN._initial_packet_keys(connection_id)
        client_message = _qgh_seal(client_sealer, Vector{UInt8}(codeunits("foobar")), 42, Vector{UInt8}(codeunits("aad")); first_byte = 0xc3)
        @test _qgh_open(server_opener, client_message; pn = 42) == codeunits("foobar")
        server_message = _qgh_seal(server_sealer, Vector{UInt8}(codeunits("raboof")), 99, Vector{UInt8}(codeunits("daa")); first_byte = 0xc3)
        @test _qgh_open(client_opener, server_message; pn = 99) == codeunits("raboof")
    end

    @testset "TestInitialAEADFailsWithDifferentConnectionIDs" begin
        client_sealer, _ = QCN._initial_packet_keys(UInt8[0, 0, 0, 0, 0, 0, 0, 1])
        server_opener, _ = QCN._initial_packet_keys(UInt8[0, 0, 0, 0, 0, 0, 0, 2])
        client_message = _qgh_seal(client_sealer, Vector{UInt8}(codeunits("foobar")), 42, Vector{UInt8}(codeunits("aad")); first_byte = 0xc3)
        @test _qgh_open(server_opener, client_message; pn = 42) === nothing
    end

    @testset "TestInitialAEADEncryptsAndDecryptsHeader" begin
        conn_id = UInt8[0xde, 0xca, 0xfb, 0xad]
        client_keys, server_keys = QCN._initial_packet_keys(conn_id)
        client_sealer = client_keys.hp
        server_opener = QCN._initial_packet_keys(conn_id)[1].hp
        server_sealer = server_keys.hp
        client_opener = QCN._initial_packet_keys(conn_id)[2].hp
        header = UInt8[0x5e, 0, 1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef]
        # Go draws a random sample; this fixed one sets mask bit 0x10 for both
        # directions, which makes the first-byte difference below deterministic.
        sample = fill(0x04, 16)
        _qgh_xor_header!(client_sealer, header, 7, sample)
        # Differs from quic-go: Go's Initial AEAD always masks 4 first-byte
        # bits (header[1] & 0xf0 == 0x5e & 0xf0); ours picks 4 or 5 bits from
        # the first byte's form bit (RFC 9001 Section 5.4.1), and 0x5e is a
        # short-header first byte, so bit 0x10 is masked too.
        @test header[1] & 0xf0 == (0x5e & 0xf0) ⊻ 0x10
        @test header[2:6] == UInt8[0, 1, 2, 3, 4]
        @test header[7:10] != UInt8[0xde, 0xad, 0xbe, 0xef]
        _qgh_xor_header!(server_opener, header, 7, sample)
        @test header[1] == 0x5e
        @test header[2:6] == UInt8[0, 1, 2, 3, 4]
        @test header[7:10] == UInt8[0xde, 0xad, 0xbe, 0xef]

        _qgh_xor_header!(server_sealer, header, 7, sample)
        @test header[1] & 0xf0 == (0x5e & 0xf0) ⊻ 0x10  # differs from quic-go, as above
        @test header[2:6] == UInt8[0, 1, 2, 3, 4]
        @test header[7:10] != UInt8[0xde, 0xad, 0xbe, 0xef]
        _qgh_xor_header!(client_opener, header, 7, sample)
        @test header[1] == 0x5e
        @test header[2:6] == UInt8[0, 1, 2, 3, 4]
        @test header[7:10] == UInt8[0xde, 0xad, 0xbe, 0xef]
    end

    # ---------------- hkdf_test.go ----------------
    @testset "TestHKDF" begin
        # Go compares hkdfExpandLabel with crypto/tls's expandLabel; these are
        # crypto/tls's outputs for the same inputs (Go 1.22, via go:linkname).
        cases = (
            ("TLS_AES_128_GCM_SHA256", TLC._TLS13_AES_128_GCM_SHA256_ID, 42,
                "78876ab584a226b7085a7b3a4cbb1ebc2f9b67d06aa224b47d293c7acec7c374cd597aa8215ee7ca01da"),
            ("TLS_AES_256_GCM_SHA384", TLC._TLS13_AES_256_GCM_SHA384_ID, 100,
                "ce1c5a4d86b23f589fc64fb241f8628b39bb9f6ebc81f25f331303aa66918f7ea640270cbd336e7af4beef3d342da5bd36753339776cd50290c592b94e4cf786968f3f7b8c5b5f680c83e2a584e3273fe5d0cd4ad1f6a46649ebee8c38b16b9736a2d6c8"),
            ("TLS_CHACHA20_POLY1305_SHA256", TLC._TLS13_CHACHA20_POLY1305_SHA256_ID, 77,
                "69af6abb19e59d00f1bd902e7867a0a6a1a261014783cf340ba46ba9a5e64c11559ed4f40739f84f1b6646cd6f692550d981c7bb59cc1b6eac7669fb013396a4897bfe3b898d4ba29bbd86d080"),
        )
        for (name, suite, len, expected) in cases
            @testset "$name" begin
                spec = TLC._tls13_cipher_spec(suite)
                expanded = TLC._tls13_expand_label(spec.hash_kind, Vector{UInt8}(codeunits("secret")), "label", Vector{UInt8}(codeunits("context")), len)
                @test expanded == hex2bytes(expected)
            end
        end
    end

    # ---------------- retry_test.go ----------------
    @testset "TestRetryIntegrityTagCalculation" begin
        conn_id = UInt8[1, 2, 3, 4]
        foo_tag = QCN._retry_integrity_tag(conn_id, codeunits("foo"))
        bar_tag = QCN._retry_integrity_tag(conn_id, codeunits("bar"))
        @test length(foo_tag) == 16 && length(bar_tag) == 16
        @test foo_tag != bar_tag
    end

    @testset "TestRetryIntegrityTagWithDifferentConnectionIDs" begin
        t1 = QCN._retry_integrity_tag(UInt8[1, 2, 3, 4], codeunits("foobar"))
        t2 = QCN._retry_integrity_tag(UInt8[4, 3, 2, 1], codeunits("foobar"))
        @test t1 != t2
    end

    @testset "TestRetryIntegrityTagWithTestVectors" begin
        data = _qgh_hex("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba")
        v = (UInt32(data[2]) << 24) | (UInt32(data[3]) << 16) | (UInt32(data[4]) << 8) | UInt32(data[5])
        @test v == 0x00000001
        conn_id = _qgh_hex(_QGH_RFC9001_DCID_HEX)
        tag = QCN._retry_integrity_tag(conn_id, data[1:(end - 16)])
        @test tag == data[(end - 15):end]
        @test QCN._valid_retry_integrity(conn_id, data)
    end

    # ---------------- updatable_aead_test.go ----------------
    @testset "TestChaChaTestVector" begin
        secret = _qgh_hex("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
        keys = QCN._PacketKeys(TLC._TLS13_CHACHA20_POLY1305_SHA256_ID, secret)
        header = _qgh_hex("4200bff4")
        plaintext = _qgh_hex("01")
        buf = vcat(header, plaintext, zeros(UInt8, 16))
        pn_offset = 2  # Go's pnOffset = 1, 0-based
        QCN._seal_packet!(keys, buf, 1, pn_offset, 3, length(header) + length(plaintext), Int64(654360564))
        @test buf[(length(header) + 1):end] == _qgh_hex("655e5cd55c41f69080575d7999c25a5bfb")
        @test buf == _qgh_hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
    end

    @testset "TestUpdatableAEADHeaderProtection" begin
        for cs in _QGH_CIPHER_SUITES
            @testset "QUIC v1/$(string(cs; base = 16))" begin
                traffic_secret1 = rand(UInt8, 16)
                client_hp = QCN._PacketKeys(cs, traffic_secret1).hp  # client write
                server_hp = QCN._PacketKeys(cs, traffic_secret1).hp  # server read
                orig = UInt8[0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef]
                last_five_bits_different = 0
                ok = true
                for _ in 1:100
                    sample = rand(UInt8, 16)
                    header = copy(orig)
                    _qgh_xor_header!(client_hp, header, 10, sample)
                    header[1] & 0x1f != 0xb5 & 0x1f && (last_five_bits_different += 1)
                    ok &= header[1] & 0xe0 == 0xb5 & 0xe0
                    ok &= header[2:9] == UInt8[1, 2, 3, 4, 5, 6, 7, 8]
                    ok &= header[10:13] != UInt8[0xde, 0xad, 0xbe, 0xef]
                    _qgh_xor_header!(server_hp, header, 10, sample)
                    ok &= header == orig
                end
                @test ok
                @test last_five_bits_different > 75
            end
        end
    end

    @testset "TestUpdatableAEADEncryptDecryptMessage" begin
        for cs in _QGH_CIPHER_SUITES
            @testset "QUIC v1/$(string(cs; base = 16))" begin
                traffic_secret2 = rand(UInt8, 16)
                server_write = QCN._PacketKeys(cs, traffic_secret2)
                client_read = QCN._PacketKeys(cs, traffic_secret2)
                encrypted = _qgh_seal(server_write, _QGH_MSG, 0x1337, _QGH_AD)
                @test _qgh_open(client_read, encrypted; pn = 0x1337) == _QGH_MSG
                @test _qgh_open(client_read, encrypted; pn = 0x1337, ad = Vector{UInt8}(codeunits("wrong ad"))) === nothing
                @test _qgh_open(client_read, encrypted; pn = 0x42) === nothing
            end
        end
    end

    @testset "TestUpdatableAEADPacketNumbers" begin
        h, server, client = _qgh_endpoints()
        space = server.spaces[_QGH_APP]
        # Go's FirstPacketNumber: the first packet number sealed; ours records
        # the first sent in the current key phase.
        first_pn = _qgh_send!(server, h.now)
        @test server.key_phase_first_sent == first_pn
        _qgh_send!(server, h.now)
        @test server.key_phase_first_sent == first_pn
        # check that decoding the packet number works as expected
        encrypted = _qgh_peer_seal(client, 0x1337)
        @test !_qgh_receive!(server, encrypted[1:(end - 1)], 0x1337, h.now)
        @test QCN._decode_packet_number(space.largest_received, UInt64(0x38), 8) == 0x38
        @test _qgh_receive!(server, encrypted, 0x1337, h.now)
        @test QCN._decode_packet_number(space.largest_received, UInt64(0x38), 8) == 0x1338
    end

    @testset "TestAEADLimitReached" begin
        h, server, client = _qgh_endpoints()
        server.invalid_packet_limit = 10
        forger = QCN._PacketKeys(client.keys.suite, rand(UInt8, 16))
        all_dropped = true
        for i in 0:8
            all_dropped &= !_qgh_receive!(server, _qgh_peer_seal(client, i; keys = forger), i, h.now)
        end
        @test all_dropped
        @test server.error === nothing
        @test !_qgh_receive!(server, _qgh_peer_seal(client, 10; keys = forger), 10, h.now)
        @test server.error !== nothing && server.error.code == QCN._AEAD_LIMIT_REACHED
    end

    @testset "TestKeyUpdates" begin
        # Go's server is the sealer here (a key chain), Go's client the opener.
        h, conn, sealer = _qgh_endpoints()
        space = conn.spaces[_QGH_APP]
        @test !sealer.phase
        encrypted0 = _qgh_peer_seal(sealer, 0x1337)
        _qgh_roll!(sealer)
        @test sealer.phase
        encrypted1 = _qgh_peer_seal(sealer, 0x1337)
        @test encrypted0[2:end] != encrypted1[2:end]
        # Opened with key phase 0, i.e. the current keys: fails.
        @test !_qgh_open!(conn, _qgh_peer_seal(sealer, 0x1337; phase = false))
        @test !conn.key_phase
        QCN._rotate_keys!(conn, space)
        @test _qgh_open!(conn, encrypted1)
    end

    @testset "TestReorderedPacketAfterKeyUpdate" begin
        h, server, client = _qgh_endpoints()
        encrypted01 = _qgh_peer_seal(client, 0x42)
        encrypted02 = _qgh_peer_seal(client, 0x43)
        @test _qgh_open!(server, encrypted01)
        _qgh_send!(server, h.now)
        _qgh_roll!(client)
        encrypted1 = _qgh_peer_seal(client, 0x44)
        @test !server.key_phase
        @test _qgh_open!(server, encrypted1)
        @test server.key_phase
        @test server.key_updates == 1  # Go: UpdatedKey(1, true)
        # now receive a reordered packet
        @test _qgh_open!(server, encrypted02)
        @test server.key_phase
    end

    @testset "TestDropsKeys3PTOsAfterKeyUpdate" begin
        h, server, client = _qgh_endpoints(; rtt_ms = 10)
        now = h.now
        pto = QCN._pto_duration(server, _QGH_APP)
        encrypted01 = _qgh_peer_seal(client, 0x42)
        encrypted02 = _qgh_peer_seal(client, 0x43)
        @test _qgh_receive!(server, encrypted01, 0x42, now)
        _qgh_send!(server, now)
        _qgh_roll!(client)
        encrypted1 = _qgh_peer_seal(client, 0x44)
        @test !server.key_phase
        @test _qgh_receive!(server, encrypted1, 0x44, now)
        @test server.key_phase
        # packet arrived too late, the key was already dropped
        @test !_qgh_receive!(server, encrypted02, 0x43, now + 3 * pto + 1)
        @test server.prev_read_keys === nothing
    end

    @testset "TestAllowsFirstKeyUpdateImmediately" begin
        h, server, client = _qgh_endpoints()
        _qgh_roll!(client)
        encrypted = _qgh_peer_seal(client, 0x1337)
        # if decryption failed, we don't expect a key phase update
        @test !_qgh_open!(server, encrypted[1:(end - 1)])
        @test !server.key_phase && server.key_updates == 0
        # the key phase is updated on first successful decryption
        @test _qgh_open!(server, encrypted)
        @test server.key_phase && server.key_updates == 1
    end

    @testset "TestRejectFrequentKeyUpdates" begin
        h, server, client = _qgh_endpoints()
        QCN._rotate_keys!(server, server.spaces[_QGH_APP])
        _qgh_roll!(client)
        @test _qgh_open!(server, _qgh_peer_seal(client, 0x42))
        _qgh_roll!(client)
        QCN._receive_datagram!(server, _qgh_peer_seal(client, 0x42), h.now)
        @test server.error !== nothing && server.error.code == QCN._KEY_UPDATE_ERROR
        @test server.error.reason == "keys updated too quickly"
        @test server.key_updates == 1
    end

    @testset "TestInitiateKeyUpdateAfterSendingMaxPackets" begin
        h, server, client = _qgh_endpoints()
        _qgh_set_key_update_intervals!(server, 5, 20)
        @test server.state == QCN._ConnState.Confirmed  # SetHandshakeConfirmed
        # first key update
        phase_ok = true
        for _ in 1:5
            phase_ok &= !server.key_phase
            _qgh_send!(server, h.now)
        end
        @test phase_ok
        # the first update is allowed without receiving an acknowledgement
        @test server.key_phase
        @test server.key_updates == 1  # Go: UpdatedKey(1, false)
        # subsequent key update
        first_phase1_pn = Int64(-1)
        phase_ok = true
        for _ in 1:40
            phase_ok &= server.key_phase
            pn = _qgh_send!(server, h.now)
            first_phase1_pn < 0 && (first_phase1_pn = pn)
        end
        @test phase_ok
        # no update allowed before receiving an acknowledgement for the current key phase
        @test server.key_phase
        @test !QCN._initiate_key_update!(server)
        # receive an ACK for a packet sent in key phase 1
        _qgh_roll!(client)
        @test _qgh_open!(server, _qgh_peer_seal(client, 1))
        old_prev = server.prev_read_keys
        _qgh_ack!(server, client, first_phase1_pn, h.now)
        @test server.error === nothing
        @test !server.key_phase
        @test server.prev_read_keys !== old_prev  # Go: DroppedKey(0) ...
        @test server.key_updates == 2             # ... then UpdatedKey(2, false)
    end

    @testset "TestKeyUpdateEnforceACKKeyPhase" begin
        h, server, client = _qgh_endpoints()
        _qgh_set_key_update_intervals!(server, 5, QCN._KEY_UPDATE_INTERVAL)
        # First make sure that we update our keys.
        pns = Int64[]
        phase_ok = true
        for _ in 1:5
            phase_ok &= !server.key_phase
            push!(pns, _qgh_send!(server, h.now))
        end
        @test phase_ok
        @test server.key_phase
        # Now that our keys are updated, send a packet using the new keys.
        next_pn = _qgh_send!(server, h.now)
        # We haven't decrypted any packet in the new key phase yet.
        # This means that the ACK must have been sent in the old key phase.
        for pn in pns
            _qgh_ack!(server, client, pn, h.now)
        end
        @test server.error === nothing
        _qgh_ack!(server, client, next_pn, h.now)
        @test server.error !== nothing && server.error.code == QCN._KEY_UPDATE_ERROR
        @test server.error.reason == "received ACK for key phase 1, but peer didn't update keys"
    end

    @testset "TestKeyUpdateAfterOpeningMaxPackets" begin
        h, server, client = _qgh_endpoints()
        _qgh_set_key_update_intervals!(server, 5, 20)
        # first key update
        pn = 0
        ok = true
        for _ in 1:5
            ok &= !server.key_phase
            ok &= _qgh_open!(server, _qgh_peer_seal(client, pn))
            pn += 1
        end
        @test ok
        # the first update is allowed without receiving an acknowledgement
        @test server.key_phase
        # subsequent key update
        _qgh_roll!(client)
        ok = true
        for _ in 1:20
            ok &= server.key_phase
            ok &= _qgh_open!(server, _qgh_peer_seal(client, pn))
            pn += 1
        end
        @test ok
        # No update allowed before receiving an acknowledgement for the current key phase
        @test server.key_phase
        @test !QCN._initiate_key_update!(server)
        sent = _qgh_send!(server, h.now)
        old_prev = server.prev_read_keys
        _qgh_ack!(server, client, sent, h.now)
        @test server.error === nothing
        @test !server.key_phase
        @test server.prev_read_keys !== old_prev  # Go: DroppedKey(0) ...
        @test server.key_updates == 2             # ... then UpdatedKey(2, false)
    end

    @testset "TestKeyUpdateKeyPhaseSkipping" begin
        h, server, client = _qgh_endpoints(; rtt_ms = 10)
        now = h.now
        @test _qgh_open!(server, _qgh_peer_seal(client, 1))
        ok = true
        for _ in 1:5
            ok &= !server.key_phase
            pn = _qgh_send!(server, now)
            _qgh_ack!(server, client, pn, now)
        end
        @test ok
        @test server.error === nothing
        # Go updates here on its own (intervals 5 and 20). Our ACK packets
        # count as received, which would make the update due a packet early,
        # so the default intervals stay and we start the update.
        @test QCN._initiate_key_update!(server)
        @test server.key_phase
        # The server never received a packet at key phase 1.
        # Make sure the key phase 0 is still there at a much later point.
        # (Go reopens packet 1; ours would ignore it as a duplicate.)
        @test _qgh_receive!(server, _qgh_peer_seal(client, 2), 2, now + 10 * QCN._pto_duration(server, _QGH_APP))
    end

    @testset "TestFastKeyUpdatesByPeer" begin
        h, server, client = _qgh_endpoints()
        _qgh_set_key_update_intervals!(server, 5, 20)
        pns = Int64[]
        ok = true
        for _ in 1:5
            ok &= !server.key_phase
            push!(pns, _qgh_send!(server, h.now))
        end
        @test ok
        @test _qgh_open!(server, _qgh_peer_seal(client, 1))
        _qgh_ack!(server, client, pns[1], h.now)
        @test server.key_phase  # Go: UpdatedKey(1, false)
        # Send and receive an acknowledgement for a packet in key phase 1.
        pn = _qgh_send!(server, h.now)
        _qgh_roll!(client)
        @test _qgh_open!(server, _qgh_peer_seal(client, 2))
        _qgh_ack!(server, client, pn, h.now)
        @test server.error === nothing
        # Now the client sends us a packet in key phase 2, forcing us to update
        # keys before the 3 PTO period is over.
        _qgh_roll!(client)
        old_prev = server.prev_read_keys
        @test _qgh_open!(server, _qgh_peer_seal(client, 3))
        @test server.prev_read_keys !== old_prev  # Go: DroppedKey(0) ...
        @test server.key_updates == 2             # ... then UpdatedKey(2, true)
        @test !server.key_phase
    end

    @testset "TestFastKeyUpdateByUs" begin
        h, server, client = _qgh_endpoints(; rtt_ms = 10)
        _qgh_set_key_update_intervals!(server, 5, 20)
        # send so many packets that we initiate the first key update
        pns = Int64[]
        ok = true
        for _ in 1:5
            ok &= !server.key_phase
            push!(pns, _qgh_send!(server, h.now))
        end
        @test ok
        @test _qgh_open!(server, _qgh_peer_seal(client, 1))
        _qgh_ack!(server, client, pns[1], h.now)
        @test server.key_phase  # Go: UpdatedKey(1, false)
        # send so many packets that we initiate the next key update
        phase1 = Int64[]
        ok = true
        for _ in 1:20
            ok &= server.key_phase
            push!(phase1, _qgh_send!(server, h.now))
        end
        @test ok
        _qgh_roll!(client)
        now = h.now
        @test _qgh_open!(server, _qgh_peer_seal(client, 2); now)
        old_prev = server.prev_read_keys
        _qgh_ack!(server, client, phase1[1], now)
        @test server.error === nothing
        @test server.prev_read_keys !== old_prev  # Go: DroppedKey(0), UpdatedKey(2, false)
        @test !server.key_phase
        # We haven't received an ACK for a packet sent in key phase 2 yet.
        # Make sure we canceled the timer to drop the previous key phase.
        @test _qgh_receive!(server, _qgh_peer_seal(client, 3), 3, now + 10 * QCN._pto_duration(server, _QGH_APP))
    end

    # ---------------- crypto_setup_test.go ----------------
    @testset "TestErrorBeforeClientHelloGeneration" begin
        err = try
            conf = TLC.Config(; server_name = "localhost", verify_peer = false, alpn_protocols = [""])
            cl = TLC.quic_client(conf)
            TLC.set_transport_parameters!(cl, _qgh_client_tp())
            TLC.start!(cl)
            ev = TLC.next_event!(cl)
            close(cl)
            ev.kind == TLC.QUICEventKind.Error ? ev.err : nothing
        catch ex
            ex
        end
        # Go refuses an empty ALPN protocol name before sending the
        # ClientHello (CRYPTO_ERROR 0x150, "tls: invalid NextProtos value");
        # ours is refused by the config check (RFC 7301 Section 3.1).
        @test err isa TLC.ConfigError
    end

    @testset "TestMessageReceivedAtWrongEncryptionLevel" begin
        _, server_conf = _qgh_tls_configs()
        server = TLC.quic_server(server_conf)
        TLC.set_transport_parameters!(server, _qgh_server_tp())
        TLC.start!(server)
        fake_ch = vcat(UInt8[1, 0, 0, 6], codeunits("foobar"))
        # wrong encryption level
        err = _qgh_feed(server, TLC.QUICEncryptionLevel.Handshake, fake_ch)
        @test err isa TLC.TLSError
        err isa TLC.TLSError && @test occursin("tls: handshake data received at wrong level", err.message)
        close(server)
    end

    @testset "TestHandshake" begin
        client_conf, server_conf = _qgh_tls_configs()
        r = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r.client_err === nothing
        @test r.server_err === nothing
        _qgh_close(r)
    end

    @testset "TestHelloRetryRequest" begin
        client_conf, server_conf = _qgh_tls_configs()
        server_conf = TLC.Config(server_conf; curve_preferences = [TLC.P384])
        r = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r.client_err === nothing
        @test r.server_err === nothing
        @test TLC.connection_state(r.client).did_hello_retry_request
        _qgh_close(r)
    end

    @testset "TestWithClientAuth" begin
        client_conf, server_conf = _qgh_tls_configs()
        client_conf = TLC.Config(client_conf; cert_file = _QCN_CERT, key_file = _QCN_KEY)
        server_conf = TLC.Config(server_conf; client_auth = TLC.ClientAuthMode.RequireAnyClientCert)
        r = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r.client_err === nothing
        @test r.server_err === nothing
        _qgh_close(r)
    end

    @testset "TestTransportParameters" begin
        client_conf, server_conf = _qgh_tls_configs()
        r = _qgh_handshake_with_conf(client_conf, server_conf;
            client_tp = _qgh_client_tp(; max_idle_timeout_ms = UInt64(42_000)),
            server_tp = _qgh_server_tp(; max_idle_timeout_ms = UInt64(1_337_000)))
        @test r.client_err === nothing
        @test r.server_err === nothing
        client_received = _qgh_received_tp(r.client_events; from_server = true)
        @test client_received isa QCN._TransportParameters
        client_received isa QCN._TransportParameters && @test client_received.max_idle_timeout_ms == 1_337_000
        server_received = _qgh_received_tp(r.server_events; from_server = false)
        @test server_received isa QCN._TransportParameters
        server_received isa QCN._TransportParameters && @test server_received.max_idle_timeout_ms == 42_000
        _qgh_close(r)
    end

    @testset "TestNewSessionTicketAtWrongEncryptionLevel" begin
        client_conf, server_conf = _qgh_tls_configs()
        r = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r.client_err === nothing
        @test r.server_err === nothing
        # inject an invalid session ticket
        b = vcat(UInt8[4, 0, 0, 6], codeunits("foobar"))
        err = _qgh_feed(r.client, TLC.QUICEncryptionLevel.Handshake, b)
        @test err isa TLC.TLSError
        err isa TLC.TLSError && @test occursin("tls: handshake data received at wrong level", err.message)
        _qgh_close(r)
    end

    @testset "TestHandlingNewSessionTicketFails" begin
        client_conf, server_conf = _qgh_tls_configs()
        r = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r.client_err === nothing
        @test r.server_err === nothing
        # inject an invalid session ticket
        b = vcat(UInt8[4, 0, 0, 6], codeunits("foobar"))
        err = _qgh_feed(r.client, TLC.QUICEncryptionLevel.Application, b)
        # Go: a TransportError whose code is a CRYPTO_ERROR. Our QUIC layer
        # reports a TLSError as CRYPTO_ERROR 0x0100 + alert_code(err).
        @test err isa TLC.TLSError
        err isa TLC.TLSError && @test 0x0100 <= QCN._CRYPTO_ERROR_BASE + TLC.alert_code(err) <= 0x01ff
        _qgh_close(r)
    end

    @testset "TestSessionResumption" begin
        client_conf, server_conf = _qgh_tls_configs()
        r1 = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r1.client_err === nothing
        @test r1.server_err === nothing
        @test r1.tickets == 1  # Go: the client session cache gets a Put
        @test !TLC.connection_state(r1.server).did_resume
        @test !TLC.connection_state(r1.client).did_resume
        r2 = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r2.client_err === nothing
        @test r2.server_err === nothing
        @test r2.tickets == 1
        @test TLC.connection_state(r2.server).did_resume
        @test TLC.connection_state(r2.client).did_resume
        # N/A: Go also restores each side's RTT from the ticket.
        _qgh_close(r1, r2)
    end

    @testset "TestSessionResumptionDisabled" begin
        client_conf, server_conf = _qgh_tls_configs()
        r1 = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r1.client_err === nothing
        @test r1.server_err === nothing
        @test r1.tickets == 1
        @test !TLC.connection_state(r1.server).did_resume
        @test !TLC.connection_state(r1.client).did_resume
        server_conf = TLC.Config(server_conf; session_tickets_disabled = true)
        r2 = _qgh_handshake_with_conf(client_conf, server_conf)
        @test r2.client_err === nothing
        @test r2.server_err === nothing
        @test r2.tickets == 0  # didn't expect to receive a session ticket
        @test !TLC.connection_state(r2.server).did_resume
        @test !TLC.connection_state(r2.client).did_resume
        _qgh_close(r1, r2)
    end
end
