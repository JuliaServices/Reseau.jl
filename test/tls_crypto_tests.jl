using Test
using Reseau
using SHA

const TLC = Reseau.TLS

_tls_hexbytes(s::AbstractString) = hex2bytes(replace(s, r"\s+" => ""))

const _TLS12_SHA256_VECTORS = (
    pre_master = _tls_hexbytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
    client_random = _tls_hexbytes("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
    server_random = _tls_hexbytes("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
    transcript = _tls_hexbytes("0100002a03037265736561752d7068617365302d636c69656e7468656c6c6f0200002a03037265736561752d7068617365302d73657276657268656c6c6f"),
    transcript_hash = _tls_hexbytes("3278142ab5de34ae832c1e75d74192fffe389d24a46e6c19abb268d3ca04973a"),
    master = _tls_hexbytes("19433de2fc69de7957e7141f16b03edcdc0c3faeaea0c7b58db62b88ef2a51f13e8c0c23079e6198becc285412c4ef6a"),
    extended_master = _tls_hexbytes("b2319bb3fd33125136dfbbf5a7b216acaab303a75c111a400bf87088cb620dbf58be8870dd934a909933b41a35b2a45b"),
    client_mac = _tls_hexbytes("1c6c915eef3b9d5019195aebedfb1914f2a0cc7f"),
    server_mac = _tls_hexbytes("217495764cf1dac3cfc46bf63c63fd2abdc8fac0"),
    client_key = _tls_hexbytes("02c163f891c6961927b58909a8de0e97"),
    server_key = _tls_hexbytes("77c620c6215d48fc193acbc57a8f5f27"),
    client_iv = _tls_hexbytes("5d9de5b67201147fc95e3fdad32f7326"),
    server_iv = _tls_hexbytes("f2ad81ff0e25485554e9c45aa52d3443"),
    ekm_context = _tls_hexbytes("7c2c806b43c09b77cfcce524addad5d8c48875bf4479a9a0b72ebda1520178e6"),
    ekm_no_context = _tls_hexbytes("18014b3b9c5ce1f59322b5093dcc4ab0880418145cf9d4b073ca335683a94dc0"),
    client_finished = _tls_hexbytes("ea20b2aeeb6acec9e14204fd"),
    server_finished = _tls_hexbytes("7da19b1590d5e9703fa15e68"),
    prf_secret = _tls_hexbytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
    prf_seed = _tls_hexbytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
    prf_out = _tls_hexbytes("773269d586ba6e526e03fa0b2113c7fdb6b995645da28e2894115d7038050ba329597b460a251c328d278304e049b4d71c7f94b7d27c6a3c6a6eb3a8c889ced1"),
)

const _TLS12_SHA384_VECTORS = (
    pre_master = _tls_hexbytes("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
    client_random = _tls_hexbytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
    server_random = _tls_hexbytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"),
    transcript = _tls_hexbytes("0100002a03037265736561752d7068617365302d636c69656e7468656c6c6f2d3338340200002a03037265736561752d7068617365302d73657276657268656c6c6f2d333834"),
    transcript_hash = _tls_hexbytes("805738bcde75793bc5e150dcd52a90ed6eec36a1d000c7c85af627308a3fda44c74d1d8b3bb7fc190e5b6d59f7707689"),
    master = _tls_hexbytes("16e84c2d66a5d448e1f9496bc8a59cbd64efcf68385143814d9db62451ddc5af31de1af1a41ac0a068dc66b436d0693f"),
    extended_master = _tls_hexbytes("69063534387095054a5cb87ffd85148971624ee574ea90ab74cb6249b755a3a86ee8acd1e5b4c992bdaf03a77f7ea993"),
    client_mac = _tls_hexbytes("1fe8fc3bf9acb56a199913a3cecae1a63b403cc223011238e37de6436614e778"),
    server_mac = _tls_hexbytes("a943bbf234871d8c6fd3fbf5000be9d130f5f0fbba96c641042c0d8bf58a22f3"),
    client_key = _tls_hexbytes("ca919d3b466fdfc252f146131ad34182d6a6cc11d590223169a118c1f3219d3b"),
    server_key = _tls_hexbytes("57716e30f03a3a3a023525f7481da528c793a077afd138356bfef0589ac04d0b"),
    client_iv = _tls_hexbytes("58aa3b2c"),
    server_iv = _tls_hexbytes("bd4a8a65"),
    ekm_context = _tls_hexbytes("0f4206b94ce044d17f5a6437a8576d6851cf6e8599d9852b2b1ae9b92e6c8ab2bad47a2dc9628350d6e8a2cce00629cf"),
    ekm_no_context = _tls_hexbytes("aee5d2ee975f29b05b3042fbc50887ae3cbbd38bef3f1271c981e3b83356b4504f8bca0be8489b0873bb9cf1dc3affa8"),
    client_finished = _tls_hexbytes("e93c2bdf0f376d7ef259fcde"),
    server_finished = _tls_hexbytes("c4ffea55ab9c19975acd8731"),
    prf_secret = _tls_hexbytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    prf_seed = _tls_hexbytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"),
    prf_out = _tls_hexbytes("c6144c8ffa135ace6442ad4e597ab7a3dfa79d41db64dc581446ec79e484f5080cbb407f2182c08e5e6287fa2e064708992686988ae00a9ac17d26d78f70f72d6e01cb46fa75fd4e76f9a8f5c428a701e7833e13787973cca28696c73ee21289"),
)

const _TLS13_ACVP_VECTORS = (
    psk = _tls_hexbytes("56288B726C73829F7A3E47B103837C8139ACF552E7530C7A710B35ED41191698"),
    dhe = _tls_hexbytes("EFFE9EC26AA29FD750DFA6A10B944D74071595B27EE88887D5E11C84590B5CC3"),
    early_secret = _tls_hexbytes("8A0617B568DEED3EFF346C6CBC373622BF597D839E084306BA6F0B1C7B9B23A3"),
    resumption_binder_key = _tls_hexbytes("3BFC101C063B1087F499B3BF78763598592A68DC3E9692A39B824D02C3DF10A2"),
    hello_client_random = _tls_hexbytes("E9137679E582BA7C1DB41CF725F86C6D09C8C05F297BAD9A65B552EAF524FDE4"),
    hello_server_random = _tls_hexbytes("23ECCFD030790748C8F8D8A656FD98D717F1B62AF3712F97211D2070B499F98A"),
    finished_client_random = _tls_hexbytes("62A62FA75563ED4FDCAA0BC16567B314871C304ACF06B0FFC3F08C1797594D43"),
    finished_server_random = _tls_hexbytes("C750EDA6696CD101B142BD79E00E6AC8C5F2C0ABC78DD64F4D991326659E9299"),
    client_early_traffic_secret = _tls_hexbytes("3272189698C3594D18F58EFA3F12B638A249515099BE7A2FA9836BABE74F0111"),
    early_exporter_master_secret = _tls_hexbytes("88E078F562CDC930219F6A5E98A1CE8C6E5F3DAC5AC516459A96F2EF8F114C66"),
    client_handshake_traffic_secret = _tls_hexbytes("B32306C3CE9932C460A1FE6C0F060593974842036B96FA45049B7352E71C2AD2"),
    server_handshake_traffic_secret = _tls_hexbytes("22787F8CA269D34BC549AC8BA19F2040938A3AA370D7CC9D60F720882B88D01B"),
    client_application_traffic_secret = _tls_hexbytes("47D7EA08397B5871154B0FE85584BCC30A87C69E84D69B56007C5B21F76493BA"),
    server_application_traffic_secret = _tls_hexbytes("EFBDB0C873C0480DA57307083839A8984BE25B9A8545E4FCA029940FE2800565"),
    exporter_master_secret = _tls_hexbytes("8A43D787EE3804EAD4A2A5B32972F9896B696295645D7222E1FD081DDD939834"),
    resumption_master_secret = _tls_hexbytes("5F4C961329C91044011ACBECB0B289282E0E3FED045CB3EA924DFFE5FE654B3D"),
)

const _TLS13_TRAFFIC_KEY_VECTORS = (
    traffic_secret = _tls_hexbytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
    key = _tls_hexbytes("3fce516009c21727d0f2e4e86ee403bc"),
    iv = _tls_hexbytes("5d313eb2671276ee13000b30"),
    next_traffic_secret = _tls_hexbytes("c5847ffa1bfea2d5c409eee45d2813181327a78a52ee6d02d8a5e10fbf0fface"),
)

const _TLS13_FINISHED_VECTORS = (
    base_key = _tls_hexbytes("1f1e1d1c1b1a19181716151413121110ffeeddccbbaa99887766554433221100"),
    transcript_digest = _tls_hexbytes("79d9037f527e9285dce75beb317784fbe5a2de625e7f309240c672e57131b793"),
    verify_data = _tls_hexbytes("6cad20a9bf4e58ea765c98ece4cdf2d4c153d12c1fe8557677ec31ba5155189b"),
    exporter_output = _tls_hexbytes("49563554eec99118ba93ac31bea69ae70afd409294820191"),
)

const _TLS13_EMPTY_PSK_EARLY_SECRET_SHA256 =
    _tls_hexbytes("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")

@testset "TLS crypto phase 0" begin
    @testset "transcript hashing matches chunked updates" begin
        chunk1 = UInt8[0x61, 0x62]
        chunk2_source = UInt8[0x00, 0x64, 0x65]
        chunk2 = @view(chunk2_source[2:3])
        chunk3 = UInt8[0x66]
        expected256 = vcat(chunk1, Vector{UInt8}(chunk2), chunk3)
        transcript = TLC._TranscriptHash(TLC._HASH_SHA256)
        TLC._transcript_update!(transcript, chunk1)
        TLC._transcript_update!(transcript, chunk2)
        TLC._transcript_update!(transcript, chunk3)
        @test TLC._transcript_digest(transcript) == SHA.sha256(expected256)
        @test TLC._transcript_buffered_bytes(transcript) == expected256
        TLC._discard_transcript_buffer!(transcript)
        @test TLC._transcript_buffered_bytes(transcript) === nothing
        @test TLC._transcript_digest(transcript) == SHA.sha256(expected256)

        expected384 = Vector{UInt8}(codeunits("foobar"))
        transcript384 = TLC._TranscriptHash(TLC._HASH_SHA384; buffer_handshake = false)
        TLC._transcript_update!(transcript384, @view(expected384[1:3]))
        TLC._transcript_update!(transcript384, @view(expected384[4:6]))
        @test TLC._transcript_digest(transcript384) == SHA.sha384(expected384)
        @test TLC._transcript_buffered_bytes(transcript384) === nothing
    end

    @testset "TLS 1.2 SHA-256 PRF and key schedule" begin
        v = _TLS12_SHA256_VECTORS
        @test TLC._tls12_prf(TLC._HASH_SHA256, v.prf_secret, "resau prf", v.prf_seed, 64) == v.prf_out
        master = TLC._tls12_master_from_pre_master_secret(TLC._HASH_SHA256, v.pre_master, v.client_random, v.server_random)
        @test master == v.master
        @test TLC._tls12_extended_master_from_pre_master_secret(TLC._HASH_SHA256, v.pre_master, v.transcript_hash) == v.extended_master
        client_mac, server_mac, client_key, server_key, client_iv, server_iv =
            TLC._tls12_keys_from_master_secret(TLC._HASH_SHA256, master, v.client_random, v.server_random, 20, 16, 16)
        @test client_mac == v.client_mac
        @test server_mac == v.server_mac
        @test client_key == v.client_key
        @test server_key == v.server_key
        @test client_iv == v.client_iv
        @test server_iv == v.server_iv
        transcript = TLC._TranscriptHash(TLC._HASH_SHA256)
        TLC._transcript_update!(transcript, @view(v.transcript[1:17]))
        TLC._transcript_update!(transcript, @view(v.transcript[18:length(v.transcript)]))
        @test TLC._transcript_digest(transcript) == v.transcript_hash
        @test TLC._tls12_client_finished_verify_data(TLC._HASH_SHA256, master, transcript) == v.client_finished
        @test TLC._tls12_server_finished_verify_data(TLC._HASH_SHA256, master, transcript) == v.server_finished
        @test TLC._tls12_export_keying_material(TLC._HASH_SHA256, master, v.client_random, v.server_random, "resau exporter", UInt8[0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74], 32) == v.ekm_context
        @test TLC._tls12_export_keying_material(TLC._HASH_SHA256, master, v.client_random, v.server_random, "resau exporter", nothing, 32) == v.ekm_no_context
        @test_throws ArgumentError TLC._tls12_export_keying_material(TLC._HASH_SHA256, master, v.client_random, v.server_random, "master secret", nothing, 16)
        @test_throws ArgumentError TLC._tls12_export_keying_material(TLC._HASH_SHA256, master, v.client_random, v.server_random, "extended master secret", nothing, 16)
        @test_throws ArgumentError TLC._tls12_export_keying_material(TLC._HASH_SHA256, master, v.client_random, v.server_random, "resau exporter", fill(UInt8(0x61), 1 << 16), 16)
    end

    @testset "TLS 1.2 SHA-384 PRF and key schedule" begin
        v = _TLS12_SHA384_VECTORS
        @test TLC._tls12_prf(TLC._HASH_SHA384, v.prf_secret, "resau prf", v.prf_seed, 96) == v.prf_out
        master = TLC._tls12_master_from_pre_master_secret(TLC._HASH_SHA384, v.pre_master, v.client_random, v.server_random)
        @test master == v.master
        @test TLC._tls12_extended_master_from_pre_master_secret(TLC._HASH_SHA384, v.pre_master, v.transcript_hash) == v.extended_master
        client_mac, server_mac, client_key, server_key, client_iv, server_iv =
            TLC._tls12_keys_from_master_secret(TLC._HASH_SHA384, master, v.client_random, v.server_random, 32, 32, 4)
        @test client_mac == v.client_mac
        @test server_mac == v.server_mac
        @test client_key == v.client_key
        @test server_key == v.server_key
        @test client_iv == v.client_iv
        @test server_iv == v.server_iv
        transcript = TLC._TranscriptHash(TLC._HASH_SHA384)
        TLC._transcript_update!(transcript, v.transcript)
        @test TLC._transcript_digest(transcript) == v.transcript_hash
        @test TLC._tls12_client_finished_verify_data(TLC._HASH_SHA384, master, transcript) == v.client_finished
        @test TLC._tls12_server_finished_verify_data(TLC._HASH_SHA384, master, transcript) == v.server_finished
        @test TLC._tls12_export_keying_material(TLC._HASH_SHA384, master, v.client_random, v.server_random, "resau exporter", codeunits("phase0-ctx!"), 48) == v.ekm_context
        @test TLC._tls12_export_keying_material(TLC._HASH_SHA384, master, v.client_random, v.server_random, "resau exporter", nothing, 48) == v.ekm_no_context
    end

    @testset "TLS 1.3 traffic keys and labels" begin
        v = _TLS13_TRAFFIC_KEY_VECTORS
        key, iv = TLC._tls13_traffic_key(TLC._TLS13_AES_128_GCM_SHA256, v.traffic_secret)
        @test key == v.key
        @test iv == v.iv
        @test TLC._tls13_next_traffic_secret(TLC._TLS13_AES_128_GCM_SHA256, v.traffic_secret) == v.next_traffic_secret
        @test_throws ArgumentError TLC._tls13_expand_label(TLC._HASH_SHA256, v.traffic_secret, repeat("a", 300), UInt8[], 16)
        @test_throws ArgumentError TLC._tls13_expand_label(TLC._HASH_SHA256, v.traffic_secret, "key", fill(UInt8(0x61), 256), 16)
    end

    @testset "TLS 1.3 ACVP secret schedule matches Go vectors" begin
        v = _TLS13_ACVP_VECTORS
        transcript = TLC._TranscriptHash(TLC._HASH_SHA256)
        early = TLC._tls13_early_secret(TLC._HASH_SHA256, v.psk)
        @test early.secret == v.early_secret
        @test TLC._tls13_resumption_binder_key(early) == v.resumption_binder_key
        TLC._transcript_update!(transcript, v.hello_client_random)
        @test TLC._tls13_client_early_traffic_secret(early, transcript) == v.client_early_traffic_secret
        early_exporter = TLC._tls13_early_exporter_master_secret(early, transcript)
        @test TLC._tls13_exporter_secret_for_test(early_exporter) == v.early_exporter_master_secret

        handshake = TLC._tls13_handshake_secret(early, v.dhe)
        TLC._transcript_update!(transcript, v.hello_server_random)
        @test TLC._tls13_client_handshake_traffic_secret(handshake, transcript) == v.client_handshake_traffic_secret
        @test TLC._tls13_server_handshake_traffic_secret(handshake, transcript) == v.server_handshake_traffic_secret

        master = TLC._tls13_master_secret(handshake)
        TLC._transcript_update!(transcript, v.finished_server_random)
        @test TLC._tls13_client_application_traffic_secret(master, transcript) == v.client_application_traffic_secret
        @test TLC._tls13_server_application_traffic_secret(master, transcript) == v.server_application_traffic_secret
        exporter = TLC._tls13_exporter_master_secret(master, transcript)
        @test TLC._tls13_exporter_secret_for_test(exporter) == v.exporter_master_secret

        TLC._transcript_update!(transcript, v.finished_client_random)
        @test TLC._tls13_resumption_master_secret(master, transcript) == v.resumption_master_secret
    end

    @testset "TLS 1.3 absent-PSK early secret follows Go semantics" begin
        @test TLC._tls13_early_secret(TLC._HASH_SHA256, nothing).secret == _TLS13_EMPTY_PSK_EARLY_SECRET_SHA256
        @test TLC._tls13_early_secret(TLC._HASH_SHA256, UInt8[]).secret != _TLS13_EMPTY_PSK_EARLY_SECRET_SHA256
    end

    @testset "TLS 1.3 finished MAC and exporter helpers" begin
        v = _TLS13_FINISHED_VECTORS
        transcript = TLC._TranscriptHash(TLC._HASH_SHA256; buffer_handshake = false)
        TLC._transcript_update!(transcript, codeunits("reseau tls13 finished transcript"))
        @test TLC._transcript_digest(transcript) == v.transcript_digest
        @test TLC._tls13_finished_verify_data(TLC._HASH_SHA256, v.base_key, transcript) == v.verify_data
        exporter = TLC._TLS13ExporterMasterSecret(TLC._HASH_SHA256, _TLS13_ACVP_VECTORS.exporter_master_secret)
        @test TLC._tls13_exporter(exporter, "resau export", codeunits("phase0-export-context"), 24) == v.exporter_output
    end

    @testset "constant-time byte comparisons" begin
        @test TLC._constant_time_equals(UInt8[0x01, 0x02, 0x03], UInt8[0x01, 0x02, 0x03])
        @test !TLC._constant_time_equals(UInt8[0x01, 0x02, 0x03], UInt8[0x01, 0x02, 0x04])
        @test !TLC._constant_time_equals(UInt8[0x01, 0x02], UInt8[0x01, 0x02, 0x03])
    end
end
