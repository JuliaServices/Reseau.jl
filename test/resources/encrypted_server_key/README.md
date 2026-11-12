These are public test credentials, not service credentials. Both files hold
`../native_tls_server.key` encrypted with the passphrase `reseau-test-passphrase`,
so they pair with `../native_tls_server.crt`. `pkcs8.key` is a PKCS#8
`ENCRYPTED PRIVATE KEY` (PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC).
`legacy.key` is a traditional `RSA PRIVATE KEY` with `Proc-Type: 4,ENCRYPTED`
(AES-256-CBC).

Generated with OpenSSL 4.1.0 on 2026-11-11, from `test/resources`:

    openssl pkcs8 -topk8 -v2 aes-256-cbc -in native_tls_server.key -out encrypted_server_key/pkcs8.key -passout pass:reseau-test-passphrase
    openssl rsa -aes256 -traditional -in native_tls_server.key -out encrypted_server_key/legacy.key -passout pass:reseau-test-passphrase

Regenerate both files when `native_tls_server.key` changes.
