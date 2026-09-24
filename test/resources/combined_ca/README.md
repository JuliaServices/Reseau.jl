These are public test credentials, not service credentials. Two independent P-256
CA keys signed the same localhost leaf key. Both leaf certificates allow server
and client authentication. The CA private keys were discarded.

Generated with OpenSSL 3.6.4 on 2026-09-22, with 3650-day validity. Tests use the
fixed certificate verification time 2026-09-23 UTC. Transport and session clocks
are unchanged. `ca_a.crt` is a bundle; `ca_b/` is a separate directory containing
only the second CA. Keeping separate sources lets tests prove that both are used.
