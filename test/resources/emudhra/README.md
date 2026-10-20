# eMudhra CA compromise fixtures

Public certificates from the incident report, captured on 20 October 2026:
https://emudhra.we-have-a-problem.com/

Source snapshot: https://github.com/galadran/we-have-a-problem.com/tree/964944032736018999e09eaa2f2dc8ba1a664801

- `intermediates.pem`: the 16 PEM certificates in `impacted-intermediates.json`,
  in source order (eight compromised keys, each with two issuers).
- `spki-sha256.txt`: the corresponding published `spki_sha256` values, in the
  same order. Independently checked with Python cryptography's DER SPKI export
  and SHA-256, and against Go 1.27.3's `crypto/x509/verify.go` denylist.
- `roots.pem`: the four PEM certificates from `roots.json`.
- `*.we-have-a-problem.com.pem`: the 12 unmodified server chains from `chains/`.
  Each contains a leaf and its intermediates; the `aaa` variants use Sectigo's
  AAA Certificate Services cross-signs.

These files contain no private keys. Verification tests use the fixed instant
2026-10-20 12:00:00 UTC, within the certificates' validity windows, and do not
contact external hosts. The included roots are test inputs only, never added
to the package's default trust store.
