# Trim Echo Goal

This directory validates a fully compiled executable using the official `JuliaC.jl` CLI with safe trimming.

## Objective

Compile and run a minimal echo program using only `Reseau` socket constructs (`TCPServer` + `TCPSocket`) with:

- `@main` entrypoint
- `--experimental`
- `--trim=safe`
- executable output (not just script execution)

Expected behavior of the script:

1. Start a `TCPServer` on any available local port.
2. Connect a `TCPSocket` client to that port.
3. Client sends `"hello"`.
4. Server reads `"hello"` and writes `"hello"` back.
5. Client reads response and verifies it is `"hello"`.

## Compilation Command

Run from the repository root:

```sh
trim/compile_echo_trim_safe.sh
```

The helper script:

- installs `JuliaC` in `@v1.12` if missing
- runs `julia -m JuliaC` from `trim/`
- writes verifier output to `/tmp/reseau_trim_verify_latest.log` by default

Direct equivalent command:

```sh
cd trim
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no --project=@v1.12 -m JuliaC \
  --output-exe echo_trim_safe \
  --project=.. \
  --experimental --trim=safe \
  echo_trim_safe.jl
```

## What To Report

When compilation fails, report verifier/trim blockers specifically attributable to `Reseau` code paths reached by this example.
