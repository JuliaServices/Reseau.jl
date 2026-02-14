# Trim Echo Goal

This directory is for validating a fully compiled executable using `JuliaC.jl` with safe trimming.

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

## Compilation Setup

Run from the repository root:

```sh
cd trim
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate()'
```

## Compilation Command

Run from `trim/`:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no \
  -e 'using JuliaC; JuliaC.main(ARGS)' -- \
  --output-exe echo_trim_safe \
  --project=.. \
  --experimental --trim=safe \
  echo_trim_safe.jl
```

Note: `JuliaC.jl` requires `--output-exe` to be a name (no path).

## What To Report

When compilation fails, report verifier/trim blockers specifically attributable to `Reseau` code paths reached by this example.
