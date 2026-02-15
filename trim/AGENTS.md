# Trim Echo Goal

This directory tracks trim-verification progress for compiling a minimal Reseau echo executable.

## Objective

Compile and run `trim/echo_trim_safe.jl` as a native executable using `JuliaC.jl` with trim-safe mode.

The script should:

1. Start a `TCPServer` on an ephemeral local port.
2. Connect a `TCPSocket` client.
3. Send `"hello"` from client to server.
4. Echo `"hello"` back from server to client.
5. Validate the echoed payload on the client.

## Tooling

Use the official JuliaC package (`https://github.com/JuliaLang/JuliaC.jl`) instead of `~/julia/contrib/juliac/juliac.jl`.

## Recommended Compile Command

Run from repository root:

```sh
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no --project -e 'using JuliaC; JuliaC.main(ARGS)' -- \
  --output-exe echo_trim_safe \
  --project=. \
  --experimental --trim=safe \
  trim/echo_trim_safe.jl
```

To persist verifier output for analysis:

```sh
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no --project -e 'using JuliaC; JuliaC.main(ARGS)' -- \
  --output-exe echo_trim_safe \
  --project=. \
  --experimental --trim=safe \
  trim/echo_trim_safe.jl 2>&1 | tee /tmp/reseau_trim_verify_latest.log
```

## Runtime Sanity Check (script mode)

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no trim/echo_trim_safe.jl
```

## Reporting Expectations

When trim compile fails, capture:

- current total verifier errors/warnings,
- grouped root causes tied to Reseau paths,
- what was fixed this iteration,
- what remains and why it is currently blocked.
