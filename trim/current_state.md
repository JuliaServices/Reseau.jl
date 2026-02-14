# Current Trim State

## Goal

Build a fully compiled executable for a simple local TCP echo flow using only `Reseau` constructs, with:

- `@main` entrypoint
- `--experimental`
- `--trim=safe`
- `JuliaC.jl` toolchain (`trim/Project.toml`)

Echo flow in `trim/echo_trim_safe.jl`:

1. Start `TCPServer` via `listenany(0)`.
2. Connect a `TCPSocket` client.
3. Client sends `"hello"`.
4. Server reads and replies `"hello"`.
5. Client verifies response.

## Compile Setup

Run from repository root:

```sh
cd trim
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate()'
```

## Compile Command

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

## Current Result (2026-02-14)

- Compile still fails under trim verifier.
- Current verifier set: `12` errors + `0` warnings.
- Latest log: `/tmp/reseau_trim_verify_latest.log`.
- Net from initial `JuliaC.jl` pass on this branch (`2026-02-14`): improved from `137` errors + `0` warnings to `12` errors + `0` warnings.

## Item-by-Item Status

1. External JLL init (`aws_c_common_jll` / `JLLWrappers` init/sort/unique paths)
- Status: `PASS (for now)`
- Result: no `JLLWrappers` or `aws_c_common_jll` verifier entries in current log.

2. Kqueue/resolver thread exception rendering path (`showerror` / `show_backtrace`)
- Status: `RESOLVED (for now)`
- Result: foreign thread catch path no longer emits the large Base error-display verifier cluster.

3. Client setup path (`_setup_client_channel`)
- Status: `UNRESOLVED`
- Result: unresolved invokes still present (`#5`, `#10`).

4. Host resolver callback/impl path (`_dispatch_resolve_callback`, `_invoke_resolver_impl`, `impl_data::Any`)
- Status: `UNRESOLVED`
- Result: unresolved calls still present (`#6`, `#7`).

5. Channel/pipeline callback-field dispatch
- Status: `PARTIALLY RESOLVED`
- Result: `write_fn`, `downstream_read_setter`, and `window_update_fn` trim errors are cleared via typed callback wrappers.
- Remaining in this area: shutdown-chain dynamic dispatch via `Vector{Any}` remains (`#1`, `#2`).

6. Socket handler trigger-read path (`_socket_handler_trigger_read`)
- Status: `UNRESOLVED`
- Result: unresolved invokes remain (`#8`, `#9`, `#11`, `#12`).

7. Socket close + logging string-format path (`socket_close`, log formatter, `AnnotatedString`)
- Status: `RESOLVED (for now)`
- Result: previous `socket_close` verifier cluster is no longer present.

8. Platform connect dispatch (`socket_connect_impl` for `NWSocket` / `PosixSocket`)
- Status: `UNRESOLVED`
- Result: unresolved invokes remain (`#3`, `#4`).

## Changes Kept From This Iteration

1. Added a dedicated `trim` tooling environment for `JuliaC.jl`:
- `trim/Project.toml`
- `trim/Manifest.toml`
2. Switched trim compile invocation to `JuliaC.main(ARGS)` in the `trim` tooling environment.
3. Simplified foreign-thread catch handling to avoid trim-hostile Base backtrace rendering paths.
4. Type-stabilized `socket_close` error handling/debug plumbing to remove boxed `Any` closures from the close path.
5. Removed trim-hostile wrapper calls in hot paths (direct positional call for `socket_pipeline_init!`, non-keyword `_socket_close_debug` calls).
6. Added typed `ObjectCallable{T}` wrappers and applied them to socket read/write dispatch and pipeline window/update setter paths.
7. Re-ran trim verifier echo compile and refreshed `/tmp/reseau_trim_verify_latest.log`.

## Validation Run

Trim compile validation run (from `trim/`) completed and failed as expected for report generation:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no \
  -e 'using JuliaC; JuliaC.main(ARGS)' -- \
  --output-exe echo_trim_safe \
  --project=.. \
  --experimental --trim=safe \
  echo_trim_safe.jl
```

Default package tests were also run and passed after these changes:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```
