# Current Trim State

## Date

2026-02-15

## Goal

Compile `trim/echo_trim_safe.jl` as a trim-safe executable via `JuliaC.jl`.

## Commands Used

Compile + verifier capture:

```sh
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no --project -e 'using JuliaC; JuliaC.main(ARGS)' -- \
  --output-exe echo_trim_safe \
  --project=. \
  --experimental --trim=safe \
  trim/echo_trim_safe.jl 2>&1 | tee /tmp/reseau_trim_verify_latest.log
```

Runtime script sanity:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no trim/echo_trim_safe.jl
```

## Current Result

- Compile status: `FAIL` (trim verifier blocks codegen)
- Verifier totals: `16` errors, `2` warnings
- Latest verifier log: `/tmp/reseau_trim_verify_latest.log`
- Runtime script mode: `PASS`

## What Improved This Iteration

1. **Foreign-thread verifier explosion resolved**
- Change: simplified exception handling in `src/foreign_threads.jl` to avoid `showerror/show_backtrace` in thread trampolines.
- Impact: reduced verifier output from `124 errors + 2 warnings` to `16 errors + 2 warnings`.

## Remaining Verifier Buckets

1. **Socket connect impl dispatch in bootstrap attempts**
- Symptoms: unresolved invokes for `socket_connect_impl(... NWSocket ...)` and `socket_connect_impl(... PosixSocket ...)`.
- Call path: `socket_connect` -> `_initiate_socket_connect` in `src/sockets/io/channel_bootstrap.jl`.
- Status: `OPEN`.
- Notes: manual dispatch rewrite was attempted and reverted (it increased total verifier errors).

2. **Client channel setup invocation**
- Symptoms: unresolved invoke on `_setup_client_channel(...)` from `_on_socket_connect_complete(...)`.
- Call path: `src/sockets/io/channel_bootstrap.jl`.
- Status: `OPEN`.
- Notes: return typing cleanup (`::Nothing`) did not resolve the verifier invoke.

3. **Host resolver callback/impl indirection**
- Symptoms:
  - unresolved call `_dispatch_resolve_callback(...)`
  - unresolved call `_invoke_resolver_impl(..., impl_data::Any)`
- Call path: `src/sockets/io/host_resolver.jl`.
- Status: `OPEN`.
- Notes: likely requires redesign of callback/impl data typing; not a trivial local patch.

4. **Channel handler callback wrappers (`_TCPSocketHandler`)**
- Symptoms: unresolved calls for `handler_shutdown`, `handler_increment_read_window`, `handler_process_{read,write}` via `_ChannelSlot*CallWrapper`.
- Call path: `src/sockets/io/channel.jl`.
- Status: `OPEN`.
- Notes: attempted callable-ref typing refactor increased verifier set and was reverted.

5. **Socket handler read trigger callback chain**
- Symptoms: unresolved invoke of `_socket_handler_trigger_read(...)` from readable/setup callback closures and handler dispatch wrappers.
- Call path: `src/sockets/io/socket_channel_handler.jl`.
- Status: `OPEN`.
- Notes: appears coupled with channel handler dispatch/callback representation.

## Attempted But Reverted (Regressed Verifier State)

1. Typed `ChannelHandler*Callable` refactor in `src/sockets/io/channel.jl` (grew to `27 errors`).
2. Manual `socket_connect` impl branch dispatch in `src/sockets/io/socket.jl` (grew to `18 errors`).

Both were reverted in favor of the lower stable baseline (`16 errors, 2 warnings`).

## Files Changed In This Iteration

1. `src/foreign_threads.jl`
2. `src/sockets/io/channel_bootstrap.jl`
3. `trim/AGENTS.md`
4. `trim/current_state.md`

## Assessment

The easy/high-impact trim win in this pass was eliminating backtrace-rendering from foreign thread wrappers. Remaining failures are concentrated in channel-handler callback indirection and bootstrap/host-resolver generic dispatch; resolving those appears to require broader architecture changes rather than single-line fixes.
