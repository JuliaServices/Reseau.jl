# Current Trim State

## Date

2026-02-16

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

- Compile status: `FAIL` (trim verifier still blocks codegen)
- Verifier totals: `15` errors, `2` warnings
- Previous baseline (prior snapshot): `12` errors, `2` warnings
- Delta vs prior snapshot: `+3` errors, warnings unchanged
- Latest verifier log: `/tmp/reseau_trim_verify_latest.log`
- Runtime script mode: `PASS`

## Notes For This Iteration

1. `client_bootstrap_connect!` is now positional-only and all direct call sites were migrated (no keyword call usage for this API).
2. The previous `TCPSocket -> client_bootstrap_connect!` kwcall verifier path is gone.
3. Overall verifier totals regressed, with new/remaining unresolved buckets now dominating.

## Remaining Verifier Buckets

1. **Socket connect dispatch from bootstrap path**
- Count: `1` error (`Verifier error #1`)
- Symptom: unresolved `Core.kwcall(...)` into `socket_connect(...)` in `_initiate_socket_connect`
- Call path: `src/sockets/io/channel_bootstrap.jl`

2. **Client channel setup invoke**
- Count: `1` error (`Verifier error #2`)
- Symptom: unresolved invoke of `_setup_client_channel(...)`
- Call path: `src/sockets/io/channel_bootstrap.jl`

3. **Host resolver callback/impl dispatch**
- Count: `2` errors (`#3`, `#4`)
- Symptoms: unresolved `_dispatch_resolve_callback(...)` and `_invoke_resolver_impl(...)`
- Call path: `src/sockets/io/host_resolver.jl`

4. **`_TCPSocketHandler` callable/slot dispatch**
- Count: `4` errors + `1` warning (`#5`, `#6`, `#7`, `#8`, warning `#1`)
- Symptoms: unresolved `_ChannelCallWrapper` closure invoke plus unresolved `handler_{shutdown,increment_read_window,process_write_message,process_read_message}`
- Call path: `src/task_scheduler.jl`, `src/sockets/io/channel.jl`

5. **`SocketChannelHandler` trigger-read + slot dispatch**
- Count: `7` errors + `1` warning (`#9`-`#15`, warning `#2`)
- Symptoms: unresolved `_socket_handler_trigger_read(...)` invoke chain and unresolved handler dispatch wrappers
- Call path: `src/sockets/io/socket_channel_handler.jl`, `src/sockets/io/channel.jl`

## Assessment

This positional API experiment did not improve total trim verifier counts in the latest run. The high-volume unresolved paths remain concentrated in channel-slot handler dispatch and socket-handler trigger-read callback chains.
