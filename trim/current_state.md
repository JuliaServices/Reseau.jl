# Current Trim State

## Goal

Build a fully compiled executable for a simple local TCP echo flow using only `Reseau` constructs, with:

- `@main` entrypoint
- `--experimental`
- `--trim=safe`
- official `JuliaC.jl` (`julia -m JuliaC`)

Echo flow in `trim/echo_trim_safe.jl`:

1. Start `TCPServer` via `listenany(0)`.
2. Connect a `TCPSocket` client.
3. Client sends `"hello"`.
4. Server reads and replies `"hello"`.
5. Client verifies response.

## Compile Command (Current)

Preferred:

```sh
trim/compile_echo_trim_safe.sh
```

Direct equivalent:

```sh
cd trim
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no --project=@v1.12 -m JuliaC \
  --output-exe echo_trim_safe \
  --project=.. \
  --experimental --trim=safe \
  echo_trim_safe.jl
```

## Current Result (2026-02-15)

- Compile still fails under trim verifier.
- Current verifier set: `129` errors, `0` warnings.
- Latest log: `/tmp/reseau_trim_verify_latest.log`.
- No executable emitted.

## Hard-Blocker Summary

1. Error/stacktrace display in thread entry catch paths dominates verifier output.
- Representative paths:
  - `src/foreign_threads.jl` (`Base.showerror(..., catch_backtrace())`)
  - `src/eventloops/epoll_event_loop.jl` (`Base.showerror(...)`)
- These produce a large cluster of Base stacktrace/printing verifier failures (#1 through most of the early set).

2. Channel/socket state still has dynamic `Any` access in trim-reached paths.
- Representative failures:
  - `downstream_read_handler::Any` property access (`socket_channel_handler_new!`)
  - `socket.handler::Any` and nested `stats` property access during write completion
  - resolver `impl_data::Any` callback invocation path

3. Remaining unresolved invokes across channel bootstrap and socket handler trigger paths.
- Representative failures:
  - `_setup_client_channel(...)`
  - `_socket_handler_trigger_read(...)`
  - `channel_slot_increment_read_window!(..., size::Any)`

## Validation Run Context

Local test suites currently passing with this code state:

- `Reseau` default
- `Reseau` TLS + network
- `AwsHTTP` default
- `HTTP` default
