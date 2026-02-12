# Current Trim State

## Goal

Build a fully compiled executable for a simple local TCP echo flow using only `Reseau` constructs, with:

- `@main` entrypoint
- `--experimental`
- `--trim=safe`
- `~/julia/contrib/juliac/juliac.jl`

Echo flow in `trim/echo_trim_safe.jl`:

1. Start `TCPServer` via `listenany(0)`.
2. Connect a `TCPSocket` client.
3. Client sends `"hello"`.
4. Server reads and replies `"hello"`.
5. Client verifies response.

## Compile Command

```sh
JULIA_NUM_THREADS=1 julia --startup-file=no --history-file=no \
  ~/julia/contrib/juliac/juliac.jl \
  --output-exe trim/echo_trim_safe \
  --project=. \
  --experimental --trim=safe \
  trim/echo_trim_safe.jl
```

## Result

- Runtime script check with `--experimental --trim=safe` succeeds.
- `juliac` executable compilation fails in trim verifier:
  - Max verifier index: `Verifier error #343` (343 total errors).
  - Julia 1.12.5 no longer prints the old `Trim verify finished with ...` footer in this run.
  - `Failed to compile trim/echo_trim_safe.jl`

## Main Blockers (Reseau)

1. ~~Logging dispatch is still dynamic in trim paths.~~ **EXPERIMENTAL FIXED**
- Logging now avoids vararg splatting in `logf/log!/format_line` and no longer shows trim verifier blockers.
- Current experiment also simplifies log argument rendering (`"... [N args]"`) to avoid dynamic formatting/show paths.

2. Channel pipeline uses dynamic fields in hot send paths.
- `src/sockets/io/channel.jl:96`
- `src/sockets/io/channel.jl:871`
- `src/sockets/io/channel.jl:878`
- `src/sockets/io/channel.jl:887`
- `src/sockets/io/channel.jl:892`
- `src/sockets/io/channel.jl:905`
- `src/sockets/io/channel.jl:907`
- Symptoms: unresolved `getproperty` and handler dispatch from `slot.channel::Any` and nullable handler fields.

3. Socket/bootstrap implementation fields are not concrete enough for trim-safe reachability.
- `src/sockets/io/socket.jl:242`
- `src/sockets/io/channel_bootstrap.jl:752`
- `src/sockets/io/channel_bootstrap.jl:753`
- `src/sockets/io/channel_bootstrap.jl:757`
- `src/sockets/io/apple_nw_socket_impl.jl:668`
- `src/sockets/io/apple_nw_socket_impl.jl:685`
- `src/sockets/io/apple_nw_socket_impl.jl:686`
- Symptoms: unresolved calls around `Union` impl fields and `Any` callback/TLS state.

4. TLS backend init is reached for this plain TCP example and triggers dynamic `Libdl` resolution.
- `src/Reseau.jl:38`
- `src/sockets/sockets.jl:76`
- `src/sockets/io/tls_channel_handler.jl:1496`
- `src/sockets/io/tls/secure_transport_tls_handler.jl:226`
- `src/sockets/io/tls/secure_transport_tls_handler.jl:227`

5. Assertions/debug paths still pull in dynamic formatting/writes.
- `src/common/assert.jl:2`
- Symptoms: unresolved formatting/write calls in `fatal_assert` path.

6. ~~Error callback handlers are invoked through untyped function storage.~~ **FIXED** — removed unused handler callback system and ~45 unused error constants/functions from `error.jl`.

## Fix Directions

1. Make TLS/host-resolver static init lazy so plain TCP trim builds do not traverse TLS setup.
2. Replace `Any` fields in channel/bootstrap/socket hot structs with concrete types or tighter unions.
3. Use typed callback wrappers (`TaskFn`/`EventCallable`/`ChannelCallable`) consistently instead of raw `Function`.
4. Keep trim-friendly logging fast paths (tuple-based/no vararg splats); optionally restore richer formatting with typed fast paths for common arg arities/types.
5. Reduce dynamic `Libdl` keyword-path usage in SecureTransport setup where trim-safe compilation requires concrete dispatch.
