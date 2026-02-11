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
  - `Trim verify finished with 372 errors, 0 warnings.`
  - `Failed to compile trim/echo_trim_safe.jl`

## Main Blockers (Reseau)

1. Logging dispatch is still dynamic in trim paths.
- `src/common/logging.jl:43`
- `src/common/logging.jl:44`
- `src/common/logging.jl:81`
- Symptoms: unresolved `log!` and vararg `_apply_iterate` logging calls.

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

5. ~~Error callback handlers are invoked through untyped function storage.~~ **FIXED** — removed unused handler callback system and ~45 unused error constants/functions from `error.jl`.

## Fix Directions

1. Make TLS/host-resolver static init lazy so plain TCP trim builds do not traverse TLS setup.
2. Replace `Any` fields in channel/bootstrap/socket hot structs with concrete types or tighter unions.
3. Use typed callback wrappers (`TaskFn`/`EventCallable`/`ChannelCallable`) consistently instead of raw `Function`.
4. Add trim-friendly logging fast paths with concrete logger/call arities.
5. Reduce dynamic `Libdl` keyword-path usage in SecureTransport setup where trim-safe compilation requires concrete dispatch.
