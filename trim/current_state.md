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

## Current Result (2026-02-12)

- Compile still fails in trim verifier.
- New max verifier index: `Verifier error #349`.
- Previous recorded baseline: `#343`.
- Delta: `+6` errors.

## Refactors Completed In This Iteration

1. TLS field typing cleanup:
- Added `src/sockets/io/tls_types.jl` and introduced `AbstractTlsContext`, `AbstractTlsConnectionOptions`, and `MaybeTlsConnectionOptions`.
- Replaced `tls_connection_options::Any` fields in socket/bootstrap structs with `MaybeTlsConnectionOptions`.

2. Flattened constructor paths (without breaking existing options constructors yet):
- Added keyword constructors for:
  - `EventLoops.event_loop_new(; ...)`
  - `EventLoops.event_loop_group_new(; ...)`
  - `EventLoops.EventLoopGroup(; ...)`
  - `Sockets.ClientBootstrap(; ...)`
  - `Sockets.ServerBootstrap(; ...)`
  - `Sockets.socket_connect(socket, endpoint; ...)`
  - `Sockets.socket_bind(socket, endpoint; ...)`
- Updated internal callsites (`src/sockets/tcp.jl`) and downstream callsites (AwsHTTP/HTTP) to use direct constructor style.

3. Shared library abstraction removal:
- Removed `src/sockets/io/shared_library.jl`.
- Switched PKCS11 dynamic-loading path to direct `Libdl`/platform-handle usage in `src/sockets/io/pkcs11.jl`.
- Removed shared-library test include/file (`test/shared_library_tests.jl`).

## Main Remaining Blockers (From Verifier Output)

1. Channel path still relies on `slot.channel::Any` in hot read/write window logic.
- `src/sockets/io/channel.jl:878`
- `src/sockets/io/channel.jl:887`
- `src/sockets/io/channel.jl:950`
- `src/sockets/io/channel.jl:953`
- `src/sockets/io/channel.jl:954`
- `src/sockets/io/channel.jl:955`

2. Platform socket impl unions still trigger unresolved field conversions/setproperty.
- `src/sockets/io/posix_socket_impl.jl:1160`
- `src/sockets/io/posix_socket_impl.jl:1165`
- `src/sockets/io/apple_nw_socket_impl.jl:660`
- `src/sockets/io/apple_nw_socket_impl.jl:1752`
- `src/sockets/io/apple_nw_socket_impl.jl:1755`
- `src/sockets/io/apple_nw_socket_impl.jl:1878`

3. Host resolver still contains dynamic callback/predicate/cfunction paths.
- `src/sockets/io/host_resolver.jl:485`
- `src/sockets/io/host_resolver.jl:505`
- `src/sockets/io/host_resolver.jl:507`
- `src/sockets/io/host_resolver.jl:552`
- `src/sockets/io/host_resolver.jl:597`
- `src/sockets/io/host_resolver.jl:649`
- `src/common/condition_variable.jl:48`
- `src/common/condition_variable.jl:97`
- `src/common/clock.jl:281`
- `src/task_scheduler.jl:238`
- `src/task_scheduler.jl:250`

4. SecureTransport dynamic symbol loading still uses trim-hostile `Libdl` lazy paths.
- `src/sockets/io/tls/secure_transport_tls_handler.jl:226`
- `src/sockets/io/tls/secure_transport_tls_handler.jl:227`
- `src/sockets/io/tls_channel_handler.jl:1508`

## Targeted Next Fix Ideas

1. Channel typing:
- Remove `Any` from `ChannelSlot.channel` and related handler fields so read-window and send paths are fully concrete.

2. Socket impl representation:
- Split platform socket implementations into fully concrete wrappers (or concrete tagged unions with typed storage) so `setproperty!` does not cross unrelated impl types.

3. Host resolver trim pass:
- Replace `Function` predicates/callback storage with typed wrappers.
- Remove `collect(::AbstractVector)`/`Tuple{Any,Any}` style flows in resolver internals.
- Avoid runtime-generated `@cfunction` paths on trim-critical resolver code.

4. TLS static init gating:
- Ensure plain TCP echo path never reaches SecureTransport symbol resolution.
- Gate TLS backend init so no `Libdl` lazy lookup runs unless TLS is explicitly configured/used.
