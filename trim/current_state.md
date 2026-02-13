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

- Compile still fails under trim verifier.
- Current verifier set: `19` errors + `2` warnings.
- Latest log: `/tmp/reseau_trim_verify_latest.log`.
- Net from this pass: improved from `27` to `19` hard errors.
- Kqueue event-loop verifier cluster is no longer present in current output.

## Item-by-Item Status

1. External JLL init (`aws_c_common_jll` / `JLLWrappers` sort/unique calls, verifier #1-#6)
- Status: `PASS (for now)`
- Reason: external package init path, not in Reseau-owned code.

2. Kqueue event-loop paths (`kqueue_event_loop_thread`, `kqueue_* task callbacks`)
- Status: `RESOLVED (for now)`
- Result: no kqueue-specific verifier failures in `/tmp/reseau_trim_verify_latest.log`.

3. `_ClientChannelOnSetup` callback invocation still unresolved under trim (verifier #7)
- Status: `PASS (for now)`
- Work attempted: moved setup logic into direct callable method body on `_ClientChannelOnSetup`.
- Result: unresolved invoke remains.

4. Host resolver callback/impl path (`_dispatch_resolve_callback`, `_invoke_resolver_impl`, `impl_data::Any`, verifier #8-#9)
- Status: `PASS (for now)`
- Work attempted: explored stronger callback typing; reverted because it introduced additional unresolved `@cfunction` verifier failures.
- Result: unresolved dynamic path remains and appears structural (callback + `impl_data` representation).

5. Channel handler vtable dispatch wrappers (`handler_process_*`, `handler_shutdown`, `handler_increment_read_window`, verifier #10-#12 and #17/#19 + warnings #1/#2)
- Status: `PASS (for now)`
- Work attempted: multiple callable-wrapper rewrites; best stable state still yields unresolved `f::Any` handler field access under trim.
- Result: unresolved dynamic handler dispatch remains.

6. Socket handler trigger-read path (`_socket_handler_trigger_read`, verifier #13-#16 and #18)
- Status: `PASS (for now)`
- Work attempted: tightened return types and removed `slot.channel::Any` usage in trigger path.
- Result: unresolved invoke remains at callback callsites.

## Changes Kept From This Iteration

1. Re-ran trim verifier echo compile and refreshed `/tmp/reseau_trim_verify_latest.log`.
2. Current branch still includes EventLoopGroup constructor cleanup (`event_loop_group_new` removal, keyword constructor usage).
3. Updated kqueue handle typing to `KqueueHandleData{KqueueEventLoop}` with a concrete `handle_registry`, which removed the prior kqueue verifier cluster.

## Validation Run

Default Reseau tests were run and passed:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```
