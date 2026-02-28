# Action Items: Winsock parity and docs-alignment follow-up

## Context
- Repo: Reseau.jl
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-winsock-deep-review
- Branch: codex/winsock-deep-review-20260228

## Items

### [x] ITEM-001 (P0) Fix AcceptEx endpoint parsing and accept context update
- Description: The current AcceptEx completion path parses the accept buffer directly and does not call `SO_UPDATE_ACCEPT_CONTEXT`. This is a docs-compliance and potential correctness issue.
- Desired outcome: Accepted sockets use documented address parsing and have updated accept context before option operations.
- Affected files: `src/sockets/windows/winsock_init.jl`, `src/sockets/windows/winsock_socket.jl`
- Implementation notes:
  - Add `WSAID_GETACCEPTEXSOCKADDRS` loading in winsock init and expose getter.
  - In TCP accept completion, use `GetAcceptExSockaddrs` to obtain remote sockaddr pointer.
  - Parse endpoint from returned sockaddr pointer, not raw buffer start.
  - Call `setsockopt(SO_UPDATE_ACCEPT_CONTEXT)` on accepted socket using listener socket handle.
  - Keep behavior and state transitions aligned with existing lifecycle/error handling.
- Verification:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); include(\"test/socket_tests.jl\")'`
- Assumptions:
  - `GetAcceptExSockaddrs` pointer lookup via `SIO_GET_EXTENSION_FUNCTION_POINTER` is available on target Windows versions.
  - Existing `accept_buffer` sizing (`288`) remains valid for ipv4/ipv6 address parsing.
- Risks:
  - Incorrect pointer handling can regress accept path or trigger GC/FFI issues.
- Completion criteria:
  - Accept path compiles, tests pass, and code no longer reads endpoint from raw buffer start.
- Verification evidence:
  - 2026-02-28: command above passed (`exit code 0`), including all socket testsets.

### [ ] ITEM-002 (P0) Add Windows accept regression tests for remote endpoint correctness
- Description: There is no explicit regression asserting accepted socket endpoint correctness on Windows AcceptEx flow.
- Desired outcome: Windows test coverage validates accepted remote endpoint is populated correctly after accept.
- Affected files: `test/socket_tests.jl`
- Implementation notes:
  - Add Windows-gated TCP accept/connect test that asserts accepted socket `remote_endpoint` address/port match client side.
  - Reuse existing event loop/socket helpers and cleanup patterns.
  - Keep test deterministic and avoid timing flakiness.
- Verification:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); include(\"test/socket_tests.jl\")'`
- Assumptions:
  - Existing loopback test infrastructure can expose client local endpoint for assertions.
- Risks:
  - Port assertion may be racey if endpoint update is delayed; assertions must run after accept callback completion.
- Completion criteria:
  - New test passes and fails against intentionally broken endpoint parsing.

### [ ] ITEM-003 (P1) Close Windows test parity gaps from aws-c-io
- Description: Key Windows parity tests are missing/partial compared to aws-c-io (`event_loop_completion_events`, wrong-thread read/write behavior, interface-name behavior).
- Desired outcome: Reseau Windows tests cover these core scenarios.
- Affected files: `test/event_loop_tests.jl`, `test/socket_tests.jl`
- Implementation notes:
  - Add IOCP completion callback argument parity test in `event_loop_tests.jl` (Windows-only).
  - Add Windows wrong-thread read/write failure test for winsock path (assert `ERROR_IO_EVENT_LOOP_THREAD_ONLY`).
  - Replace Windows no-op for invalid interface test with explicit Windows expectation (`ERROR_PLATFORM_NOT_SUPPORTED` or `ERROR_IO_SOCKET_INVALID_OPTIONS` depending path).
- Verification:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); include(\"test/event_loop_tests.jl\")'`
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); include(\"test/socket_tests.jl\")'`
- Assumptions:
  - Test harness can exercise IOCP completion callback with existing pipe/socket helpers.
- Risks:
  - IOCP callback tests can be timing-sensitive; synchronization must be robust.
- Completion criteria:
  - New/updated tests are non-noop on Windows and pass consistently.

### [ ] ITEM-004 (P1) Align connect-path option behavior with aws-c-io reference
- Description: Connect-path handling differs from aws-c-io around `SO_REUSEADDR` failure behavior and option processing in UDP/local connect paths.
- Desired outcome: Behavior matches aws-c-io expectations or is explicitly aligned where feasible.
- Affected files: `src/sockets/windows/winsock_socket.jl`, `test/socket_tests.jl`
- Implementation notes:
  - Change TCP/UDP connect `SO_REUSEADDR` behavior to fail when setsockopt fails (matching aws-c-io).
  - Ensure local/udp connect success path runs option validation/application flow where applicable.
  - Add/adjust targeted tests if behavior changes are externally observable.
- Verification:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); include(\"test/socket_tests.jl\")'`
- Assumptions:
  - Option changes do not require API changes and should remain internal behavior parity improvements.
- Risks:
  - Behavior tightening may affect existing tests that assumed best-effort semantics.
- Completion criteria:
  - Connect-path option behavior is code-aligned with aws-c-io and tests pass.

### [ ] ITEM-005 (P2) Ensure Windows resolver path initializes winsock
- Description: aws-c-io Windows resolver calls winsock init before DNS resolution; Reseau resolver path currently does not explicitly do so.
- Desired outcome: Resolver behavior is robust and parity-aligned for Windows process-init sequencing.
- Affected files: `src/sockets/socket/host_resolver.jl`, `test/socket_tests.jl` (or resolver-focused tests if available)
- Implementation notes:
  - Add Windows-gated winsock init call before native resolver calls.
  - Keep non-Windows behavior unchanged.
  - Add a lightweight regression or integration assertion if practical.
- Verification:
  - `julia --project=. test/runtests.jl`
- Assumptions:
  - Calling winsock init from resolver path is safe and idempotent due existing guard.
- Risks:
  - Initialization ordering side effects if resolver is called very early.
- Completion criteria:
  - Resolver path explicitly initializes winsock on Windows and full suite remains green.

## Compaction Continuity Block

```text
* Take investigation/review findings and make a detailed, prioritized action item .md file; ensure each action item has enough detail (description, affected files, etc.) that a fresh context/engineer "taking on" the item would understand what needs to be done and where to go to get started and ideally how to verify that it's done
* Start working on the action-item list, for each item:
  * Thoroughly investigate the action item and work involved, state assumptions, do the work, including verification step
  * Work until verification succeeds (i.e. tests pass)
  * Mark the item done in the action item list
  * Commit the work involved for this action item
  * Continue with the same steps on the next action item
* When compacting, the itemizer instructions should be preserved *exactly* to ensure continuity
* The action-item document should very clearly state the repo/worktree where the work should be done
* Post-compaction, if there are unstaged edits in files relating to the current action item, you should assume they were your own edits and should continue directly w/ work without pausing to confirm
* No shortcuts or cutting corners while doing the action item work; each item should be done thoughtfully, carefully, with production-quality effort/work put into it; we're not trying to rush the work here at all and prefer quality, robustness, and thoroughness over "quick wins".
* No backwards compat or unnecessary shims should be included unless specifically requested
```
