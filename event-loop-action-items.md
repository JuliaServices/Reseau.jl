# Event Loop Action Items (Implementation Queue)

Status legend: [ ] pending, [x] done, [~] blocked/needs-more-info

## Scope
- Combined from `event-loop-review.md`, `event-loop-claude-review.md`, and code comparisons with `~/aws-c-io`.
- Files: `src/eventloops/*.jl`, `src/task_scheduler.jl`, `src/eventloops/future.jl`, and focused tests.

## P0 (Do first)
- [x] **Future wait spurious wakeups** (`src/eventloops/future.jl`)
  - Fix wait loop to recheck completion under `f.cond`-protected loop and avoid non-atomic `f.set` reads.
  - Add regression test that forces repeated `Condition.wait` wakeups without completion before final notify.
- [x] **Cross-thread lock hygiene (kqueue)** (`src/eventloops/kqueue_event_loop.jl`)
  - Wrap `event_loop_stop!`, `schedule_task_cross_thread`, `event_loop_cancel_task!`, `process_cross_thread_data`, and pending-check probe in `try/finally` lock sections.
- [x] **Cross-thread lock hygiene (epoll)** (`src/eventloops/epoll_event_loop.jl`)
  - Wrap `schedule_task_cross_thread`, `event_loop_cancel_task!`, and `process_task_pre_queue` lock sections in `try/finally`.

## P1
- [x] **kqueue cleanup on thread exit** (`src/eventloops/kqueue_event_loop.jl`)
  - Call `event_loop_thread_exit_s2n_cleanup!(event_loop)` in main loop exit path and/or destroy path.
- [x] **IOCP cleanup on thread exit** (`src/eventloops/iocp_event_loop.jl`)
  - Mirror epoll behavior by invoking `event_loop_thread_exit_s2n_cleanup!(event_loop)` in thread-exit/cleanup path.
- [x] **kqueue task pre-queue reuse** (`src/eventloops/kqueue_event_loop.jl`, `src/eventloops/kqueue_event_loop_types.jl`)
  - Reuse cross-thread task vector across wakes to avoid allocation churn.
- [x] **Epoll pre-queue/IO signal write hardening** (`src/eventloops/epoll_event_loop.jl`)
  - Add `gc_safe = true` + retry-on-`EINTR` write for cross-thread wake signal.
  - Avoid replacing `impl.task_pre_queue` with a fresh vector each drain; reuse one pool buffer.
- [x] **Kqueue connected handle counter correctness** (`src/eventloops/kqueue_event_loop.jl`)
  - Prevent `connected_handle_count` from being incremented for canceled subscribe callbacks.

## P2 (Nice-to-have hardening)
- [x] **kqueue pipe read hardening** (`src/eventloops/kqueue_event_loop.jl`)
  - Make `read` on signal pipe `gc_safe = true` and explicit EINTR-safe loop.
- [x] **Vector allocation reduction in kqueue subscribe/unsubscribe path** (`src/eventloops/kqueue_event_loop.jl`)
  - Reuse/update fixed-size changelist memory for EV_ADD/EV_DELETE operations.
- [x] **Task scheduler cancel callback policy** (`src/task_scheduler.jl`)
  - Validate that duplicate status transitions are not possible; add/adjust tests for idempotent cancellation.
- [x] **Kqueue cleanup callback guards connected-handle accounting** (`src/eventloops/kqueue_event_loop.jl`, `test/event_loop_tests.jl`)
  - Prevent `connected_handle_count` from underflowing when cleanup runs for unsubscribed/non-connected handles.
- [x] **Kqueue unsubscribe off-thread safety** (`src/eventloops/kqueue_event_loop.jl`, `test/event_loop_tests.jl`)
  - Remove hard thread-affinity throw for unsubscribing while loop is running.
  - Route non-loop-thread unsubscribe work through scheduled task callback so cleanup/kevent deletion occur on event-loop thread.
- [x] **API compatibility: 5-arg subscribe callback with user data** (`src/eventloops/event_loop.jl`, `test/event_loop_tests.jl`)
  - Restore legacy `event_loop_subscribe_to_io_events!(..., on_event, user_data)` call shape used by tests and external callers.

## Validation requirements per item
- Add or update at least one regression test in `test/*.jl` touching changed code path.
- Re-run full `Reseau` test suite and matrix only after all items are implemented.
- Re-run downstream package suites (`AwsHTTP`, `HTTP`) before commit.
