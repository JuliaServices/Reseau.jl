# Epoll event loop review checklist (Reseau)

## Scope and objective
- [x] Confirm this checklist is reviewed before any code changes.
- [x] Prioritize items by severity (`P0` crash/deadlock, `P1` correctness, `P2` performance/stability, `P3` parity/style).

## 1) Epoll implementation: correctness, robustness, performance, and safety

### Correctness / robustness
- [x] `P0` Audit all code paths that acquire `event_loop.lock` in `epoll_event_loop.jl` for guaranteed unlock on exceptions (`try`/`finally`) in:
  - `schedule_task_cross_thread`
  - `event_loop_cancel_task!`
  - `process_task_pre_queue`
  - any helper called while holding the mutex.
- [x] `P1` Verify cross-thread wakeup write to eventfd/pipe is resilient to interruption:
  - retry on `EINTR`
  - retry/handle `EAGAIN` according to descriptor flags and backoff semantics.
- [x] `P1` Verify wakeup/read path drains notifications in a bounded, deterministic way and leaves descriptor in a consistent state when signals/interrupts occur.
- [x] `P1` Verify `on_tasks_to_schedule` callback ignores or safely handles non-read events and does not silently assume event type.
- [x] `P1` Validate that `destroy_event_loop` and `terminate` paths close every file descriptor exactly once and do not race with callbacks still using them.
- [x] `P1` Verify that stop/shutdown is idempotent and that repeated stop requests do not produce stale wakes or resurrect a closed loop.
- [x] `P2` Ensure callbacks in `event_loop_run!` are exception-contained per-iteration (a single bad callback cannot stop/poison the entire loop).
- [x] `P2` Confirm the queueing path used for task scheduling does not allow double-processing of a task if called from both loop thread and foreign threads concurrently.
- [x] `P2` Confirm cancellation (`event_loop_cancel_task!`) and scheduling operations remain race-free under rapid churn of same task IDs.
  - Added lock-protected `task.scheduled` checks in `schedule_task_common` (in-thread path) and `event_loop_cancel_task!` to close races against concurrent cross-thread queue transitions.
  - Added a dedicated Linux-only stress test: `Epoll cancel-schedule churn stays race-free on same task id`.
- [ ] `P2` Validate that `process_task` can handle user callbacks that mutate subscriptions during iteration without invalidating active event vectors/indices.

#### Queueing dedupe/ordering checks (epoll)
- [x] Cross-thread duplicate scheduling of an already-scheduled task is now ignored in `schedule_task_common` and `schedule_task_cross_thread` (including duplicates already present in `impl.task_pre_queue`).
- [x] `process_task_pre_queue` now skips queued tasks that are already `task.scheduled` at replay time.
- [x] Regression test added: `Epoll duplicate scheduling preserves explicit future timestamp` (Linux-only); verifies a foreign-thread duplicate `event_loop_schedule_task_now!` on a task already scheduled as future does not reschedule to immediate execution.

### Memory safety and resource lifecycle
- [ ] `P1` Verify ownership and lifetime assumptions for subscription callback/user-data payloads are explicit (especially around `cconvert`, `Ref`, and pointer casts).
- [x] `P1` Audit all `@ccall` sites for correct argument types and error translation; avoid unchecked assumptions about partial writes/reads.
  - Fixed Linux precompile/runtime failures by adding explicit `Csize_t` annotation on `write` length arguments, replacing deprecated `pointer(Ref(...))` usage with `Base.unsafe_convert(Ptr{UInt64}, Ref(...))`, and introducing a version-safe `_LIBC_EWOULDBLOCK` fallback.
- [x] `P1` Ensure all native resources (`epoll` fd, eventfd/pipe fds, any user-level handles) are released on both normal and exceptional paths.
- [ ] `P2` Check finalization behavior for loop/task objects: no reliance on finalizers for correctness during normal shutdown.

### Performance
- [ ] `P2` Confirm epoll wait buffer sizing (`events` array length) is appropriate for expected concurrency and can absorb burst loads without immediate reallocation.
- [ ] `P2` Verify task pre-queue handling avoids unnecessary allocation churn; reuse buffers where possible while preserving ownership invariants.
- [ ] `P2` Confirm wakeup batching avoids pathological wake storms when the same loop receives many cross-thread signals in quick succession.
- [ ] `P2` Validate fd registration/unregistration path does not perform avoidable work while lock is held.
- [ ] `P2` Confirm callback dispatch keeps fast path lightweight and does not allocate per-event where it can be avoided.

### Security / operational hardening
- [x] `P1` Validate FD lifecycle in `close`/`epoll_ctl` paths never operates on invalidated descriptors during teardown.
- [ ] `P1` Ensure failure modes from syscalls are surfaced and bounded (especially `epoll_wait`, `epoll_ctl`, `read`, and `write`), including when loop already stopped.
- [ ] `P2` Confirm no sensitive data is inferred from debug logs around descriptor values or callback pointers in production error paths.

## 2) Consistency check: epoll vs kqueue and iocp in Reseau

- [x] `P1` Compare callback exception handling behavior:
  - should all three backends isolate callback failures from event pump stability?
  - `aws-c-io` invokes callbacks in C without wrapper exceptions, while Julia kqueue/IOCP currently propagate callback throws and terminate their loop threads.
  - `epoll` now logs and contains callback exceptions in-loop and keeps processing for the tick; this is a deliberate divergence that should be documented or applied uniformly.
- [ ] `P1` Compare thread-start coordination pattern:
  - ensure epoll has equivalent guarantees to kqueue/iocp for single-startup completion and failure cleanup.
- [ ] `P1` Compare stop/shutdown state transitions:
  - is stopping while queue is non-empty deterministic and consistent across backends?
- [ ] `P1` Compare cross-thread wakeup policy:
  - epoll’s eventfd/pipe wake mechanics should provide the same starvation/loss guarantees as kqueue’s and iocp’s wake semantics.
- [ ] `P1` Compare unsubscribe path behavior under concurrent cancel:
  - do all backends tolerate unsubscribe while events are in-flight?
- [ ] `P2` Compare task queue invariants:
  - task IDs, pre-queue drain strategy, and post-queue scheduling order are aligned and documented similarly.
- [ ] `P2` Compare lifecycle ordering:
  - subscription teardown, queue flush, and loop thread exit order should match pattern in kqueue/iocp to simplify upstream assumptions.
- [ ] `P2` Compare diagnostics:
  - logging/error granularity and timeout/retry semantics should be similar so behavioral regressions are easier to reason about cross-platform.

## 3) Parity check: Julia epoll vs aws-c-io reference implementation

- [ ] `P1` Confirm core state-machine invariants from aws-c-io are preserved:
  - running/quit flags, thread identity checks, and task scheduling state.
- [ ] `P1` Confirm wakeup policy in epoll tracks aws-c-io intent (single wakeup when work appears, bounded notification accounting, no missed wakeups).
- [ ] `P1` Verify pre-queue design parity:
  - equivalent ordering and batching model (`tasks_to_schedule` flow, pre-queue swap, requeue behavior).
- [ ] `P1` Validate error-handling contract:
  - syscall failures and queueing failures return through consistent status paths and do not silently continue in broken states.
- [ ] `P1` Ensure resource cleanup sequence follows reference pattern (unregister + flush callbacks + close + signal completion/stop).
- [ ] `P1` Compare cancellation semantics:
  - cancel-by-id vs pointer identity behavior is consistent with reference expectations.
- [ ] `P2` Verify interoperability assumptions:
  - if external code depends on aws-c-io behavior (timing/ordering semantics), document any intentional divergences.
- [ ] `P2` Check for missed reference optimizations:
  - lock scope minimization, avoiding repeated syscalls under contention, and batching patterns.

## 4) Suggested review order before implementation

1. [x] Lock correctness (`unlock` guarantees) and callback exception containment (highest risk).
2. [ ] Wakeup/read-write robustness (`EINTR`/`EAGAIN` paths).
3. [ ] Shutdown/destruction race matrix (`stop`, `destroy`, double-stop, in-flight callbacks/subscriptions).
4. [ ] Cross-backend behavior matrix versus kqueue/iocp.
5. [ ] aws-c-io parity audit for any intentional vs accidental divergence.

## 5) Quick acceptance rubric

- [x] No deadlock path remains when user callbacks throw in any lock-held region.
- [ ] Epoll demonstrates the same or better wakeup reliability than kqueue/iocp under stress.
- [ ] Cleanup is idempotent and handles partially-initialized states safely.
- [ ] Differences from kqueue/iocp and aws-c-io are documented and intentional.
