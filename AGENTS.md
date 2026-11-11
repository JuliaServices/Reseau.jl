# Reseau Agent Notes

Reseau implements a native networking transport stack in Julia. The public
entrypoints are the `TCP`, `UDP`, and `TLS` modules. Keep that surface small;
internal pollers, socket operations, and resolver machinery stay internal.

## Architecture and contracts

- Implementation lives in `src/`; tests start at `test/runtests.jl`.
- Use Go's networking stack as the reference for ownership, call ordering,
  wait/unblock behavior, deadlines, and poller wakeups. A local Go checkout may
  be available at `~/golang`; the relevant source paths are `src/runtime`,
  `src/internal/poll`, `src/net`, and `src/crypto/tls`. Check the reference version
  when investigating a semantic difference.
- Use Base/stdlib `IO` behavior and Sockets signatures as public API references.
  Implement socket and name-resolution operations with native calls; keep the
  package independent of the `Sockets` stdlib internally.
- Preserve supported public contracts. Resolve lifecycle and ownership problems
  at their source instead of adding legacy API shims or wrapper layers.
- Prefer direct arguments and keywords over thin option structs. Keep hot-path
  fields concrete and avoid `Any` or unnecessary dynamic dispatch. Use `@atomic`
  fields on mutable structs instead of introducing `Threads.Atomic`.
- Support `AbstractVector{UInt8}` and views in buffer APIs where the contract
  permits. Keep comments about current behavior and the reasons behind it.

## Validation

CI in `.github/workflows/CI.yml` defines the current Julia versions, thread
counts, platform matrix, and test switches. It covers Linux, macOS, Windows,
and FreeBSD. Platform work follows the change's scope; there is no macOS-first
migration gate.

Run the package tests from the repository root:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

For a focused test file, set `RESEAU_TEST_ONLY` to an exact filename listed in
`test/runtests.jl`. Confirm the selected test actually runs. Use the CI thread
and platform configurations when changes affect scheduling or native calls.

- Exercise real transport behavior, close/wait/deadline interactions, and the
  public entrypoints affected by a change. Precompile and `--trim=safe` checks
  must reach those paths too.
- Investigate tests that stop making progress. Use bounded diagnostics to find
  the blocked operation; avoid fake waits, permanent skips, or production stubs
  that merely suppress a test or compiler failure.
- Keep platform semantics consistent. Document any Julia/compiler limitation and
  the coverage it prevents. Validate affected downstream packages when shared
  behavior changes.
- Report local results and CI results separately, including skipped checks and
  platform coverage that remains unverified.

## Scheduling, wakeups, and poller contention

Servers built on Reseau spend extra CPU, and lose some throughput, because of
how Julia wakes and schedules tasks. This was investigated repeatedly from
September to November 2026. Most of the remaining cost is in Julia's task
scheduler, not in Reseau. Fixes in Reseau are welcome, but read this section
before you change task stickiness, `pollwait!`, wakeups, the poller lock, or
deadline handling. The changes listed as rejected were measured. Propose one
again only with new evidence that addresses the failure recorded here.

### Where the cost is

- The original report is #155 by AbrJA. HttpArena's HTTP.jl server used about
  31 CPU cores at a paced 10k requests/s on Julia 1.11, CPU grew with the
  interactive thread count, and samples concentrated in `Base.poptask`.
- When a migratable task becomes ready, Julia wakes a sleeping thread. That
  thread spins on the shared queue for up to the sleep threshold (100 µs by
  default) before it sleeps again. At 10k requests/s, `multiq_deletemin`,
  `ijl_task_get_next`, and `multiq_check_empty` were 55-67% of user-space
  samples.
- Julia 1.12 and earlier woke every thread on each enqueue. julia#61826 wakes
  one thread per pool and shipped in Julia 1.13.0. On a 14-core Mac running
  HttpArena with `--threads=1,8`, paced CPU fell from 4.81 to 1.80 cores.

### Settled package-side changes

- **#155: pin a task to its thread while it waits in `pollwait!`.** Closed. A
  ready reader cannot move off a busy home thread, so data, EOF, and deadlines
  wait behind that thread's work. Code on that thread that waits for the reader
  can deadlock. `pollwait!` leaves stickiness to the caller on purpose.
- **#229: wake a parked socket waiter on its own thread.** Closed for the same
  reason. Ready I/O waited 1.05 s instead of 0.20 s behind a busy thread, and
  mixed workloads ran up to 2x slower.
- **#228: restore the caller's stickiness after a dial.** Closed in favor of
  #237.
- **#237: make resolver helper tasks migratable.** Open as a draft and held. It
  fixes a real bug: a dial with a timeout makes the calling task sticky for the
  rest of its life, because Base's `enq_work` binds a new sticky task and its
  caller to the caller's thread. On released Julia that pin hides the wake
  cost, so without it fresh-connection clients use about 9x the CPU and take
  34% longer. Merge it once a Julia release includes the wake fix from
  julia#62284.
- **#160: skip the poller lock in `arm_waiter!` when epoll or kqueue arms
  nothing.** Merged in 1.4.3. The isolated wait path got about 25-29% faster;
  end-to-end HTTP changed little. Clear, local fixes like this are welcome.
- **Split the deadline-heap lock from the readiness lock (#227).** A prototype,
  never a PR; rejected. Rearming a deadline every 20 operations gained 4% on
  separate cores and 12% oversubscribed. Rearming every operation lost 26% and
  39% and raised CPU per operation by 33% and 63%. The poller still takes the
  heap lock to choose its sleep horizon and to drain expired timers.
- **Publish the heap minimum atomically (#238, PingoLee).** Merged in November
  2026. Deadline setters update the heap under a separate `time_lock` instead of
  the poller's `state.lock`, and publish the earliest deadline in an atomic
  `time_min_ns`. The poller reads that and takes `time_lock` only when an entry
  is due, so unlike the rejected split it doesn't take the heap lock on every
  loop. The handshake is described in `src/iopoll/timers.jl`. With 8 client
  threads on 8 dedicated cores, rearming every operation ran 11% faster than
  before (5 of 6 rounds), and with no rearming it was unchanged (16 rounds).
  With 8 threads on 4 CPUs, rearming every 20 operations ran about 50% faster.

#238 avoids lost wakeups with a handshake whose four accesses must stay
`:sequentially_consistent`. A setter stores `time_min_ns`, then loads
`poll_until_ns`; the poller stores `poll_until_ns`, then reloads `time_min_ns`.
Weakening any of the four orderings can let the poller sleep past a deadline
that a setter just moved earlier.

Two other designs for #227 are untested: a single-owner update queue that the
poller drains, and lazily coalesced extensions of later deadlines, where an
early heap firing rechecks the descriptor's current deadline. Any deadline
change must keep these guarantees:

- An earlier deadline interrupts a blocking poll at once.
- A stale generation never fires.
- Closing and re-registering a descriptor never transfers a deadline.
- Concurrent setters cannot resurrect an older snapshot.
- Waiters are released when the poller fails or shuts down.
- IOCP buffer lifetimes do not change.

### Runtime direction

- julia#62284 (gbaraldi, open) is the change that matters. Its first commit
  wakes a thread only when no thread is already searching for work. On matched
  Linux builds, server CPU at 10k requests/s fell from 2.72 to 1.16 cores, and
  reused-connection client CPU fell from 399 to 55 µs per request. Its costs:
  cold bursts of tiny tasks ran about 3x slower (80 to 252 µs), 16-core peak
  throughput fell 3.6%, and fixed-load p99 rose from 220 to 298 µs. Its second
  commit parks on the scheduler task so blocked tasks can migrate. That commit
  has a scheduler-host publication race; a fix and a regression test exist but
  were not posted upstream.
- julia#62285 (work-stealing queues) speeds up Channel and yield
  microbenchmarks but gave no network throughput gain (16-core peak fell 7.4%).
  julia#63801 (yield while spinning) does not target this workload.
- Wake policies prototyped on top of julia#62284 kept a 60% CPU cut at 10k
  requests/s and recovered 16-core peak, but still lost 3.8% on
  fresh-connection HTTP throughput. None was accepted.
- Longer term, Reseau needs a supported way to integrate its event loop with
  Julia's task ownership: a public park/wake/cancel protocol for external
  waitables, based on Base's private `park.jl`, plus a batch-ready operation.
  Don't manage Julia's private task-ownership fields from Reseau. The Julia
  1.14 cancellation design is `docs/design/cancellation.md` on the
  `cancellation-design` branch.
- Known boundary race: if a notifier that owes `schedule(task)` races an
  external `schedule(task, InterruptException(); error = true)`, the finished
  task can stay queued, and Julia warns about an inconsistent workqueue.
  Reseau's own close, deadline, and cancel paths own the wake and avoid this.
  Supporting arbitrary external error scheduling needs that runtime protocol,
  not catching errors from `schedule`.

### Settings that help without code changes

- `JULIA_THREAD_SLEEP_THRESHOLD=0` cut client CPU from 399 to 31 µs per
  request, but a serial request stream got 13% (reused connections) to 30%
  (fresh connections) slower. Thresholds between 5 and 50 µs are untested.
- Julia sizes parallel GC marking from the default thread pool, so a server
  started with `--threads=1,N` marks on one thread. `--gcthreads=N,0` cut
  p99.9 latency at 10k requests/s from 25.6 ms to 0.6 ms with no CPU change.

### Measuring a scheduling or poller change

Use the original server shape: `--threads=1,N` with several interactive
workers. Measure:

- paced load, as CPU per request at a fixed rate such as 10k requests/s;
- saturated throughput;
- fresh and reused connections;
- burst latency;
- a mixed workload in which a waiter's home thread becomes busy;
- for deadline changes, rearming every 20 operations and every operation, on
  separate cores and oversubscribed.

Interleave base and candidate runs, and report the median with the minimum and
maximum over at least five runs. A flat throughput result does not disprove a
scheduler gain when the load generator, the single poller, or the kernel is
the limit. Cloud VMs can add about 130 µs to thread wakeups, so small-burst
latency measured there is noisy. Temporary pinning is a diagnostic lower bound
on scheduling overhead, never a default.

The full evidence from the October 30 2026 investigation is on the
maintainer's machine: `~/.julia/dev/network-perf-20261030/REPORT.md` with its
`research/` folder, `~/.julia/dev/network-perf-20261030-followup/REPORT.md`,
and the review summary `~/.julia/dev/network-perf-review-20261101/SUMMARY.md`.

## Checkout hygiene

Keep `Manifest.toml` out of commits. Preserve user-owned untracked files, local
probes, and working plans. Commit action-item markdown only when requested.
