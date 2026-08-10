# Native Cancellation Support in Reseau.jl — Design Proposal

Status: FINAL (v7) — jointly agreed design basis for implementation.
Produced by iterative cross-review: Claude (research + drafting) × codex gpt-5.6-sol
(six adversarial review rounds; final verdict AGREE; §13 records the history).
No code yet — implementation follows the phase order in §9.
Upstream pin: Julia master `ffa3bc8dfdd67057e4c17748ec20e1f7b8f7a275` (1.14.0-DEV,
2026-08-10). Reseau pin: `6c59a914346778ce8a4373cdbf9604ba6e9e3aed`.

---

## 1. Background

### 1.1 Julia 1.14 cancellation — merged at the pin

- `Base.CancellationTokenSource`: level-triggered cancellation scope; multi-parent
  DAG; monotonic severities `CANCEL_REQUEST_SAFE`(0x1) →
  `CANCEL_REQUEST_ABANDON_EXTERNAL`(0x3) → `CANCEL_REQUEST_ABANDON_ALL`(0x4); weak
  child links (GC detach); born-cancelled under cancelled parents.
  `Base.CancellationToken` = observe-only view; `Base.CancellationRequest(sev) <:
  Exception`; `cancel!`, `iscancelled`, `cancel_severity`, `redeliver!`; scoped
  default `Base.CANCEL_TOKEN`.
- `cancel` kwarg on the audited Base families (`wait` on
  Condition/Task/Timer/AsyncCondition/CancellationToken, `lock(::ReentrantLock)`,
  Channel ops, `sleep`, `Semaphore.acquire`, LibuvStream I/O, command I/O, Sockets,
  FileWatching). Raw `wait()`/`yield`/`yieldto` are deliberately NOT cancellation
  points (they pair with a unique `schedule`); a task parked in raw `wait()` is
  invisible to `cancel!`.
- Level-triggered semantics; shielding (`cancel=nothing` or scoped
  `CANCEL_TOKEN => nothing`) is the only mask. Entry convention: **explicit tokens
  are prechecked at API entry; the ambient default is a deferred sentinel** resolved
  only at the first potential-block point — a nonblocking success under a cancelled
  ambient scope may complete.
- `wait(tok; cancel=...)` returns the `CancellationRequest` as a value — the designed
  foreign-event-loop integration point (#62652). **No severity-floor parameter.**
- `@sync` scopes a child source (no sibling fail-fast; `Experimental.@sync` is the
  fail-fast variant). ^C = cancellation of an episode source; no more async
  `InterruptException` (downstream `catch InterruptException` idioms are obsolete).
  Compute cancellation (`@cancel_check`, reset regions); `@ccall
  cancel_handler=(fn,state)` / `reset_safe=true` for foreign calls.
- Nothing is exported or `public`-marked. Internal, off-limits: the park/waitable
  protocol, severity-floor/`cancel_value` kwargs, sentinel helpers
  (`CancelTokenArg`/`DEFAULT_CANCEL`), token→source extraction.

### 1.2 Open / conditional upstream work

#62663 (escalation ladder: 1s-grace press-to-climb ^C ladder, `freeze_task!`,
watcher-freeze exemption) and #62673 (perf-only scoped-token caching) are OPEN with
failing CI at review time. All escalation-*behavior* claims here are conditional on
#62663 as finally merged; a full-contract re-review happens at the 1.14 branch cut.

### 1.3 Reseau at the pin

Pure-Julia Go-port transport stack: one global poller thread (kqueue/epoll/IOCP) + 4
detached `getaddrinfo` worker threads. Universal park: `IOPoll.pollwait!` — raw
`Base.wait()` behind a one-word CAS (`PollWaiter.state ∈ {nothing, Task, READY,
CANCELED}`); waiters are **fd×direction-owned and serially reused across tasks and
tokens**; already exceptional-interrupt-safe (`_abort_pollwait!`). Go-sticky per-fd
deadlines (atomic words + min-heap) → `DeadlineExceededError`. Forced-synchronous
close (`evict!` + CANCELED wakes + unbounded `Base.acquire(fd.csema)` ownership
wait). Windows IOCP: completion-based; cancelled ops require `CancelIoEx` + mandatory
drain (kernel owns caller memory until terminal completion). Off-poller blocking
sites: fdlock slow path (`Threads.Condition`), DNS futures/queue/singleflight,
Happy-Eyeballs `take!`, TLS's three `ReentrantLock`s, `wait(shutdown_event)`, task
joins. A proto-token exists (`DNSRaceState` + `cancel_state` hooks). `AGENTS.md`:
Go-mirroring mandate, macOS-first phase gates.

---

## 2. Goals and non-goals

**Goals**
- **G1** Every public blocking op (TCP connect/accept, the read family incl.
  `unsafe_read`, eof, the write family incl. `unsafe_write`, TCP/TLS `closewrite`
  where it writes, TLS handshake/read/write, SOCKS, DNS, IOPoll sleep/timer family)
  is cancellable: `cancel::Union{Reseau.UseDefault, Nothing,
  Base.CancellationToken}` kwarg; Base's sentinel flow (§6.1); throws
  `CancellationRequest` with **throw-time severity** (the registration retains the
  token; `cancel_severity(tok)` re-read immediately before throwing — docs note that
  delivery-time and throw-time severity may differ under a racing escalation);
  level-triggered; `cancel=nothing` shields. Exception: APIs that can report
  progress return partial results instead of throwing (§7.3) — completion-wins at
  the logical-call level.
- **G2** *(narrowed; the narrowing is part of the public docs)* Severity is honored
  **at delivery time**: entry checks, parks, and claims observe the then-current
  severity, including initial delivery at ABANDON_*. **v1 does not provide post-SAFE
  escalation of in-progress teardown** (a task inside a shielded drain or child join
  cannot observe a later rung via public API — codex-confirmed impossibility). The
  full ladder and the Windows cancellation phase are **release-gated on upstream
  ask 1** (§11).
- **G3** Post-cancellation states are defined per op by the transition specification
  (§5–§7): multi-phase op states, published active arms, exact-arm wake tickets.
- **G4** Ungoverned ops: one branch per entry/park; no ambient lookup on nonblocking
  fast paths; benchmarked; Julia 1.10–1.13 paths allocation- and
  semantics-identical.
- **G5** ^C interrupts Reseau I/O cleanly (episode scoping; falls out of G1).
- **G6** Julia 1.10–1.13 bit-identical behavior; `@static` gates in `0_compat.jl`.
- **G7** Deadline/close/completion/cancel composition via claims; completion-wins
  wherever a successful result exists (kernel-level §6.4, logical-call-level §7.3).
- **G8** Documented-API-only; tokens never sources; **release-gated on upstream
  confirming the minimum token-API names are package-usable in 1.14** (§11 ask 3).

**Non-goals (v1)**: interruptible `getaddrinfo`; per-connection source sugar;
token-based deadlines (§8); resumable mid-record TLS reads; post-SAFE teardown
escalation (gated); **any IOCP detach** (§7.6b — drain-always at every severity;
`REAPER_OWNED` bounce-buffer designs are reserved for the gated Windows phase);
duplicate-hub-free guarantees beyond egal keying (§5.1).

---

## 3. Severity ladder — v1 contracts

| Severity | v1 contract |
|---|---|
| `SAFE` | Interrupt the governed park via exact-arm claim; completion-wins where a result exists; POSIX: local cleanup, throw. Windows: `CancelIoEx` + inline shielded drain — **honestly unbounded** (kernel-prompt in practice; no escalation escape in v1 — the gap that gates the Windows phase). Never wait on the peer. |
| `ABANDON_EXTERNAL`, initial delivery | Honored: entry/park/claim reads then-current severity; DNS futures (§7.11) and dial-race children (§7.12) are ownership-transferred to their owner/reaper; **all IOCP requests still drain** (§7.6b — v1 has no detach); peer-facing niceties skipped. |
| `ABANDON_EXTERNAL` after SAFE teardown began | **Not observable in v1** (public-API impossibility). Documented; gated on upstream ask 1. |
| `ABANDON_ALL` | #62663-conditional. Reseau's obligation is shared-state survivability (§10); frozen-task fd/fdlock leaks are the documented Base trade. **Raw-pointer freeze-safety artifact** (Windows-phase gate): prove the dynamic extent of kernel-owned caller memory contains no Base cancellation points and no Base-visible registrations, so a frozen task cannot strand kernel-owned caller memory. |

---

## 4. Phase 0 — 1.14 readiness (ships first, alone)

On 1.14 Reseau's Condition/lock/Semaphore/Channel waits become **implicitly**
ambient-cancellable while `pollwait!` stays blind — latent release-day bugs with zero
Reseau changes. Phase 0 output is a **checked-in classification artifact covering
every blocking/contended site** (inventory includes: timer parks; singleflight waits
and resolver timer joins; resolver pool/exit/service/zone-cache/future locks; TLS
identity/trust-store/session-ticket/session-cache/record/close locks; platform init
locks incl. WinSock/extension loading; poller init/registration/heap/shutdown locks)
into four classes:

1. **User wait** → made cancellation-unwind-correct now; token-plumbed in Phase 2.
2. **Short invariant lock** → shielded with an ownership/consistency proof comment.
   Sites that are *not* brief today are **refactored, not shielded**: TLS per-config
   identity init holding `state.lock` across file I/O + crypto parsing
   (`5_tls.jl:654-670,205-250`), `_SERVICE_LOCK` over services-file loads
   (`4_host_resolvers.jl:339-348`) — work moves outside the lock or behind a
   singleflight initializer; any residual unbounded shield carries an explicit proof.
3. **Mandatory memory-safety drain** (IOCP drains, close's `csema`) → shielded;
   progress source named (kernel completion).
4. **Service-loop wait** (poller body, DNS workers, shutdown event) → threads/tasks
   run under service-owned scopes from birth.

**Task-creation rule**: internal tasks (hub watchers, DNS flight owners, cache
refresh, reapers, HE supervisors) are created **from a dynamic scope whose captured
token is already `nothing`/service-owned** — under #62663 a task spawned into an
ABANDON_ALL-cancelled scope can be stopped before its body runs, so in-body
shielding is too late. All handles retained, `errormonitor`ed, shutdown-registered.

**fdlock**: the slow path gets explicit queued-waiter nodes,
`QUEUED → GRANTED | WITHDRAWN | CLOSED` (one CAS each): unlock's permit hand-off
targets a node (`QUEUED→GRANTED`); a cancelled waiter withdraws (`QUEUED→WITHDRAWN`)
and either wins (unlock passes on) or loses (it owns a `GRANTED` permit it must
consume-and-release on unwind). Transition table + invariant proof in the artifact.

Plus: 1.14-nightly CI harness (suite + cancelled-scope runs of every public op).

---

## 5. Phase 1 — delivery: token hubs

### 5.1 Hub table and lifecycle

Global `IdDict{CancellationToken, Hub}` (egal-keyed; token egality ≡ source identity,
verified at the pin; not a public contract → upstream ask 4, and the design tolerates
transient duplicate hubs — duplicate watchers over one level-triggered token share no
registrations and are harmless) behind a global **table lock**. Lock order:
**table → hub → PollState/IOCP**; `schedule`, `cancel!`, and joins are prohibited
while any of these locks are held.

Hub states (per generation; **no resurrection**):

```
STARTING → RUNNING → OBSERVED_CANCELLED → RETIRING → DEAD
STARTING | RUNNING → FAILED → RETIRING → DEAD
```

- **Creation (start-gate handoff; codex rounds 4–5). The creator is the sole owner
  of both startup transitions and runs the entire path — from `STARTING`
  publication through the final startup outcome — inside a `cancel=nothing` /
  service-owned shield** (a creator frozen or reset mid-handoff would otherwise
  strand the startup reference and linked operations):
  (1) Construct the watcher task inside the service scope **with a private start
  gate — the watcher's first action is a shielded wait on that gate; it must not
  inspect `tok` or `stop_tok`, nor touch any hub state, before the gate opens**.
  Because the gate only opens after step (4), the watcher can never act while the
  hub is `STARTING` — there is no creator-vs-watcher startup race by construction.
  (2) Under the full `table → hub → PollState` order: install the hub in `STARTING`
  with **startup outcome `PENDING`** (a published hub field), run the creator's
  complete governed-arm publication transaction (§6.2 — the creator never links
  before its wake target exists), and add one **startup reference** (a `STARTING`
  hub is never joinable at zero references).
  (3) Release all locks; `schedule` the watcher.
  (4) Re-enter table→hub and publish the startup outcome exactly once:
  — `schedule` returned a healthy task ⇒ outcome `SCHEDULED`; CAS
  `STARTING → RUNNING` (never overwriting `RETIRING` or a terminal phase);
  — `schedule` threw, or returned a task already failed (the pinned scheduler's
  `enq_work` can do this for an empty target pool) ⇒ outcome `FAILED_UNSCHEDULED`;
  CAS `STARTING → FAILED`, remove the exact table entry, and settle every operation
  linked during `STARTING` (claim + exact-arm wake with a service-failure cause).
  **In both cases the creator releases the startup reference exactly once, here.**
  It never opens the gate on the failure path and never joins an unscheduled task.
  (5) On the success path only: open the start gate outside all locks (the
  creator's own registration still holds a reference, so last-unlink cannot retire
  the hub between (4) and (5)).
  (6) After the gate opens, the watcher **re-checks hub state and proceeds only
  from `RUNNING`**; shutdown or retirement makes it exit without overwriting that
  state.
  (7) A running (post-gate) watcher that exits unexpectedly marks
  `RUNNING → FAILED` in its `finally`, removes the exact table entry, and settles
  remaining registrations before `errormonitor` reports — stranded operations are
  never silent. (`STARTING → FAILED` belongs to the creator alone; `RUNNING →
  FAILED` to the watcher alone — no transition has two possible owners.)
- **Registration**: under table→hub: a `RUNNING` hub → run the governed-arm
  publication transaction (§6.2). A **`STARTING`** hub → attach through §6.2 exactly
  as for `RUNNING` and rely on the failure-settlement path if startup fails (no
  waiting/retry). An **`OBSERVED_CANCELLED`** hub (table-resident until last unlink)
  → do not attach and do not depend on any watcher: self-claim from the
  level-triggered token and deliver locally. A `RETIRING`/`FAILED` entry is treated
  as absent → create the next generation (old/new watchers overlap briefly and
  share no registrations). In all attach cases, after unlock: **re-check
  `cancel_severity(tok)`; if cancelled, self-claim via the op-state CAS and deliver
  locally** (lock-serialized handoff: the watcher can only deliver after taking the
  same hub lock, so either it sees the registration or the registrant sees the
  cancellation).
- **Last unlink** (refcount 1→0 under table+hub): mark `RETIRING`, remove exactly
  `(token, generation, hub)` from the table if still present (both locks make this
  atomic vs registration; `FAILED` paths already removed it), release locks, then
  **consult the published startup outcome**: `SCHEDULED` ⇒ cancel the one-shot stop
  source and **join the watcher outside all locks** (the unlinker owns the join; it
  has no peer or kernel dependency and completes after the posted stop wake);
  `FAILED_UNSCHEDULED` ⇒ no stop-cancel, no join — drive `FAILED → RETIRING → DEAD`
  directly. Generation guards make stale watchers no-ops across `init!` cycles.
- **Shutdown vs `STARTING`**: shutdown records its intent under the hub lock, then
  waits **outside all locks** for the creator's shielded, lock-bounded startup
  outcome (it arrives promptly — the creator is shielded end-to-end); it then
  proceeds per the outcome: `SCHEDULED` ⇒ normal stop-cancel + join (the gate **is
  or will be opened by the creator** — outcome publishes in step (4), the gate
  opens in step (5), and only the shielded creator opens it; the watcher exits at
  its post-gate state re-check); `FAILED_UNSCHEDULED` ⇒ no join. Shutdown never
  joins an unscheduled task and never opens the gate itself. The startup-outcome
  field needs a real notification mechanism (no polling, no waiting while holding
  the hub lock) with defined publication ordering — specified in the transition
  artifact, which also carries the concrete expected-outcome matrix for the §10
  start-gate barriers.
- **Watcher loop**: `try wait(tok; cancel=stop_tok) catch ...` — catches only the
  stop-token `CancellationRequest`; everything else propagates through the `FAILED`
  settlement + `errormonitor`. On observed-token cancellation: re-enter table→hub and
  **re-check hub state** — never overwrite `RETIRING` (stop-vs-token race) — mark
  `OBSERVED_CANCELLED` (a *watcher-terminal phase*, not hub-terminal: the hub still
  retires via last-unlink), deliver (§6.3), exit. No persistent watcher for a
  cancelled token: future ops fail their entry/park recheck level-triggered; late
  registrants self-claim.

### 5.2 Tokens, not sources

Reseau carries `CancellationToken` end-to-end (positionally below the public
boundary); never extracts `.source`; only `cancel!`s sources it created (hub stop
sources; the dial-race source §7.12).

## 6. The wait/claim protocol

### 6.1 Entry checks — Base's sentinel flow

Explicit token: prechecked at public entry (after object-state validation: order is
`closing` → write/read-terminal state where applicable → explicit token). Ambient:
the sentinel flows untouched through fast paths; resolution + first check happen at
the first potential-block point. Zero-length ops run entry checks and return without
I/O; they never block, claim, or poison.

### 6.2 Governed-arm publication (one transaction)

Under table→hub→PollState, in order:
1. Inspect the waiter word. A latched READY/CANCELED token is consumed first — no
   registration is linked for a wait that won't park.
2. CAS `PollWaiter.state: nothing → ParkArm(epoch)`; publish the same arm as the
   direction's **active arm** (under `PollState.lock`); publish op state
   `ARMED(epoch)`; link the hub registration. All before releasing any lock — the
   wake target exists before any claimer can see the arm.
3. Release locks; re-check the token (§5.1); park.
4. On every exit (wake consumed, refusal, exception): clear the active arm and unlink
   the registration in an order that guarantees no hub or backend path can find the
   arm after the waiter is free; scrub pooled registrations before reuse.

Notifier rule — **all** wake paths (readiness, deadline fire, close/evict, hub
delivery, IOCP completion dispatch) go through `pollnotify!(waiter, arm, reason)`,
CASing only the exact arm (obtained from the PollState-published active arm or
captured from the backend op). Stale notifiers are no-ops. Ungoverned parks keep
today's two-reason word (zero added cost).

### 6.3 Delivery and claim semantics

Watcher delivery: snapshot under the hub lock as immutable `(arm, epoch)` tickets, in
batches (initial budget 128 wakes per lock hold; mandatory `yield()` between batches;
the continuation is hub state that retirement/shutdown cancels); per ticket: (a)
op-state CAS → `TOKEN_CLAIMED` — the **semantic claim**; (b) exact-arm wake. A lost
(a) skips (b). The wake CAS **may validly lose** to another committed wake for the
same arm (e.g. a READY already latched); that wake makes the task inspect the claimed
op state — same outcome. A wake CAS that finds `nothing` with no committed owner for
that arm is a protocol error (asserted in tests). Deterministic barriers at: arm
publication, hub link, post-link re-check, claim→wake.

### 6.4 Multi-phase operation state

Per governed attempt: compact atomic `{phase, epoch, cause}` word + **typed** result
fields (bytes/errno/accepted-fd/req) written under the direction lock with
release/acquire publication (never `::Any` in an atomic). Active arm published per
`PollState` direction so deadline fire, close/evict, IOCP completion, and hub
delivery validate the arm before claiming.

- **POSIX**: `ARMED(e) → IN_SYSCALL(e) → {result | EAGAIN}`. **Readiness is advisory
  and only wakes the exact arm.** After a wake, the task must win
  `ARMED(e) → IN_SYSCALL(e)` before issuing the syscall; a token/deadline/close cause
  that wins first prevents the syscall. A cause arriving *during* `IN_SYSCALL` is
  recorded as **pending** (nonterminal); a successful syscall then publishes its
  result and **wins** (the pending cause is observed at the next cancellation
  point); `EAGAIN` settles the pending cause (throw) or re-arms a fresh epoch.
  Non-success edges (in the transition artifact): retryable `EINTR`/`ECONNABORTED`
  settle a pending cause first, else retry; fatal errno publishes the OS error if it
  wins the transition, first-cause rule otherwise.
- **IOCP**: `SUBMITTED(e) → CANCEL_REQUESTED(e, cause)` is **nonterminal**; kernel
  terminal completion publishes typed status/bytes — success owns the result even if
  cancellation was requested; `ERROR_OPERATION_ABORTED` settles to the recorded
  cause.

**Transition specification** (checked-in, reviewed before code; §10's model tests
execute it): hub states, park arms, POSIX syscall (incl. errno edges), IOCP
submission/completion/drain, deadline, close, fdlock nodes, DNS possession, HE
result — owner, lock, memory ordering, and wake ticket per edge.

## 7. Phase 2 — per-operation contracts

("Usable" = subsequent ops as if the cancelled call never started. Sticky terminal
states use dedicated exception types carrying the cause — never a stored
`CancellationRequest` snapshot.)

1. **`TCP.connect`** (single address): claim → close the half-open socket → throw.
2. **`TCP.accept`**: linearization = ownership of a successfully accepted socket
   (POSIX: the `accept` syscall returning inside `IN_SYSCALL`; Windows: terminal
   `AcceptEx` result claim). Completion-wins: an accepted child is delivered, never
   drained-and-closed because a cancel wake arrived first. Listener usable.
3. **Read family — split by progress-reporting ability** (codex round 3):
   - *Count/result-returning* (`readbytes!` incl. `all=true`, `read(conn[, n])`,
     `readavailable`): accepted bytes are tracked across the **whole logical call**;
     cancellation after `accepted > 0` **returns the partial count/result** —
     completion-wins at the logical level; the level-triggered request throws at the
     next cancellation point. `readavailable`/single-attempt: a successful count
     wins; throw only with no result.
   - *Exact, non-reporting* (`unsafe_read`, `read!`): cancellation with
     `accepted == 0` → usable + throw. Cancellation
     after `accepted > 0` → **read direction terminal** (sticky
     `ReadPoisonedError(cause)`-class state mirroring §7.6; docs state a prefix of
     the caller buffer may have changed and the stream position advanced), then
     throw the current `CancellationRequest`. (Direct-into-caller-buffer design
     rules out Base's buffer-then-copy fallback.)
   - `read(conn, UInt8)` is a one-byte result: a successful byte wins; cancellation
     can win only before the byte result exists.
   - POSIX single attempt consumed nothing ⇒ between-attempt cancellation with
     `accepted == 0` is always clean.
4. **Read (Windows)**: via `CANCEL_REQUESTED` nonterminal — drain-revealed success is
   delivered (or counted into the logical-call progress per (3)); only
   ABORTED-with-no-result reports pure cancellation.
5. **`eof`/`_peek_eof`**: pure wait; usable after cancellation.
6. **Write family**: op state tracks accepted bytes.
   *Claim order* during the op: §6.4 (completion beats pending causes; first cause
   wins the arm). *Later-call entry precedence*: `closing` > poison > token >
   deadline. *Cause-uniform poison rule*: any abort leaving `0 < accepted <
   requested` — cancellation, deadline, or OS error — sets the sticky write-terminal
   field (under the write lock) recording the cause; the initiating call throws its
   own cause; later writes throw `WritePoisonedError(cause)`. Zero-length: entry
   checks only; never poisons. `flush` no-op. TCP `closewrite` after poison:
   permitted, non-writing (`shutdown(SHUT_WR)`). Explicit all-or-throw divergence
   from Go's `(n, err)`, documented.
6b. **Windows buffer/detach rule**: **no IOCP operation detaches in v1** — SAFE and
   both ABANDON severities drain every IOCP request (caller-visible memory: raw
   pointers and caller arrays, which the public Vector paths reach via raw pointers;
   plus private `ConnectEx`/`AcceptEx` storage — uniformly drained). Initial-ABANDON
   ownership transfer applies only to DNS futures and HE tasks. `REAPER_OWNED`
   states (private bounce buffers for writes; private targets + reaper-held results
   for reads; late-accept disposal) are sketched for the gated Windows phase only.
7. **TLS handshake**: cancellation ⇒ terminal. Close transport (no close_notify —
   never wait on the peer during cancellation); sticky dedicated state
   (`TLSHandshakeCancelledError`; the `handshake_error` union is widened — never a
   stored `CancellationRequest`); initiating call rethrows the request. The
   **API-matrix-driven pass-through audit** adds explicit `CancellationRequest`
   rethrow branches before every broad TLS catch — handshake/read/write wrappers AND
   `_peek_eof` (`5_tls.jl:1894-1922`), `eof`, `closewrite`.
8. **TLS read — complete matrix (codex round 4)**:
   - Cancellation before any byte of the next wire record is consumed, no plaintext
     accepted by this public call: throw; connection usable.
   - Cancellation **between records** after a count/result API accepted plaintext:
     return the partial count/result; the level-triggered request throws at the next
     cancellation point.
   - Cancellation **between records** after an exact non-reporting API accepted
     plaintext: read direction terminal (§7.3), then throw the current request.
   - Cancellation after **any byte of the current wire record** was consumed — for
     **every public read shape, including count-returning calls**: the TLS
     connection is terminal; close the underlying TCP transport (no close_notify);
     throw the current request. **No partial result is returned even if earlier
     records supplied plaintext in the same call** (framing state is call-local; a
     partial return would leave the next call mid-record).
   Later calls throw the stable TLS/read-terminal error; the initiating call always
   throws the fresh `CancellationRequest`. The count-returning mid-record cells join
   the API matrix and the TLS byte-injection suite.
9. **TLS write**: partial record ⇒ write side poisoned (existing
   `write_permanent_error` machinery; sequence numbers advance only
   post-transport-write, verified). **TLS `closewrite` is in the cancellable matrix**
   (it writes a record; takes `cancel`); mid-close_notify cancellation poisons.
   After poison (any writer): `closewrite` **throws `TLSError` wrapping the poison
   cause** — single behavior; never emits close_notify on a desynced stream; docs
   show the transport-level half-close recipe. `close` emits nothing after poison.
10. **SOCKS dial**: cancellation anywhere in the handshake closes the conn, throws.
11. **DNS**: possession states `PENDING → READY(ptr) → {TAKEN, ABANDONED}`,
    `PENDING → ABANDONED` (one CAS each; release-publication of the pointer,
    acquire-observation by the winner). Worker publishes `READY` retaining
    ownership; a caller claims `READY→TAKEN`, then parses + frees in `finally`;
    cancellation — performed by the caller/supervisor cleanup path **outside
    hub/table locks** — claims `PENDING→ABANDONED` (worker frees later) or
    `READY→ABANDONED` (canceller frees before throwing); a worker finishing after
    `ABANDONED` frees its own result. Free-ownership rule: **after `TAKEN`, only
    that caller's `finally` frees; before `TAKEN`, the `ABANDONED` winner or the
    late worker owns the one required free.**
    Queue acceptance and flight shutdown settle exactly one owner. **Singleflight
    redesign**: the lookup runs in a shielded flight-owned task dealing only in
    copied Julia values (native ownership settled below it); followers hold
    refcounted individually-cancellable waits; a cancelled follower leaves; the
    flight publishes to the remainder or reaps.
12. **Happy-Eyeballs / parallel dial — all-exit ownership**: race result
    `OPEN → {WON(conn), FAILED, CANCELLED}` (single CAS; one owner per connection; a
    racer whose publish loses closes its own conn). The race source is a
    Reseau-created child of the caller's token (replaces the past-deadline
    `DNSRaceState` hack; the duck-typed `cancel_state` hooks remain the seam).
    Racers are created under the race token at birth; handles + fallback timer
    retained. The parent settles children on **every** exit — success,
    all-addresses-failed, timeout, synchronous setup failure, caller cancellation,
    global shutdown. On caller cancellation at SAFE: mark done, `cancel!` the race
    source, close any late winning connection, stop the timer, join children with
    `cancel=nothing` — **may be unbounded under the child drain contract**
    (consistent with §3); initial-ABANDON delivery transfers handles to the reaper
    instead of joining; post-SAFE escalation of the join is gated (G2). Same
    protocol for `_resolve_with_deadline`'s resolver + timer tasks. Cache refresh
    runs under a service-owned scope (Phase 0).
13. **`close`, `IOPoll.shutdown!`**: not cancellable (class 3/4 shields). Close
    blocks until in-flight ownership release — honestly unbounded in the
    wedged-kernel case (same upstream remedy).
14. **Timers / `IOPoll.sleep*` / `timedwait`**: plain cancellable parks.
15. **fdlock acquisition**: cancellable user wait via the §4 node protocol; the
    resolved token reaches it (and TLS lock acquisitions, DNS future waits, HE
    `take!`, queue `put!`) through Base's own `cancel` kwargs — **explicit tokens
    govern the whole op, not just poller parks** (blocking-site table is the
    checklist).

## 8. Deadlines vs. cancellation

Orthogonal and both first-class: deadlines are per-fd sticky Go-semantics I/O policy
(`DeadlineExceededError`, retryable); cancellation is scope policy
(`CancellationRequest`, level-triggered). Composition is by claims (§6.4), **not**
priority-by-wording: readiness is advisory; only successful syscall/terminal-IOCP
results dominate causes; among causes, first claim wins the arm; later-call entry
precedence is `closing` > poison > token > deadline. We do not reimplement deadlines
as timer-cancelled sources (allocation per op; sticky-per-fd vs level-per-scope
semantics differ). Scope timeouts compose in user code (sleep + `cancel!`) or a
future Base helper.

## 9. Phase ordering & compatibility

- macOS-first per `AGENTS.md`: Phase 0 → hub + TCP (kqueue) → TLS/SOCKS/DNS → epoll →
  **Windows cancellation phase (gated)** → docs (severity table, §7 contracts, the
  G2 narrowing, InterruptException obsolescence, poison/terminal state recipes).
- Julia < 1.14: kwargs accepted (`nothing`/default only); bridge compiles away;
  bit-identical, allocation-identical (benchmarked).
- Cancellation feature floor: Julia 1.14.0.

## 10. Verification

- **Transition-spec model tests** + **deterministic interleaving tests** (test-only
  barriers at every claim point). Named permanent regressions: stale-watcher-vs-
  re-arm; IOCP-terminal-before-wake; unlock-vs-withdrawal; last-unlink-vs-
  watcher-start (expected result defined by the §5.1 start-gate handoff);
  retire-vs-register generation; stop-vs-token watcher race; arm-publication vs
  claim (§6.2/6.3 barriers); **schedule-return-vs-watcher-entry,
  watcher-entry-vs-RUNNING, registration-vs-STARTING, and shutdown-vs-STARTING**
  (§5.1 start-gate barriers) — each with expected state / startup-reference / gate /
  join outcomes for: thrown scheduling failure, returned-already-failed task,
  post-gate watcher failure (creator owns `STARTING→*`, watcher owns `RUNNING→
  FAILED` — no two-owner transitions), and shutdown arriving both before and after
  successful scheduling.
- **Public API matrix** (deliverable): every public family × {explicit, ambient,
  shielded} × {zero-length, pre-cancelled, mid-op, partial-progress} — entry
  precedence, partial-result behavior, and post-state asserted per cell;
  broad-catch pass-through audit generated from it.
- **Fault injection below the API**: after every accepted TCP chunk, **after every
  completed logical-read chunk** (round-3 addition), every TLS header/payload byte,
  around each IOCP packet, at every DNS possession CAS, at every HE publish.
- **Shutdown order**: stop new registrations → claim shutdown cause on every
  published active arm (exact-arm) → wakes → delivery ownership settles → cancel
  stop sources, join watchers → destroy waiter/backend state. Lock-order
  prohibitions enforced; generation guards across `init!`; shutdown-vs-X
  deterministic tests.
- **Storm/fairness**: 10⁴ sources × 1 waiter and 1 source × 10⁵ waiters; batch
  budget/yield verified; cancel→observe p50/p99; poller/timer latency impact;
  allocations; G4 flat-line; churn/leak baselines (hubs, tasks, fds, native
  buffers, `addrinfo`).
- **ABANDON_ALL survivability** (#62663-gated): freeze at each cancellation point;
  poller/hub/timer/fdlock consistency.
- **Downstream validation**: HTTP.jl-shaped suite — pooled TCP/TLS, cancel during
  body read/write (incl. partial-progress reads), server accept, DNS/HE, reuse
  after usable-cancellation, poison eviction from pools, `@sync`, episode ^C;
  `--trim=safe` + precompile over real public paths.
- **Resource/overload policy**: hub/watcher/reaper caps, batch backlog limits,
  documented wedge states (native DNS, kernel completion) + operator guidance.

## 11. Upstream asks

Five things we need (or would love) from Julia itself. Written so each one can be
lifted directly into a conversation or a GitHub issue. None of them blocks *starting*
the work — Phase 0 and the macOS SAFE implementation have no upstream dependency —
but ask 1 and ask 3 gate specific releases, marked below.

### Ask 1 — A way to wait for cancellation to get *worse*. (Blocks: the full ^C
escalation story, and Windows support. Our most important ask.)

**The problem in one sentence:** once a token is cancelled, there is no public way
to find out that it later got *more* cancelled.

The longer version. Cancellation has three levels: SAFE ("please stop, clean up
nicely"), ABANDON_EXTERNAL ("stop waiting on the network, just tear down locally"),
and ABANDON_ALL ("give up entirely"). Repeated ^C escalates through them — that's
the whole point of the ladder. Now picture the case it exists for: a user ^C's a
big download on Windows. We observe SAFE, cancel the in-flight kernel read
(`CancelIoEx`), and then we *must* wait for the kernel to confirm before the read
buffer is safe to touch again — usually instant, but a wedged NIC driver can hang
that wait forever. The user, staring at a frozen terminal, hits ^C again. That
second press escalates the token to ABANDON_EXTERNAL… and **we never find out**.
`wait(tok)` returns immediately once the token is cancelled at all (it's
level-triggered), so there is nothing we can park on that means "wake me only when
the severity goes above SAFE." Our cleanup wait is deaf to the very keystroke that
was supposed to break it loose.

Base has this internally and uses it for exactly this situation: its own teardown
waits take a `min_severity` floor ("only wake me for severity ≥ X" — see
`wait(c::GenericCondition, tok; min_severity=...)` and `WatcherWait(src, floor)`,
and the libuv write-cancellation teardown that re-parks at `delivered + 1`). None
of it is public.

**What would work for us** (any one of these):
- `wait(tok; min_severity=...)` — the smallest possible change: the existing public
  watcher wait, with the floor the internal machinery already has;
- a floor argument on the callback hook from ask 2, if that's the direction instead.

**Until this exists** we ship an honest but weaker contract: severity is honored at
the moment cancellation is *first* delivered, but a second ^C cannot accelerate an
in-progress cleanup. We've documented that limitation and put our Windows phase and
any "full escalation ladder" claim behind this ask.

### Ask 2 — A cancellation callback: "run this function when the token cancels."
(Doesn't block anything; deletes our riskiest code and helps every event-loop
library after us.)

Reseau has its own event loop and its own park primitive — a raw `wait()` +
`schedule()` pair, which Base deliberately does not make a cancellation point. So
to learn that a token governing one of our blocked operations got cancelled, the
only public tool is: spawn a whole Julia Task per token, have it sit in
`wait(tok)`, and have it poke our event loop when that returns. We've designed
that machinery (the "watcher/hub" system in §5) and it works — but it's a few
hundred lines of genuinely tricky lifecycle code (watcher startup/failure/join
protocols, generation-guarded retirement, a stop-token per hub) that exists *only*
because the primitive is missing. .NET solves this with one method:
`CancellationToken.Register(callback)`.

**What would work for us:**
- `register_cancel_callback(tok, f) -> handle` / `unregister!(handle)`, where `f`
  gets called once per severity level with a defined execution context (a service
  task is fine; we don't need signal-handler semantics — we just write one byte to
  our wakeup pipe); or
- publicly blessing a minimal slice of the internal waitable protocol, if that's
  preferred.

If this lands, our entire hub subsystem collapses to a ~20-line adapter, and the
next library in our position (database drivers, alternative I/O stacks) won't have
to rebuild it. We've kept all Base-cancellation-touching code in one module
(`IOPoll.Cancel`) precisely so we can make that swap without any public-facing
change. Reseau volunteers as the canonical consumer/testbed for whatever shape
this takes.

### Ask 3 — Say out loud which names packages may rely on. (Blocks: our release.
Probably 15 minutes of Keno's time.)

Everything we build on is documented in the manual but nothing is exported or
marked `public`: `Base.CancellationTokenSource`, `CancellationToken`,
`CancellationRequest`, `cancel!`, `iscancelled`, `cancel_severity`,
`CANCEL_TOKEN`, and `wait(tok)`. We're about to ship a package whose core depends
on those eight names. We need one of: `public` marking before 1.14 final, or an
explicit "these are stable, build on them" statement we can point to. Without it
we're one 1.14.x rename away from a broken ecosystem package, so we've made this a
self-imposed release gate.

A related smaller question while we're there: Base's blocking functions share a
`cancel=` keyword convention built on internal helpers (`DEFAULT_CANCEL`,
`CancelTokenArg`). Is that convention ever meant to become public? If yes, we'll
adopt it verbatim; if no, we'll ship our own equivalent sentinel and that's fine
too — we just want to pick once.

### Ask 4 — Confirm tokens are usable as dictionary keys. (Cheap insurance;
nothing blocks on it.)

We keep a table mapping "token → our per-token machinery." Today that works
because `CancellationToken` is an immutable one-field wrapper, so two tokens
wrapping the same source are `===`-equal and an `IdDict` does the right thing. We
verified this by reading the source — but it's an implementation detail, not a
promise. **Ask:** one documented sentence ("two tokens of the same source are
egal / tokens may be used as IdDict keys"), or an identity function if the
representation might change. If it silently changed, our design survives
(duplicate table entries are harmless by construction) — we'd just rather have
the guarantee than the workaround.

### Ask 5 — One sentence in the docs about which severity to throw. (Trivial;
consistency across the ecosystem.)

When a blocked operation is cancelled, the severity can escalate between "the
waiter was woken" and "the exception is constructed." Base internally re-reads the
current severity right before throwing (`handle_cancellation!`), and we do the
same. **Ask:** write that down as the contract — "a cancellation point throws the
severity current at throw time" — so every library makes the same choice and users
see consistent severities in stack traces regardless of whose code they were
blocked in.

---

Sequencing: we build in parallel with these conversations (the cross-review
concluded that's safe); ask 1 is the only one where the *answer* changes what we
can ship (Windows, full ladder), and ask 3 is the only one gating the first
release itself.

## 12. Risks

| Risk | Mitigation |
|---|---|
| #62663/#62673 churn (CI failing at pin) | All escalation behavior conditional; branch-cut re-review; gates. |
| Hub/arm protocol bugs | Lock-serialized cold path; startup pin + FAILED settlement; exact-arm tickets; checked-in transition spec; deterministic + model tests; named regressions. |
| Watcher/hub leaks | No-resurrection generations; stop-source retirement; startup reference; churn baselines. |
| Storm fan-out | Batch budget + yield + cancellable continuation; both benchmark shapes; claimed-epoch dedup. |
| Wedged-kernel drains (Windows) | Honest §3 contract; Windows phase gated on upstream ask 1 + freeze-safety artifact. |
| Partial-progress surprises | §7.3 split contract; partial-count returns for reporting APIs; poison states with dedicated exceptions; matrix cells + fault injection. |
| Token-egality reliance | Upstream ask 4; duplicate-hub tolerance. |
| Downstream `catch InterruptException` | Docs callout; HTTP.jl notes. |

## 13. Cross-review history

Round 1 (codex, REVISE): 22 findings — lock-free registry unsound (ABA, invalid
Dekker, unretirable watcher), wake-lattice insufficiency, IOCP detach/read/accept
contract errors, TLS/DNS/HE ownership gaps, entry-check semantics, macOS gating,
upstream overstatement. All accepted; v3 adopted the locked-hub architecture.
Round 2 (codex, REVISE): 6 blockers in v3's handoff protocols (hub
resurrection-vs-join contradiction; claims not owning wakes; terminal-only op state
vs completion-wins; G2 vs escalation impossibility; owned-buffer detach unsafety;
DNS two-state leak) + 7 majors + 7 production gaps; ruling: parallel-track
prototyping with hard release gates. All adopted in v4.
Round 3 (codex, REVISE): watcher startup/failure protocol (→ §5.1 STARTING/FAILED +
startup pin); arm publication ordering + wake-CAS-may-lose rule (→ §6.2/6.3);
partial-progress logical reads (→ §7.3 split contract + read-poison); READY-dominates
wording contradiction (→ §6.4/§8 advisory-readiness rule); v1 IOCP detach ambiguity
(→ §7.6b none-detaches).
Round 4 (codex, REVISE — narrow): STARTING-hub watcher race (→ §5.1 start-gate
handoff with CAS'd transitions, registrar rules for STARTING/OBSERVED_CANCELLED,
scheduling-failure ownership, four new deterministic barriers); count-returning TLS
read cancelled mid-record (→ §7.8 complete matrix with transport close); plus four
editorial fixes (DNS free-ownership wording, join-boundedness wording,
read(conn,UInt8) single-byte rule, creator-transaction cross-reference).
Round 5 (codex, REVISE — one item): startup-outcome ownership — the FAILED path
never released the startup reference, joinability of the watcher task was
unpublished, and the creator's shielded extent had been dropped in the v6 edit
(→ v7 §5.1: creator is sole owner of both `STARTING→*` transitions and runs
shielded end-to-end; published startup outcome `PENDING/SCHEDULED/
FAILED_UNSCHEDULED`; startup reference released exactly once by the creator;
last-unlink and shutdown consult the outcome to decide stop-cancel/join vs no-join;
per-barrier expected outcomes). Codex round 5 also verified the TLS matrix
exhaustive and the STARTING registrar composition sound.
Round 6 (codex): all round-5 corrections verified RESOLVED; full interleaving and
consistency audit clean; three editorial nits (applied: gate-ordering wording,
outcome-latch mechanism note, matrix-in-artifact note). **VERDICT: AGREE** — signed
off as the design basis for implementation.
