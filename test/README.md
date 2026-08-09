# Deterministic test synchronization

Reseau tests must not depend on scheduler speed or elapsed wall-clock time.
GitHub Actions runners can pause a task for an unknown period. A delay that is
safe on one runner can fail on another runner without a product defect.

Use observable state transitions instead:

- Use a `Channel`, `Base.Event`, or gate field on a fake (see the resolver
  fakes in `host_resolvers_tests.jl`) for task handshakes.
- Read exact byte counts, complete records, or EOF after the peer closes.
- Use `fetch(task)` or `wait(task)` for task completion. Wrap unexpected
  `Threads.@spawn` failures with `errormonitor`.
- Park detection: spin `while !((@atomic :acquire waiter.state) isa Task)`
  before acting on a waiter that must be blocked.
- Inject a fixed clock into pure deadline calculations
  (e.g. `IOPoll._poll_delay_ns(state; now_ns = ...)`).
- Use an already-expired absolute deadline (`Int64(1)`) when a test must
  enter a product timeout branch. Do not wait for a future deadline to
  expire.
- Use a far-future deadline (`typemax(Int64) ÷ 2`) when a deadline must be
  armed but never fire.
- To prove a peer sent nothing, establish happens-before (its task finished
  or it closed), then use a single non-blocking read probe or EOF — never a
  short read-deadline window.

Do not use `sleep`, `timedwait`, `time`, `time_ns`, `Timer`, elapsed-time
assertions, polling intervals, or helper-level timeout arguments in test code.
Do not use a short delay to prove that an event has not occurred. Build a
barrier that makes the event impossible until the test releases it, or assert
the guarded state directly.

Two places legitimately read the clock:

- `timing_semantics_tests.jl` holds the product-latency tests that genuinely
  require a real timer to fire (the poller-owned sleep heap, backend poll
  timeouts, a deadline waking a blocked reader). Every elapsed-time assertion
  there is a lower bound, so a paused runner can only lengthen the measured
  time — never fail it. Keep new clock-reading tests in this file.
- The native TLS test files call `time()` because TLS session tickets carry
  UNIX-seconds protocol timestamps that the product compares against its own
  clock. Those tests use tolerances of hours to days.

Product timeout configuration remains valid test input. It tests parsing,
propagation, and expired-deadline behavior. It must not act as the test
harness. The GitHub Actions job timeout remains the final guard for a true
deadlock.
