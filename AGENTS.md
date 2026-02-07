# Reseau Agent Notes

This repo is a Julia package (`Project.toml`). Tests live under `test/` and are driven by `test/runtests.jl`.

## Running Tests (Exact Commands)

### Recommended (fast + deterministic)

Run from the repo root:

```sh
cd "$(git rev-parse --show-toplevel)"
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

Notes:
- Julia defaults to 1 thread if you do not pass `-t`, but setting `JULIA_NUM_THREADS=1` makes this explicit and keeps runtimes predictable.
- First run can be slow due to artifact downloads + precompilation.
- Most output is per-`@testset` summaries. Multi-second (sometimes 10s+) gaps with no output are normal.
- On this machine, this command typically finishes in ~1 minute.

### Full Test Matrix (Default + Network + TLS)

All commands below run from the repo root:

```sh
cd "$(git rev-parse --show-toplevel)"
```

Default (no network, no TLS):

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

Network-only:

```sh
RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

TLS-only:

```sh
RESEAU_RUN_TLS_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

TLS + network (includes the TLS network negotiation tests):

```sh
RESEAU_RUN_TLS_TESTS=1 RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

Note: the `TLS network negotiation (requires network)` testset can take ~45s with no output.

### Downstream Packages (AwsHTTP + HTTP)

When making changes in `Reseau`, also run the tests for downstream packages that depend on it:

AwsHTTP:

```sh
cd /Users/jacob.quinn/.julia/dev/AwsHTTP
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

HTTP:

```sh
cd /Users/jacob.quinn/.julia/dev/HTTP
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

### Stressier (may run more work; slower)

```sh
cd "$(git rev-parse --show-toplevel)"
julia -t auto --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

On this machine (Julia 1.12.x), `-t auto` causes some testsets (notably `Event Loops`) to run more iterations and take longer.
If this feels “hung”, give it a couple minutes; if it is still not producing output, re-run with `JULIA_NUM_THREADS=1` to rule out thread-scheduling flakiness.

## Optional Test Suites / Env Vars

- TLS tests are disabled by default.
  - Enable: `RESEAU_RUN_TLS_TESTS=1`
  - macOS: tests may create a temporary keychain (see `test/test_utils.jl`)
- Network-heavy tests are disabled by default.
  - Enable: `RESEAU_RUN_NETWORK_TESTS=1`
  - Requires functional outbound network/DNS or tests may be slow/flaky.
- PKCS11 (SoftHSM) tests are skipped unless configured.
  - Requires `TEST_PKCS11_LIB` and `TEST_PKCS11_TOKEN_DIR`
  - Also requires `softhsm2-util` installed.

## If Tests Appear “Hung”

1. Prefer running in an interactive terminal (TTY). Non-TTY runners often hide precompile/progress output.
2. Re-run with the recommended single-thread command (`JULIA_NUM_THREADS=1`).
3. Narrow down to a specific file:

```sh
cd "$(git rev-parse --show-toplevel)"
julia -t auto --project=. --startup-file=no --history-file=no -e 'include("test/event_loop_tests.jl")'
julia -t auto --project=. --startup-file=no --history-file=no -e 'include("test/socket_tests.jl")'
```

4. If a direct `include(...)` run truly blocks, hit Ctrl+C to get a stack trace.
5. If `Pkg.test` appears hung, remember it runs tests in a child Julia process. For a stack dump on macOS:

Find the child PID:

```sh
ps -ax -o pid=,command= | rg 'Reseau/test/runtests\\.jl'
```

Then request a stack dump:

```sh
kill -INFO <pid>
```

If you are running in a TTY and the hung process is in the foreground, you can also try `Ctrl+T` (SIGINFO).

## Expected Noisy Output

- Some tests intentionally trigger `FATAL_ASSERT:` messages while validating error paths; they are expected when the overall test suite is passing.
- There are warnings about method redefinition from repeated `include(...)` of helper code in `test/`; these are noisy but not test failures.
