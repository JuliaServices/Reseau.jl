# Issue 136 Windows precompile diagnostics

This branch intentionally retains the failing Windows precompile workload. It
adds durable phase tracing and an external timeout harness so the exact
operation and IOCP lifecycle state can be recovered after the worker hangs.

## Run

Requirements:

- Windows 11 x86-64
- Julia 1.12.6 available as `julia`
- PowerShell 5.1 or newer
- internet access to GitHub and Microsoft Sysinternals

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\diagnostics\issue136\run.ps1
```

The default no-progress timeout is three minutes and the default Julia thread
count is one. Registry setup and ordinary compilation do not consume that
budget: the timer resets after every durable Reseau trace event. Both values can
be changed explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\diagnostics\issue136\run.ps1 `
    -TimeoutSeconds 300 -Threads 1
```

The script prints the path of a ZIP bundle to share with the maintainer. The
bundle contains:

- Windows, CPU, and verbose Julia version information
- the `Pkg.add` stdout and stderr logs
- a tab-separated, flush-after-each-event trace of workload and IOCP phases
- a process-tree snapshot at the timeout
- a Sysinternals ProcDump mini dump for each live Julia process, only if the
  reproducer timed out

The run uses a fresh Julia depot and removes common credential-bearing
environment variables before launching Julia. Mini dumps can still contain
process memory and local paths; inspect the bundle before sharing if that is a
concern.

The harness downloads the official Microsoft Sysinternals ProcDump 12.01 ZIP
and requires SHA-256:

```text
68e057587b0fd654efa095f76d80d633c0e5c60ea26fd3e7c0011c076bb2d00c
```
