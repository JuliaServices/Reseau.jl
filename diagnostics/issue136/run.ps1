[CmdletBinding()]
param(
    [string]$Julia = "julia",
    [ValidateRange(30, 1800)]
    [int]$TimeoutSeconds = 180,
    [ValidateRange(1, 64)]
    [int]$Threads = 1
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

if ($env:OS -ne "Windows_NT") {
    throw "This diagnostic must run on Windows."
}

$ExpectedProcDumpSha256 = "68e057587b0fd654efa095f76d80d633c0e5c60ea26fd3e7c0011c076bb2d00c"
$ProcDumpUrl = "https://download.sysinternals.com/files/Procdump.zip"
$Revision = "diagnostics/windows-precompile-136"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ReproScript = Join-Path $PSScriptRoot "repro.jl"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputDir = Join-Path (Get-Location) "reseau-issue-136-$Stamp"
$TracePath = Join-Path $OutputDir "precompile-trace.tsv"
$StdoutPath = Join-Path $OutputDir "stdout.log"
$StderrPath = Join-Path $OutputDir "stderr.log"
$SystemPath = Join-Path $OutputDir "system.txt"
$ProcessPath = Join-Path $OutputDir "process-tree.txt"
$DepotPath = Join-Path $OutputDir "depot"
$ToolsPath = Join-Path $OutputDir "tools"
$ProcDumpZip = Join-Path $ToolsPath "Procdump.zip"

New-Item -ItemType Directory -Path $OutputDir, $DepotPath, $ToolsPath | Out-Null
"monotonic_ns`tpid`tthread`tmode`tevent`tdetails" |
    Set-Content -LiteralPath $TracePath -Encoding UTF8

function Get-ReseauProcessTree {
    param([int]$RootProcessId)

    $All = @(Get-CimInstance Win32_Process)
    $Ids = New-Object "System.Collections.Generic.HashSet[uint32]"
    [void]$Ids.Add([uint32]$RootProcessId)
    do {
        $Added = $false
        foreach ($Item in $All) {
            if ($Ids.Contains([uint32]$Item.ParentProcessId) -and
                -not $Ids.Contains([uint32]$Item.ProcessId)) {
                [void]$Ids.Add([uint32]$Item.ProcessId)
                $Added = $true
            }
        }
    } while ($Added)
    return @($All | Where-Object { $Ids.Contains([uint32]$_.ProcessId) })
}

function Write-ProcessSnapshot {
    param(
        [object[]]$Processes,
        [string]$Path
    )

    $Processes |
        Sort-Object ProcessId |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine |
        Format-List |
        Out-File -LiteralPath $Path -Encoding UTF8
    foreach ($Item in $Processes) {
        try {
            Get-Process -Id $Item.ProcessId |
                Select-Object Id, ProcessName, StartTime, CPU, WorkingSet64,
                    PrivateMemorySize64, HandleCount, Threads |
                Format-List |
                Out-File -LiteralPath $Path -Encoding UTF8 -Append
        } catch {
            "Process $($Item.ProcessId) exited during snapshot: $_" |
                Out-File -LiteralPath $Path -Encoding UTF8 -Append
        }
    }
}

$JuliaCommand = Get-Command $Julia -ErrorAction Stop
$JuliaExe = $JuliaCommand.Source
$JuliaVersion = (& $JuliaExe --version 2>&1 | Out-String).Trim()
if ($JuliaVersion -notmatch "1\.12\.6") {
    throw "Issue #136 requires Julia 1.12.6; found '$JuliaVersion'."
}

@(
    "diagnostic_revision = $Revision"
    "repo_root = $RepoRoot"
    "julia_executable = $JuliaExe"
    "julia_version = $JuliaVersion"
    "threads = $Threads"
    "timeout_seconds = $TimeoutSeconds"
    "procdump_url = $ProcDumpUrl"
    "procdump_sha256 = $ExpectedProcDumpSha256"
    ""
    "Operating system:"
) | Set-Content -LiteralPath $SystemPath -Encoding UTF8

Get-CimInstance Win32_OperatingSystem |
    Format-List Caption, Version, BuildNumber, OSArchitecture |
    Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
"Computer:" | Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
Get-CimInstance Win32_ComputerSystem |
    Format-List Manufacturer, Model, TotalPhysicalMemory |
    Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
"Processor:" | Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
Get-CimInstance Win32_Processor |
    Format-List Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors,
        MaxClockSpeed, ProcessorId |
    Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
"Julia:" | Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append
& $JuliaExe --startup-file=no --history-file=no -e `
    "using InteractiveUtils; versioninfo()" 2>&1 |
    Out-File -LiteralPath $SystemPath -Encoding UTF8 -Append

Write-Host "Downloading the pinned Microsoft Sysinternals ProcDump bundle..."
Invoke-WebRequest -UseBasicParsing -Uri $ProcDumpUrl -OutFile $ProcDumpZip
$ActualProcDumpSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ProcDumpZip).Hash.ToLowerInvariant()
if ($ActualProcDumpSha256 -ne $ExpectedProcDumpSha256) {
    throw "ProcDump checksum mismatch: $ActualProcDumpSha256"
}
Expand-Archive -LiteralPath $ProcDumpZip -DestinationPath $ToolsPath
$ProcDumpExe = Join-Path $ToolsPath "procdump64.exe"
if (-not (Test-Path -LiteralPath $ProcDumpExe)) {
    throw "The verified ProcDump bundle did not contain procdump64.exe."
}

# Prevent common credential-bearing variables from entering the diagnostic
# process or its memory dump. The run uses a fresh depot and a public Git URL.
$RemovedEnvironment = @{}
Get-ChildItem Env: |
    Where-Object {
        $_.Name -match "(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|COOKIE|AUTH)" -or
        $_.Name -in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
    } |
    ForEach-Object {
        $RemovedEnvironment[$_.Name] = $_.Value
        Remove-Item -LiteralPath "Env:$($_.Name)"
    }

$PreviousDiagnosticEnvironment = @{
    JULIA_DEPOT_PATH = $env:JULIA_DEPOT_PATH
    JULIA_LOAD_PATH = $env:JULIA_LOAD_PATH
    JULIA_NUM_THREADS = $env:JULIA_NUM_THREADS
    JULIA_PKG_PRECOMPILE_AUTO = $env:JULIA_PKG_PRECOMPILE_AUTO
    RESEAU_PRECOMPILE_TRACE = $env:RESEAU_PRECOMPILE_TRACE
    RESEAU_DIAGNOSTIC_REV = $env:RESEAU_DIAGNOSTIC_REV
}

$env:JULIA_DEPOT_PATH = $DepotPath
$env:JULIA_LOAD_PATH = "@;@stdlib"
$env:JULIA_NUM_THREADS = "$Threads"
$env:JULIA_PKG_PRECOMPILE_AUTO = "1"
$env:RESEAU_PRECOMPILE_TRACE = $TracePath
$env:RESEAU_DIAGNOSTIC_REV = $Revision

$Arguments = @(
    "--startup-file=no"
    "--history-file=no"
    "--threads=$Threads"
    "`"$ReproScript`""
)

Write-Host "Starting the exact Pkg.add reproducer with Julia 1.12.6..."
try {
    $RootProcess = Start-Process -FilePath $JuliaExe -ArgumentList $Arguments `
        -WorkingDirectory $RepoRoot -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath -PassThru
} finally {
    foreach ($Name in $PreviousDiagnosticEnvironment.Keys) {
        $Value = $PreviousDiagnosticEnvironment[$Name]
        if ($null -eq $Value) {
            Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath "Env:$Name" -Value $Value
        }
    }
    foreach ($Name in $RemovedEnvironment.Keys) {
        Set-Item -LiteralPath "Env:$Name" -Value $RemovedEnvironment[$Name]
    }
}

$OverallDeadline = (Get-Date).AddSeconds([Math]::Max(600, $TimeoutSeconds * 2))
$InitialTraceLength = (Get-Item -LiteralPath $TracePath).Length
$LastTraceLength = $InitialTraceLength
$LastTraceProgress = Get-Date
$DiagnosticStarted = $false
$TimeoutReason = ""
$Completed = $false
$DoneMarker = $false
do {
    Start-Sleep -Seconds 1
    $Tree = @(Get-ReseauProcessTree -RootProcessId $RootProcess.Id)
    $LiveJulia = @(
        $Tree |
            Where-Object { $_.Name -ieq "julia.exe" } |
            Where-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
    )
    $DoneMarker = (Test-Path -LiteralPath $StdoutPath) -and
        ((Get-Content -LiteralPath $StdoutPath -Raw) -match "RESEAU_136_REPRO_DONE")
    if ($LiveJulia.Count -eq 0 -and ($DoneMarker -or $RootProcess.HasExited)) {
        $Completed = $true
        break
    }
    $TraceLength = (Get-Item -LiteralPath $TracePath).Length
    if ($TraceLength -ne $LastTraceLength) {
        $LastTraceLength = $TraceLength
        $LastTraceProgress = Get-Date
        $DiagnosticStarted = $TraceLength -gt $InitialTraceLength
    }
    $Now = Get-Date
    if ($DiagnosticStarted -and
        ($Now - $LastTraceProgress).TotalSeconds -ge $TimeoutSeconds) {
        $TimeoutReason = "no Reseau trace progress for $TimeoutSeconds seconds"
        break
    }
    if ($Now -ge $OverallDeadline) {
        $TimeoutReason = "overall setup limit reached before a clean exit"
        break
    }
} while ($true)

if ($Completed) {
    "The reproducer exited; success marker present: $DoneMarker. No process dump was taken." |
        Set-Content -LiteralPath $ProcessPath -Encoding UTF8
    if ($DoneMarker) {
        Write-Host "The reproducer completed instead of hanging."
    } else {
        Write-Host "The reproducer exited with an error; inspect stderr.log."
    }
} else {
    Write-Host "The reproducer timed out ($TimeoutReason); capturing it now."
    $Tree = @(Get-ReseauProcessTree -RootProcessId $RootProcess.Id)
    Write-ProcessSnapshot -Processes $Tree -Path $ProcessPath
    $JuliaProcesses = @(
        $Tree |
            Where-Object { $_.Name -ieq "julia.exe" } |
            Sort-Object ProcessId -Descending
    )
    foreach ($Item in $JuliaProcesses) {
        $DumpPath = Join-Path $OutputDir "julia-$($Item.ProcessId).dmp"
        try {
            & $ProcDumpExe -accepteula -mm -o `
                -dc "Reseau.jl issue 136 precompile timeout" `
                $Item.ProcessId $DumpPath |
                Out-File -LiteralPath $ProcessPath -Encoding UTF8 -Append
            "ProcDump PID $($Item.ProcessId) exit code: $LASTEXITCODE" |
                Out-File -LiteralPath $ProcessPath -Encoding UTF8 -Append
        } catch {
            "ProcDump PID $($Item.ProcessId) failed: $_" |
                Out-File -LiteralPath $ProcessPath -Encoding UTF8 -Append
        }
    }
    foreach ($Item in $JuliaProcesses) {
        Stop-Process -Id $Item.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

$BundlePath = "$OutputDir.zip"
$BundleFiles = @(Get-ChildItem -LiteralPath $OutputDir -File)
Compress-Archive -LiteralPath $BundleFiles.FullName -DestinationPath $BundlePath

Write-Host ""
Write-Host "Diagnostic bundle:"
Write-Host $BundlePath
Write-Host ""
Write-Host "Please share that ZIP with the maintainer. It contains system metadata,"
Write-Host "logs, the durable phase trace, and (only on timeout) mini dumps."
exit 0
