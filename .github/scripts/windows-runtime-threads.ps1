param(
    [Parameter(Mandatory)][string]$Driver,
    [Parameter(Mandatory)][string]$Library,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidateSet('x86', 'x64')][string]$Architecture,
    [Parameter(Mandatory)][ValidateSet('exception', 'no-exception')][string]$Mode
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$metadata = [ordered]@{
    architecture = $Architecture
    mode = $Mode
    juliaVersion = (& julia --startup-file=no -e 'print(VERSION)').Trim()
    childTimeoutSeconds = 120
    debuggerTimeoutSeconds = 30
    childTimedOut = $false
    debuggerTimedOut = $false
    driverSha256 = (Get-FileHash $Driver -Algorithm SHA256).Hash
    librarySha256 = (Get-FileHash $Library -Algorithm SHA256).Hash
}
$child = $null
$debugger = $null
$exitCode = 1
try {
    if ($metadata.juliaVersion -ne '1.13.1') { throw 'Diagnostic requires exactly Julia 1.13.1.' }
    $julia = (Get-Command julia).Source
    $metadata.juliaExecutable = $julia
    $metadata.juliaExecutableSha256 = (Get-FileHash $julia -Algorithm SHA256).Hash
    $arguments = @('--startup-file=no', '--history-file=no', '--threads=1',
        ('"{0}"' -f $Driver), ('"{0}"' -f $Library), $Mode)
    $child = Start-Process $julia -ArgumentList $arguments -PassThru `
        -RedirectStandardOutput (Join-Path $OutputDirectory 'test.stdout.txt') `
        -RedirectStandardError (Join-Path $OutputDirectory 'test.stderr.txt')
    $metadata.childPid = $child.Id
    $metadata.childStartedAt = [DateTime]::UtcNow.ToString('o')
    if ($child.WaitForExit(120000)) {
        $child.Refresh()
        $metadata.childExitCode = $child.ExitCode
        $exitCode = $child.ExitCode
    } else {
        $metadata.childTimedOut = $true
        $cdb = Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Filter cdb.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Name -eq $Architecture } | Select-Object -First 1
        if (-not $cdb) { throw "No matching $Architecture CDB debugger is installed." }
        $metadata.debuggerPath = $cdb.FullName
        $dump = Join-Path $OutputDirectory 'runtime.dmp'
        $symbols = Join-Path $OutputDirectory 'local-symbols'
        New-Item -ItemType Directory -Force -Path $symbols | Out-Null
        $commands = '.dump /ma "{0}"; ~*kb; lm; .detach; q' -f $dump
        $commandFile = Join-Path $OutputDirectory 'cdb.commands.txt'
        $commands | Set-Content $commandFile
        $debugger = Start-Process $cdb.FullName -PassThru `
            -ArgumentList @('-p', $child.Id, '-y', ('"{0}"' -f $symbols), '-cf', ('"{0}"' -f $commandFile)) `
            -RedirectStandardOutput (Join-Path $OutputDirectory 'cdb.stdout.txt') `
            -RedirectStandardError (Join-Path $OutputDirectory 'cdb.stderr.txt')
        $metadata.debuggerPid = $debugger.Id
        if (-not $debugger.WaitForExit(30000)) {
            $metadata.debuggerTimedOut = $true
        } else {
            $debugger.Refresh()
            $metadata.debuggerExitCode = $debugger.ExitCode
        }
        $exitCode = 124
    }
} catch {
    $metadata.error = $_.Exception.Message
    Write-Host $_.Exception.ToString()
    $exitCode = 1
} finally {
    foreach ($ownedProcess in @($debugger, $child)) {
        if ($null -ne $ownedProcess -and -not $ownedProcess.HasExited) {
            Stop-Process -Id $ownedProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $metadata.completedAt = [DateTime]::UtcNow.ToString('o')
    $metadata | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutputDirectory 'metadata.json')
    Get-Content (Join-Path $OutputDirectory 'test.stdout.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'test.stderr.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'cdb.stdout.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'cdb.stderr.txt') -ErrorAction SilentlyContinue
}
exit $exitCode
