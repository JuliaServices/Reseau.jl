param(
    [Parameter(Mandatory)][string]$Subject,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidateSet('x86', 'x64')][string]$Architecture
)

$ErrorActionPreference = 'Stop'
$expectedSource = '159e02da68024fd6421481dc4b8a020d9d20ead6'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$metadata = [ordered]@{
    expectedSource = $expectedSource
    actualSource = (& git -C $Subject rev-parse HEAD).Trim()
    architecture = $Architecture
    juliaVersion = (& julia --startup-file=no -e 'print(VERSION)').Trim()
    testFile = 'host_resolvers_tests.jl'
    childTimeoutSeconds = 120
    debuggerTimeoutSeconds = 30
    childTimedOut = $false
    debuggerTimedOut = $false
}
$child = $null
$debugger = $null
$exitCode = 1

try {
    if ($metadata.actualSource -ne $expectedSource) { throw 'Subject source differs from the pinned main commit.' }
    if ($metadata.juliaVersion -ne '1.13.1') { throw 'Diagnostic requires exactly Julia 1.13.1.' }
    & git -C $Subject diff --exit-code HEAD -- src test Project.toml
    if ($LASTEXITCODE -ne 0) { throw 'Subject source or tests changed before the diagnostic.' }
    Copy-Item (Join-Path $Subject 'Project.toml') $OutputDirectory
    Copy-Item (Join-Path $Subject 'Manifest.toml') $OutputDirectory
    & julia --startup-file=no -e 'using InteractiveUtils; versioninfo()' |
        Set-Content (Join-Path $OutputDirectory 'versioninfo.txt')

    $julia = (Get-Command julia).Source
    $testPath = Join-Path $Subject 'test/runtests.jl'
    $arguments = @('--startup-file=no', '--history-file=no', '--threads=1',
        ('--project="{0}"' -f $Subject), ('"{0}"' -f $testPath))
    $child = Start-Process $julia -ArgumentList $arguments -WorkingDirectory $Subject -PassThru `
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
        $dump = Join-Path $OutputDirectory 'resolver.dmp'
        $commands = '~*kb; lm; .dump /ma "{0}"; .detach; q' -f $dump
        $commandFile = Join-Path $OutputDirectory 'cdb.commands.txt'
        $commands | Set-Content $commandFile
        $debugger = Start-Process $cdb.FullName -PassThru `
            -ArgumentList @('-p', $child.Id, '-cf', ('"{0}"' -f $commandFile)) `
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
    # Stop only processes created by this diagnostic, including a stalled debugger.
    foreach ($ownedProcess in @($debugger, $child)) {
        if ($null -ne $ownedProcess -and -not $ownedProcess.HasExited) {
            Stop-Process -Id $ownedProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    & git -C $Subject diff --exit-code HEAD -- src test Project.toml |
        Set-Content (Join-Path $OutputDirectory 'subject.diff.txt')
    $metadata.sourceUnchanged = $LASTEXITCODE -eq 0
    if (-not $metadata.sourceUnchanged) { $exitCode = 1 }
    $metadata.completedAt = [DateTime]::UtcNow.ToString('o')
    $metadata | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutputDirectory 'metadata.json')
    Get-Content (Join-Path $OutputDirectory 'test.stdout.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'test.stderr.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'cdb.stdout.txt') -ErrorAction SilentlyContinue
    Get-Content (Join-Path $OutputDirectory 'cdb.stderr.txt') -ErrorAction SilentlyContinue
}
exit $exitCode
