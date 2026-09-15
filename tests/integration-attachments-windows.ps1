param(
    [string]$Binary = "target/debug/meshmsg.exe"
)

$ErrorActionPreference = "Stop"
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$Root = Join-Path ([System.IO.Path]::GetTempPath()) ("meshmsg-windows-attachments-" + [guid]::NewGuid().ToString("N"))
$Provider = Join-Path $Root "provider"
$Receiver = Join-Path $Root "receiver"
$script:Daemons = @{}
$script:Succeeded = $false
New-Item -ItemType Directory -Path $Root | Out-Null

function Invoke-Meshmsg {
    param([string[]]$CommandArgs)

    $output = & $script:Binary @CommandArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "meshmsg $($CommandArgs -join ' ') failed with exit code ${LASTEXITCODE}: $output"
    }
    return $output.Trim()
}

function Start-MeshmsgDaemon {
    param([string]$Name, [string]$StateDir)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:Binary
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @("--state-dir", $StateDir, "--json", "daemon")) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "failed to start $Name daemon"
    }
    $script:Daemons[$Name] = [pscustomobject]@{
        StateDir = $StateDir
        Process = $process
        Stdout = $process.StandardOutput.ReadToEndAsync()
        Stderr = $process.StandardError.ReadToEndAsync()
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(80)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            $stdout = $script:Daemons[$Name].Stdout.GetAwaiter().GetResult()
            $stderr = $script:Daemons[$Name].Stderr.GetAwaiter().GetResult()
            throw "$Name daemon exited during startup: $stdout $stderr"
        }
        try {
            $status = Invoke-Meshmsg -CommandArgs @("--state-dir", $StateDir, "--json", "status") | ConvertFrom-Json
            if ($status.running -eq $true) {
                return
            }
        } catch {
            # The IPC endpoint is expected to be unavailable briefly at startup.
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timed out waiting for $Name daemon"
}

function Stop-MeshmsgDaemons {
    foreach ($daemon in $script:Daemons.Values) {
        try {
            Invoke-Meshmsg -CommandArgs @("--state-dir", $daemon.StateDir, "stop") | Out-Null
        } catch {
            # A failed test may already have stopped or crashed the daemon.
        }
    }
    foreach ($name in $script:Daemons.Keys) {
        $daemon = $script:Daemons[$name]
        if (-not $daemon.Process.WaitForExit(10000)) {
            $daemon.Process.Kill($true)
            $daemon.Process.WaitForExit()
        }
        $stdout = $daemon.Stdout.GetAwaiter().GetResult()
        $stderr = $daemon.Stderr.GetAwaiter().GetResult()
        if (-not $script:Succeeded) {
            [System.IO.File]::WriteAllText((Join-Path $Root "$name.daemon.log"), $stdout)
            [System.IO.File]::WriteAllText((Join-Path $Root "$name.daemon.err"), $stderr)
            Write-Host "--- $name daemon stdout ---`n$stdout"
            Write-Host "--- $name daemon stderr ---`n$stderr"
        }
        $daemon.Process.Dispose()
    }
}

try {
    Invoke-Meshmsg -CommandArgs @("--state-dir", $Provider, "init") | Out-Null
    Start-MeshmsgDaemon -Name "provider" -StateDir $Provider

    $invite = Invoke-Meshmsg -CommandArgs @("--state-dir", $Provider, "--json", "invite") | ConvertFrom-Json
    Invoke-Meshmsg -CommandArgs @("--state-dir", $Receiver, "join", $invite.token) | Out-Null
    Start-MeshmsgDaemon -Name "receiver" -StateDir $Receiver

    $source = Join-Path $Root "source.txt"
    $destination = Join-Path $Root "received.txt"
    $offerFile = Join-Path $Root "signed-offer.txt"
    [System.IO.File]::WriteAllText($source, "native Windows attachment integration payload`n", [System.Text.UTF8Encoding]::new($false))

    $share = Invoke-Meshmsg -CommandArgs @("--state-dir", $Provider, "--json", "share", $source) | ConvertFrom-Json
    if ($share.type -ne "attachment_shared" -or [string]::IsNullOrWhiteSpace($share.offer)) {
        throw "share did not return a signed attachment offer"
    }
    [System.IO.File]::WriteAllText($offerFile, $share.offer, [System.Text.UTF8Encoding]::new($false))

    $download = Invoke-Meshmsg -CommandArgs @(
        "--state-dir", $Receiver,
        "--json", "download",
        "--offer-file", $offerFile,
        "--output", $destination
    ) | ConvertFrom-Json

    if ($download.type -ne "download_complete" -or
        $download.installed -ne $true -or
        $download.pinned -ne $true -or
        $download.destination_synced -ne $true -or
        $download.cleanup_complete -ne $true -or
        $download.warnings.Count -ne 0) {
        throw "download did not complete durably: $($download | ConvertTo-Json -Compress)"
    }
    if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
        throw "download completion did not create the destination"
    }
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($sourceHash -ne $destinationHash) {
        throw "downloaded attachment differs from the source"
    }
    $leftovers = @(Get-ChildItem -LiteralPath $Root -Force -Filter ".meshmsg-part-*.download")
    if ($leftovers.Count -ne 0) {
        throw "download left a staging file: $($leftovers.FullName -join ', ')"
    }

    $script:Succeeded = $true
    Write-Host "PASS: native Windows signed attachment download and durable installation"
} catch {
    Write-Error "Windows attachment integration failure: $_ (artifacts: $Root)"
    throw
} finally {
    Stop-MeshmsgDaemons
    if ($script:Succeeded -and $env:KEEP_MESHMSG_TEST_STATE -ne "1") {
        Remove-Item -LiteralPath $Root -Recurse -Force
    } else {
        Write-Host "kept test state: $Root"
    }
}
