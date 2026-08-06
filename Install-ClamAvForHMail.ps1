#Requires -Version 7.2
<#
.SYNOPSIS
    Prepares ClamAV on Windows for the hMailServer cleanup script: creates the
    log and temp directories, validates the configuration files, updates the
    signature database, then installs and starts the clamd service.

.DESCRIPTION
    freshclam and clamd initialize their logger before anything else, so a
    missing log directory makes both tools fail with "No such file or
    directory". This script creates every required directory first, then
    performs the remaining steps in the correct order and verifies the result.

.PARAMETER ClamRoot
    ClamAV installation directory.

.PARAMETER DataRoot
    Directory for logs and temporary files.

.PARAMETER ConfigSource
    Optional directory that holds freshclam.conf and clamd.conf to copy into
    ClamRoot before validation.

.PARAMETER SkipDatabaseUpdate
    Do not run freshclam.

.PARAMETER SkipService
    Do not install or start the clamd service; useful when only clamscan is used.

.EXAMPLE
    pwsh -NoProfile -File .\Install-ClamAvForHMail.ps1

.EXAMPLE
    pwsh -NoProfile -File .\Install-ClamAvForHMail.ps1 -ConfigSource 'C:\mail\scripts\av'

.NOTES
    Run elevated: service registration requires administrative rights.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ClamRoot = 'C:\Program Files\ClamAV',

    [string] $DataRoot = 'C:\ProgramData\ClamAV',

    [string] $ConfigSource,

    [switch] $SkipDatabaseUpdate,

    [switch] $SkipService
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

function Write-Step {
    <#
    .SYNOPSIS
        Prints a progress line.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Message
    )

    Write-Information -MessageData ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message)
}

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native executable and returns its exit code and output lines.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $ArgumentList,

        [int] $TimeoutMinutes = 30
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = (Split-Path -Path $FilePath -Parent)

    foreach ($argument in @($ArgumentList)) {
        $null = $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $exitCode = -1
    $text = ''

    try {
        $null = $process.Start()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()

        if (-not $process.WaitForExit($TimeoutMinutes * 60 * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                Write-Debug ('kill failed: {0}' -f $_.Exception.Message)
            }

            $process.WaitForExit()
            throw ('{0} did not finish within {1} minute(s).' -f $FilePath, $TimeoutMinutes)
        }

        $exitCode = $process.ExitCode
        $text = $outputTask.GetAwaiter().GetResult() + $errorTask.GetAwaiter().GetResult()
    }
    finally {
        $process.Dispose()
    }

    $lines = @()

    if ($text.Length -gt 0) {
        $lines = @([regex]::Split($text, '\r\n|\n|\r') | Where-Object -FilterScript { $_ -and $_.Trim().Length -gt 0 })
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Line = [string[]] $lines
    }
}

function Test-ConfigFile {
    <#
    .SYNOPSIS
        Verifies that a ClamAV configuration file exists and has no active Example line.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('Configuration file is missing: {0}' -f $Path)
    }

    $active = @(Get-Content -LiteralPath $Path | Where-Object -FilterScript { $_.Trim() -eq 'Example' })

    if ($active.Count -gt 0) {
        throw ('Remove the active "Example" line from {0}' -f $Path)
    }

    Write-Step -Message ('configuration ok: {0}' -f $Path)
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)

if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script elevated: installing the clamd service requires administrative rights.'
}

if (-not (Test-Path -LiteralPath $ClamRoot -PathType Container)) {
    throw ('ClamAV directory not found: {0}' -f $ClamRoot)
}

$logDir = Join-Path -Path $DataRoot -ChildPath 'logs'
$tmpDir = Join-Path -Path $DataRoot -ChildPath 'tmp'
$dbDir = Join-Path -Path $ClamRoot -ChildPath 'database'

foreach ($directory in @($DataRoot, $logDir, $tmpDir, $dbDir)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($directory, 'Create directory')) {
            $null = New-Item -ItemType Directory -Force -Path $directory
            Write-Step -Message ('created {0}' -f $directory)
        }
    }
    else {
        Write-Step -Message ('exists {0}' -f $directory)
    }
}

$freshclamConf = Join-Path -Path $ClamRoot -ChildPath 'freshclam.conf'
$clamdConf = Join-Path -Path $ClamRoot -ChildPath 'clamd.conf'

if ($ConfigSource) {
    foreach ($name in @('freshclam.conf', 'clamd.conf')) {
        $source = Join-Path -Path $ConfigSource -ChildPath $name

        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw ('Configuration file not found in the source directory: {0}' -f $source)
        }

        if ($PSCmdlet.ShouldProcess((Join-Path -Path $ClamRoot -ChildPath $name), 'Copy configuration file')) {
            Copy-Item -LiteralPath $source -Destination $ClamRoot -Force
            Write-Step -Message ('copied {0}' -f $name)
        }
    }
}

Test-ConfigFile -Path $freshclamConf
Test-ConfigFile -Path $clamdConf

$freshclam = Join-Path -Path $ClamRoot -ChildPath 'freshclam.exe'
$clamd = Join-Path -Path $ClamRoot -ChildPath 'clamd.exe'
$clamdScan = Join-Path -Path $ClamRoot -ChildPath 'clamdscan.exe'

foreach ($binary in @($freshclam, $clamd, $clamdScan)) {
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw ('Executable not found: {0}' -f $binary)
    }
}

if (-not $SkipDatabaseUpdate) {
    if ($PSCmdlet.ShouldProcess($freshclam, 'Update signature database')) {
        Write-Step -Message 'running freshclam, the first run downloads several hundred megabytes'
        $update = Invoke-Native -FilePath $freshclam -ArgumentList @() -TimeoutMinutes 60

        foreach ($line in @($update.Line | Select-Object -First 15)) {
            Write-Information -MessageData ('  {0}' -f $line)
        }

        if ($update.ExitCode -eq 0) {
            Write-Step -Message 'signature database updated'
        }
        else {
            Write-Warning -Message ('freshclam returned {0}; check {1}' -f $update.ExitCode, (Join-Path -Path $logDir -ChildPath 'freshclam.log'))
        }
    }
}

$signature = @(Get-ChildItem -LiteralPath $dbDir -File -ErrorAction Ignore | Where-Object -FilterScript { $_.Extension -in '.cvd', '.cld' })

if ($signature.Count -eq 0) {
    Write-Warning -Message ('No signature database in {0}; clamd will not start without signatures.' -f $dbDir)
}
else {
    foreach ($file in $signature) {
        Write-Step -Message ('signature {0}: {1:N0} byte(s), {2:yyyy-MM-dd HH:mm}' -f $file.Name, $file.Length, $file.LastWriteTime)
    }
}

if ($SkipService) {
    Write-Step -Message 'service step skipped; use the cleanup script with -Engine Clamscan'
    return
}

$service = Get-Service -Name '*clam*' -ErrorAction Ignore | Select-Object -First 1

if ($null -eq $service) {
    if ($PSCmdlet.ShouldProcess($clamd, 'Install the clamd service')) {
        Write-Step -Message 'registering the clamd service'
        $install = Invoke-Native -FilePath $clamd -ArgumentList @('--install') -TimeoutMinutes 5

        foreach ($line in @($install.Line | Select-Object -First 10)) {
            Write-Information -MessageData ('  {0}' -f $line)
        }

        Start-Sleep -Seconds 2
        $service = Get-Service -Name '*clam*' -ErrorAction Ignore | Select-Object -First 1

        if ($null -eq $service) {
            throw 'The clamd service was not registered. Check the clamd log and run this script elevated.'
        }
    }
}
else {
    Write-Step -Message ('service already present: {0} ({1})' -f $service.Name, $service.Status)
}

if ($null -ne $service) {
    if ($service.StartType -ne 'Automatic') {
        if ($PSCmdlet.ShouldProcess($service.Name, 'Set start type to Automatic')) {
            Set-Service -Name $service.Name -StartupType Automatic
            Write-Step -Message ('start type set to Automatic for {0}' -f $service.Name)
        }
    }

    if ($service.Status -ne 'Running') {
        if ($PSCmdlet.ShouldProcess($service.Name, 'Start service')) {
            Start-Service -Name $service.Name
            Start-Sleep -Seconds 3
            $service.Refresh()
            Write-Step -Message ('service {0} is {1}' -f $service.Name, $service.Status)
        }
    }
    else {
        Write-Step -Message ('service {0} is already running' -f $service.Name)
    }
}

$version = Invoke-Native -FilePath $clamdScan -ArgumentList @('--version') -TimeoutMinutes 2

foreach ($line in @($version.Line)) {
    Write-Information -MessageData ('  {0}' -f $line)
}

$refused = @($version.Line | Where-Object -FilterScript { $_ -match 'Connection refused' })

if ($refused.Count -gt 0) {
    Write-Warning -Message 'clamdscan could not reach the daemon. Verify TCPSocket 3310 and TCPAddr 127.0.0.1 in clamd.conf, then check the clamd log.'
}
else {
    Write-Step -Message 'clamdscan reached the daemon; the cleanup script can use -Engine Clamd'
}

Write-Step -Message ('logs: {0}' -f $logDir)
Write-Step -Message 'next: .\Invoke-HMailClamAvCleanup.ps1 -DiagnoseOnly -Debug'
