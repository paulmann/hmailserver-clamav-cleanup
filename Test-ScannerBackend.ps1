#Requires -Version 7.2
<#
.SYNOPSIS
    Reports which on-demand scanner backends are usable on this server:
    Microsoft Defender, ClamAV, Kaspersky Virus Removal Tool, or the resident
    Kaspersky real time protection.

.DESCRIPTION
    The script only inspects the system. Nothing is installed, configured or
    deleted. With IncludeEicar it writes the standard EICAR test string,
    assembled from character codes so this file itself stays harmless, and
    checks whether the resident protection intercepts it and whether the
    detected backends report it.

.PARAMETER WorkDirectory
    Directory for probe files and the summary CSV.

.PARAMETER IncludeEicar
    Also perform a live detection test with the EICAR test string.

.PARAMETER TimeoutSeconds
    Per command timeout for backend probes.

.EXAMPLE
    .\Test-ScannerBackend.ps1

.EXAMPLE
    .\Test-ScannerBackend.ps1 -IncludeEicar
#>
[CmdletBinding()]
param(
    [string] $WorkDirectory = ('C:\mail\reports\kaspersky\backend-{0:yyyyMMdd-HHmmss}' -f (Get-Date)),

    [switch] $IncludeEicar,

    [ValidateRange(10, 900)]
    [int] $TimeoutSeconds = 180
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$null = New-Item -ItemType Directory -Force -Path $WorkDirectory
$probeDir = Join-Path -Path $WorkDirectory -ChildPath 'target'
$null = New-Item -ItemType Directory -Force -Path $probeDir
$findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    <#
    .SYNOPSIS
        Records and prints one backend observation.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Backend,

        [Parameter(Mandatory)]
        [string] $Check,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Result,

        [string] $Detail = ''
    )

    $findings.Add([pscustomobject]@{
        Backend = $Backend
        Check = $Check
        Result = $Result
        Detail = $Detail
    })

    Write-Information -MessageData ('{0,-12} {1,-26} {2,-12} {3}' -f $Backend, $Check, $Result, $Detail)
}

function Find-Executable {
    <#
    .SYNOPSIS
        Locates an executable in PATH or in a list of candidate directories.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $Directory
    )

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Ignore | Select-Object -First 1

    if ($command) {
        return $command.Source
    }

    foreach ($candidateDir in @($Directory)) {
        if (-not $candidateDir) {
            continue
        }

        $candidate = Join-Path -Path $candidateDir -ChildPath $Name

        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Get-Item -LiteralPath $candidate).FullName
        }
    }

    return $null
}

function Invoke-Probe {
    <#
    .SYNOPSIS
        Runs a native command, captures output, and returns the exit code.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [string] $OutputFile
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
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

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                Write-Debug ('kill failed: {0}' -f $_.Exception.Message)
            }

            $process.WaitForExit()
        }

        $exitCode = $process.ExitCode
        $text = $outputTask.GetAwaiter().GetResult() + $errorTask.GetAwaiter().GetResult()
    }
    finally {
        $process.Dispose()
    }

    [System.IO.File]::WriteAllText($OutputFile, $text, [System.Text.UTF8Encoding]::new($false))
    $lines = @($text -split '\r\n|\n|\r' | Where-Object -FilterScript { $_ -and $_.Trim().Length -gt 0 })

    return [pscustomobject]@{
        ExitCode = $exitCode
        Line = [string[]] $lines
        OutputFile = $OutputFile
    }
}

Write-Information -MessageData ('work dir: {0}' -f $WorkDirectory)
Write-Information -MessageData ''
Write-Information -MessageData ('{0,-12} {1,-26} {2,-12} {3}' -f 'BACKEND', 'CHECK', 'RESULT', 'DETAIL')

# Kaspersky resident state
$kasperskyProcess = @(Get-Process -Name 'avp' -ErrorAction Ignore)
$kasperskyDetail = if ($kasperskyProcess.Count -gt 0) { 'avp.exe instances: {0}' -f $kasperskyProcess.Count } else { 'avp.exe not running' }
Add-Finding -Backend 'Kaspersky' -Check 'resident process' -Result ($kasperskyProcess.Count -gt 0 ? 'present' : 'absent') -Detail $kasperskyDetail
Add-Finding -Backend 'Kaspersky' -Check 'command line interface' -Result 'blocked' -Detail 'avp.com returns 3 for every command on build 21.26'

# Microsoft Defender
$defenderStatus = $null

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
}
catch {
    Add-Finding -Backend 'Defender' -Check 'Get-MpComputerStatus' -Result 'unavailable' -Detail $_.Exception.Message
}

if ($null -ne $defenderStatus) {
    $runningMode = [string] $defenderStatus.AMRunningMode
    $modeResult = if ($runningMode -eq 'Normal') { 'active' } else { 'limited' }
    $modeDetail = 'AMRunningMode={0}; AntivirusEnabled={1}; RealTime={2}' -f $runningMode, $defenderStatus.AntivirusEnabled, $defenderStatus.RealTimeProtectionEnabled
    Add-Finding -Backend 'Defender' -Check 'running mode' -Result $modeResult -Detail $modeDetail
}

$defenderDir = [System.Collections.Generic.List[string]]::new()
$defenderDir.Add((Join-Path -Path $env:ProgramFiles -ChildPath 'Windows Defender'))
$platformRoot = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows Defender\Platform'

if (Test-Path -LiteralPath $platformRoot -PathType Container) {
    $platformDir = @(Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction Ignore | Sort-Object -Property Name -Descending)

    foreach ($item in $platformDir) {
        $defenderDir.Add($item.FullName)
    }
}

$mpCmdRun = Find-Executable -Name 'MpCmdRun.exe' -Directory $defenderDir.ToArray()

if ($mpCmdRun) {
    Add-Finding -Backend 'Defender' -Check 'MpCmdRun.exe' -Result 'found' -Detail $mpCmdRun
    $probe = Invoke-Probe -FilePath $mpCmdRun -ArgumentList @('-Scan', '-ScanType', '3', '-File', $probeDir) -OutputFile (Join-Path -Path $WorkDirectory -ChildPath 'defender-scan.out')
    $probeDetail = 'code={0}; {1}' -f $probe.ExitCode, (@($probe.Line | Select-Object -First 2) -join ' | ')
    $probeResult = if ($probe.ExitCode -in 0, 2) { 'usable' } else { 'failed' }
    Add-Finding -Backend 'Defender' -Check 'on demand scan probe' -Result $probeResult -Detail $probeDetail
}
else {
    Add-Finding -Backend 'Defender' -Check 'MpCmdRun.exe' -Result 'missing' -Detail 'no Defender platform binary found'
}

# ClamAV
$clamDir = @(
    'C:\Program Files\ClamAV'
    'C:\Program Files (x86)\ClamAV'
    'C:\ClamAV'
    'C:\clamav'
)

$clamScan = Find-Executable -Name 'clamscan.exe' -Directory $clamDir
$clamdScan = Find-Executable -Name 'clamdscan.exe' -Directory $clamDir
$clamDaemon = @(Get-Process -Name 'clamd' -ErrorAction Ignore)

if ($clamScan) {
    Add-Finding -Backend 'ClamAV' -Check 'clamscan.exe' -Result 'found' -Detail $clamScan
    $probe = Invoke-Probe -FilePath $clamScan -ArgumentList @('--version') -OutputFile (Join-Path -Path $WorkDirectory -ChildPath 'clamscan-version.out')
    Add-Finding -Backend 'ClamAV' -Check 'engine version' -Result ($probe.ExitCode -eq 0 ? 'ok' : 'failed') -Detail (@($probe.Line | Select-Object -First 1) -join '')
}
else {
    Add-Finding -Backend 'ClamAV' -Check 'clamscan.exe' -Result 'missing' -Detail 'install from clamav.net, then run freshclam'
}

if ($clamdScan) {
    Add-Finding -Backend 'ClamAV' -Check 'clamdscan.exe' -Result 'found' -Detail $clamdScan
}
else {
    Add-Finding -Backend 'ClamAV' -Check 'clamdscan.exe' -Result 'missing' -Detail 'daemon client not installed'
}

Add-Finding -Backend 'ClamAV' -Check 'clamd daemon' -Result ($clamDaemon.Count -gt 0 ? 'running' : 'stopped') -Detail ('instances: {0}' -f $clamDaemon.Count)

# Kaspersky Virus Removal Tool
$kvrtDir = @(
    'C:\KVRT'
    'C:\Tools'
    (Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads')
    'C:\mail\scripts\av'
)

$kvrt = Find-Executable -Name 'KVRT.exe' -Directory $kvrtDir

if ($kvrt) {
    Add-Finding -Backend 'KVRT' -Check 'KVRT.exe' -Result 'found' -Detail $kvrt
}
else {
    Add-Finding -Backend 'KVRT' -Check 'KVRT.exe' -Result 'missing' -Detail 'standalone scanner, download from kaspersky.com'
}

# Live detection test
if ($IncludeEicar) {
    $codeList = @(88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53, 52, 40, 80, 94, 41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84, 65, 78, 68, 65, 82, 68, 45, 65, 78, 84, 73, 86, 73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73, 76, 69, 33, 36, 72, 43, 72, 42)
    $pattern = -join ($codeList | ForEach-Object -Process { [char] $_ })
    $eicarFile = Join-Path -Path $probeDir -ChildPath 'eicar-test.eml'
    $body = 'From: probe@localhost' + [System.Environment]::NewLine + 'Subject: backend probe' + [System.Environment]::NewLine + [System.Environment]::NewLine + $pattern

    try {
        [System.IO.File]::WriteAllText($eicarFile, $body, [System.Text.UTF8Encoding]::new($false))
        Start-Sleep -Seconds 3
        $stillThere = Test-Path -LiteralPath $eicarFile -PathType Leaf
        $residentResult = if ($stillThere) { 'not intercepted' } else { 'intercepted' }
        Add-Finding -Backend 'Kaspersky' -Check 'real time interception' -Result $residentResult -Detail 'EICAR test message in the probe folder'

        if ($stillThere -and $clamdScan) {
            $probe = Invoke-Probe -FilePath $clamdScan -ArgumentList @('--no-summary', $eicarFile) -OutputFile (Join-Path -Path $WorkDirectory -ChildPath 'clamdscan-eicar.out')
            Add-Finding -Backend 'ClamAV' -Check 'EICAR detection' -Result ($probe.ExitCode -eq 1 ? 'detected' : 'not detected') -Detail ('code={0}; {1}' -f $probe.ExitCode, (@($probe.Line | Select-Object -First 1) -join ''))
        }
        elseif ($stillThere -and $clamScan) {
            $probe = Invoke-Probe -FilePath $clamScan -ArgumentList @('--no-summary', $eicarFile) -OutputFile (Join-Path -Path $WorkDirectory -ChildPath 'clamscan-eicar.out')
            Add-Finding -Backend 'ClamAV' -Check 'EICAR detection' -Result ($probe.ExitCode -eq 1 ? 'detected' : 'not detected') -Detail ('code={0}; {1}' -f $probe.ExitCode, (@($probe.Line | Select-Object -First 1) -join ''))
        }
    }
    catch {
        Add-Finding -Backend 'Kaspersky' -Check 'real time interception' -Result 'blocked write' -Detail $_.Exception.Message
    }
    finally {
        if (Test-Path -LiteralPath $eicarFile -PathType Leaf) {
            Remove-Item -LiteralPath $eicarFile -Force -ErrorAction Ignore
        }
    }
}

$csvPath = Join-Path -Path $WorkDirectory -ChildPath 'backend-report.csv'
$findings | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8

Write-Information -MessageData ''
Write-Information -MessageData ('summary CSV: {0}' -f $csvPath)

$usable = [System.Collections.Generic.List[string]]::new()

if ($findings | Where-Object -FilterScript { $_.Backend -eq 'Defender' -and $_.Check -eq 'on demand scan probe' -and $_.Result -eq 'usable' }) {
    $usable.Add('Defender via MpCmdRun.exe -Scan -ScanType 3 -File <path>')
}

if ($clamdScan -and $clamDaemon.Count -gt 0) {
    $usable.Add('ClamAV via clamdscan.exe with --file-list')
}
elseif ($clamScan) {
    $usable.Add('ClamAV via clamscan.exe with --file-list')
}

if ($kvrt) {
    $usable.Add('KVRT standalone scanner')
}

if ($usable.Count -gt 0) {
    Write-Information -MessageData 'Usable backend(s):'

    foreach ($item in $usable) {
        Write-Information -MessageData ('  * {0}' -f $item)
    }
}
else {
    Write-Warning -Message 'No usable on-demand backend was found. Install ClamAV for Windows and run freshclam, then repeat this test.'
}
