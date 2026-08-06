#Requires -Version 7.2
<#
.SYNOPSIS
    Scans an hMailServer message store with ClamAV and deletes infected
    messages through the hMailServer COM API.

.DESCRIPTION
    ClamAV is used strictly as a detector: the quarantine and removal options
    of clamscan and clamdscan are never passed, so the scanner never modifies
    the store. Every deletion is performed by this script through the
    hMailServer COM API, optionally after a quarantine copy.

    Two engines are supported. Clamd uses clamdscan against an already running
    clamd daemon, which loads signatures once. Clamscan loads signatures on
    every run and needs no daemon. Auto prefers clamdscan when a running daemon
    is detected.

    Scan scope is passed with --file-list, and the list file is written as UTF-8
    because the Windows build of ClamAV expects UTF-8 input. Console output is
    decoded as OEM, because ClamAV always writes console output in the OEM code
    page even when it is redirected to a file.

    Without Delete the script only produces reports. Infected files that cannot
    be matched to a hMailServer message record are removed only when both
    Delete and DeleteOrphan are supplied.

    Credentials are resolved before scanning, so an unattended run fails within
    seconds instead of after the scan.

.PARAMETER ClamRoot
    Directory that contains clamdscan.exe, clamscan.exe and freshclam.exe.

.PARAMETER ClamdScanPath
    Full path to clamdscan.exe; overrides ClamRoot.

.PARAMETER ClamScanPath
    Full path to clamscan.exe; overrides ClamRoot.

.PARAMETER FreshclamPath
    Full path to freshclam.exe; overrides ClamRoot.

.PARAMETER Engine
    Auto, Clamd or Clamscan.

.PARAMETER DataDirectory
    hMailServer Data directory; resolved from the registry when omitted.

.PARAMETER AdminPassword
    Password of the hMailServer administrative account. Accepts a string, a
    securestring or a PSCredential, which makes the output of Import-Clixml
    usable directly. The parameter is typed as object on purpose: a
    securestring bound to a string parameter is silently converted to the
    literal text System.Security.SecureString.

.PARAMETER AdminUser
    hMailServer account used for COM authentication. Ignored when a
    PSCredential that carries a user name is supplied.

.PARAMETER CredentialPath
    Explicit path to a credential file produced by Export-Clixml. When omitted,
    the HMAIL_CRED_PATH environment variable is used, and after that the script
    directory, creds, %ProgramData%\HMailClamAvCleanup and
    %LOCALAPPDATA%\HMailClamAvCleanup are searched for hmail*.cred.xml,
    cred.xml or credential.xml.

.PARAMETER NonInteractive
    Never prompt for a password. Use this for Task Scheduler runs so that a
    missing or unreadable credential file fails the run instead of blocking it
    on a prompt.

.PARAMETER ReportDirectory
    Root directory for per-run artifacts.

.PARAMETER QuarantineDirectory
    Root directory for quarantine copies; always excluded from the scan.

.PARAMETER SinceDays
    Scan only messages modified within this number of days; 0 scans everything.

.PARAMETER TimeoutMinutes
    Maximum runtime of a single scanner call; 0 waits indefinitely.

.PARAMETER MaxFileSizeMB
    Value for --max-filesize and --max-scansize when the Clamscan engine is used.

.PARAMETER MaxDebugLines
    Maximum number of report lines written to the trace log.

.PARAMETER Stream
    Make clamdscan send file contents to the daemon instead of paths. Use this
    when clamd runs under an account that cannot read the Data directory.

.PARAMETER UpdateDatabase
    Run freshclam before scanning.

.PARAMETER IncludeQueue
    Include files that live directly in the Data root, that is the queue.

.PARAMETER SkipQuarantine
    Delete without creating quarantine copies.

.PARAMETER DiagnoseOnly
    Only check the environment and scan a small probe directory.

.PARAMETER Delete
    Delete matched messages through the hMailServer COM API.

.PARAMETER DeleteOrphan
    Also delete infected files that have no hMailServer message record.

.EXAMPLE
    .\Invoke-HMailClamAvCleanup.ps1 -DiagnoseOnly -Debug

.EXAMPLE
    .\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Debug

.EXAMPLE
    .\Invoke-HMailClamAvCleanup.ps1 -Delete -Confirm:$false

.EXAMPLE
    $cred = Import-Clixml 'C:\mail\scripts\av\hmail.cred.xml'
    .\Invoke-HMailClamAvCleanup.ps1 -AdminPassword $cred -NonInteractive -Delete -Confirm:$false

.EXAMPLE
    # Unattended: the credential file is discovered automatically.
    .\Invoke-HMailClamAvCleanup.ps1 -NonInteractive -Delete -DeleteOrphan -Confirm:$false

.NOTES
    Author:     Mikhail Deynekin <git@deynekin.com>
    Site:       https://deynekin.com/
    Repository: https://github.com/paulmann/hmailserver-clamav-cleanup
    Updated:    2026-08-06

    Run elevated. Back up the hMailServer database and Data directory first.
    Exclude the quarantine directory from any resident antivirus before using
    Delete.

    Create the credential file while logged on as the account that runs the
    scheduled task, because Export-Clixml protects the secret with DPAPI and
    binds it to one user on one machine:

        Get-Credential -UserName 'Administrator' |
            Export-Clixml "$env:ProgramData\HMailClamAvCleanup\hmail.cred.xml"

.LINK
    https://github.com/paulmann/hmailserver-clamav-cleanup

.LINK
    https://deynekin.com/
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ClamRoot = 'C:\Program Files\ClamAV',

    [string] $ClamdScanPath,

    [string] $ClamScanPath,

    [string] $FreshclamPath,

    [ValidateSet('Auto', 'Clamd', 'Clamscan')]
    [string] $Engine = 'Auto',

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string] $DataDirectory,

    [AllowNull()]
    [object] $AdminPassword,

    [ValidateNotNullOrEmpty()]
    [string] $AdminUser = 'Administrator',

    [string] $CredentialPath,

    [switch] $NonInteractive,

    [string] $ReportDirectory = 'C:\mail\reports\clamav',

    [string] $QuarantineDirectory = 'C:\mail\quarantine',

    [ValidateRange(0, 3650)]
    [int] $SinceDays = 0,

    [ValidateRange(0, 1440)]
    [int] $TimeoutMinutes = 240,

    [ValidateRange(1, 4096)]
    [int] $MaxFileSizeMB = 100,

    [ValidateRange(10, 5000)]
    [int] $MaxDebugLines = 120,

    [switch] $Stream,

    [switch] $UpdateDatabase,

    [switch] $IncludeQueue,

    [switch] $SkipQuarantine,

    [switch] $DiagnoseOnly,

    [switch] $Delete,

    [switch] $DeleteOrphan
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

if ($PSBoundParameters.ContainsKey('Debug')) {
    $DebugPreference = 'Continue'
}

if (-not $IsWindows) {
    throw 'This script requires Windows: it uses the registry and the hMailServer COM API.'
}

try {
    [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
}
catch {
    Write-Debug ('code page provider not registered: {0}' -f $_.Exception.Message)
}

$script:DebugFile = $null

#region Infrastructure

function Write-Stage {
    <#
    .SYNOPSIS
        Writes a progress line to the information stream and the run log.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Message
    )

    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message
    Write-Information -MessageData $line

    if ($script:DebugFile) {
        try {
            Add-Content -LiteralPath $script:DebugFile -Value $line -Encoding utf8
        }
        catch {
            Write-Debug ('run log not written: {0}' -f $_.Exception.Message)
        }
    }
}

function Write-Trace {
    <#
    .SYNOPSIS
        Writes a diagnostic line to the debug stream and the run log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [string] $Category = 'trace'
    )

    $line = '[{0:HH:mm:ss.fff}] [{1}] {2}' -f (Get-Date), $Category, $Message
    Write-Debug -Message $line

    if ($script:DebugFile) {
        try {
            Add-Content -LiteralPath $script:DebugFile -Value $line -Encoding utf8
        }
        catch {
            Write-Debug ('run log not written: {0}' -f $_.Exception.Message)
        }
    }
}

function Write-TraceBlock {
    <#
    .SYNOPSIS
        Dumps a bounded number of text lines into the trace log.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Line,

        [int] $Limit = 50
    )

    $all = @()

    if ($null -ne $Line) {
        $all = @($Line)
    }

    Write-Trace -Message ('--- {0} ({1} line(s)) ---' -f $Title, $all.Count) -Category 'dump'
    $shown = 0

    foreach ($entry in $all) {
        if ($shown -ge $Limit) {
            Write-Trace -Message ('... truncated at {0} line(s)' -f $Limit) -Category 'dump'
            break
        }

        Write-Trace -Message ('  {0}' -f $entry) -Category 'dump'
        $shown = $shown + 1
    }
}

function Get-PlainText {
    <#
    .SYNOPSIS
        Converts a secure string into its plain text form.
    #>
    param(
        [AllowNull()]
        [securestring] $Secure
    )

    if ($null -eq $Secure) {
        return $null
    }

    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Get-OemEncoding {
    <#
    .SYNOPSIS
        Returns the console OEM encoding that ClamAV uses for console output.
    #>
    param()

    try {
        $codePage = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
        return [System.Text.Encoding]::GetEncoding($codePage)
    }
    catch {
        Write-Debug ('OEM code page unavailable: {0}' -f $_.Exception.Message)
        return [System.Text.Encoding]::Default
    }
}

function Split-TextLine {
    <#
    .SYNOPSIS
        Splits text into lines for any combination of CR and LF.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    if ($Text.Length -eq 0) {
        return , ([string[]] @())
    }

    $fragment = [regex]::Split($Text, '\r\n|\n|\r|\x00')
    $kept = [System.Collections.Generic.List[string]]::new()

    foreach ($piece in $fragment) {
        if ($null -eq $piece) {
            continue
        }

        $trimmed = $piece.Trim()

        if ($trimmed.Length -eq 0) {
            continue
        }

        if ($trimmed -match '^-{5,}$') {
            continue
        }

        $kept.Add($trimmed)
    }

    return , ([string[]] $kept.ToArray())
}

function Read-TextLine {
    <#
    .SYNOPSIS
        Reads a text file, detecting byte order marks and UTF-16 without a mark.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [ValidateSet('Oem', 'Utf8')]
        [string] $FallbackEncoding = 'Utf8',

        [switch] $TraceEncoding
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($TraceEncoding) {
            Write-Trace -Message ('file missing: {0}' -f $Path) -Category 'report'
        }

        return , ([string[]] @())
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    if ($TraceEncoding) {
        Write-Trace -Message ('file {0}: {1:N0} byte(s)' -f $Path, $bytes.Length) -Category 'report'
    }

    if ($bytes.Length -eq 0) {
        return , ([string[]] @())
    }

    $encoding = $null
    $offset = 0
    $hasUtf8Mark = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $hasUtf16Mark = $bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE

    if ($hasUtf8Mark) {
        $encoding = [System.Text.Encoding]::UTF8
        $offset = 3
    }
    elseif ($hasUtf16Mark) {
        $encoding = [System.Text.Encoding]::Unicode
        $offset = 2
    }
    elseif ($FallbackEncoding -eq 'Oem') {
        $encoding = Get-OemEncoding
    }
    else {
        $encoding = [System.Text.UTF8Encoding]::new($false, $false)
    }

    if ($TraceEncoding) {
        Write-Trace -Message ('encoding: {0}' -f $encoding.WebName) -Category 'report'
    }

    $text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset)
    $decoded = @(Split-TextLine -Text $text)

    if ($TraceEncoding) {
        Write-Trace -Message ('decoded lines: {0}' -f $decoded.Count) -Category 'report'
    }

    return , ([string[]] $decoded)
}

function Get-NormalizedPath {
    <#
    .SYNOPSIS
        Returns an absolute path, or the original value when normalization fails.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Path
    )

    if ($Path.Length -eq 0) {
        return $Path
    }

    try {
        return [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        Write-Debug ('path not normalized: {0}' -f $_.Exception.Message)
        return $Path
    }
}

function Test-PathUnderRoot {
    <#
    .SYNOPSIS
        Tests whether a path is located inside a root directory.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Root
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $trimmedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        $fullRoot = $trimmedRoot + [System.IO.Path]::DirectorySeparatorChar
        return $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        Write-Debug ('path comparison failed: {0}' -f $_.Exception.Message)
        return $false
    }
}

function Format-ArgumentForLog {
    <#
    .SYNOPSIS
        Renders an argument list for logging.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $ArgumentList
    )

    $parts = foreach ($argument in @($ArgumentList)) {
        if ($argument -match '\s') {
            '"{0}"' -f $argument
        }
        else {
            $argument
        }
    }

    return (@($parts) -join ' ')
}

#endregion

#region Resolvers

function Resolve-ClamBinary {
    <#
    .SYNOPSIS
        Locates a ClamAV executable from an explicit path, a root or PATH.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [AllowNull()]
        [string] $Explicit,

        [AllowNull()]
        [string] $Root,

        [switch] $Required
    )

    if ($Explicit) {
        $item = Get-Item -LiteralPath $Explicit

        if ($item.PSIsContainer) {
            throw ('The path for {0} points to a directory: {1}' -f $Name, $Explicit)
        }

        Write-Trace -Message ('using explicit {0}: {1}' -f $Name, $item.FullName) -Category 'resolve'
        return $item.FullName
    }

    if ($Root) {
        $candidate = Join-Path -Path $Root -ChildPath $Name

        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Write-Trace -Message ('found {0} in the ClamAV root' -f $Name) -Category 'resolve'
            return (Get-Item -LiteralPath $candidate).FullName
        }
    }

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Ignore | Select-Object -First 1

    if ($command) {
        Write-Trace -Message ('found {0} in PATH: {1}' -f $Name, $command.Source) -Category 'resolve'
        return $command.Source
    }

    if ($Required) {
        throw ('{0} was not found. Pass an explicit path or a correct ClamRoot.' -f $Name)
    }

    Write-Trace -Message ('{0} not found' -f $Name) -Category 'resolve'
    return $null
}

function Resolve-HMailDataDirectory {
    <#
    .SYNOPSIS
        Resolves the hMailServer Data directory from the registry or the INI file.
    #>
    param(
        [AllowNull()]
        [string] $Explicit
    )

    if ($Explicit) {
        return (Get-Item -LiteralPath $Explicit).FullName
    }

    $keyList = @('HKLM:\SOFTWARE\WOW6432Node\hMailServer', 'HKLM:\SOFTWARE\hMailServer')

    foreach ($key in $keyList) {
        $property = Get-ItemProperty -Path $key -Name 'InstallLocation' -ErrorAction Ignore
        $install = $null

        if ($null -ne $property) {
            $install = $property.InstallLocation
        }

        if (-not $install) {
            Write-Trace -Message ('no InstallLocation under {0}' -f $key) -Category 'resolve'
            continue
        }

        Write-Trace -Message ('hMailServer install: {0} (from {1})' -f $install, $key) -Category 'resolve'
        $ini = Join-Path -Path $install -ChildPath 'Bin\hMailServer.INI'

        if (Test-Path -LiteralPath $ini -PathType Leaf) {
            $match = Select-String -LiteralPath $ini -Pattern '^\s*DataDir\s*=\s*(.+)$' -ErrorAction Ignore | Select-Object -First 1

            if ($match) {
                $raw = $match.Matches[0].Groups[1].Value.Trim().Trim('"')
                $dir = [System.Environment]::ExpandEnvironmentVariables($raw)
                Write-Trace -Message ('DataDir from INI: {0}' -f $dir) -Category 'resolve'

                if (Test-Path -LiteralPath $dir -PathType Container) {
                    return (Get-Item -LiteralPath $dir).FullName
                }
            }
        }

        $fallback = Join-Path -Path $install -ChildPath 'Data'

        if (Test-Path -LiteralPath $fallback -PathType Container) {
            return (Get-Item -LiteralPath $fallback).FullName
        }
    }

    throw 'Could not determine the hMailServer Data directory. Pass DataDirectory explicitly.'
}

function Get-HMailCredentialFile {
    <#
    .SYNOPSIS
        Finds a stored credential file in the conventional locations.
    .DESCRIPTION
        The newest match wins, so a freshly exported file takes precedence over
        a stale one left in the same directory.
    #>
    param()

    $candidateRoot = @(
        $PSScriptRoot
        (Join-Path -Path $PSScriptRoot -ChildPath 'creds')
        (Join-Path -Path $env:ProgramData -ChildPath 'HMailClamAvCleanup')
        (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'HMailClamAvCleanup')
    )

    foreach ($root in $candidateRoot) {
        if (-not $root) {
            continue
        }

        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        $found = @(Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue |
            Where-Object -FilterScript { $_.Name -match '^(hmail.*\.cred|cred(ential)?)\.xml$' } |
            Sort-Object -Property LastWriteTimeUtc -Descending)

        if ($found.Count -gt 0) {
            Write-Trace -Message ('credential file discovered: {0}' -f $found[0].FullName) -Category 'auth'
            return $found[0].FullName
        }

        Write-Trace -Message ('no credential file under {0}' -f $root) -Category 'auth'
    }

    return $null
}

function Test-HMailCredentialAcl {
    <#
    .SYNOPSIS
        Warns when a credential file is readable by a broad group.
    .DESCRIPTION
        Well known SIDs are compared instead of names so the check works on a
        localized Windows installation.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    try {
        $broad = @(
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null).Value
            [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null).Value
        )

        foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

            if ($broad -contains $sid) {
                Write-Warning -Message ('Credential file {0} grants access to {1}; tighten the ACL.' -f $Path, $rule.IdentityReference)
                return $false
            }
        }
    }
    catch {
        Write-Trace -Message ('ACL check skipped for {0}: {1}' -f $Path, $_.Exception.Message) -Category 'auth'
    }

    return $true
}

function Import-HMailCredentialFile {
    <#
    .SYNOPSIS
        Reads a credential file produced by Export-Clixml.
    .DESCRIPTION
        Export-Clixml protects the secret with DPAPI, so the file can only be
        decrypted by the same user on the same machine that created it. Under
        Task Scheduler the file must therefore be created while logged on as
        the account that runs the task.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('Credential file not found: {0}' -f $Path)
    }

    $null = Test-HMailCredentialAcl -Path $Path

    try {
        $imported = Import-Clixml -LiteralPath $Path
    }
    catch {
        throw ('Cannot read {0}: {1}. Export-Clixml output is bound to one user on one machine; recreate the file while logged on as {2}.' -f $Path, $_.Exception.Message, [System.Environment]::UserName)
    }

    if ($null -eq $imported) {
        throw ('Credential file {0} is empty.' -f $Path)
    }

    Write-Trace -Message ('credential loaded from {0} as {1}' -f $Path, $imported.GetType().FullName) -Category 'auth'
    return $imported
}

function Resolve-HMailAdminCredential {
    <#
    .SYNOPSIS
        Normalizes any supported secret shape into a PSCredential.
    .DESCRIPTION
        Resolution order: the value passed to AdminPassword, an explicit
        credential path, the HMAIL_CRED_PATH environment variable, a credential
        file found in the conventional locations, and finally an interactive
        prompt. Prompting is refused when NoPrompt is set, which keeps an
        unattended run from blocking forever.
    #>
    param(
        [AllowNull()]
        [object] $Secret,

        [Parameter(Mandatory)]
        [string] $UserName,

        [AllowNull()]
        [string] $Path,

        [bool] $NoPrompt = $false
    )

    $resolvedUser = $UserName
    $value = $Secret

    if ($null -eq $value) {
        $file = $Path

        if (-not $file -and $env:HMAIL_CRED_PATH) {
            $file = $env:HMAIL_CRED_PATH
            Write-Trace -Message 'credential path taken from HMAIL_CRED_PATH' -Category 'auth'
        }

        if (-not $file) {
            $file = Get-HMailCredentialFile
        }

        if ($file) {
            $value = Import-HMailCredentialFile -Path $file
        }
    }
    else {
        Write-Trace -Message ('credential supplied on the command line as {0}' -f $value.GetType().FullName) -Category 'auth'
    }

    $secure = $null

    if ($value -is [System.Management.Automation.PSCredential]) {
        if ($value.UserName) {
            $resolvedUser = $value.UserName
        }

        $secure = $value.Password
    }
    elseif ($value -is [securestring]) {
        $secure = $value
    }
    elseif ($value -is [string]) {
        if ($value.Length -gt 0) {
            $secure = ConvertTo-SecureString -String $value -AsPlainText -Force
        }
    }
    elseif ($null -ne $value) {
        throw ('Unsupported credential type {0}. Pass a string, a securestring or a PSCredential.' -f $value.GetType().FullName)
    }

    if ($null -eq $secure) {
        if ($NoPrompt) {
            throw 'No hMailServer password was supplied, no credential file was found, and NonInteractive is set.'
        }

        $secure = Read-Host -AsSecureString -Prompt ('Password for {0}' -f $resolvedUser)
    }

    return [System.Management.Automation.PSCredential]::new($resolvedUser, $secure)
}

function Write-EnvironmentDiagnostic {
    <#
    .SYNOPSIS
        Logs interpreter, identity, engine and signature facts before scanning.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Scanner,

        [AllowNull()]
        [string] $DatabaseDirectory
    )

    Write-Trace -Message ('pwsh {0} / {1} / PID {2}' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $PID) -Category 'env'
    $bitness = 32

    if ([System.Environment]::Is64BitProcess) {
        $bitness = 64
    }

    Write-Trace -Message ('process bitness: {0}-bit; OS: {1}' -f $bitness, [System.Environment]::OSVersion.VersionString) -Category 'env'
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Trace -Message ('identity: {0}; elevated: {1}' -f $identity.Name, $elevated) -Category 'env'

    if (-not $elevated) {
        Write-Warning -Message 'Not running elevated; reading the message store or the COM API may fail.'
    }

    $item = Get-Item -LiteralPath $Scanner
    Write-Trace -Message ('scanner: {0}, version {1}, modified {2:yyyy-MM-dd}' -f $item.FullName, $item.VersionInfo.FileVersion, $item.LastWriteTime) -Category 'env'
    $daemon = @(Get-Process -Name 'clamd' -ErrorAction Ignore)
    Write-Trace -Message ('clamd instances: {0}' -f $daemon.Count) -Category 'env'

    if ($DatabaseDirectory -and (Test-Path -LiteralPath $DatabaseDirectory -PathType Container)) {
        $signature = @(Get-ChildItem -LiteralPath $DatabaseDirectory -File -ErrorAction Ignore | Where-Object -FilterScript { $_.Extension -in '.cvd', '.cld' })

        foreach ($file in $signature) {
            Write-Trace -Message ('signature {0}: {1:N0} byte(s), {2:yyyy-MM-dd HH:mm}' -f $file.Name, $file.Length, $file.LastWriteTime) -Category 'env'
        }

        if ($signature.Count -eq 0) {
            Write-Warning -Message ('No signature database found in {0}; run freshclam first.' -f $DatabaseDirectory)
        }
        else {
            $newest = $signature | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
            $ageDays = [Math]::Round(((Get-Date) - $newest.LastWriteTime).TotalDays, 1)

            if ($ageDays -gt 7) {
                Write-Warning -Message ('Signature database is {0} day(s) old; run this script with UpdateDatabase.' -f $ageDays)
            }
        }
    }
}

#endregion

#region Scanner

function Wait-NativeProcess {
    <#
    .SYNOPSIS
        Waits for a native process and kills the tree on timeout.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process] $Process,

        [int] $TimeoutMinutes = 240,

        [string] $Name = 'process'
    )

    $completed = $true

    if ($TimeoutMinutes -gt 0) {
        $completed = $Process.WaitForExit([int]($TimeoutMinutes * 60 * 1000))
    }
    else {
        $Process.WaitForExit()
    }

    if (-not $completed) {
        try {
            $Process.Kill($true)
        }
        catch {
            Write-Debug ('process tree not killed: {0}' -f $_.Exception.Message)
        }

        try {
            $Process.WaitForExit()
        }
        catch {
            Write-Debug ('wait after kill failed: {0}' -f $_.Exception.Message)
        }

        throw ('{0} did not finish within {1} minute(s).' -f $Name, $TimeoutMinutes)
    }

    $Process.WaitForExit()
}

function Invoke-ClamProcess {
    <#
    .SYNOPSIS
        Runs a ClamAV executable and captures its OEM encoded console output.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $ArgumentList,

        [Parameter(Mandatory)]
        [string] $StdOutFile,

        [int] $TimeoutMinutes = 240
    )

    $argumentValue = @($ArgumentList)
    $errorFile = '{0}.err' -f $StdOutFile

    foreach ($file in @($StdOutFile, $errorFile)) {
        if (Test-Path -LiteralPath $file) {
            Remove-Item -LiteralPath $file -Force
        }
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = (Split-Path -Path $FilePath -Parent)
    $startInfo.StandardOutputEncoding = Get-OemEncoding
    $startInfo.StandardErrorEncoding = Get-OemEncoding

    foreach ($argument in $argumentValue) {
        $null = $startInfo.ArgumentList.Add($argument)
    }

    Write-Trace -Message ('exec: {0} {1}' -f $FilePath, (Format-ArgumentForLog -ArgumentList $argumentValue)) -Category 'exec'
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = -1
    $outputLine = [string[]] @()
    $errorLine = [string[]] @()
    $utf8 = [System.Text.UTF8Encoding]::new($false)

    try {
        if (-not $process.Start()) {
            throw ('Failed to start {0}' -f $FilePath)
        }

        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        Wait-NativeProcess -Process $process -TimeoutMinutes $TimeoutMinutes -Name (Split-Path -Path $FilePath -Leaf)
        $exitCode = $process.ExitCode
        $outputText = $outputTask.GetAwaiter().GetResult()
        $errorText = $errorTask.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($StdOutFile, $outputText, $utf8)
        [System.IO.File]::WriteAllText($errorFile, $errorText, $utf8)
        $outputLine = [string[]] @(Split-TextLine -Text $outputText)
        $errorLine = [string[]] @(Split-TextLine -Text $errorText)
    }
    finally {
        $stopwatch.Stop()
        $process.Dispose()
    }

    if (@($errorLine).Count -gt 0) {
        Write-TraceBlock -Title 'stderr' -Line $errorLine -Limit 30
    }

    Write-Trace -Message ('exit={0} elapsed={1:hh\:mm\:ss} stdout lines={2}' -f $exitCode, $stopwatch.Elapsed, @($outputLine).Count) -Category 'exec'

    return [pscustomobject]@{
        ExitCode = [int] $exitCode
        StdOutFile = $StdOutFile
        Line = [string[]] $outputLine
        ErrorLine = [string[]] $errorLine
        Elapsed = $stopwatch.Elapsed
    }
}

function Update-ClamDatabase {
    <#
    .SYNOPSIS
        Runs freshclam and reports the outcome.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Freshclam,

        [Parameter(Mandatory)]
        [string] $StdOutFile,

        [int] $TimeoutMinutes = 30
    )

    $result = Invoke-ClamProcess -FilePath $Freshclam -ArgumentList @() -StdOutFile $StdOutFile -TimeoutMinutes $TimeoutMinutes
    Write-TraceBlock -Title 'freshclam output' -Line $result.Line -Limit 40

    if ($result.ExitCode -eq 0) {
        Write-Stage -Message 'signature database is up to date'
    }
    else {
        Write-Warning -Message ('freshclam returned {0}; continuing with the current database.' -f $result.ExitCode)
    }

    return $result
}

function Invoke-ClamScan {
    <#
    .SYNOPSIS
        Scans a file list or a directory with clamdscan or clamscan.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Scanner,

        [Parameter(Mandatory)]
        [ValidateSet('Clamd', 'Clamscan')]
        [string] $Kind,

        [AllowNull()]
        [string] $FileList,

        [AllowNull()]
        [string] $Directory,

        [Parameter(Mandatory)]
        [string] $LogFile,

        [Parameter(Mandatory)]
        [string] $StdOutFile,

        [AllowNull()]
        [string] $ExcludeDirectory,

        [int] $MaxFileSizeMB = 100,

        [int] $TimeoutMinutes = 240,

        [switch] $UseStream
    )

    if (-not $FileList -and -not $Directory) {
        throw 'Invoke-ClamScan requires either FileList or Directory.'
    }

    $argumentList = [System.Collections.Generic.List[string]]::new()
    $argumentList.Add('--no-summary')
    $argumentList.Add(('--log={0}' -f $LogFile))

    if ($Kind -eq 'Clamscan') {
        $argumentList.Add('--recursive')
        $argumentList.Add('--stdout')
        $argumentList.Add(('--max-filesize={0}M' -f $MaxFileSizeMB))
        $argumentList.Add(('--max-scansize={0}M' -f ($MaxFileSizeMB * 4)))
        $argumentList.Add('--alert-encrypted=no')

        if ($ExcludeDirectory) {
            $escaped = [regex]::Escape($ExcludeDirectory)
            $argumentList.Add(('--exclude-dir={0}' -f $escaped))
        }
    }
    else {
        $argumentList.Add('--multiscan')

        if ($UseStream) {
            $argumentList.Add('--stream')
        }
    }

    if ($FileList) {
        $argumentList.Add(('--file-list={0}' -f $FileList))
    }
    else {
        $argumentList.Add($Directory)
    }

    $result = Invoke-ClamProcess -FilePath $Scanner -ArgumentList $argumentList.ToArray() -StdOutFile $StdOutFile -TimeoutMinutes $TimeoutMinutes
    $reportLine = @($result.Line)

    if ($reportLine.Count -eq 0 -and (Test-Path -LiteralPath $LogFile -PathType Leaf)) {
        Write-Trace -Message 'console output was empty; reading the log file' -Category 'report'
        $reportLine = @(Read-TextLine -Path $LogFile -FallbackEncoding 'Oem' -TraceEncoding)
    }

    return [pscustomobject]@{
        ExitCode = $result.ExitCode
        Line = [string[]] $reportLine
        ErrorLine = [string[]] $result.ErrorLine
        Elapsed = $result.Elapsed
        LogFile = $LogFile
        StdOutFile = $result.StdOutFile
        Kind = $Kind
    }
}

function Test-ClamExitCode {
    <#
    .SYNOPSIS
        Interprets a ClamAV exit code; 0 is clean, 1 means detections, 2 is an error.
    #>
    param(
        [Parameter(Mandatory)]
        [int] $Code,

        [int] $HitCount = 0,

        [string] $Operation = 'scan'
    )

    if ($Code -eq 0) {
        Write-Stage -Message ('{0} finished, no detections (0)' -f $Operation)
        return
    }

    if ($Code -eq 1) {
        Write-Stage -Message ('{0} finished, detections reported (1)' -f $Operation)
        return
    }

    if ($Code -eq 2) {
        if ($HitCount -gt 0) {
            Write-Warning -Message ('{0} reported errors (2) but {1} detection(s) were parsed; continuing with a partial report.' -f $Operation, $HitCount)
            return
        }

        throw ('ClamAV {0} failed with code 2 and produced no detection. Check that clamd is running, signatures are present, and the scanner can read the target paths.' -f $Operation)
    }

    throw ('ClamAV {0} returned unexpected exit code {1}.' -f $Operation, $Code)
}

function Convert-ClamOutput {
    <#
    .SYNOPSIS
        Extracts verdicts from ClamAV output without relying on line separators.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]] $Line,

        [int] $DebugLimit = 120
    )

    $all = @()

    if ($null -ne $Line) {
        $all = @($Line)
    }

    $text = $all -join "`n"
    $foundPattern = '(?<path>[A-Za-z]:\\[^\r\n\x00]*?):\s+(?<verdict>[^\r\n\x00:]+?)\s+FOUND\b'
    $errorPattern = '(?<path>[A-Za-z]:\\[^\r\n\x00]*?):\s+(?<reason>[^\r\n\x00:]+?)\s+ERROR\b'
    $cleanPattern = '(?<path>[A-Za-z]:\\[^\r\n\x00]*?):\s+OK\b'
    $hitByPath = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $errorEntry = [System.Collections.Generic.List[string]]::new()
    $cleanPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($match in [regex]::Matches($text, $foundPattern)) {
        $path = $match.Groups['path'].Value.Trim()

        $hitByPath[$path] = [pscustomobject]@{
            Path = $path
            Verdict = $match.Groups['verdict'].Value.Trim()
            FileName = [System.IO.Path]::GetFileName($path)
        }
    }

    foreach ($match in [regex]::Matches($text, $errorPattern)) {
        if ($errorEntry.Count -ge $DebugLimit) {
            break
        }

        $errorEntry.Add(('{0}: {1} ERROR' -f $match.Groups['path'].Value.Trim(), $match.Groups['reason'].Value.Trim()))
    }

    foreach ($match in [regex]::Matches($text, $cleanPattern)) {
        $null = $cleanPath.Add($match.Groups['path'].Value.Trim())
    }

    return @{
        Hit = @(@($hitByPath.Values) | Sort-Object -Property Path)
        ErrorLine = @($errorEntry)
        CleanCount = $cleanPath.Count
    }
}

function Get-HitIndex {
    <#
    .SYNOPSIS
        Builds path and unique file name lookups for parsed detections.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Hit
    )

    $byPath = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $leafGroup = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in @($Hit)) {
        $normalized = Get-NormalizedPath -Path ([string] $entry.Path)
        $byPath[$normalized] = $entry
        $leaf = [string] $entry.FileName

        if (-not $leafGroup.ContainsKey($leaf)) {
            $leafGroup[$leaf] = [System.Collections.Generic.List[object]]::new()
        }

        $leafGroup[$leaf].Add($entry)
    }

    $byUniqueLeaf = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($group in $leafGroup.GetEnumerator()) {
        if ($group.Value.Count -eq 1) {
            $byUniqueLeaf[$group.Key] = $group.Value[0]
        }
        else {
            Write-Warning -Message ('File name {0} occurs more than once; name-only matching is disabled for it.' -f $group.Key)
        }
    }

    return [pscustomobject]@{
        ByPath = $byPath
        ByUniqueLeaf = $byUniqueLeaf
    }
}

#endregion

#region hMailServer

function Get-MessageFile {
    <#
    .SYNOPSIS
        Enumerates .eml files in the message store, optionally including the queue.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [int] $NewerThanDays = 0,

        [bool] $WithQueue = $false,

        [AllowNull()]
        [string] $ExcludeDirectory
    )

    $cutoff = [datetime]::MinValue

    if ($NewerThanDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$NewerThanDays)
    }

    $normalizedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    Write-Trace -Message ('enumerating {0}; cutoff {1:yyyy-MM-dd HH:mm}; queue included: {2}' -f $Root, $cutoff, $WithQueue) -Category 'scan'
    $all = @(Get-ChildItem -LiteralPath $Root -Filter '*.eml' -File -Recurse -Force -ErrorAction SilentlyContinue)
    $selected = [System.Collections.Generic.List[object]]::new()

    foreach ($file in $all) {
        if ($file.LastWriteTime -lt $cutoff) {
            continue
        }

        $directory = [System.IO.Path]::GetFullPath($file.DirectoryName).TrimEnd('\', '/')

        if (-not $WithQueue -and $directory -eq $normalizedRoot) {
            continue
        }

        if ($ExcludeDirectory -and (Test-PathUnderRoot -Path $file.FullName -Root $ExcludeDirectory)) {
            continue
        }

        $selected.Add($file)
    }

    return $selected
}

function Find-InfectedMessage {
    <#
    .SYNOPSIS
        Matches hMailServer messages against detections through the COM API.
    #>
    param(
        [Parameter(Mandatory)]
        $Application,

        [Parameter(Mandatory)]
        $HitIndex
    )

    $matched = [System.Collections.Generic.List[object]]::new()
    $scanned = 0
    $domainCollection = $Application.Domains
    Write-Trace -Message ('domains: {0}' -f $domainCollection.Count) -Category 'com'

    for ($domainIndex = 0; $domainIndex -lt $domainCollection.Count; $domainIndex++) {
        $domain = $domainCollection.Item($domainIndex)
        $accountCollection = $domain.Accounts
        Write-Trace -Message ('domain {0}: {1} account(s)' -f $domain.Name, $accountCollection.Count) -Category 'com'

        for ($accountIndex = 0; $accountIndex -lt $accountCollection.Count; $accountIndex++) {
            $account = $accountCollection.Item($accountIndex)
            $before = $matched.Count
            $work = [System.Collections.Generic.List[object]]::new()
            $work.Add([pscustomobject]@{ Message = $account.Messages; Folder = 'INBOX' })
            $pending = [System.Collections.Generic.Stack[object]]::new()
            $pending.Push([pscustomobject]@{ Folder = $account.IMAPFolders; Prefix = '' })

            while ($pending.Count -gt 0) {
                $node = $pending.Pop()

                for ($folderIndex = 0; $folderIndex -lt $node.Folder.Count; $folderIndex++) {
                    $folder = $node.Folder.Item($folderIndex)
                    $name = [string] $folder.Name

                    if ($node.Prefix) {
                        $name = '{0}/{1}' -f $node.Prefix, $folder.Name
                    }

                    $work.Add([pscustomobject]@{ Message = $folder.Messages; Folder = $name })
                    $pending.Push([pscustomobject]@{ Folder = $folder.SubFolders; Prefix = $name })
                }
            }

            foreach ($item in $work) {
                $collection = $item.Message

                for ($messageIndex = 0; $messageIndex -lt $collection.Count; $messageIndex++) {
                    $message = $collection.Item($messageIndex)
                    $scanned = $scanned + 1
                    $messageFile = [string] $message.Filename
                    $hit = $null

                    if ($messageFile) {
                        $normalized = Get-NormalizedPath -Path $messageFile

                        if ($HitIndex.ByPath.ContainsKey($normalized)) {
                            $hit = $HitIndex.ByPath[$normalized]
                        }
                        else {
                            $leaf = [System.IO.Path]::GetFileName($messageFile)

                            if ($HitIndex.ByUniqueLeaf.ContainsKey($leaf)) {
                                $hit = $HitIndex.ByUniqueLeaf[$leaf]
                            }
                        }
                    }

                    if ($null -eq $hit) {
                        continue
                    }

                    $matched.Add([pscustomobject]@{
                        Account = $account.Address
                        Folder = $item.Folder
                        MessageId = $message.ID
                        Date = $message.Date
                        From = $message.FromAddress
                        Subject = $message.Subject
                        SizeKB = [Math]::Round($message.Size / 1KB, 1)
                        Verdict = $hit.Verdict
                        File = $hit.Path
                        ComFile = $messageFile
                        Collection = $collection
                    })
                }
            }

            Write-Trace -Message ('  {0}: +{1} hit(s)' -f $account.Address, ($matched.Count - $before)) -Category 'com'
        }
    }

    Write-Trace -Message ('messages inspected via COM: {0}' -f $scanned) -Category 'com'
    return $matched
}

#endregion

#region Main

$started = Get-Date
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$application = $null
$transcriptStarted = $false
$quarantine = $null
$credential = $null
$null = New-Item -ItemType Directory -Force -Path $ReportDirectory
$workDir = Join-Path -Path $ReportDirectory -ChildPath ('run-{0}' -f $stamp)
$null = New-Item -ItemType Directory -Force -Path $workDir
$script:DebugFile = Join-Path -Path $workDir -ChildPath 'debug.log'

try {
    try {
        $null = Start-Transcript -LiteralPath (Join-Path -Path $workDir -ChildPath 'transcript.log') -Force
        $transcriptStarted = $true
    }
    catch {
        Write-Warning -Message $_.Exception.Message
    }

    $shownParameter = @($PSBoundParameters.GetEnumerator() | Where-Object -FilterScript { $_.Key -notlike '*Password*' } | ForEach-Object -Process { '{0}={1}' -f $_.Key, $_.Value })
    Write-Trace -Message ('parameters: {0}' -f ($shownParameter -join '; ')) -Category 'init'
    Write-Trace -Message ('run directory: {0}' -f $workDir) -Category 'init'

    if (-not $DiagnoseOnly) {
        $credential = Resolve-HMailAdminCredential -Secret $AdminPassword -UserName $AdminUser -Path $CredentialPath -NoPrompt $NonInteractive.IsPresent
        Write-Trace -Message ('COM identity resolved before scanning: {0}' -f $credential.UserName) -Category 'auth'
    }

    $clamdScan = Resolve-ClamBinary -Name 'clamdscan.exe' -Explicit $ClamdScanPath -Root $ClamRoot
    $clamScan = Resolve-ClamBinary -Name 'clamscan.exe' -Explicit $ClamScanPath -Root $ClamRoot
    $daemonRunning = @(Get-Process -Name 'clamd' -ErrorAction Ignore).Count -gt 0
    $scanner = $null
    $engineKind = 'Clamscan'

    if ($Engine -eq 'Clamd') {
        if (-not $clamdScan) {
            throw 'clamdscan.exe was not found, but Engine Clamd was requested.'
        }

        $scanner = $clamdScan
        $engineKind = 'Clamd'
    }
    elseif ($Engine -eq 'Clamscan') {
        if (-not $clamScan) {
            throw 'clamscan.exe was not found, but Engine Clamscan was requested.'
        }

        $scanner = $clamScan
    }
    else {
        if ($clamdScan -and $daemonRunning) {
            $scanner = $clamdScan
            $engineKind = 'Clamd'
        }
        elseif ($clamScan) {
            $scanner = $clamScan
        }
        elseif ($clamdScan) {
            $scanner = $clamdScan
            $engineKind = 'Clamd'
        }
        else {
            throw 'Neither clamdscan.exe nor clamscan.exe was found. Install ClamAV or pass an explicit path.'
        }
    }

    if ($engineKind -eq 'Clamd' -and -not $daemonRunning) {
        Write-Warning -Message 'clamd does not appear to be running; clamdscan will fail without the daemon.'
    }

    Write-Stage -Message ('engine: {0} ({1})' -f $engineKind, $scanner)
    $databaseDirectory = Join-Path -Path $ClamRoot -ChildPath 'database'
    Write-EnvironmentDiagnostic -Scanner $scanner -DatabaseDirectory $databaseDirectory

    if ($UpdateDatabase) {
        $freshclam = Resolve-ClamBinary -Name 'freshclam.exe' -Explicit $FreshclamPath -Root $ClamRoot -Required
        Write-Stage -Message 'updating signature database with freshclam'
        $null = Update-ClamDatabase -Freshclam $freshclam -StdOutFile (Join-Path -Path $workDir -ChildPath 'freshclam.stdout') -TimeoutMinutes 30
    }

    if ($DiagnoseOnly) {
        $probeTarget = Join-Path -Path $workDir -ChildPath 'probe-target'
        $null = New-Item -ItemType Directory -Force -Path $probeTarget
        Set-Content -LiteralPath (Join-Path -Path $probeTarget -ChildPath 'probe.eml') -Value 'From: probe@localhost' -Encoding ascii
        Write-Stage -Message 'diagnostics: probe scan of a temporary directory'

        $probeParameter = @{
            Scanner = $scanner
            Kind = $engineKind
            Directory = $probeTarget
            LogFile = (Join-Path -Path $workDir -ChildPath 'probe.log')
            StdOutFile = (Join-Path -Path $workDir -ChildPath 'probe.stdout')
            MaxFileSizeMB = $MaxFileSizeMB
            TimeoutMinutes = 10
            UseStream = $Stream.IsPresent
        }

        $probe = Invoke-ClamScan @probeParameter
        Write-Stage -Message ('probe exit code: {0}' -f $probe.ExitCode)
        Write-TraceBlock -Title 'probe output' -Line $probe.Line -Limit $MaxDebugLines
        $probeParsed = Convert-ClamOutput -Line $probe.Line -DebugLimit $MaxDebugLines
        Write-Stage -Message ('probe parsed: {0} clean, {1} detection(s), {2} error line(s)' -f $probeParsed.CleanCount, @($probeParsed.Hit).Count, @($probeParsed.ErrorLine).Count)
        Write-Stage -Message ('diagnostics written to {0}' -f $script:DebugFile)
        return
    }

    $dataDir = Resolve-HMailDataDirectory -Explicit $DataDirectory
    Write-Stage -Message ('data dir: {0}' -f $dataDir)
    $quarantineRoot = $null

    if (Test-Path -LiteralPath $QuarantineDirectory -PathType Container) {
        $quarantineRoot = (Get-Item -LiteralPath $QuarantineDirectory).FullName
    }

    $scanLog = Join-Path -Path $workDir -ChildPath 'clamav-scan.log'
    $scanStdOut = Join-Path -Path $workDir -ChildPath 'clamav-scan.stdout'
    $scanParameter = @{
        Scanner = $scanner
        Kind = $engineKind
        LogFile = $scanLog
        StdOutFile = $scanStdOut
        ExcludeDirectory = $quarantineRoot
        MaxFileSizeMB = $MaxFileSizeMB
        TimeoutMinutes = $TimeoutMinutes
        UseStream = $Stream.IsPresent
    }

    if ($SinceDays -gt 0) {
        Write-Stage -Message ('enumerating messages newer than {0} day(s)' -f $SinceDays)
        $file = @(Get-MessageFile -Root $dataDir -NewerThanDays $SinceDays -WithQueue $IncludeQueue.IsPresent -ExcludeDirectory $quarantineRoot)
        Write-Stage -Message ('files to scan: {0:N0}' -f $file.Count)

        if ($file.Count -eq 0) {
            Write-Stage -Message 'nothing to scan'
            return
        }

        $listFile = Join-Path -Path $workDir -ChildPath 'scan-scope.lst'
        $fullNameList = [string[]] @($file | Select-Object -ExpandProperty FullName)
        [System.IO.File]::WriteAllLines($listFile, $fullNameList, [System.Text.UTF8Encoding]::new($false))
        Write-Trace -Message ('scope list: {0}; {1} path(s); utf-8 without mark' -f $listFile, $file.Count) -Category 'scan'
        Write-TraceBlock -Title 'scope list head' -Limit 10 -Line ([string[]] @($fullNameList | Select-Object -First 10))
        $scanParameter['FileList'] = $listFile
    }
    else {
        Write-Stage -Message 'scanning the whole message store'
        $scanParameter['Directory'] = $dataDir
    }

    Write-Stage -Message ('running ClamAV in detect-only mode; engine={0}' -f $engineKind)
    $scan = Invoke-ClamScan @scanParameter
    Write-TraceBlock -Title 'scanner output' -Line $scan.Line -Limit $MaxDebugLines
    $parsed = Convert-ClamOutput -Line $scan.Line -DebugLimit $MaxDebugLines
    $hitList = @($parsed.Hit)
    $scanErrorLine = @($parsed.ErrorLine)
    Test-ClamExitCode -Code $scan.ExitCode -HitCount $hitList.Count -Operation 'scan'
    Write-Stage -Message ('clean files: {0}; detections: {1}; error lines: {2}; elapsed {3:hh\:mm\:ss}' -f $parsed.CleanCount, $hitList.Count, $scanErrorLine.Count, $scan.Elapsed)

    if ($scanErrorLine.Count -gt 0) {
        Write-TraceBlock -Title 'scanner error lines' -Line ([string[]] $scanErrorLine) -Limit $MaxDebugLines
        Write-Warning -Message ('{0} file(s) could not be scanned; they are NOT proven clean. See debug.log.' -f $scanErrorLine.Count)
    }

    if ($hitList.Count -eq 0) {
        Write-Stage -Message ('no infected messages; run artifacts kept in {0}' -f $workDir)
        return
    }

    foreach ($hit in $hitList) {
        if (-not (Test-PathUnderRoot -Path $hit.Path -Root $dataDir)) {
            Write-Warning -Message ('Detection outside the Data directory will never be deleted: {0}' -f $hit.Path)
        }
    }

    Write-TraceBlock -Title 'detections' -Limit $MaxDebugLines -Line ([string[]] @($hitList | ForEach-Object -Process { '{0} :: {1}' -f $_.Verdict, $_.Path }))
    $hitIndex = Get-HitIndex -Hit ([object[]] $hitList)

    if ($null -eq $credential) {
        $credential = Resolve-HMailAdminCredential -Secret $AdminPassword -UserName $AdminUser -Path $CredentialPath -NoPrompt $NonInteractive.IsPresent
    }

    Write-Stage -Message 'connecting to the hMailServer COM API'

    try {
        $application = New-Object -ComObject 'hMailServer.Application'
    }
    catch {
        throw ('Cannot create hMailServer.Application: {0}. If the error is 0x80040154, check COM registration and process bitness.' -f $_.Exception.Message)
    }

    $authenticated = $application.Authenticate($credential.UserName, (Get-PlainText -Secure $credential.Password))

    if ($authenticated -is [bool] -and -not $authenticated) {
        throw ('hMailServer authentication failed for the {0} account.' -f $credential.UserName)
    }

    Write-Trace -Message ('hMailServer version: {0}' -f $application.Version) -Category 'com'
    $matchedItem = @(Find-InfectedMessage -Application $application -HitIndex $hitIndex)
    $csvPath = Join-Path -Path $workDir -ChildPath 'infected-messages.csv'
    $jsonPath = Join-Path -Path $workDir -ChildPath 'infected-messages.json'
    $view = @($matchedItem | Select-Object -Property Account, Folder, MessageId, Date, From, Subject, SizeKB, Verdict, File)

    if ($view.Count -gt 0) {
        $view | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
    }
    else {
        Set-Content -LiteralPath $csvPath -Value '"Account","Folder","MessageId","Date","From","Subject","SizeKB","Verdict","File"' -Encoding utf8
    }

    ConvertTo-Json -InputObject $view -Depth 3 | Set-Content -LiteralPath $jsonPath -Encoding utf8
    $matchedPath = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in $matchedItem) {
        $null = $matchedPath.Add((Get-NormalizedPath -Path ([string] $item.File)))
    }

    $orphanList = [System.Collections.Generic.List[object]]::new()

    foreach ($hit in $hitList) {
        if (-not $matchedPath.Contains((Get-NormalizedPath -Path ([string] $hit.Path)))) {
            $orphanList.Add($hit)
        }
    }

    Write-Stage -Message ('matched messages: {0}; unmatched detections: {1}' -f $matchedItem.Count, $orphanList.Count)

    if ($orphanList.Count -gt 0) {
        Write-TraceBlock -Title 'unmatched detections' -Limit $MaxDebugLines -Line ([string[]] @($orphanList | Select-Object -ExpandProperty Path))

        if (-not $DeleteOrphan) {
            Write-Warning -Message 'Unmatched files are not deleted unless DeleteOrphan is supplied.'
        }
    }

    Write-Stage -Message ('CSV report: {0}' -f $csvPath)

    if (-not $Delete) {
        Write-Stage -Message 'report-only mode; review the CSV and re-run with Delete'
        return
    }

    if (-not $SkipQuarantine) {
        $quarantine = Join-Path -Path $QuarantineDirectory -ChildPath $stamp
        $null = New-Item -ItemType Directory -Force -Path $quarantine
        Write-Warning -Message ('Quarantine copies go to {0}; exclude it from any resident antivirus.' -f $quarantine)
    }

    $deleted = 0

    foreach ($item in $matchedItem) {
        $target = '{0} / {1} / id={2} [{3}]' -f $item.Account, $item.Folder, $item.MessageId, $item.Verdict

        if (-not $PSCmdlet.ShouldProcess($target, 'Delete infected message via hMailServer COM')) {
            continue
        }

        if (-not $SkipQuarantine -and (Test-Path -LiteralPath $item.File -PathType Leaf)) {
            $safeAccount = [string] $item.Account -replace '[^A-Za-z0-9_.-]', '_'
            $safeName = '{0}_{1}_{2}.bad' -f $safeAccount, $item.MessageId, [System.IO.Path]::GetFileName([string] $item.File)
            Copy-Item -LiteralPath $item.File -Destination (Join-Path -Path $quarantine -ChildPath $safeName) -Force
            Write-Trace -Message ('quarantined {0}' -f $item.File) -Category 'delete'
        }

        try {
            $item.Collection.DeleteByDBID([int] $item.MessageId)
            $deleted = $deleted + 1
            Write-Trace -Message ('deleted message id={0}' -f $item.MessageId) -Category 'delete'
        }
        catch {
            Write-Warning -Message ('failed to delete id={0}: {1}' -f $item.MessageId, $_.Exception.Message)
            Write-Trace -Message ('delete exception: {0}' -f $_.Exception.ToString()) -Category 'delete'
        }
    }

    if ($DeleteOrphan) {
        foreach ($orphan in $orphanList) {
            if (-not (Test-PathUnderRoot -Path $orphan.Path -Root $dataDir)) {
                Write-Warning -Message ('refusing to delete a path outside the Data directory: {0}' -f $orphan.Path)
                continue
            }

            if (-not (Test-Path -LiteralPath $orphan.Path -PathType Leaf)) {
                continue
            }

            if ([System.IO.Path]::GetExtension($orphan.Path) -ine '.eml') {
                Write-Warning -Message ('refusing to delete a non-.eml file: {0}' -f $orphan.Path)
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($orphan.Path, 'Delete unmatched infected file')) {
                continue
            }

            if (-not $SkipQuarantine) {
                $pathByte = [System.Text.Encoding]::UTF8.GetBytes([string] $orphan.Path)
                $hashText = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($pathByte))
                $orphanName = 'orphan_{0}_{1}.bad' -f $hashText.Substring(0, 12), [System.IO.Path]::GetFileName([string] $orphan.Path)
                Copy-Item -LiteralPath $orphan.Path -Destination (Join-Path -Path $quarantine -ChildPath $orphanName) -Force
            }

            Remove-Item -LiteralPath $orphan.Path -Force
            Write-Trace -Message ('removed unmatched file {0}' -f $orphan.Path) -Category 'delete'
        }
    }

    Write-Stage -Message ('deleted messages: {0}/{1}' -f $deleted, $matchedItem.Count)
    Write-Stage -Message 'compact folders in mail clients, then re-run the scan to verify'
}
catch {
    $detail = 'FATAL: {0}{1}{2}' -f $_.Exception.ToString(), [System.Environment]::NewLine, $_.ScriptStackTrace
    Write-Warning -Message $detail

    if ($script:DebugFile) {
        try {
            Add-Content -LiteralPath $script:DebugFile -Value $detail -Encoding utf8
        }
        catch {
            Write-Debug ('fatal detail not logged: {0}' -f $_.Exception.Message)
        }
    }

    throw
}
finally {
    if ($null -ne $application) {
        try {
            $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($application)
        }
        catch {
            Write-Debug ('COM object not released: {0}' -f $_.Exception.Message)
        }
    }

    Write-Information -MessageData ('elapsed: {0:hh\:mm\:ss}' -f ((Get-Date) - $started))
    Write-Information -MessageData ('diagnostics: {0}' -f $script:DebugFile)

    if ($transcriptStarted) {
        try {
            $null = Stop-Transcript
        }
        catch {
            Write-Debug ('transcript not stopped: {0}' -f $_.Exception.Message)
        }
    }
}

#endregion
