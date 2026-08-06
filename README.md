# hMailServer ClamAV Cleanup

[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![ClamAV](https://img.shields.io/badge/ClamAV-1.x-FF6600)](https://www.clamav.net/)
[![hMailServer](https://img.shields.io/badge/hMailServer-COM%20API-1f6feb)](https://www.hmailserver.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/paulmann/hmailserver-clamav-cleanup/releases)

On-demand antivirus sweep for an **hMailServer** message store. ClamAV is used strictly as a detector; every deletion is performed through the hMailServer **COM API**, so the database row and the `.eml` file are removed together and the store never drifts out of sync.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Verification Before First Use](#verification-before-first-use)
- [Usage](#usage)
- [Parameter Reference](#parameter-reference)
- [Unattended Operation](#unattended-operation)
- [Run Artifacts](#run-artifacts)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Restoring a Deleted Message](#restoring-a-deleted-message)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Why This Exists

Mail stores accumulate messages that were clean at delivery time and turn malicious only after signatures catch up. Resident protection does not retroactively re-inspect an archive, so a periodic on-demand sweep is required.

The first implementation drove the locally installed Kaspersky console stub, `avp.com`. On the target host (consumer build **21.26.4.406**) the command line interface turned out to be fully disabled: **every** command, including `HELP` and `STATUS`, returned exit code `3` with no output. This was confirmed with a twelve-variant probe matrix executed from the product directory, with and without a settings password, through `cmd.exe` and directly.

ClamAV replaced it as the detection backend because it is free, actively maintained on Windows, ships both a daemon client and a standalone scanner, and emits a stable, machine-readable verdict format:

```
C:\path\to\message.eml: Trojan.Foo-1 FOUND
```

The resident Kaspersky installation keeps running; ClamAV only reads files, so the two coexist without conflict.

---

## Features

- **Detect-only scanning.** `--remove`, `--move` and `--copy` are never passed to ClamAV. The antivirus cannot mutate the store.
- **Transactional deletion via COM.** `DeleteByDBID` removes the database record and the message file in one operation.
- **Automatic engine selection.** Prefers `clamdscan` against a running `clamd`; falls back to `clamscan` when no daemon is available.
- **Incremental or full sweeps.** `-SinceDays` restricts the scope by modification time; the default scans the entire store.
- **Quarantine by default.** Every deleted message is copied to a timestamped quarantine directory first.
- **Unattended-ready credentials.** A stored `PSCredential` or `SecureString` is discovered automatically, and `-NonInteractive` turns a missing secret into an immediate failure instead of a hung prompt.
- **Fail-fast authentication.** Credentials are resolved *before* the scan, so a broken credential file costs seconds rather than a full sweep.
- **Delimiter-agnostic parsing.** Verdicts are extracted with global regular expressions, because `clamdscan` on Windows does not reliably separate results with CR, LF or NUL.
- **Honest error accounting.** Files the scanner could not read are counted separately and never reported as clean.
- **Safety rails.** Paths outside the hMailServer `Data` directory are never deleted; non-`.eml` files are refused; orphaned files require an explicit second switch.
- **`ShouldProcess` support.** `-WhatIf` and `-Confirm` behave exactly as expected for a high-impact cmdlet.
- **Full audit trail.** Every run writes a debug log, a transcript, the raw scanner output, and CSV plus JSON reports.
- **Lint-clean.** Passes `Invoke-ScriptAnalyzer` with zero errors and zero warnings, no suppressions, pure ASCII source.

---

## How It Works

```
  ┌─────────────────────────┐
  │ 1. Resolve environment  │  clamdscan / clamscan, clamd state, signature age
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 2. Resolve credentials  │  parameter → path → env var → auto-discovery
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 3. Locate Data dir      │  registry InstallLocation → hMailServer.INI → Data
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 4. Build scan scope     │  *.eml by age, UTF-8 file list for --file-list
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 5. Scan (detect only)   │  --no-summary --log, OEM-decoded stdout capture
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 6. Parse verdicts       │  FOUND / ERROR / OK via global regex
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 7. Match through COM    │  full path first, unique leaf name as fallback
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 8. Report               │  CSV + JSON + debug log
  └───────────┬─────────────┘
              │
  ┌───────────▼─────────────┐
  │ 9. Quarantine & delete  │  only with -Delete, guarded by ShouldProcess
  └─────────────────────────┘
```

Messages are matched by absolute path. When a path cannot be matched, the file name is used **only if it is unique** among all detections; ambiguous names are skipped and reported.

Step 2 runs early on purpose. A full-store sweep can take hours, and discovering a bad password afterwards wastes the entire window.

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| Windows | 10 / Server 2016+ | Registry and COM access required |
| PowerShell | 7.2 or newer | Tested on 7.6.3 |
| ClamAV | 1.x | Tested on 1.5.3 |
| hMailServer | 5.x | `hMailServer.Application` COM object registered |
| Privileges | Administrator | Needed for the store, the service and COM |

---

## Installation

### 1. Install ClamAV

```powershell
winget install ClamAV.ClamAV
```

### 2. Configure it for this workload

```powershell
git clone https://github.com/paulmann/hmailserver-clamav-cleanup.git
cd hmailserver-clamav-cleanup
pwsh.exe -NoProfile -File .\Install-ClamAvForHMail.ps1 -ConfigSource .
```

### Why `winget` *and* `Install-ClamAvForHMail.ps1`?

These two steps solve different problems and are intentionally not merged:

| Step | Responsibility |
|---|---|
| `winget install ClamAV.ClamAV` | Obtains and installs the **upstream product**: downloads the signed vendor package, unpacks binaries into `C:\Program Files\ClamAV`, registers uninstall metadata, and stays idempotent and upgradable through `winget upgrade`. |
| `Install-ClamAvForHMail.ps1` | Performs the **post-install integration** that no package manager can know about: creates `C:\ProgramData\ClamAV\logs` and `...\tmp`, validates the configuration files and refuses an active `Example` line, runs `freshclam` for the first signature download, registers and starts the `clamd` service, sets it to automatic start, and verifies that `clamdscan` can actually reach the daemon. |

Repackaging the vendor installer inside a project script would mean shipping download logic, hash verification and upgrade handling that `winget` already does correctly and safely. Conversely, `winget` cannot create the directories this configuration expects, and that omission is fatal: `freshclam` and `clamd` initialize their logger before anything else, so a missing log directory aborts them with `Failed to open log file ... No such file or directory` and the service never registers.

### 3. Store the hMailServer credential

Export the credential once so that no password ever appears on a command line or in a task definition:

```powershell
$dir = Join-Path $env:ProgramData 'HMailClamAvCleanup'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Get-Credential -UserName 'Administrator' -Message 'hMailServer administrator' |
    Export-Clixml -LiteralPath (Join-Path $dir 'hmail.cred.xml')
```

The script discovers this file automatically, so `-AdminPassword` becomes optional. A `PSCredential` also carries the account name, which overrides `-AdminUser`.

`Export-Clixml` protects the secret with DPAPI and binds it to **one user on one machine**. Create the file under the same account that will run the sweep — see [Unattended Operation](#unattended-operation) for the full scheduled-task walkthrough.

---

## Configuration

`clamd.conf` and `freshclam.conf` in this repository are tuned for a mail store. The settings that matter most:

| Setting | Value | Rationale |
|---|---|---|
| `TCPSocket` | `3310` | The Windows daemon supports TCP sockets only |
| `TCPAddr` | `127.0.0.1` | `localhost` may resolve to `::1` while the client connects over IPv4 |
| `ScanMail` | `yes` | Without it, attachments inside `.eml` are never unpacked |
| `ScanArchive` | `yes` | Nested archive traversal |
| `AlertOLE2Macros` | `no` | Otherwise every macro-enabled document becomes a detection |
| `AlertEncryptedArchive` | `no` | Password-protected archives are routine in email |
| `AlertExceedsMax` | `yes` | Files that hit a limit are flagged instead of passing as clean |
| `MaxFileSize` | `100M` | Keep aligned with `-MaxFileSizeMB` |
| `ExcludePath` | quarantine | The value is a **regular expression**; separators must be escaped |
| `NotifyClamd` | `clamd.conf` | `freshclam` reloads the daemon after an update, no restart needed |

Add these to your resident antivirus exclusions:

- `C:\mail\quarantine` — otherwise quarantine copies are destroyed and rollback becomes impossible.
- `C:\Program Files\ClamAV\database` — speeds up signature updates.

---

## Verification Before First Use

**1. Daemon reachable**

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 3310
Get-Service -Name clamd | Select-Object Name, Status, StartType
```

**2. Environment diagnostics**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -DiagnoseOnly -Debug
```

Expect engine `Clamd`, `clamd instances: 1`, three signature files with a recent timestamp, and `probe exit code: 0`. `-DiagnoseOnly` never touches the COM API, so it needs no credential at all.

**3. Parser sanity — the critical check**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Debug
```

`clean files` **must equal** `files to scan`. A mismatch means output parsing is broken and a result of `0 detections` proves nothing.

**4. Detection sanity**

```powershell
$dir = 'C:\mail\scripts\av\eicar-test'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$body = -join (@(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42) | ForEach-Object { [char] $_ })
[System.IO.File]::WriteAllText("$dir\test.eml", $body)
& 'C:\Program Files\ClamAV\clamdscan.exe' --no-summary "$dir\test.eml"
"exit=$LASTEXITCODE"
Remove-Item -LiteralPath "$dir\test.eml" -Force -ErrorAction Ignore
```

Expect `Eicar-Test-Signature FOUND` and `exit=1`. Exclude the test directory from resident protection first, or the file disappears before ClamAV sees it.

---

## Usage

With a stored credential in place, no password argument is needed:

**Report-only sweep of the last day**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Debug
```

**Full store sweep with fresh signatures**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -UpdateDatabase -TimeoutMinutes 480 -Debug
```

**Explicit credential from any location**

```powershell
$cred = Import-Clixml -LiteralPath 'C:\mail\scripts\av\hmail.cred.xml'
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -AdminPassword $cred
```

**Include the delivery queue**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -IncludeQueue
```

**Preview deletions without touching anything**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Delete -WhatIf
```

**Delete for real**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Delete
```

**Fully unattended, no prompts under any circumstances**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -NonInteractive -Delete -DeleteOrphan -Confirm:$false
```

**No daemon available**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Engine Clamscan
```

**Daemon cannot read the store (different service account)**

```powershell
.\Invoke-HMailClamAvCleanup.ps1 -SinceDays 1 -Engine Clamd -Stream
```

---

## Parameter Reference

### Component locations

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ClamRoot` | `string` | `C:\Program Files\ClamAV` | ClamAV installation directory |
| `-ClamdScanPath` | `string` | auto | Explicit path to `clamdscan.exe` |
| `-ClamScanPath` | `string` | auto | Explicit path to `clamscan.exe` |
| `-FreshclamPath` | `string` | auto | Explicit path to `freshclam.exe` |
| `-DataDirectory` | `string` | registry | hMailServer `Data` directory |

### Credentials

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-AdminPassword` | `object` | auto-discovery | Accepts a `string`, a `securestring` or a `PSCredential`, so `Import-Clixml` output can be passed straight through |
| `-AdminUser` | `string` | `Administrator` | Account used for COM authentication; ignored when a `PSCredential` carries a user name |
| `-CredentialPath` | `string` | auto-discovery | Explicit path to a credential file produced by `Export-Clixml` |
| `-NonInteractive` | `switch` | off | Never prompt; throw instead when no credential can be resolved |

`-AdminPassword` is deliberately typed as `object` rather than `string`. Binding a `SecureString` to a string-typed parameter silently converts it to the literal text `System.Security.SecureString`, which authenticates against nothing and sends the script back to an interactive prompt.

### Scan behaviour

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Engine` | `Auto` \| `Clamd` \| `Clamscan` | `Auto` | Backend selection |
| `-SinceDays` | `0`–`3650` | `0` | Only messages newer than N days; `0` scans everything |
| `-IncludeQueue` | `switch` | off | Include files in the `Data` root (the delivery queue) |
| `-Stream` | `switch` | off | Send file contents to the daemon instead of paths |
| `-MaxFileSizeMB` | `1`–`4096` | `100` | Size limits for the `Clamscan` engine |
| `-TimeoutMinutes` | `0`–`1440` | `240` | Per-invocation timeout; `0` waits indefinitely |
| `-UpdateDatabase` | `switch` | off | Run `freshclam` before scanning |

### Reporting and removal

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ReportDirectory` | `string` | `C:\mail\reports\clamav` | Root for per-run artifacts |
| `-QuarantineDirectory` | `string` | `C:\mail\quarantine` | Root for quarantine copies |
| `-SkipQuarantine` | `switch` | off | Delete without keeping copies |
| `-Delete` | `switch` | off | Delete matched messages through COM |
| `-DeleteOrphan` | `switch` | off | Also delete detections with no database record |
| `-DiagnoseOnly` | `switch` | off | Environment check and probe scan only |
| `-MaxDebugLines` | `10`–`5000` | `120` | Trace dump depth |

Standard `CmdletBinding` switches apply: `-Debug`, `-Verbose`, `-WhatIf`, `-Confirm`. `ConfirmImpact` is `High`, so unattended runs need `-Confirm:$false`.

---

## Unattended Operation

Interactive runs prompt for the hMailServer password. A scheduled run must supply it without a console and must fail loudly when it cannot, rather than block forever on a hidden prompt.

### Credential resolution order

`Resolve-HMailAdminCredential` walks these sources and stops at the first hit:

1. The value passed to `-AdminPassword` — `string`, `securestring` or `PSCredential`.
2. An explicit `-CredentialPath`.
3. The `HMAIL_CRED_PATH` environment variable.
4. Auto-discovery of `hmail*.cred.xml`, `cred.xml` or `credential.xml` in the script directory, `.\creds\`, `%ProgramData%\HMailClamAvCleanup\` and `%LOCALAPPDATA%\HMailClamAvCleanup\`. The newest file by `LastWriteTimeUtc` wins.
5. An interactive prompt — suppressed by `-NonInteractive`, which throws instead.

Every decision is traced under the `[auth]` category in `debug.log`, so a surprising choice is easy to audit after the fact.

### Step 1 — Create a dedicated service account

A purpose-built local account keeps the DPAPI scope narrow and the audit trail readable:

```powershell
$password = Read-Host -AsSecureString -Prompt 'Password for svc_clamav'

New-LocalUser -Name 'svc_clamav' -Password $password `
    -FullName 'ClamAV cleanup service' `
    -Description 'Runs Invoke-HMailClamAvCleanup.ps1' `
    -PasswordNeverExpires -AccountNeverExpires

Add-LocalGroupMember -Group 'Administrators' -Member 'svc_clamav'
```

Local administrator rights are not optional: the script reads the message store and instantiates the `hMailServer.Application` COM object.

### Step 2 — Export the credential as that account

DPAPI ties the file to one user on one machine, so it must be written from a session running as `svc_clamav`:

```powershell
# Start a shell as the service account first:
#   runas /user:MAILSERVER\svc_clamav "pwsh.exe -NoExit"

$dir = Join-Path $env:ProgramData 'HMailClamAvCleanup'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Get-Credential -UserName 'Administrator' -Message 'hMailServer administrator' |
    Export-Clixml -LiteralPath (Join-Path $dir 'hmail.cred.xml')
```

### Step 3 — Restrict the ACL

The script warns when the file is readable by `Everyone` or `BUILTIN\Users`, comparing well-known SIDs so the check also works on a localized Windows installation. Break inheritance and grant only what is required:

```powershell
$dir = Join-Path $env:ProgramData 'HMailClamAvCleanup'
$acl = Get-Acl -LiteralPath $dir
$acl.SetAccessRuleProtection($true, $false)

'SYSTEM', 'Administrators', 'MAILSERVER\svc_clamav' | ForEach-Object {
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $_, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}

Set-Acl -LiteralPath $dir -AclObject $acl
```

### Step 4 — Register the scheduled task

```powershell
$script = 'C:\mail\scripts\av\Invoke-HMailClamAvCleanup.ps1'
$pwsh   = 'C:\Program Files\PowerShell\7\pwsh.exe'

$argument = @(
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy', 'Bypass'
    '-File', "`"$script`""
    '-NonInteractive'
    '-SinceDays', '2'
    '-UpdateDatabase'
    '-Delete'
    '-TimeoutMinutes', '600'
    '-Confirm:$false'
) -join ' '

$action = New-ScheduledTaskAction -Execute $pwsh -Argument $argument `
    -WorkingDirectory (Split-Path -Parent $script)

$trigger = New-ScheduledTaskTrigger -Daily -At '03:30'

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 12) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 1 -RestartInterval (New-TimeSpan -Minutes 30)

$runAs = Get-Credential -UserName 'MAILSERVER\svc_clamav' -Message 'Task run-as account'

Register-ScheduledTask -TaskName 'hMailServer ClamAV cleanup' `
    -Description 'Detect-only ClamAV sweep of the hMailServer store, then delete infected messages through COM.' `
    -Action $action -Trigger $trigger -Settings $settings `
    -User $runAs.UserName `
    -Password $runAs.GetNetworkCredential().Password `
    -RunLevel Highest
```

Four details decide whether this actually survives production:

- **`-User` and `-Password`, not `-Principal`.** They belong to different parameter sets of `Register-ScheduledTask`. Supplying a principal alone registers a task that silently refuses to start while nobody is logged on.
- **`-ExecutionTimeLimit` must exceed `-TimeoutMinutes`.** Otherwise Task Scheduler kills the process mid-sweep, potentially between the quarantine copy and the COM deletion.
- **`-MultipleInstances IgnoreNew`.** A full-store sweep can outlive its own daily interval; without this a second instance starts on top of the first.
- **`pwsh -NonInteractive` does not suppress `Read-Host`.** Only the script's own `-NonInteractive` switch guarantees no prompt, which is why both appear above.

`-SinceDays 2` overlaps deliberately, so a single missed run leaves no gap in coverage.

### Step 5 — Verify the first run

```powershell
Start-ScheduledTask -TaskName 'hMailServer ClamAV cleanup'

Get-ScheduledTaskInfo -TaskName 'hMailServer ClamAV cleanup' |
    Select-Object LastRunTime, LastTaskResult, NumberOfMissedRuns
```

`LastTaskResult` of `0` means success. Then confirm how the credential was obtained:

```powershell
$run = Get-ChildItem 'C:\mail\reports\clamav' -Directory |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

Select-String -LiteralPath (Join-Path $run.FullName 'debug.log') -Pattern '\[auth\]'
```

Expected output:

```
[auth] credential file discovered: C:\ProgramData\HMailClamAvCleanup\hmail.cred.xml
[auth] credential loaded from C:\ProgramData\HMailClamAvCleanup\hmail.cred.xml as System.Management.Automation.PSCredential
[auth] COM identity resolved before scanning: Administrator
```

For a low-impact rehearsal, drop `-Delete` and narrow the scope with `-SinceDays 1`.

### Password rotation

Re-export the file as `svc_clamav`; the task needs no change because the path is unchanged:

```powershell
Get-Credential -UserName 'Administrator' -Message 'hMailServer administrator' |
    Export-Clixml -LiteralPath "$env:ProgramData\HMailClamAvCleanup\hmail.cred.xml"

.\Invoke-HMailClamAvCleanup.ps1 -NonInteractive -SinceDays 1 -Debug
```

### Alternative credential stores

| Store | Use when | Caveat |
|---|---|---|
| `Export-Clixml` (DPAPI) | Single host with one dedicated service account | Bound to one user on one machine; unusable after a profile reset or OS reinstall |
| `Protect-CmsMessage` | The task runs as `SYSTEM`, or several accounts need the same secret | Requires a document-encryption certificate and an ACL on its private key |
| `SecretManagement` + `SecretStore` | Several secrets with scheduled rotation | The vault is user-scoped too; register it as the task account with authentication and interaction disabled |
| Group Managed Service Account | Domain with multiple mail hosts | Active Directory only; the password is never exposed to the script |

---

## Run Artifacts

Each run creates `<ReportDirectory>\run-<timestamp>\`:

| File | Contents |
|---|---|
| `debug.log` | Full trace, always written regardless of `-Debug` |
| `transcript.log` | PowerShell session transcript |
| `clamav-scan.log` | Scanner log produced by `--log` |
| `clamav-scan.stdout` | Captured console output |
| `scan-scope.lst` | UTF-8 list of scanned paths |
| `infected-messages.csv` | Account, folder, message id, date, sender, subject, size, verdict, path |
| `infected-messages.json` | Same data as JSON |

The three lines worth monitoring:

```
files to scan: 1 015
clean files: 1015; detections: 0; error lines: 0; elapsed 00:00:03
matched messages: 0; unmatched detections: 0
```

A non-zero `error lines` means those files were **not** proven clean. A suspiciously fast repeat scan is normal: `clamd` caches results by file hash.

---

## Exit Codes

| ClamAV code | Meaning | Script behaviour |
|---|---|---|
| `0` | No threats found | Continue |
| `1` | Threats found | Continue and parse detections |
| `2` | Scan error | Warn if at least one detection parsed, otherwise terminate |

---

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `Could not connect to clamd ... Connection refused` | Daemon stopped or crashed at startup | Check `Get-Service clamd` and `C:\ProgramData\ClamAV\logs\clamd.log`; use `-Engine Clamscan` meanwhile |
| `Failed to open log file ... No such file or directory` | `C:\ProgramData\ClamAV\logs` missing | Create the directory; ClamAV never creates it |
| `net start clamd` → *service name is invalid* | `clamd.exe --install` failed, usually after the logger error | Fix directories, rerun elevated, confirm with `Get-Service -Name '*clam*'` |
| `clean files` ≠ `files to scan` | Output parsing broken | Ensure the delimiter-agnostic parser is in place; `clamdscan` on Windows does not always separate results with CR, LF or NUL |
| `Cannot create hMailServer.Application` | COM not registered or bitness mismatch | Verify registration; `0x80040154` usually means the wrong process architecture |
| A password prompt appears although `-AdminPassword` was supplied | An older build declared the parameter as `securestring` or `string`, so the value was stringified | Update to a build where `-AdminPassword` is `object` |
| `Cannot read ...cred.xml ... bound to one user on one machine` | The file was exported by another account or on another host | Re-export while logged on as the account that runs the task |
| `No hMailServer password was supplied, no credential file was found` | Auto-discovery found nothing and prompting is disabled | Pass `-CredentialPath`, set `HMAIL_CRED_PATH`, or place the file in a discovered directory |
| `hMailServer authentication failed for the ... account` | Wrong password, or a `PSCredential` carrying an unexpected user name | Re-export the credential, or pass `-AdminUser` explicitly |
| Scheduled task never starts while logged off | Registered with `-Principal` instead of `-User` and `-Password` | Re-register as shown in [Unattended Operation](#unattended-operation) |
| Sweep killed part-way through | `-ExecutionTimeLimit` shorter than `-TimeoutMinutes` | Raise the task limit above the script timeout |
| Excessive false positives | Aggressive heuristics enabled | Disable `AlertOLE2Macros`, `AlertEncryptedArchive` and `DetectPUA` in `clamd.conf` |
| Scan finishes in seconds | `clamd` result cache | Expected; set `DisableCache yes` temporarily for a cold measurement |

---

## Restoring a Deleted Message

Quarantine copies live in `<QuarantineDirectory>\<timestamp>\` and are named `account_at_domain_<id>_<original>.bad`.

1. Locate the row in `infected-messages.csv` for that run.
2. Copy the file out of quarantine and drop the `.bad` suffix.
3. Re-inject the message through hMailServer rather than copying it into an account folder.

Copying an `.eml` back into the account directory does **not** make it visible: hMailServer serves clients from the database, not from directory contents.

---

## Security Considerations

- The hMailServer password never appears in the script, in a task definition or on a command line. Store it with `Export-Clixml` (DPAPI) or pass a `securestring` or `PSCredential` explicitly.
- Keep the credential file in a directory with inheritance disabled, readable only by `SYSTEM`, `Administrators` and the service account. The script warns when `Everyone` or `BUILTIN\Users` retains access.
- The plaintext password exists only for the duration of the COM `Authenticate` call, and the holding variable is cleared immediately afterwards.
- Prefer a dedicated service account over a personal one: DPAPI scope, task ownership and audit trail all stay narrow.
- Use `-NonInteractive` for every scheduled run so a broken credential fails the task instead of hanging it invisibly.
- The quarantine directory holds live malware. Restrict its ACL and exclude it from resident scanning deliberately, not accidentally.
- Deletions outside the `Data` directory are refused, and non-`.eml` files are never removed.
- Orphaned detections require both `-Delete` and `-DeleteOrphan`; the default posture reports them and stops.
- Always take a database and `Data` backup before the first destructive run.

---

## Limitations

- ClamAV detects considerably less than commercial engines; this tool complements resident protection rather than replacing it.
- Leaf-name matching is disabled for duplicate file names; only absolute paths are used in that case.
- Detections outside the `Data` directory are reported but never deleted.
- Deletion is irreversible outside quarantine: `DeleteByDBID` removes both the record and the file.
- A DPAPI credential file cannot be shared between accounts or hosts; each machine and each service account needs its own export.
- IMAP clients may need a folder compact after a bulk removal.

---

## Roadmap

- [ ] Re-injection helper that restores a quarantined message through the COM API
- [ ] Optional `SecretManagement` and DPAPI-NG credential backends for `SYSTEM`-owned tasks
- [ ] Optional Microsoft Defender backend via `MpCmdRun.exe` for hosts where Defender runs in normal mode
- [ ] Pester test suite covering the parser against recorded scanner output
- [ ] Optional email or webhook notification on detection
- [ ] Prometheus-friendly metrics file per run

---

## Contributing

Issues and pull requests are welcome. Please make sure that:

- `Invoke-ScriptAnalyzer -Path .\<script>.ps1` reports no errors and no warnings, without suppressions;
- source files stay pure ASCII, with localized patterns expressed as `\uXXXX` escapes;
- destructive code paths remain behind `ShouldProcess`;
- new behaviour is documented in this README.

---

## License

Released under the MIT License. See [LICENSE](LICENSE).

---

## Author

**Mikhail Deynekin**

- Website: [deynekin.com](https://deynekin.com/)
- GitHub: [@paulmann](https://github.com/paulmann)
- Email: git@deynekin.com

Repository: <https://github.com/paulmann/hmailserver-clamav-cleanup>
