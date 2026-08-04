# hmailserver-clamav-cleanup

PowerShell tooling to scan an hMailServer message store with ClamAV and delete infected messages via the hMailServer COM API.

## Why ClamAV and winget

The original design used Kasperskyavp.com as the scanner stub, but the consumer build installed on the server (Kaspersky 21.26.4.406) refused every command line, including HELP and STATUS, with exit code 3 and no output. That made it impossible to drive on-demand scans from PowerShell in a reliable way.

ClamAV was chosen as a replacement backend because:

- It is free and well supported on Windows.
- It provides both a daemon-based scanner (clamd + clamdscan) and a standalone scanner (clamscan).
- Its output format is stable and easy to parse: `path: verdict FOUND`.

The base installation of ClamAV is handled via:

```powershell
winget install ClamAV.ClamAV
```

Using `winget` instead of `Install-ClamAvForHMail.ps1` for the core install keeps the tooling simple and reproducible:

- `winget` takes care of downloading and placing binaries under `C:\Program Files\ClamAV`.
- It works across machines without maintaining a custom installer script.
- It is idempotent: rerunning the command upgrades or repairs the installation.

The `Install-ClamAvForHMail.ps1` script does the *post-install* work that `winget` does not:

- Creates the log and temp directories under `C:\ProgramData\ClamAV`.
- Validates and copies `freshclam.conf` and `clamd.conf`.
- Runs `freshclam.exe` to download the signature databases.
- Registers and starts the `clamd` service and verifies that `clamdscan` can reach it.

In other words:

- `winget install ClamAV.ClamAV`  installs ClamAV itself.
- `Install-ClamAvForHMail.ps1`  configures ClamAV specifically for hMailServer message store scanning.

## Files

- `Invoke-HMailClamAvCleanup.ps1`  main cleanup script; scans the hMailServer Data directory with ClamAV and deletes infected messages through COM.
- `Install-ClamAvForHMail.ps1`  helper to prepare ClamAV on Windows for use with the cleanup script.
- `Test-ScannerBackend.ps1`  helper to report which on-demand backends are available on a given server.
- `freshclam.conf`  configuration for `freshclam.exe`, aligned with `clamd.conf`.
- `clamd.conf`  configuration for the ClamAV daemon.

## Author and version

- Author: Mikhail Deynekin (MAILSERVER)
- Repository: https://github.com/paulmann/hmailserver-clamav-cleanup
- Version: 0.1.0
