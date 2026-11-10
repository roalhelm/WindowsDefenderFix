# Windows Defender Fix - Intune Remediations

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4.svg)](https://intune.microsoft.com)

Detection and remediation scripts for Intune Remediations (formerly Proactive Remediations) that fix the most common Microsoft Defender problems on Windows 11 clients.

Each problem has its own detection/remediation pair, so you can deploy, schedule and report on each one separately. The finding IDs are the same as in [Get-ClientHealth.ps1](https://github.com/roalhelm/ClientFixPage), and the [ClientFixPage](https://roalhelm.github.io/ClientFixPage/) recommends these scripts when its report shows the matching finding.

## Scripts

| Finding ID | Problem | Detection | Remediation |
|---|---|---|---|
| `DEF.SERVICE.STOPPED` | Defender antivirus service not running, in passive mode, or engine off, with no other antivirus active | [Detect-DefenderService.ps1](Service/Detect-DefenderService.ps1) | [Remediate-DefenderService.ps1](Service/Remediate-DefenderService.ps1) |
| `DEF.SIGNATURE.OUTDATED` | Security intelligence (signatures) older than 3 days | [Detect-DefenderSignatures.ps1](Signatures/Detect-DefenderSignatures.ps1) | [Remediate-DefenderSignatures.ps1](Signatures/Remediate-DefenderSignatures.ps1) |
| `DEF.RTP.DISABLED` | Real-time protection, behavior monitoring, on-access or IOAV protection switched off | [Detect-DefenderRealTimeProtection.ps1](RealTimeProtection/Detect-DefenderRealTimeProtection.ps1) | [Remediate-DefenderRealTimeProtection.ps1](RealTimeProtection/Remediate-DefenderRealTimeProtection.ps1) |
| `DEF.MDE.NOTONBOARDED` | Not onboarded to Defender for Endpoint, or the Sense sensor is not running | [Detect-MDEOnboarding.ps1](MDEOnboarding/Detect-MDEOnboarding.ps1) | [Remediate-MDEOnboarding.ps1](MDEOnboarding/Remediate-MDEOnboarding.ps1) |

Detection scripts are read-only. Exit `0` = healthy or not applicable, exit `1` = issue found (Intune then runs the remediation). Every script writes one summary line (`<FindingId> | OK/Issue/Fixed/Failed | <details>`), which Intune shows in the device status columns.

## What the remediations do

**Defender service (`DEF.SERVICE.STOPPED`)**
1. Does nothing when another antivirus is active (Defender in passive mode is expected then).
2. Removes leftover Group Policy values `DisableAntiSpyware` and `DisableAntiVirus` (backup first, see below).
3. Starts the `WinDefend` service.
4. Reports `ForceDefenderPassiveMode = 1` without changing it, because it is normally set on purpose.

**Signatures (`DEF.SIGNATURE.OUTDATED`)**
1. `MpCmdRun -SignatureUpdate` with the update sources configured on the device.
2. If that fails: `MpCmdRun -SignatureUpdate -MMPC`, directly from Microsoft (works around a broken WSUS / Windows Update source).
3. If that fails: `MpCmdRun -RemoveDefinitions -DynamicSignatures` (only the cached cloud signatures) and step 2 again.

The full signature set is never removed. The configured fallback order and a disabled Windows Update service are written to the log.

**Real-time protection (`DEF.RTP.DISABLED`)**
1. Does nothing when another antivirus is active or Defender runs in passive mode.
2. Reports an Intune policy that switches protection off (`Allow* = 0` under `PolicyManager\current\device\Defender`) without changing it. Fix the antivirus policy in Intune.
3. Removes leftover Group Policy values under `Windows Defender\Real-Time Protection` (backup first).
4. Resets local preferences with `Set-MpPreference` (`DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`).

Tamper protection is reported but never changed: it can only be switched on from Intune (Endpoint security > Antivirus) or the Defender portal.

**Defender for Endpoint (`DEF.MDE.NOTONBOARDED`)**
1. Installs the `Microsoft.Windows.Sense.Client` Windows capability when the Sense service is missing (some Windows 11 24H2+ images ship without it).
2. Checks that the Intune EDR onboarding policy has reached the device (`OnboardingInfo`). If not, it reports that and stops.
3. Sets the `DiagTrack` service (Connected User Experiences and Telemetry) back to Automatic and starts it, because Defender for Endpoint needs it to report.
4. Starts `Sense` and waits up to two minutes for `OnboardingState = 1`.

Assign this pair only to devices that should be onboarded to Defender for Endpoint.

## Safety

- Nothing is deleted except the Group Policy values named above. Before they are removed, the whole key is exported to `C:\ProgramData\DefenderFix\Backup\*.reg`.
- Policy values are left alone on devices with a Configuration Manager client (`CcmExec`), where they are usually set on purpose.
- Set `-removePolicyBlocks 0` to only report Group Policy values. Intune cannot pass parameters to remediation scripts, so change the default in the `param()` block if you want that in Intune.
- Intune policies, tamper protection, update source configuration and the Defender platform are never changed.
- Uses `Get-CimInstance` (no WMIC) and runs on Windows PowerShell 5.1.

## Deployment in Intune

**Devices > Scripts and remediations > Remediations > + Create** (one script package per finding)

| Setting | Value |
|---|---|
| Detection script | `Detect-*.ps1` |
| Remediation script | matching `Remediate-*.ps1` |
| Run this script using the logged-on credentials | **No** (runs as SYSTEM) |
| Enforce script signature check | **No** (unless you sign the scripts) |
| Run script in 64-bit PowerShell | **Yes** |
| Schedule | Daily (signatures: every 8 hours is a good choice) |

Licensing: Intune Remediations need Windows Enterprise E3/E5 or Windows Education A3/A5 (also included in Microsoft 365 E3/E5/F3).

## Local test

Run all detections on a test device (elevated):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DefenderDetection.ps1
```

Run one remediation by hand:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\RealTimeProtection\Remediate-DefenderRealTimeProtection.ps1 -removePolicyBlocks 0
```

## Logs

All scripts write to `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DefenderFix.log`, so the log is included when you collect diagnostics from Intune. For deeper analysis see the event logs `Microsoft-Windows-Windows Defender/Operational` and `Microsoft-Windows-SENSE/Operational`, and `C:\Windows\Temp\MpCmdRun.log`.

## Requirements

Windows 10/11 (built and documented for Windows 11) | Microsoft Intune | Windows PowerShell 5.1 | runs as SYSTEM

## License

[MIT](LICENSE)
