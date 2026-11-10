<#
.SYNOPSIS
    Intune remediation: get Microsoft Defender for Endpoint onboarding and the Sense sensor working again.

.DESCRIPTION
    Finding ID: DEF.MDE.NOTONBOARDED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Steps (each one only when needed):
      1. Installs the "Microsoft Defender for Endpoint" Windows capability (Microsoft.Windows.Sense.Client)
         when the Sense service is missing. On some Windows 11 24H2 and later images the sensor is an
         optional feature that is not installed. Needs access to Windows Update or a Features on Demand source.
      2. Checks that an onboarding policy has reached the device
         (OnboardingInfo in HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection).
         Without it the device cannot onboard: the script reports that the Intune EDR policy is missing.
      3. Sets the Connected User Experiences and Telemetry service (DiagTrack) back to Automatic and starts it
         when it is disabled or stopped. Defender for Endpoint needs it to report.
      4. Starts the Sense service and waits up to two minutes for OnboardingState = 1.

    The script does not onboard or offboard with a local script package and does not change policies.

    Exit 0 = onboarded and Sense running afterwards, exit 1 = not yet (see output and log).

.NOTES
    File Name : Remediate-MDEOnboarding.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell
    Log       : C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DefenderFix.log

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Remediate-MDEOnboarding.ps1
#>

$FindingId    = 'DEF.MDE.NOTONBOARDED'
$LogFile      = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'
$StatusKey    = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
$AtpPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
$Notes = New-Object System.Collections.Generic.List[string]

function Write-FixLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] [Remediate] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $FindingId, $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Test-Onboarded {
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    return ((Get-RegValue -Path $StatusKey -Name 'OnboardingState') -eq 1 -and $sense -and $sense.Status -eq 'Running')
}

function Write-Result {
    param([string]$Status, [string]$Message, [int]$Code)
    $level = if ($Code -eq 0) { 'INFO' } else { 'ERROR' }
    Write-FixLog "Finished: $Message" $level
    Write-Output "$FindingId | $Status | $Message"
    exit $Code
}

Write-FixLog 'Started'

try {
    if (Test-Onboarded) { Write-Result -Status 'OK' -Message 'Already onboarded and Sense is running.' -Code 0 }

    # 1. Sense missing: install the Windows capability.
    if (-not (Get-Service -Name 'Sense' -ErrorAction SilentlyContinue)) {
        $cap = $null
        try { $cap = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like 'Microsoft.Windows.Sense.Client*' } | Select-Object -First 1 } catch { }
        if (-not $cap) {
            Write-Result -Status 'Failed' -Message 'Sense service is missing and the Sense capability is not offered on this Windows build. Check the Windows edition (Pro/Enterprise/Education needed).' -Code 1
        }
        if ([string]$cap.State -ne 'Installed') {
            Write-FixLog "Installing Windows capability $($cap.Name) (state $($cap.State))"
            try {
                $result = Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
                Write-FixLog "Installed $($cap.Name). Restart needed: $($result.RestartNeeded)"
                $Notes.Add("Installed $($cap.Name)")
                if ($result.RestartNeeded) {
                    Write-Result -Status 'Fixed' -Message "Installed $($cap.Name). Restart the device to finish; onboarding continues after the restart." -Code 0
                }
            }
            catch {
                Write-Result -Status 'Failed' -Message "Could not install $($cap.Name): $($_.Exception.Message). The device needs access to Windows Update or a Features on Demand source." -Code 1
            }
        }
    }

    # 2. Onboarding policy present?
    $onboardingInfo = Get-RegValue -Path $AtpPolicyKey -Name 'OnboardingInfo'
    if (-not $onboardingInfo) {
        $msg = 'No onboarding policy has reached the device (OnboardingInfo missing). Assign an Endpoint detection and response policy in Intune and sync the device.'
        if ($Notes.Count -gt 0) { $msg = ($Notes -join '; ') + '. ' + $msg }
        Write-Result -Status 'Failed' -Message $msg -Code 1
    }

    # 3. DiagTrack is needed for reporting.
    $diag = Get-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue
    if ($diag) {
        if ([string]$diag.StartType -eq 'Disabled') {
            try {
                Set-Service -Name 'DiagTrack' -StartupType Automatic -ErrorAction Stop
                Write-FixLog 'DiagTrack start type set to Automatic'
                $Notes.Add('DiagTrack set to Automatic')
            }
            catch {
                Write-FixLog "Could not change DiagTrack start type: $($_.Exception.Message)" 'ERROR'
            }
        }
        if ((Get-Service -Name 'DiagTrack').Status -ne 'Running') {
            try {
                Start-Service -Name 'DiagTrack' -ErrorAction Stop
                Write-FixLog 'Started DiagTrack'
                $Notes.Add('Started DiagTrack')
            }
            catch {
                Write-FixLog "Could not start DiagTrack: $($_.Exception.Message)" 'ERROR'
            }
        }
    }

    # 4. Start Sense and wait for onboarding.
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
    if ($sense -and $sense.Status -ne 'Running') {
        try {
            Start-Service -Name 'Sense' -ErrorAction Stop
            Write-FixLog 'Started Sense'
            $Notes.Add('Started Sense')
        }
        catch {
            Write-FixLog "Could not start Sense: $($_.Exception.Message)" 'ERROR'
            $Notes.Add('Sense could not be started')
        }
    }
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Test-Onboarded) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 10 }

    $summary = if ($Notes.Count -gt 0) { $Notes -join '; ' } else { 'No change made' }
    if (Test-Onboarded) { Write-Result -Status 'Fixed' -Message "Onboarded and Sense is running. $summary" -Code 0 }

    $state = Get-RegValue -Path $StatusKey -Name 'OnboardingState'
    Write-Result -Status 'Failed' -Message "Still not onboarded (OnboardingState=$state). $summary. Check the SENSE event log (Applications and Services Logs > Microsoft > Windows > SENSE) and run the MDE Client Analyzer." -Code 1
}
catch {
    Write-Result -Status 'Failed' -Message "Unexpected error: $($_.Exception.Message)" -Code 1
}
