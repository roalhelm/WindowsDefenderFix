<#
.SYNOPSIS
    Intune detection: device not onboarded to Microsoft Defender for Endpoint, or the sensor is not running.

.DESCRIPTION
    Finding ID: DEF.MDE.NOTONBOARDED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Read-only. Reports an issue when
      - OnboardingState in HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status is not 1, or
      - the Defender for Endpoint sensor service (Sense) is missing or not running.

    Assign this remediation only to devices that should be onboarded to Defender for Endpoint.
    On a tenant without Defender for Endpoint every device would show as an issue.

    Exit 0 = healthy, exit 1 = issue found (Intune runs the remediation).

.NOTES
    File Name : Detect-MDEOnboarding.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Detect-MDEOnboarding.ps1
#>

$FindingId = 'DEF.MDE.NOTONBOARDED'
$LogFile   = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'

function Write-FixLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] [Detect] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $FindingId, $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

try {
    $state = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'
    $sense = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue

    if (-not $sense) {
        $msg = "Sense service is missing (OnboardingState=$state)."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }
    if ($state -ne 1) {
        $msg = "Device is not onboarded (OnboardingState=$state, Sense $($sense.Status))."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }
    if ($sense.Status -ne 'Running') {
        $msg = "Device is onboarded but the Sense service is $($sense.Status)."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    $orgId = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OrgId'
    $msg = "Device is onboarded and Sense is running (OrgId $orgId)."
    Write-FixLog $msg
    Write-Output "$FindingId | OK | $msg"
    exit 0
}
catch {
    $msg = "Onboarding state could not be read: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Issue | $msg"
    exit 1
}
