<#
.SYNOPSIS
    Intune detection: Microsoft Defender Antivirus service not running or not the active antivirus.

.DESCRIPTION
    Finding ID: DEF.SERVICE.STOPPED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Read-only. Reports an issue when
      - the WinDefend service is missing or not running, or
      - Defender runs in passive mode, or its antivirus engine is off,
    and no other antivirus product is registered and enabled in Windows Security Center.
    A device that runs a third-party antivirus is healthy for this check.

    Exit 0 = healthy or not applicable, exit 1 = issue found (Intune runs the remediation).

.NOTES
    File Name : Detect-DefenderService.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Detect-DefenderService.ps1
#>

$FindingId = 'DEF.SERVICE.STOPPED'
$LogFile   = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'

function Write-FixLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] [Detect] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $FindingId, $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Get-ThirdPartyAntivirus {
    # Names of enabled antivirus products other than Microsoft Defender, from Windows Security Center.
    try {
        $products = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
    }
    catch {
        return @()
    }
    $names = @()
    foreach ($p in $products) {
        if ($p.displayName -match 'Windows Defender|Microsoft Defender') { continue }
        $state = (([int]$p.productState) -shr 12) -band 0xF   # 1 = on
        if ($state -eq 1) { $names += [string]$p.displayName }
    }
    return $names
}

try {
    $thirdParty = @(Get-ThirdPartyAntivirus)
    $service = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue

    if ($thirdParty.Count -gt 0) {
        $msg = "Not applicable: another antivirus is active ($($thirdParty -join ', '))."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }

    if (-not $service) {
        $msg = 'WinDefend service is missing and no other antivirus is active.'
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    if ($service.Status -ne 'Running') {
        $msg = "WinDefend service is $($service.Status) (start type $($service.StartType)) and no other antivirus is active."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    $mp = Get-MpComputerStatus -ErrorAction Stop
    $mode = [string]$mp.AMRunningMode
    if ($mode -and $mode -notin @('Normal', 'EDR Block Mode')) {
        $msg = "Defender running mode is '$mode' and no other antivirus is active."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }
    if (-not $mp.AMServiceEnabled -or -not $mp.AntivirusEnabled) {
        $msg = "Defender engine is off (AMServiceEnabled=$($mp.AMServiceEnabled), AntivirusEnabled=$($mp.AntivirusEnabled))."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    $msg = "Defender antivirus is running (mode '$mode', platform $($mp.AMProductVersion))."
    Write-FixLog $msg
    Write-Output "$FindingId | OK | $msg"
    exit 0
}
catch {
    $msg = "Defender status could not be read: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Issue | $msg"
    exit 1
}
