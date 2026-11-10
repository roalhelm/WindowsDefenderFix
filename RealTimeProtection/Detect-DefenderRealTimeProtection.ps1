<#
.SYNOPSIS
    Intune detection: Microsoft Defender real-time protection (or one of its parts) switched off.

.DESCRIPTION
    Finding ID: DEF.RTP.DISABLED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Read-only. Reports an issue when Defender is the active antivirus and one of these is off:
    real-time protection, behavior monitoring, on-access protection, IOAV (download/attachment) protection.

    Tamper protection is written to the output and the log but does not count as an issue here:
    it can only be switched on from Intune or the Defender portal, never by a script on the device.

    Not applicable (exit 0) when another antivirus is active or Defender runs in passive mode.

    Exit 0 = healthy or not applicable, exit 1 = issue found (Intune runs the remediation).

.NOTES
    File Name : Detect-DefenderRealTimeProtection.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Detect-DefenderRealTimeProtection.ps1
#>

$FindingId = 'DEF.RTP.DISABLED'
$LogFile   = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'

function Write-FixLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] [Detect] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $FindingId, $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Get-ThirdPartyAntivirus {
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
    if ($thirdParty.Count -gt 0) {
        $msg = "Not applicable: another antivirus is active ($($thirdParty -join ', '))."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }

    $mp = Get-MpComputerStatus -ErrorAction Stop
    $mode = [string]$mp.AMRunningMode
    if ($mode -and $mode -notin @('Normal', 'EDR Block Mode')) {
        $msg = "Not applicable: Defender running mode is '$mode'. See DEF.SERVICE.STOPPED."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }

    $off = @()
    if (-not $mp.RealTimeProtectionEnabled) { $off += 'RealTimeProtection' }
    if (-not $mp.BehaviorMonitorEnabled)    { $off += 'BehaviorMonitor' }
    if (-not $mp.OnAccessProtectionEnabled) { $off += 'OnAccessProtection' }
    if (-not $mp.IoavProtectionEnabled)     { $off += 'IoavProtection' }
    $tamper = if ($mp.IsTamperProtected) { 'on' } else { 'off' }

    if ($off.Count -gt 0) {
        $msg = "Switched off: $($off -join ', '). Tamper protection $tamper."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    $msg = "Real-time protection is on. Tamper protection $tamper."
    if ($tamper -eq 'off') { Write-FixLog "$msg Turn tamper protection on in Intune (Endpoint security > Antivirus)." 'WARN' } else { Write-FixLog $msg }
    Write-Output "$FindingId | OK | $msg"
    exit 0
}
catch {
    $msg = "Protection status could not be read: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Issue | $msg"
    exit 1
}
