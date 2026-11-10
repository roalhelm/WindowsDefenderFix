<#
.SYNOPSIS
    Intune remediation: switch Microsoft Defender real-time protection back on.

.DESCRIPTION
    Finding ID: DEF.RTP.DISABLED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Steps (each one only when needed):
      1. Stops without changes when another antivirus is active or Defender runs in passive mode.
      2. Checks whether an Intune (MDM) policy switches protection off
         (HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender, Allow* = 0).
         An Intune policy wins over anything done on the device, so the script only reports it.
      3. Removes leftover Group Policy values that switch protection off
         (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection: DisableRealtimeMonitoring,
         DisableBehaviorMonitoring, DisableOnAccessProtection, DisableIOAVProtection).
         The key is exported to C:\ProgramData\DefenderFix\Backup first. Skipped when
         -removePolicyBlocks 0 or a Configuration Manager client (CcmExec) is installed.
      4. Resets the local Defender preferences with Set-MpPreference
         (DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection = false).

    Tamper protection is not changed: it can only be switched on from Intune or the Defender portal.

    Exit 0 = protection is on afterwards, exit 1 = still off (see output and log).

.PARAMETER removePolicyBlocks
    1 (default) removes the Group Policy values listed above, 0 only reports them.

.NOTES
    File Name : Remediate-DefenderRealTimeProtection.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell
    Log       : C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DefenderFix.log

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Remediate-DefenderRealTimeProtection.ps1 -removePolicyBlocks 0
#>
param(
    [int]$removePolicyBlocks = 1
)

$FindingId = 'DEF.RTP.DISABLED'
$LogFile   = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'
$BackupDir = Join-Path $env:ProgramData 'DefenderFix\Backup'
$RtpPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
$MdmPolicyKey = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender'
$Notes = New-Object System.Collections.Generic.List[string]

function Write-FixLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] [{2}] [Remediate] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $FindingId, $Message
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

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Backup-RegistryKey {
    param([string]$Path, [string]$Label)
    try {
        if (-not (Test-Path -LiteralPath $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }
        $file = Join-Path $BackupDir ('{0}-{1}.reg' -f $Label, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $regPath = $Path -replace '^HKLM:\\', 'HKLM\'
        $null = & reg.exe export $regPath $file /y 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-FixLog "Backed up $Path to $file"
            return $true
        }
        Write-FixLog "Backup of $Path failed (reg.exe exit $LASTEXITCODE)" 'ERROR'
        return $false
    }
    catch {
        Write-FixLog "Backup of $Path failed: $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Remove-PolicyBlock {
    param([string]$Path, [string[]]$Names, [string]$Label)
    $found = @()
    foreach ($n in $Names) {
        if ((Get-RegValue -Path $Path -Name $n) -eq 1) { $found += $n }
    }
    if ($found.Count -eq 0) { return @() }

    Write-FixLog "Policy values that switch protection off: $($found -join ', ') in $Path" 'WARN'
    if ($removePolicyBlocks -ne 1) {
        $Notes.Add("Policy blocks found but left unchanged (-removePolicyBlocks 0): $($found -join ', ')")
        return @()
    }
    if (Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue) {
        Write-FixLog 'Configuration Manager client found (CcmExec): policy values are left unchanged'
        $Notes.Add("Policy blocks found but left unchanged because of the Configuration Manager client: $($found -join ', ')")
        return @()
    }
    if (-not (Backup-RegistryKey -Path $Path -Label $Label)) {
        $Notes.Add('Policy blocks not removed because the backup failed')
        return @()
    }
    $removed = @()
    foreach ($n in $found) {
        try {
            Remove-ItemProperty -LiteralPath $Path -Name $n -ErrorAction Stop
            Write-FixLog "Removed policy value $n"
            $removed += $n
        }
        catch {
            Write-FixLog "Could not remove policy value ${n}: $($_.Exception.Message)" 'ERROR'
        }
    }
    if ($removed.Count -gt 0) { $Notes.Add("Removed policy blocks: $($removed -join ', ')") }
    return $removed
}

function Get-ProtectionGap {
    # Names of protection parts that are off. 'StatusUnavailable' when Defender cannot be queried.
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { return @('StatusUnavailable') }
    $off = @()
    if (-not $mp.RealTimeProtectionEnabled) { $off += 'RealTimeProtection' }
    if (-not $mp.BehaviorMonitorEnabled)    { $off += 'BehaviorMonitor' }
    if (-not $mp.OnAccessProtectionEnabled) { $off += 'OnAccessProtection' }
    if (-not $mp.IoavProtectionEnabled)     { $off += 'IoavProtection' }
    return $off
}

Write-FixLog "Started (removePolicyBlocks=$removePolicyBlocks)"

try {
    # 1. Not applicable?
    $thirdParty = @(Get-ThirdPartyAntivirus)
    if ($thirdParty.Count -gt 0) {
        $msg = "No change: another antivirus is active ($($thirdParty -join ', '))."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $mode = [string]$mp.AMRunningMode
    if ($mode -and $mode -notin @('Normal', 'EDR Block Mode')) {
        $msg = "No change: Defender running mode is '$mode'. Fix DEF.SERVICE.STOPPED first."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }
    $before = @(Get-ProtectionGap)
    Write-FixLog "Off before: $($before -join ', '). Tamper protection: $($mp.IsTamperProtected)"

    # 2. Intune policy that switches protection off: report only.
    $mdmBlocks = @()
    foreach ($n in @('AllowRealtimeMonitoring', 'AllowBehaviorMonitoring', 'AllowOnAccessProtection', 'AllowIOAVProtection')) {
        if ((Get-RegValue -Path $MdmPolicyKey -Name $n) -eq 0) { $mdmBlocks += $n }
    }
    if ($mdmBlocks.Count -gt 0) {
        Write-FixLog "Intune policy switches protection off: $($mdmBlocks -join ', ') = 0. Not changed on the device." 'WARN'
        $Notes.Add("Intune policy sets $($mdmBlocks -join ', ') = 0: fix the antivirus policy in Intune")
    }

    # 3. Group Policy leftovers.
    $removed = @(Remove-PolicyBlock -Path $RtpPolicyKey -Names @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableIOAVProtection') -Label 'DefenderRealTimeProtectionPolicies')

    # 4. Local preferences.
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $set = @{}
        if ($pref.DisableRealtimeMonitoring) { $set['DisableRealtimeMonitoring'] = $false }
        if ($pref.DisableBehaviorMonitoring) { $set['DisableBehaviorMonitoring'] = $false }
        if ($pref.DisableIOAVProtection)     { $set['DisableIOAVProtection'] = $false }
        if ($set.Count -gt 0) {
            Set-MpPreference @set -ErrorAction Stop
            Write-FixLog "Set-MpPreference: $(($set.Keys | Sort-Object) -join ', ') = False"
            $Notes.Add("Reset local preferences: $(($set.Keys | Sort-Object) -join ', ')")
        }
    }
    catch {
        Write-FixLog "Set-MpPreference failed: $($_.Exception.Message)" 'ERROR'
        $Notes.Add('Local preferences could not be changed (blocked by policy or tamper protection)')
    }

    # Give Defender time to apply the change.
    $deadline = (Get-Date).AddSeconds(30)
    $after = @(Get-ProtectionGap)
    while ($after.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $after = @(Get-ProtectionGap)
    }

    $summary = if ($Notes.Count -gt 0) { $Notes -join '; ' } else { 'No change made' }
    if ($after.Count -eq 0) {
        Write-FixLog "Finished: protection is on. $summary"
        Write-Output "$FindingId | Fixed | $summary"
        exit 0
    }
    if ($removed.Count -gt 0) { $summary += '; restart the device so Defender picks up the policy change' }
    Write-FixLog "Finished: still off: $($after -join ', '). $summary" 'ERROR'
    Write-Output "$FindingId | Failed | Still off: $($after -join ', '). $summary"
    exit 1
}
catch {
    $msg = "Unexpected error: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Failed | $msg"
    exit 1
}
