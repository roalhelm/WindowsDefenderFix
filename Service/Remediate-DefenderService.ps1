<#
.SYNOPSIS
    Intune remediation: bring the Microsoft Defender Antivirus service back when no other antivirus is active.

.DESCRIPTION
    Finding ID: DEF.SERVICE.STOPPED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Steps (each one only when needed):
      1. Stops without changes when another antivirus is active (Defender in passive mode is expected then).
      2. Removes leftover Group Policy values that switch Defender off
         (DisableAntiSpyware, DisableAntiVirus under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender).
         The key is exported to C:\ProgramData\DefenderFix\Backup first. Skipped when
         -removePolicyBlocks 0 or a Configuration Manager client (CcmExec) is installed.
      3. Starts the WinDefend service.
      4. Reports, but does not change, ForceDefenderPassiveMode. That value is normally set on purpose.

    Nothing is deleted except the policy values named above, and those are backed up.
    Tamper protection, Intune policies and the Defender platform are not changed.

    Exit 0 = Defender is running as active antivirus afterwards, exit 1 = still broken (see output and log).

.PARAMETER removePolicyBlocks
    1 (default) removes the Group Policy values listed above, 0 only reports them.

.NOTES
    File Name : Remediate-DefenderService.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell
    Log       : C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DefenderFix.log

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Remediate-DefenderService.ps1 -removePolicyBlocks 0
#>
param(
    [int]$removePolicyBlocks = 1
)

$FindingId = 'DEF.SERVICE.STOPPED'
$LogFile   = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'
$BackupDir = Join-Path $env:ProgramData 'DefenderFix\Backup'
$PolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$AtpPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
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
    # Exports a registry key to a .reg file before anything in it changes. Returns $true on success.
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
    # Removes the given policy values when they are set to 1. Returns the names that were removed.
    param([string]$Path, [string[]]$Names, [string]$Label)
    $found = @()
    foreach ($n in $Names) {
        if ((Get-RegValue -Path $Path -Name $n) -eq 1) { $found += $n }
    }
    if ($found.Count -eq 0) { return @() }

    Write-FixLog "Policy values that switch Defender off: $($found -join ', ') in $Path" 'WARN'
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

function Test-DefenderActive {
    $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') { return $false }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        return ($mp.AMServiceEnabled -and $mp.AntivirusEnabled -and ([string]$mp.AMRunningMode -in @('Normal', 'EDR Block Mode')))
    }
    catch {
        return $false
    }
}

Write-FixLog "Started (removePolicyBlocks=$removePolicyBlocks)"

try {
    # 1. Another antivirus is active: nothing to do.
    $thirdParty = @(Get-ThirdPartyAntivirus)
    if ($thirdParty.Count -gt 0) {
        $msg = "No change: another antivirus is active ($($thirdParty -join ', '))."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }

    # 2. Group Policy leftovers that switch Defender off.
    $removed = @(Remove-PolicyBlock -Path $PolicyKey -Names @('DisableAntiSpyware', 'DisableAntiVirus') -Label 'WindowsDefenderPolicies')

    # 3. Start WinDefend.
    $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if (-not $svc) {
        $msg = 'WinDefend service is missing. This needs an in-place repair of Windows; no change made.'
        Write-FixLog $msg 'ERROR'
        Write-Output "$FindingId | Failed | $msg"
        exit 1
    }
    if ($svc.Status -ne 'Running') {
        if ([string]$svc.StartType -eq 'Disabled') {
            # WinDefend is a protected service. Its start type normally cannot be changed, even as SYSTEM.
            Write-FixLog 'WinDefend start type is Disabled. Protected service: start type is not changed by this script.' 'WARN'
            $Notes.Add('WinDefend start type is Disabled')
        }
        try {
            Start-Service -Name 'WinDefend' -ErrorAction Stop
            Write-FixLog 'Started WinDefend'
            $Notes.Add('Started WinDefend')
        }
        catch {
            Write-FixLog "Could not start WinDefend: $($_.Exception.Message)" 'ERROR'
            $Notes.Add('WinDefend could not be started')
        }
    }

    # Give Defender time to load its engine after a start or a policy change.
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-DefenderActive) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }

    # 4. ForceDefenderPassiveMode: report only.
    if ((Get-RegValue -Path $AtpPolicyKey -Name 'ForceDefenderPassiveMode') -eq 1) {
        Write-FixLog 'ForceDefenderPassiveMode=1 is set but no other antivirus is active. Not changed: remove it in the policy that sets it.' 'WARN'
        $Notes.Add('ForceDefenderPassiveMode=1 is set (not changed)')
    }

    $summary = if ($Notes.Count -gt 0) { $Notes -join '; ' } else { 'No change needed' }
    if (Test-DefenderActive) {
        Write-FixLog "Finished: Defender is active. $summary"
        Write-Output "$FindingId | Fixed | $summary"
        exit 0
    }
    if ($removed.Count -gt 0) {
        $summary += '; restart the device so Defender picks up the policy change'
    }
    Write-FixLog "Finished: Defender is still not active. $summary" 'ERROR'
    Write-Output "$FindingId | Failed | $summary. Check the log and the Microsoft-Windows-Windows Defender/Operational event log."
    exit 1
}
catch {
    $msg = "Unexpected error: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Failed | $msg"
    exit 1
}
