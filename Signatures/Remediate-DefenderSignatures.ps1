<#
.SYNOPSIS
    Intune remediation: update Microsoft Defender security intelligence (signatures).

.DESCRIPTION
    Finding ID: DEF.SIGNATURE.OUTDATED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Steps (stops at the first one that brings the signatures up to date):
      1. MpCmdRun -SignatureUpdate with the sources configured on the device (WSUS, Windows Update, file share, ...).
      2. MpCmdRun -SignatureUpdate -MMPC, which downloads directly from Microsoft and works around
         a broken or unreachable WSUS / Windows Update source.
      3. MpCmdRun -RemoveDefinitions -DynamicSignatures (removes only the cached cloud-delivered
         signatures, which Defender downloads again) and then step 2 again.

    The full signature set is never removed and the update source configuration is not changed.
    The script logs the configured fallback order and the state of the Windows Update service,
    which are the most common reasons for failing updates.

    Exit 0 = signatures are current afterwards, exit 1 = still outdated (see output and log).

.NOTES
    File Name : Remediate-DefenderSignatures.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell
    Log       : C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DefenderFix.log

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Remediate-DefenderSignatures.ps1
#>

$FindingId           = 'DEF.SIGNATURE.OUTDATED'
$MaxSignatureAgeDays = 3
$UpdateTimeoutSec    = 600
$LogFile             = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'
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

function Get-MpCmdRunPath {
    # Prefer the current platform folder; fall back to the inbox copy.
    $location = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender' -Name 'InstallLocation'
    if ($location) {
        $candidate = Join-Path $location 'MpCmdRun.exe'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $inbox = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path -LiteralPath $inbox) { return $inbox }
    return $null
}

function Invoke-MpCmdRun {
    # Runs MpCmdRun with a timeout and returns its exit code (-1 on timeout or start failure).
    param([string]$Path, [string]$Arguments)
    Write-FixLog "Running MpCmdRun $Arguments"
    try {
        $p = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
        if (-not $p.WaitForExit($UpdateTimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            Write-FixLog "MpCmdRun $Arguments timed out after $UpdateTimeoutSec seconds" 'ERROR'
            return -1
        }
        Write-FixLog "MpCmdRun $Arguments exit code $($p.ExitCode)"
        return $p.ExitCode
    }
    catch {
        Write-FixLog "MpCmdRun $Arguments could not start: $($_.Exception.Message)" 'ERROR'
        return -1
    }
}

function Get-SignatureAge {
    try { return [int](Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge } catch { return 65535 }
}

Write-FixLog 'Started'

try {
    $thirdParty = @(Get-ThirdPartyAntivirus)
    if ($thirdParty.Count -gt 0) {
        $msg = "No change: another antivirus is active ($($thirdParty -join ', '))."
        Write-FixLog $msg
        Write-Output "$FindingId | OK | $msg"
        exit 0
    }

    $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        $msg = 'WinDefend is not running, so signatures cannot be updated. Fix DEF.SERVICE.STOPPED first.'
        Write-FixLog $msg 'ERROR'
        Write-Output "$FindingId | Failed | $msg"
        exit 1
    }

    $mpCmdRun = Get-MpCmdRunPath
    if (-not $mpCmdRun) {
        $msg = 'MpCmdRun.exe not found.'
        Write-FixLog $msg 'ERROR'
        Write-Output "$FindingId | Failed | $msg"
        exit 1
    }

    # Context for the log: why updates may fail.
    $fallback = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' -Name 'FallbackOrder'
    if (-not $fallback) { $fallback = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender' -Name 'SignatureUpdateFallbackOrder' }
    if ($fallback) { Write-FixLog "Configured signature fallback order: $fallback" }
    $wu = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($wu -and [string]$wu.StartType -eq 'Disabled') {
        Write-FixLog 'Windows Update service (wuauserv) is disabled. Updates through Windows Update / WSUS cannot work.' 'WARN'
        $Notes.Add('wuauserv is disabled')
    }

    $before = Get-SignatureAge
    Write-FixLog "Signature age before: $before days"

    # 1. Configured sources.
    $null = Invoke-MpCmdRun -Path $mpCmdRun -Arguments '-SignatureUpdate'
    $age = Get-SignatureAge
    if ($age -le $MaxSignatureAgeDays) {
        $Notes.Add('Updated from the configured source')
    }
    else {
        # 2. Directly from Microsoft.
        $null = Invoke-MpCmdRun -Path $mpCmdRun -Arguments '-SignatureUpdate -MMPC'
        $age = Get-SignatureAge
        if ($age -le $MaxSignatureAgeDays) {
            $Notes.Add('Updated directly from Microsoft (MMPC); check the configured update source')
        }
        else {
            # 3. Clear cached dynamic signatures and try again.
            $null = Invoke-MpCmdRun -Path $mpCmdRun -Arguments '-RemoveDefinitions -DynamicSignatures'
            $null = Invoke-MpCmdRun -Path $mpCmdRun -Arguments '-SignatureUpdate -MMPC'
            $age = Get-SignatureAge
            if ($age -le $MaxSignatureAgeDays) {
                $Notes.Add('Updated after clearing cached dynamic signatures')
            }
        }
    }

    $summary = $Notes -join '; '
    if ($age -le $MaxSignatureAgeDays) {
        $msg = "Signatures are $age days old now (were $before). $summary"
        Write-FixLog "Finished: $msg"
        Write-Output "$FindingId | Fixed | $msg"
        exit 0
    }
    $msg = "Signatures are still $age days old. $summary Check proxy access to definitionupdates.microsoft.com and go.microsoft.com, and the MpCmdRun log in C:\Windows\Temp."
    Write-FixLog "Finished: $msg" 'ERROR'
    Write-Output "$FindingId | Failed | $msg"
    exit 1
}
catch {
    $msg = "Unexpected error: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Failed | $msg"
    exit 1
}
