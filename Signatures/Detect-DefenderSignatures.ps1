<#
.SYNOPSIS
    Intune detection: Microsoft Defender security intelligence (signatures) outdated.

.DESCRIPTION
    Finding ID: DEF.SIGNATURE.OUTDATED (same ID as Get-ClientHealth.ps1 in roalhelm/ClientFixPage).

    Read-only. Reports an issue when the antivirus signatures are older than $MaxSignatureAgeDays days.
    Not applicable (exit 0) when another antivirus is active, because Defender then does not need
    current signatures for real-time protection.

    Exit 0 = healthy or not applicable, exit 1 = issue found (Intune runs the remediation).

.NOTES
    File Name : Detect-DefenderSignatures.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10
    Requires  : Windows 10/11, Windows PowerShell 5.1, run as SYSTEM in 64-bit PowerShell

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Detect-DefenderSignatures.ps1
#>

$FindingId           = 'DEF.SIGNATURE.OUTDATED'
$MaxSignatureAgeDays = 3   # same threshold as Get-ClientHealth.ps1
$LogFile             = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\DefenderFix.log'

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
    $age = [int]$mp.AntivirusSignatureAge          # 65535 when signatures were never loaded
    $lastUpdated = $mp.AntivirusSignatureLastUpdated
    $version = [string]$mp.AntivirusSignatureVersion

    if ($age -gt $MaxSignatureAgeDays) {
        $msg = "Signatures are $age days old (limit $MaxSignatureAgeDays). Version $version, last update $lastUpdated."
        Write-FixLog $msg 'WARN'
        Write-Output "$FindingId | Issue | $msg"
        exit 1
    }

    $msg = "Signatures are current ($age days, version $version, engine $($mp.AMEngineVersion), platform $($mp.AMProductVersion))."
    Write-FixLog $msg
    Write-Output "$FindingId | OK | $msg"
    exit 0
}
catch {
    $msg = "Signature status could not be read: $($_.Exception.Message)"
    Write-FixLog $msg 'ERROR'
    Write-Output "$FindingId | Issue | $msg"
    exit 1
}
