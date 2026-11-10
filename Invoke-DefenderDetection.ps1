<#
.SYNOPSIS
    Runs all Defender detection scripts of this repository locally and shows the results.

.DESCRIPTION
    Read-only. Use it on a test device before you deploy the remediations in Intune.
    Each detection script runs in its own Windows PowerShell process, the same way Intune runs it.
    Run it elevated (as Administrator), otherwise some values cannot be read.

.NOTES
    File Name : Invoke-DefenderDetection.ps1
    Author    : Ronny Alhelm
    Version   : 1.0
    Created   : 2026-11-10

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DefenderDetection.ps1
#>

$scripts = @(
    'Service\Detect-DefenderService.ps1',
    'Signatures\Detect-DefenderSignatures.ps1',
    'RealTimeProtection\Detect-DefenderRealTimeProtection.ps1',
    'MDEOnboarding\Detect-MDEOnboarding.ps1'
)

$results = foreach ($relative in $scripts) {
    $path = Join-Path $PSScriptRoot $relative
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path
    [pscustomobject]@{
        Script   = Split-Path $relative -Leaf
        ExitCode = $LASTEXITCODE
        Result   = ($output | Select-Object -Last 1)
    }
}

$results | Format-Table -AutoSize -Wrap
Write-Output 'Exit code 1 means Intune would run the matching remediation script.'
