<#
.SYNOPSIS
    Randomly toggles a network adapter on and off to disrupt adversary connectivity.

.DESCRIPTION
    Disables and re-enables a network adapter at randomized intervals. Useful for
    disrupting attacker lateral movement or C2 channels during an active incident.

    If only one network adapter is present, it is auto-detected. The disable/enable
    cycle uses a random interval between MinInterval and MaxInterval seconds. If
    Duration is set, the script stops after that many minutes; otherwise it runs
    until interrupted.

    Each toggle action is logged with a timestamp.

.PARAMETER AdapterName
    Name of the network adapter to toggle. If omitted and only one adapter exists,
    it is auto-detected. If multiple adapters exist and no name is given, the script
    exits with an error.

.PARAMETER Duration
    Total runtime in minutes. 0 (default) means run indefinitely until Ctrl+C.

.PARAMETER MinInterval
    Minimum seconds between toggle actions. Default: 3.

.PARAMETER MaxInterval
    Maximum seconds between toggle actions. Default: 10.

.EXAMPLE
    .\Toggle-NIC.ps1
    Auto-detect the single NIC and toggle it with 3-10 second random intervals.

.EXAMPLE
    .\Toggle-NIC.ps1 -AdapterName "Ethernet" -Duration 5 -MinInterval 1 -MaxInterval 5
    Toggle the "Ethernet" adapter for 5 minutes with 1-5 second intervals.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner.
    WARNING: This script performs disruptive network/session operations. Evaluate carefully before using in production environments.
#>

param(
    [string]$AdapterName,
    [int]$Duration = 0,
    [int]$MinInterval = 3,
    [int]$MaxInterval = 10
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Toggle-NIC"

# --- Auto-detect adapter if not specified ---
if (-not $AdapterName) {
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                  Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 1) {
        $AdapterName = $adapters[0].Name
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Auto-detected adapter: $AdapterName" -ForegroundColor Cyan
    } elseif ($adapters.Count -eq 0) {
        Write-Host "No active physical adapters found." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "Multiple adapters found. Specify -AdapterName:" -ForegroundColor Red
        $adapters | ForEach-Object { Write-Host "  - $($_.Name) ($($_.InterfaceDescription))" -ForegroundColor Yellow }
        exit 1
    }
}

# Validate adapter exists
$adapter = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
if (-not $adapter) {
    Write-Host "Adapter '$AdapterName' not found." -ForegroundColor Red
    exit 1
}

if ($MinInterval -gt $MaxInterval) {
    Write-Host "MinInterval ($MinInterval) cannot exceed MaxInterval ($MaxInterval)." -ForegroundColor Red
    exit 1
}

$stopTime = if ($Duration -gt 0) { (Get-Date).AddMinutes($Duration) } else { $null }
$durationMsg = if ($Duration -gt 0) { "$Duration minutes" } else { "indefinitely (Ctrl+C to stop)" }

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Toggling '$AdapterName' every ${MinInterval}-${MaxInterval}s for $durationMsg" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    if ($stopTime -and (Get-Date) -ge $stopTime) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Duration reached. Ensuring adapter is enabled." -ForegroundColor Green
        Enable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction SilentlyContinue
        break
    }

    $sleepSec = Get-Random -Minimum $MinInterval -Maximum ($MaxInterval + 1)

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] DISABLE '$AdapterName' (next action in ${sleepSec}s)" -ForegroundColor Red
    Disable-NetAdapter -Name $AdapterName -Confirm:$false
    Start-Sleep -Seconds $sleepSec

    if ($stopTime -and (Get-Date) -ge $stopTime) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Duration reached. Re-enabling adapter." -ForegroundColor Green
        Enable-NetAdapter -Name $AdapterName -Confirm:$false
        break
    }

    $sleepSec = Get-Random -Minimum $MinInterval -Maximum ($MaxInterval + 1)

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ENABLE  '$AdapterName' (next action in ${sleepSec}s)" -ForegroundColor Green
    Enable-NetAdapter -Name $AdapterName -Confirm:$false
    Start-Sleep -Seconds $sleepSec
}

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Toggle-NIC complete." -ForegroundColor Cyan
