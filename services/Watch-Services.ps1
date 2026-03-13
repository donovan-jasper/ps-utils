<#
.SYNOPSIS
    Continuously monitors services against a baseline snapshot for unauthorized changes.
.DESCRIPTION
    Polls every 30 seconds, comparing current service state to a Snapshot-Services.ps1 baseline.
    Alerts on: binary path changes, SDDL changes, startup type changes, new services, deleted services.

    Color-coded output:
    - Red: changed or deleted services
    - Yellow: new services
    - Green: all clear

.PARAMETER SnapshotFile
    Path to the baseline snapshot JSON. Default: services-snapshot.json in script directory.
.PARAMETER AutoRevert
    Automatically restore original SDDL and binary path from snapshot when changes detected.
.PARAMETER Interval
    Polling interval in seconds. Default: 30.
#>
param(
    [string]$SnapshotFile = (Join-Path $PSScriptRoot "services-snapshot.json"),
    [switch]$AutoRevert,
    [int]$Interval = 30
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Watch-Services"

if (-not (Test-Path $SnapshotFile)) {
    Write-Host "No snapshot found at $SnapshotFile. Run Snapshot-Services.ps1 first." -ForegroundColor Red
    exit 1
}

$baseline = [string]::Join("", (Get-Content $SnapshotFile)) | ConvertFrom-Json
$baselineByName = @{}
foreach ($svc in $baseline) {
    $baselineByName[$svc.Name] = $svc
}

Write-Host "Loaded baseline: $($baseline.Count) services. Monitoring every ${Interval}s..."
if ($AutoRevert) {
    Write-Host "AutoRevert: ON — will restore SDDL/ImagePath on change" -ForegroundColor Yellow
}

while ($true) {
    $now = Get-Date -Format "HH:mm:ss"
    $alerts = @()

    # Get current service state
    $currentServices = @{}
    Get-Service | ForEach-Object {
        $name = $_.Name
        $currentServices[$name] = $true

        $base = $baselineByName[$name]
        if (-not $base) {
            $alerts += [PSCustomObject]@{ Type = "NEW"; Name = $name; Detail = "Display: $($_.DisplayName), Status: $($_.Status)" }
            return
        }

        # Check binary path
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $regKey = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($regKey -and $regKey.ImagePath -ne $base.ImagePath) {
            $alerts += [PSCustomObject]@{
                Type = "CHANGED_PATH"; Name = $name
                Detail = "Old: $($base.ImagePath) -> New: $($regKey.ImagePath)"
            }
            if ($AutoRevert -and $base.ImagePath) {
                Set-ItemProperty -Path $regPath -Name "ImagePath" -Value $base.ImagePath -ErrorAction SilentlyContinue
            }
        }

        # Check SDDL
        $sddlLine = (sc.exe sdshow $name 2>&1 | Where-Object { $_ -match '^D:' -or $_ -match '^O:' }) | Select-Object -First 1
        $currentSDDL = if ($sddlLine) { $sddlLine.Trim() } else { "" }
        if ($currentSDDL -and $base.SDDL -and $currentSDDL -ne $base.SDDL) {
            $alerts += [PSCustomObject]@{
                Type = "CHANGED_SDDL"; Name = $name
                Detail = "SDDL modified"
            }
            if ($AutoRevert -and $base.SDDL) {
                sc.exe sdset $name $base.SDDL 2>&1 | Out-Null
            }
        }

        # Check startup type
        if ($_.StartType.ToString() -ne $base.StartType) {
            $alerts += [PSCustomObject]@{
                Type = "CHANGED_START"; Name = $name
                Detail = "Old: $($base.StartType) -> New: $($_.StartType)"
            }
        }
    }

    # Check for deleted services
    foreach ($name in $baselineByName.Keys) {
        if (-not $currentServices.ContainsKey($name)) {
            $alerts += [PSCustomObject]@{ Type = "DELETED"; Name = $name; Detail = "Service removed" }
        }
    }

    if ($alerts.Count -gt 0) {
        foreach ($alert in $alerts) {
            $color = switch ($alert.Type) {
                "NEW" { "Yellow" }
                default { "Red" }
            }
            $revertMsg = if ($AutoRevert -and $alert.Type -match "CHANGED") { " [REVERTED]" } else { "" }
            Write-Host "[$now] $($alert.Type): $($alert.Name) - $($alert.Detail)$revertMsg" -ForegroundColor $color
        }
    } else {
        Write-Host "[$now] All clear — $($baseline.Count) services match baseline" -ForegroundColor Green
    }

    Start-Sleep -Seconds $Interval
}
