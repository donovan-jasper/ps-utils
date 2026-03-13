<#
.SYNOPSIS
    Installs all dependencies needed by the toolkit on the current machine.
.DESCRIPTION
    Detects machine role (DC vs workstation) and installs the appropriate set of
    dependencies. Checks what's already installed and skips it. Supports offline
    mode for air-gapped environments.

    Dependencies installed:
    - DSInternals module (for Dump-Hashes, Rollback-Users)
    - ActiveDirectory module (RSAT, for all credential/AD scripts)
    - DnsServer module (RSAT, for DNS scripts - DC only)
    - GroupPolicy module (RSAT, for Remove-GPOs)
    - Sysmon (from logging/ directory if present)
    - NuGet package provider (required for Install-Module)
.PARAMETER Offline
    Skip downloads, only install from local files in the repo.
#>
param(
    [switch]$Offline
)

$ErrorActionPreference = "Stop"

# Detect role
try {
    $productType = (Get-CimInstance Win32_OperatingSystem).ProductType
} catch {
    $productType = (Get-WmiObject Win32_OperatingSystem).ProductType
}
$isDC = $productType -eq 2
$role = if ($isDC) { "Domain Controller" } else { "Workstation/Member Server" }
Write-Host "Detected role: $role" -ForegroundColor Cyan

# NuGet provider (needed for Install-Module)
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    if ($Offline) {
        Write-Host "SKIP: NuGet provider (offline mode)" -ForegroundColor Yellow
    } else {
        Write-Host "Installing NuGet provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }
} else {
    Write-Host "NuGet provider: already installed" -ForegroundColor Green
}

# DSInternals
if (-not (Get-Module -ListAvailable -Name DSInternals)) {
    if ($Offline) {
        Write-Host "SKIP: DSInternals (offline mode, install manually)" -ForegroundColor Yellow
    } else {
        Write-Host "Installing DSInternals..."
        Install-Module -Name DSInternals -Force -AllowClobber
    }
} else {
    Write-Host "DSInternals: already installed" -ForegroundColor Green
}

# RSAT features (Windows 10/11 and Server 2019+)
$rsatFeatures = @("Rsat.ActiveDirectory.DS-LDS.Tools")
if ($isDC) {
    $rsatFeatures += "Rsat.Dns.Tools"
    $rsatFeatures += "Rsat.GroupPolicy.Management.Tools"
}

foreach ($feature in $rsatFeatures) {
    $installed = Get-WindowsCapability -Online -Name "$feature*" -ErrorAction SilentlyContinue |
        Where-Object State -eq "Installed"
    if (-not $installed) {
        if ($Offline) {
            Write-Host "SKIP: $feature (offline mode)" -ForegroundColor Yellow
        } else {
            Write-Host "Installing $feature..."
            Add-WindowsCapability -Online -Name "$feature~~~~0.0.1.0" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "$feature`: already installed" -ForegroundColor Green
    }
}

# For older Windows Server (2016), RSAT is installed via WindowsFeature
if ($productType -ne 1) {
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory
    if (-not $adModule) {
        Write-Host "Installing AD module via WindowsFeature..."
        Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction SilentlyContinue
    }
    if ($isDC) {
        Install-WindowsFeature RSAT-DNS-Server -ErrorAction SilentlyContinue
        Install-WindowsFeature GPMC -ErrorAction SilentlyContinue
    }
}

Write-Host "`nDependency installation complete." -ForegroundColor Green
Write-Host "Run individual scripts - each will verify its own dependencies before executing."
