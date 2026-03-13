<#
.SYNOPSIS
    Executes a PowerShell script on multiple remote Windows hosts via PsExec.
.DESCRIPTION
    Reads a list of IPs from an inventory file, encodes the specified script as
    base64, and runs it remotely on each host using PsExec64. Useful for deploying
    hardening scripts or configuration changes across multiple machines simultaneously.

.PARAMETER inventory
    File containing one IP per line.
.PARAMETER password
    Password for the administrator account on all target hosts.
.PARAMETER script
    Path to the local PowerShell script to execute remotely.
.PARAMETER PsExecPath
    Path to PsExec64.exe. Default: searches current directory, then PATH.
#>
param(
    [string]$inventory, # File containing the list of IPs (inventory file)
    [string]$password,  # Password for all hosts
    [string]$script,    # Path to the local script to execute
    [string]$PsExecPath # Path to PsExec64.exe (optional)
)

function WindowsExecute {
    param (
        [string]$ip,
        [string]$password,
        [string]$script
    )

    # Find PsExec: explicit path, current dir, or PATH
    if (-not $PsExecPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot "PsExec64.exe"),
            (Join-Path "." "PsExec64.exe")
        )
        foreach ($c in $candidates) {
            if (Test-Path $c) { $PsExecPath = $c; break }
        }
        if (-not $PsExecPath) {
            $found = Get-Command PsExec64.exe -ErrorAction SilentlyContinue
            if ($found) { $PsExecPath = $found.Source }
        }
    }

    if (-not $PsExecPath -or -not (Test-Path $PsExecPath)) {
        Write-Error "PsExec64.exe not found. Provide -PsExecPath or place it in the script directory."
        return
    }
    if (-not (Test-Path $psexecPath)) {
        Write-Error "PsExec not found. Please ensure PsExec is installed to $psexecPath"
        return
    }

    # Read the script and encode it to Base64
    $scriptContent = Get-Content -Path $script -Raw
    $base64Script = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptContent))

    $command = "powershell -enc $base64Script"

    # Execute the script remotely using PsExec
    $psexecCommand = "$psexecPath -NoBanner \\$ip -u administrator -p $password $command"

    try {
        # Run the PsExec command and check for success
        Write-Host "Running command: $psexecCommand"
        $output = Invoke-Expression $psexecCommand
        Write-Host "Successfully executed the script on $ip"
        Write-Host "Output: $output"
    } catch {
        Write-Error "Failed to execute the script on $ip"
    }
}

# Validate parameters
if (-not $inventory -or -not (Test-Path $inventory)) {
    Write-Error "Error: Inventory file not found."
    exit 1
}

if (-not $script -or -not (Test-Path $script)) {
    Write-Error "Error: Script file not found."
    exit 1
}

if (-not $password) {
    Write-Error "Error: Password is required."
    exit 1
}

# Read IPs from the inventory file
$ips = Get-Content -Path $inventory

# Loop over each IP and execute the script
foreach ($ip in $ips) {
    WindowsExecute -ip $ip -username $username -password $password -script $script
}
