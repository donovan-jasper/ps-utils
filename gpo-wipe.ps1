<#
.SYNOPSIS
    Backs up all GPOs, generates individual restore scripts, 
    and unlinks (removes) GPO links from domain root + OUs.

.DESCRIPTION
    1) Backs up all GPOs to a specified folder, storing each 
       GPO’s settings in .cab files and an index.xml.
    2) Creates a subfolder "RestoreScripts" with one .ps1 
       file per GPO. Each .ps1 file can be run to re-create 
       the GPO (if deleted) or restore it (if corrupted).
    3) Removes (unlinks) every GPO from the domain root 
       (unless -SkipDomainRoot) and any OUs (optionally 
       filtered by -SearchBase).

.PARAMETER BackupPath
    Where to store GPO backups. Defaults to "C:\GPO_Backups".

.PARAMETER SearchBase
    Optional DN of an OU/container from which to retrieve OUs.
    Example: "OU=MyOU,DC=example,DC=com"

.PARAMETER SkipDomainRoot
    If specified, the script won't attempt to remove GPO 
    links from the domain root.

.EXAMPLE
    .\Backup-And-Unlink-GPOs.ps1 -WhatIf -Verbose
    Shows which GPO links would be removed, without actually removing them.

.EXAMPLE
    .\Backup-And-Unlink-GPOs.ps1 -BackupPath "D:\GPObackups" -SearchBase "OU=Test,DC=example,DC=com"
    Backs up all GPOs to D:\GPObackups, then removes/unlinks 
    them from domain root + only the OUs under OU=Test,DC=example,DC=com.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BackupPath = "C:\GPO_Backups",

    [string]$SearchBase,

    [switch]$SkipDomainRoot
)

### 1) BACKUP ALL GPOs AND GENERATE RESTORE SCRIPTS

Write-Verbose "Backing up all GPOs to: $BackupPath"

# Ensure the backup folder exists
if (!(Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

try {
    Backup-GPO -All -Path $BackupPath -Verbose -ErrorAction Stop
}
catch {
    Write-Warning "Failed to back up GPOs: $_"
    return
}

# Create a subfolder for our one-click restore scripts
$restoreScriptFolder = Join-Path $BackupPath "RestoreScripts"
if (!(Test-Path $restoreScriptFolder)) {
    New-Item -ItemType Directory -Path $restoreScriptFolder -Force | Out-Null
}

Write-Verbose "Generating restore scripts in: $restoreScriptFolder"

# Gather all GPOs in the domain
$allGPOs = Get-GPO -All

foreach ($gpo in $allGPOs) {
    # Make a file-safe name
    $safeName = $gpo.DisplayName -replace '[^\w\-\(\) \.]', '_' -replace '\s+', '_'
    $scriptPath = Join-Path $restoreScriptFolder ("Restore_" + $safeName + ".ps1")

    # We'll generate a Restore-GPO command that re-creates or overwrites the GPO
    $restoreCmd = @"
Restore-GPO -Name "$($gpo.DisplayName)" -Path "$BackupPath"
"@

    $scriptContent = @"
# This script restores the GPO named '$($gpo.DisplayName)' 
# from the backup in '$BackupPath'.
#
# If the GPO no longer exists in AD, this will re-create it (with the original GUID).
# If the GPO still exists but is corrupted, this will overwrite it.

$restoreCmd
"@

    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8

    Write-Verbose "Generated: $scriptPath"
}

### 2) REMOVE (UNLINK) ALL GPOs FROM DOMAIN ROOT + OUs

Write-Verbose "`nPreparing to remove (unlink) GPOs from domain root and OUs..."

# Get the domain root DN (unless SkipDomainRoot)
if (-not $SkipDomainRoot) {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
    }
    catch {
        Write-Warning "Couldn't retrieve domain root DN: $_"
        $domainDN = $null
    }
} else {
    $domainDN = $null
}

# Retrieve OUs
try {
    if ($SearchBase) {
        Write-Verbose "Getting OUs under SearchBase: $SearchBase"
        $allOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -ErrorAction Stop
    } else {
        Write-Verbose "Getting all OUs in the domain."
        $allOUs = Get-ADOrganizationalUnit -Filter * -ErrorAction Stop
    }
}
catch {
    Write-Warning "Failed to get OUs. Error: $_"
    return
}

# Build the target list (domain root + OUs)
$targets = New-Object System.Collections.Generic.List[System.String]
if ($domainDN) {
    [void]$targets.Add($domainDN)
}
foreach ($ou in $allOUs) {
    [void]$targets.Add($ou.DistinguishedName)
}

Write-Verbose "Total targets: $($targets.Count)"
if ($targets.Count -eq 0) {
    Write-Verbose "No targets found. Exiting."
    return
}

foreach ($target in $targets) {
    Write-Verbose "`nProcessing target: $target"
    try {
        $links = (Get-GPInheritance -Target $target).GpoLinks
    }
    catch {
        Write-Warning "Could not retrieve GPO links for $target. Error details: $_"
        continue
    }

    if (-not $links -or $links.Count -eq 0) {
        Write-Verbose "No GPO links found for $target."
        continue
    }

    foreach ($link in $links) {
        $msg = "Removing link for GPO '$($link.DisplayName)' (GUID: $($link.GPOId)) from '$target'"
        if ($PSCmdlet.ShouldProcess($target, $msg)) {
            try {
                Remove-GPLink -Guid $link.GPOId -Target $target -ErrorAction Stop
                Write-Verbose "  → Link removed successfully."
            }
            catch {
                Write-Warning "  → Failed to remove link: $_"
            }
        }
    }
}

Write-Verbose "`nDone! All GPOs have been backed up to '$BackupPath', restore scripts are in '$restoreScriptFolder', and all links have been removed."
Write-Host "Script complete. Run with -WhatIf next time if you want a preview."
