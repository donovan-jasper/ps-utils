<#
.SYNOPSIS
    Backs up all GPOs, generates per-GPO restore scripts, and removes GPO links
    from domain root, OUs, and AD sites.

.DESCRIPTION
    Merged from gpo-wipe.ps1 and remove_gpos.ps1. This script:
        1. Backs up all GPOs to a specified folder with index.xml
        2. Creates per-GPO restore scripts (using -BackupGpoName for
           correct restore after deletion)
        3. Removes (unlinks) GPOs from the domain root (unless -SkipDomainRoot)
        4. Removes GPO links from all OUs (optionally scoped by -SearchBase)
        5. Removes GPO links from all AD sites in the forest

    Supports -WhatIf to preview without making changes.

.PARAMETER BackupPath
    Directory to store GPO backups. Defaults to "C:\GPO_Backups".

.PARAMETER SearchBase
    Optional DN to scope OU enumeration.
    Example: "OU=MyOU,DC=example,DC=com"

.PARAMETER SkipDomainRoot
    If specified, skip removing GPO links from the domain root.

.EXAMPLE
    .\Remove-GPOs.ps1 -WhatIf -Verbose
    Preview which GPO links would be removed without making changes.

.EXAMPLE
    .\Remove-GPOs.ps1 -BackupPath "D:\GPObackups" -SearchBase "OU=Test,DC=example,DC=com"
    Back up all GPOs, then remove links from domain root + OUs under the specified SearchBase + all sites.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
Param(
    [string]$BackupPath = "C:\GPO_Backups",
    [string]$SearchBase,
    [switch]$SkipDomainRoot
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Remove-GPOs"
Assert-Role -Required DomainController
Assert-Dependencies -Modules @("GroupPolicy")

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 1. Backup All GPOs and Generate Restore Scripts
# ---------------------------------------------------------------------------
Write-Verbose "Backing up all GPOs to: $BackupPath"

if (!(Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

try {
    Backup-GPO -All -Path $BackupPath -Verbose -ErrorAction Stop
} catch {
    Write-Warning "Failed to back up GPOs: $_"
    return
}

$restoreScriptFolder = Join-Path $BackupPath "RestoreScripts"
if (!(Test-Path $restoreScriptFolder)) {
    New-Item -ItemType Directory -Path $restoreScriptFolder -Force | Out-Null
}

Write-Verbose "Generating restore scripts in: $restoreScriptFolder"

$allGPOs = Get-GPO -All

foreach ($gpo in $allGPOs) {
    $safeName = $gpo.DisplayName -replace '[^\w\-\(\) \.]', '_' -replace '\s+', '_'
    $scriptPath = Join-Path $restoreScriptFolder ("Restore_" + $safeName + ".ps1")

    # Use -BackupGpoName instead of -Name so restores work even after GPO deletion
    $restoreCmd = @"
Restore-GPO -BackupGpoName "$($gpo.DisplayName)" -Path "$BackupPath"
"@

    $scriptContent = @"
# This script restores the GPO named '$($gpo.DisplayName)'
# from the backup in '$BackupPath'.
#
# Uses -BackupGpoName so the restore works even if the GPO
# has been deleted from AD (re-creates with original GUID).

$restoreCmd
"@

    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    Write-Verbose "Generated: $scriptPath"
}

# ---------------------------------------------------------------------------
# 2. Remove GPO Links from Domain Root and OUs
# ---------------------------------------------------------------------------
Write-Verbose "Preparing to remove (unlink) GPOs from domain root, OUs, and sites..."

# Domain root
if (-not $SkipDomainRoot) {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
    } catch {
        Write-Warning "Couldn't retrieve domain root DN: $_"
        $domainDN = $null
    }
} else {
    $domainDN = $null
}

# OUs
try {
    if ($SearchBase) {
        Write-Verbose "Getting OUs under SearchBase: $SearchBase"
        $allOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -ErrorAction Stop
    } else {
        Write-Verbose "Getting all OUs in the domain."
        $allOUs = Get-ADOrganizationalUnit -Filter * -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to get OUs. Error: $_"
    return
}

# Build target list: domain root + OUs
$targets = New-Object System.Collections.Generic.List[System.String]
if ($domainDN) {
    [void]$targets.Add($domainDN)
}
foreach ($ou in $allOUs) {
    [void]$targets.Add($ou.DistinguishedName)
}

Write-Verbose "Total OU/domain targets: $($targets.Count)"

foreach ($target in $targets) {
    Write-Verbose "Processing target: $target"
    try {
        $links = (Get-GPInheritance -Target $target).GpoLinks
    } catch {
        Write-Warning "Could not retrieve GPO links for $target. Error: $_"
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
                Write-Verbose "  Removed link successfully."
            } catch {
                Write-Warning "  Failed to remove link: $_"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Remove GPO Links from AD Sites (absorbed from remove_gpos.ps1)
# ---------------------------------------------------------------------------
Write-Verbose "Removing GPO links from all AD sites in the forest..."

try {
    $forestObject = Get-ADForest
    $configurationNamingContext = $forestObject.ConfigurationNamingContext
    $sitesContainer = "CN=Sites,$configurationNamingContext"

    $sites = Get-ADObject -SearchBase $sitesContainer -LDAPFilter "(objectClass=site)" -SearchScope OneLevel

    foreach ($site in $sites) {
        $siteDN = $site.DistinguishedName
        try {
            $siteInheritance = Get-GPInheritance -Target $siteDN -TargetType Site

            foreach ($link in $siteInheritance.GPLinks) {
                $msg = "Removing GPO link '$($link.DisplayName)' from site '$($site.Name)'"
                if ($PSCmdlet.ShouldProcess($siteDN, $msg)) {
                    try {
                        Remove-GPLink -Guid $link.GPOId -Target $siteDN -ErrorAction Stop
                        Write-Verbose "  Removed site link successfully."
                    } catch {
                        Write-Warning "  Failed to remove site link: $_"
                    }
                }
            }
        } catch {
            Write-Warning "Failed to retrieve/remove links on site '$($site.Name)': $($_.Exception.Message)"
        }
    }
} catch {
    Write-Warning "Failed to enumerate AD Sites: $($_.Exception.Message)"
}

Write-Verbose "Done. All GPOs backed up to '$BackupPath', restore scripts in '$restoreScriptFolder'."
Write-Host "Remove-GPOs complete. Run with -WhatIf to preview without changes."
