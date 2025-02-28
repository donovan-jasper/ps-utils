<#
.SYNOPSIS
    Removes (unlinks) all GPOs from all OUs, the domain root, and (optionally) all AD sites.

.DESCRIPTION
    This script will:
    1. Enumerate all OUs and remove any linked GPOs.
    2. Remove GPO links from the domain root (by DN).
    3. Remove GPO links from each AD site in the forest.

    Use with extreme caution. Test in a non-production environment first!
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy

###############################################################################
# 0. Get Domain and Forest Information
###############################################################################

# Get domain info
$domainObject = Get-ADDomain
$domainName   = $domainObject.DNSRoot              # e.g. "lowkey.studios"
$domainDN     = $domainObject.DistinguishedName    # e.g. "DC=lowkey,DC=studios"

# Get forest info
$forestObject          = Get-ADForest
$configurationNamingContext = $forestObject.ConfigurationNamingContext
# This should look like "CN=Configuration,DC=lowkey,DC=studios"

Write-Host "Domain Name (DNSRoot): $domainName"
Write-Host "Domain DistinguishedName: $domainDN"
Write-Host "Configuration Naming Context: $configurationNamingContext"
Write-Host "-----------------------------------------------------------------`n"

###############################################################################
# 1. Remove GPO links from ALL Organizational Units
###############################################################################
Write-Host "=== Removing GPO links from all OUs in $domainDN ==="
$AllOUs = Get-ADOrganizationalUnit -Filter *

foreach ($OU in $AllOUs) {
    try {
        # Retrieve GP Inheritance for this OU using its DN
        $inheritance = Get-GPInheritance -Target $OU.DistinguishedName

        foreach ($link in $inheritance.GPLinks) {
            Write-Host "Removing GPO link '$($link.DisplayName)' from OU: $($OU.DistinguishedName)"
            Remove-GPLink -Name $link.DisplayName -Target $OU.DistinguishedName -Confirm:$false
        }
    }
    catch {
        Write-Warning "Failed to retrieve/remove links on OU: $($OU.DistinguishedName). Error: $($_.Exception.Message)"
    }
}

###############################################################################
# 2. Remove GPO links at the Domain Root (must use the DN, not DNS name)
###############################################################################
Write-Host "`n=== Removing GPO links from the domain root: $domainDN ==="

try {
    # Use domain DN for the target
    $domainInheritance = Get-GPInheritance -Target $domainDN
    foreach ($link in $domainInheritance.GPLinks) {
        Write-Host "Removing GPO link '$($link.DisplayName)' from domain root: $domainDN"
        Remove-GPLink -Name $link.DisplayName -Target $domainDN -TargetType Domain -Confirm:$false
    }
}
catch {
    Write-Warning "Failed to retrieve/remove links at domain root ($domainDN). Error: $($_.Exception.Message)"
}

###############################################################################
# 3. Remove GPO links from all AD Sites
###############################################################################
Write-Host "`n=== Removing GPO links from all AD sites in the forest ==="

# Construct the full path to the Sites container
$sitesContainer = "CN=Sites,$configurationNamingContext"

try {
    # Enumerate all site objects under CN=Sites,<ConfigurationNC>
    $sites = Get-ADObject -SearchBase $sitesContainer -LDAPFilter "(objectClass=site)" -SearchScope OneLevel

    foreach ($site in $sites) {
        $siteDN = $site.DistinguishedName
        try {
            # Retrieve GP Inheritance for this site
            $siteInheritance = Get-GPInheritance -Target $siteDN -TargetType Site

            foreach ($link in $siteInheritance.GPLinks) {
                Write-Host "Removing GPO link '$($link.DisplayName)' from site: $($site.Name)"
                Remove-GPLink -Name $link.DisplayName -Target $siteDN -TargetType Site -Confirm:$false
            }
        }
        catch {
            Write-Warning "Failed to retrieve/remove links on site: $($site.Name). Error: $($_.Exception.Message)"
        }
    }
}
catch {
    Write-Warning "Failed to enumerate AD Sites. Error: $($_.Exception.Message)"
}

Write-Host "`nAll GPO links removed from OUs, domain root, and sites (where applicable)."
