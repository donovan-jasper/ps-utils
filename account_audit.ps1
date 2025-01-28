<#
.SYNOPSIS
    Removes members from sensitive groups and disables default accounts based on machine role.

.DESCRIPTION
    This script performs the following actions:
    - Detects if the machine is a Domain Controller.
    - Removes members from sensitive groups (DC) or local Administrators group (non-DC) with exclusions.
    - Disables default Administrator and Guest accounts (domain or local based on machine role).

.PARAMETER ExcludeUsers
    A comma-separated list of usernames or group names to exclude from removal.

.EXAMPLE
    .\Remove-AdminMembers.ps1 -ExcludeUsers "AdminUser1,AdminGroup1"

.NOTES
    Ensure you have backups of current group memberships before executing the script.
    Test the script in a non-production environment prior to deployment.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Comma-separated list of users or groups to exclude from removal.")]
    [string]$ExcludeUsers
)

# ------------------------ #
#        Configuration     #
# ------------------------ #

# Define sensitive AD groups to process if DC
$SensitiveGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

# Define path for backups and logs
$BackupPath = "C:\ADGroupBackups"
$LogFile = "C:\ADGroupBackups\RemovalLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# ------------------------ #
#        Functions         #
# ------------------------ #

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO","WARNING","ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] - $Message"
    Write-Output $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

function Export-GroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Groups
    )

    if (-Not (Test-Path -Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }

    foreach ($Group in $Groups) {
        try {
            if ($IsDC) {
                # Export AD group members
                $Members = Get-ADGroupMember -Identity $Group -Recursive | Select-Object Name, SamAccountName, ObjectClass
                $Members | Export-Csv -Path "$BackupPath\$($Group.Replace(' ','_'))-members.csv" -NoTypeInformation
                Write-Log -Message "Exported members of AD group '$Group' to CSV." -Level "INFO"
            }
            else {
                # Export local group members
                $LocalGroup = [ADSI]"WinNT://./Administrators,group"
                $Members = @($LocalGroup.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                $Members | Export-Csv -Path "$BackupPath\LocalAdministrators-members.csv" -NoTypeInformation
                Write-Log -Message "Exported members of Local Administrators group to CSV." -Level "INFO"
            }
        }
        catch {
            Write-Log -Message "Failed to export members of '$Group'. Error: $_" -Level "ERROR"
        }
    }
}

function Disable-DefaultAccounts {
    if ($IsDC) {
        # Disable domain Administrator and Guest accounts
        try {
            $DomainSID = (Get-ADDomain).DomainSID.Value
            $AdminSid = "$DomainSID-500"
            $GuestSid = "$DomainSID-501"

            # Disable Administrator
            $DomainAdmin = Get-ADUser -Filter "SID -eq '$AdminSid'" -ErrorAction Stop
            if ($DomainAdmin.Enabled) {
                Set-ADUser -Identity $DomainAdmin -Enabled $false
                Write-Log -Message "Disabled domain Administrator account." -Level "INFO"
            }
        }
        catch {
            Write-Log -Message "Error disabling domain Administrator account: $_" -Level "ERROR"
        }

        try {
            # Disable Guest
            $DomainGuest = Get-ADUser -Filter "SID -eq '$GuestSid'" -ErrorAction Stop
            if ($DomainGuest.Enabled) {
                Set-ADUser -Identity $DomainGuest -Enabled $false
                Write-Log -Message "Disabled domain Guest account." -Level "INFO"
            }
        }
        catch {
            Write-Log -Message "Error disabling domain Guest account: $_" -Level "ERROR"
        }
    }
    else {
        # Disable local Administrator and Guest accounts
        try {
            # Check for required module
            if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts)) {
                Write-Log -Message "Microsoft.PowerShell.LocalAccounts module missing. Cannot disable local accounts." -Level "ERROR"
                return
            }
            Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

            # Disable Local Administrator
            $LocalAdmin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
            if ($LocalAdmin -and $LocalAdmin.Enabled) {
                Disable-LocalUser -SID $LocalAdmin.SID
                Write-Log -Message "Disabled local Administrator account (SID: $($LocalAdmin.SID))." -Level "INFO"
            }

            # Disable Local Guest
            $LocalGuest = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-501") }
            if ($LocalGuest -and $LocalGuest.Enabled) {
                Disable-LocalUser -SID $LocalGuest.SID
                Write-Log -Message "Disabled local Guest account (SID: $($LocalGuest.SID))." -Level "INFO"
            }
        }
        catch {
            Write-Log -Message "Error disabling local accounts: $_" -Level "ERROR"
        }
    }
}

function Remove-ADGroupMembers {
    param (
        [string[]]$Groups,
        [string[]]$ExclusionsDN
    )

    foreach ($Group in $Groups) {
        try {
            $Members = Get-ADGroupMember -Identity $Group -Recursive
            foreach ($Member in $Members) {
                if ($ExclusionsDN -contains $Member.DistinguishedName) {
                    Write-Log -Message "Excluded '$($Member.SamAccountName)' from removal in '$Group'." -Level "INFO"
                    continue
                }

                try {
                    Remove-ADGroupMember -Identity $Group -Members $Member -Confirm:$false -ErrorAction Stop
                    Write-Log -Message "Removed '$($Member.SamAccountName)' from '$Group'." -Level "INFO"
                }
                catch {
                    Write-Log -Message "Failed to remove '$($Member.SamAccountName)' from '$Group'. Error: $_" -Level "ERROR"
                }
            }
            Write-Log -Message "Completed processing for '$Group'." -Level "INFO"
        }
        catch {
            Write-Log -Message "Error processing group '$Group'. Error: $_" -Level "ERROR"
        }
    }
}

function Remove-LocalGroupMembers {
    param (
        [string[]]$Exclusions
    )

    $LocalGroup = [ADSI]"WinNT://./Administrators,group"
    $Members = @($LocalGroup.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

    foreach ($Member in $Members) {
        if ($Exclusions -contains $Member) {
            Write-Log -Message "Excluded '$Member' from removal in Local Administrators group." -Level "INFO"
            continue
        }

        try {
            $LocalGroup.Remove("WinNT://$Member")
            Write-Log -Message "Removed '$Member' from Local Administrators group." -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to remove '$Member' from Local Administrators group. Error: $_" -Level "ERROR"
        }
    }

    Write-Log -Message "Completed processing for Local Administrators group." -Level "INFO"
}

# ------------------------ #
#      Main Execution      #
# ------------------------ #

# Determine if the machine is a Domain Controller
try {
    $IsDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
}
catch {
    Write-Log -Message "Failed to determine Domain Role. Assuming non-DC. Error: $_" -Level "WARNING"
    $IsDC = $false
}

# Parse ExcludeUsers parameter into an array
$Exclusions = @()
if ($ExcludeUsers) {
    $Exclusions = $ExcludeUsers -split ',' | ForEach-Object { $_.Trim() }
    Write-Log -Message "Exclusions provided: $($Exclusions -join ', ')" -Level "INFO"
}

# Export current group memberships
if ($IsDC) {
    Write-Log -Message "Machine is a Domain Controller. Processing sensitive AD groups." -Level "INFO"
    Export-GroupMemberships -Groups $SensitiveGroups
}
else {
    Write-Log -Message "Machine is not a Domain Controller. Processing Local Administrators group." -Level "INFO"
    Export-GroupMemberships -Groups @("Administrators")
}

# Convert exclusions to Distinguished Names for AD groups or exact names for local groups
$ExcludedMembers = @()

if ($IsDC) {
    Import-Module ActiveDirectory -ErrorAction Stop

    foreach ($User in $Exclusions) {
        try {
            # Attempt to get as AD User
            $ADUser = Get-ADUser -Identity $User -ErrorAction Stop
            $ExcludedMembers += $ADUser.DistinguishedName
            Write-Log -Message "Excluded AD User: $User" -Level "INFO"
        }
        catch {
            try {
                # Attempt to get as AD Group
                $ADGroup = Get-ADGroup -Identity $User -ErrorAction Stop
                $ExcludedMembers += $ADGroup.DistinguishedName
                Write-Log -Message "Excluded AD Group: $User" -Level "INFO"
            }
            catch {
                Write-Log -Message "Excluded member '$User' not found as User or Group in AD." -Level "WARNING"
            }
        }
    }
}
else {
    # For local groups, exclusions are based on exact names
    $ExcludedMembers = $Exclusions
}

# Execute removal based on machine role
if ($IsDC) {
    Remove-ADGroupMembers -Groups $SensitiveGroups -ExclusionsDN $ExcludedMembers
}
else {
    Remove-LocalGroupMembers -Exclusions $ExcludedMembers
}

# Disable default accounts
Disable-DefaultAccounts

Write-Log -Message "Script execution completed." -Level "INFO"