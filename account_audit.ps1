<#
.SYNOPSIS
    Removes members from sensitive groups and disables default accounts based on machine role.

.DESCRIPTION
    This script performs the following actions:
      - Detects if the machine is a Domain Controller.
      - Exports the current group memberships for backup.
      - Removes members from sensitive groups (on a DC) or the local Administrators group (non-DC) while honoring exclusions.
      - Disables default Administrator and Guest accounts (domain or local based on machine role).
      - Logs details of the users removed to a dedicated log file (appending with timestamps and extra details).

.PARAMETER ExcludeUsers
    A comma-separated list of usernames or group names to exclude from removal.

.PARAMETER ExcludeUser
    An additional user to exclude from removal.

.PARAMETER Interval
    Interval in seconds between repeated removal operations. Set to 0 (the default) for one-time execution.

.PARAMETER DryRun
    If specified, the script will simulate actions without making any actual changes.

.EXAMPLE
    .\Remove-AdminMembers.ps1 -ExcludeUsers "AdminUser1,AdminGroup1" -ExcludeUser "CriticalServiceUser" -Interval 3600

    This runs the removal process every 3600 seconds (1 hour), excluding both the comma‐separated list and the additional user, and making actual changes.
    
.NOTES
    Ensure you have backups of current group memberships before executing the script.
    Test the script in a non-production environment prior to deployment.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Comma-separated list of users or groups to exclude from removal.")]
    [string]$ExcludeUsers,

    [Parameter(Mandatory = $false, HelpMessage = "Additional user to exclude from removal.")]
    [string]$ExcludeUser,

    [Parameter(Mandatory = $false, HelpMessage = "Interval in seconds between repeated removal operations. Set to 0 for one-time execution.")]
    [int]$Interval = 0,

    [Parameter(Mandatory = $false, HelpMessage = "Perform a dry run without making actual changes.")]
    [switch]$DryRun
)

# ------------------------ #
#        Configuration     #
# ------------------------ #

# Define sensitive AD groups to process if running on a Domain Controller
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

# Define paths for backups and logs
$BackupPath = "C:\ADGroupBackups"
if (-Not (Test-Path -Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

# General log file (fixed file so entries are appended over time)
$LogFile = "$BackupPath\RemovalLog.txt"

# Removed users log file
$RemovedUsersLogFile = "$BackupPath\RemovedUsersLog.txt"

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
    # Append the log entry to the general log file
    Add-Content -Path $LogFile -Value $logMessage
}

function Log-Removal {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Message"
    # Append removal details to the removed users log file
    Add-Content -Path $RemovedUsersLogFile -Value $entry
}

function Export-GroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Groups
    )

    foreach ($Group in $Groups) {
        try {
            if ($global:IsDC) {
                # Export AD group members
                $Members = Get-ADGroupMember -Identity $Group -Recursive | Select-Object Name, SamAccountName, ObjectClass
                $exportFile = "$BackupPath\$($Group.Replace(' ','_'))-members.csv"
                $Members | Export-Csv -Path $exportFile -NoTypeInformation -Append
                Write-Log -Message "Exported members of AD group '$Group' to CSV ($exportFile)." -Level "INFO"
            }
            else {
                # Export local group members (Administrators group)
                $LocalGroup = [ADSI]"WinNT://./Administrators,group"
                $Members = @($LocalGroup.Invoke("Members")) | ForEach-Object {
                    $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                }
                $exportFile = "$BackupPath\LocalAdministrators-members.csv"
                $Members | Export-Csv -Path $exportFile -NoTypeInformation -Append
                Write-Log -Message "Exported members of Local Administrators group to CSV ($exportFile)." -Level "INFO"
            }
        }
        catch {
            Write-Log -Message "Failed to export members of '$Group'. Error: $_" -Level "ERROR"
        }
    }
}

function Disable-DefaultAccounts {
    if ($global:IsDC) {
        # Disable domain Administrator and Guest accounts
        try {
            $DomainSID = (Get-ADDomain).DomainSID.Value
            $AdminSid = "$DomainSID-500"
            $GuestSid = "$DomainSID-501"

            # Disable Administrator account
            $DomainAdmin = Get-ADUser -Filter "SID -eq '$AdminSid'" -ErrorAction Stop
            if ($DomainAdmin.Enabled) {
                if ($DryRun) {
                    Write-Log -Message "DryRun: Would disable domain Administrator account." -Level "INFO"
                }
                else {
                    Set-ADUser -Identity $DomainAdmin -Enabled $false
                    Write-Log -Message "Disabled domain Administrator account." -Level "INFO"
                }
            }
        }
        catch {
            Write-Log -Message "Error disabling domain Administrator account: $_" -Level "ERROR"
        }

        try {
            # Disable Guest account
            $DomainGuest = Get-ADUser -Filter "SID -eq '$GuestSid'" -ErrorAction Stop
            if ($DomainGuest.Enabled) {
                if ($DryRun) {
                    Write-Log -Message "DryRun: Would disable domain Guest account." -Level "INFO"
                }
                else {
                    Set-ADUser -Identity $DomainGuest -Enabled $false
                    Write-Log -Message "Disabled domain Guest account." -Level "INFO"
                }
            }
        }
        catch {
            Write-Log -Message "Error disabling domain Guest account: $_" -Level "ERROR"
        }
    }
    else {
        # Disable local Administrator and Guest accounts
        try {
            if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.LocalAccounts)) {
                Write-Log -Message "Microsoft.PowerShell.LocalAccounts module missing. Cannot disable local accounts." -Level "ERROR"
                return
            }
            Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

            $LocalAdmin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
            if ($LocalAdmin -and $LocalAdmin.Enabled) {
                if ($DryRun) {
                    Write-Log -Message "DryRun: Would disable local Administrator account (SID: $($LocalAdmin.SID))." -Level "INFO"
                }
                else {
                    Disable-LocalUser -SID $LocalAdmin.SID
                    Write-Log -Message "Disabled local Administrator account (SID: $($LocalAdmin.SID))." -Level "INFO"
                }
            }

            $LocalGuest = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-501") }
            if ($LocalGuest -and $LocalGuest.Enabled) {
                if ($DryRun) {
                    Write-Log -Message "DryRun: Would disable local Guest account (SID: $($LocalGuest.SID))." -Level "INFO"
                }
                else {
                    Disable-LocalUser -SID $LocalGuest.SID
                    Write-Log -Message "Disabled local Guest account (SID: $($LocalGuest.SID))." -Level "INFO"
                }
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
                if ($DryRun) {
                    Write-Log -Message "DryRun: Would remove '$($Member.SamAccountName)' from '$Group'." -Level "INFO"
                }
                else {
                    try {
                        Remove-ADGroupMember -Identity $Group -Members $Member -Confirm:$false -ErrorAction Stop
                        Write-Log -Message "Removed '$($Member.SamAccountName)' from '$Group'." -Level "INFO"
                        Log-Removal "Removed AD member '$($Member.SamAccountName)' (DN: $($Member.DistinguishedName)) from group '$Group'."
                    }
                    catch {
                        Write-Log -Message "Failed to remove '$($Member.SamAccountName)' from '$Group'. Error: $_" -Level "ERROR"
                    }
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
    $Members = @($LocalGroup.Invoke("Members")) | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }

    foreach ($Member in $Members) {
        if ($Exclusions -contains $Member) {
            Write-Log -Message "Excluded '$Member' from removal in Local Administrators group." -Level "INFO"
            continue
        }
        if ($DryRun) {
            Write-Log -Message "DryRun: Would remove '$Member' from Local Administrators group." -Level "INFO"
        }
        else {
            try {
                $LocalGroup.Remove("WinNT://$Member")
                Write-Log -Message "Removed '$Member' from Local Administrators group." -Level "INFO"
                Log-Removal "Removed local member '$Member' from Local Administrators group."
            }
            catch {
                Write-Log -Message "Failed to remove '$Member' from Local Administrators group. Error: $_" -Level "ERROR"
            }
        }
    }

    Write-Log -Message "Completed processing for Local Administrators group." -Level "INFO"
}

# Encapsulate the main removal process in a function
function Invoke-RemovalProcess {
    # Determine if the machine is a Domain Controller
    try {
        $IsDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    }
    catch {
        Write-Log -Message "Failed to determine Domain Role. Assuming non-DC. Error: $_" -Level "WARNING"
        $IsDC = $false
    }
    $global:IsDC = $IsDC

    if ($IsDC) {
        Write-Log -Message "Machine is a Domain Controller. Processing sensitive AD groups." -Level "INFO"
    }
    else {
        Write-Log -Message "Machine is not a Domain Controller. Processing Local Administrators group." -Level "INFO"
    }

    # Export current group memberships for backup
    if ($IsDC) {
        Export-GroupMemberships -Groups $SensitiveGroups
    }
    else {
        Export-GroupMemberships -Groups @("Administrators")
    }

    # Combine exclusions from both parameters into an array
    $Exclusions = @()
    if ($ExcludeUsers) {
        $Exclusions = $ExcludeUsers -split ',' | ForEach-Object { $_.Trim() }
    }
    if ($ExcludeUser) {
        $Exclusions += $ExcludeUser
    }

    # For AD (DC) exclusions, convert provided names to Distinguished Names
    $ExcludedMembers = @()
    if ($IsDC) {
        Import-Module ActiveDirectory -ErrorAction Stop
        foreach ($User in $Exclusions) {
            try {
                # Try to get as an AD User
                $ADUser = Get-ADUser -Identity $User -ErrorAction Stop
                $ExcludedMembers += $ADUser.DistinguishedName
                Write-Log -Message "Excluded AD User: $User" -Level "INFO"
            }
            catch {
                try {
                    # Try to get as an AD Group
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

    # Remove group members based on machine role
    if ($IsDC) {
        Remove-ADGroupMembers -Groups $SensitiveGroups -ExclusionsDN $ExcludedMembers
    }
    else {
        Remove-LocalGroupMembers -Exclusions $ExcludedMembers
    }

    # Disable default accounts
    Disable-DefaultAccounts

    Write-Log -Message "Removal process iteration completed." -Level "INFO"
}

# ------------------------ #
#      Main Execution      #
# ------------------------ #

if ($Interval -gt 0) {
    while ($true) {
        Invoke-RemovalProcess
        Write-Log -Message "Sleeping for $Interval seconds before next iteration." -Level "INFO"
        Start-Sleep -Seconds $Interval
    }
}
else {
    Invoke-RemovalProcess
}

Write-Log -Message "Script execution completed." -Level "INFO"
