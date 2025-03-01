<#
.SYNOPSIS
  Script to set one user as the sole owner (and group) of specific Windows services,
  removing all other permissions.

.DESCRIPTION
  1. Prompts for the user account to own the services (e.g. "MYDOMAIN\MyUser").
  2. Enumerates a list of critical services (update as needed).
  3. Builds a new SDDL that sets:
       - Owner = your specified account SID
       - Group = your specified account SID
       - DACL = only your specified account SID has Full Access
     (No SACL is specified, and no other ACEs remain.)
  4. Applies the new SDDL via `sc.exe sdset`.

  Result: That one account is the ONLY principal with full control. 
          SYSTEM, TrustedInstaller, etc. lose all rights.

  WARNING: Likely to break Windows or domain services. Use at your own risk.
#>

# Prompt for the user account in "DOMAIN\User" or ".\User" form
$TargetAccount = Read-Host "Enter the account that should exclusively own the services (e.g. MYDOMAIN\MyServiceAdmin)"

# Convert that account to its SID
try {
    $acctSID = ([System.Security.Principal.NTAccount] $TargetAccount).Translate([System.Security.Principal.SecurityIdentifier]).Value
}
catch {
    Write-Error "Failed to resolve SID for account '$TargetAccount'. Check the name and try again."
    return
}

# Function returns a highly restrictive SDDL string:
#    Owner = $OwnerSID
#    Group = $OwnerSID
#    DACL  = only $OwnerSID has full control (FA).
# No SACL ("S:") is specified.
function Get-RestrictiveSDDL {
    param (
        [string] $OwnerSID
    )
    # Format string approach to avoid parsing issues
    return ("O:{0}G:{0}D:(A;;FA;;;{0})" -f $OwnerSID)
}

# List of services to modify. These are examples; add/remove as needed.
# **Some of these do not exist on all systems (e.g., DNS on a non-DC).**
# **Likely to break domain controllers if you remove Netlogon, DNS, etc. from SYSTEM.**
$CriticalServices = @(
    # Core Windows services
    "W32Time",       # Windows Time
    "CryptSvc",      # Cryptographic Services
    "WinDefend",     # Microsoft Defender Antivirus
    "Dhcp",          # DHCP Client
    "EventLog",      # Windows Event Log
    "PlugPlay",      # Plug and Play
    "Spooler",       # Print Spooler
    
    # Domain-related services
    "Netlogon",      # Net Logon
    "DNS",           # DNS Server
    "Dnscache",      # DNS Client
    "LanmanServer",  # Server (file/print sharing)
    "LanmanWorkstation" # Workstation (SMB client)
)

foreach ($serviceName in $CriticalServices) {
    Write-Host ("Processing service: {0}" -f $serviceName)

    try {
        # 1. Retrieve current SDDL (for reference/logging)
        $currentSDDL = sc.exe sdshow $serviceName 2>$null
        if (-not $currentSDDL) {
            Write-Warning ("Could not retrieve SDDL for {0}. Possibly doesn't exist on this system. Skipping..." -f $serviceName)
            continue
        }
        
        Write-Host ("Current SDDL for {0}:" -f $serviceName)
        Write-Host $currentSDDL
        Write-Host "---------------------------------------------"
        
        # 2. Build the new SDDL (only $acctSID for everything)
        $newSDDL = Get-RestrictiveSDDL -OwnerSID $acctSID
        
        Write-Host ("Applying new SDDL to {0}:" -f $serviceName)
        Write-Host $newSDDL
        Write-Host "---------------------------------------------"

        # 3. Set the service's security descriptor
        sc.exe sdset $serviceName $newSDDL | Out-Null

        Write-Host ("Successfully updated {0}." -f $serviceName)
    }
    catch {
        Write-Warning ("Error processing service '{0}': {1}" -f $serviceName, $_.Exception.Message)
    }
}

Write-Host "Script complete. A reboot may be required for changes to take effect."
