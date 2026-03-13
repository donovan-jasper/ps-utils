<#
.SYNOPSIS
    Rolls back domain user passwords to a previous state using NT hash restoration.
.DESCRIPTION
    Reads a previously dumped hash file (from Dump-Hashes.ps1) and uses DSInternals
    Set-SamAccountPasswordHash to restore each user's password hash to its previous value.

    Also updates the current password state CSV to reflect the rollback so that
    Roll-Passwords.ps1 and teammates have an accurate credential list.

    Requires: DSInternals module, must run on a Domain Controller.

.PARAMETER UsersInclude
    Roll back only these specific users.
.PARAMETER UsersExclude
    Roll back all users in the hash file except these.
.PARAMETER UserHashFile
    Path to the hash CSV to restore from. Defaults to user_hashes_1.csv (the state
    before the most recent dump).
#>

[CmdletBinding(DefaultParameterSetName = 'All')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Include')]
    [string[]]$UsersInclude,

    [Parameter(Mandatory = $true, ParameterSetName = 'Exclude')]
    [string[]]$UsersExclude,

    [Parameter(Mandatory = $false)]
    [string]$UserHashFile = (Join-Path $PSScriptRoot "user_hashes_1.csv")
)

. "$PSScriptRoot\Password-Utils.ps1"

Import-Module DSInternals

# Ensure user hash file exists
if (-not (Test-Path $UserHashFile)) {
    Write-Host "User hash file does not exist: $UserHashFile" -ForegroundColor Red
    exit 1
}

$userHashes = Import-Csv $UserHashFile

# Load previous password state from the matching user_passwords_X.csv (if present).
$previousPasswordsByUser = @{}
$previousPasswordFile = $null
if ($UserHashFile -match '^(.*[\\/])?user_hashes_(\d+)\.csv$') {
    $dir = Split-Path -Parent $UserHashFile
    if (-not $dir) { $dir = "." }
    $previousPasswordFile = Join-Path $dir ("user_passwords_{0}.csv" -f $matches[2])
} else {
    Write-Warning "Could not infer previous password CSV from UserHashFile name: $UserHashFile"
}

if ($previousPasswordFile) {
    if (Test-Path $previousPasswordFile) {
        $previousPasswordsByUser = Get-PasswordState -Path $previousPasswordFile
    } else {
        Write-Warning "Previous password state not found: $previousPasswordFile"
    }
}

# Load current password state
$currentPasswordsByUser = Get-PasswordState -Path $CurrentPasswordOutFile

# Determine target users
if ($PSCmdlet.ParameterSetName -eq 'Exclude') {
    $targetUsers = $userHashes.SamAccountName |
        Where-Object { $_ } |
        Where-Object { $_ -notin $UsersExclude }

    foreach ($user in $UsersExclude) {
        if ($user -notin $userHashes.SamAccountName) {
            Write-Host "Warning: excluded user $user not found in hash file ($UserHashFile)" -ForegroundColor Red
        }
    }
} elseif ($PSCmdlet.ParameterSetName -eq 'Include') {
    $targetUsers = $UsersInclude
} else {
    $targetUsers = $userHashes.SamAccountName | Where-Object { $_ }
}

# Verify all target users exist in the hash file
$usersNotFound = $false
foreach ($user in $targetUsers) {
    if ($user -notin $userHashes.SamAccountName) {
        Write-Host "Error: $user not found in user hash file ($UserHashFile)" -ForegroundColor Red
        $usersNotFound = $true
    }
}

if ($usersNotFound) {
    exit 1
}

# Rollback the hash for each target user
foreach ($user in $targetUsers) {
    $row = $userHashes | Where-Object SamAccountName -eq $user | Select-Object -First 1
    if (-not $row.NTHash) {
        Write-Host "Error: NT hash for user $user is empty" -ForegroundColor Red
        continue
    }

    Write-Host "Rolling back hash for user $user (new hash will be $($row.NTHash))"
    try {
        Set-SamAccountPasswordHash -SamAccountName $user -Domain $env:USERDOMAIN -NTHash $row.NTHash
        Write-Host "-> Successfully rolled back hash for user $user" -ForegroundColor Green

        # Update current password state from the previous state
        if ($previousPasswordsByUser.ContainsKey($user)) {
            $currentPasswordsByUser[$user] = $previousPasswordsByUser[$user]
        } else {
            [void]$currentPasswordsByUser.Remove($user)
        }
    } catch {
        Write-Host "Error: Failed to rollback hash for user $user" -ForegroundColor Red
        Write-Error $_
    }
}

# Sort and save updated password state
$passwordResults = $currentPasswordsByUser.GetEnumerator() |
    Sort-Object Key |
    ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.Key
            Password       = $_.Value
        }
    }

$userPasswordCSV = Rotate-OutputFiles -BasePath $PasswordOutFile
$passwordResults | Export-Csv -Path $userPasswordCSV -NoTypeInformation
Write-Host "Updated current password state. Output saved to: $userPasswordCSV"

Write-Host "Dumping current password hash state after rollback"
. "$PSScriptRoot\Dump-Hashes.ps1"
