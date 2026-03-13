<#
.SYNOPSIS
    Dumps NT password hashes for all domain users via AD replication (DCSync).
.DESCRIPTION
    Uses DSInternals Get-ADReplAccount to extract NT hashes for all domain users.
    Outputs a CSV with SamAccountName and NTHash columns. Excludes built-in accounts
    (Administrator, krbtgt, Guest, DefaultAccount).

    The output file is rotated automatically so previous dumps are preserved as
    user_hashes_1.csv, user_hashes_2.csv, etc.

    Requires: DSInternals module, must run on a Domain Controller.
#>

. "$PSScriptRoot\Password-Utils.ps1"

Import-Module DSInternals

function DumpHashes {
    param(
        # Base path to store hashes in without suffix
        [Parameter(Mandatory)]
        [string] $HashOutBase
    )

    # Newest output path
    $outPath = Rotate-OutputFiles -BasePath $HashOutBase

    # Dump all hashes
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    Get-ADReplAccount -All -Server $domain |
        Where-Object {
            $_.NTHash -and
            $_.SamAccountType -eq "User" -and
            $_.SamAccountName -ne "Administrator" -and
            $_.SamAccountName -ne "krbtgt" -and
            $_.SamAccountName -ne "Guest" -and
            $_.SamAccountName -ne "DefaultAccount"
        } |
        Select-Object `
            SamAccountName,
            @{ Name='NTHash'; Expression = { ($_.NTHash | ForEach-Object { $_.ToString('x2') }) -join '' } } |
        Sort-Object SamAccountName |
        Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8

    Write-Host "Dump complete. Output saved to $outPath"
}

DumpHashes -HashOutBase $HashOutFile
