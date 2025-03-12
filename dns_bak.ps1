<#
.SYNOPSIS
    Backup DNS records from a DNS server (including AD-integrated zones).

.DESCRIPTION
    This script enumerates all DNS zones from a specified DNS server, 
    then retrieves all records from each zone using Get-DnsServerResourceRecord.
    It stores them in a JSON file, which can be restored later with the companion script.

.PARAMETER DnsServer
    The hostname or IP of the DNS server.

.PARAMETER BackupFile
    The path to the JSON file that will store the DNS record backup.

.EXAMPLE
    .\Backup-DnsRecords.ps1 -DnsServer "localhost" -BackupFile "C:\dns\DNSBackup.json"

    Backs up all DNS records on "localhost" into "C:\dns\DNSBackup.json".
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$DnsServer,

    [Parameter(Mandatory = $true)]
    [string]$BackupFile
)

Write-Host "Starting DNS record backup from server: '$DnsServer'"

# Attempt to retrieve all zones on the DNS server
try {
    $allZones = Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Unable to retrieve zones from '$DnsServer'. Message: $($_.Exception.Message)"
    return
}

$backupCollection = @()

foreach ($zone in $allZones) {
    Write-Host "Collecting records for zone: $($zone.ZoneName)"
    try {
        # Retrieve all records for this zone
        $recordList = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue

        foreach ($record in $recordList) {
            # Build a custom object for each record
            $exportItem = [PSCustomObject]@{
                ZoneName   = $zone.ZoneName
                RecordName = $record.HostName
                RecordType = $record.RecordType
                TTL        = $record.TimeToLive.TotalSeconds  # store TTL in seconds
                Data       = $record.RecordData
            }
            $backupCollection += $exportItem
        }
    }
    catch {
        Write-Host "Failed to retrieve records for zone $($zone.ZoneName). Error: $($_.Exception.Message)"
    }
}

if ($backupCollection.Count -eq 0) {
    Write-Host "`nNo records found (or none retrieved). Backup file not created."
    return
}

# Convert to JSON with a Depth of 10 (this is supported in PowerShell 5.1)
try {
    $jsonData = $backupCollection | ConvertTo-Json -Depth 10
    $backupDir = Split-Path $BackupFile -Parent

    if (!(Test-Path $backupDir)) {
        Write-Host "Backup directory '$backupDir' does not exist. Creating..."
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }

    $jsonData | Out-File $BackupFile -Encoding UTF8
    Write-Host "`nBackup complete. DNS records saved to '$BackupFile'."
}
catch {
    Write-Host "ERROR: Failed to write backup file '$BackupFile'. Error: $($_.Exception.Message)"
}
