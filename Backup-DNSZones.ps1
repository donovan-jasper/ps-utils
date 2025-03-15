# --- BEGIN: Backup-DNSZones.ps1 ---

# Path to store DNS zone backup files
$BackupPath = "C:\DNSBackups"

# Create the backup directory if it doesn't exist
if (!(Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory | Out-Null
}

# Retrieve all DNS zones on the local server
$zones = Get-DnsServerZone

foreach ($zone in $zones) {
    $zoneName = $zone.ZoneName

    # Build the filename for the zone file
    $fileName = Join-Path $BackupPath ("$zoneName.dns")

    Write-Host "Backing up zone '$zoneName' to file '$fileName'..."
    Export-DnsServerZone -Name $zoneName -FileName $fileName
}

Write-Host "DNS zone backup completed. Files are in '$BackupPath'."

# --- END: Backup-DNSZones.ps1 ---
