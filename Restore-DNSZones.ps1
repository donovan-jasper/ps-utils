# --- BEGIN: Restore-DNSZones.ps1 ---

# Path containing the DNS zone backup files
$BackupPath = "C:\DNSBackups"

# Get a list of all .dns files in the backup directory
$zoneFiles = Get-ChildItem -Path $BackupPath -Filter *.dns

foreach ($file in $zoneFiles) {
    # Derive the zone name from the filename (remove the .dns extension)
    $zoneName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)

    Write-Host "Restoring zone '$zoneName' from '$($file.FullName)'..."

    # If the zone already exists, remove it (optional). 
    # Uncomment below if you need a "fresh" restore:
    # Remove-DnsServerZone -Name $zoneName -Force -ErrorAction SilentlyContinue

    # Re-create the zone using the exported file
    Add-DnsServerPrimaryZone -Name $zoneName -ZoneFile $file.FullName 
}

Write-Host "DNS zone restore completed."

# --- END: Restore-DNSZones.ps1 ---
