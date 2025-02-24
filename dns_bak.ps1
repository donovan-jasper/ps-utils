# Create a backup folder if it doesn't exist
$backupPath = "C:\DNSBackups"
if (!(Test-Path -Path $backupPath)) {
    New-Item -ItemType Directory -Path $backupPath
}

# Export each zone to a DNS zone file
$zones = Get-DnsServerZone
foreach ($zone in $zones) {
    # This will export the zone to a file in the DNS folder (usually %SystemRoot%\System32\dns)
    Export-DnsServerZone -Name $zone.ZoneName -FileName "$($zone.ZoneName).dns"
    # Optionally copy the exported file to your backup folder
    Copy-Item -Path "$env:SystemRoot\System32\dns\$($zone.ZoneName).dns" -Destination $backupPath -Force
    Write-Output "Exported zone '$($zone.ZoneName)' to $backupPath\$($zone.ZoneName).dns"
}
