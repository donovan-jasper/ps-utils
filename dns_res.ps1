<#
.SYNOPSIS
    Restore DNS records from a JSON backup file.

.DESCRIPTION
    This script reads a JSON file created by Backup-DnsRecords.ps1,
    loops through each record, and re-creates them on the specified DNS server.

.PARAMETER DnsServer
    The hostname or IP of the DNS server.

.PARAMETER BackupFile
    The path to the JSON file that contains the DNS record backup.

.EXAMPLE
    .\Restore-DnsRecords.ps1 -DnsServer "localhost" -BackupFile "C:\dns\DNSBackup.json"

    Restores all DNS records from "C:\dns\DNSBackup.json" to the DNS server "localhost".
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$DnsServer,

    [Parameter(Mandatory = $true)]
    [string]$BackupFile
)

if (!(Test-Path $BackupFile)) {
    Write-Host "ERROR: Backup file '$BackupFile' not found."
    return
}

Write-Host "Loading DNS backup data from '$BackupFile'..."

# Read JSON file and convert to objects
try {
    # In Windows PowerShell 5.1, ConvertFrom-Json does NOT have a -Depth parameter
    $jsonContent = Get-Content -Path $BackupFile -Raw
    $restoreData = $jsonContent | ConvertFrom-Json
}
catch {
    Write-Host "ERROR: Failed to load or parse JSON file. Error: $($_.Exception.Message)"
    return
}

if (-not $restoreData) {
    Write-Host "No data found in JSON file or parsing failed."
    return
}

Write-Host "Starting restore of DNS records to server '$DnsServer'..."

foreach ($entry in $restoreData) {
    $zoneName   = $entry.ZoneName
    $recordName = $entry.RecordName
    $recordType = $entry.RecordType.ToUpper()
    $ttlSeconds = $entry.TTL
    $timeToLive = [TimeSpan]::FromSeconds($ttlSeconds)

    switch ($recordType) {
        "A" {
            foreach ($rd in $entry.Data) {
                if ($rd.IPv4Address) {
                    Write-Host "Restoring A record: $recordName.$zoneName => $($rd.IPv4Address)"
                    Add-DnsServerResourceRecordA -Name $recordName `
                        -ZoneName $zoneName `
                        -IPv4Address $rd.IPv4Address `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer `
                        -CreatePtr:$false
                }
            }
        }
        "AAAA" {
            foreach ($rd in $entry.Data) {
                if ($rd.IPv6Address) {
                    Write-Host "Restoring AAAA record: $recordName.$zoneName => $($rd.IPv6Address)"
                    Add-DnsServerResourceRecordAAAA -Name $recordName `
                        -ZoneName $zoneName `
                        -IPv6Address $rd.IPv6Address `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "CNAME" {
            foreach ($rd in $entry.Data) {
                if ($rd.HostNameAlias) {
                    Write-Host "Restoring CNAME record: $recordName.$zoneName => $($rd.HostNameAlias)"
                    Add-DnsServerResourceRecordCName -Name $recordName `
                        -ZoneName $zoneName `
                        -HostNameAlias $rd.HostNameAlias `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "PTR" {
            foreach ($rd in $entry.Data) {
                if ($rd.PtrDomainName) {
                    Write-Host "Restoring PTR record: $recordName.$zoneName => $($rd.PtrDomainName)"
                    Add-DnsServerResourceRecordPtr -Name $recordName `
                        -ZoneName $zoneName `
                        -PtrDomainName $rd.PtrDomainName `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "MX" {
            foreach ($rd in $entry.Data) {
                if ($rd.MailExchange) {
                    Write-Host "Restoring MX record: $recordName.$zoneName => $($rd.MailExchange) (Pref=$($rd.Preference))"
                    Add-DnsServerResourceRecordMX -Name $recordName `
                        -ZoneName $zoneName `
                        -MailExchange $rd.MailExchange `
                        -Preference $rd.Preference `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "TXT" {
            foreach ($rd in $entry.Data) {
                if ($rd.DescriptiveText) {
                    Write-Host "Restoring TXT record: $recordName.$zoneName => $($rd.DescriptiveText)"
                    Add-DnsServerResourceRecordTxt -Name $recordName `
                        -ZoneName $zoneName `
                        -DescriptiveText $rd.DescriptiveText `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "NS" {
            foreach ($rd in $entry.Data) {
                if ($rd.NameServer) {
                    Write-Host "Restoring NS record: $recordName.$zoneName => $($rd.NameServer)"
                    Add-DnsServerResourceRecordNS -Name $recordName `
                        -ZoneName $zoneName `
                        -NameServer $rd.NameServer `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        "SRV" {
            foreach ($rd in $entry.Data) {
                if ($rd.DomainName) {
                    Write-Host "Restoring SRV record: $recordName.$zoneName => $($rd.DomainName):$($rd.Port)"
                    Add-DnsServerResourceRecordSrv -Name $recordName `
                        -ZoneName $zoneName `
                        -DomainName $rd.DomainName `
                        -Priority $rd.Priority `
                        -Weight $rd.Weight `
                        -Port $rd.Port `
                        -TimeToLive $timeToLive `
                        -ComputerName $DnsServer
                }
            }
        }
        default {
            Write-Warning "Record type '$recordType' not explicitly handled. Skipping record $recordName.$zoneName"
        }
    }
}

Write-Host "`nDNS record restore completed."
