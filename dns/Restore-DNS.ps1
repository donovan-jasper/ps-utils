<#
.SYNOPSIS
    Restores DNS records from a JSON backup produced by Backup-DNS.ps1.

.DESCRIPTION
    Reads a dns-backup JSON file and re-creates each resource record on the
    target DNS server.  Existing records are detected and skipped to avoid
    duplicate-record errors.  Use -WhatIf to preview changes without applying.

.PARAMETER BackupFile
    Path to the JSON backup file (required).

.PARAMETER DnsServer
    DNS server to restore records to. Defaults to localhost.

.PARAMETER WhatIf
    Preview mode -- prints what would be restored without making changes.

.EXAMPLE
    .\Restore-DNS.ps1 -BackupFile .\dns-backup-2026-03-10-143000.json -WhatIf
    .\Restore-DNS.ps1 -BackupFile .\dns-backup-2026-03-10-143000.json
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$BackupFile,

    [string]$DnsServer = "localhost"
)

# --- Bootstrap ---------------------------------------------------------------
. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Restore-DNS"
Assert-Role -Required "DomainController"
Assert-Dependencies -Modules @("DnsServer")

# --- Load backup -------------------------------------------------------------

if (-not (Test-Path $BackupFile)) {
    Write-Error "Backup file not found: $BackupFile"
    exit 1
}

$records = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json

if (-not $records -or $records.Count -eq 0) {
    Write-Warning "Backup file contains no records."
    exit 0
}

Write-Host "Loaded $($records.Count) records from $BackupFile" -ForegroundColor Cyan

# --- Helpers -----------------------------------------------------------------

function Test-RecordExists {
    param(
        [string]$ZoneName,
        [string]$HostName,
        [string]$RecordType,
        [string]$Server
    )
    try {
        $existing = Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $HostName -RRType $RecordType -ComputerName $Server -ErrorAction Stop
        return ($null -ne $existing)
    }
    catch {
        return $false
    }
}

# --- Restore -----------------------------------------------------------------

$restored = 0
$skipped  = 0
$failed   = 0

foreach ($rec in $records) {
    $zone = $rec.ZoneName
    $host_ = $rec.HostName
    $type = $rec.RecordType
    $data = $rec.RecordData
    $ttl  = [System.TimeSpan]::Parse($rec.TimeToLive)

    $label = "$type  $host_.$zone"

    # Skip SOA records -- these are zone-level and cannot be added
    if ($type -eq "SOA") {
        Write-Host "  SKIP (SOA): $label" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    # Check for existing record to avoid duplicates
    if (Test-RecordExists -ZoneName $zone -HostName $host_ -RecordType $type -Server $DnsServer) {
        Write-Host "  EXISTS: $label" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    if ($PSCmdlet.ShouldProcess($label, "Add DNS record")) {
        try {
            $commonParams = @{
                ZoneName     = $zone
                ComputerName = $DnsServer
                Name         = $host_
                TimeToLive   = $ttl
            }

            switch ($type) {
                "A" {
                    Add-DnsServerResourceRecordA @commonParams `
                        -IPv4Address $data.IPv4Address
                }
                "AAAA" {
                    Add-DnsServerResourceRecordAAAA @commonParams `
                        -IPv6Address $data.IPv6Address
                }
                "CNAME" {
                    Add-DnsServerResourceRecordCName @commonParams `
                        -HostNameAlias $data.HostNameAlias
                }
                "MX" {
                    Add-DnsServerResourceRecordMX @commonParams `
                        -Preference $data.Preference `
                        -MailExchange $data.MailExchange
                }
                "NS" {
                    Add-DnsServerResourceRecord @commonParams `
                        -NS -NameServer $data.NameServer
                }
                "SRV" {
                    Add-DnsServerResourceRecord @commonParams `
                        -Srv `
                        -DomainName $data.DomainName `
                        -Priority $data.Priority `
                        -Weight $data.Weight `
                        -Port $data.Port
                }
                "TXT" {
                    $txtStrings = @($data.DescriptiveText)
                    Add-DnsServerResourceRecord @commonParams `
                        -Txt -DescriptiveText $txtStrings
                }
                "PTR" {
                    Add-DnsServerResourceRecordPtr @commonParams `
                        -PtrDomainName $data.PtrDomainName
                }
                default {
                    Write-Warning "  UNSUPPORTED type '$type' for $label -- skipping"
                    $skipped++
                    continue
                }
            }

            Write-Host "  RESTORED: $label" -ForegroundColor Green
            $restored++
        }
        catch {
            Write-Warning "  FAILED: $label -- $($_.Exception.Message)"
            $failed++
        }
    }
}

# --- Summary -----------------------------------------------------------------
Write-Host "`n--- Restore Summary ---" -ForegroundColor Yellow
Write-Host "  Restored : $restored"
Write-Host "  Skipped  : $skipped"
Write-Host "  Failed   : $failed"
Write-Host "  Total    : $($records.Count)"
