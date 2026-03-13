<#
.SYNOPSIS
    Dual-mode LDAP monitoring for Domain Controllers.

.DESCRIPTION
    Monitors LDAP bind activity on Domain Controllers using Directory Service
    diagnostic logging (events 1644 and 2889). Two modes of operation:

    Map mode (-Map):
      Enables LDAP diagnostic logging, captures events for a fixed number of
      polling rounds, combines with netstat data for port 389/636 connections,
      and outputs a summary table of source IP, hostname, bind account, and
      frequency. Disables diagnostic logging when finished.

    Alert mode (-Alert):
      Continuous monitoring that alerts on LDAP binds from non-whitelisted IPs
      and detects credential spray patterns (>5 failed binds from one IP in
      30 seconds). Requires -TeamHosts to specify whitelisted IPs.

.PARAMETER Map
    Run in map mode: enumerate LDAP clients for a fixed number of rounds.

.PARAMETER Alert
    Run in alert mode: continuous monitoring with whitelist-based alerting.

.PARAMETER TeamHosts
    Array of IP addresses to whitelist in alert mode. Binds from these IPs
    are shown in green; all others trigger a red alert.

.PARAMETER Rounds
    Number of 15-second polling cycles for map mode. Default: 5.

.EXAMPLE
    .\Watch-LDAP.ps1 -Map
    Run 5 rounds of LDAP client mapping.

.EXAMPLE
    .\Watch-LDAP.ps1 -Map -Rounds 10
    Run 10 rounds of LDAP client mapping.

.EXAMPLE
    .\Watch-LDAP.ps1 -Alert -TeamHosts 10.100.100.105,10.100.100.11
    Continuously monitor and alert on non-team LDAP binds.

.NOTES
    Requires an elevated PowerShell session on a Domain Controller.
    Dot-sources Common.ps1 for Write-Banner and Assert-Role.
#>

param(
    [switch]$Map,
    [switch]$Alert,
    [string[]]$TeamHosts = @(),
    [int]$Rounds = 5
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Watch-LDAP"
Assert-Role -Required @("DomainController")
Assert-Dependencies -Commands @("Get-WinEvent")

if (-not $Map -and -not $Alert) {
    Write-Host "Specify -Map or -Alert mode." -ForegroundColor Yellow
    Write-Host "  -Map              Enumerate LDAP clients for N rounds"
    Write-Host "  -Alert -TeamHosts  Continuous alerting on non-team LDAP binds"
    exit 1
}

if ($Map -and $Alert) {
    Write-Host "Specify only one of -Map or -Alert, not both." -ForegroundColor Yellow
    exit 1
}

# --- Registry paths for LDAP diagnostic logging ---
$diagPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
$diagValue = "16 LDAP Interface Events"

function Enable-LDAPDiagnostics {
    Write-Host "Enabling LDAP diagnostic logging (level 5)..." -ForegroundColor Yellow
    Set-ItemProperty -Path $diagPath -Name $diagValue -Value 5
}

function Disable-LDAPDiagnostics {
    Write-Host "Disabling LDAP diagnostic logging..." -ForegroundColor Yellow
    Set-ItemProperty -Path $diagPath -Name $diagValue -Value 0
}

function Get-XmlField {
    param([System.Xml.XmlElement[]]$DataItems, [string]$Name)
    $node = $DataItems | Where-Object { $_.Name -eq $Name }
    if ($node) { return $node.'#text' }
    return $null
}

function Resolve-IPSafe {
    param([string]$IP)
    try {
        $result = [System.Net.Dns]::GetHostEntry($IP)
        return $result.HostName
    } catch {
        return $IP
    }
}

function Get-LDAPEvents {
    param([datetime]$Since)
    $events = @()
    try {
        $events += @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Directory Service'
            Id        = 1644, 2889
            StartTime = $Since
        } -ErrorAction SilentlyContinue)
    } catch {}
    return $events
}

function Get-NetstatLDAP {
    # Parse netstat for established connections on ports 389 and 636
    $connections = @()
    $netstat = netstat -an 2>$null
    foreach ($line in $netstat) {
        if ($line -match 'ESTABLISHED' -and $line -match ':(389|636)\s') {
            if ($line -match '\s+(\d+\.\d+\.\d+\.\d+):\d+\s+(\d+\.\d+\.\d+\.\d+):(389|636)') {
                $connections += [PSCustomObject]@{
                    SourceIP = $Matches[1]
                    Port     = $Matches[3]
                }
            }
            # Also match the reverse direction (remote connecting to our 389/636)
            elseif ($line -match '\s+\d+\.\d+\.\d+\.\d+:(389|636)\s+(\d+\.\d+\.\d+\.\d+):') {
                $connections += [PSCustomObject]@{
                    SourceIP = $Matches[2]
                    Port     = $Matches[1]
                }
            }
        }
    }
    return $connections
}

function Parse-LDAPEvent {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data
    $msg = $Event.Message

    $ip = $null
    $account = $null

    # Try XML data fields first
    if ($data) {
        $ip = Get-XmlField $data 'ClientIP'
        if (-not $ip) { $ip = Get-XmlField $data 'IPAddress' }
        $account = Get-XmlField $data 'BindAccount'
        if (-not $account) { $account = Get-XmlField $data 'SubjectUserName' }
    }

    # Fall back to message parsing
    if ($msg) {
        if (-not $ip -and $msg -match 'Client IP[:\s]+(\d+\.\d+\.\d+\.\d+)') {
            $ip = $Matches[1]
        }
        if (-not $ip -and $msg -match '(\d+\.\d+\.\d+\.\d+)') {
            $ip = $Matches[1]
        }
        if (-not $account -and $msg -match '(?:bind|account|user)[:\s]+(\S+)') {
            $account = $Matches[1]
        }
    }

    # Strip port from IP if present (e.g., 10.0.0.5:49152)
    if ($ip -and $ip -match '^(\d+\.\d+\.\d+\.\d+):\d+$') {
        $ip = $Matches[1]
    }

    return [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventId     = $Event.Id
        SourceIP    = if ($ip) { $ip } else { 'unknown' }
        Account     = if ($account) { $account } else { 'unknown' }
    }
}

# =====================================================================
# MAP MODE
# =====================================================================
if ($Map) {
    Write-Host "LDAP Map Mode: $Rounds rounds of 15-second polling" -ForegroundColor Cyan
    Write-Host ""

    Enable-LDAPDiagnostics

    $allRecords = @()

    try {
        for ($i = 1; $i -le $Rounds; $i++) {
            Write-Host "Round $i/$Rounds ..." -ForegroundColor Gray
            Start-Sleep -Seconds 15

            $since = (Get-Date).AddSeconds(-15)
            $events = Get-LDAPEvents -Since $since

            foreach ($evt in $events) {
                $parsed = Parse-LDAPEvent -Event $evt
                $allRecords += $parsed
            }
        }

        # Also grab current netstat connections
        Write-Host "`nCollecting current LDAP connections from netstat..." -ForegroundColor Gray
        $netConns = Get-NetstatLDAP
        foreach ($conn in $netConns) {
            $allRecords += [PSCustomObject]@{
                TimeCreated = Get-Date
                EventId     = 0
                SourceIP    = $conn.SourceIP
                Account     = "(netstat:$($conn.Port))"
            }
        }
    } finally {
        Disable-LDAPDiagnostics
    }

    if ($allRecords.Count -eq 0) {
        Write-Host "`nNo LDAP bind activity detected." -ForegroundColor Yellow
        exit 0
    }

    # Build summary table: group by SourceIP + Account
    Write-Host "`n--- LDAP Client Summary ---" -ForegroundColor Cyan
    Write-Host ""

    $grouped = $allRecords | Group-Object SourceIP, Account | Sort-Object Count -Descending

    $results = foreach ($g in $grouped) {
        $parts = $g.Name -split ',\s*'
        $ip = $parts[0]
        $acct = if ($parts.Count -gt 1) { $parts[1] } else { 'unknown' }
        $hostname = Resolve-IPSafe -IP $ip

        [PSCustomObject]@{
            SourceIP  = $ip
            Hostname  = $hostname
            Account   = $acct
            Count     = $g.Count
        }
    }

    $results | Format-Table -AutoSize
}

# =====================================================================
# ALERT MODE
# =====================================================================
if ($Alert) {
    if ($TeamHosts.Count -eq 0) {
        Write-Host "Alert mode requires -TeamHosts to whitelist team IPs." -ForegroundColor Yellow
        Write-Host "Example: .\Watch-LDAP.ps1 -Alert -TeamHosts 10.100.100.105,10.100.100.11" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "LDAP Alert Mode: continuous monitoring" -ForegroundColor Cyan
    Write-Host "Whitelisted IPs: $($TeamHosts -join ', ')" -ForegroundColor Green
    Write-Host "Alerting on non-team LDAP binds and credential spray patterns" -ForegroundColor Yellow
    Write-Host ""

    Enable-LDAPDiagnostics

    # Track failed binds for spray detection: IP -> list of timestamps
    $failTracker = @{}

    try {
        while ($true) {
            $since = (Get-Date).AddSeconds(-15)
            $events = Get-LDAPEvents -Since $since

            foreach ($evt in $events) {
                $parsed = Parse-LDAPEvent -Event $evt
                $ts = $parsed.TimeCreated.ToString("HH:mm:ss")
                $ip = $parsed.SourceIP
                $acct = $parsed.Account

                $isTeam = $ip -in $TeamHosts

                if ($isTeam) {
                    Write-Host "[$ts] LDAP bind  ip=$ip  account=$acct" -ForegroundColor Green
                } else {
                    Write-Host "[$ts] ALERT  Non-team LDAP bind  ip=$ip  account=$acct" -ForegroundColor Red
                }

                # Track for spray detection (event 2889 is insecure bind, treat as suspicious)
                if (-not $isTeam) {
                    if (-not $failTracker.ContainsKey($ip)) {
                        $failTracker[$ip] = [System.Collections.ArrayList]@()
                    }
                    [void]$failTracker[$ip].Add($parsed.TimeCreated)

                    # Prune entries older than 30 seconds
                    $cutoff = (Get-Date).AddSeconds(-30)
                    $failTracker[$ip] = [System.Collections.ArrayList]@(
                        $failTracker[$ip] | Where-Object { $_ -gt $cutoff }
                    )

                    # Check for spray: >5 binds from same IP in 30 seconds
                    if ($failTracker[$ip].Count -gt 5) {
                        Write-Host "[$ts] SPRAY DETECTED  ip=$ip  binds=$($failTracker[$ip].Count) in 30s" -ForegroundColor Red -BackgroundColor DarkRed
                    }
                }
            }

            Start-Sleep -Seconds 15
        }
    } finally {
        Disable-LDAPDiagnostics
    }
}
