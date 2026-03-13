<#
.SYNOPSIS
    Port-knock gatekeeper that blocks management ports and opens them only after
    a correct TCP knock sequence.

.DESCRIPTION
    Closes RDP (3389) and WinRM (5985) by creating Windows Firewall block rules,
    then listens for a knock sequence on a series of TCP ports. When the correct
    sequence is received from a single IP within the timeout window, the management
    ports are temporarily opened for that IP only.

    The knock listener uses .NET TcpListener on each port in the sequence. The
    knocker must connect to each port in order within KnockTimeout seconds. After
    a successful knock, a temporary firewall allow rule is created for the knocker's
    IP, lasting OpenDuration seconds before automatic removal.

.PARAMETER KnockPorts
    Array of TCP port numbers for the knock sequence. Default: @(7331, 7332, 7333)

.PARAMETER KnockTimeout
    Maximum seconds allowed between the first and last knock. Default: 10

.PARAMETER OpenDuration
    Seconds to keep management ports open after a successful knock. Default: 60

.EXAMPLE
    .\Guard-Ports.ps1
    Block RDP/WinRM, listen for knocks on 7331,7332,7333.

.EXAMPLE
    .\Guard-Ports.ps1 -KnockPorts 9001,9002,9003 -KnockTimeout 15 -OpenDuration 120
    Custom knock sequence with longer timeout and open window.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner.
    The knock client can be any tool that makes TCP connections (ncat, Test-NetConnection, etc.).
    WARNING: This script performs disruptive network/session operations. Evaluate carefully before using in production environments.
#>

param(
    [int[]]$KnockPorts = @(7331, 7332, 7333),
    [int]$KnockTimeout = 10,
    [int]$OpenDuration = 60
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Guard-Ports"
Assert-Dependencies -Commands @("New-NetFirewallRule", "Remove-NetFirewallRule")

$ManagementPorts = @(3389, 5985)
$BlockRulePrefix = "GuardPorts-Block"
$AllowRulePrefix = "GuardPorts-TempAllow"

# --- Block management ports ---

function Install-BlockRules {
    foreach ($port in $ManagementPorts) {
        $ruleName = "${BlockRulePrefix}-${port}"
        # Remove existing rule if present
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Action Block -Protocol TCP `
            -LocalPort $port -Profile Any -ErrorAction Stop | Out-Null
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Blocked inbound TCP/$port ($ruleName)" -ForegroundColor Red
    }
}

function Remove-BlockRules {
    foreach ($port in $ManagementPorts) {
        $ruleName = "${BlockRulePrefix}-${port}"
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Removed block rule for TCP/$port" -ForegroundColor Green
    }
}

function Add-TempAllowRule {
    param([string]$SourceIP)
    foreach ($port in $ManagementPorts) {
        $ruleName = "${AllowRulePrefix}-${port}-${SourceIP}"
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $port -RemoteAddress $SourceIP `
            -Profile Any -ErrorAction Stop | Out-Null
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ALLOW TCP/$port from $SourceIP (${OpenDuration}s)" -ForegroundColor Green
    }
}

function Remove-TempAllowRule {
    param([string]$SourceIP)
    foreach ($port in $ManagementPorts) {
        $ruleName = "${AllowRulePrefix}-${port}-${SourceIP}"
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Removed temp allow rules for $SourceIP" -ForegroundColor Yellow
}

# --- Knock listener ---

function Wait-ForKnockSequence {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Listening for knock sequence on ports: $($KnockPorts -join ', ')" -ForegroundColor Cyan

    # Listen on the first knock port and wait for a connection
    $firstPort = $KnockPorts[0]
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $firstPort)
        $listener.Start()

        while ($true) {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Waiting for first knock on TCP/$firstPort..." -ForegroundColor Cyan
            $client = $listener.AcceptTcpClient()
            $knockerIP = $client.Client.RemoteEndPoint.Address.ToString()
            $client.Close()

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Knock 1/$($KnockPorts.Count) from $knockerIP on TCP/$firstPort" -ForegroundColor Yellow
            $knockStart = Get-Date
            $sequenceOk = $true

            # Now listen for remaining knocks in sequence
            for ($i = 1; $i -lt $KnockPorts.Count; $i++) {
                $elapsed = ((Get-Date) - $knockStart).TotalSeconds
                if ($elapsed -ge $KnockTimeout) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Knock timeout from $knockerIP" -ForegroundColor Red
                    $sequenceOk = $false
                    break
                }

                $nextPort = $KnockPorts[$i]
                $nextListener = $null
                try {
                    $nextListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $nextPort)
                    $nextListener.Start()

                    # Wait for connection with remaining timeout
                    $remainingMs = [int](($KnockTimeout - $elapsed) * 1000)
                    if ($remainingMs -le 0) {
                        $sequenceOk = $false
                        break
                    }

                    # Poll for connection with timeout
                    $deadline = (Get-Date).AddMilliseconds($remainingMs)
                    $gotKnock = $false
                    while ((Get-Date) -lt $deadline) {
                        if ($nextListener.Pending()) {
                            $nextClient = $nextListener.AcceptTcpClient()
                            $nextIP = $nextClient.Client.RemoteEndPoint.Address.ToString()
                            $nextClient.Close()

                            if ($nextIP -eq $knockerIP) {
                                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Knock $($i+1)/$($KnockPorts.Count) from $knockerIP on TCP/$nextPort" -ForegroundColor Yellow
                                $gotKnock = $true
                                break
                            } else {
                                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Wrong IP on knock port $nextPort (got $nextIP, expected $knockerIP)" -ForegroundColor Red
                            }
                        }
                        Start-Sleep -Milliseconds 100
                    }

                    if (-not $gotKnock) {
                        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Knock sequence failed from $knockerIP (missed port $nextPort)" -ForegroundColor Red
                        $sequenceOk = $false
                    }
                } finally {
                    if ($nextListener) {
                        $nextListener.Stop()
                    }
                }

                if (-not $sequenceOk) { break }
            }

            if ($sequenceOk) {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] KNOCK SEQUENCE COMPLETE from $knockerIP" -ForegroundColor Green

                # Open management ports for this IP
                Add-TempAllowRule -SourceIP $knockerIP

                # Schedule removal in background
                $removeJob = Start-Job -ScriptBlock {
                    param($SourceIP, $Duration, $ManagementPorts, $Prefix)
                    Start-Sleep -Seconds $Duration
                    foreach ($port in $ManagementPorts) {
                        $ruleName = "${Prefix}-${port}-${SourceIP}"
                        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                    }
                } -ArgumentList $knockerIP, $OpenDuration, $ManagementPorts, $AllowRulePrefix

                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Auto-close scheduled in ${OpenDuration}s (job $($removeJob.Id))" -ForegroundColor Cyan
            }
        }
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

# --- Main ---

try {
    Install-BlockRules
    Write-Host ""
    Write-Host "Knock sequence: $($KnockPorts -join ' -> ')" -ForegroundColor Cyan
    Write-Host "Knock timeout: ${KnockTimeout}s | Open duration: ${OpenDuration}s" -ForegroundColor Cyan
    Write-Host "Management ports guarded: $($ManagementPorts -join ', ')" -ForegroundColor Cyan
    Write-Host ""
    Wait-ForKnockSequence
} finally {
    # Cleanup on exit
    Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Cleaning up firewall rules..." -ForegroundColor Yellow
    Remove-BlockRules
    # Remove any lingering temp allow rules
    Get-NetFirewallRule -DisplayName "${AllowRulePrefix}*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Guard-Ports stopped. Management ports restored." -ForegroundColor Cyan
}
