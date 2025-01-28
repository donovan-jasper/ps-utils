<#
.SYNOPSIS
    Checks every 15 seconds for both failed (4625) and successful (4624) logon attempts 
    in the last 15 seconds, coloring success in green and fail in red (except the "no failed" message is green).

.DESCRIPTION
    - Gets both 4624 (success) and 4625 (fail) events from the Security log in the last 15 seconds
    - Uses -ErrorAction SilentlyContinue to avoid red error text if no events exist
    - Ensures we never pass null to the parsing logic (binds to empty array if no events found)
    - Prints console output in color:
        Green for successful events
        Red for failed events
        Green "No failed attempts" message if no failures found
    - Continues running until closed (or Ctrl+C)

.NOTES
    Save as "login_checks.ps1"
    Run in PowerShell (Administrator).
    Adjust intervals, etc., as needed.
#>

Write-Host "Starting authentication monitoring (every 15 seconds)...`n"

while ($true) {
    # Time window to check: last 15 seconds
    $startTime = (Get-Date).AddSeconds(-15)

    # --- Retrieve events for successful logons (4624) ---
    try {
        $successfulLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
    }
    catch {
        $successfulLogons = $null
    }

    # If Get-WinEvent returns $null, force it to an empty array
    if (-not $successfulLogons) {
        $successfulLogons = @()
    }

    # --- Retrieve events for failed logons (4625) ---
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
    }
    catch {
        $failedLogons = $null
    }

    if (-not $failedLogons) {
        $failedLogons = @()
    }

    # --- Output Header ---
    $currentTime = Get-Date
    Write-Host "===================================="
    Write-Host "Checking past 15s: $($currentTime)"
    Write-Host "===================================="

    # --- Process SUCCESS (Green) ---
    if ($successfulLogons.Count -gt 0) {
        Write-Host -ForegroundColor Green "`nFound $($successfulLogons.Count) successful logon(s):"
        
        foreach ($event in $successfulLogons) {
            $xml = [xml]$event.ToXml()

            $username  = $xml.Event.EventData.Data |
                         Where-Object { $_.Name -eq 'TargetUserName' } |
                         Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue

            $ipaddress = $xml.Event.EventData.Data |
                         Where-Object { $_.Name -eq 'IpAddress' } |
                         Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue

            $timeStamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            Write-Host -ForegroundColor Green "  [$timeStamp] User: $username  IP: $ipaddress"
        }
    }
    else {
        Write-Host -ForegroundColor Green "`nNo successful logon attempts in the last 15 seconds."
    }

    # --- Process FAIL ---
    if ($failedLogons.Count -gt 0) {
        # If there are any failures, print them in red
        Write-Host -ForegroundColor Red "`nFound $($failedLogons.Count) failed logon attempt(s):"
        
        foreach ($event in $failedLogons) {
            $xml = [xml]$event.ToXml()

            $username  = $xml.Event.EventData.Data |
                         Where-Object { $_.Name -eq 'TargetUserName' } |
                         Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue

            $ipaddress = $xml.Event.EventData.Data |
                         Where-Object { $_.Name -eq 'IpAddress' } |
                         Select-Object -ExpandProperty '#text' -ErrorAction SilentlyContinue

            $timeStamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            Write-Host -ForegroundColor Red "  [$timeStamp] User: $username  IP: $ipaddress"
        }
    }
    else {
        # Otherwise, if no failures, let's show that in green
        Write-Host -ForegroundColor Green "`nNo failed logon attempts in the last 15 seconds."
    }

    # Sleep 15 seconds before the next check
    Start-Sleep -Seconds 15
    Write-Host "`n"
}
