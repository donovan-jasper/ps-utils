<#
.SYNOPSIS
    Monitors a variety of suspicious security events in real time (every 15 seconds).

.DESCRIPTION
    This script audits multiple potentially suspicious events from the Security event log 
    within the last 15 seconds. In addition to the events you previously monitored,
    this version includes:
      - Process Creation (Event ID 4688)
      - Service Installation (Event ID 4697)
      - Special Privilege Assignment (Event ID 4672)
      - User Account Creation (Event ID 4720)
      - Failed Logon Attempt (Event ID 4625)
      - Account Lockout (Event ID 4740)
      - User Account Deletion (Event ID 4726)
      - Local Group Member Addition (Event ID 4732)
      - Audit Policy Change (Event ID 4719)

    For each event type, key details are extracted from the XML data and printed in color:
      - Process Creation events are shown in Yellow.
      - Service Installation events are shown in Red.
      - Special Privilege Assignment events are shown in Magenta.
      - User Account Creation events are shown in Cyan.
      - Failed Logon Attempts are shown in Red.
      - Account Lockouts are shown in DarkMagenta.
      - User Account Deletions are shown in DarkCyan.
      - Local Group Member additions are shown in Blue.
      - Audit Policy Changes are shown in Gray.
    When no events of a given type are found, a message is displayed in Green.

.NOTES
    Save as "suspicious_event_audit.ps1".
    Run in an elevated (Administrator) PowerShell session.
    Adjust event IDs, field names, colors, or time intervals as needed.
#>

# Define the suspicious event definitions
$suspiciousEvents = @(
    @{
        Id     = 4688
        Name   = "Process Creation"
        Color  = "Yellow"
        Fields = @("SubjectUserName", "NewProcessName", "NewProcessId", "ProcessCommandLine")
    },
    @{
        Id     = 4697
        Name   = "Service Installation"
        Color  = "Red"
        Fields = @("ServiceName", "ServiceFileName")
    },
    @{
        Id     = 4672
        Name   = "Special Privilege Assignment"
        Color  = "Magenta"
        Fields = @("SubjectUserName", "PrivilegeList")
    },
    @{
        Id     = 4720
        Name   = "User Account Creation"
        Color  = "Cyan"
        Fields = @("TargetUserName", "SubjectUserName")
    },
    @{
        Id     = 4625
        Name   = "Failed Logon Attempt"
        Color  = "Red"
        Fields = @("TargetUserName", "IpAddress", "FailureReason")
    },
    @{
        Id     = 4740
        Name   = "Account Lockout"
        Color  = "DarkMagenta"
        Fields = @("TargetUserName", "IpAddress")
    },
    @{
        Id     = 4726
        Name   = "User Account Deletion"
        Color  = "DarkCyan"
        Fields = @("TargetUserName", "SubjectUserName")
    },
    @{
        Id     = 4732
        Name   = "Local Group Member Added"
        Color  = "Blue"
        Fields = @("TargetUserName", "MemberName")
    },
    @{
        Id     = 4719
        Name   = "Audit Policy Change"
        Color  = "Gray"
        Fields = @("SubcategoryGUID", "SubcategoryName")
    }
)

Write-Host "Starting suspicious security event audit monitoring (every 15 seconds)...`n"

while ($true) {
    # Define the time window to check: the past 15 seconds
    $startTime = (Get-Date).AddSeconds(-15)

    Write-Host "===================================="
    Write-Host "Audit Interval: $(Get-Date)"
    Write-Host "===================================="

    foreach ($eventDef in $suspiciousEvents) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = $eventDef.Id
                StartTime = $startTime
            } -ErrorAction SilentlyContinue
        }
        catch {
            $events = @()
        }
        if (-not $events) { $events = @() }

        if ($events.Count -gt 0) {
            Write-Host -ForegroundColor $eventDef.Color "`nFound $($events.Count) $($eventDef.Name) event(s):"
            foreach ($event in $events) {
                # Parse the event XML to extract details
                $xml       = [xml]$event.ToXml()
                $dataItems = $xml.Event.EventData.Data
                $details   = ""
                foreach ($field in $eventDef.Fields) {
                    $value = ($dataItems | Where-Object { $_.Name -eq $field } |
                              Select-Object -ExpandProperty "#text" -ErrorAction SilentlyContinue)
                    if ($value) {
                        # Using subexpression operators to correctly delimit variable references
                        $details += "$($field): $($value); "
                    }
                }
                $timeStamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host -ForegroundColor $eventDef.Color "  [$($timeStamp)] $details"
            }
        }
        else {
            Write-Host -ForegroundColor Green "`nNo $($eventDef.Name) events in the last 15 seconds."
        }
    }

    # Wait 15 seconds before the next audit cycle
    Start-Sleep -Seconds 15
    Write-Host "`n"
}
