<#
.SYNOPSIS
    Monitors 9 suspicious security event types with human-readable one-line output.

.DESCRIPTION
    Polls the Security event log every 15 seconds for the following events:
      - 4688: Process Creation (Yellow)
      - 4697: Service Installation (Red)
      - 4672: Special Privilege Assignment (Magenta)
      - 4720: User Account Creation (Cyan)
      - 4625: Failed Logon Attempt (Red)
      - 4740: Account Lockout (DarkMagenta)
      - 4726: User Account Deletion (DarkCyan)
      - 4732: Local Group Member Added (Blue)
      - 4719: Audit Policy Change (Gray)

    Each event is printed as a single color-coded line with timestamp and
    extracted fields. Based on the wider_audit.ps1 approach but with
    human-readable translations and compact output.

.EXAMPLE
    .\Watch-Events.ps1

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner and Assert-Role.
#>

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Watch-Events"
Assert-Role -Required @("DomainController", "MemberServer", "Workstation")
Assert-Dependencies -Commands @("Get-WinEvent")

# Failure code translation for 4625 events
$FailureCodes = @{
    '0xc000006d' = 'Bad username or password'; '0xc000006e' = 'Account restriction'
    '0xc0000064' = 'User does not exist'; '0xc000006a' = 'Wrong password'
    '0xc0000234' = 'Account locked out'; '0xc000015b' = 'Logon type not granted'
    '0xc0000072' = 'Account disabled'; '0xc0000193' = 'Account expired'
    '0xc0000070' = 'Workstation restriction'; '0xc0000133' = 'Clock skew too great'
}

# 4688 - Process Creation: a new process was started on this machine
# 4697 - Service Installation: a new Windows service was installed
# 4672 - Special Privilege Assignment: sensitive privileges (SeDebugPrivilege, etc.) assigned to a logon
# 4720 - User Account Creation: a new local or domain user account was created
# 4625 - Failed Logon Attempt: someone tried to log in and failed
# 4740 - Account Lockout: an account was locked after too many failed attempts
# 4726 - User Account Deletion: a user account was removed
# 4732 - Local Group Member Added: a user was added to a local security group (e.g. Administrators)
# 4719 - Audit Policy Change: the system audit policy was modified

$eventDefs = @(
    @{ Id = 4688; Name = "PROC";    Color = "Yellow";      Fields = @("SubjectUserName", "NewProcessName", "ProcessCommandLine") }
    @{ Id = 4697; Name = "SVC";     Color = "Red";         Fields = @("ServiceName", "ServiceFileName") }
    @{ Id = 4672; Name = "PRIV";    Color = "Magenta";     Fields = @("SubjectUserName", "PrivilegeList") }
    @{ Id = 4720; Name = "USERADD"; Color = "Cyan";        Fields = @("TargetUserName", "SubjectUserName") }
    @{ Id = 4625; Name = "FAIL";    Color = "Red";         Fields = @("TargetUserName", "IpAddress", "Status", "SubStatus") }
    @{ Id = 4740; Name = "LOCKOUT"; Color = "DarkMagenta"; Fields = @("TargetUserName", "IpAddress") }
    @{ Id = 4726; Name = "USERDEL"; Color = "DarkCyan";    Fields = @("TargetUserName", "SubjectUserName") }
    @{ Id = 4732; Name = "GRPADD";  Color = "Blue";        Fields = @("TargetUserName", "MemberName") }
    @{ Id = 4719; Name = "AUDIT";   Color = "Gray";        Fields = @("SubcategoryName") }
)

function Get-XmlField {
    param([System.Xml.XmlElement[]]$DataItems, [string]$Name)
    $node = $DataItems | Where-Object { $_.Name -eq $Name }
    if ($node) { return $node.'#text' }
    return $null
}

function Format-EventLine {
    param($Event, $Def)

    $xml = [xml]$Event.ToXml()
    $data = $xml.Event.EventData.Data
    $ts = $Event.TimeCreated.ToString("HH:mm:ss")

    $parts = @()
    foreach ($field in $Def.Fields) {
        $val = Get-XmlField $data $field
        if ($val) {
            # Clean up multiline privilege lists
            $val = ($val -replace '\s+', ' ').Trim()

            # Translate failure codes for 4625
            if ($Def.Id -eq 4625 -and ($field -eq 'Status' -or $field -eq 'SubStatus')) {
                $code = $val.ToLower()
                if ($FailureCodes.ContainsKey($code)) {
                    $val = $FailureCodes[$code]
                }
                if ($field -eq 'Status') { $field = 'reason' }
                if ($field -eq 'SubStatus') { $field = 'detail' }
            }

            $parts += "$field=$val"
        }
    }

    return "[$ts] $($Def.Name)  $($parts -join '  ')"
}

# Collect all event IDs for a single query
$allIds = $eventDefs | ForEach-Object { $_.Id }

Write-Host "Monitoring 9 event types every 15 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
Write-Host ""

while ($true) {
    $startTime = (Get-Date).AddSeconds(-15)

    # Single query for all event IDs
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $allIds
            StartTime = $startTime
        } -ErrorAction SilentlyContinue)
    } catch {
        $events = @()
    }

    if ($events.Count -eq 0) {
        Start-Sleep -Seconds 15
        continue
    }

    # Sort by time and print each event
    $events | Sort-Object TimeCreated | ForEach-Object {
        $evt = $_
        $def = $eventDefs | Where-Object { $_.Id -eq $evt.Id } | Select-Object -First 1
        if ($def) {
            $line = Format-EventLine -Event $evt -Def $def
            Write-Host $line -ForegroundColor $def.Color
        }
    }

    Start-Sleep -Seconds 15
}
