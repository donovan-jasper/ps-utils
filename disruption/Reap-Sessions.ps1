<#
.SYNOPSIS
    Kills user sessions not in a whitelist, optionally disabling their accounts.

.DESCRIPTION
    Polls `query user` every 15 seconds and forcibly logs off any session whose
    username is not in the TeamUsers whitelist. Useful for ejecting unauthorized
    users who have established interactive or RDP sessions.

    With -DisableAccount, the script also disables the user's AD account (on a
    domain controller) or local account (on member servers/workstations) to
    prevent re-authentication.

    Each reap action is logged with timestamp, username, session ID, and source.

.PARAMETER TeamUsers
    Array of usernames that should NOT be reaped. Case-insensitive.
    Default: @("administrator", "blue_admin")

.PARAMETER DisableAccount
    If set, also disables the AD or local account of each reaped user.

.EXAMPLE
    .\Reap-Sessions.ps1
    Reap all sessions except administrator and blue_admin.

.EXAMPLE
    .\Reap-Sessions.ps1 -TeamUsers "admin","sysop" -DisableAccount
    Reap sessions not belonging to admin or sysop, and disable reaped accounts.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner and Get-MachineRole.
    WARNING: This script performs disruptive network/session operations. Evaluate carefully before using in production environments.
#>

param(
    [string[]]$TeamUsers = @("administrator", "blue_admin"),
    [switch]$DisableAccount
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Reap-Sessions"

$role = Get-MachineRole

# Normalize whitelist to lowercase for comparison
$whitelist = $TeamUsers | ForEach-Object { $_.ToLower() }

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Whitelisted users: $($whitelist -join ', ')" -ForegroundColor Cyan
if ($DisableAccount) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] DisableAccount is ON - reaped accounts will be disabled" -ForegroundColor Yellow
}
Write-Host "Polling every 15 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
Write-Host ""

function Parse-QueryUser {
    $output = query user 2>&1
    if ($LASTEXITCODE -ne 0) { return @() }

    $sessions = @()
    # Skip the header line
    $lines = $output | Select-Object -Skip 1
    foreach ($line in $lines) {
        $lineStr = $line.ToString().Trim()
        if (-not $lineStr) { continue }

        # query user output is columnar; parse with regex
        # Format: USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME
        # The '>' prefix indicates the current session
        $lineStr = $lineStr -replace '^\>', ''
        $parts = $lineStr -split '\s{2,}'
        if ($parts.Count -ge 3) {
            $username = $parts[0].Trim()
            # Session ID is typically the 3rd or 2nd numeric field
            $sessionId = $null
            foreach ($p in $parts) {
                if ($p.Trim() -match '^\d+$') {
                    $sessionId = $p.Trim()
                    break
                }
            }
            if ($username -and $sessionId) {
                $sessions += [PSCustomObject]@{
                    Username  = $username
                    SessionId = $sessionId
                    Raw       = $lineStr
                }
            }
        }
    }
    return $sessions
}

function Disable-UserAccount {
    param([string]$Username)

    if ($role -eq "DomainController") {
        try {
            Disable-ADAccount -Identity $Username -ErrorAction Stop
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   AD account '$Username' DISABLED" -ForegroundColor Yellow
        } catch {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   Failed to disable AD account '$Username': $_" -ForegroundColor Red
        }
    } else {
        try {
            Disable-LocalUser -Name $Username -ErrorAction Stop
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   Local account '$Username' DISABLED" -ForegroundColor Yellow
        } catch {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   Failed to disable local account '$Username': $_" -ForegroundColor Red
        }
    }
}

while ($true) {
    $sessions = Parse-QueryUser
    $reaped = $false

    foreach ($s in $sessions) {
        if ($s.Username.ToLower() -in $whitelist) { continue }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] REAP user=$($s.Username) sessionId=$($s.SessionId) raw=[$($s.Raw)]" -ForegroundColor Red

        try {
            logoff $s.SessionId /server:localhost 2>&1 | Out-Null
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   Session $($s.SessionId) logged off" -ForegroundColor Red
        } catch {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')]   Failed to logoff session $($s.SessionId): $_" -ForegroundColor Red
        }

        if ($DisableAccount) {
            Disable-UserAccount -Username $s.Username
        }

        $reaped = $true
    }

    if (-not $reaped) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] All clear - no unauthorized sessions" -ForegroundColor Green
    }

    Start-Sleep -Seconds 15
}
