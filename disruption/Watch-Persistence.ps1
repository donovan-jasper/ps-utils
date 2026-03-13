<#
.SYNOPSIS
    Monitors for new persistence mechanisms (scheduled tasks, services, registry Run keys).

.DESCRIPTION
    Takes a baseline snapshot of scheduled tasks, services, and Run/RunOnce registry
    keys at startup, then polls every 30 seconds for new entries. New items are
    displayed in red with full details (task XML path, service binary, registry value).

    With -AutoRemove, new scheduled tasks are unregistered, new services are stopped
    and removed, and new Run/RunOnce registry values are deleted automatically.

    All actions are logged with timestamps. Green output when no changes are detected.

.PARAMETER AutoRemove
    Automatically remove newly detected persistence items.

.EXAMPLE
    .\Watch-Persistence.ps1
    Monitor for new persistence entries, alert only.

.EXAMPLE
    .\Watch-Persistence.ps1 -AutoRemove
    Monitor and automatically remove new persistence entries.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner.
#>

param(
    [switch]$AutoRemove
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Watch-Persistence"

# --- Registry paths to monitor ---
$RunKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

# --- Snapshot functions ---

function Get-TaskBaseline {
    $tasks = @{}
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $key = "$($_.TaskPath)$($_.TaskName)"
            $tasks[$key] = $_
        }
    } catch {}
    return $tasks
}

function Get-ServiceBaseline {
    $services = @{}
    Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
        $services[$_.Name] = $_
    }
    return $services
}

function Get-RegistryBaseline {
    $entries = @{}
    foreach ($path in $RunKeyPaths) {
        if (-not (Test-Path $path)) { continue }
        try {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $props.PSObject.Properties | Where-Object {
                $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
            } | ForEach-Object {
                $key = "${path}\$($_.Name)"
                $entries[$key] = $_.Value
            }
        } catch {}
    }
    return $entries
}

# --- Take initial baselines ---

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Taking baseline snapshots..." -ForegroundColor Cyan

$baselineTasks    = Get-TaskBaseline
$baselineServices = Get-ServiceBaseline
$baselineRegistry = Get-RegistryBaseline

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Baseline: $($baselineTasks.Count) tasks, $($baselineServices.Count) services, $($baselineRegistry.Count) registry values" -ForegroundColor Cyan
if ($AutoRemove) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] AutoRemove is ON - new persistence items will be removed" -ForegroundColor Yellow
}
Write-Host "Polling every 30 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
Write-Host ""

# --- Poll loop ---

while ($true) {
    Start-Sleep -Seconds 30
    $foundNew = $false

    # --- Check scheduled tasks ---
    $currentTasks = Get-TaskBaseline
    foreach ($key in $currentTasks.Keys) {
        if (-not $baselineTasks.ContainsKey($key)) {
            $task = $currentTasks[$key]
            $foundNew = $true
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] NEW TASK: $key" -ForegroundColor Red
            Write-Host "  State: $($task.State)  URI: $($task.URI)" -ForegroundColor Red
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Host "  Last Run: $($taskInfo.LastRunTime)  Next Run: $($taskInfo.NextRunTime)" -ForegroundColor Red
                }
            } catch {}
            try {
                $xml = Export-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
                if ($xml) {
                    # Extract the command from XML
                    $xmlDoc = [xml]$xml
                    $exec = $xmlDoc.Task.Actions.Exec
                    if ($exec) {
                        Write-Host "  Command: $($exec.Command) $($exec.Arguments)" -ForegroundColor Red
                    }
                }
            } catch {}

            if ($AutoRemove) {
                try {
                    Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                    Write-Host "  REMOVED task: $key" -ForegroundColor Yellow
                } catch {
                    Write-Host "  Failed to remove task: $_" -ForegroundColor Red
                }
            }
        }
    }

    # --- Check services ---
    $currentServices = Get-ServiceBaseline
    foreach ($name in $currentServices.Keys) {
        if (-not $baselineServices.ContainsKey($name)) {
            $svc = $currentServices[$name]
            $foundNew = $true

            # Get binary path from WMI
            $binaryPath = "unknown"
            try {
                $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
                if ($wmiSvc) { $binaryPath = $wmiSvc.PathName }
            } catch {}

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] NEW SERVICE: $name" -ForegroundColor Red
            Write-Host "  DisplayName: $($svc.DisplayName)  Status: $($svc.Status)  StartType: $($svc.StartType)" -ForegroundColor Red
            Write-Host "  BinaryPath: $binaryPath" -ForegroundColor Red

            if ($AutoRemove) {
                try {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                    sc.exe delete $name 2>&1 | Out-Null
                    Write-Host "  REMOVED service: $name" -ForegroundColor Yellow
                } catch {
                    Write-Host "  Failed to remove service: $_" -ForegroundColor Red
                }
            }
        }
    }

    # --- Check registry Run keys ---
    $currentRegistry = Get-RegistryBaseline
    foreach ($key in $currentRegistry.Keys) {
        if (-not $baselineRegistry.ContainsKey($key)) {
            $foundNew = $true
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] NEW RUN KEY: $key" -ForegroundColor Red
            Write-Host "  Value: $($currentRegistry[$key])" -ForegroundColor Red

            if ($AutoRemove) {
                try {
                    # Parse path and property name
                    $lastBackslash = $key.LastIndexOf('\')
                    $regPath = $key.Substring(0, $lastBackslash)
                    $propName = $key.Substring($lastBackslash + 1)
                    Remove-ItemProperty -Path $regPath -Name $propName -Force -ErrorAction Stop
                    Write-Host "  REMOVED registry value: $propName from $regPath" -ForegroundColor Yellow
                } catch {
                    Write-Host "  Failed to remove registry value: $_" -ForegroundColor Red
                }
            }
        }
    }

    if (-not $foundNew) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] All clear - no new persistence detected" -ForegroundColor Green
    }

    # Update baselines (so we don't re-alert on items we already handled)
    if (-not $AutoRemove) {
        $baselineTasks    = $currentTasks
        $baselineServices = $currentServices
        $baselineRegistry = $currentRegistry
    } else {
        # Re-snapshot after removals
        $baselineTasks    = Get-TaskBaseline
        $baselineServices = Get-ServiceBaseline
        $baselineRegistry = Get-RegistryBaseline
    }
}
