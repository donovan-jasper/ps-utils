<#
.SYNOPSIS
    Monitors for new processes not present in a baseline snapshot.

.DESCRIPTION
    Takes a snapshot of all running process names and executable paths at startup,
    then polls every 15 seconds for new process names. Known transient system
    processes are whitelisted to reduce noise.

    Unknown processes are displayed in red with PID, path, and parent process info.
    With -AutoKill, unknown processes are forcibly terminated.

    Green output is shown when no new processes are detected.

.PARAMETER AutoKill
    Forcibly terminate any process not in the baseline or transient whitelist.

.EXAMPLE
    .\Watch-Processes.ps1
    Monitor for new processes, alert only.

.EXAMPLE
    .\Watch-Processes.ps1 -AutoKill
    Monitor and automatically kill unknown processes.

.NOTES
    Requires an elevated (Administrator) PowerShell session.
    Dot-sources Common.ps1 for Write-Banner.
#>

param(
    [switch]$AutoKill
)

. "$PSScriptRoot\..\Common.ps1"

Write-Banner -ScriptName "Watch-Processes"

# --- Transient system processes that come and go normally ---
$TransientWhitelist = @(
    "conhost",
    "WmiPrvSE",
    "SearchProtocolHost",
    "RuntimeBroker",
    "backgroundTaskHost",
    "WUDFHost",
    "SearchFilterHost",
    "SearchIndexer",
    "ShellExperienceHost",
    "ApplicationFrameHost",
    "SystemSettings",
    "MicrosoftEdgeUpdate",
    "MpCmdRun",
    "WMIADAP",
    "WmiApSrv",
    "TiWorker",
    "TrustedInstaller",
    "MsMpEng",
    "NisSrv",
    "dllhost",
    "sihost",
    "taskhostw",
    "smartscreen"
)
$transientLower = $TransientWhitelist | ForEach-Object { $_.ToLower() }

# --- Baseline snapshot ---

function Get-ProcessBaseline {
    $baseline = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.ProcessName.ToLower()
        if (-not $baseline.ContainsKey($name)) {
            $baseline[$name] = @{
                Path = $_.Path
                Id   = $_.Id
            }
        }
    }
    return $baseline
}

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Taking process baseline snapshot..." -ForegroundColor Cyan

$baseline = Get-ProcessBaseline
$baselineNames = $baseline.Keys

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Baseline: $($baselineNames.Count) unique process names" -ForegroundColor Cyan
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Transient whitelist: $($TransientWhitelist.Count) entries" -ForegroundColor Cyan
if ($AutoKill) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] AutoKill is ON - unknown processes will be terminated" -ForegroundColor Yellow
}
Write-Host "Polling every 15 seconds... (Ctrl+C to stop)" -ForegroundColor Cyan
Write-Host ""

# --- Poll loop ---

while ($true) {
    Start-Sleep -Seconds 15
    $foundNew = $false

    $currentProcs = Get-Process -ErrorAction SilentlyContinue
    $seen = @{}

    foreach ($proc in $currentProcs) {
        $name = $proc.ProcessName.ToLower()

        # Skip if already checked this cycle
        if ($seen.ContainsKey($name)) { continue }
        $seen[$name] = $true

        # Skip if in baseline
        if ($name -in $baselineNames) { continue }

        # Skip transient system processes
        if ($name -in $transientLower) { continue }

        # Also allow svchost spawns explicitly
        if ($name -eq "svchost") { continue }

        $foundNew = $true

        # Get parent process info
        $parentInfo = "unknown"
        try {
            $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
            if ($wmiProc -and $wmiProc.ParentProcessId) {
                $parent = Get-Process -Id $wmiProc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parent) {
                    $parentInfo = "$($parent.ProcessName) (PID $($parent.Id))"
                }
            }
        } catch {}

        $path = if ($proc.Path) { $proc.Path } else { "N/A" }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] UNKNOWN PROCESS: $($proc.ProcessName)" -ForegroundColor Red
        Write-Host "  PID: $($proc.Id)  Path: $path" -ForegroundColor Red
        Write-Host "  Parent: $parentInfo" -ForegroundColor Red

        if ($AutoKill) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host "  KILLED PID $($proc.Id)" -ForegroundColor Yellow
            } catch {
                Write-Host "  Failed to kill PID $($proc.Id): $_" -ForegroundColor Red
            }
        }
    }

    if (-not $foundNew) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] All clear - no unknown processes" -ForegroundColor Green
    }
}
