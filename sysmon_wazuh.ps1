<#
.SYNOPSIS
    Installs Wazuh Agent + Sysmon on Windows and configures Wazuh to collect Sysmon logs.
    Uses the <wodle name="windows_eventchannel"> block for Sysmon as required by Wazuh 4.x+.

.DESCRIPTION
    1. Prompts for Wazuh manager information, agent name, and registration password.
    2. Downloads or falls back to a local Wazuh Agent MSI.
    3. Installs Wazuh Agent silently.
    4. Attempts to start Wazuh Agent service. If not running, does a manual registration (agent-auth).
    5. Downloads or falls back to Sysmon.zip and Wazuh’s sysmonconfig.xml.
    6. Installs Sysmon with the config file.
    7. Checks ossec.conf for <wodle name="windows_eventchannel">. If missing, appends a Sysmon eventchannel block before </ossec_config>.
    8. Restarts Wazuh Agent.

#>

[CmdletBinding()]
param()

Write-Host "`n========== WAZUH AND SYSMON INSTALL/CONFIG SCRIPT =========="

# ---------------------------------------------------------------
# 1. Collect Basic Wazuh Parameters
# ---------------------------------------------------------------
$managerIP            = Read-Host "Enter your Wazuh Manager IP or hostname"
$agentName            = Read-Host "Enter a name for this Wazuh agent (optional, press Enter for default hostname)"
$registrationPassword = Read-Host "Enter the registration password for the Wazuh manager (if required; press Enter if not used)"

Write-Host "`nWe will install the Wazuh agent with the following parameters:"
Write-Host "  Manager IP/Host: $managerIP"
Write-Host "  Agent Name:      $agentName"
Write-Host "  Registration PW: $registrationPassword (blank = no password)"
if ((Read-Host "Press Enter to continue, or 'N' to cancel.") -eq 'N') {
    Write-Host "Installation canceled by user."
    return
}

# ---------------------------------------------------------------
# Variables / Paths
# ---------------------------------------------------------------
# Adjust to your desired Wazuh Agent version
$wazuhVersion = "4.4.5"

# Wazuh Agent download URL
$wazuhMsiUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhVersion-1.msi"

# Script directory (where we look for local fallback files)
$scriptDir    = Split-Path $MyInvocation.MyCommand.Definition -Parent

# MSI local fallback
$localMsiName      = "wazuh-agent.msi"
$downloadedMsiPath = Join-Path $scriptDir "wazuh-agent.msi"

# Wazuh install path and config file
$WazuhInstallPath = "C:\Program Files (x86)\ossec-agent"
$wazuhConfFile    = Join-Path $WazuhInstallPath "ossec.conf"

# Sysmon variables
$sysmonZipUrl      = "https://download.sysinternals.com/files/Sysmon.zip"
$downloadedZipPath = Join-Path $scriptDir "Sysmon.zip"
$localSysmonZip    = "Sysmon.zip"

$wazuhSysmonConfigUrl = "https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml"
$sysmonConfigLocal    = Join-Path $scriptDir "sysmon_config.xml"
$localSysmonConf      = "conf.xml"

# ---------------------------------------------------------------
# Helper: TryDownloadFile
# ---------------------------------------------------------------
function TryDownloadFile {
    param (
        [string]$Url,
        [string]$DestinationPath
    )
    try {
        Write-Host "Attempting to download $Url ..."
        Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Download succeeded: $DestinationPath"
        return $true
    }
    catch {
        Write-Warning "Download failed from $Url. Error: $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------
# 2. Download or Fallback: Wazuh Agent MSI
# ---------------------------------------------------------------
Write-Host "`n---- Step 2: Retrieve Wazuh Agent MSI (version $wazuhVersion) ----"
$needWazuhMsi = $true
if (TryDownloadFile -Url $wazuhMsiUrl -DestinationPath $downloadedMsiPath) {
    $needWazuhMsi = $false
}

if ($needWazuhMsi) {
    $fallbackMsiPath = Join-Path $scriptDir $localMsiName
    if (Test-Path $fallbackMsiPath) {
        Write-Host "Using local fallback MSI at $fallbackMsiPath"
        Copy-Item $fallbackMsiPath $downloadedMsiPath -Force
        $needWazuhMsi = $false
    } else {
        Write-Error "Could not retrieve Wazuh Agent MSI from remote or local. Aborting."
        return
    }
}

# ---------------------------------------------------------------
# 3. Install Wazuh Agent
# ---------------------------------------------------------------
Write-Host "`n---- Step 3: Install Wazuh Agent ----"
if (!(Test-Path $downloadedMsiPath)) {
    Write-Error "Wazuh Agent MSI not found at $downloadedMsiPath. Aborting."
    return
}

# Build msiexec arguments
# Use /quiet for silent. /qb for basic progress. Log to C:\Windows\Temp\wazuh_agent_install.log
$msiArgs = '/i "' + $downloadedMsiPath + '" /quiet /l*v "C:\Windows\Temp\wazuh_agent_install.log"'

# Pass MSI properties
if ($managerIP) {
    $msiArgs += ' WAZUH_MANAGER="' + $managerIP + '"'
}
if ($agentName) {
    $msiArgs += ' WAZUH_AGENT_NAME="' + $agentName + '"'
}
if ($registrationPassword) {
    $msiArgs += ' WAZUH_REGISTRATION_PASS="' + $registrationPassword + '"'
}

Write-Host "Running: msiexec $msiArgs"
cmd /c "msiexec.exe $msiArgs"

# Wait a few seconds for service to register and start
Start-Sleep -Seconds 5

# Check if Wazuh Agent service is running
$service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Running') {
        Write-Warning "WazuhSvc is installed but not running. Attempting to start..."
        Start-Service WazuhSvc -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $service.Refresh()
    }
} else {
    Write-Warning "Wazuh Service (WazuhSvc) not found. Installation might have failed or the system needs a reboot."
}

# If still not running, attempt manual agent-auth registration
if ($service -and $service.Status -ne 'Running') {
    Write-Warning "Wazuh service is not running. Trying manual agent registration..."

    $agentAuthExe = Join-Path $WazuhInstallPath "agent-auth.exe"
    if (Test-Path $agentAuthExe) {
        if ($managerIP -and $registrationPassword) {
            Write-Host "Registering agent manually via agent-auth.exe ..."
            & $agentAuthExe -m $managerIP -p $registrationPassword
            # Start service again
            Start-Service WazuhSvc -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            $service.Refresh()
        } else {
            Write-Warning "Manager IP or registration password is missing. Cannot do manual agent-auth."
        }
    } else {
        Write-Warning "agent-auth.exe not found at $agentAuthExe. Cannot do manual registration."
    }
}

if ($service -and $service.Status -eq 'Running') {
    Write-Host "Wazuh Agent is installed and running."
} else {
    Write-Warning "Wazuh service is still not running. Check logs at '$WazuhInstallPath\logs\ossec.log' and 'C:\Windows\Temp\wazuh_agent_install.log'"
}

# ---------------------------------------------------------------
# 4. Sysmon Download or Fallback
# ---------------------------------------------------------------
Write-Host "`n---- Step 4: Retrieve Sysmon.zip ----"
$needSysmonZip = $true
if (TryDownloadFile -Url $sysmonZipUrl -DestinationPath $downloadedZipPath) {
    $needSysmonZip = $false
}
if ($needSysmonZip) {
    $fallbackZipPath = Join-Path $scriptDir $localSysmonZip
    if (Test-Path $fallbackZipPath) {
        Write-Host "Using local fallback Sysmon.zip at $fallbackZipPath"
        Copy-Item $fallbackZipPath $downloadedZipPath -Force
        $needSysmonZip = $false
    } else {
        Write-Error "Sysmon.zip could not be retrieved from remote or local. Aborting."
        return
    }
}

# ---------------------------------------------------------------
# 5. Download or Fallback for Wazuh Sysmon config
# ---------------------------------------------------------------
Write-Host "`n---- Step 5: Retrieve Wazuh Sysmon config ----"
if (Test-Path $sysmonConfigLocal) {
    Remove-Item -Path $sysmonConfigLocal -Force
}

$needSysmonConf = $true
if (TryDownloadFile -Url $wazuhSysmonConfigUrl -DestinationPath $sysmonConfigLocal) {
    $needSysmonConf = $false
}
if ($needSysmonConf) {
    $fallbackConfPath = Join-Path $scriptDir $localSysmonConf
    if (Test-Path $fallbackConfPath) {
        Write-Host "Using local fallback Sysmon config at $fallbackConfPath"
        Copy-Item $fallbackConfPath $sysmonConfigLocal -Force
        $needSysmonConf = $false
    } else {
        Write-Error "Sysmon configuration could not be retrieved from remote or local. Aborting."
        return
    }
}

# ---------------------------------------------------------------
# 6. Extract and Install Sysmon
# ---------------------------------------------------------------
Write-Host "`n---- Step 6: Extract and Install Sysmon ----"
$extractPath = Join-Path $scriptDir "Sysmon_Extracted"
if (Test-Path $extractPath) {
    Remove-Item $extractPath -Recurse -Force
}
Expand-Archive -Path $downloadedZipPath -DestinationPath $extractPath

$sysmonBinary = Join-Path $extractPath "Sysmon64.exe"
if (!(Test-Path $sysmonBinary)) {
    Write-Error "Sysmon64.exe not found in extracted folder. Aborting."
    return
}

Write-Host "Installing Sysmon service with config: $sysmonConfigLocal"
$output = & $sysmonBinary /accepteula -i $sysmonConfigLocal 2>&1
Write-Host $output

# ---------------------------------------------------------------
# 7. Ensure Wazuh monitors Sysmon (windows_eventchannel)
# ---------------------------------------------------------------
Write-Host "`n---- Step 7: Configure Wazuh to monitor Sysmon logs ----"
if (Test-Path $wazuhConfFile) {
    if (!(Test-Path "$wazuhConfFile.bak")) {
        Write-Host "Backing up original Wazuh config to $wazuhConfFile.bak ..."
        Copy-Item -Path $wazuhConfFile -Destination "$wazuhConfFile.bak"
    }

    # Read full config as a single string (for insertion).
    $confContent = Get-Content $wazuhConfFile -Raw

    # Check if there's already a <wodle name="windows_eventchannel"> block
    if ($confContent -notmatch '<wodle name="windows_eventchannel">') {
        Write-Host 'Appending <wodle name="windows_eventchannel"> block with Sysmon channel ...'

        # The block to insert (Sysmon channel).
        $windowsEventChannelBlock = @'
  <wodle name="windows_eventchannel">
    <disabled>no</disabled>
    <eventchannel>
      <name>Microsoft-Windows-Sysmon/Operational</name>
      <!-- Optional: only Sysmon provider -->
      <query>Event[System[Provider[@Name="Microsoft-Windows-Sysmon"]]]</query>
    </eventchannel>
  </wodle>
  <localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
  </localfile>
'@

        # Insert before the final </ossec_config>
        # We'll use a simple regex approach. A more robust approach would be real XML editing.
        $updatedConf = $confContent -replace '(</ossec_config>)', "$windowsEventChannelBlock`r`n`$1"
        $updatedConf | Set-Content $wazuhConfFile
    } else {
        Write-Host "Found existing <wodle name='windows_eventchannel'> block. Skipping addition."
    }

    Write-Host "Restarting Wazuh Agent..."
    net stop WazuhSvc | Out-Null
    net start WazuhSvc | Out-Null
    Write-Host "Wazuh agent restarted."
} else {
    Write-Warning "Wazuh config file not found at $wazuhConfFile. Skipping Sysmon eventchannel config."
}

Write-Host ''
Write-Host '========== INSTALLATION AND CONFIGURATION COMPLETE =========='
Write-Host "1) Wazuh Agent installed (version $wazuhVersion)."
Write-Host "2) Sysmon installed with config: $sysmonConfigLocal"
Write-Host "   Check Event Viewer -> Microsoft-Windows-Sysmon/Operational for logs."
Write-Host "3) Wazuh Agent is configured to read Sysmon logs via windows_eventchannel."
Write-Host "   Verify logs in the Wazuh Manager or Kibana."
Write-Host ''
