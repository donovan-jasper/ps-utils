<#
.SYNOPSIS
    Workstation and member server hardening script.

.DESCRIPTION
    Applies aggressive local hardening for Windows 10/11 workstations and member servers:
        - Interactive logon and account policies
        - LSA and authentication hardening (RunAsPPL, NTLMv2, WDigest disable)
        - Network security (SMBv1 disable, SMB signing, LLMNR/NetBIOS/WPAD disable, TLS lockdown)
        - System security (DLL search, pagefile clear, AutoRun disable, DCOM disable, HVCI)
        - Privacy and telemetry removal
        - Microsoft Defender configuration and ASR rules
        - Service hardening (disable unnecessary services, Print Spooler)
        - Firewall lockdown with logging
        - Browser hardening (IE, Edge, Chrome policies)
        - USB mass storage block
        - Software Restriction Policies
        - BitLocker enforcement

.NOTES
    Run as Administrator. Many changes require a reboot.
    This script is highly restrictive and can disrupt normal workflows -- test thoroughly.
#>

[CmdletBinding()]
Param()

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Harden-Workstation"
Assert-Role -Required Workstation, MemberServer

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
     [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# Create a System Restore Point (only works if System Protection is enabled)
try {
    Checkpoint-Computer -Description "Pre-Hardening" -RestorePointType "Modify_Settings"
    Write-Host "[INFO] System restore point created successfully."
} catch {
    Write-Warning "Could not create a system restore point. Continuing..."
}


# ---------------------------------------------------------------------------
# 1. Interactive Logon and Account Policies
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring interactive logon and account policies..."
$regSystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (!(Test-Path $regSystemPath)) { New-Item -Path $regSystemPath -Force | Out-Null }

# Hide last username
New-ItemProperty -Path $regSystemPath -Name "DontDisplayLastUserName" -Value 1 -PropertyType DWORD -Force | Out-Null
# Require Ctrl+Alt+Del
New-ItemProperty -Path $regSystemPath -Name "DisableCAD" -Value 0 -PropertyType DWORD -Force | Out-Null
# Disable password reveal button
$credUIPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
if (!(Test-Path $credUIPath)) { New-Item -Path $credUIPath -Force | Out-Null }
New-ItemProperty -Path $credUIPath -Name "DisablePasswordReveal" -Value 1 -PropertyType DWORD -Force | Out-Null
# Do not display network selection UI on logon
$sysPolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (!(Test-Path $sysPolPath)) { New-Item -Path $sysPolPath -Force | Out-Null }
New-ItemProperty -Path $sysPolPath -Name "DontDisplayNetworkSelectionUI" -Value 1 -PropertyType DWORD -Force | Out-Null
# Legal notice
New-ItemProperty -Path $regSystemPath -Name "LegalNoticeCaption" -Value "NOTICE" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $regSystemPath -Name "LegalNoticeText" -Value "Unauthorized use is prohibited. All activities may be monitored." -PropertyType String -Force | Out-Null
# Limit cached logon credentials
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 4 -PropertyType String -Force | Out-Null
# Do not allow shutdown without logon
New-ItemProperty -Path $regSystemPath -Name "ShutdownWithoutLogon" -Value 0 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 2. LSA and Authentication
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring LSA and authentication policies..."
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (!(Test-Path $lsaPath)) { New-Item -Path $lsaPath -Force | Out-Null }

New-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "ForceGuest" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "NoLMHash" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdmin" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lsaPath -Name "FIPSAlgorithmPolicy" -Value 1 -PropertyType DWORD -Force | Out-Null

# NTLM session security (128-bit encryption)
$msvPath = "$lsaPath\MSV1_0"
if (!(Test-Path $msvPath)) { New-Item -Path $msvPath -Force | Out-Null }
New-ItemProperty -Path $msvPath -Name "NtlmMinClientSec" -Value 0x20080000 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $msvPath -Name "NtlmMinServerSec" -Value 0x20080000 -PropertyType DWORD -Force | Out-Null

# Disable WDigest plaintext credential storage
$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (!(Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
New-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 3. Network Security
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring network-level security..."

# Disable SMBv1
$lanmanServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (!(Test-Path $lanmanServerPath)) { New-Item -Path $lanmanServerPath -Force | Out-Null }
New-ItemProperty -Path $lanmanServerPath -Name "SMB1" -Value 0 -PropertyType DWORD -Force | Out-Null

$mrxsmbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if (Test-Path $mrxsmbPath) {
    New-ItemProperty -Path $mrxsmbPath -Name "Start" -Value 4 -PropertyType DWORD -Force | Out-Null
}
$mrxsmb2Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20"
if (Test-Path $mrxsmb2Path) {
    New-ItemProperty -Path $mrxsmb2Path -Name "Start" -Value 0 -PropertyType DWORD -Force | Out-Null
}

# Require SMB signing (client and server)
New-ItemProperty -Path $lanmanServerPath -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lanmanServerPath -Name "EnableSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null

$lanmanWorkstationPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (!(Test-Path $lanmanWorkstationPath)) { New-Item -Path $lanmanWorkstationPath -Force | Out-Null }
New-ItemProperty -Path $lanmanWorkstationPath -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $lanmanWorkstationPath -Name "EnableSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disallow insecure guest auth
$polWorkstationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (!(Test-Path $polWorkstationPath)) { New-Item -Path $polWorkstationPath -Force | Out-Null }
New-ItemProperty -Path $polWorkstationPath -Name "AllowInsecureGuestAuth" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable LLMNR
$dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (!(Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
New-ItemProperty -Path $dnsClientPath -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable NetBIOS over TCP/IP on all adapters
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
    $_.SetTcpipNetBIOS(2) | Out-Null
}

# Disable WPAD
$wpadPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (!(Test-Path $wpadPath)) { New-Item -Path $wpadPath -Force | Out-Null }
New-ItemProperty -Path $wpadPath -Name "WpadOverride" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable TLS 1.0 and 1.1
$protocolPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
foreach ($ver in @("TLS 1.0","TLS 1.1")) {
    foreach ($side in @("Server","Client")) {
        New-Item -Path "$protocolPath\$ver\$side" -Force | Out-Null
        New-ItemProperty -Path "$protocolPath\$ver\$side" -Name "Enabled" -Value 0 -PropertyType DWORD -Force | Out-Null
    }
}


# ---------------------------------------------------------------------------
# 4. System Security
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring system-level security settings..."
$sessionManagerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

# Safe DLL Search Mode
New-ItemProperty -Path $sessionManagerPath -Name "SafeDllSearchMode" -Value 1 -PropertyType DWORD -Force | Out-Null
# Clear Pagefile at Shutdown
New-ItemProperty -Path "$sessionManagerPath\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable AutoRun/AutoPlay
$explorerPolPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (!(Test-Path $explorerPolPath)) { New-Item -Path $explorerPolPath -Force | Out-Null }
New-ItemProperty -Path $explorerPolPath -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force | Out-Null

# Disable Remote Assistance
$raPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (!(Test-Path $raPath)) { New-Item -Path $raPath -Force | Out-Null }
New-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable Remote Desktop
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -PropertyType DWORD -Force | Out-Null
# If RDP is needed, require NLA
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable DCOM
$olePath = "HKLM:\SOFTWARE\Microsoft\OLE"
if (!(Test-Path $olePath)) { New-Item -Path $olePath -Force | Out-Null }
New-ItemProperty -Path $olePath -Name "EnableDCOM" -Value "N" -PropertyType String -Force | Out-Null

# Enable Memory Integrity / HVCI
$dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (!(Test-Path $dgPath)) { New-Item -Path $dgPath -Force | Out-Null }
New-ItemProperty -Path $dgPath -Name "Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 5. UI/UX Tweaks
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Applying UI/UX tweaks..."
New-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 -PropertyType String -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableBalloonTips" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $explorerPolPath -Name "HideSCAHealth" -Value 1 -PropertyType DWORD -Force | Out-Null

$gpExplorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $gpExplorerPath)) { New-Item -Path $gpExplorerPath -Force | Out-Null }
New-ItemProperty -Path $gpExplorerPath -Name "NoWindowMinimizingShortcuts" -Value 1 -PropertyType DWORD -Force | Out-Null

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 6. Privacy and Telemetry
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Blocking telemetry, CEIP, and data collection..."
$datacolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (!(Test-Path $datacolPath)) { New-Item -Path $datacolPath -Force | Out-Null }
New-ItemProperty -Path $datacolPath -Name "AllowTelemetry" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $datacolPath -Name "LimitDiagnosticLogCollection" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable Wi-Fi Sense
$wcmPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
if (!(Test-Path $wcmPath)) { New-Item -Path $wcmPath -Force | Out-Null }
New-ItemProperty -Path $wcmPath -Name "AutoConnectAllowedOEM" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $wcmPath -Name "AutoConnectAllowed" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable Advertising ID
$advPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
if (!(Test-Path $advPath)) { New-Item -Path $advPath -Force | Out-Null }
New-ItemProperty -Path $advPath -Name "Disabled" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable Cortana and web search
$searchPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path $searchPath)) { New-Item -Path $searchPath -Force | Out-Null }
New-ItemProperty -Path $searchPath -Name "AllowCortana" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $searchPath -Name "DisableWebSearch" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $searchPath -Name "ConnectedSearchUseWeb" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $searchPath -Name "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable CEIP
$sqmPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient"
if (!(Test-Path $sqmPath)) { New-Item -Path $sqmPath -Force | Out-Null }
New-ItemProperty -Path $sqmPath -Name "CEIPEnable" -Value 0 -PropertyType DWORD -Force | Out-Null

# Disable Windows Media Player CEIP
$wmplayerPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
if (!(Test-Path $wmplayerPath)) { New-Item -Path $wmplayerPath -Force | Out-Null }
New-ItemProperty -Path $wmplayerPath -Name "DisableAutoLearning" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $wmplayerPath -Name "GroupPrivacyAcceptance" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable Windows Error Reporting
$werPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
if (!(Test-Path $werPath)) { New-Item -Path $werPath -Force | Out-Null }
New-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -PropertyType DWORD -Force | Out-Null

# Disable OneDrive
$oneDrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (!(Test-Path $oneDrivePath)) { New-Item -Path $oneDrivePath -Force | Out-Null }
New-ItemProperty -Path $oneDrivePath -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 7. Microsoft Defender
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring Microsoft Defender..."
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent 0
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -DisableRealtimeMonitoring $false

# Attack Surface Reduction rule
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFc-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled

# SmartScreen
$sysPolWinPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (!(Test-Path $sysPolWinPath)) { New-Item -Path $sysPolWinPath -Force | Out-Null }
New-ItemProperty -Path $sysPolWinPath -Name "EnableSmartScreen" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $sysPolWinPath -Name "ShellSmartScreenLevel" -Value "Block" -PropertyType String -Force | Out-Null


# ---------------------------------------------------------------------------
# 8. Disable Unnecessary Services
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Disabling unnecessary or vulnerable services..."
$servicesToDisable = @(
    "RemoteRegistry",
    "LanmanServer",
    "Browser",
    "TermService",
    "TlntSvr",
    "Fax",
    "XblGameSave",
    "XboxNetApiSvc",
    "WMPNetworkSvc",
    "MapsBroker",
    "WSearch",
    "DiagTrack",
    "dmwappushservice",
    "Wscsvc"
)
foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        try {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host " [DISABLED] Service: $svc"
        } catch {
            Write-Warning "Could not disable service $svc. $_"
        }
    }
}

# Disable Print Spooler
try {
    Stop-Service Spooler -Force
    Set-Service Spooler -StartupType Disabled
    Write-Host " [DISABLED] Print Spooler"
} catch {
    Write-Warning "Could not disable Print Spooler. $_"
}


# ---------------------------------------------------------------------------
# 9. Firewall Configuration
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring Windows Firewall..."
$profiles = @('Domain','Private','Public')
foreach ($profile in $profiles) {
    Set-NetFirewallProfile -Profile $profile -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow `
        -AllowInboundRemoteAdministration False -AllowInboundRemoteDesktop False
}

New-NetFirewallRule -DisplayName "Block SMB TCP 445 (Public)" -Profile Public -Direction Inbound -Action Block -Protocol TCP -LocalPort 445 -RemoteAddress Any -Force | Out-Null
New-NetFirewallRule -DisplayName "Block SMB NetBIOS 139 (Public)" -Profile Public -Direction Inbound -Action Block -Protocol TCP -LocalPort 139 -RemoteAddress Any -Force | Out-Null
New-NetFirewallRule -DisplayName "Block Outbound SMB 445" -Profile Any -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 -RemoteAddress Any -Force | Out-Null

Set-NetFirewallProfile -Profile $profiles -LogAllowed $false -LogBlocked $true -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384


# ---------------------------------------------------------------------------
# 10. Disable Telemetry Scheduled Tasks
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Disabling telemetry-related scheduled tasks..."
$tasksToDisable = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Maintenance\WinSAT",
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
)
foreach ($taskName in $tasksToDisable) {
    try {
        $path  = Split-Path $taskName -Parent
        $tname = Split-Path $taskName -Leaf
        $task = Get-ScheduledTask -TaskPath ($path + "\") -TaskName $tname -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskPath ($path + "\") -TaskName $tname
            Write-Host " [DISABLED] Scheduled Task: $taskName"
        }
    } catch {
        Write-Warning "Could not disable task $taskName. $_"
    }
}


# ---------------------------------------------------------------------------
# 11. Browser Hardening (IE, Edge, Chrome)
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Applying browser hardening..."

# Internet Explorer
$iePolPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer"
if (!(Test-Path $iePolPath)) { New-Item -Path $iePolPath -Force | Out-Null }
$ieInfoPath = "$iePolPath\Infodelivery\Restrictions"
if (!(Test-Path $ieInfoPath)) { New-Item -Path $ieInfoPath -Force | Out-Null }
New-ItemProperty -Path $ieInfoPath -Name "FormSuggest Passwords" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $ieInfoPath -Name "FormSuggest PW Ask" -Value 0 -PropertyType DWORD -Force | Out-Null
$ieMainPath = "$iePolPath\Main"
if (!(Test-Path $ieMainPath)) { New-Item -Path $ieMainPath -Force | Out-Null }
New-ItemProperty -Path $ieMainPath -Name "DisableFirstRunCustomize" -Value 1 -PropertyType DWORD -Force | Out-Null

# Microsoft Edge (Chromium)
$edgePolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (!(Test-Path $edgePolPath)) { New-Item -Path $edgePolPath -Force | Out-Null }
New-ItemProperty -Path $edgePolPath -Name "SmartScreenEnabled" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $edgePolPath -Name "BlockPopups" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $edgePolPath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $edgePolPath -Name "BrowserSignin" -Value 0 -PropertyType DWORD -Force | Out-Null

# Google Chrome
$chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (!(Test-Path $chromePath)) { New-Item -Path $chromePath -Force | Out-Null }
New-ItemProperty -Path $chromePath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $chromePath -Name "SyncDisabled" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $chromePath -Name "SavingBrowserHistoryDisabled" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $chromePath -Name "DefaultBrowserSettingEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $chromePath -Name "SafeBrowsingProtectionLevel" -Value 1 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 12. USB Mass Storage Block
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Blocking USB mass storage devices..."
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
    Write-Host " [BLOCKED] USB mass storage devices."
} catch {
    Write-Warning "Could not disable USB mass storage driver. $_"
}


# ---------------------------------------------------------------------------
# 13. Software Restriction Policies
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] Configuring Software Restriction Policies (SRP)..."
$srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
if (!(Test-Path $srpKey)) { New-Item -Path $srpKey -Force | Out-Null }
New-ItemProperty -Path $srpKey -Name "PolicyScope" -Value 0 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $srpKey -Name "TransparentEnabled" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $srpKey -Name "DefaultLevel" -Value 0x00001000 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $srpKey -Name "AuthenticodeEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null

# Unrestricted paths for Windows and Program Files
New-Item -Path "$srpKey\0\Paths" -Force | Out-Null
New-Item -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000001}" -Force | Out-Null
New-ItemProperty -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000001}" -Name "Path" -Value "%WINDIR%\*" -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000001}" -Name "SaferFlags" -Value 0x00000000 -PropertyType DWORD -Force | Out-Null
New-Item -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000002}" -Force | Out-Null
New-ItemProperty -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000002}" -Name "Path" -Value "%ProgramFiles%\*" -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$srpKey\0\Paths\{00000000-0000-0000-0000-000000000002}" -Name "SaferFlags" -Value 0x00000000 -PropertyType DWORD -Force | Out-Null


# ---------------------------------------------------------------------------
# 14. BitLocker Drive Encryption
# ---------------------------------------------------------------------------
Write-Host "[HARDENING] (Optional) Enforcing BitLocker on system drive..."
try {
    $bitLockerStatus = (Get-BitLockerVolume -MountPoint "C:").EncryptionPercentage
    if ($bitLockerStatus -lt 100) {
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TpmProtector -UsedSpaceOnly
        Write-Host " [ENABLED] BitLocker on C: drive (AES256, TPM)."
    } else {
        Write-Host " [INFO] BitLocker is already fully enabled on C:."
    }
} catch {
    Write-Warning "Could not enable BitLocker. $_"
}


Write-Host "`n[COMPLETED] Workstation hardening finished. Some changes require a reboot."
