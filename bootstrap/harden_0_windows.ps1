# Windows hardening script to be run in the first minute of deployment.

if (Get-Command Set-PSReadlineOption -ErrorAction SilentlyContinue) {
    # Don't save history. This isn't supported in versions lower than Windows 7. This shouldn't
    # be necessary, but just in case.
    Set-PSReadlineOption -HistorySaveStyle SaveNothing
}

# The new password to set for all accounts (administrator and krbtgt)
# Note: Single and double quotes do not work for Windows passwords
$NEW_PASSWORD = ''

# The public key to add for SSH
$PUBKEY = ''

# Make sure we are running with elevated privileges
$user = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Error: Must run as Administrator"
    exit 1
}

if (-not $NEW_PASSWORD) {
    Write-Output "Error: Need to set NEW_PASSWORD"
    exit 1
}
if (-not $PUBKEY) {
    Write-Output "Error: Need to set PUBKEY"
    exit 1
}

# Check if the computer is a domain controller
try {
    $isDomainController = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2
} catch {
    # Fall back for Windows versions older than Windows 8
    $isDomainController = (Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 2
}

if ($isDomainController) {
    Write-Output "Computer $env:COMPUTERNAME is a domain controller"
} else {
    Write-Output "Computer $env:COMPUTERNAME is NOT a domain controller"
}

function RollPasswords {
    Write-Output "Rolling passwords"
    net user Administrator $NEW_PASSWORD

    if ($isDomainController) {
        # Set krbtgt password twice as the last two passwords work for the account. krbtgt
        # doesn't use the password you provide, but instead sets a random 128-bit password.
        net user krbtgt password
        net user krbtgt password

        # Add backup domain administrator
        net user domino $NEW_PASSWORD /add /Y
        net group "Domain Admins" domino /add
    }
}

function ApplyHardening {
    Write-Output "Applying hardening"

    # Disable SMBv1 to mitigate EternalBlue
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f | Out-Null

    # Require SMB signing
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null

    # Harden NTLM authentication
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f | Out-Null
    # Disable LM hash storage for passwords less than 15 characters
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
    # Disable plaintext cred storage in WDigest
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null

    # Enable LSA protection
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d 1 /f | Out-Null

    # Stop and disable the spooler service, mitigating PrintNightmare
    if (Get-Service -Name "Spooler" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Spooler" -Force
        Set-Service -Name "Spooler" -StartupType Disabled
    }

    # Mitigate Certified
    if (Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "CertSvc"
        Set-Service -Name "CertSvc" -StartupType Disabled
    }

    # Enable real-time monitoring for Defender. Better protection will be applied later
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null

    # Enable UAC
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null

    # Disable scheduled tasks for the current boot
    if (Get-Service -Name "Schedule" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Schedule" -Force
    }

    # Disable NetBIOS interfaces
    Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2
    }

    # Mitigate SMBGhost by disabling SMB compression
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f | Out-Null

    # Mitigate BlueKeep by enabling NLA
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null

    # Delete Run and RunOnce registry keys
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f 2>$null | Out-Null
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /f 2>$null | Out-Null
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f 2>$null | Out-Null
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /f 2>$null | Out-Null

    # Enable success and failure auditing for everything
    auditpol /set /category:* /failure:enable /success:enable

    net user Guest /active:no

    if ($isDomainController) {
        # Prevent Zerologon. Only works for DCs that have patches for Zerologon
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FullSecureChannelProtection" /t REG_DWORD /d 1 /f | Out-Null
        reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "VulnerableChannelAllowList" /f 2>$null | Out-Null

        # Mitigate SigRed
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f | Out-Null

        # Delays autopropogation by SDHolder which stops protected groups from being restored
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v AdminSDProtectFrequency /t REG_DWORD /d 7200 /f | Out-Null

        # Mitigate noPac. Users can still bypass if they have high privileges by using an existing computer account
        Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="0"}
        # Prevent noPac. Only works if the DC has patches for it
        reg add "HKLM\System\CurrentControlSet\Services\Kdc" /v PacRequestorEnforcement /t REG_DWORD /d 2 /f | Out-Null

        # Turn off dynamic updates for DNS zones
        Get-DnsServerZone |
            Where-Object {$_.ZoneType -like "Primary" -and -not $_.IsAutoCreated} |
            Select-Object -Property ZoneName,ZoneType |
            Set-DnsServerPrimaryZone -DynamicUpdate None -Notify Notify -SecureSecondaries TransferToZoneNameServer

        Get-DnsServerZone |
            Where-Object {$_.ZoneType -like "Primary" -and -not $_.IsAutoCreated} |
            Select-Object -Property ZoneName,ZoneType |
            Set-DnsServerPrimaryZone -DynamicUpdate None -Notify NoNotify -SecureSecondaries NoTransfer

        # Backup DNS zones
        $backupPath = "C:\DNSBackups"
        if (!(Test-Path -Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath
        }
        # Export each zone to a DNS zone file
        $zones = Get-DnsServerZone
        foreach ($zone in $zones) {
            # Export the zone to a file in the DNS folder (usually %SystemRoot%\System32\dns)
            try {
                Export-DnsServerZone -Name $zone.ZoneName -FileName "$($zone.ZoneName).dns"
                Copy-Item -Path "$env:SystemRoot\System32\dns\$($zone.ZoneName).dns" -Destination $backupPath -Force
                Write-Output "Exported zone '$($zone.ZoneName)' to $backupPath\$($zone.ZoneName).dns"
            } catch {
                Write-Output "Failed to export zone '$($zone.ZoneName)'"
            }
        }

        # Print so we know what DNS servers to allow from the DC at the firewall level
        $dnsServerForwarders = Get-DnsServerForwarder | Select-Object -ExpandProperty IPAddress
        Write-Output "DNS Server Forwarders: $dnsServerForwarders"
    }
}

function ProcessAuthorizedKeys {
    param (
        [Parameter(Mandatory = $true)]
        [string] $authorizedKeysPath
    )
    $backupPath = "$authorizedKeysPath.bak"

    if ((Test-Path $authorizedKeysPath) -and -not (Test-Path $backupPath)) {
        # Make a backup if it doesn't already exist
        Copy-Item -Path $authorizedKeysPath -Destination $backupPath -Force
    }

    # Overwrite the file
    Set-Content -Path $authorizedKeysPath -Value $PUBKEY -Force
}

function ConfigureSSH {
    try {
        Get-Service -Name sshd -ErrorAction Stop | Out-Null
    } catch {
        Write-Output "SSH is not installed, skipping SSH configuration"
        return
    }

    Write-Output "Configuring SSH"

    # Add pubkey to authorized_keys
    ProcessAuthorizedKeys -authorizedKeysPath $env:ProgramData\ssh\administrators_authorized_keys
    icacls.exe ""$env:ProgramData\ssh\administrators_authorized_keys"" /inheritance:r /grant ""Administrators:F"" /grant ""SYSTEM:F""

    # This technically does nothing since administrators_authorized_keys is used
    # but better safe than sorry
    New-Item -Force -ItemType Directory -Path $env:USERPROFILE\.ssh | Out-Null
    ProcessAuthorizedKeys -authorizedKeysPath $env:USERPROFILE\.ssh\authorized_keys

    $sshdConfig = "$env:ProgramData\ssh\sshd_config"
    $backupSshdConfig = "$sshdConfig.bak"
    Copy-Item -Path $sshdConfig -Destination $backupSshdConfig -Force

    # For some reason, multiline strings don't work so these are all separate calls
    Add-Content -Force -Path "$sshdConfig" -Value ""
    # Just in case the config ends with a match block.
    Add-Content -Force -Path "$sshdConfig" -Value "Math all"

    # Only disable password authentication for the administrator account. Other accounts could be used
    # for service checks.
    Add-Content -Force -Path "$sshdConfig" -Value "Match Group administrators"
    Add-Content -Force -Path "$sshdConfig" -Value "PasswordAuthentication no"
    Add-Content -Force -Path "$sshdConfig" -Value "Match all"

    # Disable DNS for sshd
    Add-Content -Force -Path "$sshdConfig" -Value "UseDNS no"

    # Ensure SSH config is valid. If not, restore old SSH config
    if ($sshd = Get-Command sshd -ErrorAction SilentlyContinue) {
        & $sshd.Source -t 2>&1
        if ($LASTEXITCODE -ne 0) {
            $brokenSshdConfig = "$sshdConfig.broken"
            Write-Output "Error: SSH configuration is invalid. Restoring original config. Old config is saved as $brokenSshdConfig"
            Copy-Item $sshdConfig $brokenSshdConfig -Force
            Move-Item $backupSshdConfig $sshdConfig -Force
            return
        }
    }

    Restart-Service -Name sshd
}

RollPasswords

# Before configuring, make sure our group policy is up to date as we will
# disable GPOs on the DC before running this
gpupdate /force

ApplyHardening
ConfigureSSH

# Self-delete
if (Test-Path $script:MyInvocation.MyCommand.Path) {
    Remove-Item $script:MyInvocation.MyCommand.Path -Force
}
