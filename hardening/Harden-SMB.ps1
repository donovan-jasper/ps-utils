<#
.SYNOPSIS
    SMB hardening script for initial hardening.

.DESCRIPTION
    Applies critical SMB hardening that requires an SMB service restart:
        - Disable SMBv1 (EternalBlue mitigation, optional via -KeepSMB)
        - Require SMB signing
        - Disable anonymous/null session logins
        - Disable SMB compression (SMBGhost mitigation)
        - Restart LanmanServer to apply changes

    Run this separately from the main hardening script because the SMB restart
    will terminate remote management connections (e.g., Geist). Use --no-output
    flag when running remotely to avoid waiting for unretrievable output.

.PARAMETER KeepSMB
    When specified, preserves SMBv1 instead of disabling it.
    Some legacy services depend on SMBv1.

.NOTES
    Run as Administrator. The SMB service restart will disconnect active SMB sessions.
#>

[CmdletBinding()]
Param(
    [switch]$KeepSMB
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Harden-SMB"

$lanmanParams = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$lsaPath      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Disable SMBv1 unless -KeepSMB is specified
if (-not $KeepSMB) {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f | Out-Null
    Write-Host "[SMB] Disabled SMBv1 (EternalBlue mitigation)."
} else {
    Write-Host "[SMB] Keeping SMBv1 enabled (-KeepSMB specified)."
}

# Require SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[SMB] Required SMB signing on server."

# Disable anonymous/null session logins
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[SMB] Disabled anonymous and null session logins."

# Disable SMB compression (SMBGhost / CVE-2020-0796 mitigation)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[SMB] Disabled SMB compression (SMBGhost mitigation)."

# Restart LanmanServer to apply changes
Write-Host "[SMB] Restarting LanmanServer service to apply changes..."
Restart-Service -Name LanmanServer -Force

Write-Host "[SMB] Hardening complete. Active SMB sessions were reset."

# Self-delete
if (Test-Path -Path $script:MyInvocation.MyCommand.Path) {
    Remove-Item $script:MyInvocation.MyCommand.Path -Force
}
