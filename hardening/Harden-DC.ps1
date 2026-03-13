<#
.SYNOPSIS
    Comprehensive Domain Controller hardening script (Audit or Enforce).

.DESCRIPTION
    Merged from ad.ps1 and dc.ps1. Covers:
        - DNSAdmins abuse mitigation
        - AdminSDHolder ACL backdoor removal
        - AD CS template lockdown (ESC1+)
        - Golden/Silver Ticket mitigation (KRBTGT rotation check, Protected Users)
        - LSASS protection (RunAsPPL, WDigest disable)
        - Delegation abuse (unconstrained, RBCD, sensitive accounts)
        - SIDHistory detection and trust SID filtering
        - GPP cpassword removal
        - SMB signing, LDAP signing, NTLM restrictions
        - LLMNR disable
        - DCShadow / DCSync ACL audit
        - Zerologon (Netlogon enforcement)
        - Print Spooler disable on DC
        - MachineAccountQuota = 0
        - AS-REP Roasting fix
        - LAPS schema and KDS root key checks

.PARAMETER AuditOnly
    When specified, reports what would change without making modifications.

.NOTES
    Run as Domain Admin on a Domain Controller.
    Always test in a lab first. Some changes require reboot or AD replication.
#>

[CmdletBinding()]
Param(
    [switch]$AuditOnly
)

. "$PSScriptRoot\..\Common.ps1"
Write-Banner -ScriptName "Harden-DC"
Assert-Role -Required DomainController
Assert-Dependencies -Modules @("ActiveDirectory")

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Helper function for logging
Function Log($msg) {
    if ($AuditOnly) {
        Write-Host "[AUDIT] $msg"
    } else {
        Write-Host "$msg"
    }
}

$ntdsService = Get-Service 'NTDS' -ErrorAction SilentlyContinue
$isDC = $ntdsService -ne $null

# ---------------------------------------------------------------------------
# 1. DNSAdmins Group Hardening
# ---------------------------------------------------------------------------
if ($isDC -or (Get-Service 'DNS' -ErrorAction SilentlyContinue)) {
    Try {
        $dnsAdminsMembers = Get-ADGroupMember -Identity "DNSAdmins" -ErrorAction Stop
    } Catch { $dnsAdminsMembers = @() }
    if ($dnsAdminsMembers.Count -gt 0) {
        foreach ($member in $dnsAdminsMembers) {
            if ($AuditOnly) {
                Log "User '$($member.SamAccountName)' is in DNSAdmins - recommended to remove non-Admin accounts."
            } else {
                Remove-ADGroupMember -Identity "DNSAdmins" -Members $member -Confirm:$false -ErrorAction SilentlyContinue
                Log "Removed '$($member.SamAccountName)' from DNSAdmins group (DNS abuse mitigation)."
            }
        }
    } else {
        Log "DNSAdmins group has no members (secure)."
    }
}

# ---------------------------------------------------------------------------
# 2. AdminSDHolder ACL Hardening
# ---------------------------------------------------------------------------
if ($isDC) {
    $domainDN = (Get-ADDomain).DistinguishedName
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    Try {
        $sdHolderACL = Get-ACL "AD:$adminSDHolderDN"
    } Catch {
        $sdHolderACL = $null
        Log "Could not retrieve AdminSDHolder ACL: $($_.Exception.Message)"
    }
    if ($sdHolderACL) {
        $domNetBIOS = (Get-ADDomain).NetBIOSName
        $safePrincipals = @(
            "$domNetBIOS\Domain Admins",
            "$domNetBIOS\Enterprise Admins",
            "$domNetBIOS\Administrators",
            "NT AUTHORITY\SYSTEM"
        )
        $removeACEs = @()
        foreach ($ace in $sdHolderACL.Access) {
            $trustee = $ace.IdentityReference
            $rights = $ace.ActiveDirectoryRights
            $highRights = @("WriteOwner","WriteDacl","GenericAll","GenericWrite","WriteProperty","ExtendedRight")
            $hasHighRight = $highRights | Where-Object { $rights.ToString().Contains($_) }
            if ($hasHighRight -and ($safePrincipals -notcontains $trustee.Value)) {
                $removeACEs += $ace
                if ($AuditOnly) {
                    Log "AdminSDHolder ACL: Unprivileged '$trustee' has high rights [$rights]."
                }
            }
        }
        if (-not $AuditOnly -and $removeACEs.Count -gt 0) {
            foreach ($ace in $removeACEs) {
                [void]$sdHolderACL.RemoveAccessRule($ace)
            }
            Try {
                Set-ACL -Path "AD:$adminSDHolderDN" -AclObject $sdHolderACL
                Log "Removed $($removeACEs.Count) unauthorized ACE(s) from AdminSDHolder."
            } Catch {
                Log "Failed to update AdminSDHolder ACL: $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 3. AD CS Hardening (Templates)
# ---------------------------------------------------------------------------
if (Get-Service 'CertSvc' -ErrorAction SilentlyContinue) {
    $configDN = (Get-ADRootDSE).ConfigurationNamingContext
    $tplSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    $templates = Get-ADObject -Filter 'ObjectClass -eq "pKICertificateTemplate"' -SearchBase $tplSearchBase -Properties displayName, msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag
    foreach ($tpl in $templates) {
        $tplACL = Get-ACL -Path ("AD:" + $tpl.DistinguishedName)
        $hasLowPrivEnroll = $false
        foreach ($ace in $tplACL.Access) {
            if ($ace.AccessControlType -eq 'Allow' -and ($ace.IdentityReference -match 'Authenticated Users$' -or $ace.IdentityReference -match 'Domain Users$')) {
                $hasLowPrivEnroll = $true
                break
            }
        }
        $nameFlags   = $tpl.'msPKI-Certificate-Name-Flag'
        $enrollFlags = $tpl.'msPKI-Enrollment-Flag'
        $subjectIsSupplied = ($nameFlags -band 0x1) -ne 0
        $requiresApproval  = ($enrollFlags -band 0x2) -ne 0
        if ($hasLowPrivEnroll -and $subjectIsSupplied -and -not $requiresApproval) {
            if ($AuditOnly) {
                Log "Cert Template '$($tpl.DisplayName)' = subject supply + no approval + low-priv enroll => VULNERABLE."
            } else {
                foreach ($ace in $tplACL.Access) {
                    if ($ace.IdentityReference -match 'Authenticated Users$' -or $ace.IdentityReference -match 'Domain Users$') {
                        [void]$tplACL.RemoveAccessRule($ace)
                    }
                }
                Set-ACL -Path ("AD:" + $tpl.DistinguishedName) -AclObject $tplACL
                $newEnrollFlags = $enrollFlags -bor 0x2
                $null = Set-ADObject -Identity $tpl -Replace @{ 'msPKI-Enrollment-Flag' = $newEnrollFlags }
                $newNameFlags = $nameFlags -band 0xFFFFFFFE
                $null = Set-ADObject -Identity $tpl -Replace @{ 'msPKI-Certificate-Name-Flag' = $newNameFlags }
                Log "Hardened template '$($tpl.DisplayName)': removed low-priv enroll, required CA approval, disabled subject supply."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Golden/Silver Ticket Mitigations (Protected Users, KRBTGT, SPN accounts)
# ---------------------------------------------------------------------------
if ($isDC) {
    $tier0Groups = @("Domain Admins","Enterprise Admins")
    $protUsersGroup = "Protected Users"
    $protMembers = @()
    Try {
        $protMembers = Get-ADGroupMember $protUsersGroup -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    } Catch {}
    foreach ($group in $tier0Groups) {
        Try {
            $members = Get-ADGroupMember $group -ErrorAction Stop
        } Catch { $members = @() }
        foreach ($m in $members) {
            if ($m.ObjectClass -eq 'user') {
                if ($AuditOnly) {
                    if ($protMembers -notcontains $m.SamAccountName) {
                        Log "Privileged user '$($m.SamAccountName)' not in Protected Users => consider adding."
                    }
                } else {
                    Add-ADGroupMember -Identity $protUsersGroup -Members $m -ErrorAction SilentlyContinue
                }
            }
        }
    }
    if (-not $AuditOnly) {
        Log "Ensured Domain/Enterprise Admins are in Protected Users group."
    }

    # KRBTGT password age
    Try {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
    } Catch { $krbtgt = $null }
    if ($krbtgt) {
        $pwdAgeDays = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
        if ($pwdAgeDays -ge 180) {
            Log "KRBTGT password age is $pwdAgeDays days => recommend rotating krbtgt to invalidate old tickets."
        }
    }

    # Service accounts with SPN => check password age
    $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -ne $null } -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires
    foreach ($acct in $serviceAccounts) {
        $oldPwd = ($acct.PasswordLastSet -lt (Get-Date).AddDays(-365))
        if ($acct.PasswordNeverExpires -or $oldPwd) {
            Log "Service account '$($acct.SamAccountName)' has SPN & old/never-expiring password => rotate or use gMSA."
        }
    }
}

# ---------------------------------------------------------------------------
# 5. LSASS Process Protection
# ---------------------------------------------------------------------------
$lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPPL = 0
Try {
    $runAsPPL = (Get-ItemProperty -Path $lsaKey -Name "RunAsPPL" -ErrorAction Stop).RunAsPPL
} Catch {}
if ($AuditOnly) {
    if ($runAsPPL -ne 1) {
        Log "LSASS (RunAsPPL) not enabled => recommended to set 'RunAsPPL=1'."
    }
} else {
    if ($runAsPPL -ne 1) {
        New-ItemProperty -Path $lsaKey -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force | Out-Null
        Log "Enabled LSASS protected process (RunAsPPL=1)."
    }
}

# Disable WDigest
$wdKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
Try {
    $wdVal = Get-ItemProperty -Path $wdKey -Name "UseLogonCredential" -ErrorAction Stop
} Catch { $wdVal = $null }
if ($AuditOnly) {
    if ($wdVal -and $wdVal.UseLogonCredential -ne 0) {
        Log "WDigest caching is enabled => recommended to disable (UseLogonCredential=0)."
    }
} else {
    if (-not $wdVal) {
        New-Item -Path $wdKey -Force | Out-Null
        New-ItemProperty -Path $wdKey -Name "UseLogonCredential" -Value 0 -PropertyType DWORD -Force | Out-Null
        Log "Disabled WDigest plaintext credential caching."
    } elseif ($wdVal.UseLogonCredential -ne 0) {
        Set-ItemProperty -Path $wdKey -Name "UseLogonCredential" -Value 0
        Log "Disabled WDigest plaintext credential caching (UseLogonCredential=0)."
    }
}

# ---------------------------------------------------------------------------
# 6. Delegation Abuse Mitigations
# ---------------------------------------------------------------------------
$delegationFilter = 'UserAccountControl -band 524288 -or UserAccountControl -band 16777216'
Try {
    $delegatedObjs = Get-ADObject -Filter $delegationFilter -Properties SamAccountName, UserAccountControl, ObjectClass
} Catch {
    $delegatedObjs = @()
}
foreach ($obj in $delegatedObjs) {
    $name = $obj.SamAccountName
    $isComputer = ($obj.ObjectClass -eq 'computer')
    if ($isComputer -and ($name -match '\$$')) {
        if ($isDC) {
            continue
        }
    }
    if ($AuditOnly) {
        Log "Account '$name' has Unconstrained Delegation => recommended removal."
    } else {
        Set-ADAccountControl -Identity $obj -TrustedForDelegation:$false -TrustedToAuthForDelegation:$false -ErrorAction SilentlyContinue
        Log "Removed Unconstrained Delegation from '$name'."
    }
}

# Resource-Based Constrained Delegation
Try {
    $rbcdObjs = Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, SamAccountName
} Catch { $rbcdObjs = @() }
foreach ($obj in $rbcdObjs) {
    $target = $obj.SamAccountName
    if ($AuditOnly) {
        Log "Account '$target' has RBCD set => verify necessity."
    } else {
        Set-ADObject -Identity $obj -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -ErrorAction SilentlyContinue
        Log "Cleared RBCD on '$target'."
    }
}

# Mark privileged accounts as sensitive (not delegable)
if ($isDC) {
    foreach ($grp in @("Domain Admins","Enterprise Admins","Schema Admins")) {
        Try {
            $grpMembers = Get-ADGroupMember $grp -ErrorAction Stop
        } Catch { $grpMembers = @() }
        foreach ($m in $grpMembers) {
            if ($m.ObjectClass -eq 'user') {
                $user = Get-ADUser $m -Properties UserAccountControl
                $flag = $user.UserAccountControl
                $notDelegatedFlag = 0x100000
                $isSensitive = (($flag -band $notDelegatedFlag) -ne 0)
                if (-not $isSensitive) {
                    if ($AuditOnly) {
                        Log "Privileged user '$($user.SamAccountName)' not marked 'AccountNotDelegated'."
                    } else {
                        Set-ADUser -Identity $user -CannotBeDelegated $true
                        Log "Set 'Sensitive, cannot be delegated' on '$($user.SamAccountName)'."
                    }
                }
            }
        }
    }
}

# MachineAccountQuota = 0
if ($isDC) {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $currentMAQ = $domain."ms-DS-MachineAccountQuota"
        if ($AuditOnly) {
            if ($currentMAQ -gt 0) {
                Log "MachineAccountQuota=$currentMAQ => recommended to set 0 to block rogue machine creation."
            }
        } else {
            if ($currentMAQ -gt 0) {
                Set-ADDomain -Identity $domain.DNSRoot -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }
                Log "Set MachineAccountQuota from $currentMAQ to 0."
            }
        }
    } catch {
        Log "Could not read or set MachineAccountQuota: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 7. SIDHistory Abuse Mitigations
# ---------------------------------------------------------------------------
if ($isDC) {
    Try {
        $sidHistoryUsers = Get-ADUser -Filter { SIDHistory -ne $null } -Properties SIDHistory, SamAccountName
    } Catch { $sidHistoryUsers = @() }
    foreach ($u in $sidHistoryUsers) {
        if ($AuditOnly) {
            Log "User '$($u.SamAccountName)' has SIDHistory => potential abuse if old domain SIDs are present."
        } else {
            Log "SIDHistory found for '$($u.SamAccountName)'. Consider removing after verifying no legit migration need."
        }
    }

    # Enforce SID filtering on external trusts (fixed: use Get-ADTrust -Filter *)
    Try {
        $trusts = Get-ADTrust -Filter *
    } Catch { $trusts = @() }
    foreach ($trst in $trusts) {
        if ($trst.SIDFilteringQuarantined -eq $false) {
            if ($AuditOnly) {
                Log "Trust '$($trst.Name)' does NOT have SID filtering => recommended to enable it."
            } else {
                Set-ADTrust -Identity $trst.Name -EnableSIDHistory $false -Confirm:$false
                Log "Enabled SID filtering on trust '$($trst.Name)'."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 8. GPP Password cpassword
# ---------------------------------------------------------------------------
if ($isDC) {
    $sysvolPath = "$env:systemroot\SYSVOL\domain\Policies"
    if (Test-Path $sysvolPath) {
        $cpasswordFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include '*.xml' -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword'
        if ($cpasswordFiles) {
            foreach ($match in $cpasswordFiles) {
                $filePath = $match.Path
                if ($AuditOnly) {
                    Log "GPP file '$filePath' has cpassword => remove or rename to mitigate credential leak."
                } else {
                    Try {
                        Rename-Item -Path $filePath -NewName ($filePath + ".bak") -ErrorAction Stop
                        Log "Renamed GPP password file '$filePath' => '$($filePath).bak'."
                    } Catch {
                        Log "Failed to rename '$filePath': $($_.Exception.Message)"
                    }
                }
            }
        } else {
            Log "No GPP cpassword found in SYSVOL."
        }
    }
}

# ---------------------------------------------------------------------------
# 9. SMB & NTLM Relay Mitigations
# ---------------------------------------------------------------------------
Try {
    $smbSrvCfg = Get-SmbServerConfiguration
} Catch { $smbSrvCfg = $null }
if ($smbSrvCfg) {
    if ($AuditOnly) {
        if (-not $smbSrvCfg.EnableSecuritySignature) {
            Log "SMB server signing not enabled => set Enable/RequireSecuritySignature=1."
        }
        if (-not $smbSrvCfg.RequireSecuritySignature) {
            Log "SMB server signing not required => set RequireSecuritySignature=1."
        }
        if ($smbSrvCfg.EnableSMB1Protocol) {
            Log "SMBv1 on server side is enabled => recommended to disable."
        }
    } else {
        if (-not $smbSrvCfg.EnableSecuritySignature -or -not $smbSrvCfg.RequireSecuritySignature) {
            Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force | Out-Null
            Log "Enabled & required SMB signing on server."
        }
        if ($smbSrvCfg.EnableSMB1Protocol) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
            Log "Disabled SMBv1 on the server side."
        }
    }
}
Try {
    $smbClientCfg = Get-SmbClientConfiguration
} Catch { $smbClientCfg = $null }
if ($smbClientCfg) {
    if ($AuditOnly) {
        if ($smbClientCfg.EnableSMB1Protocol) {
            Log "SMBv1 on client side is enabled => recommended to disable."
        }
    } else {
        if ($smbClientCfg.EnableSMB1Protocol) {
            Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force | Out-Null
            Log "Disabled SMBv1 on the client side."
        }
    }
}

# LDAP signing & channel binding on DC
if ($isDC) {
    $ntdsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    Try {
        $ldapSign = Get-ItemProperty -Path $ntdsParams -Name "LDAPServerIntegrity" -ErrorAction Stop
    } Catch { $ldapSign = $null }
    Try {
        $ldapCB = Get-ItemProperty -Path $ntdsParams -Name "LdapEnforceChannelBinding" -ErrorAction Stop
    } Catch { $ldapCB = $null }
    if ($AuditOnly) {
        if (-not $ldapSign -or $ldapSign.LDAPServerIntegrity -lt 2) {
            Log "LDAP signing not required => set LDAPServerIntegrity=2 to prevent MITM."
        }
        if (-not $ldapCB -or $ldapCB.LdapEnforceChannelBinding -lt 1) {
            Log "LDAP channel binding not enforced => set LdapEnforceChannelBinding=1 or 2."
        }
    } else {
        if (-not $ldapSign -or $ldapSign.LDAPServerIntegrity -lt 2) {
            Set-ItemProperty -Path $ntdsParams -Name "LDAPServerIntegrity" -Value 2 -Force
            Log "Set LDAPServerIntegrity=2 (Require LDAP signing)."
        }
        if (-not $ldapCB -or $ldapCB.LdapEnforceChannelBinding -lt 1) {
            Set-ItemProperty -Path $ntdsParams -Name "LdapEnforceChannelBinding" -Value 1 -Force
            Log "Set LdapEnforceChannelBinding=1 (Strict channel binding)."
        }
    }
}

# Restrict outgoing NTLM
$msvKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Try {
    $ntlmSetting = Get-ItemProperty -Path $msvKey -Name "RestrictSendingNTLMTraffic" -ErrorAction Stop
} Catch { $ntlmSetting = $null }
if ($AuditOnly) {
    if (-not $ntlmSetting -or $ntlmSetting.RestrictSendingNTLMTraffic -ne 2) {
        Log "Outgoing NTLM is allowed => set RestrictSendingNTLMTraffic=2 to block."
    }
} else {
    if (-not $ntlmSetting -or $ntlmSetting.RestrictSendingNTLMTraffic -ne 2) {
        New-ItemProperty -Path $msvKey -Name "RestrictSendingNTLMTraffic" -Value 2 -PropertyType DWORD -Force | Out-Null
        Log "Set RestrictSendingNTLMTraffic=2 (no outgoing NTLM)."
    }
}

# Disable NTLMv1 (LmCompatibilityLevel=5)
$lmCompat = 0
Try {
    $lmCompat = (Get-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -ErrorAction Stop).LmCompatibilityLevel
} Catch {}
if ($AuditOnly) {
    if ($lmCompat -lt 5) {
        Log "LmCompatibilityLevel=$lmCompat => recommended to set 5 (NTLMv2 only)."
    }
} else {
    if ($lmCompat -lt 5) {
        New-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWORD -Force | Out-Null
        Log "Set LmCompatibilityLevel=5 (NTLMv2 only)."
    }
}

# ---------------------------------------------------------------------------
# 10. Disable LLMNR (absorbed from ad.ps1)
# ---------------------------------------------------------------------------
$dnsClientKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
Try {
    $llmnrVal = (Get-ItemProperty -Path $dnsClientKey -Name "EnableMulticast" -ErrorAction Stop).EnableMulticast
} Catch { $llmnrVal = $null }
if ($AuditOnly) {
    if ($llmnrVal -ne 0) {
        Log "LLMNR is not disabled => set EnableMulticast=0 to reduce name-resolution attack surface."
    }
} else {
    New-Item -Path $dnsClientKey -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $dnsClientKey -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force | Out-Null
    Log "Disabled LLMNR (EnableMulticast=0)."
}

# ---------------------------------------------------------------------------
# 11. DCShadow / DCSync ACL Audit
# ---------------------------------------------------------------------------
if ($isDC) {
    $domainDN = (Get-ADDomain).DistinguishedName
    $domainACL = Get-ACL "AD:$domainDN"
    $guidGetChanges      = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $guidGetChangesAll   = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    $guidGetChangesFilt  = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
    $guidGetChangesOther = "89e95b76-444d-4c62-991a-0facbeda640c"
    $repGuidSet = @($guidGetChanges,$guidGetChangesAll,$guidGetChangesFilt,$guidGetChangesOther)
    $safeReplSIDs = @(
        (Get-ADGroup "Domain Controllers").SID,
        (Get-ADGroup "Enterprise Domain Controllers").SID,
        (Get-ADGroup "Administrators").SID,
        (Get-ADGroup "Domain Admins").SID,
        (Get-ADGroup "Enterprise Admins").SID
    )
    $removed = 0
    foreach ($ace in $domainACL.Access) {
        if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
            $objType = $ace.ObjectType.ToString()
            if ($repGuidSet -contains $objType) {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                if ($safeReplSIDs -notcontains $sid) {
                    if ($AuditOnly) {
                        Log "Account '$($ace.IdentityReference)' has replication rights => recommended remove to prevent DCSync/DCShadow."
                    } else {
                        $null = $domainACL.RemoveAccessRule($ace)
                        $removed++
                    }
                }
            }
        }
    }
    if (!$AuditOnly -and $removed -gt 0) {
        Set-ACL -Path "AD:$domainDN" -AclObject $domainACL
        Log "Removed $removed unauthorized replication ACE(s) from domain ACL."
    }
}

# ---------------------------------------------------------------------------
# 12. Netlogon (Zerologon) Hardening
# ---------------------------------------------------------------------------
if ($isDC) {
    $netlogonKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    Try {
        $fullSecure = Get-ItemProperty -Path $netlogonKey -Name "FullSecureChannelProtection" -ErrorAction Stop
    } Catch { $fullSecure = $null }
    if ($AuditOnly) {
        if (-not $fullSecure -or $fullSecure.FullSecureChannelProtection -ne 1) {
            Log "FullSecureChannelProtection not enabled => set to 1 for Zerologon fix."
        }
    } else {
        if (-not $fullSecure -or $fullSecure.FullSecureChannelProtection -ne 1) {
            New-ItemProperty -Path $netlogonKey -Name "FullSecureChannelProtection" -Value 1 -PropertyType DWORD -Force | Out-Null
            Log "Enabled Netlogon FullSecureChannelProtection=1 (Zerologon fix)."
        }
    }
}

# ---------------------------------------------------------------------------
# 13. Disable Print Spooler on DC
# ---------------------------------------------------------------------------
if ($isDC) {
    $spoolerSvc = Get-Service "Spooler" -ErrorAction SilentlyContinue
    if ($spoolerSvc) {
        if ($AuditOnly) {
            if ($spoolerSvc.Status -ne 'Stopped' -or $spoolerSvc.StartType -ne 'Disabled') {
                Log "Print Spooler on DC is running => recommended to disable to mitigate PrintNightmare."
            }
        } else {
            Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            Log "Disabled Print Spooler service on DC."
        }
    }
}

# ---------------------------------------------------------------------------
# 14. AS-REP Roasting (remove DONT_REQ_PREAUTH flag)
# ---------------------------------------------------------------------------
if ($isDC) {
    try {
        $noPreAuthUsers = Get-ADUser -Filter "UserAccountControl -band 4194304" -Properties UserAccountControl
        foreach ($u in $noPreAuthUsers) {
            $sam = $u.SamAccountName
            if ($AuditOnly) {
                Log "User '$sam' has 'Do not require Kerberos preauth' => vulnerable to AS-REP roast."
            } else {
                $newUAC = $u.UserAccountControl -band (-1 -bxor 4194304)
                Set-ADUser $u -Replace @{UserAccountControl=$newUAC}
                Log "Removed 'DoNotRequirePreauth' from user '$sam'."
            }
        }
    } catch {
        Log "Error enumerating no-preauth users: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 15. LAPS & KDS Root Key Checks (absorbed from ad.ps1)
# ---------------------------------------------------------------------------
if ($isDC) {
    $domainDN = (Get-ADDomain).DistinguishedName

    # Check LAPS schema attribute
    Log "Checking if LAPS schema attributes exist (ms-MCS-AdmPwd)..."
    try {
        $lapsObj = Get-ADObject -Filter "name='ms-MCS-AdmPwd'" -SearchBase "CN=Schema,CN=Configuration,$domainDN" -ErrorAction Stop
        if ($lapsObj) {
            Log "LAPS schema attribute found. Ensure GPO is configured for LAPS deployment on all machines."
        }
    } catch {
        Log "LAPS attribute not found or error reading schema: $($_.Exception.Message)"
        Log "Install LAPS if not installed, and update schema to store local admin passwords securely."
    }

    # Check KDS Root Key for gMSAs
    Log "Checking for KDS Root Key needed for gMSAs..."
    $kdsKey = Get-ADObject -Filter { name -like 'KDS*' } -SearchBase "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$domainDN" -ErrorAction SilentlyContinue
    if (!$kdsKey) {
        if ($AuditOnly) {
            Log "KDS Root Key not found => required for gMSA support. Create with Add-KdsRootKey."
        } else {
            Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
            Log "KDS Root Key created. Wait for AD replication before using gMSAs."
        }
    } else {
        Log "KDS Root Key already exists. gMSAs can be created/used."
    }
}

# ---------------------------------------------------------------------------
# 16. AD ACL Hardening (Domain Admins group check, from ad.ps1)
# ---------------------------------------------------------------------------
if ($isDC) {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $daDistName = "CN=Domain Admins,CN=Users,$domainDN"
        $daACL = Get-ACL -Path ("AD:" + $daDistName)
        $badACEs = $daACL.Access | Where-Object {
            ($_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite") `
            -and ($_.IdentityReference -notmatch "^(BUILTIN\\Administrators|.*Domain\\(Domain|Enterprise)Admins)")
        }
        if ($badACEs) {
            Log "WARNING: Found potential non-admin ACE(s) on Domain Admins group:"
            $badACEs | Format-Table IdentityReference, ActiveDirectoryRights, IsInherited
            Log "Consider removing or tightening these ACEs with DSACLS or ADAC."
        } else {
            Log "Domain Admins group ACL looks normal (no unexpected write perms)."
        }
    } catch {
        Log "Could not check Domain Admins ACL: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 17. Insecure Credential Storage (Scheduled Tasks)
# ---------------------------------------------------------------------------
Log "Checking for DisableDomainCreds setting..."
$disableDomCreds = 0
Try {
    $disableDomCreds = (Get-ItemProperty -Path $lsaKey -Name "DisableDomainCreds" -ErrorAction Stop).DisableDomainCreds
} Catch {}
if ($AuditOnly) {
    if ($disableDomCreds -ne 1) {
        Log "DisableDomainCreds not set => recommended to set 1 to prevent network credential storage."
    }
} else {
    if ($disableDomCreds -ne 1) {
        New-ItemProperty -Path $lsaKey -Name "DisableDomainCreds" -Value 1 -PropertyType DWORD -Force | Out-Null
        Log "Set DisableDomainCreds=1. Reboot may be required."
    }
}

Import-Module ScheduledTasks -ErrorAction SilentlyContinue
$tasksWithCreds = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.LogonType -eq 'Password' }
if ($tasksWithCreds) {
    Log "WARNING: These scheduled tasks store credentials locally (risky):"
    $tasksWithCreds | Format-Table TaskName, @{Label="RunAsUser"; Expression={$_.Principal.UserId}}
    Log "Reconfigure them to run as SYSTEM or a gMSA if possible."
} else {
    Log "No scheduled tasks found with stored credentials."
}

Write-Host "`n=== Harden-DC COMPLETED. Mode: $(if($AuditOnly){'AUDIT-ONLY'} else {'ENFORCEMENT'}) ==="
