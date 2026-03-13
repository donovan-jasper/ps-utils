# Windows AD Security Toolkit

Defensive PowerShell toolkit for Windows Active Directory environments. Built for blue teams hardening infrastructure in **cybersecurity competitions (CCDC, etc.)** and authorized security exercises.

> **Important:** Several scripts in this toolkit use aggressive techniques (mass password rotation, DCSync, GPO wiping, service DACL lockdown, process killing) that are appropriate for **gamified competition environments** but **not for production networks**. Scripts are labeled below.

## Environment Labels

| Label | Meaning |
|-------|---------|
| **GENERAL** | Safe for production use with standard change management |
| **COMPETITION** | Designed for CTF/CCDC competition environments only. Aggressive, fast, may cause service disruption. Do not run in production. |

## Quick Start — First 5 Minutes (Competition)

1. **Run `Install-Dependencies.ps1`** to install required modules (DSInternals, RSAT tools)
2. **Run `bootstrap/harden_0_windows.ps1`** for immediate hardening (SMB, NTLM, Defender, UAC, auditing)
3. **Run `credentials/Roll-Passwords.ps1`** to rotate all domain passwords (preview before applying)
4. **Run `services/Snapshot-Services.ps1`** to baseline all services
5. **Start `monitoring/Watch-Logons.ps1`** in a separate window to catch unauthorized logins

## Repository Structure

All scripts auto-detect whether they're running on a Domain Controller or workstation and adapt behavior accordingly. Each script checks its own dependencies and exits with a clear message if something is missing.

### hardening/
Scripts that apply defensive configurations.

| Script | Env | Description |
|--------|-----|-------------|
| `Harden-DC.ps1` | **GENERAL** | AD hardening: SMB signing, NTLM restrictions, LSA protection, Zerologon/noPac/SigRed mitigations. `-AuditOnly` flag to preview. |
| `Harden-Workstation.ps1` | **GENERAL** | Workstation-specific hardening (firewall, services, local policies) |
| `Harden-SMB.ps1` | **GENERAL** | SMB-specific hardening (disable SMBv1, require signing) |
| `Lock-Filesystem.ps1` | **COMPETITION** | Strips ACLs from staging dirs and system binaries (`-LockBinaries`). Takes ownership of cmd.exe, powershell.exe, net.exe, sc.exe, etc. Can break legitimate tooling. |
| `Restore-Filesystem.ps1` | **GENERAL** | Restore filesystem ACLs from Lock-Filesystem snapshot |
| `Remove-GPOs.ps1` | **COMPETITION** | Nukes all GPO links domain-wide (domain root, all OUs, all sites). Backs up first with per-GPO restore scripts, but the blast radius is the entire domain. |

### credentials/
Password management and account auditing.

| Script | Env | Description |
|--------|-----|-------------|
| `Roll-Passwords.ps1` | **COMPETITION** | Mass-rotates all domain user passwords in one shot. Safe charset, preview + confirm, but bulk password rotation is a competition-speed tactic. |
| `Dump-Hashes.ps1` | **COMPETITION** | DCSync hash dump of all domain users. Intended for rollback capability but this is an offensive technique (replicating the AD database). |
| `Rollback-Users.ps1` | **COMPETITION** | Restore passwords from hash dump. Companion to Dump-Hashes. |
| `Password-Utils.ps1` | **GENERAL** | Shared helpers (file rotation, state loading) |
| `Account-Audit.ps1` | **COMPETITION** | Strips members from all sensitive AD groups (Domain Admins, Enterprise Admins, etc.), disables built-in accounts, creates backup admin accounts. Can run on a loop (`-Interval`). `-DryRun` available but default mode is destructive. |

### dns/
DNS backup and restore.

| Script | Env | Description |
|--------|-----|-------------|
| `Backup-DNS.ps1` | **GENERAL** | Three outputs: console table, CSV chart, JSON backup. `-DnsServer` for remote backup. |
| `Restore-DNS.ps1` | **GENERAL** | Restore from JSON backup. Skips existing records. `-WhatIf` support. |

### monitoring/
Real-time event monitoring with human-readable output. All translate Windows event codes to readable descriptions.

| Script | Env | Description |
|--------|-----|-------------|
| `Watch-Logons.ps1` | **GENERAL** | Authentication monitor. Translates logon types (Interactive, Network, RDP...) and failure codes (wrong password, locked out...). |
| `Watch-Events.ps1` | **GENERAL** | Broad security event monitor: process creation, service installs, privilege use, account changes, policy changes. Color-coded. |
| `Watch-LDAP.ps1` | **GENERAL** | LDAP dependency mapper (`-Map`) and alert mode (`-Alert`). Tracks who's binding to LDAP. DC only. |

### services/
Service integrity monitoring and protection.

| Script | Env | Description |
|--------|-----|-------------|
| `Snapshot-Services.ps1` | **GENERAL** | Baseline all services: SDDL, binary path, startup type, logon account. JSON + console. |
| `Lock-Services.ps1` | **COMPETITION** | Strips SYSTEM from every service DACL domain-wide. Only specified admin retains control. Blocks sc.exe abuse but also blocks legitimate SYSTEM-level service management. |
| `Watch-Services.ps1` | **GENERAL** | Continuous integrity monitor against baseline. Detects binary path, SDDL, startup type changes. `-AutoRevert`. |

### disruption/
Active defense scripts for adversary disruption.

> **These scripts are designed exclusively for competition/CTF active defense.** They will cause service disruption, kill processes, disable accounts, and interfere with normal operations. Do not use in production.

| Script | Env | Description |
|--------|-----|-------------|
| `Toggle-NIC.ps1` | **COMPETITION** | Randomly disables/enables network adapters to break persistent adversary connections. |
| `Reap-Sessions.ps1` | **COMPETITION** | Force-logoff of non-whitelisted sessions. Optionally disables reaped accounts. Runs continuously. |
| `Watch-Persistence.ps1` | **COMPETITION** | Detects new scheduled tasks, services, Run keys. `-AutoRemove` auto-deletes them. Alert-only mode is safe for general use. |
| `Guard-Ports.ps1` | **COMPETITION** | Port-knock gatekeeper. Blocks RDP/WinRM by default, opens temporarily on correct knock sequence. Breaks standard remote management. |
| `Watch-Processes.ps1` | **COMPETITION** | Baseline process monitor. `-AutoKill` forcibly terminates any process not in the initial snapshot. Alert-only mode is safe for general use. |
| `Deploy-Honeypots.ps1` | **GENERAL** | Deploy honey users, services, shares, and scheduled tasks as detection tripwires. `-Deploy`, `-Monitor`, `-Remove`. Pure detection, no disruption. |

### bootstrap/
Rapid deployment scripts for competition quick-starts.

| Script | Env | Description |
|--------|-----|-------------|
| `harden_0_windows.ps1` | **COMPETITION** | First-minute speed hardening. Hardcodes a backup domain admin, mass-rotates passwords via `net user`, wipes Run/RunOnce keys, stops Task Scheduler, self-deletes after execution. No confirmation prompts. |
| `geist.ps1` | **COMPETITION** | Bulk remote execution via PsExec with base64-encoded payloads. Passes credentials on the command line. Designed for rapid fleet-wide deployment in competition. |

### logging/
Logging and monitoring agent deployment.

| Script | Env | Description |
|--------|-----|-------------|
| `sysmon_wazuh.ps1` | **GENERAL** | Installs Wazuh Agent + Sysmon with event channel integration |
| Sysmon configs | **GENERAL** | Default, aggressive, and basic rule sets |

### reference/
Static reference documents.

| File | Description |
|------|-------------|
| `event-codes.md` | Windows event IDs, logon type codes, failure codes, color legend |
| `cheatsheet.md` | Quick reference commands |
| `services.md` | Service notes |

## Shared Infrastructure

### Common.ps1
Dot-sourced by every script. Provides:
- **`Get-MachineRole`**: Returns "DomainController", "MemberServer", or "Workstation"
- **`Assert-Dependencies`**: Checks for required modules/commands, exits with clear error
- **`Assert-Role`**: Exits early if machine role doesn't match requirement
- **`Write-Banner`**: Prints script name and detected role

### Install-Dependencies.ps1
One-shot installer for all required modules. Detects role and installs appropriately:
- DSInternals (hash operations)
- RSAT AD PowerShell (all AD scripts)
- RSAT DNS (DNS scripts, DC only)
- RSAT Group Policy (GPO scripts, DC only)

## Output Conventions

- **Monitoring scripts**: Color-coded console output with human-readable translations
- **CSV files**: Unquoted, comma-separated. Easy to import into other tools.
- **JSON files**: Machine-readable backups for restore scripts
- **All dangerous operations**: Require confirmation prompt or support `-WhatIf`/`-AuditOnly`/`-DryRun`

## Monitoring Color Legend

| Color | Meaning |
|-------|---------|
| Green | All clear / successful |
| Red | Critical alert / failed logon / service install |
| Yellow | Warning / new process / new service |
| Cyan | Informational / user creation |
| Magenta | Privilege escalation |
