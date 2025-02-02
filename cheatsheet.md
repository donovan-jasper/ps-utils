# Windows Administrative Tools Cheatsheet

---

## MMC Snap-ins

> **Note:** Run these tools with administrative privileges.

- **Server Manager**  
  - **Path:**  
    `C:\Windows\System32\servermanager.exe`  
  - **Description:** Primary console for managing server roles, features, and connected servers.

- **Active Directory Administrative Center**  
  - **Path:**  
    `C:\Windows\System32\dsac.exe`  
  - **Description:** A modern, task-oriented interface for managing Active Directory (AD) objects and configurations.

- **Active Directory Users and Computers**  
  - **Path:**  
    `C:\Windows\System32\dsa.msc`  
  - **Description:** Manage users, groups, computers, and organizational units within AD.

- **Active Directory Sites and Services**  
  - **Path:**  
    `C:\Windows\System32\dssite.msc`  
  - **Description:** Manage AD replication topology, sites, and subnets.

- **Group Policy Management Console (GPMC)**  
  - **Path:**  
    `C:\Windows\System32\gpmc.msc`  
  - **Description:** Create, edit, and manage Group Policy Objects (GPOs) for your domain and local computer.

- **DNS Manager**  
  - **Path:**  
    `C:\Windows\System32\dnsmgmt.msc`  
  - **Description:** Administer DNS zones, records, and server settings (available when the DNS role is installed).

- **DHCP Manager**  
  - **Path:**  
    `C:\Windows\System32\dhcpmgmt.msc`  
  - **Description:** Configure and manage DHCP scopes, leases, and reservations (requires the DHCP role).

- **Failover Cluster Manager**  
  - **Path:**  
    `C:\Windows\System32\cluadmin.msc`  
  - **Description:** Oversee and configure cluster resources and settings (available with the Failover Clustering role).

- **File Server Resource Manager (FSRM)**  
  - **Path:**  
    `C:\Windows\System32\fsrm.msc`  
  - **Description:** Monitor and control file server storage with quotas, file screening, and reporting.

- **Hyper-V Manager**  
  - **Path:**  
    `C:\Windows\System32\virtmgmt.msc`  
  - **Description:** Manage virtual machines, virtual switches, and Hyper-V host settings (if the Hyper-V role is installed).

- **Windows Defender Firewall with Advanced Security**  
  - **Path:**  
    `C:\Windows\System32\wf.msc`  
  - **Description:** Configure and monitor inbound/outbound firewall rules and security settings.

- **Performance Monitor**  
  - **Path:**  
    `C:\Windows\System32\perfmon.msc`  
  - **Description:** Monitor system performance, create data collector sets, and analyze performance counters.

- **Event Viewer**  
  - **Path:**  
    `C:\Windows\System32\eventvwr.msc`  
  - **Description:** View logs (Application, System, Security, etc.) for troubleshooting and auditing.

- **Services**  
  - **Path:**  
    `C:\Windows\System32\services.msc`  
  - **Description:** Start, stop, and configure Windows services and view their dependencies.

- **Task Scheduler**  
  - **Path:**  
    `C:\Windows\System32\taskschd.msc`  
  - **Description:** Create, manage, and troubleshoot scheduled tasks.

- **Computer Management**  
  - **Path:**  
    `C:\Windows\System32\compmgmt.msc`  
  - **Description:** A unified console providing access to several tools (e.g., Device Manager, Disk Management, Event Viewer).

- **Certificates (Current User)**  
  - **Path:**  
    `C:\Windows\System32\certmgr.msc`  
  - **Description:** Manage certificates for the current user.  
  - **Note:** To manage Local Computer certificates, open MMC, choose **File → Add/Remove Snap-in**, and select **Certificates** for the computer account.

---

## Standalone Executable Tools

- **Registry Editor**  
  - **Path:**  
    `C:\Windows\System32\regedit.exe`  
  - **Description:** Edit the system registry.

- **Control Panel**  
  - **Path:**  
    `C:\Windows\System32\control.exe`  
  - **Description:** Launch the classic Control Panel or individual CPL applets.

- **Windows PowerShell**  
  - **Path:**  
    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  
  - **Description:** A powerful command-line shell and scripting environment.

- **System Information**  
  - **Path:**  
    `C:\Windows\System32\msinfo32.exe`  
  - **Description:** Displays detailed system information including hardware resources and configuration.

- **Event Create**  
  - **Path:**  
    `C:\Windows\System32\eventcreate.exe`  
  - **Description:** Create custom events in the event log.

- **Sconfig** *(For Server Core installations)*  
  - **Path:**  
    `C:\Windows\System32\sconfig.cmd`  
  - **Description:** A command-line tool for configuring core server settings (useful on Server Core installations).

---
