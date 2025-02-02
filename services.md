# Windows DC Key Services: Names & Dependencies Cheatsheet


---

## 1. Remote Procedure Call (RPC)
- **Display Name:** Remote Procedure Call (RPC)
- **Service Name:** `RpcSs`
- **Description:** Provides the core communication framework for Windows services. Nearly every service depends on RPC.
- **Dependencies:**  
  - *None* (it is a core system service)

---

## 2. Windows Time
- **Display Name:** Windows Time
- **Service Name:** `W32Time`
- **Description:** Synchronizes the system clock with domain controllers or external time sources.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Netlogon** (in a domain environment)

---

## 3. Netlogon
- **Display Name:** Netlogon
- **Service Name:** `Netlogon`
- **Description:** Facilitates secure authentication and the location of domain controllers for domain-joined computers.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **DNS** (for locating domain controllers)  
  - **Active Directory Domain Services (AD DS)** (on domain controllers)

---

## 4. Kerberos Key Distribution Center (KDC)
- **Display Name:** Kerberos Key Distribution Center
- **Service Name:** `KDC`
- **Description:** Issues Kerberos tickets for authentication; runs only on domain controllers.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Netlogon**  
  - **Active Directory Domain Services (AD DS)**

---

## 5. Active Directory Web Services (ADWS)
- **Display Name:** Active Directory Web Services
- **Service Name:** `ADWS`
- **Description:** Provides a web service interface for managing Active Directory.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Active Directory Domain Services (AD DS)**

---

## 6. DNS Server
- **Display Name:** DNS Server
- **Service Name:** `DNS`
- **Description:** Provides DNS resolution for network resources (available when the DNS role is installed).
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Network Connectivity**  
  - **Active Directory Domain Services (AD DS)** (if integrated with AD)

---

## 7. DHCP Server
- **Display Name:** DHCP Server
- **Service Name:** `DHCPServer`
- **Description:** Manages dynamic IP address assignment for clients (requires the DHCP role).
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Network Stack/Connectivity**

---

## 8. Windows Event Log
- **Display Name:** Windows Event Log
- **Service Name:** `EventLog`
- **Description:** Logs system, security, and application events.
- **Dependencies:**  
  - **RPC (`RpcSs`)**

---

## 9. Task Scheduler
- **Display Name:** Task Scheduler
- **Service Name:** `Schedule`
- **Description:** Executes scheduled tasks and maintenance scripts.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Windows Event Log (`EventLog`)**

---

## 10. Server Service
- **Display Name:** Server
- **Service Name:** `LanmanServer`
- **Description:** Provides file, print, and named-pipe sharing over the network.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Network Protocols** (e.g., TCP/IP, NetBT)

---

## 11. Workstation Service
- **Display Name:** Workstation
- **Service Name:** `LanmanWorkstation`
- **Description:** Manages network connections to remote servers.
- **Dependencies:**  
  - **RPC (`RpcSs`)**  
  - **Network Connectivity**

---

## 12. Windows Update
- **Display Name:** Windows Update
- **Service Name:** `wuauserv`
- **Description:** Manages the detection, download, and installation of Windows updates.
- **Dependencies:**  
  - **Background Intelligent Transfer Service (BITS)**  
  - **RPC (`RpcSs`)**  
  - **Network Connectivity**

---

## 13. Background Intelligent Transfer Service (BITS)
- **Display Name:** Background Intelligent Transfer Service
- **Service Name:** `BITS`
- **Description:** Transfers files in the background for Windows Update and other services.
- **Dependencies:**  
  - **RPC (`RpcSs`)**

---

## 14. Windows Defender Antivirus Service
- **Display Name:** Windows Defender Antivirus Service
- **Service Name:** `WinDefend`
- **Description:** Provides real-time protection against malware.
- **Dependencies:**  
  - **Windows Defender Network Inspection Service (WdNisSvc)**  
  - **Core system integrity components**

---

