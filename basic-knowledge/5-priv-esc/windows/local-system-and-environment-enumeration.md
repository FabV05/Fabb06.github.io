# Local System & Environment Enumeration

### Overview

**Local system enumeration** is the critical reconnaissance phase after gaining initial access to a Windows system. This process involves gathering comprehensive information about the compromised host, including system configuration, user accounts, installed software, network settings, security controls, and potential privilege escalation vectors. Thorough enumeration is essential for understanding the attack surface, identifying weaknesses, and planning subsequent exploitation steps.

**Key Concepts:**

* **System Information** - OS version, architecture, hostname, domain membership
* **User Enumeration** - Local accounts, privileges, group memberships
* **Network Configuration** - IP addresses, routing, firewall rules, connections
* **Security Controls** - Antivirus, AppLocker, LAPS, credential guard
* **Privilege Escalation Vectors** - Misconfigurations, weak permissions, vulnerable services

**Why this matters:** Comprehensive enumeration enables:

* Identification of privilege escalation opportunities
* Discovery of credentials and sensitive data
* Understanding of security controls and monitoring
* Planning of lateral movement paths
* Assessment of persistence mechanisms
* Detection evasion strategy development

**Attack advantages:**

* Most enumeration uses native Windows tools (difficult to detect)
* Provides situational awareness for next steps
* Reveals hidden attack paths
* Identifies high-value targets
* Enables informed decision-making

**Common enumeration categories:**

* System and OS information
* User accounts and privileges
* Network configuration and connections
* Running processes and services
* Installed applications and patches
* Security software and configurations
* File system and shares
* Scheduled tasks and startup items

***

### Exploitation Workflow Summary

1. Basic System Information ├─ OS version and architecture ├─ Hostname and domain membership ├─ System uptime └─ Environment variables
2. User and Privilege Enumeration ├─ Current user and privileges ├─ Local user accounts ├─ Group memberships └─ Logged-in users
3. Network Reconnaissance ├─ Network interfaces and IP configuration ├─ Active connections and listening ports ├─ Routing tables ├─ DNS configuration └─ Firewall rules
4. Process and Service Discovery ├─ Running processes ├─ Installed services ├─ Service permissions └─ Process owners
5. Security Control Assessment ├─ Antivirus and EDR detection ├─ Windows Defender status ├─ AppLocker policies ├─ PowerShell logging └─ LAPS configuration
6. Application and Patch Analysis ├─ Installed applications ├─ Missing patches ├─ Vulnerable software versions └─ Third-party software
7. File System Enumeration ├─ Interesting files and directories ├─ Network shares ├─ Mounted drives └─ File permissions
8. Scheduled Tasks and Persistence ├─ Scheduled tasks ├─ Startup programs ├─ Registry run keys └─ Services

***

### System Information Enumeration

#### Operating System Details

**Get OS version and build:**

```cmd
systeminfo
```

**Expected output:**

```
Host Name:                 WORKSTATION01
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19044 N/A Build 19044
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          CORP\john
Registered Organization:   CORP
Product ID:                00329-00000-00003-AA123
Original Install Date:     1/15/2023, 10:30:00 AM
System Boot Time:          12/21/2024, 9:45:23 AM
System Manufacturer:       Dell Inc.
System Model:              OptiPlex 7090
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                          [01]: Intel64 Family 6 Model 165 Stepping 2 GenuineIntel ~2904 Mhz
BIOS Version:              Dell Inc. 2.8.0, 5/12/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     16,234 MB
Available Physical Memory: 8,456 MB
Virtual Memory: Max Size:  32,768 MB
Virtual Memory: Available: 18,234 MB
Virtual Memory: In Use:    14,534 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    corp.local
Logon Server:              \\DC01
Hotfix(s):                 5 Hotfix(s) Installed.
                          [01]: KB5020030
                          [02]: KB5012170
                          [03]: KB5019509
                          [04]: KB5021233
                          [05]: KB5020872
Network Card(s):           2 NIC(s) Installed.
                          [01]: Intel(R) Ethernet Connection
                                Connection Name: Ethernet
                                DHCP Enabled:    Yes
                                DHCP Server:     10.10.10.1
                                IP address(es)
                                [01]: 10.10.10.50
                                [02]: fe80::1234:5678:90ab:cdef
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes
                          Virtualization Enabled In Firmware: Yes
                          Second Level Address Translation: Yes
                          Data Execution Prevention Available: Yes
```

**Key information to note:**

* **OS Name/Version** - Identifies potential exploits
* **Build Number** - Determines patch level
* **Domain** - Domain membership vs. workgroup
* **Hotfixes** - Installed patches (missing patches = vulnerabilities)
* **System Type** - x64 vs x86 (affects exploit compatibility)

**Quick OS version check:**

```cmd
ver
```

**Output:**

```
Microsoft Windows [Version 10.0.19044.2364]
```

**PowerShell method:**

```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
```

**Output:**

```
WindowsProductName              : Windows 10 Enterprise
WindowsVersion                  : 2009
OsHardwareAbstractionLayer      : 10.0.19044.2364
```

#### Hostname and Domain Information

**Get hostname:**

```cmd
hostname
```

**Output:**

```
WORKSTATION01
```

**Get domain information:**

```cmd
echo %USERDOMAIN%
```

**Output:**

```
CORP
```

**Check if domain-joined:**

```cmd
wmic computersystem get domain
```

**Output (domain-joined):**

```
Domain
corp.local
```

**Output (workgroup):**

```
Domain
WORKGROUP
```

**Detailed domain info:**

```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Domain, Workgroup, PartOfDomain
```

**Expected output:**

```
Name          : WORKSTATION01
Domain        : corp.local
Workgroup     : 
PartOfDomain  : True
```

#### System Architecture

**Check architecture:**

```cmd
echo %PROCESSOR_ARCHITECTURE%
```

**Output:**

```
AMD64
```

**Alternative:**

```cmd
wmic os get osarchitecture
```

**Output:**

```
OSArchitecture
64-bit
```

**Why this matters:**

* Determines which exploits/tools will work
* x64 systems can run x86 binaries (WOW64)
* Some privilege escalation techniques are architecture-specific

#### Environment Variables

**List all environment variables:**

```cmd
set
```

**Expected output:**

```
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\john\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
COMPUTERNAME=WORKSTATION01
ComSpec=C:\Windows\system32\cmd.exe
HOMEDRIVE=C:
HOMEPATH=\Users\john
LOCALAPPDATA=C:\Users\john\AppData\Local
LOGONSERVER=\\DC01
NUMBER_OF_PROCESSORS=8
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 165 Stepping 2, GenuineIntel
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
PROMPT=$P$G
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\john\AppData\Local\Temp
TMP=C:\Users\john\AppData\Local\Temp
USERDOMAIN=CORP
USERNAME=john
USERPROFILE=C:\Users\john
windir=C:\Windows
```

**Key variables:**

* **USERNAME/USERDOMAIN** - Current user context
* **LOGONSERVER** - Domain controller
* **Path** - Search paths for executables
* **TEMP/TMP** - Temporary directories (often writable)

**PowerShell method:**

```powershell
Get-ChildItem Env: | Format-Table Name, Value
```

***

### User and Privilege Enumeration

#### Current User Information

**Get current username:**

```cmd
whoami
```

**Output:**

```
corp\john
```

**Get current user privileges:**

```cmd
whoami /priv
```

**Expected output:**

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

**High-value privileges to look for:**

```
SeImpersonatePrivilege        - Potato attacks, token manipulation
SeAssignPrimaryTokenPrivilege - Token manipulation
SeBackupPrivilege             - Read any file on system
SeRestorePrivilege            - Write any file on system
SeDebugPrivilege              - Debug processes (dump LSASS)
SeTakeOwnershipPrivilege      - Take ownership of files
SeLoadDriverPrivilege         - Load kernel drivers
```

**Get user groups:**

```cmd
whoami /groups
```

**Expected output:**

```
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
```

**High-value groups:**

```
BUILTIN\Administrators       - Local admin
BUILTIN\Backup Operators     - SeBackupPrivilege, SeRestorePrivilege
BUILTIN\Server Operators     - Can modify services
BUILTIN\Account Operators    - Can modify non-admin accounts
CORP\Domain Admins          - Domain admin (if member)
```

**Get all information at once:**

```cmd
whoami /all
```

#### Local User Accounts

**List local users:**

```cmd
net user
```

**Expected output:**

```
User accounts for \\WORKSTATION01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
john                     WDAGUtilityAccount
The command completed successfully.
```

**Detailed user information:**

```cmd
net user Administrator
```

**Expected output:**

```
User name                    Administrator
Full Name                    
Comment                      Built-in account for administering the computer/domain
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/15/2023 10:30:00 AM
Password expires             Never
Password changeable          1/16/2023 10:30:00 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/21/2024 9:45:23 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```

**Key information:**

* **Account active** - Is account enabled?
* **Password expires** - Password policy
* **Password last set** - Old passwords = weak passwords
* **Last logon** - Recently used accounts
* **Local Group Memberships** - Administrator status

**PowerShell enumeration:**

```powershell
Get-LocalUser
```

**Output:**

```
Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
john               True    
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender...
```

**Get detailed user info:**

```powershell
Get-LocalUser -Name Administrator | Select-Object *
```

#### Local Groups and Membership

**List local groups:**

```cmd
net localgroup
```

**Expected output:**

```
Aliases for \\WORKSTATION01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Remote Desktop Users
*Remote Management Users
*Replicator
*System Managed Accounts Group
*Users
The command completed successfully.
```

**View group members:**

```cmd
net localgroup Administrators
```

**Expected output:**

```
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
CORP\Domain Admins
CORP\it-admin
The command completed successfully.
```

**Important groups to check:**

```cmd
net localgroup Administrators
net localgroup "Backup Operators"
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
```

**PowerShell method:**

```powershell
Get-LocalGroup
Get-LocalGroupMember -Name "Administrators"
```

#### Currently Logged-In Users

**Query logged-in users:**

```cmd
query user
```

**Expected output:**

```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>john                  console             1  Active          .  12/21/2024 9:45 AM
 admin                 rdp-tcp#2           2  Active      1:30  12/21/2024 8:15 AM
```

**What this shows:**

* **USERNAME** - Logged-in users
* **SESSIONNAME** - console (physical), rdp-tcp (RDP)
* **STATE** - Active vs. Disconnected
* **LOGON TIME** - When they logged in

**Alternative method:**

```cmd
qwinsta
```

**Why this matters:**

* Identifies high-value targets (admins logged in)
* Shows RDP sessions (potential lateral movement)
* Helps timing for credential dumping

***

### Network Configuration Enumeration

#### IP Configuration

**View network configuration:**

```cmd
ipconfig /all
```

**Expected output:**

```
Windows IP Configuration

   Host Name . . . . . . . . . . . . : WORKSTATION01
   Primary Dns Suffix  . . . . . . . : corp.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : corp.local

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-50-56-12-34-56
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.10.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Saturday, December 21, 2024 9:45:23 AM
   Lease Expires . . . . . . . . . . : Sunday, December 22, 2024 9:45:23 AM
   Default Gateway . . . . . . . . . : 10.10.10.1
   DHCP Server . . . . . . . . . . . : 10.10.10.1
   DNS Servers . . . . . . . . . . . : 10.10.10.10
                                       10.10.10.11
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

**Key information:**

* **Host Name/DNS Suffix** - Domain membership
* **IP Address** - Network location
* **Default Gateway** - Router/firewall
* **DNS Servers** - Often domain controllers
* **DHCP Server** - Network infrastructure

**Quick IP check:**

```cmd
ipconfig
```

#### Routing Table

**View routing table:**

```cmd
route print
```

**Expected output:**

```
===========================================================================
Interface List
 12...00 50 56 12 34 56 ......Intel(R) Ethernet Connection
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.10.10.1     10.10.10.50     25
       10.10.10.0    255.255.255.0         On-link      10.10.10.50    281
      10.10.10.50  255.255.255.255         On-link      10.10.10.50    281
     10.10.10.255  255.255.255.255         On-link      10.10.10.50    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link      10.10.10.50    281
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link      10.10.10.50    281
===========================================================================
Persistent Routes:
  None
```

**Why this matters:**

* Identifies network segments
* Shows routing to other networks
* Helps plan lateral movement
* Reveals VPN connections

#### ARP Cache

**View ARP cache:**

```cmd
arp -a
```

**Expected output:**

```
Interface: 10.10.10.50 --- 0xc
  Internet Address      Physical Address      Type
  10.10.10.1            00-50-56-aa-bb-cc     dynamic
  10.10.10.10           00-50-56-dd-ee-ff     dynamic
  10.10.10.11           00-50-56-11-22-33     dynamic
  10.10.10.100          00-50-56-44-55-66     dynamic
  10.10.10.255          ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
```

**What this reveals:**

* Recently contacted hosts
* Active machines on network
* Potential lateral movement targets

#### Active Network Connections

**View active connections:**

```cmd
netstat -ano
```

**Expected output:**

```
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1048
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    10.10.10.50:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.50:49152      10.10.10.10:88         ESTABLISHED     860
  TCP    10.10.10.50:49153      10.10.10.10:389        ESTABLISHED     860
  TCP    10.10.10.50:49154      52.123.45.67:443       ESTABLISHED     2340
  TCP    127.0.0.1:49155        127.0.0.1:49156        ESTABLISHED     3456
  UDP    0.0.0.0:123            *:*                                    1
  UDP    0.0.0.0:500            *:*                                    4284
  UDP    0.0.0.0:4500           *:*                                    4284
  UDP    0.0.0.0:5353           *:*                                    1568
  UDP    0.0.0.0:5355           *:*                                    1568
  UDP    10.10.10.50:137        *:*                                    4
  UDP    10.10.10.50:138        *:*                                    4
```

**Columns explained:**

* **Proto** - Protocol (TCP/UDP)
* **Local Address** - Local IP:Port
* **Foreign Address** - Remote IP:Port
* **State** - Connection state (LISTENING, ESTABLISHED, etc.)
* **PID** - Process ID

**Find listening ports:**

```cmd
netstat -ano | findstr LISTENING
```

**Common ports to note:**

```
135  - RPC
139  - NetBIOS
445  - SMB
3389 - RDP
5985 - WinRM HTTP
5986 - WinRM HTTPS
```

**Get process name with port:**

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

#### DNS Configuration

**View DNS servers:**

```cmd
ipconfig /displaydns
```

**PowerShell method:**

```powershell
Get-DnsClientServerAddress
```

**Output:**

```
InterfaceAlias               Interface Address ServerAddresses
                             Index     Family
--------------               --------- ------- ---------------
Ethernet                            12 IPv4    {10.10.10.10, 10.10.10.11}
Ethernet                            12 IPv6    {}
```

**Clear DNS cache:**

```cmd
ipconfig /flushdns
```

#### Firewall Rules

**Check firewall status:**

```cmd
netsh advfirewall show allprofiles
```

**Expected output:**

```
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Enable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
...
```

**List firewall rules (PowerShell):**

```powershell
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object DisplayName, Direction, Action | Format-Table
```

**Find specific rule:**

```powershell
Get-NetFirewallRule -DisplayName "*Remote Desktop*"
```

***

### Process and Service Enumeration

#### Running Processes

**List all processes:**

```cmd
tasklist
```

**Expected output:**

```
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0      1,024 K
smss.exe                       416 Services                   0        416 K
csrss.exe                      580 Services                   0      4,152 K
wininit.exe                    656 Services                   0      1,392 K
csrss.exe                      668 Console                    1      7,264 K
winlogon.exe                   732 Console                    1      3,824 K
services.exe                   760 Services                   0      8,956 K
lsass.exe                      780 Services                   0     15,204 K
svchost.exe                    896 Services                   0     10,324 K
```

**Detailed process information:**

```cmd
tasklist /v
```

**Output includes:**

* **User Name** - Process owner
* **CPU Time** - CPU usage
* **Window Title** - Application windows

**Processes with services:**

```cmd
tasklist /svc
```

**Output:**

```
Image Name                     PID Services
========================= ======== ============================================
System                           4 N/A
smss.exe                       416 N/A
csrss.exe                      580 N/A
svchost.exe                    896 Appinfo, BrokerInfrastructure, DcomLaunch, LSM, 
                                   PlugPlay, Power, SystemEventsBroker
```

**PowerShell process enumeration:**

```powershell
Get-Process | Select-Object ProcessName, Id, CPU, Path | Format-Table
```

**Find specific process:**

```powershell
Get-Process | Where-Object {$_.ProcessName -like "*anti*"}
```

**Processes running as SYSTEM:**

```powershell
Get-WmiObject Win32_Process | Where-Object {$_.GetOwner().User -eq "SYSTEM"} | Select-Object ProcessName, ProcessId, GetOwner
```

#### Installed Services

**List all services:**

```cmd
sc query
```

**Services in all states:**

```cmd
sc query state= all
```

**Expected output:**

```
SERVICE_NAME: AeLookupSvc
DISPLAY_NAME: Application Experience
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: ALG
DISPLAY_NAME: Application Layer Gateway Service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

**Service configuration details:**

```cmd
sc qc ServiceName
```

**Output:**

```
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\spoolsv.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Print Spooler
        DEPENDENCIES       : RPCSS
                           : http
        SERVICE_START_NAME : LocalSystem
```

**Key fields:**

* **START\_TYPE** - Auto, Manual, Disabled
* **BINARY\_PATH\_NAME** - Service executable
* **SERVICE\_START\_NAME** - Account service runs as
* **DEPENDENCIES** - Required services

**PowerShell service enumeration:**

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table
```

**Find vulnerable services:**

```powershell
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode | Where-Object {$_.PathName -notlike "C:\Windows*"} | Format-List
```

**Why this matters:**

* Third-party services often have weak permissions
* Services running as SYSTEM = privilege escalation
* Unquoted service paths = exploitation opportunity

#### Service Permissions

**Check service permissions:**

```cmd
sc sdshow ServiceName
```

**Output (SDDL format):**

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
```

**Better readability with PowerShell:**

```powershell
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\ServiceName" | Format-List
```

**Using accesschk (Sysinternals):**

```cmd
accesschk.exe -ucqv ServiceName
```

**Output:**

```
Spooler
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  R  NT AUTHORITY\INTERACTIVE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
```

**Vulnerable permissions:**

```
SERVICE_CHANGE_CONFIG - Can modify service
SERVICE_START/STOP    - Can start/stop service
WRITE_DAC             - Can change permissions
WRITE_OWNER           - Can take ownership
```

***

### Security Control Assessment

#### Antivirus and EDR Detection

**Check Windows Defender status:**

```powershell
Get-MpComputerStatus
```

**Expected output:**

```
AMEngineVersion                 : 1.1.19700.3
AMProductVersion                : 4.18.2211.5
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2211.5
AntispywareEnabled              : True
AntispywareSignatureAge         : 0
AntispywareSignatureLastUpdated : 12/21/2024 6:15:23 AM
AntispywareSignatureVersion     : 1.381.123.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 0
AntivirusSignatureLastUpdated   : 12/21/2024 6:15:23 AM
AntivirusSignatureVersion       : 1.381.123.0
BehaviorMonitorEnabled          : True
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 : 
FullScanStartTime               : 
IoavProtectionEnabled           : True
IsTamperProtected               : True
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : True
NISEngineVersion                : 1.1.19700.3
NISSignatureAge                 : 0
NISSignatureLastUpdated         : 12/21/2024 6:15:23 AM
NISSignatureVersion             : 1.381.123.0
OnAccessProtectionEnabled       : True
QuickScanAge                    : 0
QuickScanEndTime                : 12/21/2024 9:45:23 AM
QuickScanStartTime              : 12/21/2024 9:30:00 AM
RealTimeProtectionEnabled       : True
RebootRequired                  : False
ScanAvgCPULoadFactor            : 50
ScanPurgeItemsAfterDelay        : 15
TamperProtectionSource          : ATP
```

**Key indicators:**

* **RealTimeProtectionEnabled: True** - Active scanning
* **BehaviorMonitorEnabled: True** - Behavioral detection
* **IsTamperProtected: True** - Protected from modification
* **AMRunningMode: Normal** - Defender operational

**Check Defender preferences:**

```powershell
Get-MpPreference | Select-Object Disable*, Exclusion*
```

**List running AV processes:**

```powershell
Get-Process | Where-Object {$_.ProcessName -match "defender|virus|anti|mcafee|symantec|kaspersky|sophos|cylance|crowdstrike|sentinel"} | Select-Object ProcessName, Id, Path
```

**Common AV/EDR processes:**

```
MsMpEng.exe          - Windows Defender
MsSense.exe          - Microsoft Defender for Endpoint
CSFalconService.exe  - CrowdStrike Falcon
cb.exe               - Carbon Black
SentinelAgent.exe    - SentinelOne
CylanceSvc.exe       - Cylance
```

**Check for EDR drivers:**

```powershell
fltmc
```

**Expected output:**

```
Filter Name                     Num Instances    Altitude    Frame
------------------------------  -------------  ------------  -----
WdFilter                                3       328010         0
storqosflt                              0       244000         0
wcifs                                   0       189900         0
CldFlt                                  0       180451         0
FileCrypt                               0       141100         0
luafv                                   1       135000         0
npsvctrig                               1        46000         0
```

**WdFilter = Windows Defender minifilter**

#### AppLocker Status

**Check if AppLocker is enabled:**

```powershell
Get-AppLockerPolicy -Effective
```

**If enabled, output shows:**

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="..." Name="..." Description="..." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

**Check AppLocker event logs:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 50
```

#### PowerShell Logging

**Check PowerShell transcript logging:**

```powershell
$PSTranscription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
$PSTranscription
```

**Check script block logging:**

```powershell
$PSScriptBlock = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$PSScriptBlock
```

**Check module logging:**

```powershell
$PSModuleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
$PSModuleLogging
```

#### LAPS Configuration

**Check if LAPS is installed:**

```powershell
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
```

**Check LAPS registry settings:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
```

**Expected output if LAPS configured:**

```
AdmPwdEnabled       : 1
PasswordAgeDays     : 30
PasswordComplexity  : 4
PasswordLength      : 14
```

**Why this matters:**

* LAPS randomizes local admin passwords
* Can't use same local admin across machines
* Password stored in AD (need domain privileges)

#### Credential Guard

**Check if Credential Guard is enabled:**

```powershell
Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

**Output:**

```
AvailableSecurityProperties        : {1, 2}
CodeIntegrityPolicyEnforcementStatus : 0
RequiredSecurityProperties         : {}
SecurityServicesConfigured         : {1, 2}
SecurityServicesRunning            : {1, 2}
UsermodeCodeIntegrityPolicyEnforcementStatus : 0
Version                            : 1.0
VirtualizationBasedSecurityStatus  : 2
```

**SecurityServicesRunning: {1, 2}** indicates:

* 1 = Credential Guard
* 2 = HVCI (Hypervisor Code Integrity)

***

### Installed Applications and Patches

#### Installed Software

**List installed programs (32-bit):**

```powershell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
```

**List installed programs (64-bit):**

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
```

**Expected output:**

```
DisplayName                  DisplayVersion Publisher            InstallDate
-----------                  -------------- ---------            -----------
7-Zip 19.00 (x64 edition)    19.00.00.0     Igor Pavlov          20230115
Google Chrome                108.0.5359.125 Google LLC           20221215
Microsoft Edge               108.0.1462.54  Microsoft Corporation
Adobe Acrobat Reader DC      22.003.20282   Adobe Systems Inc.   20230110
Wireshark 4.0.2 64-bit       4.0.2          Wireshark Foundation 20230105
```

**Using WMIC:**

```cmd
wmic product get name,version,vendor
```

**Why this matters:**

* Identify vulnerable software versions
* Find interesting applications (VPN, password managers, etc.)
* Discover potential exploit targets

#### Installed Patches

**List installed hotfixes:**

```cmd
wmic qfe get HotFixID,InstalledOn
```

**Expected output:**

```
HotFixID   InstalledOn
KB5020030  12/14/2022
KB5012170  4/12/2022
KB5019509  11/9/2022
KB5021233  1/10/2023
KB5020872  12/14/2022
```

**PowerShell method:**

```powershell
Get-HotFix | Select-Object HotFixID, InstalledOn, Description | Sort-Object InstalledOn -Descending
```

**Check for specific patch:**

```powershell
Get-HotFix -Id KB5020030
```

**Missing patches = vulnerabilities:** Research CVEs for missing patches to find privilege escalation exploits.

***

### File System Enumeration

#### Interesting Files and Directories

**Search for interesting files:**

```cmd
dir /s /b C:\*password*.txt
dir /s /b C:\*credential*.xml
dir /s /b C:\*.config
dir /s /b C:\*vnc*.ini
```

**PowerShell recursive search:**

```powershell
Get-ChildItem -Path C:\ -Include *password*,*credential*,*.config,*vnc*.ini -Recurse -ErrorAction SilentlyContinue
```

**Common interesting locations:**

```
C:\Users\*\Desktop\
C:\Users\*\Documents\
C:\Users\*\Downloads\
C:\Users\*\AppData\Local\
C:\Users\*\AppData\Roaming\
C:\inetpub\wwwroot\
C:\xampp\
C:\Program Files\
```

**Search for SSH keys:**

```powershell
Get-ChildItem -Path C:\Users -Include id_rsa,id_dsa,*.ppk -Recurse -ErrorAction SilentlyContinue
```

**Search for database files:**

```powershell
Get-ChildItem -Path C:\ -Include *.mdb,*.accdb,*.db,*.sqlite,*.kdbx -Recurse -ErrorAction SilentlyContinue
```

#### Network Shares

**List local shares:**

```cmd
net share
```

**Expected output:**

```
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
SharedDocs   C:\SharedDocuments              
The command completed successfully.
```

**View share permissions:**

```cmd
net share SharedDocs
```

**Enumerate accessible network shares:**

```cmd
net view \\WORKSTATION01
net view \\DC01
```

**Find all shares in domain (PowerView):**

```powershell
Invoke-ShareFinder
```

#### Mounted Drives

**List drives:**

```cmd
wmic logicaldisk get name,description,filesystem,volumename
```

**Expected output:**

```
Description         FileSystem  Name  VolumeName
Local Fixed Disk    NTFS        C:    Windows
CD-ROM Disc                     D:
Network Connection  NTFS        Z:    NetworkShare
```

**PowerShell method:**

```powershell
Get-PSDrive -PSProvider FileSystem
```

#### File Permissions

**Check file/folder permissions:**

```cmd
icacls "C:\Program Files\Application"
```

**Expected output:**

```
C:\Program Files\Application NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                             BUILTIN\Administrators:(OI)(CI)(F)
                             BUILTIN\Users:(OI)(CI)(RX)
                             CREATOR OWNER:(OI)(CI)(IO)(F)
```

**Permission abbreviations:**

```
F  - Full control
M  - Modify
RX - Read and execute
R  - Read
W  - Write
D  - Delete
```

**Find writable directories:**

```powershell
Get-ChildItem C:\ -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}) {
        $_.FullName
    }
}
```

***

### Scheduled Tasks and Startup Items

#### Scheduled Tasks

**List all scheduled tasks:**

```cmd
schtasks /query /fo LIST /v
```

**PowerShell method:**

```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State | Format-Table
```

**Get detailed task information:**

```powershell
Get-ScheduledTask -TaskName "TaskName" | Get-ScheduledTaskInfo
```

**Check task permissions:**

```cmd
icacls "C:\Windows\System32\Tasks\TaskName"
```

**Why this matters:**

* Tasks running as SYSTEM = privilege escalation
* Writable task files = hijack execution
* Scheduled tasks = persistence opportunity

#### Startup Programs

**Registry Run keys:**

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**Expected output:**

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    VMware User Process    REG_SZ    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
```

**PowerShell method:**

```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Startup folder:**

```powershell
Get-ChildItem "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

**Using WMIC:**

```cmd
wmic startup get caption,command,location
```

***

### Automated Enumeration Tools

#### WinPEAS

**Windows Privilege Escalation Awesome Scripts:**

```powershell
.\winPEASany.exe
```

**What it checks:**

* System information
* User privileges
* Running processes and services
* Network configuration
* Installed software
* Scheduled tasks
* Interesting files
* Registry settings
* AlwaysInstallElevated
* Unquoted service paths
* Weak permissions
* And much more

#### PowerUp

**PowerShell privilege escalation framework:**

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

**What it checks:**

* Service enumeration
* Unquoted service paths
* Service permissions
* Registry autoruns
* DLL hijacking
* AlwaysInstallElevated
* Scheduled tasks
* And more

#### Seatbelt

**C# project for host enumeration:**

```cmd
Seatbelt.exe -group=all
```

**Enumeration groups:**

```
System         - OS version, patches, architecture
User           - Current user, privileges, groups
Misc           - Interesting files, configurations
Remote         - RDP, WinRM settings
Chrome         - Saved Chrome data
```

#### SharpUp

**C# port of PowerUp:**

```cmd
SharpUp.exe
```

**Same functionality as PowerUp but compiled binary.**

***

### Troubleshooting

#### Error: "Access Denied" During Enumeration

**Problem:** Cannot query certain information

**Cause:** Insufficient privileges

**Solution:**

```powershell
# Try different enumeration method
# Some commands require admin, others don't

# Example: Can't query services
sc query  # Requires admin

# Alternative
Get-Service  # Works without admin
```

#### Error: "Command Not Found"

**Problem:** Tool/command doesn't exist

**Cause:** Windows version differences

**Solution:**

```cmd
# Use alternative commands
# PowerShell vs CMD differences

# Example: Get-LocalUser not available on older systems
Get-LocalUser  # Windows 10+

# Alternative
net user  # Works on all versions
```

#### No Output from PowerShell Commands

**Problem:** PowerShell commands return nothing

**Cause:** Execution policy or missing modules

**Solution:**

```powershell
# Bypass execution policy
powershell -ep bypass

# Import module
Import-Module ActiveDirectory
```

***

### Quick Reference

#### Essential Enumeration Commands

```cmd
# System information
systeminfo
hostname
whoami /all
ver

# Network
ipconfig /all
route print
arp -a
netstat -ano
netsh advfirewall show allprofiles

# Users and groups
net user
net localgroup Administrators
query user
whoami /priv

# Processes and services
tasklist /v
sc query
Get-Process

# Files and shares
net share
dir /s /b C:\*password*.txt
Get-ChildItem -Recurse

# Scheduled tasks
schtasks /query
Get-ScheduledTask

# Security
Get-MpComputerStatus
Get-AppLockerPolicy -Effective
```

#### PowerShell One-Liners

```powershell
# Quick system info
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture

# Current user details
whoami /all

# Find writable directories
Get-ChildItem C:\ -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object {(Get-Acl $_.FullName).Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}}

# Running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Non-standard processes
Get-Process | Where-Object {$_.Path -notlike "C:\Windows\*"}

# Network connections
Get-NetTCPConnection -State Established

# Scheduled tasks not from Microsoft
Get-ScheduledTask | Where-Object {$_.Author -notlike "Microsoft*"}
```
