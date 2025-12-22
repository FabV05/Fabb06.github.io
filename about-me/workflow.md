# WorkFlow

```
┌─────────────────────────────────────────────────────────────────┐
│                    START: NEW TARGET                             │
│                                                                  │
│  Input: IP/Domain/Network Range/Web Application                 │
│  Notes: 0 Mindmaps → Table of Contents                          │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: RECONNAISSANCE                       │
│                    Notes: 1 Recon                                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Host Discovery] → 1 Recon/Host Discovery               │   │
│  │  □ Ping sweep (nmap -sn)                                │   │
│  │  □ Identify live hosts                                   │   │
│  │  □ Document IP addresses                                 │   │
│  └──────────┬──────────────────────────────────────────────┘   │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Port Scanning & Service Enumeration]                   │   │
│  │  □ Full TCP scan: nmap -p- -T4 target                   │   │
│  │  □ Service detection: nmap -sV -sC -p [ports] target    │   │
│  │  □ OS fingerprinting: nmap -O target                     │   │
│  │  □ Save results: nmap -oA scan target                    │   │
│  └──────────┬──────────────────────────────────────────────┘   │
└─────────────┼────────────────────────────────────────────────────┘
              │
              ▼
      ┌───────┴────────┐
      │  What ports     │
      │  are open?      │
      └───────┬─────────┘
              │
    ┌─────────┼─────────┬─────────────┬──────────────┬──────────┐
    │         │         │             │              │          │
    ▼         ▼         ▼             ▼              ▼          ▼
┌──────┐ ┌──────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐
│ 21   │ │ 88   │ │ 445      │ │1433/3306 │ │ 80/443   │ │5985    │
│ FTP  │ │Kerb  │ │ SMB      │ │ DB       │ │ HTTP/S   │ │WinRM   │
└──┬───┘ └──┬───┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘
   │        │          │            │            │          │
   │        │          │            │            │          │
   ▼        ▼          ▼            ▼            ▼          ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 2: PROTOCOL-SPECIFIC ATTACKS                  │
│              Notes: 2 Protocols/[Service]                        │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ FTP (21) → 2 Protocols/FTP - 21                        │    │
│  │  □ Anonymous login: ftp target                          │    │
│  │  □ Check version for exploits                           │    │
│  │  □ Download all files: mget *                           │    │
│  │  □ Look for credentials in files                        │    │
│  │  □ Test for writable directories                        │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ Kerberos (88) → 2 Protocols/Kerberos - 88              │    │
│  │  □ Enumerate users: kerbrute userenum                   │    │
│  │  □ AS-REP Roasting: GetNPUsers.py                       │    │
│  │  □ Kerberoasting: GetUserSPNs.py (if creds)            │    │
│  │  □ Request TGT: getTGT.py                               │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ LDAP (389) → 2 Protocols/LDAP Protocol (Port 389)      │    │
│  │  □ Anonymous bind: ldapsearch -x -h target             │    │
│  │  □ Enumerate naming contexts                            │    │
│  │  □ Dump all data: ldapsearch -b "DC=domain,DC=local"   │    │
│  │  □ Extract users and groups                             │    │
│  │  □ Check for passwords in description fields            │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ SMB (445) → 2 Protocols/SMB 445                        │    │
│  │  □ Null session: smbclient -N -L //target              │    │
│  │  □ Enumerate shares: smbmap -H target                   │    │
│  │  □ Check permissions: crackmapexec smb target --shares │    │
│  │  □ Download files from accessible shares               │    │
│  │  □ Check for EternalBlue (MS17-010)                     │    │
│  │  □ Test SMB signing: crackmapexec smb target           │    │
│  │  □ RID cycling for user enumeration                     │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ MSSQL (1433) → 2 Protocols/MSSQL - 1433                │    │
│  │  □ Test default creds: sa:sa, sa:(blank)               │    │
│  │  □ Connect: mssqlclient.py user:pass@target            │    │
│  │  □ Enable xp_cmdshell for RCE                          │    │
│  │  □ Check for linked servers                             │    │
│  │  □ Enumerate databases and tables                       │    │
│  │  □ Steal NTLM hash via UNC path                        │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ MySQL (3306) → 2 Protocols/MYSQL 3306                  │    │
│  │  □ Test default creds: root:(blank), root:root         │    │
│  │  □ Connect: mysql -h target -u root -p                 │    │
│  │  □ Enumerate databases: SHOW DATABASES;                │    │
│  │  □ Check for UDF exploitation                          │    │
│  │  □ Read files: SELECT LOAD_FILE('/etc/passwd');        │    │
│  │  □ Write web shell if possible                         │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ WinRM (5985/5986) → 2 Protocols/WinRM 5985, 5986       │    │
│  │  □ Check availability: crackmapexec winrm target       │    │
│  │  □ Test credentials: evil-winrm -i target -u user -p pass│  │
│  │  □ Try pass-the-hash: evil-winrm -i target -u user -H hash│ │
│  │  □ Upload/download files after connection              │    │
│  └────────────────────────────────────────────────────────┘    │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 3: WEB APPLICATION TESTING                    │
│              Notes: 3 Web Pentest                                │
│              (if port 80/443/8080/etc open)                     │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Initial Web Enumeration]                                │   │
│  │  □ Check web server: curl -I http://target              │   │
│  │  □ View robots.txt and sitemap.xml                       │   │
│  │  □ Inspect page source for comments/credentials          │   │
│  │  □ Check SSL certificate for subdomains                  │   │
│  │  □ Test for default credentials                          │   │
│  └──────────┬──────────────────────────────────────────────┘   │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Directory/File Fuzzing] → 3 Web Pentest/Fuzzing        │   │
│  │  □ Gobuster: gobuster dir -u http://target -w wordlist  │   │
│  │  □ Ffuf: ffuf -u http://target/FUZZ -w wordlist         │   │
│  │  □ Feroxbuster: feroxbuster -u http://target            │   │
│  │  □ Check for: /admin, /backup, /api, /.git, /.env       │   │
│  │  □ File extension fuzzing: .php, .bak, .old, ~          │   │
│  └──────────┬──────────────────────────────────────────────┘   │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Virtual Host Discovery] → 1 Recon/Virtual Host         │   │
│  │  □ Fuzz vhosts: gobuster vhost -u http://target -w vhosts│  │
│  │  □ Add to /etc/hosts                                     │   │
│  │  □ Test each vhost separately                            │   │
│  └──────────┬──────────────────────────────────────────────┘   │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Common Target Analysis]                                 │   │
│  │  → 3 Web Pentest/Common Web Targets                      │   │
│  │                                                           │   │
│  │  ├─ IIS → 3 Web/Common Targets/IIS                      │   │
│  │  │   □ Check version and default files                   │   │
│  │  │   □ Test WebDAV: davtest -url http://target          │   │
│  │  │   □ Look for web.config (credentials)                │   │
│  │  │   □ IIS shortname vulnerability                       │   │
│  │  │                                                        │   │
│  │  └─ Jenkins → 3 Web/Common Targets/Jenkins              │   │
│  │      □ Access /script console without auth              │   │
│  │      □ Test default creds: admin:admin                   │   │
│  │      □ Execute Groovy script for RCE                     │   │
│  │      □ Check build logs for credentials                  │   │
│  └──────────┬──────────────────────────────────────────────┘   │
│             │                                                    │
│             ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ [Vulnerability Testing]                                  │   │
│  │  → 3 Web Pentest/Vulnerabilities                         │   │
│  │                                                           │   │
│  │  ├─ SQL Injection → 3 Web/Vulnerabilities/SQLI          │   │
│  │  │   □ Test inputs: ', '', ", --, #, ' OR '1'='1        │   │
│  │  │   □ Error-based SQLi detection                        │   │
│  │  │   □ Blind SQLi: time-based, boolean-based            │   │
│  │  │   □ Union-based: ' UNION SELECT NULL--               │   │
│  │  │   □ Automated: sqlmap -u "http://target?id=1"        │   │
│  │  │   □ Extract: databases, tables, data                  │   │
│  │  │                                                        │   │
│  │  ├─ XSS → 3 Web/Vulnerabilities/XSS                     │   │
│  │  │   □ Reflected: <script>alert(1)</script>             │   │
│  │  │   □ Stored: Submit payload, check persistence        │   │
│  │  │   □ DOM-based: Check JavaScript DOM manipulation     │   │
│  │  │   □ Bypass filters: encoding, obfuscation            │   │
│  │  │   □ Advanced: <img src=x onerror=alert(1)>           │   │
│  │  │                                                        │   │
│  │  ├─ LFI → 3 Web/Vulnerabilities/LFI                     │   │
│  │  │   □ Basic: ../../../../etc/passwd                     │   │
│  │  │   □ Null byte: ../../../../etc/passwd%00             │   │
│  │  │   □ Encoding: ..%2F..%2F..%2Fetc%2Fpasswd            │   │
│  │  │   □ PHP wrappers: php://filter, php://input          │   │
│  │  │   □ Log poisoning for RCE                            │   │
│  │  │                                                        │   │
│  │  ├─ SSRF → 3 Web/Vulnerabilities/SSRF                   │   │
│  │  │   □ Test URL parameters: url=, uri=, path=           │   │
│  │  │   □ Access localhost: http://127.0.0.1               │   │
│  │  │   □ Scan internal network: http://192.168.1.1-254    │   │
│  │  │   □ Cloud metadata: http://169.254.169.254/          │   │
│  │  │   □ Bypass filters with encoding                     │   │
│  │  │                                                        │   │
│  │  ├─ Command Injection → 3 Web/Vulnerabilities/Command   │   │
│  │  │   □ Test separators: ; whoami, | whoami, `whoami`    │   │
│  │  │   □ Blind: ; sleep 10, ; ping -c 10 127.0.0.1        │   │
│  │  │   □ Reverse shell payloads                           │   │
│  │  │   □ Bypass filters: wildcards, $IFS                  │   │
│  │  │                                                        │   │
│  │  ├─ File Upload → 3 Web/Vulnerabilities/File Upload     │   │
│  │  │   □ Upload web shell: shell.php, shell.aspx          │   │
│  │  │   □ Bypass extension filters: double extension       │   │
│  │  │   □ Bypass MIME type checks                          │   │
│  │  │   □ Magic bytes: Add GIF89a                          │   │
│  │  │   □ Path traversal in filename                       │   │
│  │  │                                                        │   │
│  │  ├─ SSTI → 3 Web/Vulnerabilities/SSTI                   │   │
│  │  │   □ Detect: {{7*7}}, ${7*7}, <%= 7*7 %>             │   │
│  │  │   □ Identify engine: Jinja2, Twig, Smarty           │   │
│  │  │   □ Exploit for RCE                                  │   │
│  │  │                                                        │   │
│  │  ├─ CSTI → 3 Web/Vulnerabilities/CSTI                   │   │
│  │  │   □ AngularJS: {{constructor.constructor('alert(1)')()}}│ │
│  │  │   □ Check framework version                          │   │
│  │  │                                                        │   │
│  │  ├─ IDOR → 3 Web/Vulnerabilities/IDOR                   │   │
│  │  │   □ Test ID manipulation: /user/123 → /user/124      │   │
│  │  │   □ Check API endpoints                              │   │
│  │  │   □ Test different HTTP methods                      │   │
│  │  │                                                        │   │
│  │  └─ LDAP Injection → 3 Web/Vulnerabilities/LDAP Injection│  │
│  │      □ Test: *)(uid=*))(|(uid=*                          │   │
│  │      □ Bypass auth: admin)(&(password=*))               │   │
│  └──────────┬──────────────────────────────────────────────┘   │
└─────────────┼────────────────────────────────────────────────────┘
              │
              ▼
      ┌───────────────┐
      │ Got Initial   │
      │   Access?     │
      └───┬───────┬───┘
          │       │
     NO   │       │   YES
          │       │
          ▼       ▼
    ┌─────────┐  ┌────────────────────────────────────────────┐
    │  More   │  │  PHASE 4: POST-EXPLOITATION                │
    │  Recon  │  │  Notes: 4 Inside the target                │
    │  & Try  │  │                                            │
    │  Other  │  │  ┌──────────────────────────────────────┐ │
    │ Vectors │  │  │ [Situational Awareness]              │ │
    └─────────┘  │  │  □ whoami / id                       │ │
                 │  │  □ hostname                          │ │
                 │  │  □ ifconfig / ip addr                │ │
                 │  │  □ uname -a / systeminfo             │ │
                 │  │  □ Check privileges                  │ │
                 │  └───────────┬──────────────────────────┘ │
                 │              │                            │
                 │              ▼                            │
                 │      ┌───────┴────────┐                  │
                 │      │  What OS?      │                  │
                 │      └───────┬────────┘                  │
                 │              │                            │
                 │      ┌───────┴────────┐                  │
                 │      │                │                  │
                 │      ▼                ▼                  │
                 │  ┌────────┐      ┌────────┐             │
                 │  │Windows │      │ Linux  │             │
                 │  └───┬────┘      └────┬───┘             │
                 │      │                │                  │
                 └──────┼────────────────┼──────────────────┘
                        │                │
        ┌───────────────┘                └────────────────┐
        │                                                  │
        ▼                                                  ▼
┌────────────────────────────────┐    ┌──────────────────────────────────┐
│   WINDOWS PRIVILEGE ESCALATION │    │   LINUX PRIVILEGE ESCALATION     │
│   Notes: 5 Priv Esc/Windows    │    │   Notes: 5 Priv Esc/Linux        │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ Initial Surface Mapping  │  │    │ │ Local Environment Enum       │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   Local System & Env     │  │    │ │   Local Environment Enum     │ │
│ │                          │  │    │ │                              │ │
│ │ □ whoami /priv           │  │    │ │ □ Check sudo -l              │ │
│ │ □ systeminfo             │  │    │ │ □ Find SUID binaries         │ │
│ │ □ List processes         │  │    │ │ □ Check cron jobs            │ │
│ │ □ netstat -ano           │  │    │ │ □ Review /etc/passwd, shadow │ │
│ │ □ Installed software     │  │    │ │ □ Check capabilities         │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ Credential Hygiene       │  │    │ │ Credential Hunting           │ │
│ │ → 4 Inside/Windows/      │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   Credential Hygiene     │  │    │ │   Local Credential Exposure  │ │
│ │                          │  │    │ │                              │ │
│ │ □ Search for passwords   │  │    │ │ □ History files              │ │
│ │ □ Check config files     │  │    │ │ □ Config files               │ │
│ │ □ Browser credentials    │  │    │ │ □ SSH keys                   │ │
│ │ □ Saved credentials      │  │    │ │ □ Database credentials       │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ Local Credential Dump    │  │    │ │ Writable Files/Directories   │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   Local Credential       │  │    │ │   Writable Files and Dirs    │ │
│ │   Exposure & Abuse       │  │    │ │                              │ │
│ │                          │  │    │ │ □ /etc/passwd writable       │ │
│ │ □ Mimikatz → LSASS       │  │    │ │ □ /etc/shadow readable       │ │
│ │ □ SAM/SYSTEM files       │  │    │ │ □ World-writable scripts     │ │
│ │ □ NTDS.dit extraction    │  │    │ │ □ Cron job scripts           │ │
│ │ □ Registry credentials   │  │    │ │ □ Service files              │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ UAC Bypass               │  │    │ │ Path Manipulation            │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   UAC Trust Boundary     │  │    │ │   Path Manipulation          │ │
│ │                          │  │    │ │                              │ │
│ │ □ Check UAC level        │  │    │ │ □ SUID PATH hijacking        │ │
│ │ □ Eventvwr bypass        │  │    │ │ □ Writable dirs in PATH      │ │
│ │ □ FodHelper bypass       │  │    │ │ □ Relative path exploits     │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ DLL Hijacking            │  │    │ │ Sudo Exploitation            │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   Dynamic Library Load   │  │    │ │   Delegated Privilege (sudo) │ │
│ │                          │  │    │ │                              │ │
│ │ □ Find missing DLLs      │  │    │ │ □ GTFOBins lookup            │ │
│ │ □ Check PATH directories │  │    │ │ □ Wildcard exploitation      │ │
│ │ □ DLL load order hijack  │  │    │ │ □ Sudo version vulns         │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ Service Exploitation     │  │    │ │ Capabilities                 │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │   Service Abuse          │  │    │ │   Capabilities               │ │
│ │                          │  │    │ │                              │ │
│ │ □ Unquoted service paths │  │    │ │ □ getcap -r /                │ │
│ │ □ Weak permissions       │  │    │ │ □ cap_setuid exploitation    │ │
│ │ □ AlwaysInstallElevated  │  │    │ │ □ cap_dac_read_search        │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ Scheduled Tasks          │  │    │ │ Kernel Exploits              │ │
│ │ → Check task permissions │  │    │ │ → 5 Priv Esc/Linux/          │ │
│ │ → Modify task scripts    │  │    │ │   Linux Kernel Exploits      │ │
│ │                          │  │    │ │                              │ │
│ │ □ schtasks /query        │  │    │ │ □ Check kernel version       │ │
│ │ □ Check for writable     │  │    │ │ □ DirtyCow, DirtyPipe        │ │
│ │   task scripts           │  │    │ │ □ PwnKit, Baron Samedit      │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
│                                │    │                                  │
│ ┌──────────────────────────┐  │    │ ┌──────────────────────────────┐ │
│ │ NTLM-Based Attacks       │  │    │ │ SSH Exploitation             │ │
│ │ → 5 Priv Esc/Windows/    │  │    │ │ → 5 Priv Esc/Linux/SSH       │ │
│ │   NTLM-Based Priv Esc    │  │    │ │                              │ │
│ │                          │  │    │ │ □ Plant SSH keys             │ │
│ │ □ RemotePotato           │  │    │ │ □ Hijack authorized_keys     │ │
│ │ □ LocalPotato            │  │    │ │ □ Extract private keys       │ │
│ └──────────────────────────┘  │    │ └──────────────────────────────┘ │
└────────────┬───────────────────┘    └──────────────┬───────────────────┘
             │                                       │
             │                                       │
             └───────────────┬───────────────────────┘
                             │
                             ▼
                     ┌───────────────┐
                     │  Got Admin/   │
                     │  Root Access? │
                     └───┬───────┬───┘
                         │       │
                    NO   │       │   YES
                         │       │
                    ┌────┘       └────┐
                    │                 │
                    ▼                 ▼
            ┌──────────────┐   ┌─────────────────────────────────┐
            │  Try Other   │   │  Is This Active Directory?       │
            │  Techniques  │   │                                  │
            │  or Lateral  │   └───┬───────────────┬─────────────┘
            │  Movement    │       │               │
            └──────────────┘       │ NO            │ YES
                                   │               │
                                   │               ▼
                                   │   ┌──────────────────────────────┐
                                   │   │ PHASE 6: AD ATTACKS          │
                                   │   │ Notes: 4 Inside/Windows      │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ LLMNR/NBT-NS Poisoning   │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   LLMNR / NBT-NS         │ │
                                   │   │ │                          │ │
                                   │   │ │ □ Responder -I eth0 -wrf │ │
                                   │   │ │ □ Capture NTLMv2 hashes  │ │
                                   │   │ │ □ Crack with hashcat     │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ Kerberoasting            │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   Kerberoast             │ │
                                   │   │ │                          │ │
                                   │   │ │ □ GetUserSPNs.py         │ │
                                   │   │ │ □ Request TGS tickets    │ │
                                   │   │ │ □ Crack service hashes   │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ AS-REP Roasting          │ │
                                   │   │ │ (Part of Kerberoast)     │ │
                                   │   │ │                          │ │
                                   │   │ │ □ Find users w/o preauth │ │
                                   │   │ │ □ GetNPUsers.py          │ │
                                   │   │ │ □ Crack hashes offline   │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ Password Spray           │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   Password Spray         │ │
                                   │   │ │                          │ │
                                   │   │ │ □ Enumerate usernames    │ │
                                   │   │ │ □ Common password list   │ │
                                   │   │ │ □ Spray carefully        │ │
                                   │   │ │ □ Avoid lockouts         │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ DCSync                   │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   DCSync                 │ │
                                   │   │ │                          │ │
                                   │   │ │ □ Check replication rights│ │
                                   │   │ │ □ secretsdump.py         │ │
                                   │   │ │ □ Dump all domain hashes │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ AD CS Attacks            │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   AD CS Domain Escalation│ │
                                   │   │ │                          │ │
                                   │   │ │ □ Certificate templates  │ │
                                   │   │ │ □ ESC1-ESC8 vulns        │ │
                                   │   │ │ □ Certify.exe            │ │
                                   │   │ └──────────────────────────┘ │
                                   │   │                              │
                                   │   │ ┌──────────────────────────┐ │
                                   │   │ │ Trust Abuse              │ │
                                   │   │ │ → 4 Inside/Windows/      │ │
                                   │   │ │   Inter-Domain Trust     │ │
                                   │   │ │                          │ │
                                   │   │ │ □ Enumerate trusts       │ │
                                   │   │ │ □ Golden ticket across   │ │
                                   │   │ │ □ SID history injection  │ │
                                   │   │ └──────────────────────────┘ │
                                   │   └──────────────────────────────┘
                                   │
                                   └────────────┬─────────────────────┐
                                                │                     │
                                                ▼                     │
                               ┌──────────────────────────────────┐  │
                               │  PHASE 7: LATERAL MOVEMENT       │  │
                               │  Notes: 6 Post Explotation/      │  │
                               │         Lateral movement         │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Pass-the-Hash (PtH)          │ │  │
                               │ │ → 6 Post Explotation/        │ │  │
                               │ │   Lateral movement/PtH       │ │  │
                               │ │                              │ │  │
                               │ │ □ Obtain NTLM hash           │ │  │
                               │ │ □ psexec.py -hashes :hash    │ │  │
                               │ │ □ wmiexec.py -hashes :hash   │ │  │
                               │ │ □ evil-winrm -H hash         │ │  │
                               │ │ □ xfreerdp /pth:hash         │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Pass-the-Ticket (PtT)        │ │  │
                               │ │ → 6 Post Explotation/        │ │  │
                               │ │   Lateral movement/PtT       │ │  │
                               │ │                              │ │  │
                               │ │ □ Export Kerberos tickets    │ │  │
                               │ │ □ Convert format if needed   │ │  │
                               │ │ □ Inject with Rubeus/Mimikatz│ │  │
                               │ │ □ Use with Impacket          │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ RDP Lateral Movement         │ │  │
                               │ │ → 6 Post Explotation/        │ │  │
                               │ │   Lateral movement/RDP       │ │  │
                               │ │                              │ │  │
                               │ │ □ Identify RDP-enabled hosts │ │  │
                               │ │ □ xfreerdp with creds/hash   │ │  │
                               │ │ □ Session hijacking (tscon)  │ │  │
                               │ │ □ Tunnel RDP through pivot   │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ WinRM Movement               │ │  │
                               │ │ (Part of protocols)          │ │  │
                               │ │                              │ │  │
                               │ │ □ evil-winrm -i target       │ │  │
                               │ │ □ Enter-PSSession            │ │  │
                               │ │ □ Pass-the-Hash compatible   │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Pivoting/Tunneling           │ │  │
                               │ │ → 6 Post Explotation/        │ │  │
                               │ │   Pivoting, Tunneling & Port │ │  │
                               │ │   Forwarding                 │ │  │
                               │ │                              │ │  │
                               │ │ □ SSH tunneling              │ │  │
                               │ │   - Local: -L                │ │  │
                               │ │   - Dynamic: -D (SOCKS)      │ │  │
                               │ │   - Remote: -R               │ │  │
                               │ │                              │ │  │
                               │ │ □ Chisel SOCKS proxy         │ │  │
                               │ │   - Server: --reverse        │ │  │
                               │ │   - Client: R:socks          │ │  │
                               │ │                              │ │  │
                               │ │ □ Ligolo-ng (recommended)    │ │  │
                               │ │   - ip tuntap add ligolo     │ │  │
                               │ │   - ./proxy -selfcert        │ │  │
                               │ │   - ./agent -connect         │ │  │
                               │ │   - ip route add             │ │  │
                               │ │                              │ │  │
                               │ │ □ Metasploit autoroute       │ │  │
                               │ │   - portfwd                  │ │  │
                               │ │   - socks_proxy module       │ │  │
                               │ └──────────────────────────────┘ │  │
                               └──────────────┬───────────────────┘  │
                                              │                      │
                                              ▼                      │
                               ┌──────────────────────────────────┐  │
                               │  PHASE 8: POST-EXPLOITATION      │  │
                               │  Notes: 6 Post Explotation       │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Credential Dumping           │ │  │
                               │ │                              │ │  │
                               │ │ □ Mimikatz logonpasswords    │ │  │
                               │ │ □ secretsdump.py             │ │  │
                               │ │ □ LaZagne                    │ │  │
                               │ │ □ Browser credentials        │ │  │
                               │ │ □ /etc/shadow extraction     │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Persistence                  │ │  │
                               │ │                              │ │  │
                               │ │ □ Registry keys (Windows)    │ │  │
                               │ │ □ Scheduled tasks            │ │  │
                               │ │ □ Service installation       │ │  │
                               │ │ □ Golden ticket              │ │  │
                               │ │ □ SSH key injection (Linux)  │ │  │
                               │ │ □ Cron jobs (Linux)          │ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Data Exfiltration            │ │  │
                               │ │ → 6 Post Explotation/        │ │  │
                               │ │   Data Exfiltration (Theft)  │ │  │
                               │ │                              │ │  │
                               │ │ □ Identify sensitive data    │ │  │
                               │ │ □ Compress files             │ │  │
                               │ │   - tar czf / Compress-Archive│ │  │
                               │ │                              │ │  │
                               │ │ □ Encrypt (optional)         │ │  │
                               │ │   - openssl enc / GPG        │ │  │
                               │ │                              │ │  │
                               │ │ □ Exfiltration methods:      │ │  │
                               │ │   - HTTP/HTTPS (curl/wget)   │ │  │
                               │ │   - SCP/SFTP                 │ │  │
                               │ │   - SMB shares               │ │  │
                               │ │   - DNS tunneling            │ │  │
                               │ │   - Through established pivot│ │  │
                               │ └──────────────────────────────┘ │  │
                               │                                  │  │
                               │ ┌──────────────────────────────┐ │  │
                               │ │ Covering Tracks              │ │  │
                               │ │                              │ │  │
                               │ │ □ Clear event logs           │ │  │
                               │ │ □ Remove artifacts           │ │  │
                               │ │ □ Delete uploaded tools      │ │  │
                               │ │ □ Clear command history      │ │  │
                               │ └──────────────────────────────┘ │  │
                               └──────────────────────────────────┘  │
                                              │                      │
                                              ▼                      │
                                      ┌───────────────┐              │
                                      │  MISSION      │              │
                                      │  COMPLETE     │              │
                                      │               │              │
                                      │  Document:    │              │
                                      │  - Findings   │              │
                                      │  - Paths      │              │
                                      │  - Evidence   │              │
                                      │  - Remediations│             │
                                      └───────────────┘              │
                                                                     │
                                      ┌──────────────────────────────┘
                                      │
                                      ▼
                              ┌───────────────────┐
                              │  Need to continue │
                              │  to other systems?│
                              └───────┬───────────┘
                                      │
                                YES   │
                                      │
                                      └──────────────────┐
                                                         │
                        Go back to Lateral Movement ─────┘
                        (Phase 7) to access more systems
```

