

## What is Kerberos?

**Kerberos** is an authentication protocol used primarily in Windows Active Directory environments. It runs on **port 88** and uses **tickets** instead of passwords to verify identities.

Think of it like an airport security system:
- You show your ID once (login)
- You get a boarding pass (TGT - Ticket Granting Ticket)
- You use that pass to access different gates (services) without showing ID again

---

## Getting Kerberos Tickets with Impacket

### What is getTGT.py?

`getTGT.py` is a tool that requests a **TGT (Ticket Granting Ticket)** from the domain controller. This ticket lets you authenticate to services without sending your password over the network.

### Method 1: Using NTLM Hash
```bash
getTGT.py -dc-ip 10.10.11.45 domain.htb/GMSA01$ -hashes :NTLM_HASH_HERE
```

**Output**:
```
[*] Saving ticket in GMSA01$.ccache
```

### Method 2: Using Username and Password
```bash
getTGT.py -dc-ip 10.10.11.45 domain.htb/username:password
```

### Using the Ticket

After getting the ticket, **export it** so other tools can use it:
```bash
export KRB5CCNAME=GMSA01$.ccache
```

Now you can use the `-k` flag in tools like:
- `bloodyAD`
- `crackmapexec`
- `impacket scripts`

**Example**:
```bash
crackmapexec smb 10.10.11.45 -k --use-kcache
```

---

## Clock Synchronization Issues

### The Problem

Kerberos is **extremely sensitive to time differences**. If your clock differs from the Domain Controller by more than **5 minutes**, you'll get this error:
```
KRB_AP_ERR_SKEW (Clock skew too great)
```

**Why?** Kerberos tickets have timestamps to prevent replay attacks. If clocks don't match, tickets are rejected.

### Detecting Clock Skew

#### Method 1: Nmap Service Scan
```bash
nmap -sV -sC 10.10.10.10
```

**Look for**:
```
clock-skew: mean: -1998d09h03m04s, deviation: 4h00m00s
```

#### Method 2: SMB Time Check
```bash
nmap -sT 10.10.10.10 -p445 --script smb2-time -vv
```

This tells you the **exact time** on the target server.

---

## Fixing Clock Skew (3 Methods)

### Fix #1: Synchronize Your Clock (Recommended)

#### Linux - Using ntpdate
```bash
sudo ntpdate dc.domain.local
```

**What this does**: Syncs your system clock with the Domain Controller.

#### Linux - Using rdate
```bash
sudo rdate -n 10.10.10.10
```

#### Linux - Manual Time Set
```bash
sudo date -s "14 APR 2015 18:25:16"
```

#### Windows
```cmd
net time /domain /set
```

### Fix #2: Fake the Time for Specific Commands
```bash
faketime -f '+8h' getTGT.py domain.htb/user:pass
```

**What this does**: Runs the command as if it's 8 hours in the future (adjust based on clock skew).

### Fix #3: Disable Auto Time Sync
```bash
sudo timedatectl set-ntp off
```

**Warning**: Only use this if you need manual control. Don't forget to re-enable later.

**To re-enable**:
```bash
sudo timedatectl set-ntp on
```

---

## Common Kerberos Attacks

### 1. Kerberoasting

**What it is**: Extracting service account password hashes from TGS tickets, then cracking them offline.

**Tools**:
- `GetUserSPNs.py` (Impacket)
- Rubeus (Windows)

**Reference**: See SMB/RPC section for detailed walkthrough.

### 2. AS-REP Roasting

**What it is**: Attacking accounts that don't require Kerberos pre-authentication.

**Tools**:
- `GetNPUsers.py` (Impacket)

### 3. Kerberos Relay Attacks

**What it is**: Similar to NTLM relay but using Kerberos authentication.

**Tools**:
- `krbrelayx`
- `mitm6`

**References**:
- [From NTLM Relay to Kerberos Relay](https://decoder.cloud/2025/04/24/from-ntlm-relay-to-kerberos-relay-everything-you-need-to-know/)
- See Network Attacks section

---

## Quick Reference Cheat Sheet

### Get TGT with Password
```bash
getTGT.py -dc-ip <DC_IP> <domain>/<user>:<pass>
export KRB5CCNAME=<user>.ccache
```

### Get TGT with Hash
```bash
getTGT.py -dc-ip <DC_IP> <domain>/<user> -hashes :<NTLM>
export KRB5CCNAME=<user>.ccache
```

### Fix Clock Skew
```bash
sudo ntpdate <DC_IP>
```

### Use Ticket with Tools
```bash
# Add -k flag
crackmapexec smb <target> -k --use-kcache
impacket-smbclient -k <domain>/<user>@<target>
```

### Check Current Kerberos Tickets
```bash
klist
```

### Delete All Tickets
```bash
kdestroy
```

---

## Troubleshooting

### Error: "KRB_AP_ERR_SKEW"
**Solution**: Sync your clock (see Clock Synchronization section)

### Error: "KDC_ERR_PREAUTH_FAILED"
**Problem**: Wrong password/hash
**Solution**: Verify credentials

### Error: "KDC_ERR_C_PRINCIPAL_UNKNOWN"
**Problem**: User doesn't exist
**Solution**: Check username spelling and domain

### Error: "KRB5CCNAME not set"
**Problem**: Ticket not exported
**Solution**: Run `export KRB5CCNAME=ticket.ccache`

---
