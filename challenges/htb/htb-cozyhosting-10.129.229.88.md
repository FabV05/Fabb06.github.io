# HTB - CozyHosting - 10.129.229.88

## HTB - CozyHosting

### Machine Info

* **Difficulty:** Easy
* **OS:** Linux (Ubuntu)
* **IP:** 10.129.229.88
* **Key Skills:** Spring Boot Actuator enumeration, Session hijacking, Command injection, Bash filter bypass, PostgreSQL credential extraction, SSH ProxyCommand privilege escalation

### Overview

CozyHosting is an easy Linux box that demonstrates Spring Boot misconfiguration and command injection exploitation. The attack begins by discovering exposed Spring Boot Actuator endpoints, which leak active user sessions. Using a hijacked session, we access an admin panel with a vulnerable SSH execution feature. By bypassing whitespace filters using Bash brace expansion, we achieve command injection and obtain a reverse shell. Post-exploitation involves extracting database credentials from the Spring Boot configuration, cracking password hashes, and escalating privileges via SSH's ProxyCommand option. This box teaches essential web application enumeration and creative filter bypass techniques.

**Key Concepts:**

* Spring Boot Actuator endpoint enumeration
* Session hijacking via exposed endpoints
* Command injection in SSH execution
* Bash whitespace filter bypass using brace expansion `{}`
* PostgreSQL credential extraction
* Password hash cracking (bcrypt)
* SSH ProxyCommand privilege escalation (GTFOBins)

**Common Ports:**

* **22/TCP** - SSH (OpenSSH 8.9p1)
* **80/TCP** - HTTP (nginx 1.18.0)

***

### Exploitation Workflow Summary

1. **Initial Enumeration** ├─ Nmap reveals SSH and HTTP ├─ Web application redirects to cozyhosting.htb ├─ Whitelabel Error Page indicates Spring Boot └─ Fuzz for Spring Boot Actuator endpoints
2. **Session Hijacking** ├─ /actuator/sessions exposes active sessions ├─ Extract kanderson's session cookie ├─ /actuator/mappings reveals /executessh endpoint └─ Access admin panel with hijacked session
3. **Command Injection** ├─ Analyze SSH execution endpoint ├─ Confirm command injection via error messages ├─ Identify whitespace filter ├─ Bypass with Bash brace expansion └─ Obtain reverse shell
4. **Credential Extraction** ├─ Find cloudhosting-0.0.1.jar ├─ Extract application.properties ├─ Obtain PostgreSQL credentials └─ Dump user table with password hashes
5. **Lateral Movement** ├─ Crack bcrypt hash for admin user ├─ Password reuse: admin = josh system user └─ SSH as josh
6. **Privilege Escalation** ├─ sudo -l reveals SSH with full access ├─ Exploit SSH ProxyCommand (GTFOBins) └─ Root shell obtained

***

### Initial Enumeration

#### Port Scanning

```bash
```
