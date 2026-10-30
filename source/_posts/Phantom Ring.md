# PhantomRing: a Linux backdoor built to blind the defender

**Hack The Box Sherlock** · Mohamed Malek Wertatani (inferno-sec) · Static analysis only, the sample was never executed

---

## Summary

A suspicious binary was found on a Linux server after it tried to call out. The goal: understand it without running it, extract IoCs, and work out how it talks to its C2.

Reversing it in Ghidra showed a backdoor that connects to an operator, runs commands from 12 built-in handlers, and spends a lot of its code on **not being seen**: it uses `io_uring` to avoid syscall-based monitoring, tries to disable eBPF-based security tooling, and has a self-destruct routine for investigations.

| Field | Value |
|---|---|
| File | `agent` |
| SHA-256 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| Language / packer | **[TODO: result from Detect It Easy]** |
| C2 | **[TODO: IP:port]**, reconnect every **[TODO: seconds]** |
| Tools | `sha256sum`, Detect It Easy, Ghidra |

**Capabilities at a glance:** C2 with reconnect loop · 12 built-in commands · logged-in user recon · SUID enumeration · security tooling tampering · `io_uring` evasion · self-destruct

---

## 1. Triage

Hash of the file first:

```python
┌──(inferno㉿inferno)-[/mnt/c/Users/med malek/Downloads/PhantomRing/phantom_ring]
└─$ sha256sum agent
2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5  agent

```

Then Detect It Easy, to check for obfuscation, the language the binary is written in, and whether a packer is applied:

![[malware_1.png]]

**[TODO: one line with the result: language, compiler, packed or not.]**

## 2. C2 and beaconing

With the hash, language and compiler known, the binary goes into Ghidra:

![[malware_2.png]]

First thing I checked was the sleep time between reconnection attempts:

![[malware_3.png]]

![[malware_4.png|640]]


A fixed reconnect interval is the implant's beaconing rhythm, and it is something a network defender can look for.

## 3. The command loop

After a successful connection, execution goes into `process_cmd`:

![[malware_5.png]]

`sanitize_cmd` cleans the syntax of the incoming command so it does not break. The agent has **12 built-in commands**, and each one has its own function that runs it internally:

![[malware_6.png]]

## 4. Targeting the defender

### 4.1 `io_uring` to avoid syscall monitoring

The agent initializes `io_uring` (`io_uring_queue_init`, which calls `io_uring_setup`):

![[malware_7.png]]

Instead of the usual `read`, `write`, `connect` and `recv` syscalls that EDRs and user-space hooks watch, operations are queued through shared ring buffers. Many Linux monitoring tools hook those standard entry points, so some file and network operations run with less noise.

It does not make the agent invisible. The `io_uring_setup` call can still be audited, and few programs on a normal server use it.

### 4.2 Killing the sensors

After it starts, the agent looks for the BPF system and kills it, so the protections that depend on it stop working. It disables tracing first, then goes through an array of other targets:

![[malware_10.png]]

![[malware_11.png]]

### 4.3 Self-destruct

If it is being investigated, a custom destruct function starts by finding the agent's own path:

![[malware_12.png]]

## 5. Recon and privilege escalation

`cmd_users`, called from `process_cmd`, reads `/var/run/utmp` to list the users logged in ([utmp(5)](https://man7.org/linux/man-pages/man5/utmp.5.html)):

![[malware_8.png]]

For privilege escalation, the agent looks in `/usr/bin` for binaries with the `4000` permission bit (SUID), which run with the privileges of their owner:

![[malware_9.png]]

**[TODO: persistence, one or two lines on what you found, or remove this line.]**

---

## 6. Behavior, ATT&CK and detection

|Behavior|ATT&CK (from the code)|How a SOC can catch it|
|---|---|---|
|C2 connection with reconnect loop|T1071 Application Layer Protocol|Regular connections to the same IP:port in firewall or proxy logs|
|`io_uring_setup` to avoid syscall hooks|No clean match, closest is T1562 Impair Defenses|auditd rule on `io_uring_setup`, with an allowlist|
|Reads `/var/run/utmp`|T1033 System Owner/User Discovery|auditd watch on the file, only alert on odd processes or paths|
|Scans `/usr/bin` for SUID files|T1083 File and Directory Discovery, T1548.001 Setuid and Setgid (enumeration only)|Hard to catch alone, correlate with the other behaviors|
|Kills BPF and other security tooling|T1562.001 Disable or Modify Tools|Sensor heartbeat lost on a Linux server, treat it as a possible compromise|
|Self-destruct|T1070.004 File Deletion|Hunt for running processes with a deleted executable|

Starting points for the three most useful signals. I have not tested them against the sample:

```
# io_uring use (auditd)
-a always,exit -F arch=b64 -S io_uring_setup -k io_uring_use

# utmp reads (auditd), noisy: who, w, last and login tools read it too
-w /var/run/utmp -p r -k utmp_read

# running processes whose executable was deleted (a package update can cause this too)
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

## 7. IoCs

- SHA-256: `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5`
- C2: **[TODO: IP:port]**
- Behavior: unknown binary calling `io_uring_setup`, reading `/var/run/utmp`, scanning `/usr/bin` for SUID files or killing security tooling; running process whose executable is deleted

## 8. What I could not confirm

- Everything here comes from static analysis. I did not run the sample, so I did not see its network traffic or runtime behavior.
- The C2 address comes from values in the binary. It may be offline.
- The SUID step is enumeration. **[TODO: say whether you saw what it does with the result.]**

## Takeaway

This sample shows where Linux malware is going: it does not worry much about antivirus, it worries about the sensors watching the endpoint. Abusing `io_uring` to avoid syscall hooks and attacking eBPF-based tooling means a SOC cannot assume the agent on the box still sees everything. Monitoring the monitor (sensor health, `io_uring` use, deleted executables) is the useful lesson, and static analysis alone was enough to get there.