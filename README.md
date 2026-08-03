# Security write-ups

Penetration testing write-ups from training platforms, written as engagement reports rather than walkthroughs — attack chain, impact, and remediation for each finding.

My focus is **application security**: access control, authentication, and business logic flaws.

---

## Write-ups

| Write-up | Focus | Key findings | Lang |
|---|---|---|---|
| [Web application exploitation](tryhackme/web-app-exploitation) | AppSec | IDOR → weak password reset → upload filter bypass → RCE. Full chain analysis with OWASP mapping and remediation table. | FR |
| [Network penetration test & privilege escalation](tryhackme/network-privesc) | Infrastructure | Backdoored UnrealIRCd (unauthenticated RCE) → plaintext root credentials in a world-readable file. | EN |
| [DVWA — SQLi defence analysis](dvwa/sqli-defense-analysis) | Code review | SQL injection and the source-code differences between DVWA security levels. | FR |
| [SOC detection](tryhackme/soc-detection) | Blue team | Alert triage and investigation — the detection side of the techniques above. | FR |

---

## How I write these

Each write-up follows the same structure:

1. **Executive summary** — what was compromised and why it matters
2. **Enumeration** — what the target exposed
3. **Vulnerability analysis** — root cause, not just the payload
4. **Exploitation** — reproducible steps
5. **Remediation** — what a defender should actually change
6. **Lessons learned** — including what I got wrong

The single most useful thing I have taken from these: individual findings are rarely critical on their own. **The chain is the vulnerability.** An IDOR that leaks usernames is low severity until it feeds a weak password reset, which then feeds an upload bypass, which ends in RCE.

---

## A note on training platforms

These come from TryHackMe and DVWA. Some rooms are guided, and I do not pretend otherwise — the value here is not in finding an unknown bug, it is in **documenting a methodology and reasoning about impact and remediation**.

Where a solution was pointed to rather than found, that is stated in the write-up.

---

## Next

Web Security Academy labs (PortSwigger) — access control, authentication, business logic, injection.

---

**Jonathan KABORE** — Cybersecurity engineering student, UIR Rabat
Application security & payment systems security (BCEAO/UEMOA)
