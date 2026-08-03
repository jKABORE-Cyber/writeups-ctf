# TryHackMe — SOC Simulator: Alert Triage & Investigation

**Path:** SOC Level 1
**Room:** SOC Simulator
**Modules covered:** Introduction to Phishing · SOC L1 Alert Triage · SOC L1 Alert Reporting
**Tools used:** SIEM Dashboard, Splunk (SPL), Analyst VM
**Difficulty:** Easy → Medium
**Author:** Jonathan KABORE ([@jKABORE-cyber](https://github.com/jKABORE-cyber))

---

## Table of Contents

- [Overview](#overview)
- [Methodology: The Five Ws](#methodology-the-five-ws)
- [Scenario 1 — Dashboard Triage (Introduction to Phishing)](#scenario-1--dashboard-triage-introduction-to-phishing)
  - [Alert: Potential Data Exfiltration](#alert-potential-data-exfiltration)
  - [Alert: Double-Extension File Creation](#alert-double-extension-file-creation)
  - [Alert: Download from GitHub Repository](#alert-download-from-github-repository)
- [Scenario 2 — Deep Dive with Splunk (SOC L1 Alert Triage/Reporting)](#scenario-2--deep-dive-with-splunk-soc-l1-alert-triagereporting)
  - [Alert: Spoofed Microsoft Teams Phishing Email](#alert-spoofed-microsoft-teams-phishing-email)
  - [Alert: Spike of Domain Discovery Commands](#alert-spike-of-domain-discovery-commands)
- [Scenario 3 — Multi-Vector Phishing Campaign](#scenario-3--multi-vector-phishing-campaign)
  - [Attack Chain Diagram](#attack-chain-diagram)
  - [Alert 8814/8818 — HR Onboarding Impersonation](#alert-88148818--hr-onboarding-impersonation)
  - [Alert 8815 — Amazon Delivery Phishing](#alert-8815--amazon-delivery-phishing)
  - [Alert 8816 — Firewall Block](#alert-8816--firewall-block)
  - [Alert 8817 — Fake Microsoft Credential Phishing](#alert-8817--fake-microsoft-credential-phishing)
- [Key Takeaways](#key-takeaways)
- [Remediation Summary](#remediation-summary)

---

## Overview

This write-up documents a full SOC Level 1 alert-triage exercise completed on TryHackMe's **SOC Simulator**, which recreates a realistic SOC analyst workflow: monitoring a live alert dashboard, investigating suspicious activity using a SIEM (Splunk), classifying alerts as **True Positive** / **False Positive**, writing structured analyst comments, and escalating confirmed incidents according to a defined workflow.

The exercise covered three progressively complex scenarios: basic dashboard triage, SIEM-driven deep-dive investigation, and correlation of a multi-vector phishing campaign spanning several employees.

## Methodology: The Five Ws

Every alert investigated in this room was documented using the **Five Ws** framework, a structured approach that ensures no critical context is missed during triage:

| Question | Purpose |
|---|---|
| **Who** | Source/destination users, hosts, or identities involved |
| **What** | The nature of the activity/artifact that triggered the alert |
| **When** | Timestamp and sequence of events |
| **Where** | Network segment, host, or delivery point |
| **Why** | The reasoning behind the True/False Positive verdict |

---

## Scenario 1 — Dashboard Triage (Introduction to Phishing)

The first scenario introduces the SOC dashboard interface. The objective is to close all **True Positive** alerts to pass.

### Alert: Potential Data Exfiltration

| Field | Value |
|---|---|
| Severity | Critical |
| Rule | 5+ GB sent from a single device to a single destination in a day |
| Destination | `*.zoom.us` |
| Source | `192.168.45.66` — `UK04/MEETINGROOM` |
| Sent / Received | 5.8 GB / 5.2 GB |

**Verdict: False Positive**

A conference room device generating several GB of traffic toward a legitimate video-conferencing domain (Zoom) is expected behavior — not anomalous. The volume is consistent with a normal audio/video/screen-share session, and the destination is a known, trusted SaaS provider.

### Alert: Double-Extension File Creation

| Field | Value |
|---|---|
| Severity | High |
| Host | `LPT-HR-009` |
| Process | `chrome.exe` |
| User | `S.Conway` |
| Target file | `C:\Users\S.Conway\Downloads\cats2025.mp4.exe` |
| Source URL | `freecatvideoshd.monster` |
| MD5 | `14d8486f3f63875ef93cfd240c5dc10b` |

**Verdict: True Positive**

The file `cats2025.mp4.exe` uses a classic **double-extension masquerade** technique to disguise an executable as a harmless video file. Combined with a low-reputation, typosquat-style domain (`freecatvideoshd.monster`), this is a textbook social-engineering/malware-delivery attempt targeting a non-technical (HR) user.

### Alert: Download from GitHub Repository

| Field | Value |
|---|---|
| Severity | Low |
| URL | `github.com/facebook/react` |
| User | `G.Chandler` |
| Host | `LPT-IT-063` |
| Network | `VPN/DEVELOPERS` |

**Verdict: False Positive**

A well-known, legitimate open-source repository, accessed by a developer over the corporate VPN's developer subnet — activity fully consistent with the user's role.

---

## Scenario 2 — Deep Dive with Splunk (SOC L1 Alert Triage/Reporting)

This scenario introduces the **Analyst VM** and **Splunk** as the SIEM of choice (SPL query language), used to pivot from a raw alert to supporting log evidence.

### Alert: Spoofed Microsoft Teams Phishing Email

| Field | Value |
|---|---|
| Severity | Medium |
| Subject | "Important Update: Microsoft Teams Pricing Increase" |
| Sender | `Microsoft Support <support@microsoft.com>` |
| Recipient | `Eddie Huffman, IT Manager <e.huffman@tryhackme.thm>` |
| Security checks | SPF: **Fail** / DKIM: **Fail** |
| Attachment | `REPORT.rar` |

**Verdict: True Positive — Phishing**

Both **SPF and DKIM failures** confirm the sender domain is spoofed; the message did not genuinely originate from `microsoft.com`. This is reinforced by urgency-based language ("600% price increase," "urgent notice") and a compressed `.rar` attachment — a common technique to smuggle malicious executables past mail/AV filters.

### Alert: Spike of Domain Discovery Commands

| Field | Value |
|---|---|
| Severity | Medium (escalated as Critical impact) |
| Host | `DMZ-MSEXCHANGE-2013` (Windows Server 2012 R2) |
| User | `NT AUTHORITY\SYSTEM` |
| Commands | `whoami`, `net group "Domain Admins" /domain`, `nltest /dclist:tryhackme.thm` |
| Process chain | `w3wp.exe` → `C:\Users\Public\revshell.exe` → `cmd.exe` |

**Verdict: True Positive — Active Compromise**

The process lineage tells the whole story: the IIS/Exchange worker process (`w3wp.exe`) spawned a binary explicitly named `revshell.exe` from a public user folder, which then ran Active Directory reconnaissance commands under `SYSTEM` privileges. This is consistent with **exploitation of an internet-facing Exchange server**, followed by a reverse shell and AD enumeration in preparation for lateral movement / privilege escalation.

```
Attacker (Internet)
        │
        ▼
  DMZ-MSEXCHANGE-2013  (Windows Server 2012 R2, internet-facing)
        │  exploit of IIS/Exchange (w3wp.exe)
        ▼
  C:\Users\Public\revshell.exe   (dropped reverse shell)
        │  spawns
        ▼
  cmd.exe   (NT AUTHORITY\SYSTEM)
        │  runs
        ▼
  whoami | net group "Domain Admins" /domain | nltest /dclist:tryhackme.thm
        │
        ▼
  Active Directory reconnaissance → lateral movement risk
```

**Escalation:** Yes — immediate host containment recommended given SYSTEM-level compromise on a DMZ-facing server.

---

## Scenario 3 — Multi-Vector Phishing Campaign

The final scenario simulates a real-world SOC pivot: a cluster of related "Inbound Email Containing Suspicious External Link" alerts, plus a corroborating firewall block, that together reveal a single coordinated phishing campaign against multiple employees.

### Attack Chain Diagram

```
                     ┌─────────────────────────────┐
                     │   Phishing Campaign Wave     │
                     │   (multiple lures, 1 actor)  │
                     └──────────────┬───────────────┘
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                           ▼
 HR Onboarding lure          Amazon delivery lure         Microsoft security lure
 onboarding@hrconnex.thm     urgents@amazon.biz           no-reply@m1crosoftsupport.co
 → j.garcia (x2: 8814, 8818) → h.harris (8815)             → c.allen (8817)
                                     │
                                     ▼
                          h.harris clicks bit.ly link
                                     │
                                     ▼
                     Firewall blocks connection (8816)
                     dest 67.199.248.11:80 — BLOCKED
```

### Alert 8814/8818 — HR Onboarding Impersonation

| Field | Value |
|---|---|
| Sender | `onboarding@hrconnex.thm` (spoofed) |
| Recipient | `j.garcia@thetrydaily.thm` (new hire) |
| Subject | "Action Required: Finalize Your Onboarding Profile" |
| Link | `https://hrconnex.thm/onboarding/15400654060/j.garcia` |
| Occurrences | 07:13:18 (8814) and 07:19:17 (8818, resend) |

**Verdict: True Positive**

`hrconnex.thm` is confirmed as the company's **legitimate** third-party HR vendor — but an internal email from `h.harris` to IT (07:14:51) confirms the *real* onboarding email from this vendor **never arrived**. This proves the message received by `j.garcia` is an impersonation of a trusted, expected sender, exploiting the onboarding process of a new employee who is less familiar with internal procedures — a textbook targeted social-engineering / vendor-impersonation attack.

### Alert 8815 — Amazon Delivery Phishing

| Field | Value |
|---|---|
| Sender | `urgents@amazon.biz` (not `amazon.com`) |
| Recipient | `h.harris@thetrydaily.thm` |
| Subject | "Your Amazon Package Couldn't Be Delivered – Action Required" |
| Link | `http://bit.ly/3sHkX3da12340` |
| Time | 07:16:31 |

**Verdict: True Positive**

Fake TLD (`.biz`), generic greeting, urgency tactic, and a link-shortener used to obscure the true destination — all classic mass-phishing indicators.

### Alert 8816 — Firewall Block

| Field | Value |
|---|---|
| Time | 07:17:45 (~76s after alert 8815) |
| Source host | `10.20.2.17` |
| Destination | `67.199.248.11:80` |
| URL | `http://bit.ly/3sHkX3da12340` |
| Action | **Blocked** |

**Verdict: True Positive**

The blocked URL is **identical** to the one sent in the Amazon phishing email (8815), and the timing (~1 minute later) strongly indicates the recipient clicked the link. The firewall/threat-intel feed successfully prevented the connection from completing — no confirmed compromise, but confirmed user interaction with malicious content.

### Alert 8817 — Fake Microsoft Credential Phishing

| Field | Value |
|---|---|
| Sender | `no-reply@m1crosoftsupport.co` (typosquat: "1" instead of "i") |
| Recipient | `c.allen@thetrydaily.thm` |
| Subject | "Unusual Sign-In Activity on Your Microsoft Account" |
| Link | `https://m1crosoftsupport.co/login` |

**Verdict: True Positive**

A fake "suspicious sign-in" alert designed to panic the user into visiting a credential-harvesting login page hosted on a lookalike domain.

---

## Key Takeaways

- **Severity ≠ priority alone** — a Critical exfiltration alert (Zoom) turned out to be a false positive, while a "Medium" phishing email led to confirmed active compromise. Context always outweighs the raw severity label.
- **Process lineage is gold** for validating suspected compromise (`w3wp.exe → revshell.exe → cmd.exe` told the entire story of the Exchange server incident).
- **SPF/DKIM checks** are a fast, reliable first signal for spoofed-sender phishing.
- **Correlating independent alerts** (a phishing email + a firewall block sharing the same shortened URL, minutes apart) turned four "isolated" medium-severity alerts into one clear, escalation-worthy campaign.
- **Multi-vector campaigns** targeting different employees with different lures (HR onboarding, delivery notice, account security) are a deliberate strategy to maximize the odds that at least one target engages.

## Remediation Summary

- Block all identified malicious sender domains/addresses at the mail gateway (`hrconnex.thm` impersonation, `amazon.biz`, `m1crosoftsupport.co`).
- Blocklist the shortened URL (`bit.ly/3sHkX3da12340`) and its resolved destination IP at the firewall/proxy.
- Isolate and investigate host `DMZ-MSEXCHANGE-2013` for full compromise scope; patch/harden the internet-facing Exchange server.
- Notify affected users (`j.garcia`, `h.harris`, `c.allen`) and confirm no credentials or data were submitted.
- Search mail logs organization-wide for additional recipients of the same campaign.
- Reinforce phishing-awareness training, with emphasis on onboarding-themed and delivery-themed lures for new hires.

---

*Note: this exercise was completed as part of the TryHackMe SOC Level 1 learning path to build hands-on SOC analyst triage, SIEM investigation, and incident reporting skills.*
