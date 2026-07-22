# Threat-Hunt-Just-Another-Day

![image](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/JustAnotherDay.png)

**Participant:** Jared Riskus

**Date:** July 21, 2026

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 11-Based System

**Languages/Tools:**

* Kusto Query Language (KQL) for querying Device Logon Events, Device Process Events, and persistence artifacts

---

## Scenario 

From: Hunt Lead // Cyber Range SOC
To: Threat Hunt // On-Shift
Re: Nimbus Health // billing account posture review
Your shift starts with a routine one. Nimbus Health, a small outpatient clinic we support, asked for a posture review after a billing account showed some odd activity. The paperwork calls it a stale-access housekeeping check. Read it as an investigation anyway, and let the telemetry decide what it actually is.

The account in question belongs to a billing analyst. On paper, submissions work, nothing more. In the logs, that account is doing things a billing analyst has no business doing, and it's being used in a way that should make you look twice at where it's being used from.

What we need you to work out:

   · Whether this is really a curious employee, or something else
   · What the account did that falls outside its role
   · What sensitive material it reached, and where that material ended up
   · Whether it stayed on one machine, or moved
   · The honest root cause, once you've seen the evidence

Everything is in the law-cyber-range Sentinel workspace, MDE tables: DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceEvents. Authentication, process and file activity each live in their own table. The story only appears when you pivot across them.

Filter, or drown. This is a shared workspace. Bound every query to the March window and scope to the Nimbus hosts: where DeviceName startswith "nh-" and a time filter across 08-18 March 2026. There is a later, separate incident on the same estate. If your results run into May, or into accounts you don't recognise, you've lost the filter.
One thing to hold from the start. The clinic wants this written up as an insider who forgot to hand back some access. Don't accept that on trust. Some of the strongest evidence here is about where the account is being driven from, and some of it is about what you don't find. Follow the logs, not the paperwork.

Work it end to end. Reconstruct what the account did, in order. Reason where the evidence is thin. There's noise in here that looks like activity and isn't, learn to cut it. Then give the honest read.

Section 00 is a gate. Confirm you're set up on the right workspace, scoped to the right window and hosts, before you start. The phrase to submit is in this brief: Nimbus review ready. Acknowledge it, then begin.

Get hunting.

---

## Flag 1 — Identification of the Compromised Account
## Hunt Lead

"The review flagged one billing account behaving oddly. Name it. That's who you're following."

### Objective

Identify the billing department account responsible for the suspicious authentication activity and establish the primary investigative pivot for the threat hunt.

### Investigation

The investigation began by reviewing failed network authentication events recorded in DeviceLogonEvents during the investigation window. Several billing accounts experienced failed authentication attempts; however, one account displayed a distinct pattern that warranted additional investigation.

The account j.morris exhibited repeated failed network logons followed by successful authentication events later in the investigation. Unlike the remaining billing users, this account immediately transitioned into interactive command execution and unauthorized resource access after successful authentication. This sequence of events strongly suggested that valid credentials had been compromised and were being used by an unauthorized individual.

### Evidence

* Artifact	Value
* Account	j.morris
* Log Source	DeviceLogonEvents
* Authentication Type	Network
* Investigation Window	March 1–30, 2026

### Analysis

The identification of j.morris established the starting point for the remainder of the investigation. All subsequent queries and investigative pivots focused on reconstructing activity performed under this account to determine attacker objectives, scope of compromise, and potential organizational impact.

The combination of repeated failed authentication attempts followed by successful access and immediate post-authentication reconnaissance is consistent with the use of compromised credentials rather than routine user behavior.

### MITRE ATT&CK
Tactic	Technique
Initial Access	T1078 – Valid Accounts
Assessment

### Severity: High

The compromised account represented the initial foothold used throughout the intrusion and served as the foundation for all subsequent attacker activity.

I think this is a strong foundation. Each of the remaining 19 findings can follow this same structure, giving you a cohesive, professional report rather than a collection of lab answers. In the next section, we'll build Finding 2, where we analyze the RemoteInteractive logon and establish how the attacker gained interactive access to the environment.

### Query

   ```kql
   DeviceLogonEvents
| where DeviceName startswith "nh-"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where isnotempty(AccountDomain)
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-30))
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP, AccountDomain
```

![First Query](
