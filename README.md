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

![First Query](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/Flag1.png)

---

## Flag 2 - Interactive Remote Access Established
### Hunt Lead

"This account isn't being used by someone sitting at the billing desk. Its successful sessions are a different kind of logon entirely. Give me the logon type."

### Objective

Determine how the compromised account authenticated to the environment and whether the observed logon activity was consistent with the user's normal role or indicative of unauthorized remote access.

### Investigation

Following identification of the compromised account (j.morris), the investigation pivoted from failed authentication events to successful logons recorded in DeviceLogonEvents. The objective was to determine how the attacker transitioned from unsuccessful authentication attempts to an active session within the environment.

Filtering for successful authentication events associated with the compromised account revealed that each successful session used the RemoteInteractive logon type rather than a standard interactive workstation logon. This logon type is commonly associated with technologies such as Remote Desktop Protocol (RDP), Remote Assistance, or other remote interactive session mechanisms, allowing a user to control a system from another location.

For a billing department employee whose daily responsibilities are expected to occur from an assigned workstation, repeated RemoteInteractive sessions represent a notable deviation from expected behavior. While remote interactive logons can be legitimate in environments that support remote work or IT administration, their occurrence immediately following repeated failed authentication attempts significantly increases the likelihood of unauthorized account use.

The successful remote sessions also served as the starting point for the attacker’s subsequent activity, including system reconnaissance, network enumeration, and access to sensitive business data documented throughout the remainder of this investigation.

### Evidence

*Artifact	Value
*Account	j.morris
*Log Source	DeviceLogonEvents
*ActionType	LogonSuccess
*Logon Type	RemoteInteractive
*Investigation Window	March 1–30, 2026

### Analysis

The transition from failed network authentication attempts to successful RemoteInteractive logons strongly suggests that the attacker successfully authenticated using valid credentials and established an interactive session on the target workstation.

Unlike automated malware or scripted attacks, RemoteInteractive sessions provide an attacker with direct control of the system, enabling them to manually execute commands, browse directories, and interact with resources as though they were physically present at the workstation. This observation is significant because it establishes that the attacker was operating in an interactive, hands-on manner rather than relying solely on automated tools.

Although the logon type alone does not confirm malicious activity, its correlation with the previously identified failed authentication attempts and the reconnaissance activity observed immediately afterward provides strong evidence that the account was being used by an unauthorized operator.

This finding also establishes the beginning of the attack lifecycle reconstructed throughout this report, linking the initial credential compromise to the subsequent Discovery, Lateral Movement, and Collection phases.

MITRE ATT&CK Mapping
Tactic	Technique	Rationale
Initial Access	T1078 – Valid Accounts	The attacker authenticated using legitimate user credentials.
Lateral Movement	T1021 – Remote Services	The RemoteInteractive session indicates the use of remote access services to establish an interactive session.

### Risk Assessment

*Severity: High

A successful RemoteInteractive logon using a compromised user account provides an attacker with the same capabilities as a legitimate user, allowing unrestricted interaction with the operating system within the permissions of that account. Because these sessions often resemble normal administrative activity, they can evade traditional signature-based detection if behavioral monitoring is not in place.

### Detection Opportunities

The following detections could have identified this activity earlier:

Alert on RemoteInteractive logons originating from uncommon or external IP addresses.
Detect user accounts transitioning from repeated failed logons to successful RemoteInteractive sessions within a short timeframe.
Establish behavioral baselines for remote logon activity by department and alert on deviations.
Correlate RemoteInteractive logons with immediate execution of reconnaissance commands such as whoami, hostname, net, or nslookup.

### Conclusion

The investigation confirmed that the compromised j.morris account established RemoteInteractive sessions, indicating that the attacker had successfully gained interactive remote access to the environment using valid credentials. This finding marks the transition from initial compromise to active post-compromise operations and provides the foundation for the reconnaissance, network discovery, and data collection activities examined in the subsequent findings.

### Query

   ```kql
   DeviceLogonEvents
| where DeviceName startswith "nh-"
| where AccountName == "j.morris" 
| where AccountDomain == "nimbus"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-30))
| project TimeGenerated, AccountName, ActionType, LogonType, AccountDomain, RemoteIP
```

![Second Query](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/Flag2.png)

---

## Flag 3 – External Source of Remote Access Identified
