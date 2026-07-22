## Threat-Hunt-Just-Another-Day

![image](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/JustAnotherDay.png)

**Participant:** Jared Riskus

**Date:** July 21, 2026

### Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace
* Windows 11-Based System

**Languages/Tools:**

* Kusto Query Language (KQL) for querying Device Logon Events, Device Process Events, and persistence artifacts

---

### Scenario 

* From: Hunt Lead // Cyber Range SOC
* To: Threat Hunt // On-Shift
* Re: Nimbus Health // billing account posture review
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

## Finding 1 — Identification of the Compromised Account

### Hunt Lead

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

* Tactic	Technique
* Initial Access	T1078 – Valid Accounts

### Assessment

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

## Finding 2 - Interactive Remote Access Established

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

* Artifact	Value
* Account	j.morris
* Log Source	DeviceLogonEvents
* ActionType	LogonSuccess
* Logon Type	RemoteInteractive
* Investigation Window	March 1–30, 2026

### Analysis

The transition from failed network authentication attempts to successful RemoteInteractive logons strongly suggests that the attacker successfully authenticated using valid credentials and established an interactive session on the target workstation.

Unlike automated malware or scripted attacks, RemoteInteractive sessions provide an attacker with direct control of the system, enabling them to manually execute commands, browse directories, and interact with resources as though they were physically present at the workstation. This observation is significant because it establishes that the attacker was operating in an interactive, hands-on manner rather than relying solely on automated tools.

Although the logon type alone does not confirm malicious activity, its correlation with the previously identified failed authentication attempts and the reconnaissance activity observed immediately afterward provides strong evidence that the account was being used by an unauthorized operator.

This finding also establishes the beginning of the attack lifecycle reconstructed throughout this report, linking the initial credential compromise to the subsequent Discovery, Lateral Movement, and Collection phases.

### MITRE ATT&CK Mapping

* Tactic	Technique	Rationale
* Initial Access	T1078 – Valid Accounts	The attacker authenticated using legitimate user credentials.
* Lateral Movement	T1021 – Remote Services	The RemoteInteractive session indicates the use of remote access services to establish an interactive session.

### Risk Assessment

* Severity: High

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

## Finding 3 – External Source of Remote Access Identified

### Hunt Lead

"Here's what should stop you. Those remote sessions into the billing workstation are not coming from inside the clinic. Give me one of the sources they're coming from, and satisfy yourself it isn't an internal address."

### Objective

Determine the source IP address associated with the successful RemoteInteractive sessions and assess whether the connections originated from a trusted internal network or an external source.

### Investigation

After confirming that the compromised j.morris account established successful RemoteInteractive sessions, the investigation focused on identifying the source of those connections. Using the same DeviceLogonEvents query developed during Finding 2, attention shifted to the RemoteIP field to determine the origin of the authenticated sessions.

Review of the authentication logs identified the remote source IP address 193.36.225.245 as the origin of the successful logons. The address did not correspond to an internal Nimbus Healthcare network and was observed during the same timeframe as the suspicious authentication activity.

Because the successful remote sessions originated from an external address rather than the organization's internal infrastructure, the likelihood of legitimate employee activity was significantly reduced. Combined with the previously observed failed authentication attempts and subsequent interactive command execution, the evidence supports the conclusion that the attacker successfully authenticated from outside the corporate network using valid credentials.

### Evidence

* Artifact	Value
* Account	j.morris
* Log Source	DeviceLogonEvents
* Logon Type	RemoteInteractive
* Remote Source IP	193.36.225.245
* Authentication	Successful Remote Logon

### Analysis

The identification of an external source IP represents a critical milestone in the investigation because it establishes that the suspicious authentication activity originated from outside the organization's trusted environment.

While remote access from external IP addresses can be legitimate when employees connect through approved remote access solutions, the source material does not indicate that 193.36.225.245 belongs to an approved corporate network or VPN infrastructure. Accordingly, the investigation treats it as an external source associated with the suspicious activity, rather than attributing it to a known trusted service.

When viewed alongside the evidence from the previous findings, the attack sequence becomes clearer:

Multiple failed authentication attempts occurred.
The attacker successfully authenticated using the j.morris account.
The successful sessions originated from an external IP address.
The attacker immediately began interactive reconnaissance using native Windows utilities.

This progression is consistent with an external actor gaining access through compromised credentials and beginning manual post-compromise operations.

### MITRE ATT&CK Mapping
* Tactic	Technique	Rationale
* Initial Access	T1078 – Valid Accounts	The attacker successfully authenticated using legitimate credentials.
* Lateral Movement	T1021 – Remote Services	Remote interactive access was established from an external source.

### Risk Assessment

* Severity: High

Successful authentication from an external IP address using a compromised account presents a significant security risk because it provides an attacker with direct access to internal resources while appearing as a legitimate user. Without behavioral monitoring or conditional access controls, this type of activity can blend into normal authentication traffic and delay detection.

### Detection Opportunities

The following monitoring capabilities could improve detection of similar activity:

Alert on successful RemoteInteractive logons originating from public IP addresses.
Correlate repeated authentication failures followed by a successful remote logon from the same account.
Generate alerts for user accounts authenticating from previously unseen source IP addresses.
Monitor for remote sessions that are immediately followed by execution of discovery commands such as whoami, hostname, or net.exe.
Enrich authentication logs with IP reputation and geolocation data to provide additional context during investigations.

### Conclusion

The investigation identified 193.36.225.245 as the source of the successful RemoteInteractive sessions associated with the compromised j.morris account. Based on the source material, the address was external to the organization's environment and was observed immediately before the attacker began reconnaissance activities. This finding strengthens the assessment that the activity originated from an unauthorized external actor using valid credentials rather than from routine internal user activity.

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
![Third Query](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/Flag%203%20.png)

---

## Finding 4 – Analysis of Initial Command-Line Activity

### Hunt Lead

"Sort the account's command-shell activity by time and the first thing you'll hit is a burst of deletions. Before you build a theory on it, tell me, is that the intruder, or is it noise? And say how you know."

### Objective

Analyze the earliest command-line activity associated with the compromised j.morris account to determine whether the observed deletion commands represented malicious attacker behavior or benign background activity.

### Investigation

Following confirmation that the j.morris account had been compromised, the investigation pivoted to DeviceProcessEvents to establish a chronological timeline of process execution. By sorting command-line activity in chronological order, the earliest commands associated with the compromised account were identified.

The first notable activity consisted of multiple executions involving the rmdir command. Because directory deletion can be associated with attacker efforts to remove evidence or destroy data, these commands were initially treated as suspicious and examined in the context of surrounding activity.

Further review of the process timeline did not indicate that the deletion commands targeted business documents, user profile data, payroll records, or other sensitive organizational assets. Instead, the activity appeared isolated and was not immediately followed by additional destructive behavior. Shortly afterward, the command history shifted to a deliberate sequence of reconnaissance commands—including whoami, hostname, and net utilities—that clearly marked the beginning of the attacker's interactive discovery phase.

Based on the available evidence, the initial deletion activity was assessed as unrelated to the intrusion and treated as environmental noise rather than malicious attacker activity.

### Evidence

* Artifact	Value
* Log Source	DeviceProcessEvents
* Account	j.morris
* Command Observed	rmdir
* Activity	Directory deletion commands
* Assessment	Benign background activity

### Analysis

One of the primary objectives during incident reconstruction is separating attacker actions from unrelated system activity. Although the rmdir command can be abused by attackers to delete files, remove staging directories, or eliminate forensic evidence, the evidence in this investigation does not support those conclusions.

Instead, the observed deletion activity lacked characteristics commonly associated with malicious cleanup, such as deletion of sensitive files, log tampering, or removal of attacker-created artifacts. More importantly, the attacker's observable behavior began only after these commands, when the compromised account initiated structured reconnaissance using native Windows utilities.

This distinction is important because attributing unrelated system activity to an attacker can lead to inaccurate timelines and incorrect conclusions. By identifying the rmdir executions as benign, the investigation maintained a more accurate reconstruction of the intrusion and ensured subsequent analysis focused on activity directly supporting the attack lifecycle.

### MITRE ATT&CK Assessment

* No MITRE ATT&CK technique was attributed to this finding.

Although directory deletion can map to techniques involving artifact removal in other investigations, the available evidence does not support attributing these specific rmdir executions to malicious activity. Therefore, they were intentionally excluded from ATT&CK mapping to avoid overstating the evidence.

### Risk Assessment

* Severity: Informational

The observed directory deletion commands were assessed as benign environmental activity and did not contribute to the attacker's objectives. Their significance lies in demonstrating the importance of validating suspicious events before incorporating them into the incident timeline.

### Detection Opportunities

Even though the activity was determined to be benign, similar commands can warrant investigation when accompanied by additional indicators of compromise. Detection opportunities include:

Monitor for rmdir or del commands executed immediately after privilege escalation or data staging.
Alert when directory deletion targets user profile directories, document repositories, or security log locations.
Correlate deletion commands with subsequent log clearing or evidence of anti-forensic behavior.
Review command execution in chronological context to distinguish legitimate maintenance activity from attacker actions.

### Conclusion

The initial rmdir commands observed for the j.morris account were investigated because directory deletion can indicate attempts to destroy evidence or remove files during an intrusion. However, based on the available telemetry, the commands were not associated with destructive actions against sensitive organizational data and preceded the attacker's identifiable reconnaissance activity. As a result, they were assessed as benign environmental noise and excluded from the reconstructed attack timeline, allowing the investigation to focus on the confirmed malicious actions that followed.

### Query 

   ```kql
DeviceProcessEvents
| where AccountName == "j.morris"
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-30))
| where InitiatingProcessCommandLine contains "rmdir"
| project TimeGenerated, AccountName, ActionType, InitiatingProcessCommandLine, ProcessCommandLine
```

![Fourth Query](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/Flag%204%20.png)

---

## Finding 5 – Initial Host and Network Reconnaissance

### Hunt Lead

"Past the noise, the account's operator runs a short, deliberate burst of native commands to get their bearings. Give me that sequence, in order."

### Objective

Identify the first deliberate command-line activity performed by the compromised account and determine what information the attacker was attempting to gather immediately after establishing remote access.

### Investigation

After excluding the earlier rmdir activity as benign environmental noise, the investigation continued by reviewing the chronological sequence of process execution associated with the compromised j.morris account. The next series of commands marked a clear shift from unrelated system activity to deliberate attacker reconnaissance.

The following native Windows commands were executed in rapid succession:

* whoami
* hostname
* net use
* net view \\NH-FS-01

This sequence demonstrates a structured approach to environmental discovery rather than random command execution. Each command builds upon the information obtained from the previous one, allowing the attacker to progressively understand the compromised system and identify accessible network resources.

### Evidence

#### Order	Command	Purpose

* 1	whoami	Identify the current security context and logged-on account.
* 2	hostname	Identify the name of the compromised workstation.
* 3	net use	Enumerate mapped network drives and existing network connections.
* 4	net view \\NH-FS-01	Enumerate resources shared by the targeted file server.

### Analysis

The observed command sequence reflects a disciplined reconnaissance workflow commonly associated with hands-on-keyboard intrusions. Rather than immediately attempting privilege escalation or data collection, the attacker first established situational awareness by identifying the current user context, confirming the compromised host, and determining which network resources were available.

The progression of commands is significant:

whoami confirmed the privileges and identity associated with the compromised account.
hostname identified the workstation from which the attacker was operating, helping correlate their position within the enterprise.
net use provided visibility into mapped drives and active network connections that could expose accessible file shares.
net view \\NH-FS-01 shifted the focus from the local workstation to a specific file server, indicating that the attacker had already identified a potentially valuable target for further investigation.

The deliberate order of execution suggests that the attacker was systematically preparing for the next phase of the intrusion. Rather than conducting broad, noisy scanning, the reconnaissance remained focused and leveraged trusted Windows utilities that are commonly present on enterprise systems.

### MITRE ATT&CK Mapping

* Tactic	Technique	Rationale
* Discovery	T1033 – System Owner/User Discovery	whoami identified the security context of the compromised account.
* Discovery	T1082 – System Information Discovery	hostname identified the compromised system.
* Discovery	T1135 – Network Share Discovery	net use and net view were used to identify accessible network resources and shared file locations.

### Risk Assessment

* Severity: High

Although no data was accessed during this phase, successful reconnaissance significantly increases an attacker's ability to navigate the environment efficiently. By collecting information about user context, host identity, and available network resources, the attacker reduced uncertainty and positioned themselves for targeted lateral movement and unauthorized data access.

### Detection Opportunities

The following detection opportunities could improve visibility into similar reconnaissance activity:

Alert on execution of whoami, hostname, net use, and net view by non-administrative users following remote interactive logons.
Correlate multiple reconnaissance commands executed within a short time window by the same account.
Monitor for net view targeting file servers containing sensitive business data.
Create behavioral analytics that identify unusual command sequences immediately following successful remote authentication.

### Conclusion

Following successful remote access, the attacker executed a concise sequence of native Windows reconnaissance commands to establish situational awareness within the environment. By identifying the active user context, confirming the compromised workstation, enumerating network connections, and targeting the NH-FS-01 file server, the attacker laid the groundwork for subsequent network discovery and unauthorized access to sensitive resources. This sequence represents the beginning of the Discovery phase of the intrusion and demonstrates a deliberate, hands-on approach to navigating the environment.

### Query 

   ```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-30))
| where ProcessCommandLine has_any ("net", "whoami", "hostname", "nslookup", "nltest")
| project TimeGenerated, AccountName, DeviceName, ActionType, ProcessCommandLine
```

![Query Five](https://github.com/jaredriskus1/Threat-Hunt-Just-Another-Day/blob/main/Flag%205.png)

---

## Finding 6 – Targeted File Server Reconnaissance

### Hunt Lead

"The recon wasn't aimless. The last discovery command names one system specifically. Which server were they lining up?"

### Objective

Determine whether the attacker transitioned from general host reconnaissance to identifying a specific network resource for further investigation and potential data access.

### Investigation

Following the initial reconnaissance sequence documented in Finding 5, the investigation focused on the final command executed during the attacker's discovery phase. Review of DeviceProcessEvents revealed that the attacker executed a targeted network enumeration command against the server NH-FS-01.

Unlike the previous commands (whoami, hostname, and net use), which gathered information about the compromised workstation and user context, the command:

net view \\NH-FS-01

explicitly targeted a known file server within the Nimbus Healthcare environment. This command requests a list of shared resources hosted by the specified system, allowing the attacker to identify directories that may contain valuable organizational data.

The progression from local host discovery to a specific network resource indicates that the attacker had completed their initial situational awareness and was beginning to identify high-value systems for follow-on activity.

### Evidence

* Artifact	Value
* Account	j.morris
* Log Source	DeviceProcessEvents
* Command	net view \\NH-FS-01
* Target System	NH-FS-01
* Activity	Network Share Enumeration

### Analysis

This finding represents the first indication that the attacker had identified a specific objective within the environment.

Rather than broadly scanning the network, the attacker directly queried NH-FS-01, suggesting they either had prior knowledge of the environment or had already identified the file server as a likely repository for business-critical information. This targeted approach reduced unnecessary network activity while enabling the attacker to efficiently locate accessible file shares.

The transition from generic host discovery to focused server reconnaissance illustrates a common progression observed during interactive intrusions:

* Establish access to the compromised workstation.
* Identify the current user and host.
* Determine available network connections.
* Identify high-value systems.
* Enumerate available resources before attempting access.

This behavior demonstrates deliberate planning rather than opportunistic exploration and sets the stage for the unauthorized access to billing and Human Resources data observed in later findings.

### MITRE ATT&CK Mapping

* Tactic	Technique	Rationale
* Discovery	T1135 – Network Share Discovery	The attacker enumerated shared resources on a specific file server using native Windows commands.

### Risk Assessment

* Severity: High

Targeted enumeration of enterprise file servers is a significant precursor to unauthorized data access. File servers often contain centralized repositories of sensitive information, making them high-value targets during post-compromise reconnaissance.

Although this activity alone did not modify or exfiltrate data, it substantially increased the attacker's understanding of the environment and enabled subsequent access to restricted business resources.

### Detection Opportunities

Organizations can improve visibility into similar activity by:

Monitoring execution of net view commands directed at critical file servers.
Correlating file server enumeration immediately following RemoteInteractive logons.
Alerting when non-administrative accounts enumerate enterprise file servers outside their normal responsibilities.
Creating behavioral detections for users transitioning from workstation reconnaissance to server enumeration within a short time period.

### Conclusion

The investigation determined that the attacker deliberately targeted the NH-FS-01 file server during the reconnaissance phase of the intrusion. By executing net view \\NH-FS-01, the attacker identified shared resources available on the server and prepared for subsequent access to sensitive billing and Human Resources data. This activity represents the transition from general environmental discovery to focused reconnaissance against a high-value organizational asset and marks the beginning of the attacker's movement toward data collection objectives.

### Query

   ```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-30))
| where ProcessCommandLine has_any ("net", "whoami", "hostname", "nslookup", "nltest")
| project TimeGenerated, AccountName, DeviceName, ActionType, ProcessCommandLine
```

![Query Six]()
