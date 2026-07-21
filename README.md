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

## Threat Hunting Process
