# AvSuite Incident Response Playbook

## Overview

This playbook defines response procedures when AvSuite detects a threat.

---

## Severity Levels

| Level | Confidence | Examples | Response Time |
|-------|-----------|----------|----------------|
| **CRITICAL** | 95%+ | Shadow copy deletion, AV killer process | **5 minutes** |
| **HIGH** | 80-95% | Process injection, privilege escalation | **15 minutes** |
| **MEDIUM** | 60-80% | Suspicious registry writes, API hooks | **1 hour** |
| **LOW** | <60% | Encryption detected, potential FP | **Next business day** |

---

## Incident: Shadow Copy Deletion (CRITICAL)

**Trigger:** `rule_shadow_copy_delete` fires

**Confidence:** 95%+ (Ransomware classic)

### Immediate Actions (0-5 min)

```
1. ALERT & NOTIFY
   ├─ SOC team: Page on-call
   ├─ System owner: Immediate notification
   └─ Incident commander: Activate IR team

2. ISOLATE SYSTEM
   ├─ Disable network: Unplug from LAN
   ├─ Disable wireless: Disable WiFi/Bluetooth
   └─ Preserve evidence: No force shutdown

3. CONTAIN SPREAD
   ├─ Revoke domain credentials
   ├─ Disable VPN access
   └─ Block lateral movement paths
```

### Investigation (5-30 min)

```
1. COLLECT EVIDENCE
   ├─ System memory dump (vmss)
   ├─ Disk image (evidence preservation)
   ├─ AvSuite event log (SQLite)
   ├─ Windows Event Log export
   └─ Network traffic capture

2. ANALYZE
   ├─ What process deleted shadows? (PID, name, hash)
   ├─ When did it start? (timestamp correlation)
   ├─ What parent spawned it? (process tree)
   ├─ Where did it come from? (file origin, download)
   └─ What else did it do? (registry changes, files)

3. DETERMINE SCOPE
   ├─ Single system or multiple?
   ├─ Enterprise-wide or isolated?
   ├─ Production impact assessment
   └─ Data classification review
```

### Response Actions (30 min - 2 hours)

```
1. CONTAINMENT
   ├─ Kill malicious process (if safe)
   ├─ Terminate any spawned children
   ├─ Disable persistence mechanisms
   │  ├─ Remove registry Run keys
   │  ├─ Stop suspicious services
   │  └─ Delete scheduled tasks
   └─ Verify no lateral movement

2. PRESERVATION
   ├─ Backup system before remediation
   ├─ Preserve logs for forensics
   ├─ Document all findings
   └─ Chain of custody for evidence

3. ERADICATION
   ├─ Remove malware payload
   ├─ Patch vulnerable process
   ├─ Update detections if new TTP
   └─ Verify clean state
```

### Recovery (2-24 hours)

```
1. VERIFY CLEAN
   ├─ Boot into safe mode, scan
   ├─ Run full disk malware scan
   ├─ Check shadow copies recovered (VSS)
   └─ Verify system functionality

2. RESTORE
   ├─ If ransom paid: Obtain decryption key
   ├─ If not paid: Restore from clean backup
   ├─ Verify data integrity
   └─ Test application functionality

3. HARDEN
   ├─ Enable Volume Shadow Copy protection
   ├─ Implement backup immutability
   ├─ Increase monitoring sensitivity
   └─ Deploy additional detection
```

### Post-Incident (24+ hours)

```
1. ANALYSIS
   ├─ Root cause analysis (RCA)
   ├─ Attack timeline reconstruction
   ├─ Detection gaps identification
   └─ Learning document

2. IMPROVEMENT
   ├─ Update detection rules (if new malware)
   ├─ Patch exploited vulnerabilities
   ├─ Improve segmentation
   └─ Update incident playbook

3. COMMUNICATION
   ├─ Notification to affected users
   ├─ Legal/compliance notification (if data breach)
   ├─ Regulatory reporting (if required)
   └─ Stakeholder debrief
```

---

## Incident: Process Injection (HIGH)

**Trigger:** `rule_suspicious_parent_child` + `VirtualAllocEx` pattern

**Confidence:** 80-95%

### Immediate Actions (0-15 min)

```
1. ALERT & VALIDATE
   ├─ Check AvSuite confidence score
   ├─ Manual verification of parent-child relationship
   └─ False positive risk assessment

2. ISOLATION (if high confidence)
   ├─ Terminate malicious process
   ├─ Kill spawned child process
   └─ Preserve for forensics

3. INVESTIGATE
   ├─ What process was parent? (likely malware)
   ├─ What process was child? (legitimate app hijacked)
   ├─ What code was injected? (shellcode analysis)
   └─ Where did parent come from?
```

### Scope Determination

```
Is it targeted or widespread?

Single System:
├─ Likely: Targeted attack or local infection
├─ Response: Standard incident response
└─ Timeline: Normal SLA

Multiple Systems:
├─ Likely: Worm or mass malware
├─ Response: ESCALATE to incident commander
└─ Timeline: URGENT (activate incident war room)

Enterprise-wide:
├─ Likely: Supply chain, trojanized software
├─ Response: DECLARE MAJOR INCIDENT
└─ Timeline: CRITICAL (activate all IR resources)
```

---

## Incident: API Hooking Detected (MEDIUM)

**Trigger:** `rule_api_hooking` detects entry point modification

**Confidence:** 60-80% (some legitimate tools hook APIs)

### Analysis Required

```
1. VALIDATE NOT FALSE POSITIVE
   ├─ Check process: Is it debugger? (WinDbg, x64dbg, IDA)
   ├─ Check process: Is it monitoring tool? (Sysinternals, etc.)
   ├─ Check timing: Normal working hours? (admin tool)
   └─ If FALSE POSITIVE: whitelist and move on

2. IF MALICIOUS
   ├─ What APIs are hooked? (CreateProcessA, WriteFile, etc.)
   ├─ What is the hook doing? (monitoring, blocking, modifying)
   ├─ How stealthy is it? (can we detect all hooks?)
   └─ What's the attack goal?
```

### Response

```
MEDIUM confidence = Don't immediately kill

Instead:
├─ Enable logging for hooked APIs
├─ Monitor for suspicious behavior
├─ Collect more evidence
├─ Escalate if behavior matches malware pattern
└─ Or whitelist if confirmed legitimate
```

---

## Escalation Matrix

```
Detection Type        | Confidence | Severity | Auto-Action | Manual Review |
─────────────────────────────────────────────────────────────────────────
Shadow copy deletion  | 95%+       | CRITICAL | KILL + ISOLATE | Yes (5 min) |
Process hollowing     | 90%+       | CRITICAL | KILL + ISOLATE | Yes (5 min) |
Reflective DLL inject | 85%+       | HIGH     | KILL | Yes (15 min) |
Privilege escalation  | 80%+       | HIGH     | FLAG | Yes (30 min) |
API hooking           | 75%+       | MEDIUM   | FLAG | Yes (1 hour) |
Suspicious parent     | 70%+       | MEDIUM   | FLAG | Yes (1 hour) |
Encryption detected   | 60%+       | LOW      | ALERT | Yes (next day) |
```

---

## Forensics Checklist

When incident is detected, collect:

```
VOLATILE DATA (collect immediately):
├─ System memory dump (vmss or hiberfil.sys)
├─ Running processes (tasklist /v)
├─ Network connections (netstat -anob)
├─ Open files (openfiles /query)
├─ Event logs (Application, Security, System)
└─ AvSuite SQLite database

DISK DATA (after isolation):
├─ Full disk image (dd, FTK Imager)
├─ File system timeline (fls, tln)
├─ Registry hives (%systemroot%\System32\config)
├─ Prefetch files (C:\Windows\Prefetch)
├─ MFT (Master File Table analysis)
└─ Alternate data streams (ads)

ANALYSIS DATA:
├─ Hash malware samples (MD5, SHA256)
├─ VirusTotal submission
├─ Reverse engineering report
├─ Timeline reconstruction
└─ Indicator of Compromise (IoCs)
```

---

## Communication Template

### To Management

```
Subject: Security Incident Alert - [System] - [Date]

Impact:
- Affected systems: [list]
- Data at risk: [classification]
- Service impact: [up/down/degraded]
- Estimated recovery: [time]

Action Taken:
- System isolated
- Investigation ongoing
- Forensics collected
- Incident commander assigned

Next Steps:
- Investigation completion: [ETA]
- Remediation start: [ETA]
- Status updates: [frequency]
```

### To End Users

```
Subject: System Maintenance - [System] - [Date]

We've detected a potential security issue and temporarily disabled [system]
while we investigate. Your data is secure and backed up.

Timeline:
- Investigation: In progress
- Expected recovery: [time/date]
- Updates: [frequency]

Questions? Contact: [SOC email/phone]
```

### To Legal/Compliance (if data breach)

```
Incident Classification: [Type]
Date/Time Detected: [timestamp]
Scope: [systems/users affected]
Data Types: [PII/PHI/CC/Trade Secrets]
Notification Required: [Yes/No]
Regulatory Agencies: [GDPR/HIPAA/PCI/etc]
Timeline for Notification: [48-72 hours per law]
```

---

## Playbook Maintenance

Review and update quarterly:

```
QUARTERLY REVIEW:
├─ Update severity levels based on incident history
├─ Add new malware patterns discovered
├─ Improve response procedures based on lessons learned
├─ Test playbook accuracy with tabletop exercises
└─ Update contact information

ANNUAL REVIEW:
├─ Full playbook audit
├─ Run simulated incident drill
├─ Document lessons learned from real incidents
├─ Update recovery time estimates
└─ Refresh team training
```

---

**Version:** 1.0  
**Last Updated:** 2026-07-09  
**Maintained By:** Security Operations Center (SOC)
