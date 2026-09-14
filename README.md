# EDR Alert Triage: Investigating Three Endpoint Detections Across a Corporate Fleet

**TryHackMe, Introduction to EDR | Core SOC Solutions Module | SOC Level 1 Path | July 2026**

Triaging four live detections in an EDR console across a 55 host environment, using only the visibility the endpoint tooling provides.

**[Read the full report with all 11 screenshots (PDF)](EDR-Alert-Triage.pdf)** for the original document exactly as written, with every figure.

---

## Goal

This lab placed me in the role of a SOC analyst at a company (TECH THM) with access to the EDR console. The environment had 55 active hosts and four new medium and high severity detections waiting in the queue. The objective was to triage each detection using only the visibility the EDR provides: read the alert summaries, walk the process chains, review the indicators of compromise, and answer investigation questions about what actually happened on each endpoint.

The bigger goal was learning to use an EDR console the way analysts use one daily: knowing which tab holds which type of evidence, reading parent child process relationships, and understanding why the EDR flagged each activity, whether through behavioral detection, threat intelligence matching, or anomaly detection.

## Tools used

- EDR console (browser based simulation within TryHackMe)
- Process chain and process tree analysis
- Indicators of Compromise review: file paths, hashes, domains, IP addresses, registry keys
- MITRE ATT&CK framework (tactic and technique mapping, for example T1566.001, T1003.001)
- Threat intelligence context provided within each detection

## What I did

Reviewed the EDR dashboard for the environment: 55 active hosts, 4 new detections, with detection sources spanning anomaly, behavior, and threat intelligence.

Assessed the alert queue and the detections by tactics trend, noting alerts across four hosts covering Initial Access, Execution, Persistence, and Credential Access activity.

Opened the high severity detection on DESKTOP-HR01 (Initial Access via Malicious Office Document) and read the behavior summary, MITRE mapping, and detection confidence. Walked the process chain (WINWORD.EXE, CMD.EXE, cURL.EXE, INSTALL.EXE) and confirmed the payload download tool and the dropped file location from the IOC table.

Opened the high severity detection on WIN-ENG-LAPTOP03 (Credential Dumping via LSASS Memory Access) and analyzed the suspicious `syncsvc.exe` process card: its command line, registry persistence, and attempted exfiltration URL.

Opened the medium severity detection on DESKTOP-DEV01 (Execution from AppData Directory) and evaluated why a file labelled clean by threat intelligence was still flagged based on its location and behavior.

Answered all investigation questions correctly using evidence pulled from the Summary, Process Info, and IOC tabs of each detection.

Reviewed the Actions and Response options available in the console (isolate host, terminate process, quarantine file, collect artifact, remote shell) to understand the response capabilities, which were outside the scope of this room.

## Investigation summary

### Detection 1: Initial Access via Malicious Office Document (DESKTOP-HR01, High)

The summary told the story clearly. User alice.thomas opened a macro enabled document, `invoice.docm`, using WINWORD.EXE. The macro launched CMD, which used cURL to download a payload from an external domain. The file was saved to disk but never executed, which the EDR described as behavior consistent with malware staging. In practical terms, the weapon was smuggled in and parked, but not yet fired, so the detection caught the attack before detonation.

The risk assessment mapped the activity to MITRE ATT&CK: tactic Initial Access, technique **T1566.001 (Spearphishing Attachment)**, with a confidence score of 95. The process chain confirmed the flow: WINWORD.EXE (spawned by explorer.exe, meaning the user opened the file herself) started CMD.EXE, which launched cURL.EXE, which pulled down INSTALL.EXE.

Notably, Word itself was labelled a clean Microsoft binary by threat intel. **Every program in the chain was legitimate. The unusual parent child sequence was what made it malicious.**

The IOC table completed the picture. The payload `install.exe` was dropped at `C:\Users\Public\install.exe` and quarantined, the download domain `ayebd[.]thm` was identified as a C2 server and blocked, the source IP `1.161.138[.]92` was logged, and the original lure document was quarantined in the user's Downloads folder.

### Detection 2: Credential Dumping via LSASS Memory Access (WIN-ENG-LAPTOP03, High)

On the second host, an unsigned executable named `syncsvc.exe` was running from `C:\Users\haris.khan\AppData\Local\Temp`, a user writable temp directory, which is a classic staging location because it requires no admin rights. Its command line left nothing to interpretation:

```
syncsvc.exe -ma lsass.exe C:\Users\Public\dump_2025.dmp
```

The process took a full memory dump of `lsass.exe`, the Windows process that holds credentials in memory, and wrote it to disk. Threat intelligence matched the file to a known credential dumping tool, mapped to **MITRE T1003.001 (LSASS Memory)**.

The process card also showed dual persistence: the tool registered itself both as a Windows service (`HKLM\SYSTEM\CurrentControlSet\Services\syncsvc`) and in the user Run key (`HKCU\...\Run\syncsvc`), so it would survive reboots even if one mechanism was discovered.

The most important finding was the exfiltration attempt. The tool tried to upload the credential dump to `hxxps://files-wetransfer[.]com/upload/session/ab12cd34ef56/dump_2025.dmp` over port 80. **The domain imitates the legitimate WeTransfer file sharing service**, a lookalike chosen so the traffic would blend in as normal file sharing. The upload was blocked by the EDR and the C2 IP `100.42.28[.]64` was blocked by the firewall, meaning the credentials were dumped locally but never left the network.

### Detection 3: Execution from AppData Directory (DESKTOP-DEV01, Medium)

The third detection was the most instructive. `UpdateAgent.exe` was flagged running from `C:\Users\daniel.richards\AppData\Roaming`, unsigned, and making an outbound HTTP connection to an internal address on port 8080. Threat intelligence labelled the file itself as a "Known internal IT utility tool". In other words, the file was clean.

The EDR flagged it anyway, because context matters. Legitimate IT utilities are deployed to Program Files by IT teams and signed. They do not run unsigned from a user's roaming profile. This is either a real tool brought in and abused by an attacker, which is living off the land, or unauthorized use. Both deserve analyst attention.

Together, the three detections showed three different detection philosophies working side by side: **behavioral detection** caught the unknown malware on DESKTOP-HR01 through its process chain, **threat intelligence matching** caught the known credential dumper on WIN-ENG-LAPTOP03, and **anomaly and context based detection** flagged a clean labelled tool on DESKTOP-DEV01 because of where and how it ran.

## Results and findings

**DESKTOP-HR01.** A spearphishing attachment (`invoice.docm`) used a macro to launch CMD and cURL, downloading `install.exe` from a C2 domain to `C:\Users\Public\`. The payload was caught at the staging phase and never executed. The domain was blocked and both files quarantined.

**WIN-ENG-LAPTOP03.** An unsigned credential dumping tool (`syncsvc.exe`) running from a user Temp folder dumped LSASS memory to `dump_2025.dmp`, established dual registry persistence, and attempted to exfiltrate the dump to a lookalike WeTransfer domain. The exfiltration was blocked. The stolen credentials never left the network.

**DESKTOP-DEV01.** A file labelled clean by threat intelligence (`UpdateAgent.exe`) was correctly flagged based on context: unsigned, running from AppData\Roaming, and making an unexpected outbound connection. Clean file, suspicious circumstances.

**Verification.** All investigation questions were answered correctly on the evidence: the download tool (cURL.exe), the payload path, the syncsvc.exe path, the full exfiltration URL, and the threat intel label.

**Key insight.** Advanced attacks chain legitimate tools (Word, CMD, cURL), and detection often lives in the relationships and context, not in any single malicious file.

## Skills demonstrated

- EDR console navigation and endpoint detection triage
- Process tree and parent child process analysis
- Command line analysis and living off the land technique recognition
- Indicators of Compromise analysis: file paths, hashes, domains, IPs, registry keys
- MITRE ATT&CK mapping (T1566.001 Spearphishing Attachment, T1003.001 LSASS Memory)
- Credential access and data exfiltration investigation
- Persistence mechanism identification (registry Run keys, Windows services)
- Behavioral, anomaly, and threat intelligence based detection concepts
- Evidence based investigation and analytical thinking
- Security documentation with defanged indicators

## What I learned

The biggest lesson from this lab is that in modern attacks, almost nothing malicious looks malicious on its own. Word is clean. CMD is clean. cURL ships with Windows. Even `UpdateAgent.exe` had a clean threat intel label. What made each detection real was the relationships and the context: a document spawning a shell, a known good tool running unsigned from a user profile, a "sync service" reaching into LSASS memory. I now instinctively read process chains asking who started whom, and why.

I also learned to navigate an EDR console with intent instead of wandering. Each tab answers a different kind of question: the Summary gives the story, Process Info gives the actions and command lines, and the IOC tab gives the fingerprints. Once I understood that, finding evidence stopped being a search and became a routine. The full exfiltration URL, for example, was never going to be in the IOC table, because a URL with its path is something the malware did, and actions live on the process card.

Finally, the three detections together made the detection theory from this room concrete. Behavioral detection, threat intelligence matching, and anomaly detection are not abstract categories anymore. I watched each one catch a different attack that the others might have missed. That layered thinking is something I will carry into SIEM investigations and, eventually, into a real SOC seat.
