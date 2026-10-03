# Skill: Incident Handler

Drive a DFIR engagement end-to-end: triage → scope → root cause → impact →
report. This skill owns task tracking, evidence standards and the deliverable;
it delegates parsing to the **dfir** skill.

## When to use
Any incident / CTF-IR scenario where a task list must be answered with
evidence, or a timeline + IOCs + report must be produced.

## Principles
- **No claim without evidence.** Every answer cites file + channel + record and
  a UTC timestamp.
- **Cross-verify.** Confirm each key finding against an independent artefact
  (log ↔ PCAP ↔ $MFT).
- **Reconstruct the kill chain**, not just individual events.
- **State uncertainty.** If two techniques fit, present the stronger one and
  note the alternative.
- **Defang IOCs** and separate windows.

## Engagement flow
1. **Intake** — read the task list (`evidences/Questions.md`), inventory hosts
   and evidence types.
2. **Chain of custody** — hash all evidence (see dfir skill).
3. **Triage** — Sigma/Hayabusa per host; identify malicious vs. benign/IR
   activity (note forensic-tool runs by the responder too).
4. **Root cause** — initial access, exploited service, first execution.
5. **Scope** — accounts, hosts, privileges, persistence, lateral movement.
6. **Impact** — data accessed/exfiltrated, credentials compromised.
7. **Timeline** — consolidated UTC attack chain.
8. **Report** — executive summary, per-task answers with evidence, IOCs,
   ATT&CK mapping, gaps/unknowns.

## Task-tracking template
For each question keep a row: `id | question | answer | evidence(file:record) |
UTC time | technique`. Answer only when the evidence field is filled.

## Evidence-citation standard
`<host> <channel> EID=<id> Rec=<n> <UTC> — "<raw field>"`.
Example: `WIN-01 Security EID=4688 Rec=12345 2024-01-01T12:00:00Z — C:\Windows\System32\cmd.exe /c whoami`.

## MITRE ATT&CK mapping
Tag each finding (e.g. T1190 Exploit Public-Facing App, T1059.001 PowerShell,
T1053 Scheduled Task, T1003 OS Credential Dumping, T1558.003 Kerberoasting,
T1021.002 SMB/PsExec, T1550.002 Pass the Hash, T1134 Access Token Manipulation,
T1071.001 Web Protocols, T1074 Data Staged, T1021 Remote Services,
T1087 Account Discovery, T1482 Domain Trust Discovery).

## Report template
1. Executive summary (what happened, when, impact).
2. Environment & evidence inventory (hashes).
3. Attack-chain timeline (UTC, per host).
4. Task answers (each with evidence citation).
5. IOCs (defanged): URLs, hashes, accounts, IPs, services, filenames.
6. ATT&CK coverage table.
7. Gaps, assumptions and unknowns.
8. Recommendations / containment.

## Hand-off
Parsing/EVTX/MFT/PCAP mechanics → **dfir** skill. This skill consumes its
outputs and owns the narrative and deliverable.
