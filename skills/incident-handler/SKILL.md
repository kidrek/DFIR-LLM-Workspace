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
- **Promote reusable tooling.** When a bespoke parser/hunter is needed,
  generalize it — no hardcoded host names, IPs, dates or case strings. If it is
  broadly useful, save it under `docker/` (run via
  `docker/dfir.sh python3 /data/tools/<tool>.py`) so it survives `reset_case.sh`
  and is reusable next case. One-off, case-specific scripts stay in `notes/`.
  `docker/` must contain **zero case data** (see `docker/dfir_signatures.py`).
  After changing a helper, run `docker/selftest.sh` (fixtures under
  `docker/tests/fixtures/`) and extend it with a case-free check.

## Engagement flow
1. **Intake** — read the task list (`evidences/Questions.md`), inventory hosts
   and evidence types.
2. **Chain of custody** — hash all evidence (`docker/custody.py hash`), then
   `verify` after analysis and require exit 0 (see dfir skill).
3. **Triage** — Sigma/Hayabusa per host; identify malicious vs. benign/IR
   activity (note forensic-tool runs by the responder too).
4. **Root cause** — initial access, exploited service, first execution.
5. **Scope** — accounts, hosts, privileges, persistence, lateral movement.
6. **Impact** — data accessed/exfiltrated, credentials compromised.
7. **Timeline** — consolidated UTC attack chain.
8. **Visualize** — render the attack timeline, actor/network graph and ATT&CK
   matrix from the artifacts (`analysis/iocs.json`, the timeline table,
   Zeek logs) with `docker/incident_viz.py`; reference the HTML/SVG from the
   report (see dfir skill, workflow step 14).
9. **Endpoint dashboard** — build the single-file, filterable dashboard
   (`reports/dashboard.html`) with `docker/incident_dashboard.py`; it aggregates
   timeline, actor graph, process trees, observables, IOCs and the ATT&CK matrix
   and scopes them by endpoint (see dfir skill, workflow step 15).
10. **Report** — executive summary, per-task answers with evidence, IOCs,
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
5. IOCs (defanged): URLs, hashes, accounts, IPs, services, filenames —
   maintain `analysis/iocs.json` and export `analysis/iocs.csv` (+
   `analysis/iocs_threatintel.csv`) via `docker/ioc_export.py` (see dfir skill).
   Tag internal/benign/responder observables `benign` so they are excluded from
   the threat-intel view.
6. ATT&CK coverage table (see also the generated `mitre_matrix.html`).
7. Visual deliverables — attack timeline and actor/network graph
   (`reports/viz/*.html`, `*.svg`) from `docker/incident_viz.py`.
8. Gaps, assumptions and unknowns.
9. Recommendations / containment.

## Hand-off
Parsing/EVTX/MFT/PCAP mechanics → **dfir** skill. This skill consumes its
outputs and owns the narrative and deliverable.
