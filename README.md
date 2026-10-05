# DFIR Workspace Template

A **container-only** digital forensics and incident response (DFIR) workspace
template. It ships a tri-OS forensic toolchain (Windows, Linux, macOS, plus
network and memory analysis) and a strict evidence-handling discipline. Copy it
per case; the evidence never leaves the read-only mount.

## What's inside

| Path | Role | Writable |
|---|---|---|
| `evidences/` | Raw, original evidence (disk images, EVTX, PCAP, memory dumps, registry hives, archives). Immutable. | No |
| `analysis/` | Derived/parsed output: JSON, CSV, Zeek logs, timelines, hashes. | Yes |
| `reports/` | Final write-ups and deliverables. | Yes |
| `notes/` | Working notes and scratch. | Yes |
| `docker/` | Toolchain image (`Dockerfile`) and wrapper (`dfir.sh`). Reusable. | Yes |
| `skills/` | Agent skill definitions (`dfir`, `incident-handler`). Reusable. | Yes |
| `.opencode/` | Agent definitions (`incident-handler`) and commands (`analyse`, `reset-case`). Reusable. | Yes |
| `opencode.jsonc` | OpenCode config: registers `skills/`, auto-starts the Incident Handler. | Yes |
| `reset_case.sh` | Reset the workspace for a new case (dry-run by default). Reusable. | Yes |

See `CLAUDE.md` for the full workspace guide and hard rules, and
`AGENTS.md` for the always-on agent summary.

## Prerequisites

- Docker (with build + run rights).
- ~3 GB free disk for the image (plaso, the Zimmerman suite, and parsers are
  large).

## Build the image

```sh
docker build -t dfir-toolkit docker/
```

## Bootstrap a new case

This template is used **manually** — copy it, then work inside the copy.

```sh
# 1. Copy the template to a new case directory
cp -r ~/Documents/DFIR_Workspace_template ~/Cases/<case-name>
cd ~/Cases/<case-name>
```

## Guided analysis (Incident Handler agent)

`opencode.jsonc` registers the template's `skills/` with OpenCode and sets the
**Incident Handler** primary agent as the default, so a new `opencode` session
inside a case copy starts in guided mode.

The agent loads `skills/incident-handler`, reads the case task list, and walks
the analyst through the engagement one step at a time — objective, the exact
`docker/dfir.sh` command, what to look for, and which task it answers — while
delegating parsing mechanics to the `dfir` skill. It keeps a running
`analysis/task_tracking.md` and denies edits under `evidences/`.

### Quick start: `/analyse`

Once evidence is in `evidences/`, start the pipeline with the slash command
**`/analyse`** (defined in `.opencode/commands/analyse.md`). It runs in the
default **Incident Handler** agent and injects the standard objective, so you
don't have to pick the agent or restate the goal:

> Analyse the evidence and produce an incident timeline

It is the entry point to the analyst pipeline once evidence is dropped. The
command hands that objective to the guided flow — intake and task tracking,
chain-of-custody hashing, triage, parsing, correlation, the UTC timeline, the
visuals/dashboard and the final report — and walks it **one step at a time**,
each step presented as **Objective → exact `docker/dfir.sh` command → what to
look for → what it concludes**.

**Placement:** inside OpenCode (Incident Handler agent). It takes no arguments;
to steer a specific host or task, state it in the prompt.

To use a different agent for a session, pick it from the agent switcher; the
default only affects new sessions.

### Example session

Start the default **Incident Handler** agent and give it the case prompt:

> Analyse the evidence and produce an incident timeline.

The agent then walks the engagement one step at a time; for this prompt it
suggests:

1. **Intake** — read `evidences/Questions.md`, inventory hosts and evidence
   types, and open `analysis/task_tracking.md`.
2. **Chain of custody** — SHA-256 every evidence file into `analysis/hashes/`
   (before and after analysis).
3. **Triage** — Hayabusa/Chainsaw Sigma + ATT&CK pass per host; separate
   adversary activity from responder/forensic-tool activity.
4. **Parse** — export per-source EVTX to JSON, `$MFT` to CSV, PCAP to Zeek,
   registry hives to CSV, and build a `plaso` super-timeline.
5. **Correlate** — consolidate a UTC super-timeline and cross-verify each
   finding against a second independent artifact (log ↔ PCAP ↔ `$MFT`).
6. **Timeline** — assemble the consolidated UTC attack chain (the incident
   timeline deliverable).
7. **Visualize / dashboard** — render `reports/viz/*` and
   `reports/dashboard.html` from `analysis/iocs.json`, the timeline and Zeek.
8. **Report** — write the deliverable to `reports/` with per-task answers,
   evidence citations, defanged IOCs, ATT&CK mapping and gaps/unknowns.

Each step is presented as **Objective → exact `docker/dfir.sh` command → what
to look for → what it concludes and the next step**.

## Reset for a new case

`reset_case.sh` clears the case-specific content (evidence, `analysis/`,
`reports/`, `notes/`) while preserving the reusable template (`docker/`,
`skills/`, `.opencode/`, docs, and every `.gitkeep`). It is **dry-run by
default** — nothing is deleted until you pass `--yes`.

> This deliberately overrides the workspace rule "do not delete evidence". It is
> a **template reset only**: archive any evidence you still need first, and
> **never run it on a live case mid-investigation**.

```sh
./reset_case.sh                  # dry-run: show exactly what would be removed
./reset_case.sh --yes            # apply the reset
./reset_case.sh --yes --keep-evidence   # keep evidences/, reset the rest
./reset_case.sh --yes --scrub-refs      # also genericize leftover case examples
./reset_case.sh --yes --reset-git       # also rm -rf .git && git init
```

It auto-detects the case name from `analysis/iocs.json` / the report title, and
after cleaning scans the reusable tree for residual case references and warns.
The same operation is available as the slash command **`/reset-case`** inside
OpenCode (analyst or agent): it runs the dry-run, asks for confirmation, then
applies. `/reset-case --keep-evidence` passes flags through.

## Wrapper usage

`docker/dfir.sh` enforces read-only evidence, ephemeral (`--rm`) containers,
non-root execution, no network by default, and a hardened container (all Linux
capabilities dropped, `no-new-privileges`, a `noexec/nosuid/nodev` `/tmp` tmpfs,
and pids/memory/cpu limits).

```sh
docker/dfir.sh [--net] [--image IMG] [--shell] [--privileged-cap] \
               [--no-hardening] <command> [args...]
```

- `--privileged-cap` adds `SYS_ADMIN` + `/dev/fuse` + `apparmor:unconfined`;
  needed only for the read-only VMFS/VMDK mounts (`vmfs-fuse`, `qemu-nbd`).
- `--no-hardening` disables the hardening flags (last resort).
- Limits default to 4 GB / 4 CPUs and a 2 GB `/tmp`; override with
  `DFIR_MEM` / `DFIR_CPUS` / `DFIR_TMP_SIZE`.

Build reproducibility: Python packages are pinned in `docker/constraints.txt`.

Mounts:

- `/data/evidences` -> `evidences/` (read-only)
- `/data/analysis`  -> `analysis/` (read-write, also `/data/out`)
- `/data/reports`   -> `reports/`  (read-write)
- `/data/notes`     -> `notes/`    (read-write)
- `/data/tools`     -> `docker/`   (read-only)

## Tooling highlights

- **Windows:** EVTX (`evtx_dump_rs`, Hayabusa, Chainsaw, Sigma), `MFTECmd`,
  `PECmd`, `LECmd`, `JLECmd`, `SBECmd`, `AmcacheParser`,
  `AppCompatCacheParser`, `SrumECmd`, `RECmd`, `EvtxECmd`, `regipy`,
  `sqlite3`, `libesedb-utils`.
- **Linux / macOS:** `plaso` (`log2timeline.py`/`psort.py`), `mac_apt`
  (macOS plists, unified logs, FSEvents), `sqlite3`, `util-linux`,
  `linux_proctree.py` (process tree from a `/proc` snapshot + systemd
  journal/`auth.log` → JSON/CSV/DOT/HTML/SVG/PNG).
- **Disk images:** `sleuthkit`, `ewf-tools`, `libfsapfs-utils`,
  `libvmdk-utils`, `p7zip-full`.
- **Network:** `tshark`, `zeek`.
- **Memory:** `volatility3`.
- **ESXi / VMware:** `vmfs-tools`, `vmfs6-tools`, `qemu-utils` (VMFS datastore
  and VMDK access) plus the helper `docker/esxi_triage.py` (support-bundle log
  parser, analyser and hunter).
- **Antivirus / EDR:** `clamscan` (ClamAV, signatures baked in — refresh with
  `freshclam`), `yara` + `yara-python` with the `signature-base` and
  `Yara-Rules` rule sets under `/opt/yara-rules`, plus the helpers
  `docker/av_triage.py` (YARA/ClamAV scanning) and `docker/av_parse.py`
  (Defender EVTX/text-log normalization).
- **IOC export & schema:** `docker/ioc_export.py` turns a structured
  `analysis/iocs.json` (or `.yaml`) observable list into a flat
  `analysis/iocs.csv` for SIEM/CTI ingestion; `--exclude-benign` yields a
  threat-intel-only view, `--validate` enforces the schema (exit 1 on errors),
  and duplicate `(type,value)` observables are dropped by default. The shared
  schema (`docker/ioc_schema.py`) defines the allowed types, defanging and
  validation. The optional `endpoints` block names hosts and sets dashboard
  ordering. Schema in `skills/dfir`; reference example (never loaded) in
  `skills/dfir/examples/iocs.example.json`.
- **IOC drafting:** `docker/ioc_collect.py` scans the parsed artifacts (EVTX
  TSV, `$MFT`/`$J` CSV, Zeek) and proposes a de-duplicated, defanged
  `analysis/iocs_draft.json` — review, enrich, then save as `analysis/iocs.json`.
  Internal/private IPs are tagged `internal,benign` by default.
- **Timeline consolidation:** `docker/merge_timeline.py` folds parsed artifacts
  into the normalized `time_utc,host,actor,event,technique,evidence,tags` CSV
  consumed by `incident_viz.py` / `incident_dashboard.py` — an EVTX→EID map
  (4624/4688/4769/7045/1102/…), file events from `$MFT`/`$J`, and Zeek
  `http`/`dns`/`smb_mapping`/`kerberos` (+ optional `conn`) events, each with a
  MITRE technique and a source citation. `--all-evtx` emits every event.
  `--ip-map` maps IP/FQDN/alias → display name (the IOC `endpoints` block works
  directly); host labels are normalised via `docker/hostmap.py` — an IP is never
  truncated, an FQDN becomes its first label, and link-local/multicast/broadcast
  hosts become `Network` (dropped by default). `incident_viz.py` and
  `incident_dashboard.py` accept the same `--ip-map`.
- **Artifact queries:** three case-free helpers speed up fact extraction —
  `docker/evtx_query.py` (filter a flattened EVTX TSV by EID/time/field/regex),
  `docker/mft_query.py` (query MFTECmd `$MFT` **or** `$J`/USN CSV by
  name/extension/time/reason), and `docker/pcap_objects.py` (carve protocol
  objects from a PCAP with `tshark` and emit a SHA-256 manifest).
- **Chain of custody:** `docker/custody.py` hashes every evidence file into
  `analysis/hashes/<label>.sha256` (plus a JSON manifest) and `verify`
  re-hashes and compares, exiting non-zero on any change — so "hash before and
  after" is two commands instead of manual shell. Run it via
  `docker/dfir.sh python3 /data/tools/custody.py hash|verify …`.
- **Toolkit self-test:** `docker/selftest.sh` runs `docker/tests/run_selftest.py`
  against synthetic fixtures in `docker/tests/fixtures/` (no case evidence) —
  a regression gate after changing a helper.
- **Case signatures:** the tools contain **no case-specific patterns**. Any
  engagement-specific detection pattern (random dropper names, responder
  tooling, actor aliases) goes in an optional `analysis/signatures.json`,
  auto-loaded when present (`--signatures PATH` to override). Wiping `analysis/`
  on reset means it never survives into the next case. See
  `skills/dfir/examples/signatures.example.json`.
- **Visualization:** `docker/incident_viz.py` renders an attack timeline,
  actor/network graph and MITRE ATT&CK matrix from `analysis/iocs.json`, a
  normalized timeline CSV (or a Markdown chain table via `--from-markdown`) and
  Zeek logs. Output is single-file, offline HTML (JS inlined from
  `/opt/viz-assets`) plus optional static SVG/PNG, written to `reports/viz/`.
  Example in `skills/dfir`.
- **Endpoint dashboard:** `docker/incident_dashboard.py` aggregates the same
  artifacts into **one** self-contained HTML (`reports/dashboard.html`) with a
  client-side **endpoint filter** across every panel — timeline, actor graph,
  process tree, observables, IOCs and the ATT&CK matrix — plus an Overview and a
  global "All endpoints" view. Process trees come from flattened Security 4688
  (`--proc`), correlated by PID + time so PID reuse across reboots does not
  merge unrelated processes. See "Endpoint dashboard" below.
- **Coverage manifest:** `/opt/forensic-artifacts` — the ForensicArtifacts YAML
  catalog of artifact *locations*. It is a checklist, not a parser.

## Antivirus / EDR analysis

Two helpers cover AV work. Both read evidence read-only and write only to
`analysis/`.

**1. File-level scanning** (`av_triage.py`) — YARA against the vendored rule
sets and an optional ClamAV signature scan:

```sh
docker/dfir.sh python3 /data/tools/av_triage.py \
  --clamav --json /data/analysis/av/yara_hits.json \
  /data/evidences/<HOST>
```

Exit code `1` means matches were found. Rule sets live at
`/opt/yara-rules/{signature-base,yara-rules}`; override with `--rules DIR`.
ClamAV ships with a signature database baked into the image (refresh it with
`docker/dfir.sh freshclam` when network is enabled).

**2. AV telemetry normalization** (`av_parse.py`) — Windows Defender
operational records and `MPLog-*.log`/`MPDetection-*.log` into a flat TSV:

```sh
# EVTX -> JSONL first
docker/dfir.sh evtx_dump_rs -o jsonl \
  '/data/evidences/<HOST>/C/ProgramData/Microsoft/Windows Defender/Operational.evtx' \
  > /data/analysis/<HOST>/defender_operational.jsonl
docker/dfir.sh python3 /data/tools/av_parse.py \
  --out /data/analysis/<HOST>/av_timeline.tsv \
  /data/analysis/<HOST>/defender_operational.jsonl \
  '/data/evidences/<HOST>/C/ProgramData/Microsoft/Windows Defender/Support/MPLog-*.log'
```

Handled artifacts (per `skills/dfir/SKILL.md`): `MicrosoftAVLogs`,
`MicrosoftAVQuarantine` (records), `WindowsDefenderScanDetectionHistoryFiles`,
`WindowsDefenderExclusions`. **Not decoded:** quarantined/encoded file
containers (Defender RBRC, Sophos/Symantec/ESET stores) — see "Not included".

## ESXi / VMware analysis

`esxi_triage.py` parses a VMware ESXi support bundle (`vm-support` `.tgz`),
a bare log directory (`/var/log`, `/var/run/log`) or a single log, producing a
normalized timeline plus categorized security findings.

```sh
docker/dfir.sh python3 /data/tools/esxi_triage.py \
  --out /data/analysis/esxi --datastore /data/evidences/vmfs \
  /data/evidences/vm-support-XXXX.tgz
```

Outputs (in `--out`):

- `timeline.csv` — one row per interesting log line (`time_utc`, `source_log`,
  `line_no`, `component`, `severity`, `category`, `event`, `user`, `src_ip`,
  `detail`, `raw`).
- `findings.json` — findings with `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` severity.
- `summary.txt`, `coverage.json` (which of the `esxi.yaml` artifacts were
  present), and `av_hits.json`/`av_result.json` when the YARA/ClamAV handoff runs.

Exit code `1` if any `HIGH`/`CRITICAL` finding exists. Detection content:

- **Authentication** — SSH logon/logoff, invalid user/failures, root SSH,
  WebUI logon (VCSA/`VMware-client` filtered), password changes.
- **Execution** — `shell.log` commands, `esxcli`, `rhttpproxy` clients, SFTP
  transfers, `exec denied`, unsigned-binary execution prevented.
- **Integrity / config** — SSH enable/disable, VIB acceptance-level change,
  ESXi shell / admin-access toggles, account create/delete.
- **Ransomware** — extensions (`.esxiargs`, `.babyk`, `.royal`, `.blackbasta`,
  `.akira`, `.alphv`, `.enc`, `.locked`, …), ransom notes, suspicious scripts
  (`encrypt.sh`, `ksmd`, `autobackup.bin`), VMDK deletion, and
  `vmware_local.sh` persistence in `/etc/rc.local.d/`.
- **VM-escape CVEs** — OpenSLP/427, CD-ROM (CVE-2021-22045), VMCI/vSock
  (CVE-2022-31696), VMware Tools guest ops/UNC3886 (CVE-2023-20867), USB
  controller (CVE-2024-22252/3/4).

Mount VMFS datastores / VMDKs read-only for file-level review:

```sh
docker/dfir.sh --privileged-cap vmfs-fuse -o ro /data/evidences/datastore /mnt/vmfs   # 5.x/6.x
docker/dfir.sh --privileged-cap qemu-nbd --read-only -c /dev/nbd0 /data/evidences/disk.vmdk
```

> ESXi logs are text, so plaso's generic `syslog` parser does not understand
> the `Hostd[...]`/`vobd[...]` grammar — `esxi_triage.py` is the parser for
> this data.

## Linux process tree

`linux_proctree.py` builds a process tree and process-event timeline for a
Linux host from a UAC/LinuxCatScale-style triage bundle. It combines two
complementary views:

- **Snapshot** — the exact parent/child tree from the collection instant,
  using `/proc/<pid>/status` `PPid` and `ps -axwwSo` (no inference needed).
  Enriched with `/proc/<pid>/cmdline`, `exe` links and SHA-1 hashes.
- **Journal** — best-effort historical process events from the systemd journal
  (`journalctl --file`/`-D`, read offline) plus pid-tagged `auth.log`/`syslog`
  lines (`sudo`, `su`, `sshd`, `CRON`, `systemd`).

> This host's journal carries **no `_PPID`** and there is no `auditd`/memory
> image, so journal parentage is *inferred* (cgroup/unit + a time-aware
> PID-reuse rule). Snapshot edges are `exact`; journal edges are `inferred`.

```sh
docker/dfir.sh linux_proctree \
  --snapshot /data/analysis/extracted/<HOST>/catscale_out/Process_and_Network \
  --logdir   /data/analysis/extracted/<HOST>/catscale_out \
  --host <HOST> --tz "+02:00" \
  --since 2025-12-26T00:40:00Z --until 2025-12-26T05:30:00Z \
  --out /data/analysis/<HOST>/proctree --title "<HOST> process tree" \
  --formats json,csv,dot,html,svg,png
```

Outputs to `--out`: `proctree.json` (nodes + edges with provenance),
`proctree.csv` / `process_events.csv` (flat), `proctree.dot` (Graphviz) and,
when requested, `proctree.svg`/`.png` (via `dot`) and `proctree.html` (single
offline file, vis-network inlined from `/opt/viz-assets`). `--all` ignores the
window; `--logdir` auto-discovers the journal tar and text logs.

## Incident visualization

`incident_viz.py` renders analyst-facing diagrams from artifacts you have
already produced — no new parsing, no network. The visuals are **deliverables**,
so they are written beside the report (default convention `reports/viz/`). It
reads the structured IOC list, a normalized timeline, and/or Zeek logs and
writes to `--out`:

- `attack_timeline.{html,svg,png}` — swimlane timeline per host, colored by tag.
- `actor_graph.{html,svg,png}` — attacker/victim hosts, accounts, payloads and
  observed network edges (from Zeek `conn`/`http`/`smb_mapping`/`kerberos`/`ntlm`).
- `mitre_matrix.{html,svg,png}` — ATT&CK tactic grid from the IOCs' `mitre` field.
- `timeline.csv`, `timeline.json`, `graph.json` — machine-readable intermediates.

```sh
# From an existing Markdown chain table (bootstraps timeline.csv):
docker/dfir.sh python3 /data/tools/incident_viz.py \
  --iocs /data/analysis/iocs.json \
  --from-markdown /data/reports/incident_timeline.md \
  --zeek /data/analysis/network/zeek \
  --out /data/reports/viz --formats html,svg,png

# Once reports/viz/timeline.csv exists, feed it back directly:
docker/dfir.sh python3 /data/tools/incident_viz.py \
  --iocs /data/analysis/iocs.json \
  --timeline /data/reports/viz/timeline.csv \
  --zeek /data/analysis/network/zeek \
  --out /data/reports/viz
```

The HTML is a **single self-contained file** — the vis.js bundles are inlined
from `/opt/viz-assets` at render time, so it opens in any browser with no
network and no server. Static `--formats svg,png` are embeddable in the report
(`matplotlib`/`networkx`). Pass `--date YYYY-MM-DD` when the source report only
contains bare `HH:MM` times; without it the helper tries to infer the incident
date from the report and the IOCs.

## Endpoint dashboard

`incident_dashboard.py` combines the timeline, actor graph, process trees,
observables, IOCs and the ATT&CK matrix into **one** offline HTML with a
client-side **endpoint filter** — so an analyst can answer "what happened on
this host?" without cross-referencing separate files. "All endpoints" is the
global view.

The simplest way to build it is the wrapper, which discovers every input
(including one `--proc` per `Security.tsv`) so nothing is omitted:

```sh
docker/build_dashboard.sh --strict          # title taken from iocs.json
docker/build_dashboard.sh --title "Case" --strict
```

Or call the generator directly:

```sh
docker/dfir.sh python3 /data/tools/incident_dashboard.py \
  --iocs     /data/analysis/iocs.json \
  --timeline /data/analysis/timeline.csv \
  --attack-timeline /data/analysis/attack_timeline.csv \
  --zeek     /data/analysis/network/zeek \
  --proc     /data/analysis/<HOST>/evtx/Security.tsv \
  --proc     /data/analysis/<HOST2>/evtx/Security.tsv \
  --out      /data/reports --title "Incident report"
```

`--ip-map` names hosts and must be either the IOC `endpoints` block or a JSON
map in this shape (a flat `{"key": {"name": ...}}` object is also accepted):

```json
{"endpoints": {
  "10.0.0.30": {"name": "DC01", "role": "victim", "order": 3,
                "aliases": ["dc01", "dc01.corp.example"]}}}
```

`--attack-timeline` is the **curated attack-chain** CSV (same
`time_utc,host,actor,event,technique,evidence,tags` schema). When supplied (or
when `analysis/attack_timeline.csv` exists) the timeline opens on **only those
suspect/malicious events**; the full `--timeline` stays available behind the
`all events` selector. With no curated file the timeline falls back to the full
set. Observe/derive rules still apply (`Rec=`/`EID=` anchors + distinctive
values), and `first/last seen` are back-filled from cited evidence.

Outputs `reports/dashboard.html`, ``reports/report.html`` and
`reports/dashboard_data.json` (the embedded payload, for reuse). `--layout`
selects `dashboard` (tabbed), `document` (single-scroll report) or `both`
(default).

Two complementary all-in-one layouts are produced from the same data:

- **`dashboard.html` (tabbed)** — the narrative Markdown report as a leading
  **Report** tab (pass `--report-md /data/reports/incident_report.md`;
  headings/tables/blockquotes/lists render and relative images are inlined as
  data URIs; `--report-base` overrides the image directory).
- **`report.html` (document)** — the report rendered inline followed by every
  data section in one scrolling page (Overview, Timeline, Actor graph, Process
  trees, Observables, IOCs, ATT&CK), a sticky table-of-contents with
  scroll-spy, and a **filter bar per section** (endpoint **chips**, free-text
  search, hide-benign) so each graph can be scoped independently. Pass
  `--embed name=path` to drop an extra self-contained HTML (e.g. the standalone
  `proctree.html`) in as an `<iframe srcdoc>` section.

- **Endpoint filter** — chips for each host; `All endpoints` = global view.
  Every tab respects it, and there is a free-text search plus a
  "hide benign/responder" toggle.
- **Per-endpoint attribution** — observables carry a `hosts: [...]` field;
  when absent it is inferred from the entry's `source`/`context` text.
- **Process trees** — built from flattened Security 4688 (`--proc`, repeatable)
  and/or a Linux snapshot (`--proc-linux`, a `proctree.json` from
  `linux_proctree.py`, repeatable). Parentage is resolved by **PID + time**
  (parent must not post-date the child), so a PID reused after a reboot does not
  graft unrelated processes together. Trees keep attacker-relevant processes,
  their ancestor chain and descendants; identical leaf roots (e.g. 15
  `wevtutil cl` calls) are collapsed with ×N. The Linux path carries exact
  snapshot `PPid`; journal-inferred edges stay in the standalone
  `proctree.html`.
  - **`--proc` is auto-discovered** from `analysis/*/evtx/tsv/Security.tsv`
    when omitted, so the panel is never silently empty. `--no-proc-autodiscover`
    disables it; `--strict` exits non-zero when process sources exist but no
    trees are produced (e.g. a host label that does not map to a known
    endpoint).
  - A tree host that is not a declared endpoint is **dropped with a warning** —
    add the FQDN/short-name to the `--ip-map` `endpoints` `aliases` so it maps
    to the display name.
- Panels: **Overview**, **Timeline**, **Actor graph**, **Process trees**,
  **Observables** (all, incl. benign), **IOCs** (benign removed), **ATT&CK**.
- **Timeline scoped to the attack chain** — the timeline opens on the **curated
  attack chain** (`attack chain` mode, from `--attack-timeline`) and can be
  switched to `all events`. Identical rows can be collapsed (`×N`) or shown
  individually (`rows` selector). The panel has a **bounded height with vertical
  scrolling** (the time axis stays pinned at the top and bottom); `−`/`+` zoom
  (clamped to the displayed rows so timestamps never leave the incident window),
  `Ctrl+wheel` zooms, `⟲ recenter` fits the displayed events, `⛶ full screen`
  expands it. The `Timeline events` stat follows the active mode.
- **First/last seen** — an observable with no `first_seen_utc` is back-filled at
  build time from cited evidence (an ISO timestamp in `source`/`context`, else
  the timeline row carrying its `Rec=`, else the earliest linked event). Derived
  values are marked `*` in the table (hover shows the reference); nothing is
  guessed when no evidence supports it.

## Not included

- **APOLLO** (macOS unified-archive parsing) — omitted to avoid the Swift
  toolchain. Add it as a separate Docker layer if needed.
- **AV quarantine decoders** — encoded quarantine containers (Windows Defender
  `RBRC`/resource-data, Sophos, Symantec, ESET, CrowdStrike) are not decoded.
  AV *logs, detections and exclusions* are handled; recovering the quarantined
  file bytes is not.
