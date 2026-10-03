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

# 2. Re-initialize version control (the template's history is not the case's)
rm -rf .git && git init

# 3. Drop evidence into evidences/ (keep original archives intact)
#    and put the case task list at evidences/Questions.md if you have one.

# 4. Inventory & hash evidence (chain of custody)
docker/dfir.sh bash -lc \
  'cd /data/evidences && find . -type f -exec sha256sum {} \; | sort -k2 \
   > /data/analysis/hashes_evidence.sha256'

# 5. Run a tool
docker/dfir.sh hayabusa dfir-timeline \
  -d /data/evidences/<HOST>/C/Windows/System32/winevt/Logs \
  -o /data/analysis/<HOST>/hayabusa_timeline.csv
```

## Wrapper usage

`docker/dfir.sh` enforces read-only evidence, ephemeral (`--rm`) containers,
non-root execution, and no network by default.

```sh
docker/dfir.sh [--net] [--image IMG] [--shell] <command> [args...]
```

Mounts:

- `/data/evidences` -> `evidences/` (read-only)
- `/data/analysis`  -> `analysis/` (read-write)
- `/data/reports`   -> `reports/`  (read-write)
- `/data/notes`     -> `notes/`    (read-write)
- `/data/tools`     -> `docker/`   (read-only)

## Tooling highlights

- **Windows:** EVTX (`evtx_dump_rs`, Hayabusa, Chainsaw, Sigma), `MFTECmd`,
  `PECmd`, `LECmd`, `JLECmd`, `SBECmd`, `AmcacheParser`,
  `AppCompatCacheParser`, `SrumECmd`, `RECmd`, `EvtxECmd`, `regipy`,
  `sqlite3`, `libesedb-utils`.
- **Linux / macOS:** `plaso` (`log2timeline.py`/`psort.py`), `mac_apt`,
  `sqlite3`, `util-linux`.
- **Disk images:** `sleuthkit`, `ewf-tools`, `libfsapfs-utils`,
  `libvmdk-utils`, `p7zip-full`.
- **Network:** `tshark`, `zeek`.
- **Memory:** `volatility3`.
- **Antivirus / EDR:** `clamscan` (ClamAV, signatures baked in — refresh with
  `freshclam`), `yara` + `yara-python` with the `signature-base` and
  `Yara-Rules` rule sets under `/opt/yara-rules`, plus the helpers
  `docker/av_triage.py` (YARA/ClamAV scanning) and `docker/av_parse.py`
  (Defender EVTX/text-log normalization).
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

## Not included

- **APOLLO** (macOS unified-archive parsing) — omitted to avoid the Swift
  toolchain. Add it as a separate Docker layer if needed.
- **AV quarantine decoders** — encoded quarantine containers (Windows Defender
  `RBRC`/resource-data, Sophos, Symantec, ESET, CrowdStrike) are not decoded.
  AV *logs, detections and exclusions* are handled; recovering the quarantined
  file bytes is not.
