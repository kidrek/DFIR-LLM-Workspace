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
- **Coverage manifest:** `/opt/forensic-artifacts` — the ForensicArtifacts YAML
  catalog of artifact *locations*. It is a checklist, not a parser.

## Not included

- **APOLLO** (macOS unified-archive parsing) — omitted to avoid the Swift
  toolchain. Add it as a separate Docker layer if needed.
