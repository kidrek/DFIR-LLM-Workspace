#!/usr/bin/env python3
"""linux_proctree.py -- process tree + process-event timeline for a Linux host.

Part of the container-only DFIR workspace. Built for UAC/LinuxCatScale-style
triage collections (e.g. the `catscale_app01-*` bundle) where the live /proc
state and the systemd journal are captured but auditd was NOT running and there
is no memory image. It reconstructs two complementary views:

  SNAPSHOT  exact parent/child tree from the collection instant
            (``/proc/<pid>/status`` -> PPid, ``ps -axwwSo``)
  JOURNAL   best-effort historical process events from the systemd journal and
            auth.log/syslog (pid-tagged sudo/su/sshd/CRON/systemd lines)

Outputs (to ``--out``):

  proctree.json        nodes + edges with provenance (source file/record)
  proctree.csv         flat nodes
  process_events.csv   flat journal/auth events
  proctree.dot         Graphviz source (clustered by user)
  proctree.html        single-file offline vis-network graph (assets inlined)

Stdlib only. `journalctl`, `jq` and the vis.js assets are baked into the image;
if the assets are missing the HTML still renders the tree as nested tables.

Design notes / limitations (surfaced again in the JSON and HTML):
  * The `/proc` snapshot is a single instant. Processes that ran and exited
    during the incident are absent, and a snapshot PPid can reflect reparenting
    after the real parent died.
  * The journal does NOT record ``_PPID`` on this host (all null), so journal
    parentage is *inferred* from ``_SYSTEMD_UNIT`` / cgroup / session and a
    time-aware PID-reuse rule (reusing incident_dashboard.py's approach).
  * With no auditd there is no complete exec-level history.
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone, timedelta

UTC = timezone.utc

# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _load_asset(name: str) -> str:
    p = os.path.join(os.environ.get("DFIR_VIZ_ASSETS", "/opt/viz-assets"), name)
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def short(s, n=220) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def decode_cmdline(raw: str) -> str:
    """cmdline dumps use NUL separators; render as a readable command line."""
    raw = raw.replace("\x00", " ").rstrip()
    return re.sub(r"\s+", " ", raw).strip()


def parse_tz(tz: str) -> timezone:
    """Accepts 'UTC', '+02:00', '-0500', 'local'. Defaults to UTC."""
    tz = (tz or "UTC").strip()
    if tz.upper() in ("UTC", "Z", "GMT", ""):
        return UTC
    if tz.lower() == "local":
        off = datetime.now().astimezone().utcoffset() or timedelta(0)
        return timezone(off)
    m = re.match(r"^([+-])(\d{1,2}):?(\d{2})$", tz)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    return UTC


def syslog_ts_to_utc(line: str, tz: timezone, now: datetime) -> str:
    """'Dec 26 00:57:20 host proc[pid]: ...' -> ISO-8601 UTC, inferring year."""
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", line)
    if not m:
        return ""
    mon = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7,
           "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}[m.group(1)]
    year = now.year
    try:
        dt = datetime(year, mon, int(m.group(2)),
                      *map(int, m.group(3).split(":")), tzinfo=tz)
    except ValueError:
        return ""
    # if parsing as "this year" lands well in the future, it belongs to last year
    if dt - now > timedelta(days=2):
        dt = dt.replace(year=year - 1)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_usec(usec: str, tz: timezone) -> str:
    try:
        dt = datetime.fromtimestamp(int(usec) / 1_000_000, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
# snapshot inputs  (/proc/<pid>/status + ps)
# --------------------------------------------------------------------------- #
def parse_status_details(path: str) -> dict[int, dict]:
    """Parse a concatenated `/proc/<pid>/status` dump -> {pid: fields}."""
    out: dict[int, dict] = {}
    cur: dict = {}

    def flush():
        if cur.get("pid") is not None:
            out[cur["pid"]] = dict(cur)

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("Name:"):
                flush()
                cur.clear()
                cur["name"] = line.split(":", 1)[1].strip()
                cur["pid"] = None
                cur["ppid"] = None
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            v = v.strip()
            if k == "Pid":
                cur["pid"] = _int(v)
            elif k == "PPid":
                cur["ppid"] = _int(v)
            elif k == "Tgid":
                cur["tgid"] = _int(v)
            elif k == "Uid":
                cur["uid"] = _int(v.split()[0]) if v else None
            elif k == "Gid":
                cur["gid"] = _int(v.split()[0]) if v else None
            elif k == "State":
                cur["state"] = v
            elif k == "Threads":
                cur["threads"] = _int(v)
            elif k == "NStgid":
                cur["nstgid"] = v
            elif k in ("NSpid", "NSpgid", "NSsid"):
                cur[k.lower()] = v
            elif k == "TracerPid":
                cur["tracerpid"] = _int(v)
        flush()
    return out


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_ps(path: str) -> dict[int, dict]:
    """Parse `ps -axwwSo` (USER PID PPID VSZ RSS TTY STAT STIME TIME COMMAND)."""
    out: dict[int, dict] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("USER") or not line.strip():
                continue
            # keep COMMAND intact (may contain spaces): split into 9 fields max
            parts = line.rstrip("\n").split(None, 9)
            if len(parts) < 3:
                continue
            user, pid, ppid = parts[0], _int(parts[1]), _int(parts[2])
            stime = parts[7] if len(parts) > 7 else ""
            cmd = parts[9] if len(parts) > 9 else ""
            if pid is None:
                continue
            out[pid] = {"user": user, "ppid": ppid, "stime": stime, "cmd": cmd}
    return out


def parse_cmdlines(path: str) -> dict[int, str]:
    """Parse a `/proc/<pid>/cmdline` dump -> {pid: argv string}."""
    out: dict[int, str] = {}
    cur = None
    buf: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^==> /proc/(\d+)/cmdline <==", line.strip())
            if m:
                if cur is not None:
                    out[cur] = decode_cmdline("".join(buf))
                cur = int(m.group(1))
                buf = []
                continue
            if cur is not None:
                buf.append(line)
    if cur is not None:
        out[cur] = decode_cmdline("".join(buf))
    return out


def parse_exe_links(path: str) -> dict[int, str]:
    out: dict[int, str] = {}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.search(r"/proc/(\d+)/exe(?:\s*->\s*(\S.*))?$", line.rstrip("\n"))
            if m:
                out[int(m.group(1))] = (m.group(2) or "").strip()
    return out


def parse_hashes(path: str) -> dict[int, str]:
    """Parse `sha1sum /proc/<pid>/exe` style dump -> {pid: sha1}."""
    out: dict[int, str] = {}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{32,64})\s+/proc/(\d+)/exe", line.strip())
            if m:
                out[int(m.group(2))] = m.group(1).lower()
    return out


def parse_fd_sockets(path: str) -> dict[int, list[str]]:
    """Pull socket:[inode] and notable path fds per pid (for enrichment)."""
    out: dict[int, list[str]] = {}
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.search(r"/proc/(\d+)/fd/\d+\s*->\s*(\S.*)$", line.rstrip("\n"))
            if not m:
                continue
            dst = m.group(2).strip()
            if dst.startswith("socket:[") or dst.startswith("/"):
                out.setdefault(int(m.group(1)), []).append(dst)
    return out


def snapshot_dir_files(d: str) -> dict[str, str]:
    """Map the canonical catscale filenames in a Process_and_Network dir."""
    def find(*needles):
        for f in glob.glob(os.path.join(d, "*")):
            b = os.path.basename(f)
            if all(n in b for n in needles):
                return f
        return ""

    return {
        "ps": find("processes-axwwSo"),
        "details": find("process-details"),
        "cmdline": find("process-cmdline"),
        "exe": find("process-exe-links"),
        "hashes": find("processhashes") or find("process-hashes"),
        "fd": find("process-fd-links"),
    }


def build_snapshot(snapdir: str, host: str) -> tuple[dict[int, dict], dict[str, str]]:
    files = snapshot_dir_files(snapdir)
    ps = parse_ps(files["ps"]) if files["ps"] else {}
    details = parse_status_details(files["details"]) if files["details"] else {}
    cmdlines = parse_cmdlines(files["cmdline"]) if files["cmdline"] else {}
    exes = parse_exe_links(files["exe"]) if files["exe"] else {}
    hashes = parse_hashes(files["hashes"]) if files["hashes"] else {}
    fds = parse_fd_sockets(files["fd"]) if files["fd"] else {}

    pids = set(ps) | set(details)
    nodes: dict[int, dict] = {}
    for pid in pids:
        d = details.get(pid, {})
        p = ps.get(pid, {})
        cmd = cmdlines.get(pid) or p.get("cmd") or ""
        name = d.get("name") or (cmd.split()[0] if cmd else "")
        sockets = [x for x in fds.get(pid, []) if x.startswith("socket:[")]
        paths = [x for x in fds.get(pid, []) if x.startswith("/")]
        nodes[pid] = {
            "pid": pid,
            "ppid": d.get("ppid") if d.get("ppid") is not None else p.get("ppid"),
            "name": name,
            "user": p.get("user", ""),
            "uid": d.get("uid"),
            "exe": exes.get(pid, ""),
            "sha1": hashes.get(pid, ""),
            "state": d.get("state", ""),
            "cmd": cmd,
            "stime": p.get("stime", ""),
            "sockets": sockets[:20],
            "open_paths": paths[:20],
            "kernel": (pid == 2 or bool(re.match(r"^\[.*\]$", name))
                       or d.get("ppid") == 2),
            "source": "snapshot:" + os.path.basename(files["details"] or files["ps"] or "snapshot"),
            "edge_confidence": "exact",
        }
    return nodes, files


# --------------------------------------------------------------------------- #
# journal + text-log inputs
# --------------------------------------------------------------------------- #
def _journal_from_dir(d: str, host: str, since: str, until: str,
                      tz: timezone) -> list[dict]:
    """Run journalctl -D <dir> and keep pid-bearing events."""
    if not shutil.which("journalctl"):
        print("[linux_proctree] journalctl not found; skipping journal", file=sys.stderr)
        return []
    cmd = ["journalctl", "-D", d, "-o", "json", "--no-pager"]
    if since:
        cmd += ["--since", _journal_since(since, tz)]
    if until:
        cmd += ["--until", _journal_until(until, tz)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False).stdout
    except OSError as exc:
        print(f"[linux_proctree] journalctl failed on {d}: {exc}", file=sys.stderr)
        return []
    events, seen = [], set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        pid = _int(r.get("_PID"))
        if pid is None:
            continue
        comm = r.get("_COMM", "") or ""
        # skip kernel relays and audit-only records with no process identity
        if comm == "kernel" or (not comm and not r.get("_SYSTEMD_UNIT")):
            continue
        cur = r.get("__CURSOR", "")
        if cur and cur in seen:
            continue
        if cur:
            seen.add(cur)
        events.append({
            "host": host,
            "time_utc": iso_from_usec(r.get("__REALTIME_TIMESTAMP", ""), tz),
            "pid": pid,
            "ppid": _int(r.get("_PPID")),
            "comm": r.get("_COMM", ""),
            "exe": r.get("_EXE", ""),
            "cmd": r.get("_CMDLINE", "") if isinstance(r.get("_CMDLINE"), str) else "",
            "unit": r.get("_SYSTEMD_UNIT", ""),
            "cgroup": r.get("_SYSTEMD_CGROUP", ""),
            "session": r.get("_SYSTEMD_SESSION", ""),
            "boot": r.get("_BOOT_ID", ""),
            "message": short(r.get("MESSAGE", ""), 300),
            "source": "journal" + ((":" + r["_BOOT_ID"][:8]) if r.get("_BOOT_ID") else ""),
            "edge_confidence": "inferred",
        })
    return events


def _journal_since(s: str, tz: timezone) -> str:
    return _jh(s, tz) or s


def _journal_until(s: str, tz: timezone) -> str:
    return _jh(s, tz) or s


def _jh(s: str, tz: timezone) -> str:
    """Convert an ISO time to a TZ-local wall-clock string for journalctl."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ]?(\d{2}:\d{2}(?::\d{2})?)?Z?$", s)
    if not m:
        return ""
    y, mo, d, t = m.group(1), m.group(2), m.group(3), m.group(4) or "00:00:00"
    try:
        dt = datetime.fromisoformat(f"{y}-{mo}-{d}T{t}").replace(tzinfo=UTC)
    except ValueError:
        return ""
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


# "Dec 26 00:57:20 app01 systemd[1]: message"
SYSLOG_TAIL = re.compile(
    r"^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+([\w./-]+)(?:\[(\d+)\])?:\s*(.*)$")


def parse_text_log(path: str, host: str, tz: timezone, now: datetime,
                   since: str, until: str) -> list[dict]:
    """pid-tagged auth.log / syslog lines -> process events."""
    events = []
    if not os.path.isfile(path):
        return events
    ident_re = re.compile(
        r"(sudo|su|sshd|CRON|cron|systemd|login|polkitd|useradd|usermod|passwd|"
        r"gpasswd|pkexec|dbus-daemon|sssd)\b")
    if path.endswith(".gz"):
        import gzip
        opener = lambda: gzip.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        opener = lambda: open(path, encoding="utf-8", errors="replace")
    with opener() as fh:
        for line in fh:
            ts = syslog_ts_to_utc(line, tz, now)
            if not ts:
                continue
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            m = SYSLOG_TAIL.match(line.strip())
            if not m:
                continue
            ident = m.group(2).strip()
            pid = _int(m.group(3))
            msg = m.group(4).strip()
            if not ident_re.search(ident) and \
                    not re.search(r"session (?:opened|closed)|COMMAND=", msg):
                continue
            events.append({
                "host": host,
                "time_utc": ts,
                "pid": pid,
                "ppid": None,
                "comm": ident,
                "exe": "",
                "cmd": _extract_command(msg),
                "unit": ident,
                "cgroup": "",
                "session": _extract_tty(msg),
                "boot": "",
                "message": short(msg, 300),
                "source": "text:" + os.path.basename(path),
                "edge_confidence": "inferred",
            })
    return events


def _extract_command(msg: str) -> str:
    m = re.search(r"COMMAND=(.*)$", msg)
    if m:
        return m.group(1).strip()
    m = re.search(r"\((to [^)]+)\)", msg)
    if m:
        return m.group(1)
    return ""


def _extract_tty(msg: str) -> str:
    m = re.search(r"TTY=(\S+)", msg) or re.search(r"tty=(\S+)", msg)
    return m.group(1) if m else ""


def discover_log_sources(args) -> dict:
    """Resolve tars, journal dirs and text logs from --logdir / explicit args."""
    tars = list(args.journal_tar)
    jdirs = list(args.journal)
    textlogs = list(args.auth) + list(args.syslog)

    if args.logdir:
        d = args.logdir
        tars += sorted(glob.glob(os.path.join(d, "**", "*var-log*.tar.gz"), recursive=True))
        tars += sorted(glob.glob(os.path.join(d, "**", "*var-log*.tgz"), recursive=True))
        # extracted tree?
        for cand in ("auth.log", "syslog"):
            hits = glob.glob(os.path.join(d, "**", "var", "log", cand), recursive=True)
            if hits:
                textlogs.append(hits[0])
        for jrn in glob.glob(os.path.join(d, "**", "journal"), recursive=True):
            if glob.glob(os.path.join(jrn, "*.journal")) or \
                    glob.glob(os.path.join(jrn, "*.journal~")):
                jdirs.append(jrn)
    return {"tars": sorted(set(tars)), "jdirs": sorted(set(jdirs)),
            "textlogs": sorted(set(textlogs))}


def _tar_member_events(tars: list[str], host: str, since: str, until: str,
                       tz: timezone, now: datetime) -> list[dict]:
    """Extract journal + auth.log/syslog members from tars and parse them."""
    events: list[dict] = []
    for t in tars:
        if not os.path.isfile(t):
            continue
        tmp = tempfile.mkdtemp(prefix="lpt-tar-")
        try:
            with tarfile.open(t) as tf:
                jmembers, tmembers = [], []
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    if m.name.endswith((".journal", ".journal~")):
                        jmembers.append(m)
                    elif os.path.basename(m.name) in ("auth.log", "syslog") \
                            or re.search(r"/(auth|syslog)\.log[\d.]*(\.gz)?$", m.name):
                        tmembers.append(m)
                for m in jmembers:
                    dest = os.path.join(tmp, "journal", os.path.basename(m.name))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with tf.extractfile(m) as src, open(dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                if jmembers:
                    events += _journal_from_dir(os.path.join(tmp, "journal"),
                                                host, since, until, tz)
                for m in tmembers:
                    dest = os.path.join(tmp, os.path.basename(m.name))
                    with tf.extractfile(m) as src, open(dest, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    events += parse_text_log(dest, host, tz, now, since, until)
        except (tarfile.TarError, OSError) as exc:
            print(f"[linux_proctree] tar {t}: {exc}", file=sys.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return events


# --------------------------------------------------------------------------- #
# tree construction
# --------------------------------------------------------------------------- #
def build_snapshot_tree(nodes: dict[int, dict], roots_only=True) -> list[dict]:
    """Exact PPid tree from the snapshot. Kernel threads pruned."""
    kids = collections.defaultdict(list)
    for pid, n in nodes.items():
        if n["kernel"]:
            continue
        kids[n["ppid"]].append(pid)

    def build(pid, depth=0, seen=None):
        seen = seen or set()
        if pid in seen or pid not in nodes or depth > 12:
            return None
        n = nodes[pid]
        if n["kernel"]:
            return None
        seen = seen | {pid}
        children = [c for c in sorted(kids.get(pid, []), key=lambda x: x)
                    for c in [build(c, depth + 1, seen)] if c]
        return {
            "pid": pid, "name": n["name"], "user": n["user"], "cmd": short(n["cmd"]),
            "ts": n["stime"], "exe": n["exe"], "sha1": n["sha1"], "state": n["state"],
            "interesting": is_interesting(n["name"] + " " + n["cmd"]),
            "reparented": pid != 1 and nodes[pid]["ppid"] not in nodes,
            "children": children,
        }

    # roots: pid 1 plus any non-kernel orphan whose ppid is absent
    root_pids = []
    for pid, n in nodes.items():
        if n["kernel"]:
            continue
        if pid == 1 or n["ppid"] not in nodes or nodes.get(n["ppid"], {}).get("kernel"):
            root_pids.append(pid)
    roots = [r for r in (build(p) for p in sorted(root_pids)) if r]
    return roots


INTERESTING = re.compile(
    r"\bcron\b|/dev/shm|/tmp/|\.upd\b|curl|wget|base64|bash -c|nc\b|ncat|"
    r"socat|chisel|python3? -c|systemd-journald-helper|updat3|realm|"
    r"sudo|/bin/su\b|\bsu\b|sshd|tmux|xterm|wsgi|uwsgi|mysql|sqlite|"
    r"velociraptor|ssh-agent",
    re.I)


def is_interesting(s: str) -> bool:
    return bool(INTERESTING.search(s or ""))


def resolve_journal_edges(events: list[dict]) -> list[dict]:
    """Infer parent links for journal events (no _PPID on this host).

    Rule: a child's PPID (when present) resolves to the most recent event with
    that PID at or before the child. When _PPID is absent we fall back to the
    enclosing cgroup/unit and time-window heuristics. Every edge is tagged
    `inferred`.
    """
    edges = []
    by_boot: dict[str, list[dict]] = collections.defaultdict(list)
    for e in events:
        by_boot[e["boot"]].append(e)
    for boot, evs in by_boot.items():
        evs = sorted(evs, key=lambda e: e["time_utc"] or "")
        by_pid: dict[int, list[dict]] = collections.defaultdict(list)
        for e in evs:
            by_pid[e["pid"]].append(e)

        def nearest(pid, ts):
            cands = [p for p in by_pid.get(pid, []) if (p["time_utc"] or "") <= (ts or "")]
            return max(cands, key=lambda p: p["time_utc"] or "") if cands else None

        for e in evs:
            parent = None
            if e.get("ppid"):
                cand = nearest(e["ppid"], e["time_utc"])
                if cand:
                    parent = cand
            if parent is None and e.get("cgroup"):
                # same cgroup slice: attach to the earliest event in the group
                grp = [x for x in evs if x.get("cgroup") == e["cgroup"]
                       and x is not e and x["pid"] != e["pid"]]
                grp = [x for x in grp if (x["time_utc"] or "") <= (e["time_utc"] or "")]
                if grp:
                    parent = min(grp, key=lambda x: x["time_utc"] or "")
            if parent is not None and parent["pid"] != e["pid"]:
                edges.append({
                    "ppid": parent["pid"],
                    "pid": e["pid"],
                    "kind": "journal",
                    "confidence": "inferred",
                    "reason": "ppid-lookup" if e.get("ppid") else "cgroup/time",
                    "time_utc": e["time_utc"],
                })

    # drop reciprocal duplicates (cgroup grouping can produce A->B and B->A)
    out, seen, undirected = [], set(), set()
    for ed in edges:
        a, b = ed["ppid"], ed["pid"]
        pair = frozenset((a, b))
        if (a, b) in seen or pair in undirected:
            continue
        seen.add((a, b))
        undirected.add(pair)
        out.append(ed)
    return out


# --------------------------------------------------------------------------- #
# outputs
# --------------------------------------------------------------------------- #
def flatten_snapshot(nodes: dict[int, dict]) -> list[dict]:
    rows = []
    for pid, n in sorted(nodes.items()):
        rows.append({
            "pid": pid, "ppid": n["ppid"], "name": n["name"], "user": n["user"],
            "uid": n.get("uid"), "state": n.get("state"), "exe": n["exe"],
            "sha1": n["sha1"], "cmd": n["cmd"], "start": n["stime"],
            "kernel": int(n["kernel"]), "source": n["source"],
            "edge_confidence": n["edge_confidence"],
            "sockets": ";".join(n.get("sockets", [])),
            "open_paths": ";".join(n.get("open_paths", [])),
        })
    return rows


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def write_csv(path, rows, fields):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_dot(path, host, roots):
    lines = ['digraph proctree {', '  rankdir=LR;',
             '  node [shape=box, style="rounded,filled", fontname="Helvetica", '
             'fontsize=10];', '  edge [color="#3d4b5c"];']

    def emit(node, parent, seen):
        nid = f'n{node["pid"]}'
        color = "#f85149" if node["interesting"] else (
            "#8957e5" if node["pid"] == 1 else "#1f6feb")
        label = f'{node["name"]}\\npid {node["pid"]} · {node["user"]}'
        shape = "component" if node["interesting"] else "box"
        lines.append(f'  {nid} [label="{label}", fillcolor="{color}", '
                     f'fontcolor="white", shape={shape}];')
        if parent is not None:
            lines.append(f'  {parent} -> {nid};')
        for c in node["children"]:
            emit(c, nid, seen)

    for r in roots:
        emit(r, None, set())
    lines.append("}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def render_dot_image(dot_path: str, out_base: str, fmt: str) -> bool:
    """Render proctree.dot to <out_base>.<fmt> with Graphviz `dot`."""
    if not shutil.which("dot"):
        print("[linux_proctree] graphviz `dot` not found; skipping "
              f"{fmt}", file=sys.stderr)
        return False
    try:
        subprocess.run(["dot", f"-T{fmt}", "-o", f"{out_base}.{fmt}", dot_path],
                       check=True, capture_output=True, text=True)
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"[linux_proctree] dot -T{fmt} failed: {exc}", file=sys.stderr)
        return False


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>$title</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--bd:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#1f6feb;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:14px 20px;border-bottom:1px solid var(--bd);background:var(--panel)}
h1{margin:0;font-size:17px}h1 small{color:var(--mut);font-weight:400;font-size:12px;margin-left:8px}
main{display:grid;grid-template-columns:58% 42%;height:calc(100vh - 56px)}
#net{width:100%;height:100%;border-right:1px solid var(--bd)}
#side{overflow:auto;padding:14px 16px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--mut);margin:14px 0 6px}
.legend span{display:inline-flex;align-items:center;gap:6px;margin-right:14px;font-size:12px}
.sw{width:11px;height:11px;border-radius:3px;display:inline-block}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#c9d1d9}
.badge{font-size:10px;padding:1px 6px;border-radius:10px;border:1px solid var(--bd);color:var(--mut)}
.hit{color:#f85149;font-weight:600}
.note{background:var(--panel);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;
font-size:12px;color:var(--mut);margin-top:8px}
.warn{border-left:3px solid #d29922}
ul{list-style:none;margin:0;padding-left:16px}li{margin:2px 0}
.pn{background:var(--panel);border:1px solid var(--bd);border-radius:6px;padding:5px 8px;display:inline-block}
</style></head>
<body>
<header><h1>$title <small>$subtitle</small></h1></header>
<main>
  <div id="net"></div>
  <div id="side">
    <h2>Legend for the graph</h2>
    <div class="legend">
      <span><i class="sw" style="background:#8957e5"></i>init / systemd</span>
      <span><i class="sw" style="background:#1f6feb"></i>normal</span>
      <span><i class="sw" style="background:#f85149"></i>interesting</span>
      <span><i class="sw" style="background:#d29922"></i>inferred edge (journal)</span>
    </div>
    <div class="note warn"><b>Snapshot</b> = exact PPid, one instant.
      <b>Journal</b> = inferred parent, only logged processes; this host has no
      <b>_PPID</b> in the journal and no auditd, so historical parentage is
      best-effort.</div>
    <h2>Snapshot tree</h2>
    <div id="tree"></div>
    <h2>Process events (journal + text logs)</h2>
    <div id="events"></div>
  </div>
</main>
<script>$visnet</script>
<script>
const DATA = $data;
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function nodeHtml(n, depth){
  const kids = (n.children||[]).map(c=>nodeHtml(c, depth+1)).join('');
  const cls = n.interesting?'hit':'';
  return `<li><div class="pn"><span class="${cls}">${esc(n.name)}</span>
    <span class="badge">pid ${n.pid}</span>
    <span class="mono">${esc(n.user||'')} ${esc(n.ts||'')}</span>
    ${n.reparented?'<span class="badge">reparented</span>':''}
    ${n.sha1?`<div class="mono">sha1 ${esc(n.sha1)}</div>`:''}
    ${n.cmd?`<div class="mono">${esc(n.cmd)}</div>`:''}</div>
    ${kids?`<ul>${kids}</ul>`:''}</li>`;
}
function renderTree(){
  const el=document.getElementById('tree');
  el.innerHTML = '<ul>'+DATA.snapshot_roots.map(n=>nodeHtml(n,0)).join('')+'</ul>';
}
function renderEvents(){
  const el=document.getElementById('events');
  if(!DATA.events.length){el.innerHTML='<div class="note">No pid-tagged events.</div>';return;}
  el.innerHTML='<table><thead><tr><th>UTC</th><th>pid</th><th>comm</th><th>cmd</th><th>src</th></tr></thead><tbody>'+
    DATA.events.map(e=>`<tr><td class="mono">${esc(e.time_utc)}</td><td>${e.pid??''}</td>
      <td>${esc(e.comm)}</td><td class="mono">${esc(e.cmd||e.message)}</td>
      <td class="badge">${esc((e.source||'').split(':')[0])}</td></tr>`).join('')+'</tbody></table>';
}
function renderGraph(){
  const el=document.getElementById('net');
  if(!(window.vis&&vis.Network)){el.innerHTML='<div class="note">vis-network asset not bundled.</div>';return;}
  new vis.Network(el,{nodes:new vis.DataSet(DATA.graph.nodes),edges:new vis.DataSet(DATA.graph.edges)},
   {layout:{hierarchical:{direction:'LR',sortMethod:'directed'}},
    physics:false,
    nodes:{shape:'box',font:{size:12,color:'#e6edf3'},borderWidth:1},
    edges:{arrows:'to',color:{color:'#3d4b5c'},smooth:{type:'cubicBezier'},
           font:{size:9,color:'#8b949e'}},
    interaction:{hover:true,tooltipDelay:120}});
}
try{renderTree();renderEvents();renderGraph();}catch(e){console.error(e);
  document.getElementById('net').innerHTML='<div class="note">Graph render error: '+esc(e.message)+'</div>';}
</script>
</body></html>
"""


def build_graph_payload(roots, journal_edges):
    nodes, edges, seen = [], [], set()
    cid = [0]
    pid_key: dict[int, str] = {}

    def add(node, parent_key):
        key = f'n{cid[0]}'; cid[0] += 1
        pid_key[node["pid"]] = key
        color = "#f85149" if node["interesting"] else (
            "#8957e5" if node["pid"] == 1 else "#1f6feb")
        nodes.append({
            "id": key,
            "label": f'{node["name"]}\npid {node["pid"]}',
            "title": f'pid {node["pid"]}\nuser {node["user"]}\n{node["cmd"]}',
            "color": {"background": color, "border": color},
            "font": {"color": "#ffffff"},
        })
        if parent_key:
            edges.append({"from": parent_key, "to": key, "color": "#3d4b5c",
                          "dashes": False, "title": "snapshot (exact PPid)"})
        for c in node["children"]:
            add(c, key)

    for r in roots:
        add(r, None)

    # overlay inferred journal edges between processes present in the snapshot
    for ed in journal_edges:
        a, b = pid_key.get(ed["ppid"]), pid_key.get(ed["pid"])
        if not a or not b or a == b:
            continue
        k = (a, b, "j")
        if k in seen:
            continue
        seen.add(k)
        edges.append({"from": a, "to": b, "color": "#d29922", "dashes": True,
                      "title": f'inferred ({ed["reason"]}) — no _PPID in journal'})
    return {"nodes": nodes, "edges": edges}


def render_html(path, title, subtitle, payload):
    visnet = _load_asset("vis-network.min.js")
    subs = {
        "$title": esc(title), "$subtitle": esc(subtitle),
        "$visnet": visnet, "$data": json.dumps(payload, ensure_ascii=False),
    }
    out = HTML_TEMPLATE
    for k, v in subs.items():
        out = out.replace(k, v)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build a Linux process tree (snapshot) + process-event timeline.")
    ap.add_argument("--snapshot", required=True,
                    help="Process_and_Network directory from the triage collection")
    ap.add_argument("--logdir", help="directory to auto-discover journal/tar/logs")
    ap.add_argument("--journal-tar", action="append", default=[],
                    help="tar(.gz) containing var/log/journal; repeatable")
    ap.add_argument("--journal", action="append", default=[],
                    help="directory of *.journal files; repeatable")
    ap.add_argument("--auth", action="append", default=[], help="auth.log path")
    ap.add_argument("--syslog", action="append", default=[], help="syslog path")
    ap.add_argument("--host", default="app01", help="host label")
    ap.add_argument("--tz", default="UTC", help="host-local timezone (e.g. +02:00)")
    ap.add_argument("--since", default="", help="incident window start (ISO-8601 UTC)")
    ap.add_argument("--until", default="", help="incident window end (ISO-8601 UTC)")
    ap.add_argument("--all", action="store_true", help="ignore --since/--until")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--title", default="", help="case/host title")
    ap.add_argument("--formats", default="json,csv,dot,html",
                    help="comma list: json,csv,dot,html")
    args = ap.parse_args(argv)

    tz = parse_tz(args.tz)
    now = datetime.now(UTC)
    since = "" if args.all else args.since
    until = "" if args.all else args.until
    os.makedirs(args.out, exist_ok=True)
    title = args.title or f"Linux process tree — {args.host}"

    # ---- snapshot ----
    snap_nodes, snap_files = build_snapshot(args.snapshot, args.host)
    snap_roots = build_snapshot_tree(snap_nodes)
    if not snap_nodes:
        print(f"[linux_proctree] no snapshot data under {args.snapshot}", file=sys.stderr)

    # ---- journal ----
    sources = discover_log_sources(args)
    events: list[dict] = []
    for jd in sources["jdirs"]:
        events += _journal_from_dir(jd, args.host, since, until, tz)
    events += _tar_member_events(sources["tars"], args.host, since, until, tz, now)
    for tl in sources["textlogs"]:
        events += parse_text_log(tl, args.host, tz, now, since, until)

    # window filter (journalctl already filters, text logs filtered in parse)
    if since or until:
        def keep(e):
            t = e.get("time_utc", "")
            return (not since or t >= since) and (not until or t <= until)
        events = [e for e in events if keep(e)]

    events.sort(key=lambda e: (e["time_utc"] or "", e["pid"] or 0))
    # de-duplicate the same record surfaced by overlapping journal segments
    dedup, seen = [], set()
    for e in events:
        k = (e["time_utc"], e["pid"], e["comm"], e["cmd"], e["message"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(e)
    events = dedup
    journal_edges = resolve_journal_edges(events)

    # ---- outputs ----
    formats = {f.strip() for f in args.formats.split(",") if f.strip()}
    subtitle = (f"snapshot {len(snap_nodes)} procs · {len(events)} events · "
                f"window {'all' if args.all else (since or '…') + '→' + (until or '…')}")

    payload = {
        "host": args.host,
        "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tz": args.tz,
        "window": {"since": since or None, "until": until or None, "all": args.all},
        "snapshot_sources": {k: os.path.basename(v) for k, v in snap_files.items() if v},
        "snapshot_nodes": flatten_snapshot(snap_nodes),
        "snapshot_roots": snap_roots,
        "events": events,
        "journal_edges": journal_edges,
        "graph": build_graph_payload(snap_roots, journal_edges),
        "limitations": [
            "Snapshot is a single collection instant; processes that ran and "
            "exited during the incident are absent.",
            "Snapshot PPid may reflect reparenting to PID 1 after the real "
            "parent died.",
            "The systemd journal on this host carries no _PPID and there is no "
            "auditd/memory image, so journal parentage is inferred "
            "(cgroup/unit + time-aware PID lookup).",
        ],
    }
    if "json" in formats:
        write_json(os.path.join(args.out, "proctree.json"), payload)
    if "csv" in formats:
        write_csv(os.path.join(args.out, "proctree.csv"), flatten_snapshot(snap_nodes),
                  ["pid", "ppid", "name", "user", "uid", "state", "exe", "sha1",
                   "cmd", "start", "kernel", "source", "edge_confidence",
                   "sockets", "open_paths"])
        write_csv(os.path.join(args.out, "process_events.csv"), events,
                  ["time_utc", "pid", "ppid", "comm", "exe", "cmd", "unit",
                   "cgroup", "session", "boot", "message", "source",
                   "edge_confidence"])
    if "dot" in formats or formats & {"svg", "png"}:
        dot_path = os.path.join(args.out, "proctree.dot")
        write_dot(dot_path, args.host, snap_roots)
        for fmt in ("svg", "png"):
            if fmt in formats:
                render_dot_image(dot_path, os.path.join(args.out, "proctree"), fmt)
    if "html" in formats:
        render_html(os.path.join(args.out, "proctree.html"), title, subtitle, payload)

    print(f"[linux_proctree] {args.host}: {len(snap_nodes)} procs, "
          f"{len(snap_roots)} roots, {len(events)} events, "
          f"{len(journal_edges)} inferred edges -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
