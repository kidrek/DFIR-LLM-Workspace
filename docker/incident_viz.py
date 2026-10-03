#!/usr/bin/env python3
"""incident_viz.py -- turn DFIR analysis artifacts into incident visuals.

Part of the container-only DFIR workspace. Reads already-produced artifacts
(structured IOCs, a normalized timeline, Zeek logs) and writes self-contained,
air-gapped **interactive HTML** plus optional **static SVG/PNG**:

  attack_timeline.{html,svg}   swimlane timeline, colored by tag
  actor_graph.{html,svg}       IOC + network relationship graph
  mitre_matrix.{html,svg}      ATT&CK tactic grid from the `mitre` field
  timeline.csv                 normalized timeline (also written for reuse)
  graph.json / timeline.json   machine-readable intermediates

All HTML is a single file with the JS/CSS inlined (assets baked into the image
at /opt/viz-assets), so it opens in any browser with no network and no server.

Input sources
-------------
* ``--iocs``      structured observables (see skills/dfir IOC schema)
* ``--timeline``  normalized CSV: time_utc,host,actor,event,technique,evidence,tags
* ``--from-markdown``  bootstrap timeline.csv by converting the consolidated
                  chain table found in a Markdown report (e.g.
                  reports/incident_timeline.md)
* ``--zeek``      directory of Zeek *.log (conn/http/smb_mapping/kerberos/ntlm)

Usage::

    docker/dfir.sh python3 /data/tools/incident_viz.py \
        --iocs     /data/analysis/iocs.json \
        --from-markdown /data/reports/incident_timeline.md \
        --zeek     /data/analysis/network/zeek \
        --out      /data/reports/viz \
        --title    "SaSync / shanocorp.htb" \
        --formats  html,svg,png

Only matplotlib/networkx (static formats) are optional; the script degrades
gracefully when they are absent. Stdlib-only otherwise.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

UTC = timezone.utc

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
TIMELINE_COLUMNS = ["time_utc", "host", "actor", "event", "technique", "evidence", "tags"]

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Other",
]

# base or sub-technique ID -> primary tactic
TECHNIQUE_TACTICS = {
    "T1595": "Reconnaissance", "T1592": "Reconnaissance", "T1589": "Reconnaissance",
    "T1590": "Reconnaissance",
    "T1190": "Initial Access", "T1566": "Initial Access", "T1133": "Initial Access",
    "T1078": "Initial Access", "T1195": "Initial Access",
    "T1505": "Persistence", "T1053": "Persistence", "T1543": "Persistence",
    "T1136": "Persistence", "T1547": "Persistence",
    "T1059": "Execution", "T1047": "Execution", "T1204": "Execution",
    "T1569": "Execution", "T1106": "Execution",
    "T1068": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1548": "Privilege Escalation", "T1055": "Privilege Escalation",
    "T1484": "Defense Evasion",
    "T1070": "Defense Evasion", "T1112": "Defense Evasion", "T1562": "Defense Evasion",
    "T1218": "Defense Evasion", "T1140": "Defense Evasion",
    "T1003": "Credential Access", "T1110": "Credential Access",
    "T1558": "Credential Access", "T1555": "Credential Access", "T1552": "Credential Access",
    "T1087": "Discovery", "T1033": "Discovery", "T1069": "Discovery",
    "T1057": "Discovery", "T1018": "Discovery", "T1046": "Discovery",
    "T1021": "Lateral Movement", "T1570": "Lateral Movement", "T1550": "Lateral Movement",
    "T1560": "Collection", "T1005": "Collection", "T1074": "Collection",
    "T1071": "Command and Control", "T1105": "Command and Control",
    "T1571": "Command and Control", "T1095": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact", "T1489": "Impact",
}

TAG_COLORS = {
    "anti-forensics": "#8e44ad",
    "payload": "#e74c3c",
    "credential": "#e67e22",
    "exfil": "#c0392b",
    "lateral": "#2980b9",
    "discovery": "#16a085",
    "execution": "#d35400",
    "entry": "#f1c40f",
    "persistence": "#7f8c8d",
    "impact": "#2c3e50",
    "attacker": "#e74c3c",
    "c2": "#c0392b",
    "benign": "#95a5a6",
    "infrastructure": "#95a5a6",
}
DEFAULT_COLOR = "#3498db"

TYPE_COLORS = {
    "ipv4": "#2c3e50", "mac": "#7f8c8d", "hostname": "#16a085", "port": "#e67e22",
    "url": "#c0392b", "file-path": "#8e44ad", "share": "#d35400",
    "account": "#e74c3c", "command": "#34495e", "event-id": "#2980b9",
    "guid": "#7f8c8d", "domain": "#16a085",
}

TAG_KEYWORDS = [
    ("anti-forensics", r"wevtutil|event log clear|\blog clear|\b1102\b|anti-?forensic"),
    ("payload", r"\bnc\.exe|sigmapotato|mimikatz|certutil|/9999/|payload|ingress tool"),
    ("exfil", r"exfil|net use|devmachine|\bcopy .*n:|data stag|t1041|t1048"),
    ("credential", r"\b4625\b|\b4776\b|\b4768\b|\b4769\b|\b4662\b|\b4648\b|reg save|lsass|hk\s*sam|sam hive|password spray|as-rep|kerberoast|dcsync|credential"),
    ("lateral", r"\b4624\b|pass-the-hash|lateral|\bsmb\b|logon type 3|remote service"),
    ("discovery", r"whoami|port scan|\brecon\b|discovery|\bdir c:"),
    ("execution", r"xp_cmdshell|reverse shell|\bt1059|cmd\.exe /c|powershell -e|base64"),
    ("persistence", r"scheduled task|run key|new account|service install|persist"),
    ("impact", r"ransom|encrypt|destructive|\bimpact\b"),
]

# preference order for the single colour-defining tag
TAG_PRIORITY = [
    "anti-forensics", "payload", "exfil", "credential", "lateral",
    "discovery", "execution", "persistence", "impact",
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
FQDN_RE = re.compile(r"\b([a-z0-9][a-z0-9._-]*\.(?:htb|local|lan|internal|corp))\b", re.I)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def strip_md(text: str) -> str:
    text = text.replace("\\|", "|")
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return text.strip()


def first_ip(text: str) -> str | None:
    m = IPV4_RE.search(text or "")
    return m.group(0) if m else None


def scan_tags(text: str) -> list[str]:
    text = (text or "").lower()
    tags = [tag for tag, pat in TAG_KEYWORDS if re.search(pat, text)]
    return tags


def primary_tag(tags: list[str]) -> str:
    for t in TAG_PRIORITY:
        if t in tags:
            return t
    return tags[0] if tags else "default"


def color_for_tags(tags: list[str], fallback: str = DEFAULT_COLOR) -> str:
    for t in tags:
        if t in TAG_COLORS:
            return TAG_COLORS[t]
    return fallback


def base_technique(tech: str) -> str:
    return tech.split(".")[0]


def tactic_for(tech: str) -> str:
    if tech in TECHNIQUE_TACTICS:
        return TECHNIQUE_TACTICS[tech]
    base = base_technique(tech)
    return TECHNIQUE_TACTICS.get(base, "Other")


def parse_time(text: str, date: tuple[int, int, int]) -> datetime | None:
    text = (text or "").strip()
    if not text:
        return None
    # full ISO
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?", text)
    if m:
        y, mo, d, h, mi = (int(m.group(i)) for i in range(1, 6))
        s = int(m.group(6) or 0)
        return datetime(y, mo, d, h, mi, s, tzinfo=UTC)
    # bare HH:MM[:SS]
    m = re.search(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", text)
    if m:
        y, mo, d = date
        return datetime(y, mo, d, int(m.group(1)), int(m.group(2)),
                        int(m.group(3) or 0), tzinfo=UTC)
    return None


def iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def infer_date(path: str) -> tuple[int, int, int] | None:
    """Pick the most plausible incident date from a Markdown report.

    Prefers a 'YYYY-MM-DD between HH:MM' style phrase (report prose), else the
    earliest ISO date in the file. Skips an obvious 'report date' line only when
    another date is available.
    """
    text = open(path, encoding="utf-8", errors="replace").read()
    dates: list[tuple[int, int, int]] = []
    for m in re.finditer(r"\b(\d{4})-(\d{2})-(\d{2})\b", text):
        dates.append(tuple(int(x) for x in m.groups()))  # type: ignore
    if not dates:
        return None
    return min(dates)


def infer_date_from_iocs(obs: list[dict]) -> tuple[int, int, int] | None:
    dates: list[tuple[int, int, int]] = []
    for o in obs:
        for key in ("first_seen_utc", "last_seen_utc"):
            m = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(o.get(key, "")))
            if m:
                dates.append(tuple(int(x) for x in m.groups()))  # type: ignore
    return min(dates) if dates else None


# --------------------------------------------------------------------------- #
# markdown -> timeline
# --------------------------------------------------------------------------- #
def _split_md_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def parse_md_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    lines = text.splitlines()
    tables, i = [], 0
    while i < len(lines):
        if lines[i].strip().startswith("|"):
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i]); i += 1
            if len(block) >= 2 and re.match(r"^\|[\s:|-]+\|$", block[1].strip()):
                header = [strip_md(c) for c in _split_md_row(block[0])]
                rows = [[strip_md(c) for c in _split_md_row(r)] for r in block[2:]]
                tables.append((header, rows))
        else:
            i += 1
    return tables


def _col(header: list[str], *pats: str) -> int | None:
    for idx, h in enumerate(header):
        for p in pats:
            if re.search(p, h, re.I):
                return idx
    return None


def timeline_from_markdown(path: str, date: tuple[int, int, int]) -> list[dict]:
    text = open(path, encoding="utf-8", errors="replace").read()
    tables = parse_md_tables(text)
    best = None
    for header, rows in tables:
        if _col(header, r"utc", r"\btime\b") is not None and _col(header, r"host") is not None:
            if best is None or len(rows) > len(best[1]):
                best = (header, rows)
    if not best:
        sys.exit(f"ERROR: no timeline table (UTC+Host columns) found in {path}")
    header, rows = best
    ti = _col(header, r"utc", r"\btime\b")
    hi = _col(header, r"host")
    ei = _col(header, r"event", r"action")
    vi = _col(header, r"evidence")
    xi = _col(header, r"technique")
    ai = _col(header, r"actor")

    out = []
    for r in rows:
        def cell(idx):
            return r[idx] if idx is not None and idx < len(r) else ""
        event = cell(ei)
        evidence = cell(vi)
        tech = cell(xi)
        blob = " ".join([event, evidence, tech])
        tags = scan_tags(blob)
        techniques = ",".join(dict.fromkeys(MITRE_RE.findall(blob)))
        if not techniques and tech:
            techniques = ",".join(dict.fromkeys(MITRE_RE.findall(tech)))
        dt = parse_time(cell(ti), date)
        host = cell(hi)
        actor = cell(ai)
        if not actor:
            if re.search(r"responder|forensic collection|ftk|exterro", blob, re.I):
                actor = "Responder"
            elif "kali" in blob.lower() or "attacker" in blob.lower():
                actor = "Attacker (Kali)"
            else:
                actor = "System"
        out.append({
            "time_utc": iso(dt),
            "host": host,
            "actor": actor,
            "event": event,
            "technique": techniques,
            "evidence": evidence,
            "tags": ";".join(tags),
        })
    out.sort(key=lambda x: x["time_utc"] or "")
    return out


def read_timeline_csv(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append({c: (r.get(c) or "").strip() for c in TIMELINE_COLUMNS})
    for r in rows:
        if not r["tags"]:
            r["tags"] = ";".join(scan_tags(" ".join([r["event"], r["evidence"]])))
        if not r["technique"]:
            r["technique"] = ",".join(dict.fromkeys(
                MITRE_RE.findall(" ".join([r["event"], r["evidence"]]))))
    rows.sort(key=lambda x: x["time_utc"] or "")
    return rows


def write_timeline_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=TIMELINE_COLUMNS)
        w.writeheader()
        w.writerows(rows)


# --------------------------------------------------------------------------- #
# Zeek
# --------------------------------------------------------------------------- #
def read_zeek(path: str):
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                vals = line.split("\t")
                if len(vals) == len(fields):
                    yield dict(zip(fields, vals))


def _zval(row: dict, key: str, default: str = "") -> str:
    v = row.get(key, default)
    return "" if v in ("-", "(empty)", None) else v


def _is_noise_ip(ip: str) -> bool:
    """Drop link-local, multicast, broadcast and loopback noise from graphs."""
    if not ip:
        return True
    if ip.startswith(("fe80:", "ff02:", "ff00:", "::1", "224.", "239.")):
        return True
    if ip.endswith(".255") or ip in ("0.0.0.0", "255.255.255.255"):
        return True
    return False


def parse_zeek_dir(path: str):
    """Return (edges, name_map).

    Edges are collapsed per directed host pair; the label lists the distinct
    services observed (capped) and ``count`` is the number of connections.
    edges: (src, dst, label, count, first_ts, last_ts).
    """
    agg = defaultdict(lambda: {"count": 0, "first": None, "last": None,
                               "services": defaultdict(int)})
    name_map = {}

    def add(src, dst, svc, ts):
        if not src or not dst or src == dst:
            return
        if _is_noise_ip(src) or _is_noise_ip(dst):
            return
        a = agg[(src, dst)]
        a["count"] += 1
        if svc:
            a["services"][svc] += 1
        if ts:
            a["first"] = ts if a["first"] is None else min(a["first"], ts)
            a["last"] = ts if a["last"] is None else max(a["last"], ts)

    def conn_label(r):
        svc = _zval(r, "service") or _zval(r, "proto") or "?"
        return svc.split(",")[0]  # first service token only

    handlers = {
        "conn.log": lambda r: (_zval(r, "id.orig_h"), _zval(r, "id.resp_h"),
                               conn_label(r), _zval(r, "ts")),
        "http.log": lambda r: (_zval(r, "id.orig_h"), _zval(r, "id.resp_h"),
                               "http", _zval(r, "ts")),
        "smb_mapping.log": lambda r: (_zval(r, "id.orig_h"), _zval(r, "id.resp_h"),
                                      "smb", _zval(r, "ts")),
        "kerberos.log": lambda r: (_zval(r, "id.orig_h"), _zval(r, "id.resp_h"),
                                   "krb", _zval(r, "ts")),
        "ntlm.log": lambda r: (_zval(r, "id.orig_h"), _zval(r, "id.resp_h"),
                               "ntlm", _zval(r, "ts")),
    }

    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".log"):
            continue
        full = os.path.join(path, fname)
        handler = handlers.get(fname)
        if handler:
            for row in read_zeek(full):
                src, dst, svc, ts = handler(row)
                try:
                    ts = float(ts) if ts else None
                except ValueError:
                    ts = None
                add(src, dst, svc, ts)
        elif fname == "dns.log":
            for row in read_zeek(full):
                query = _zval(row, "query")
                answers = _zval(row, "answers")
                if query and answers:
                    ip = first_ip(answers)
                    if ip and not _is_noise_ip(ip):
                        name_map[query] = ip

    edges = []
    for (src, dst), a in sorted(agg.items()):
        svcs = [s for s, _ in sorted(a["services"].items(), key=lambda kv: -kv[1])
                if s and s != "?"][:4]
        label = ",".join(svcs) if svcs else "conn"
        edges.append({"from": src, "to": dst, "label": label,
                      "count": a["count"], "first": a["first"], "last": a["last"]})
    return edges, name_map


# --------------------------------------------------------------------------- #
# graph build
# --------------------------------------------------------------------------- #
def build_graph(iocs: dict, zeek_edges: list[dict]) -> tuple[list[dict], list[dict]]:
    nodes: dict[str, dict] = {}

    def add_node(nid, label, ntype, tags=None, title="", role=""):
        if nid in nodes:
            return
        tags = tags or []
        nodes[nid] = {
            "id": nid,
            "label": label,
            "type": ntype,
            "tags": tags,
            "title": title,
            "color": TYPE_COLORS.get(ntype, color_for_tags(tags)),
            "size": 26 if ntype == "ipv4" else 16,
        }

    obs = iocs.get("observables", []) if isinstance(iocs, dict) else (iocs or [])
    known_ips: set[str] = set()
    for o in obs:
        if o.get("type") == "ipv4":
            known_ips.add(o.get("value", ""))

    for o in obs:
        typ = o.get("type", "?")
        val = o.get("value", "")
        nid = val if typ == "ipv4" else f"{typ}:{val}"
        tags = o.get("tags") or []
        title = "\n".join(x for x in [
            f"role: {o.get('role','')}",
            f"source: {o.get('source','')}",
            f"context: {o.get('context','')}",
            f"mitre: {o.get('mitre','')}",
            f"first: {o.get('first_seen_utc','')}",
            f"tags: {';'.join(tags) if isinstance(tags, list) else tags}",
        ] if x.split(":", 1)[-1].strip())
        add_node(nid, str(val)[:40], typ, tags, title, o.get("role", ""))

    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    def add_edge(a, b, label, title="", width=1.0):
        if a == b or (a, b, label) in seen_edges:
            return
        seen_edges.add((a, b, label))
        edges.append({"from": a, "to": b, "label": label, "title": title, "width": width})

    for e in zeek_edges:
        src, dst = e["from"], e["to"]
        add_node(src, src, "ipv4", title="observed in Zeek")
        add_node(dst, dst, "ipv4", title="observed in Zeek")
        lbl = e["label"] if e["count"] <= 1 else f"{e['label']} ×{e['count']}"
        add_edge(src, dst, lbl, width=min(1.0 + e["count"] * 0.15, 6.0))

    # attach non-IP observables to any known IP mentioned in their text
    for o in obs:
        typ = o.get("type", "?")
        if typ == "ipv4":
            continue
        val = o.get("value", "")
        nid = f"{typ}:{val}"
        blob = " ".join(str(o.get(k, "")) for k in ("value", "source", "context", "defanged"))
        for ip in set(IPV4_RE.findall(blob)):
            if ip in known_ips and ip in nodes:
                role = o.get("role", typ)
                add_edge(ip, nid, typ, title=role)
    return list(nodes.values()), edges


def build_matrix(obs: list[dict]) -> dict[str, list[dict]]:
    """tactic -> list of {id, count, values}."""
    tech: dict[str, dict] = {}
    for o in obs:
        raw = o.get("mitre", "") or ""
        for t in MITRE_RE.findall(raw):
            d = tech.setdefault(t, {"id": t, "count": 0, "values": []})
            d["count"] += 1
            if o.get("value"):
                d["values"].append(o["value"])
    grid: dict[str, list[dict]] = {t: [] for t in TACTIC_ORDER}
    for t, d in tech.items():
        grid[tactic_for(t)].append(d)
    for t in grid:
        grid[t].sort(key=lambda d: (-d["count"], d["id"]))
    return grid


# --------------------------------------------------------------------------- #
# HTML rendering
# --------------------------------------------------------------------------- #
def _assets_dir() -> str:
    return os.environ.get("DFIR_VIZ_ASSETS", "/opt/viz-assets")


def _load_asset(name: str) -> str | None:
    p = os.path.join(_assets_dir(), name)
    if os.path.isfile(p):
        return open(p, encoding="utf-8", errors="replace").read()
    return None


HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin:0; background:#11151c; color:#e6edf3;
  font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
header {{ padding:18px 24px; border-bottom:1px solid #2a3543; background:#0d1117; }}
header h1 {{ margin:0; font-size:18px; }}
header .sub {{ color:#8b949e; font-size:12px; margin-top:4px; }}
#container {{ width:100%; height:calc(100vh - 78px); }}
.legend {{ position:absolute; top:8px; right:8px; background:#0d1117cc; border:1px solid #2a3543;
  border-radius:6px; padding:8px 10px; font-size:11px; z-index:5; }}
.legend span {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; }}
.legend div {{ margin:2px 0; }}
table.matrix {{ border-collapse:collapse; width:calc(100% - 32px); margin:16px; }}
table.matrix th, table.matrix td {{ border:1px solid #2a3543; padding:6px 8px; vertical-align:top;
  font-size:12px; }}
table.matrix th {{ background:#0d1117; position:sticky; top:0; }}
.tech {{ display:inline-block; margin:2px 3px 2px 0; padding:2px 6px; border-radius:4px;
  background:#1f6feb; color:#fff; font-size:11px; }}
.tech.lo {{ background:#1a3a63; }}
.tech.md {{ background:#1f6feb; }}
.tech.hi {{ background:#b62324; }}
.fallback {{ padding:16px 24px; }}
.fallback table {{ border-collapse:collapse; width:100%; }}
.fallback td, .fallback th {{ border:1px solid #2a3543; padding:4px 8px; font-size:12px; }}
</style>{extra_css}
</head><body>
<header><h1>{title}</h1><div class="sub">{subtitle}</div></header>
"""


def html_timeline(rows: list[dict], title: str) -> str:
    extra_css = "".join(
        f".tl-{t}{{background:{c};border-color:{c};}}" for t, c in TAG_COLORS.items())
    head = HTML_HEAD.format(title=html.escape(title),
                            subtitle="Attack timeline (UTC) — hover an item for its source record",
                            extra_css=extra_css)
    if not rows:
        return head + "<div class='fallback'>No timeline rows.</div></body></html>"

    items, groups, seen_groups = [], [], set()
    for i, r in enumerate(rows):
        host = r["host"] or "unknown"
        if host not in seen_groups:
            seen_groups.add(host)
            groups.append({"id": host, "content": html.escape(host)})
        tags = [t for t in (r["tags"] or "").split(";") if t]
        ptag = primary_tag(tags)
        content = (r["event"] or "")[:70]
        tip = "\n".join(x for x in [
            r["time_utc"], f"host: {host}", f"actor: {r['actor']}",
            f"technique: {r['technique']}", f"tags: {r['tags']}",
            f"evidence: {r['evidence']}"] if x.split(": ", 1)[-1].strip())
        items.append({
            "id": i, "group": host, "start": r["time_utc"] or None,
            "content": html.escape(content), "className": f"tl-{ptag}",
            "title": html.escape(tip) if tip else None,
        })
    js = _load_asset("vis-timeline-graph2d.min.js")
    css = _load_asset("vis-timeline-graph2d.min.css")
    if not js:
        return _fallback_timeline(head, rows)
    return (head + (f"<style>{css}</style>" if css else "")
            + "<div id='container'></div><script>" + js + "</script><script>\n"
            + "var items=new vis.DataSet(" + json.dumps(items) + ");\n"
            + "var groups=new vis.DataSet(" + json.dumps(groups) + ");\n"
            + "var c=document.getElementById('container');\n"
            + "new vis.Timeline(c,items,groups,{stack:true,zoomable:true,"
              "moveable:true,selectable:true,horizontalScroll:true,"
              "minHeight:'100%',margin:{item:{horizontal:4}}});\n"
            + "</script></body></html>")


def _fallback_timeline(head: str, rows: list[dict]) -> str:
    h = ["<div class='fallback'><table><tr><th>UTC</th><th>Host</th><th>Event</th>"
         "<th>Tag</th><th>Evidence</th></tr>"]
    for r in rows:
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(r["time_utc"]), html.escape(r["host"]),
            html.escape(r["event"]), html.escape(r["tags"]),
            html.escape(r["evidence"])))
    h.append("</table></div></body></html>")
    return head + "".join(h)


def html_graph(nodes: list[dict], edges: list[dict], title: str) -> str:
    head = HTML_HEAD.format(title=html.escape(title),
                            subtitle="Actor / network graph — drag nodes; hover for source",
                            extra_css="")
    if not nodes:
        return head + "<div class='fallback'>No graph nodes.</div></body></html>"
    legend = ["<div class='legend'>"]
    for t in sorted({n["type"] for n in nodes}):
        legend.append(f"<div><span style='background:{TYPE_COLORS.get(t, DEFAULT_COLOR)}'></span>{html.escape(t)}</div>")
    legend.append("</div>")
    js = _load_asset("vis-network.min.js")
    if not js:
        return _fallback_graph(head, nodes, edges)
    return (head + "".join(legend)
            + "<div id='container'></div><script>" + js + "</script><script>\n"
            + "var nodes=new vis.DataSet(" + json.dumps(nodes) + ");\n"
            + "var edges=new vis.DataSet(" + json.dumps(edges) + ");\n"
            + "var c=document.getElementById('container');\n"
            + "new vis.Network(c,{nodes:nodes,edges:edges},{physics:{stabilization:true},"
              "nodes:{shape:'dot',font:{size:14,color:'#e6edf3'}},"
              "edges:{arrows:'to',font:{size:10,color:'#8b949e',align:'middle'},"
              "color:{color:'#3d4b5c',highlight:'#1f6feb'}},"
              "interaction:{hover:true,tooltipDelay:120}});\n"
            + "</script></body></html>")


def _fallback_graph(head: str, nodes: list[dict], edges: list[dict]) -> str:
    h = ["<div class='fallback'><table><tr><th>From</th><th>To</th><th>Label</th></tr>"]
    for e in edges:
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(str(e["from"])), html.escape(str(e["to"])),
            html.escape(str(e["label"]))))
    h.append("</table></div></body></html>")
    return head + "".join(h)


def html_matrix(grid: dict, title: str) -> str:
    head = HTML_HEAD.format(title=html.escape(title),
                            subtitle="MITRE ATT&CK coverage (from the `mitre` field)",
                            extra_css="")
    total = sum(len(v) for v in grid.values())
    if total == 0:
        return head + "<div class='fallback'>No MITRE techniques found.</div></body></html>"
    cols = [t for t in TACTIC_ORDER if grid.get(t)]
    h = ["<table class='matrix'><tr>"]
    for t in cols:
        h.append(f"<th>{html.escape(t)}</th>")
    h.append("</tr><tr>")
    for t in cols:
        h.append("<td>")
        for d in grid[t]:
            cls = "hi" if d["count"] >= 3 else ("md" if d["count"] == 2 else "lo")
            tip = html.escape("; ".join(sorted(set(map(str, d["values"])))[:8]))
            h.append(f"<span class='tech {cls}' title='{tip}'>{d['id']} ×{d['count']}</span>")
        h.append("</td>")
    h.append("</tr></table></body></html>")
    return head + "".join(h)


# --------------------------------------------------------------------------- #
# static rendering (matplotlib / networkx)
# --------------------------------------------------------------------------- #
def render_static(out_dir: str, formats: list[str], rows: list[dict],
                  nodes: list[dict], edges: list[dict], grid: dict, title: str) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # noqa: BLE001
        print(f"[incident_viz] static formats skipped (matplotlib missing: {exc})",
              file=sys.stderr)
        return []
    written = []

    # timeline -----------------------------------------------------------------
    if rows:
        fig, ax = plt.subplots(figsize=(14, max(4, len(rows) * 0.32)))
        hosts = sorted({r["host"] or "unknown" for r in rows})
        ypos = {h: i for i, h in enumerate(hosts)}
        for i, r in enumerate(rows):
            dt = parse_time(r["time_utc"], (1970, 1, 1))
            if not dt:
                continue
            tags = [t for t in (r["tags"] or "").split(";") if t]
            ax.scatter(dt, ypos[r["host"] or "unknown"], s=90,
                       color=color_for_tags(tags), zorder=3)
            ax.annotate(str(i + 1), (dt, ypos[r["host"] or "unknown"]),
                        fontsize=7, ha="center", va="center", color="white", zorder=4)
        ax.set_yticks(range(len(hosts)))
        ax.set_yticklabels(hosts)
        ax.set_xlabel("Time (UTC)")
        ax.set_title(title + " — attack timeline (numbered = row order)")
        ax.grid(True, axis="x", alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()
        for ext in formats:
            p = os.path.join(out_dir, f"attack_timeline.{ext}")
            fig.savefig(p, dpi=130)
            written.append(p)
        plt.close(fig)

    # graph --------------------------------------------------------------------
    if nodes:
        try:
            import networkx as nx
        except Exception as exc:  # noqa: BLE001
            print(f"[incident_viz] graph svg skipped (networkx missing: {exc})",
                  file=sys.stderr)
            nx = None
        if nx is not None:
            g = nx.DiGraph()
            for n in nodes:
                g.add_node(n["id"], color=n.get("color", DEFAULT_COLOR), label=n["label"])
            for e in edges:
                g.add_edge(e["from"], e["to"], label=e.get("label", ""))
            fig, ax = plt.subplots(figsize=(14, 10))
            try:
                pos = nx.spring_layout(g, k=0.6, seed=7, iterations=80)
            except TypeError:
                pos = nx.spring_layout(g, k=0.6, seed=7)
            ncolors = [g.nodes[n].get("color", DEFAULT_COLOR) for n in g.nodes]
            nx.draw_networkx_nodes(g, pos, ax=ax, node_color=ncolors,
                                   node_size=[300 if n.get("type") == "ipv4" else 120
                                              for n in nodes])
            nx.draw_networkx_edges(g, pos, ax=ax, arrows=True, alpha=0.5,
                                   edge_color="#7f8c8d")
            nx.draw_networkx_labels(g, pos, ax=ax, font_size=7,
                                    labels={n["id"]: n["label"] for n in nodes})
            ax.set_title(title + " — actor / network graph")
            ax.axis("off")
            fig.tight_layout()
            for ext in formats:
                p = os.path.join(out_dir, f"actor_graph.{ext}")
                fig.savefig(p, dpi=130)
                written.append(p)
            plt.close(fig)

    # matrix -------------------------------------------------------------------
    cols = [t for t in TACTIC_ORDER if grid.get(t)]
    if cols:
        fig, ax = plt.subplots(figsize=(1.6 * len(cols), 5))
        ax.axis("off")
        for i, t in enumerate(cols):
            ax.text(i + 0.5, 0.96, t, rotation=0, ha="center", va="top",
                    fontsize=8, wrap=True)
            y = 0.88
            for d in grid[t]:
                ax.text(i + 0.04, y, f"{d['id']} ×{d['count']}", fontsize=7,
                        ha="left", va="top")
                y -= 0.05
        ax.set_xlim(0, len(cols)); ax.set_ylim(0, 1)
        ax.set_title(title + " — MITRE ATT&CK coverage")
        for ext in formats:
            p = os.path.join(out_dir, f"mitre_matrix.{ext}")
            fig.savefig(p, dpi=130, bbox_inches="tight")
            written.append(p)
        plt.close(fig)
    return written


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Render incident visuals from DFIR artifacts.")
    ap.add_argument("--iocs", help="structured IOC JSON (observables)")
    ap.add_argument("--timeline", help="normalized timeline CSV")
    ap.add_argument("--from-markdown", dest="from_md",
                    help="Markdown report with a consolidated chain table")
    ap.add_argument("--zeek", help="directory of Zeek *.log")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--title", default="Incident", help="case title")
    ap.add_argument("--date", default="", help="override date YYYY-MM-DD for bare times")
    ap.add_argument("--formats", default="html,svg",
                    help="comma list: html,svg,png (default html,svg)")
    args = ap.parse_args(argv)

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    os.makedirs(args.out, exist_ok=True)

    # date context for bare HH:MM times
    date_ctx = datetime.now(UTC).timetuple()[:3]
    date_explicit = False
    if args.date:
        try:
            date_ctx = tuple(int(x) for x in args.date.split("-")[:3])  # type: ignore
            date_explicit = True
        except Exception:  # noqa: BLE001
            pass

    # IOCs
    iocs = {}
    if args.iocs:
        iocs = json.load(open(args.iocs, encoding="utf-8"))
    obs = iocs.get("observables", []) if isinstance(iocs, dict) else (iocs or [])
    if isinstance(iocs, dict) and iocs.get("case") and args.title == "Incident":
        args.title = iocs["case"]

    # timeline
    if args.timeline:
        rows = read_timeline_csv(args.timeline)
    elif args.from_md:
        if not date_explicit:
            found = infer_date(args.from_md) or infer_date_from_iocs(obs)
            if found:
                date_ctx = found
            else:
                print("[incident_viz] WARNING: no full date found; anchoring bare "
                      "HH:MM times to today. Pass --date YYYY-MM-DD to fix.",
                      file=sys.stderr)
        rows = timeline_from_markdown(args.from_md, date_ctx)
    else:
        rows = []
    if rows:
        write_timeline_csv(rows, os.path.join(args.out, "timeline.csv"))
        json.dump(rows, open(os.path.join(args.out, "timeline.json"), "w"),
                  indent=2, ensure_ascii=False)

    # Zeek + graph
    zeek_edges = []
    if args.zeek and os.path.isdir(args.zeek):
        zeek_edges, _ = parse_zeek_dir(args.zeek)
    nodes, edges = build_graph(iocs, zeek_edges)
    if nodes:
        json.dump({"nodes": nodes, "edges": edges},
                  open(os.path.join(args.out, "graph.json"), "w"), indent=2, ensure_ascii=False)

    grid = build_matrix(obs)

    written = []
    if "html" in formats:
        p = os.path.join(args.out, "attack_timeline.html"); open(p, "w").write(html_timeline(rows, args.title)); written.append(p)
        p = os.path.join(args.out, "actor_graph.html"); open(p, "w").write(html_graph(nodes, edges, args.title)); written.append(p)
        p = os.path.join(args.out, "mitre_matrix.html"); open(p, "w").write(html_matrix(grid, args.title)); written.append(p)
    static = [f for f in formats if f in ("svg", "png")]
    written += render_static(args.out, static, rows, nodes, edges, grid, args.title)

    print(f"[incident_viz] wrote {len(written)} file(s) to {args.out}", file=sys.stderr)
    for w in written:
        print(f"  {os.path.basename(w)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
