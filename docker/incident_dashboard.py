#!/usr/bin/env python3
"""incident_dashboard.py -- one self-contained, filterable incident dashboard.

Part of the container-only DFIR workspace. Aggregates already-produced artifacts
into a SINGLE offline HTML file:

  --iocs        structured observables (analysis/iocs.json; `hosts` field used
                for per-endpoint attribution)
  --timeline    normalized timeline CSV (time_utc,host,actor,event,...)
  --graph       prebuilt graph.json (nodes/edges) -- optional; rebuilt from IOCs
                + Zeek if omitted
  --zeek        directory of Zeek *.log (adds observed network edges)
  --proc        one or more flattened Security.tsv files (4688) for process
                trees; may be repeated. Host name taken from the `computer`
                column, else from --proc-host
  --out         output directory (default reports/)

Output: ``reports/dashboard.html`` -- a single file with vis.js inlined, so it
opens in any browser with no network and no server. Every panel (timeline,
actor graph, process tree, observables, IOCs, ATT&CK matrix) is scoped live by
an endpoint filter ("All endpoints" = the global view).

Stdlib only. Reuses incident_viz.py for colours, tag heuristics and graph build
when it sits beside this script.
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
from datetime import datetime, timezone

UTC = timezone.utc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import incident_viz as viz  # reuse colours / heuristics / graph build
except Exception:  # noqa: BLE001 -- degrade to local copies if unavailable
    viz = None

# local fallbacks if incident_viz is missing ---------------------------------- #
TACTIC_ORDER = getattr(viz, "TACTIC_ORDER", [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Other",
])
TECHNIQUE_TACTICS = getattr(viz, "TECHNIQUE_TACTICS", {})
TAG_COLORS = getattr(viz, "TAG_COLORS", {})
TYPE_COLORS = getattr(viz, "TYPE_COLORS", {})
DEFAULT_COLOR = getattr(viz, "DEFAULT_COLOR", "#3498db")
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _assets_dir() -> str:
    return os.environ.get("DFIR_VIZ_ASSETS", "/opt/viz-assets")


def _load_asset(name: str) -> str:
    p = os.path.join(_assets_dir(), name)
    if os.path.isfile(p):
        return open(p, encoding="utf-8", errors="replace").read()
    return ""


IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def norm_host(v: str) -> str:
    """Normalise a host label to a short endpoint name."""
    v = (v or "").strip()
    v = v.split(".")[0] if re.match(r"^[A-Za-z0-9-]+\.", v) else v
    m = {"dc2": "DC2", "sqlsvr": "SqlSvr", "dc1": "DC1", "dev01": "Attacker",
         "attacker": "Attacker"}
    return m.get(v.lower(), v or "Unknown")


# --------------------------------------------------------------------------- #
# inputs
# --------------------------------------------------------------------------- #
def read_timeline(path: str) -> list[dict]:
    cols = ["time_utc", "host", "actor", "event", "technique", "evidence", "tags"]
    rows = []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            row = {c: (r.get(c) or "").strip() for c in cols}
            row["host"] = norm_host(row["host"])
            rows.append(row)
    rows.sort(key=lambda x: x["time_utc"] or "")
    return rows


def read_iocs(path: str) -> dict:
    d = json.load(open(path, encoding="utf-8"))
    obs = d.get("observables", []) if isinstance(d, dict) else (d or [])
    for o in obs:
        hs = o.get("hosts")
        if not hs:
            hs = _infer_hosts(o)
        if isinstance(hs, str):
            hs = [hs]
        o["hosts"] = [norm_host(h) for h in (hs or [])]
    return {"case": d.get("case", "Incident") if isinstance(d, dict) else "Incident",
            "observables": obs}


def _infer_hosts(o: dict) -> list[str]:
    """Best-effort endpoint attribution from an observable's text."""
    blob = " ".join(str(o.get(k, "")) for k in
                    ("value", "source", "context", "defanged", "role")).lower()
    hosts = []
    if "sqlsvr" in blob:
        hosts.append("SqlSvr")
    if re.search(r"\bdc2\b", blob):
        hosts.append("DC2")
    if re.search(r"\bdc1\b", blob):
        hosts.append("DC1")
    if "192.168.186.135" in blob or "dev01" in blob or "attacker" in blob:
        hosts.append("Attacker")
    return hosts


def ip_host_map(obs: list[dict]) -> dict[str, str]:
    m = {}
    known = {"192.168.186.139": "SqlSvr", "192.168.186.30": "DC2",
             "192.168.186.10": "DC1", "192.168.186.135": "Attacker"}
    m.update(known)
    for o in obs:
        if o.get("type") == "ipv4" and o.get("hosts"):
            m.setdefault(str(o.get("value")), o["hosts"][0])
    return m


# --------------------------------------------------------------------------- #
# process trees from flattened Security.tsv (4688)
# --------------------------------------------------------------------------- #
INTERESTING = re.compile(
    r"certutil[^\r\n]*urlcache"
    r"|\bnc\.exe\b"
    r"|mimikatz"
    r"|sigmapotato"
    r"|wevtutil[^\r\n]*\bcl\b"
    r"|reg(?:\.exe)?\s+save\b"
    r"|fypdjnvh"
    r"|psexec"
    r"|net(?:\.exe)?\s+use\b[^\r\n]*/user:"
    r"|powershell[^\r\n]*\s-(?:e|enc|encodedcommand)\b"
    r"|whoami\s+/priv"
    r"|\bFTK Imager\.exe\b"
    r"|Exterro_FTK"
    r"|\\temp\\[^\s\"]+\.exe",
    re.I)


def _parse_kv(data: str) -> dict:
    out = {}
    for part in (data or "").split(" | "):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def read_process_events(path: str, host_override: str = "") -> list[dict]:
    evs = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        rdr = csv.DictReader(fh, delimiter="\t")
        for r in rdr:
            if str(r.get("event_id")) != "4688":
                continue
            d = _parse_kv(r.get("data", ""))
            name = d.get("NewProcessName", "")
            cmd = d.get("CommandLine", "")

            def hx(x):
                try:
                    return int(str(x), 16)
                except Exception:  # noqa: BLE001
                    return None

            evs.append({
                "host": norm_host(host_override or r.get("computer", "")),
                "ts": (r.get("time_utc") or "")[:19],
                "pid": hx(d.get("NewProcessId")),
                "ppid": hx(d.get("ProcessId")),
                "name": name.rsplit("\\", 1)[-1],
                "path": name,
                "cmd": cmd,
                "parent": (d.get("ParentProcessName", "") or "").rsplit("\\", 1)[-1],
                "user": d.get("SubjectUserName", ""),
                "logon": d.get("SubjectLogonId", ""),
                "interesting": bool(INTERESTING.search(name + " " + cmd)),
            })
    return evs


def build_trees(events: list[dict]) -> dict[str, list[dict]]:
    """host -> list of root nodes (nested).

    Uses a time-aware parent lookup: a child's PPID resolves to the most recent
    process with that PID **created no later than the child** (same host). This
    avoids merging unrelated processes that reuse the same PID across boots.

    Keeps only the attacker-relevant lineage: each interesting process, its
    ancestor chain, and its descendants; unrelated siblings are pruned.
    """
    by_host = defaultdict(list)
    for e in events:
        by_host[e["host"]].append(e)

    # regex for the tools we always want to surface
    HIGH = re.compile(r"certutil|nc\.exe|mimikatz|sigmapotato|wevtutil|"
                      r"fypdjnvh|psexec|psexesvc|reg\.exe", re.I)

    trees: dict[str, list[dict]] = {}
    for host, evs in by_host.items():
        evs = sorted(evs, key=lambda e: e["ts"] or "")
        # index events, give each a stable local id
        for i, e in enumerate(evs):
            e["_id"] = i

        # pid -> events (sorted by ts), for closest-preceding parent lookup
        by_pid: dict[int, list[dict]] = defaultdict(list)
        for e in evs:
            if e["pid"] is not None:
                by_pid[e["pid"]].append(e)

        def resolve_parent(child: dict):
            ppid = child["ppid"]
            if ppid is None:
                return None
            cands = [p for p in by_pid.get(ppid, []) if (p["ts"] or "") <= (child["ts"] or "")]
            if not cands:
                return None
            return max(cands, key=lambda p: p["ts"] or "")

        # adjacency by event id
        parent_of: dict[int, int | None] = {}
        children: dict[int, list[int]] = defaultdict(list)
        seen_edge: set[tuple] = set()
        for e in evs:
            par = resolve_parent(e)
            pid_key = par["_id"] if par else None
            parent_of[e["_id"]] = pid_key
            if pid_key is not None and pid_key != e["_id"] and (pid_key, e["_id"]) not in seen_edge:
                seen_edge.add((pid_key, e["_id"]))
                children[pid_key].append(e["_id"])

        # keep = interesting + their ancestors + their descendants
        keep: set[int] = set()
        idx = {e["_id"]: e for e in evs}

        def mark_ancestors(i):
            seen = set()
            while i is not None and i in idx and i not in seen:
                seen.add(i)
                keep.add(i)
                i = parent_of.get(i)

        def mark_descendants(i, depth=0):
            if depth > 6:
                return
            for c in children.get(i, []):
                if c not in keep:
                    keep.add(c)
                    mark_descendants(c, depth + 1)

        for e in evs:
            if e["interesting"]:
                keep.add(e["_id"])
                mark_ancestors(parent_of.get(e["_id"]))
                mark_descendants(e["_id"])

        def build_node(i, depth=0, seen=None):
            seen = seen or set()
            if i in seen or i not in idx or depth > 10:
                return None
            seen = seen | {i}
            e = idx[i]
            kids = [n for c in children.get(i, []) if c in keep
                    for n in [build_node(c, depth + 1, seen)] if n]
            return {
                "pid": e["pid"], "name": e["name"], "cmd": e["cmd"][:220],
                "user": e["user"], "ts": e["ts"], "interesting": e["interesting"],
                "children": kids,
            }

        roots = []
        for e in evs:
            if e["_id"] in keep and parent_of.get(e["_id"]) not in keep:
                n = build_node(e["_id"])
                if n:
                    roots.append(n)

        def count(n):
            return 1 + sum(count(c) for c in n["children"])

        def score(n):
            s = 0
            stack = [n]
            while stack:
                x = stack.pop()
                if HIGH.search(x["name"] + " " + x["cmd"]):
                    s += 5
                s += 1 if x["interesting"] else 0
                stack += x["children"]
            return s

        roots.sort(key=lambda n: (-score(n), -count(n), n["ts"]))

        # collapse identical *leaf* roots (e.g. the 15 wevtutil log-clearing
        # invocations) into one entry carrying a repeat count
        merged: list[dict] = []
        leaf_index: dict[tuple, dict] = {}
        for r in roots:
            key = None
            if not r["children"]:
                key = (r["name"], r["user"])
            if key and key in leaf_index:
                leaf_index[key]["repeat"] += 1
                continue
            r.setdefault("repeat", 1)
            if key:
                leaf_index[key] = r
            merged.append(r)
        trees[host] = merged
    return trees


# --------------------------------------------------------------------------- #
# graph with host attribution
# --------------------------------------------------------------------------- #
def build_graph(iocs: dict, zeek_edges: list[dict], ipmap: dict[str, str]):
    if viz is not None:
        nodes, edges = viz.build_graph(iocs, zeek_edges)
    else:  # minimal fallback
        nodes, edges = [], []
        for o in iocs["observables"]:
            nodes.append({"id": o["value"], "label": o["value"][:40],
                          "type": o.get("type"), "tags": o.get("tags", []),
                          "title": o.get("context", ""),
                          "color": TYPE_COLORS.get(o.get("type"), DEFAULT_COLOR),
                          "size": 18})
    # attach hosts to every node
    obs_hosts = {}
    for o in iocs["observables"]:
        nid = o["value"] if o.get("type") == "ipv4" else f"{o.get('type')}:{o['value']}"
        obs_hosts[nid] = o.get("hosts") or []
    for n in nodes:
        hs = obs_hosts.get(n["id"], [])
        if not hs:
            hs = [ipmap[n["id"]]] if n["id"] in ipmap else []
        if not hs and n.get("type") == "ipv4":
            hs = ["Network"]
        n["hosts"] = hs
        if not n.get("title"):
            n["title"] = "endpoint: " + (", ".join(hs) if hs else "—")
        else:
            n["title"] = n["title"] + "\nendpoint: " + (", ".join(hs) if hs else "—")
    # drop endpoints' self-loops / keep edges but note host of edge = union
    for e in edges:
        a, b = e["from"], e["to"]
        ha = next((n["hosts"] for n in nodes if n["id"] == a), [])
        hb = next((n["hosts"] for n in nodes if n["id"] == b), [])
        e["hosts"] = sorted(set(ha) | set(hb))
    return nodes, edges


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
:root { color-scheme: dark; --bg:#11151c; --bg2:#0d1117; --line:#2a3543;
  --fg:#e6edf3; --mut:#8b949e; --acc:#1f6feb; }
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);background:var(--bg2);
  position:sticky;top:0;z-index:50}
header h1{margin:0;font-size:18px}
header .sub{color:var(--mut);font-size:12px;margin-top:3px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
.bar label{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{background:#161b22;border:1px solid var(--line);color:var(--fg);
  border-radius:999px;padding:5px 12px;cursor:pointer;font-size:13px}
.chip.active{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}
.chip.benign.active{background:#6e7681;border-color:#6e7681}
.search{background:#0d1117;border:1px solid var(--line);color:var(--fg);
  border-radius:6px;padding:6px 10px;font-size:13px;min-width:220px}
.switch{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px;cursor:pointer}
.stats{display:flex;gap:10px;flex-wrap:wrap;padding:12px 24px 0}
.stat{background:#0d1117;border:1px solid var(--line);border-radius:8px;
  padding:8px 14px;min-width:110px}
.stat .n{font-size:20px;font-weight:700}
.stat .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
nav.tabs{display:flex;gap:2px;padding:12px 24px 0;flex-wrap:wrap}
nav.tabs button{background:#0d1117;border:1px solid var(--line);border-bottom:none;
  color:var(--mut);padding:8px 16px;border-radius:8px 8px 0 0;cursor:pointer;font-size:13px}
nav.tabs button.active{color:var(--fg);background:#161b22;font-weight:600}
main{padding:0 24px 40px}
section.panel{display:none;background:#161b22;border:1px solid var(--line);
  border-radius:0 8px 8px 8px;padding:16px}
section.panel.active{display:block}
#container{width:100%;height:60vh;min-height:420px}
.hint{color:var(--mut);font-size:12px;margin:0 0 10px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{border:1px solid var(--line);padding:6px 8px;vertical-align:top;text-align:left}
th{background:#0d1117;position:sticky;top:0;cursor:pointer;user-select:none}
tr:hover td{background:#1a2029}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;
  background:#21262d;margin:1px 2px 1px 0;border:1px solid var(--line)}
.badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px}
.b-high{background:#7d1a1a;color:#ffd7d7}
.b-medium{background:#7a5b12;color:#ffe9b0}
.b-low{background:#1a3a63}
.b-benign{background:#30363d;color:#c9d1d9}
.conf-benign{background:#30363d;color:#c9d1d9}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:16px}
ul.tree>li{margin:2px 0}
.proc{border-left:3px solid var(--line);padding:3px 8px;margin:2px 0;border-radius:0 4px 4px 0}
.proc.hit{border-left-color:#e74c3c}
.proc .nm{font-weight:600;font-family:ui-monospace,monospace}
.proc .cmd{color:var(--mut);font-size:11px;word-break:break-all}
.proc .meta{color:#6e7681;font-size:10px}
.tree-host{margin:0 0 18px}
.tree-host h3{margin:6px 0;font-size:14px}
.matrix{display:flex;gap:8px;overflow-x:auto;padding-bottom:8px}
.tac{min-width:150px;background:#0d1117;border:1px solid var(--line);
  border-radius:6px;padding:8px}
.tac h4{margin:0 0 6px;font-size:11px;color:var(--mut);text-transform:uppercase;
  letter-spacing:.5px}
.tech{display:block;background:#1f6feb;color:#fff;border-radius:4px;
  padding:2px 6px;margin:3px 0;font-size:11px}
.tech.hi{background:#b62324}
.tech.md{background:#1f6feb}
.tech.lo{background:#1a3a63}
.legend{display:flex;gap:14px;flex-wrap:wrap;color:var(--mut);font-size:12px;margin:8px 0}
.legend span.sw{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:4px}
.empty{color:var(--mut);padding:16px;font-style:italic}
footer{color:#6e7681;font-size:11px;padding:0 24px 30px}
a{color:var(--acc)}
</style>
</head><body>
<header>
  <h1>$title</h1>
  <div class="sub">$subtitle</div>
  <div class="bar">
    <label>Endpoint</label>
    <div class="chips" id="hostChips"></div>
    <input class="search" id="search" placeholder="filter text (host, event, IOC, command…)">
    <label class="switch"><input type="checkbox" id="hideBenign"> hide benign / responder</label>
  </div>
</header>

<div class="stats" id="stats"></div>

<nav class="tabs" id="tabs">
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="timeline">Timeline</button>
  <button data-tab="graph">Actor graph</button>
  <button data-tab="trees">Process trees</button>
  <button data-tab="observables">Observables</button>
  <button data-tab="iocs">IOCs</button>
  <button data-tab="matrix">ATT&amp;CK</button>
</nav>

<main>
  <section class="panel active" id="p-overview">
    <p class="hint">Per-endpoint summary of the attack chain. Select an endpoint
      above to scope every tab (the default “All endpoints” is the global view).</p>
    <div id="overviewCards"></div>
  </section>
  <section class="panel" id="p-timeline">
    <p class="hint">Attack timeline (UTC). Hover an item for its source record.
      Rows are scoped to the selected endpoint.</p>
    <div id="container" style="height:64vh"></div>
  </section>
  <section class="panel" id="p-graph">
    <p class="hint">Attacker / victim / observable relationships. Drag nodes; hover for source.</p>
    <div class="legend" id="graphLegend"></div>
    <div id="graphContainer" style="width:100%;height:64vh"></div>
  </section>
  <section class="panel" id="p-trees">
    <p class="hint">Process trees derived from Security 4688 (attacker-relevant
      processes + lineage). Endpoint-filtered.</p>
    <div id="trees"></div>
  </section>
  <section class="panel" id="p-observables">
    <p class="hint">All observables (includes benign/responder). Click a header to sort.</p>
    <div id="obsTable"></div>
  </section>
  <section class="panel" id="p-iocs">
    <p class="hint">Threat-intel view: benign/responder observables removed.</p>
    <div id="iocTable"></div>
  </section>
  <section class="panel" id="p-matrix">
    <p class="hint">MITRE ATT&amp;CK coverage from observables in scope.</p>
    <div class="matrix" id="matrix"></div>
  </section>
</main>
<footer>Generated $generated by incident_dashboard.py — offline, self-contained.</footer>

<style>$viscss</style>
<script>$visnet</script>
<script>$vistimeline</script>
<script>
const DATA = $data;
const TACTICS = $tactics;
const TECH_TACTICS = $tech_tactics;
const TAG_COLORS = $tag_colors;
const ALL = "__ALL__";

let state = { host: ALL, q: "", hideBenign: false };
const hosts = DATA.hosts;

function inHost(itemHosts){
  if(state.host === ALL) return true;
  return (itemHosts||[]).includes(state.host);
}
function textMatch(blob){
  if(!state.q) return true;
  return (blob||"").toLowerCase().includes(state.q.toLowerCase());
}
function isBenign(o){
  const t = (o.tags||[]).join(" ").toLowerCase() + " " + (o.confidence||"");
  return /benign|responder|internal/.test(t);
}
function filtObs(list){
  return list.filter(o => inHost(o.hosts) && textMatch(JSON.stringify(o)) &&
    (!state.hideBenign || !isBenign(o)));
}

/* ---- header chips ---- */
function renderChips(){
  const box = document.getElementById('hostChips');
  const list = [ALL].concat(hosts);
  box.innerHTML = list.map(h =>
    `<div class="chip ${state.host===h?'active':''}" data-h="${h}">${h===ALL?'All endpoints':h}</div>`
  ).join('');
  box.querySelectorAll('.chip').forEach(c => c.onclick = () => {
    state.host = c.dataset.h; renderChips(); renderAll();
  });
}

/* ---- stats ---- */
function renderStats(){
  const obs = filtObs(DATA.observables);
  const tl = DATA.timeline.filter(r => inHost([r.host]) && textMatch(JSON.stringify(r)));
  const tech = new Set(); obs.forEach(o => (o.mitre||"").split(/[,\s]+/).forEach(t=>t&&tech.add(t)));
  const cards = [
    ['Endpoints', hosts.length],
    ['Timeline events', tl.length],
    ['Observables', obs.length],
    ['IOCs (non-benign)', obs.filter(o=>!isBenign(o)).length],
    ['ATT&CK techniques', tech.size],
  ];
  document.getElementById('stats').innerHTML = cards.map(c =>
    `<div class="stat"><div class="n">${c[1]}</div><div class="l">${c[0]}</div></div>`).join('');
}

/* ---- timeline ---- */
let timelineObj = null;
function renderTimeline(){
  const rows = DATA.timeline.filter(r => inHost([r.host]) && textMatch(JSON.stringify(r)));
  const el = document.getElementById('container');
  const items=[], groups=[], seen=new Set();
  rows.forEach((r,i)=>{
    const host=r.host;
    if(!seen.has(host)){ seen.add(host); groups.push({id:host, content:host}); }
    const tags=(r.tags||'').split(';').filter(Boolean);
    const ptag=tags[0]||'default';
    items.push({id:i, group:host, start:r.time_utc||null,
      content:(r.event||'').slice(0,70),
      className:'tl-'+(TAG_COLORS[ptag]?'x':'default'),
      style:'background:'+(TAG_COLORS[ptag]||'#3498db')+';border-color:'+(TAG_COLORS[ptag]||'#3498db')+';color:#fff',
      title:[r.time_utc,'host: '+host,'actor: '+r.actor,'technique: '+r.technique,
             'tags: '+r.tags,'evidence: '+r.evidence].filter(x=>x.split(': ')[1]).join('\n')});
  });
  if(timelineObj){ try{timelineObj.destroy();}catch(e){} timelineObj=null; }
  el.innerHTML='';
  if(!items.length){ el.innerHTML='<div class="empty">No timeline rows for this filter.</div>'; return; }
  if(!(window.vis && vis.Timeline)){ el.innerHTML='<div class="empty">Timeline library unavailable.</div>'; return; }
  timelineObj = new vis.Timeline(el, new vis.DataSet(items), new vis.DataSet(groups),
    {stack:true, zoomable:true, moveable:true, selectable:true, horizontalScroll:true,
     minHeight:'100%', margin:{item:{horizontal:4}}});
}

/* ---- graph ---- */
let netObj=null;
function renderGraph(){
  const nodes = DATA.graph.nodes.filter(n => inHost(n.hosts));
  const ids = new Set(nodes.map(n=>n.id));
  const edges = DATA.graph.edges.filter(e => ids.has(e.from) && ids.has(e.to));
  const el=document.getElementById('graphContainer');
  if(netObj){ try{netObj.destroy();}catch(e){} netObj=null; }
  el.innerHTML='';
  if(!nodes.length){ el.innerHTML='<div class="empty">No graph nodes for this filter.</div>'; return; }
  if(!(window.vis && vis.Network)){ el.innerHTML='<div class="empty">Graph library unavailable.</div>'; return; }
  const types=[...new Set(nodes.map(n=>n.type))];
  document.getElementById('graphLegend').innerHTML = types.map(t =>
    `<span><span class="sw" style="background:${(DATA.type_colors[t]||'#3498db')}"></span>${t}</span>`).join('');
  netObj = new vis.Network(el, {nodes:new vis.DataSet(nodes), edges:new vis.DataSet(edges)},
    {physics:{stabilization:true},
     nodes:{shape:'dot', font:{size:14,color:'#e6edf3'}},
     edges:{arrows:'to', font:{size:10,color:'#8b949e',align:'middle'},
            color:{color:'#3d4b5c',highlight:'#1f6feb'}},
     interaction:{hover:true, tooltipDelay:120}});
}

/* ---- process trees ---- */
function procNode(n){
  const kids = n.children.map(procNode).join('');
  return `<li><div class="proc ${n.interesting?'hit':''}">
    <div class="nm">${esc(n.name)} <span class="meta">pid ${n.pid} · ${esc(n.user||'')} · ${esc(n.ts)}${n.repeat>1?' · ×'+n.repeat+' identical':''}</span></div>
    ${n.cmd?`<div class="cmd">${esc(n.cmd)}</div>`:''}
    ${kids?`<ul>${kids}</ul>`:''}
  </div></li>`;
}
function renderTrees(){
  const box=document.getElementById('trees');
  const parts=[];
  for(const host of hosts){
    if(state.host!==ALL && state.host!==host) continue;
    const roots=(DATA.trees[host]||[]);
    if(!roots.length) continue;
    parts.push(`<div class="tree-host"><h3>${host} <span class="meta">${countNodes(roots)} processes kept</span></h3>
      <ul class="tree">${roots.map(procNode).join('')}</ul></div>`);
  }
  box.innerHTML = parts.length?parts.join(''):'<div class="empty">No process data for this filter.</div>';
}
function countNodes(roots){ let n=0; const w=r=>{n++; r.children.forEach(w);}; roots.forEach(w); return n; }

/* ---- tables ---- */
function obsRow(o){
  const val = o.defanged ? `<span class="mono">${esc(o.defanged)}</span>` : `<span class="mono">${esc(o.value)}</span>`;
  const hs = (o.hosts||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join('');
  const tags=(o.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
  const conf=o.confidence?`<span class="badge b-${o.confidence}">${o.confidence}</span>`:'';
  return `<tr><td>${esc(o.type)}</td><td>${val}</td><td>${esc(o.role||'')}</td>
    <td>${hs}</td><td>${conf}</td><td class="mono">${esc(o.first_seen_utc||'')}</td>
    <td>${esc(o.mitre||'')}</td><td>${tags}</td>
    <td>${esc(o.context||'')}</td><td>${esc(o.source||'')}</td></tr>`;
}
const OBS_HEAD=['type','value (defanged)','role','endpoints','confidence','first seen (UTC)','mitre','tags','context','source'];
function renderTable(elId, list){
  const el=document.getElementById(elId);
  if(!list.length){ el.innerHTML='<div class="empty">No rows for this filter.</div>'; return; }
  el.innerHTML=`<table><thead><tr>${OBS_HEAD.map(h=>`<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${list.map(obsRow).join('')}</tbody></table>`;
}
function renderObservables(){ renderTable('obsTable', filtObs(DATA.observables)); }
function renderIocs(){ renderTable('iocTable', filtObs(DATA.observables).filter(o=>!isBenign(o))); }

/* ---- matrix ---- */
function renderMatrix(){
  const obs=filtObs(DATA.observables);
  const tech={};
  obs.forEach(o=>{ (o.mitre||'').split(/[,\s]+/).filter(t=>/^T\d{4}/.test(t)).forEach(t=>{
    tech[t]=tech[t]||{n:0,vals:[]}; tech[t].n++; if(o.value) tech[t].vals.push(o.value);
  });});
  const grid={}; TACTICS.forEach(t=>grid[t]=[]);
  for(const t in tech){
    const base=t.split('.')[0];
    let tac=TECH_TACTICS[t]||TECH_TACTICS[base]||'Other';
    grid[tac].push({id:t,n:tech[t].n,vals:tech[t].vals});
  }
  const cols=TACTICS.filter(t=>grid[t].length);
  const el=document.getElementById('matrix');
  if(!cols.length){ el.innerHTML='<div class="empty">No ATT&CK techniques for this filter.</div>'; return; }
  el.innerHTML=cols.map(t=>`<div class="tac"><h4>${t}</h4>${grid[t].sort((a,b)=>b.n-a.n)
    .map(d=>`<span class="tech ${d.n>=3?'hi':(d.n===2?'md':'lo')}" title="${esc([...new Set(d.vals)].slice(0,8).join('; '))}">${d.id} ×${d.n}</span>`).join('')}</div>`).join('');
}

/* ---- overview ---- */
function renderOverview(){
  const parts=[];
  for(const host of hosts){
    if(state.host!==ALL && state.host!==host) continue;
    const tl=DATA.timeline.filter(r=>r.host===host);
    const obs=DATA.observables.filter(o=>(o.hosts||[]).includes(host));
    const atk=obs.filter(o=>!isBenign(o));
    const first=tl[0]?tl[0].time_utc:'—', last=tl.length?tl[tl.length-1].time_utc:'—';
    const tech=[...new Set(tl.flatMap(r=>(r.technique||'').split(/[,\s]+/)).filter(Boolean))];
    parts.push(`<div class="stat" style="min-width:auto">
      <div style="font-weight:700;font-size:15px;margin-bottom:6px">${host}</div>
      <div style="font-size:12px;color:var(--mut)">Window: ${first} → ${last}</div>
      <div style="margin-top:6px">events <b>${tl.length}</b> · observables <b>${obs.length}</b>
        · attacker IOCs <b>${atk.length}</b> · techniques <b>${tech.length}</b></div>
      <div style="margin-top:8px">${tech.map(t=>`<span class="tech lo" style="display:inline-block">${t}</span>`).join('')}</div>
    </div>`);
  }
  document.getElementById('overviewCards').innerHTML =
    `<div class="stats" style="padding:0">${parts.join('')}</div>`;
}

function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function safe(fn){ try{ fn(); }catch(e){ console.error('[dashboard]', e); } }
function renderAll(){
  [renderStats, renderOverview, renderTimeline, renderGraph,
   renderTrees, renderObservables, renderIocs, renderMatrix].forEach(safe);
}

/* ---- tabs ---- */
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#tabs button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section.panel').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  document.getElementById('p-'+b.dataset.tab).classList.add('active');
  if(b.dataset.tab==='timeline' && timelineObj) timelineObj.redraw();
  if(b.dataset.tab==='graph' && netObj) netObj.redraw();
});
document.getElementById('search').oninput = e => { state.q = e.target.value;
  [renderStats, renderOverview, renderTimeline, renderObservables, renderIocs, renderMatrix].forEach(safe); };
document.getElementById('hideBenign').onchange = e => { state.hideBenign = e.target.checked; renderAll(); };

renderChips();
renderAll();
</script>
</body></html>
"""


def render_html(title: str, subtitle: str, data: dict) -> str:
    visnet = _load_asset("vis-network.min.js")
    vistimeline = _load_asset("vis-timeline-graph2d.min.js")
    css = _load_asset("vis-timeline-graph2d.min.css")
    subs = {
        "$title": html.escape(title),
        "$subtitle": html.escape(subtitle),
        "$generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "$viscss": css,
        "$visnet": visnet,
        "$vistimeline": vistimeline,
        "$data": json.dumps(data, ensure_ascii=False),
        "$tactics": json.dumps(TACTIC_ORDER),
        "$tech_tactics": json.dumps(TECHNIQUE_TACTICS),
        "$tag_colors": json.dumps(TAG_COLORS),
    }
    out = HTML
    for k, v in subs.items():
        out = out.replace(k, v)
    return out


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a single filterable incident dashboard HTML.")
    ap.add_argument("--iocs", required=True, help="structured IOC JSON")
    ap.add_argument("--timeline", help="normalized timeline CSV")
    ap.add_argument("--graph", help="prebuilt graph.json (else rebuilt from IOCs + Zeek)")
    ap.add_argument("--zeek", help="directory of Zeek *.log")
    ap.add_argument("--proc", action="append", default=[],
                    help="flattened Security.tsv (4688); repeatable")
    ap.add_argument("--proc-host", default="", help="override host name for --proc files")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--title", default="Incident", help="case title")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)

    iocs = read_iocs(args.iocs)
    if args.title == "Incident" and iocs.get("case"):
        args.title = iocs["case"]
    obs = iocs["observables"]
    ipmap = ip_host_map(obs)

    timeline = read_timeline(args.timeline) if args.timeline else []

    # graph
    zeek_edges = []
    if args.zeek and os.path.isdir(args.zeek) and viz is not None:
        zeek_edges, _ = viz.parse_zeek_dir(args.zeek)
    if args.graph and os.path.isfile(args.graph):
        g = json.load(open(args.graph, encoding="utf-8"))
        nodes, edges = g.get("nodes", []), g.get("edges", [])
        for n in nodes:
            n.setdefault("hosts", [ipmap.get(n["id"], [])] if n["id"] in ipmap else [])
            if not n["hosts"] and n.get("type") == "ipv4":
                n["hosts"] = ["Network"]
        for e in edges:
            ha = next((n["hosts"] for n in nodes if n["id"] == e["from"]), [])
            hb = next((n["hosts"] for n in nodes if n["id"] == e["to"]), [])
            e["hosts"] = sorted(set(ha) | set(hb))
    else:
        nodes, edges = build_graph(iocs, zeek_edges, ipmap)

    # process trees
    events = []
    for p in args.proc:
        events += read_process_events(p, args.proc_host)
    trees = build_trees(events)

    # host universe
    hosts = set()
    for o in obs:
        hosts.update(o.get("hosts") or [])
    for r in timeline:
        if r["host"]:
            hosts.add(r["host"])
    for n in nodes:
        hosts.update(n.get("hosts") or [])
    hosts.discard("")
    order = ["Attacker", "SqlSvr", "DC2", "DC1", "Network"]
    hosts_sorted = sorted(hosts, key=lambda h: (order.index(h) if h in order else 99, h))

    # trim graph nodes to json-friendly (vis needs id/label/color/size/title)
    gnodes = [{
        "id": n["id"], "label": n.get("label", n["id"]), "type": n.get("type", ""),
        "tags": n.get("tags", []), "title": n.get("title", ""),
        "color": n.get("color", DEFAULT_COLOR), "size": n.get("size", 16),
        "hosts": n.get("hosts", []),
    } for n in nodes]

    data = {
        "case": args.title,
        "hosts": hosts_sorted,
        "timeline": timeline,
        "observables": obs,
        "graph": {"nodes": gnodes, "edges": edges},
        "trees": trees,
        "type_colors": TYPE_COLORS,
    }

    subtitle = ("Single-file incident dashboard — filter by endpoint; "
                "'All endpoints' is the global view.")
    out_html = os.path.join(args.out, "dashboard.html")
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(render_html(args.title, subtitle, data))

    # also drop the machine-readable payload for reuse
    with open(os.path.join(args.out, "dashboard_data.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    print(f"[incident_dashboard] wrote {out_html}", file=sys.stderr)
    print(f"  hosts: {', '.join(hosts_sorted)}", file=sys.stderr)
    print(f"  timeline: {len(timeline)} | observables: {len(obs)} | "
          f"graph: {len(gnodes)}n/{len(edges)}e | tree-hosts: {len(trees)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
