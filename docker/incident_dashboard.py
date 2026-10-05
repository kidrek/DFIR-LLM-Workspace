#!/usr/bin/env python3
"""incident_dashboard.py -- one self-contained, filterable incident dashboard.

Part of the container-only DFIR workspace. Aggregates already-produced artifacts
into a SINGLE offline HTML file:

  --iocs        structured observables (analysis/iocs.json; the optional
                `endpoints` block and per-observable `hosts` drive endpoint
                attribution)
  --signatures  optional per-case signatures JSON (default:
                analysis/signatures.json if present). Absent -> generic rules
                only; nothing case-specific is ever built in.
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
try:
    import linux_proctree as lpt  # reuse Linux interest heuristic
except Exception:  # noqa: BLE001
    lpt = None
try:
    import dfir_signatures as siglib  # optional, per-case detection patterns
except Exception:  # noqa: BLE001
    siglib = None
try:
    import evtx_flatten as flat  # canonical pipe-safe data-blob parser
except Exception:  # noqa: BLE001
    flat = None
try:
    import hostmap as hm  # generic host-label normalisation (case-free)
except Exception:  # noqa: BLE001
    hm = None

# Case host map (IP/FQDN/alias -> display name); populated in main().
_HOST_MAP: dict[str, str] = {}


def set_host_map(path: str = "") -> None:
    """Populate the module host map from a JSON map (endpoints / ip-map)."""
    global _HOST_MAP
    _HOST_MAP = hm.load_map(path) if (hm and path) else {}

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
# injection guardrails (evidence is untrusted data, never instructions)
# --------------------------------------------------------------------------- #
_SAFE_LINK_SCHEMES = ("http://", "https://", "mailto:")
_SAFE_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".avif")
_SCRIPT_UNSAFE = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026",
                  "\u2028": "\\u2028", "\u2029": "\\u2029"}


def json_for_script(obj) -> str:
    """Serialise to JSON safe to embed inside an inline <script> block.

    json.dumps does NOT escape ``</script>``, so a collected string like
    ``</script><img src=x onerror=...>`` would break out of the script element.
    Escaping ``<``/``>``/``&`` (and the JS line separators) keeps the payload
    inert as data.
    """
    out = json.dumps(obj, ensure_ascii=False)
    for bad, good in _SCRIPT_UNSAFE.items():
        out = out.replace(bad, good)
    return out


def safe_href(url: str) -> str:
    """Return a whitelisted href, or '' if the scheme is not allowed.

    Blocks javascript:/data:/vbscript: and other executable schemes so a link
    from collected data cannot run code when clicked.
    """
    u = (url or "").strip()
    low = u.lower()
    if low.startswith(_SAFE_LINK_SCHEMES):
        return u
    if low.startswith("#") or low.startswith("/") or low.startswith("./") \
            or low.startswith("../"):
        return u
    # a bare relative path with no scheme (no ':' before the first '/')
    if ":" not in u.split("/", 1)[0]:
        return u
    return ""


def safe_img_src(src: str) -> str:
    """Only local image files are inlined; reject data:/http(s):/other schemes."""
    s = (src or "").strip()
    if not s or ":" in s.split("/", 1)[0]:
        return ""
    return s


# --------------------------------------------------------------------------- #
# Markdown report renderer (stdlib; covers the report's feature set)
# --------------------------------------------------------------------------- #
_MD_IMG = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_MD_INLINE = re.compile(r"`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*")


def _md_inline(text: str) -> str:
    # protect image/link targets before escaping the rest of the text
    tokens: list[str] = []

    def stash(html_snippet: str) -> str:
        tokens.append(html_snippet)
        return f"\x00{len(tokens) - 1}\x00"

    def img_repl(m):
        src = safe_img_src(m.group(2))
        if not src:
            return html.escape(m.group(0), quote=False)  # inert literal text
        return stash(f'<img src="{html.escape(src, quote=True)}" '
                     f'alt="{html.escape(m.group(1), quote=True)}">')

    def link_repl(m):
        href = safe_href(m.group(2))
        if not href:
            # display the untrusted link as plain text, not a live <a href>
            return html.escape(m.group(0), quote=False)
        return stash(f'<a href="{html.escape(href, quote=True)}" '
                     f'rel="noopener noreferrer" target="_blank">'
                     f'{html.escape(m.group(1))}</a>')

    text = _MD_IMG.sub(img_repl, text)
    text = _MD_LINK.sub(link_repl, text)

    text = html.escape(text, quote=False)
    text = _MD_INLINE.sub(
        lambda m: (f"<code>{m.group(1)}</code>" if m.group(1) is not None
                   else f"<strong>{m.group(2)}</strong>" if m.group(2) is not None
                   else f"<em>{m.group(3)}</em>"), text)
    return re.sub(r"\x00(\d+)\x00", lambda m: tokens[int(m.group(1))], text)


def render_markdown(md: str, base_dir: str = "") -> str:
    """Minimal Markdown -> HTML for the incident report.

    Handles headings, tables, blockquotes, fenced code, hr, ordered/unordered
    lists and inline code/bold/italic/images/links. Image paths are resolved
    relative to ``base_dir`` and inlined as data URIs so the output stays a
    single self-contained file.
    """
    import base64
    import mimetypes

    def inline_img(src: str) -> str:
        src = safe_img_src(src)
        if not src:
            return ""
        path = os.path.normpath(os.path.join(base_dir or ".", src))
        if not os.path.isfile(path) or \
                not path.lower().endswith(_SAFE_IMG_EXT):
            return ""
        mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if not mime.startswith("image/"):
            return ""
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"

    out, lines, i = [], md.splitlines(), 0
    n = len(lines)

    def is_table_row(s: str) -> bool:
        return s.strip().startswith("|") and s.strip().endswith("|")

    def split_row(s: str) -> list[str]:
        return [c.strip() for c in s.strip().strip("|").split("|")]

    while i < n:
        line = lines[i]
        s = line.strip()

        if not s:
            i += 1
            continue
        # fenced code
        if s.startswith("```"):
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i]); i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(buf)) + "</code></pre>")
            continue
        # hr
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", s):
            out.append("<hr>"); i += 1; continue
        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_md_inline(m.group(2))}</h{lvl}>")
            i += 1; continue
        # table
        if is_table_row(line) and i + 1 < n and \
                re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            head = split_row(line)
            i += 2
            body = []
            while i < n and is_table_row(lines[i]):
                body.append(split_row(lines[i])); i += 1
            th = "".join(f"<th>{_md_inline(c)}</th>" for c in head)
            trs = "".join(
                "<tr>" + "".join(f"<td>{_md_inline(c)}</td>" for c in r) + "</tr>"
                for r in body)
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>")
            continue
        # blockquote
        if s.startswith(">"):
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip().lstrip(">").strip()); i += 1
            out.append("<blockquote>" + _md_inline(" ".join(buf)) + "</blockquote>")
            continue
        # lists
        if re.match(r"^\s*([-*+]|\d+\.)\s+", line):
            ordered = bool(re.match(r"^\s*\d+\.\s+", line))
            items = []
            while i < n and re.match(r"^\s*([-*+]|\d+\.)\s+", lines[i]):
                items.append(_md_inline(re.sub(r"^\s*([-*+]|\d+\.)\s+", "", lines[i])))
                i += 1
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>" + "".join(f"<li>{x}</li>" for x in items) + f"</{tag}>")
            continue
        # paragraph
        buf = [line]
        i += 1
        while i < n and lines[i].strip() and not re.match(
                r"^(#{1,6}\s|>|```|\s*([-*+]|\d+\.)\s|\|)", lines[i]):
            buf.append(lines[i]); i += 1
        out.append("<p>" + _md_inline(" ".join(x.strip() for x in buf)) + "</p>")

    # resolve image sources in the assembled HTML (inline local files as data URIs)
    def fix(m):
        return (f'<img src="{inline_img(m.group(1))}"'
                f'{m.group(2)} style="max-width:100%">')
    return re.sub(r'<img src="([^"]+)"([^>]*)>', fix, "\n".join(out))


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
    """Normalise a host label to a short endpoint name.

    Delegates to ``hostmap.norm_host`` (generic, case-free): a literal IP is
    never truncated, link-local/multicast/broadcast becomes ``Network``, and an
    FQDN is reduced to its first label. Endpoint display names are supplied per
    case via the ``endpoints`` block of analysis/iocs.json (see
    ``read_endpoints``); nothing case-specific is hardcoded here.
    """
    if hm is not None:
        return hm.norm_host(v, _HOST_MAP)
    v = (v or "").strip()
    return v or "Unknown"


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
    endpoints = read_endpoints(d)
    ipmap = ip_host_map(obs, endpoints) if isinstance(d, dict) else {}
    for o in obs:
        hs = o.get("hosts")
        if not hs and o.get("type") == "ipv4":
            # fall back to the case endpoint inventory, if any
            hs = [ipmap[o["value"]]] if o.get("value") in ipmap else []
        if isinstance(hs, str):
            hs = [hs]
        o["hosts"] = [norm_host(h) for h in (hs or [])]
    return {"case": d.get("case", "Incident") if isinstance(d, dict) else "Incident",
            "endpoints": endpoints,
            "observables": obs}


def read_endpoints(iocs) -> dict[str, dict]:
    """Return the optional ``endpoints`` inventory from analysis/iocs.json.

    Shape (all fields optional)::

        {"endpoints": {
            "<ip>": {"name": "FILE01", "role": "victim", "order": 2},
            ...}}

    Nothing is hardcoded: a case with no ``endpoints`` block simply yields {}.
    """
    if not isinstance(iocs, dict):
        return {}
    raw = iocs.get("endpoints")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for key, val in raw.items():
        if isinstance(val, dict):
            out[str(key)] = {
                "name": str(val.get("name") or key),
                "role": str(val.get("role") or ""),
                "order": val.get("order") if isinstance(val.get("order"), int) else None,
            }
        else:  # allow {"<ip>": "HostName"}
            out[str(key)] = {"name": str(val or key), "role": "", "order": None}
    return out


def ip_host_map(obs: list[dict], endpoints: dict[str, dict] | None = None) -> dict[str, str]:
    """Map IP -> endpoint display name, driven purely by analysis/iocs.json.

    ``endpoints`` (the case inventory) wins; the ``hosts`` field on each
    ipv4 observable fills any gaps. No IP or host name is hardcoded.
    """
    m: dict[str, str] = {}
    for ip, meta in (endpoints or {}).items():
        if meta.get("name"):
            m[ip] = meta["name"]
    for o in obs:
        if o.get("type") == "ipv4" and o.get("hosts"):
            m.setdefault(str(o.get("value")), o["hosts"][0])
    return m


def endpoint_order(endpoints: dict[str, dict]) -> list[str]:
    """Display order of endpoints: by ``order`` field, else alphabetical."""
    named = [m["name"] for m in endpoints.values() if m.get("name")]
    ordered = [n for _, n in sorted(
        ((m["order"], m["name"]) for m in endpoints.values()
         if m.get("name") and m.get("order") is not None))]
    rest = sorted(n for n in named if n not in ordered)
    return ordered + rest


# --------------------------------------------------------------------------- #
# process trees from flattened Security.tsv (4688)
# --------------------------------------------------------------------------- #
INTERESTING_BASE = re.compile(
    r"certutil[^\r\n]*urlcache"
    r"|\bnc\.exe\b"
    r"|mimikatz"
    r"|sigmapotato"
    r"|wevtutil[^\r\n]*\bcl\b"
    r"|reg(?:\.exe)?\s+save\b"
    r"|psexec"
    r"|net(?:\.exe)?\s+use\b[^\r\n]*/user:"
    r"|powershell[^\r\n]*\s-(?:e|enc|encodedcommand)\b"
    r"|whoami\s+/priv"
    r"|\\temp\\[^\s\"]+\.exe",
    re.I)

# Optional per-case signatures (analysis/signatures.json). Absent -> generic.
SIGNATURES = siglib.load_signatures() if siglib else {
    "windows_process_patterns": [], "linux_process_patterns": [],
    "actor_keywords": {}}


def set_signatures(path: str = "") -> None:
    """(Re)load optional case signatures and rebind the module-level patterns."""
    global SIGNATURES, INTERESTING, LINUX_INTERESTING
    if siglib is None:
        return
    SIGNATURES = siglib.load_signatures(path)
    INTERESTING = siglib.compile_with(INTERESTING_BASE,
                                      SIGNATURES.get("windows_process_patterns"))
    LINUX_INTERESTING = siglib.compile_with(LINUX_INTERESTING_BASE,
                                            SIGNATURES.get("linux_process_patterns"))


INTERESTING = INTERESTING_BASE


def _parse_kv(data: str) -> dict:
    """Parse a flattened EVTX data blob into a dict (pipe-safe).

    Reuses evtx_flatten.split_data so literal ``|`` inside values (e.g. a
    CommandLine pipeline) cannot shift field boundaries.
    """
    if flat is not None:
        return flat.split_data(data)
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

    # regex for the tools we always want to surface (generic); case-specific
    # names come from the optional signatures file
    HIGH_BASE = re.compile(r"certutil|nc\.exe|mimikatz|sigmapotato|wevtutil|"
                           r"psexec|psexesvc|reg\.exe", re.I)
    HIGH = siglib.compile_with(HIGH_BASE, SIGNATURES.get("windows_process_patterns")) \
        if siglib else HIGH_BASE

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
# process tree from a Linux `linux_proctree.py` snapshot (--proc-linux)
# --------------------------------------------------------------------------- #
LINUX_INTERESTING_BASE = re.compile(
    r"\bcron\b|/dev/shm|/tmp/|\.upd\b|curl|wget|base64|bash -c|nc\b|ncat|"
    r"socat|chisel|python3? -c|systemd-journald-helper|"
    r"sudo|/bin/su\b|\bsu\b|sshd|tmux|xterm|wsgi|uwsgi|mysql|sqlite|"
    r"velociraptor|ssh-agent",
    re.I)

LINUX_INTERESTING = LINUX_INTERESTING_BASE


def _linux_interesting(s: str) -> bool:
    # linux_proctree.is_interesting also honours the optional signatures file
    if lpt is not None:
        return lpt.is_interesting(s)
    return bool(LINUX_INTERESTING.search(s or ""))


def read_linux_tree(path: str) -> tuple[str, list[dict]]:
    """Read a proctree.json from linux_proctree.py -> (host, pruned roots).

    Mirrors the Windows strategy: keep interesting processes, their ancestor
    chain and descendants; prune unrelated siblings; collapse identical leaves.
    """
    d = json.load(open(path, encoding="utf-8"))
    host = norm_host(d.get("host", "linux"))
    raw = d.get("snapshot_roots", []) or []

    # --- normalise into the dashboard node shape, indexed by full path ---
    idx: dict[int, dict] = {}
    parent_of: dict[int, int | None] = {}
    order: list[dict] = []

    def walk(node, parent):
        key = len(order)
        n = {
            "pid": node.get("pid"), "name": node.get("name", ""),
            "cmd": (node.get("cmd") or "")[:220], "user": node.get("user", ""),
            "ts": node.get("ts", ""),
            "interesting": bool(node.get("interesting")) or
                           _linux_interesting(f'{node.get("name","")} {node.get("cmd","")}'),
            "children": [], "_id": key,
        }
        idx[key] = n
        parent_of[key] = parent["_id"] if parent else None
        order.append(n)
        if parent is not None:
            parent["children"].append(n)
        for c in node.get("children", []):
            walk(c, n)

    roots_raw: list[dict] = []
    for r in raw:
        n = {"pid": r.get("pid"), "name": r.get("name", ""),
             "cmd": (r.get("cmd") or "")[:220], "user": r.get("user", ""),
             "ts": r.get("ts", ""), "interesting": False, "children": [], "_id": None}
        n["interesting"] = bool(r.get("interesting")) or \
            _linux_interesting(f'{r.get("name","")} {r.get("cmd","")}')
        n["_id"] = len(order)
        idx[n["_id"]] = n
        parent_of[n["_id"]] = None
        order.append(n)
        for c in r.get("children", []):
            walk(c, n)
        roots_raw.append(n)

    if not order:
        return host, []

    # --- keep interesting nodes + ancestors + descendants (Windows strategy) ---
    keep: set[int] = set()

    def mark_ancestors(i):
        seen = set()
        while i is not None and i in idx and i not in seen:
            seen.add(i)
            keep.add(i)
            i = parent_of.get(i)

    def mark_descendants(i, depth=0):
        if depth > 6:
            return
        for c in idx[i]["children"]:
            if c["_id"] not in keep:
                keep.add(c["_id"])
                mark_descendants(c["_id"], depth + 1)

    for n in order:
        if n["interesting"]:
            keep.add(n["_id"])
            mark_ancestors(parent_of.get(n["_id"]))
            mark_descendants(n["_id"])

    def build_pruned(n):
        kids = [build_pruned(c) for c in n["children"] if c["_id"] in keep]
        kids = [k for k in kids if k]
        return {"pid": n["pid"], "name": n["name"], "cmd": n["cmd"],
                "user": n["user"], "ts": n["ts"], "interesting": n["interesting"],
                "children": kids}

    pruned = [build_pruned(r) for r in roots_raw if r["_id"] in keep]
    pruned = [p for p in pruned if p]

    # collapse identical leaf roots (e.g. repeated cron/sudo invocations)
    merged: list[dict] = []
    leaf_index: dict[tuple, dict] = {}
    for r in pruned:
        key = (r["name"], r["user"]) if not r["children"] else None
        if key and key in leaf_index:
            leaf_index[key]["repeat"] += 1
            continue
        r.setdefault("repeat", 1)
        if key:
            leaf_index[key] = r
        merged.append(r)
    return host, merged


# --------------------------------------------------------------------------- #
# timeline <-> observable correlation + observable "first seen" derivation
# --------------------------------------------------------------------------- #
# Observed-only view of the timeline: which rows are tied to an observable.
# Matching is deliberately exact (source Rec=/EID= anchors, record references,
# IP/hash/unique-file-name/account tokens); a generic token like a Windows
# service account or a log channel name must NOT pull in every routine event.
LINK_STOPWORDS = {
    "security", "system", "application", "setup", "sam", "server", "admin",
    "administrator", "cmd", "net", "windows", "system32", "powershell",
    "ntds", "mssqlserver", "service", "services", "update", "default",
    "kernel", "driver", "microsoft", "local", "network", "user", "guest",
}
_REF_RE = re.compile(
    r"(?P<channel>[A-Za-z][A-Za-z0-9 _-]*?)\s+EID=(?P<eid>\d+)"
    r"(?:\s+Rec=(?P<rec>\d+))?")
_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?")
_DATE_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
_REC_IN_EVIDENCE_RE = re.compile(r"\bRec=(\d+)\b")
_EID_IN_EVIDENCE_RE = re.compile(r"\bEID=(\d+)\b")
_WORD_RE = re.compile(r"[a-z0-9_.$@\\/:.-]+")


def observable_refs(o: dict) -> set[tuple[str, str, str]]:
    """(channel, eid, rec) triples parsed from an observable's ``source``."""
    return {(m.group("channel").strip().lower(), m.group("eid"),
             m.group("rec")) for m in _REF_RE.finditer(o.get("source") or "")}


def observable_tokens(o: dict) -> set[str]:
    """Distinctive, matchable strings carried by an observable value.

    Only values that are (near-)unique to the attacker activity are kept --
    IPv4, hostnames, hashes, full file paths/URLs, registry keys, shares and
    account names. Generic Windows names are dropped.
    """
    typ = o.get("type")
    val = (o.get("value") or "").strip()
    toks: set[str] = set()
    if typ in ("ipv4", "hostname", "file-hash"):
        toks.add(val.lower())
    elif typ == "account":
        toks.add(val.lower())
    elif typ == "file-path":
        toks.add(val.lower())
        toks.add(val.rsplit("\\", 1)[-1].lower())
    elif typ == "url":
        toks.add(val.lower())
        toks.add(val.rstrip("/").rsplit("/", 1)[-1].lower())
    elif typ == "registry":
        toks.add(val.lower())
        toks.add(val.rsplit("\\", 1)[-1].lower())
    elif typ == "share":
        toks.add(val.lower())
    return {t for t in toks if len(t) >= 3 and t not in LINK_STOPWORDS}


def link_timeline(timeline: list[dict], obs: list[dict]) -> None:
    """Annotate every timeline row with the observables it is tied to.

    Adds ``row["observables"]`` (sorted list of observable values); this drives
    the observed-only timeline filter, the tooltip and the derived first-seen.
    The ``actor`` field is intentionally NOT matched: a compromised account
    (e.g. the SQL Server service account) appears as the actor on hundreds of
    routine events and would otherwise swamp the signal.
    """
    rec_idx: dict[str, list[dict]] = defaultdict(list)
    eid_idx: dict[str, list[dict]] = defaultdict(list)
    tok_idx: dict[str, list[dict]] = defaultdict(list)
    for o in obs:
        for _ch, eid, rec in observable_refs(o):
            if rec:
                rec_idx[rec].append(o)
        if o.get("type") == "event-id":
            for n in re.findall(r"\d{3,4}", o.get("value") or ""):
                eid_idx[n].append(o)
        for tok in observable_tokens(o):
            tok_idx[tok].append(o)

    for r in timeline:
        ev = r.get("evidence") or ""
        hits: set[str] = set()
        for m in _REC_IN_EVIDENCE_RE.findall(ev):
            for o in rec_idx.get(m, []):
                hits.add(o["value"])
        for m in _EID_IN_EVIDENCE_RE.findall(ev):
            for o in eid_idx.get(m, []):
                hits.add(o["value"])
        blob = ((r.get("event") or "") + " " + ev).lower()
        for w in set(_WORD_RE.findall(blob)):
            for o in tok_idx.get(w, []):
                hits.add(o["value"])
        r["observables"] = sorted(hits)


def derive_first_seen(o: dict, timeline: list[dict]) -> tuple[str, str]:
    """Best-effort (ISO-UTC timestamp, citation) for an observable with none.

    Order of evidence, most direct first:
      1. an explicit ISO date/time in the observable's own source/context;
      2. the timeline row carrying the observed ``Rec=`` reference;
      3. the earliest timeline row linked to the observable value.
    Returns ("", "") when nothing can be substantiated -- never invents a date.
    """
    text = (o.get("source") or "") + " " + (o.get("context") or "")
    m = _ISO_RE.search(text)
    if m:
        ts = m.group(0)
        return (ts if ts.endswith("Z") else ts + "Z"), "source"
    m = _DATE_TIME_RE.search(text)
    if m:
        return m.group(1) + "T" + m.group(2) + "Z", "source"

    recs = [rec for _ch, _eid, rec in observable_refs(o) if rec]
    best, ref = "", ""
    for r in timeline:
        ev = r.get("evidence") or ""
        ts = r.get("time_utc") or ""
        if not ts:
            continue
        for rec in recs:
            if re.search(r"\bRec=%s\b" % re.escape(rec), ev) and \
                    (not best or ts < best):
                best, ref = ts, "Rec=" + rec
    if best:
        return best, ref

    for r in timeline:
        if o.get("value") in (r.get("observables") or []):
            ts = r.get("time_utc") or ""
            if ts and (not best or ts < best):
                best, ref = ts, "timeline"
    return best, ref


def backfill_first_seen(obs: list[dict], timeline: list[dict]) -> int:
    """Fill missing ``first_seen_utc`` from cited evidence; mark as derived.

    Never overwrites an analyst-supplied value. Derived values get
    ``first_seen_derived=True`` and ``first_seen_ref`` so the UI can show them
    as inferred rather than observed.
    """
    n = 0
    for o in obs:
        if o.get("first_seen_utc"):
            continue
        ts, ref = derive_first_seen(o, timeline)
        if ts:
            o["first_seen_utc"] = ts
            o["first_seen_derived"] = True
            o["first_seen_ref"] = ref
            n += 1
    return n


# --------------------------------------------------------------------------- #
# graph with host attribution
# --------------------------------------------------------------------------- #
def build_graph(iocs: dict, zeek_edges: list[dict], ipmap: dict[str, str]):
    if viz is not None:
        nodes, edges = viz.build_graph(iocs, zeek_edges, ipmap)
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
section.panel.tl-full{position:fixed;inset:0;z-index:200;margin:0;border-radius:0;
  display:flex;flex-direction:column;background:var(--bg)}
section.panel.tl-full #container{flex:1 1 auto;height:auto;min-height:0}
.tl-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 10px}
.tl-tools .grow{flex:1 1 auto}
.tl-tools select{background:#0d1117;border:1px solid var(--line);color:var(--fg);
  border-radius:6px;padding:5px 8px;font-size:12px}
.tl-tools button{background:#161b22;border:1px solid var(--line);color:var(--fg);
  border-radius:6px;padding:5px 12px;cursor:pointer;font-size:12px}
.tl-tools button:hover{border-color:var(--acc)}
.hint{color:var(--mut);font-size:12px;margin:0 0 10px}
table{border-collapse:collapse;width:100%;font-size:12px}
.tablewrap{width:100%;overflow-x:auto}
th,td{border:1px solid var(--line);padding:6px 8px;vertical-align:top;text-align:left;
  overflow-wrap:anywhere;word-break:break-word}
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
.report-md{max-width:980px;line-height:1.6}
.report-md h1{font-size:22px;border-bottom:1px solid var(--line);padding-bottom:6px}
.report-md h2{font-size:18px;margin-top:22px;border-bottom:1px solid var(--line);padding-bottom:4px}
.report-md h3{font-size:15px;margin-top:16px}
.report-md table{margin:10px 0}
.report-md blockquote{border-left:3px solid var(--acc);margin:10px 0;padding:2px 12px;
  color:var(--mut);background:#0d1117}
.report-md code{background:#0d1117;border:1px solid var(--line);border-radius:4px;
  padding:1px 5px;font-family:ui-monospace,monospace;font-size:12px}
.report-md pre{background:#0d1117;border:1px solid var(--line);border-radius:6px;
  padding:10px;overflow:auto}
.report-md img{border:1px solid var(--line);border-radius:6px;margin:8px 0}
.report-md a{color:var(--acc)}
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
  <button data-tab="report">Report</button>
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="timeline">Timeline</button>
  <button data-tab="graph">Actor graph</button>
  <button data-tab="trees">Process trees</button>
  <button data-tab="observables">Observables</button>
  <button data-tab="iocs">IOCs</button>
  <button data-tab="matrix">ATT&amp;CK</button>
</nav>

<main>
  <section class="panel" id="p-report">
    <p class="hint">Full narrative incident report (embedded). Content is
      endpoint-agnostic; use the visual tabs above to scope by endpoint.</p>
    <div class="report-md" id="reportMd"></div>
  </section>
  <section class="panel active" id="p-overview">
    <p class="hint">Per-endpoint summary of the attack chain. Select an endpoint
      above to scope every tab (the default “All endpoints” is the global view).</p>
    <div id="overviewCards"></div>
  </section>
  <section class="panel" id="p-timeline">
    <p class="hint">Attack timeline (UTC). Shows only the curated attack chain
      (suspect/malicious events) by default; switch the mode to see all events.
      Hover an item for its source record; scroll vertically to navigate,
      Ctrl+wheel or −/+ to zoom.</p>
    <div class="tl-tools">
      <label class="switch">show
        <select id="tlMode">
          <option value="attack" selected>attack chain</option>
          <option value="all">all events</option>
        </select>
      </label>
      <label class="switch">rows
        <select id="tlGroup">
          <option value="collapse" selected>collapse identical</option>
          <option value="none">every row</option>
        </select>
      </label>
      <span class="grow"></span>
      <button id="tlOut" title="Zoom out (keep the time axis in view)">−</button>
      <button id="tlIn" title="Zoom in">+</button>
      <button id="tlFit" title="Recenter / reset zoom on the displayed events">⟲ recenter</button>
      <button id="tlFull" title="Toggle full screen">⛶ full screen</button>
    </div>
    <div id="container" style="height:64vh"></div>
  </section>
  <section class="panel" id="p-graph">
    <p class="hint">Attacker / victim / observable relationships. Drag nodes; hover for source.</p>
    <div class="legend" id="graphLegend"></div>
    <div id="graphContainer" style="width:100%;height:64vh"></div>
  </section>
  <section class="panel" id="p-trees">
    <p class="hint">$treehint</p>
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

let state = { host: ALL, q: "", hideBenign: false, tlMode: "attack", tlGroup: "collapse" };
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
function tlRows(mode){
  if(mode==='all') return DATA.timeline;
  return DATA.attack_timeline && DATA.attack_timeline.length ? DATA.attack_timeline : DATA.timeline;
}
function renderStats(){
  const obs = filtObs(DATA.observables);
  let tl = tlRows(state.tlMode).filter(r => inHost([r.host]) && textMatch(JSON.stringify(r)));
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
function tlTooltip(r,host){
  const lines=[r.time_utc,'host: '+host,'actor: '+r.actor,'technique: '+r.technique,
    'tags: '+r.tags,'evidence: '+r.evidence];
  const iocs=(r.observables||[]);
  if(iocs.length) lines.push('IOCs: '+iocs.join('; '));
  return esc(lines.filter(x=>x.split(': ')[1]).join('\n'));
}
function groupRows(rows){
  if(state.tlGroup==='none') return rows.map(r=>({r,count:1}));
  const m=new Map();
  for(const r of rows){
    const k=[r.time_utc,r.host,r.event,r.actor,r.technique,r.tags,r.evidence].join('\x1f');
    const e=m.get(k);
    if(e) e.count++; else m.set(k,{r,count:1});
  }
  return [...m.values()];
}
/* clamp user zoom to the displayed rows so the time axis always shows
   incident-relevant timestamps (no de-zoom back to 1990). */
function tlBounds(rows){
  let lo=null, hi=null;
  (rows||[]).forEach(r=>{ const t=Date.parse(r.time_utc); if(!isNaN(t)){ if(lo===null||t<lo)lo=t; if(hi===null||t>hi)hi=t; } });
  if(lo===null) return {};
  const pad=Math.max((hi-lo)*0.04, 1800000);   // >= 30 min margin
  return {min:new Date(lo-pad), max:new Date(hi+pad)};
}
function tlZoom(dir){
  if(!timelineObj) return;
  try{ dir>0 ? timelineObj.zoomIn(0.3,{animation:false})
             : timelineObj.zoomOut(0.3,{animation:false}); }catch(e){}
  try{ timelineObj.redraw(); }catch(e){}
}
function renderTimeline(){
  const rows = tlRows(state.tlMode).filter(r => inHost([r.host]) && textMatch(JSON.stringify(r)));
  const grouped = groupRows(rows);
  const el = document.getElementById('container');
  const items=[], groups=[], seen=new Set();
  grouped.forEach((g,i)=>{
    const r=g.r, host=r.host;
    if(!seen.has(host)){ seen.add(host); groups.push({id:host, content:esc(host)}); }
    const tags=(r.tags||'').split(';').filter(Boolean);
    const ptag=tags[0]||'default';
    const linked=(r.observables||[]).length>0;
    const bg=TAG_COLORS[ptag]||'#3498db';
    const label=(r.event||'').slice(0,70)+(g.count>1?'  ×'+g.count:'');
    items.push({id:i, group:host, start:r.time_utc||null,
      content:esc(label),
      style:'background:'+bg+';border-color:'+(linked?'#e74c3c':bg)+';color:#fff;'
        +(linked?'border-width:2px':''),
      title:tlTooltip(r,host)});
  });
  if(timelineObj){ try{timelineObj.destroy();}catch(e){} timelineObj=null; }
  el.innerHTML='';
  if(!items.length){ el.innerHTML='<div class="empty">No timeline rows for this filter.</div>'; return; }
  if(!(window.vis && vis.Timeline)){ el.innerHTML='<div class="empty">Timeline library unavailable.</div>'; return; }
  const opts = Object.assign(
    {stack:true, zoomable:true, moveable:true, selectable:true, horizontalScroll:true,
     height:'100%', maxHeight:'100%', verticalScroll:true, zoomKey:'ctrlKey',
     margin:{item:{horizontal:4}}}, tlBounds(rows));
  timelineObj = new vis.Timeline(el, new vis.DataSet(items), new vis.DataSet(groups), opts);
  try{ timelineObj.fit(); }catch(e){}
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
    `<span><span class="sw" style="background:${(DATA.type_colors[t]||'#3498db')}"></span>${esc(t)}</span>`).join('');
  const safeNodes = nodes.map(n => Object.assign({}, n, {label:esc(n.label||''), title:esc(n.title||'')}));
  netObj = new vis.Network(el, {nodes:new vis.DataSet(safeNodes), edges:new vis.DataSet(edges)},
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
function seenCell(ts, derived, ref){
  if(!ts) return '';
  if(derived) return `<span class="mono" title="derived from ${esc(ref||'evidence')}">${esc(ts)}<sup>*</sup></span>`;
  return `<span class="mono">${esc(ts)}</span>`;
}
function obsRow(o){
  const val = o.defanged ? `<span class="mono">${esc(o.defanged)}</span>` : `<span class="mono">${esc(o.value)}</span>`;
  const hs = (o.hosts||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join('');
  const tags=(o.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
  const conf=o.confidence?`<span class="badge b-${o.confidence}">${o.confidence}</span>`:'';
  return `<tr><td>${seenCell(o.first_seen_utc,o.first_seen_derived,o.first_seen_ref)}</td>
    <td>${seenCell(o.last_seen_utc,false,'')}</td>
    <td>${esc(o.type)}</td><td>${val}</td><td>${esc(o.role||'')}</td>
    <td>${hs}</td><td>${conf}</td>
    <td>${esc(o.mitre||'')}</td><td>${tags}</td>
    <td>${esc(o.context||'')}</td><td>${esc(o.source||'')}</td></tr>`;
}
const OBS_HEAD=['first seen (UTC)','last seen (UTC)','type','value (defanged)','role','endpoints','confidence','mitre','tags','context','source'];
function renderTable(elId, list){
  const el=document.getElementById(elId);
  if(!list.length){ el.innerHTML='<div class="empty">No rows for this filter.</div>'; return; }
  // oldest -> newest (lowest timestamp first); rows with no timestamp sort last
  const rows=[...list].sort((a,b)=>{
    const x=a.first_seen_utc||'', y=b.first_seen_utc||'';
    if(!x) return 1; if(!y) return -1;
    return x.localeCompare(y);
  });
  el.innerHTML=`<div class="tablewrap"><table><thead><tr>${OBS_HEAD.map(h=>`<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(obsRow).join('')}</tbody></table></div>
    <p class="hint"><sup>*</sup> first/last seen derived from cited evidence (source reference or the matching timeline record); hover the value for the reference.</p>`;
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
    .map(d=>`<span class="tech ${d.n>=3?'hi':(d.n===2?'md':'lo')}" title="${esc([...new Set(d.vals)].slice(0,8).join('; '))}">${esc(d.id)} ×${d.n}</span>`).join('')}</div>`).join('');
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
      <div style="font-weight:700;font-size:15px;margin-bottom:6px">${esc(host)}</div>
      <div style="font-size:12px;color:var(--mut)">Window: ${esc(first)} → ${esc(last)}</div>
      <div style="margin-top:6px">events <b>${tl.length}</b> · observables <b>${obs.length}</b>
        · attacker IOCs <b>${atk.length}</b> · techniques <b>${tech.length}</b></div>
      <div style="margin-top:8px">${tech.map(t=>`<span class="tech lo" style="display:inline-block">${esc(t)}</span>`).join('')}</div>
    </div>`);
  }
  document.getElementById('overviewCards').innerHTML =
    `<div class="stats" style="padding:0">${parts.join('')}</div>`;
}

/* ---- report (embedded markdown, static) ---- */
function renderReport(){
  const el=document.getElementById('reportMd');
  if(!el) return;
  el.innerHTML = (DATA.report_html && DATA.report_html.length)
    ? DATA.report_html : '<div class="empty">No report embedded.</div>';
}

function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function safe(fn){ try{ fn(); }catch(e){ console.error('[dashboard]', e); } }
function renderAll(){
  [renderReport, renderStats, renderOverview, renderTimeline, renderGraph,
   renderTrees, renderObservables, renderIocs, renderMatrix].forEach(safe);
}

/* ---- tabs ---- */
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#tabs button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section.panel').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');
  document.getElementById('p-'+b.dataset.tab).classList.add('active');
  if(b.dataset.tab==='timeline'){ renderTimeline(); if(timelineObj) timelineObj.redraw(); }
  if(b.dataset.tab==='graph' && netObj) netObj.redraw();
});
document.getElementById('search').oninput = e => { state.q = e.target.value;
  [renderStats, renderOverview, renderTimeline, renderObservables, renderIocs, renderMatrix].forEach(safe); };
document.getElementById('hideBenign').onchange = e => { state.hideBenign = e.target.checked; renderAll(); };
(function(){
  const mode=document.getElementById('tlMode');
  if(mode) mode.onchange = e => { state.tlMode = e.target.value; renderStats(); renderTimeline(); };
  const grp=document.getElementById('tlGroup');
  if(grp) grp.onchange = e => { state.tlGroup = e.target.value; renderStats(); renderTimeline(); };
  const fit=document.getElementById('tlFit');
  if(fit) fit.onclick = () => { if(timelineObj){ try{timelineObj.fit();}catch(e){} timelineObj.redraw(); } };
  const zin=document.getElementById('tlIn');
  if(zin) zin.onclick = () => tlZoom(1);
  const zout=document.getElementById('tlOut');
  if(zout) zout.onclick = () => tlZoom(-1);
  const full=document.getElementById('tlFull');
  if(full) full.onclick = () => {
    const p=document.getElementById('p-timeline');
    p.classList.toggle('tl-full');
    full.textContent = p.classList.contains('tl-full') ? '⛶ exit' : '⛶ full screen';
    if(timelineObj){ try{timelineObj.fit();}catch(e){} timelineObj.redraw();
      setTimeout(()=>{ try{timelineObj.fit(); timelineObj.redraw();}catch(e){} }, 60); }
  };
})();

renderChips();
renderAll();
</script>
</body></html>
"""


def _apply_template(template: str, subs: dict) -> str:
    """Substitute placeholders, applying $data / $report last to avoid a
    substituted value being re-scanned for later placeholders."""
    deferred = {k: subs[k] for k in ("$data", "$embeds") if k in subs}
    for k, v in subs.items():
        if k not in deferred:
            template = template.replace(k, v)
    for k, v in deferred.items():
        template = template.replace(k, v)
    return template


def render_html(title: str, subtitle: str, data: dict, treehint: str = "") -> str:
    visnet = _load_asset("vis-network.min.js")
    vistimeline = _load_asset("vis-timeline-graph2d.min.js")
    css = _load_asset("vis-timeline-graph2d.min.css")
    subs = {
        "$title": html.escape(title),
        "$subtitle": html.escape(subtitle),
        "$treehint": html.escape(treehint or
            "Attacker-relevant processes + lineage. Endpoint-filtered."),
        "$generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "$viscss": css,
        "$visnet": visnet,
        "$vistimeline": vistimeline,
        "$data": json_for_script(data),
        "$tactics": json_for_script(TACTIC_ORDER),
        "$tech_tactics": json_for_script(TECHNIQUE_TACTICS),
        "$tag_colors": json_for_script(TAG_COLORS),
    }
    return _apply_template(HTML, subs)


# --------------------------------------------------------------------------- #
# document (single-scroll) layout: report + all panels, per-section filters
# --------------------------------------------------------------------------- #
HTML_DOC = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
:root{color-scheme:dark;--bg:#0b0d12;--panel:#12141a;--panel2:#171a22;--line:#232838;
  --fg:#e6e8ee;--mut:#8b90a0;--acc:#6d6afc;--acc2:#8f8cff;
  --ok:#2ea043;--warn:#d29922;--crit:#e5484d;}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc2);text-decoration:none}a:hover{text-decoration:underline}
header.top{padding:18px 28px;border-bottom:1px solid var(--line);background:var(--panel);
  position:sticky;top:0;z-index:60}
header.top h1{margin:0;font-size:20px;letter-spacing:.2px}
header.top .sub{color:var(--mut);font-size:12px;margin-top:3px}
.layout{display:grid;grid-template-columns:250px minmax(0,1fr);gap:0;max-width:1600px;
  margin:0 auto}
nav.toc{position:sticky;top:69px;align-self:start;height:calc(100vh - 69px);
  overflow:auto;padding:18px 14px;border-right:1px solid var(--line)}
nav.toc .lbl{color:var(--acc2);font-size:11px;text-transform:uppercase;letter-spacing:1px;
  margin:4px 8px 8px}
nav.toc a{display:block;color:var(--mut);padding:6px 10px;border-radius:8px;font-size:13px;
  border:1px solid transparent}
nav.toc a:hover{color:var(--fg);background:var(--panel2)}
nav.toc a.active{color:var(--fg);background:#1b1e2b;border-color:var(--line);
  box-shadow:inset 2px 0 0 var(--acc)}
main{padding:26px 34px 80px;min-width:0}
section.blk{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:20px 22px;margin:0 0 22px;overflow:hidden}
section.blk>h2.blk-title{font-size:16px;margin:0 0 4px;display:flex;align-items:center;gap:10px}
section.blk>h2.blk-title .accent{color:var(--acc2);font-size:11px;text-transform:uppercase;
  letter-spacing:1.5px;display:block;margin-bottom:2px}
section.blk>p.blk-sub{color:var(--mut);font-size:12px;margin:0 0 14px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 14px}
.filters .flabel{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.8px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
  border-radius:999px;padding:4px 12px;cursor:pointer;font-size:12px}
.chip.active{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}
.chip.benign.active{background:#4a5060;border-color:#4a5060}
.search{background:var(--bg);border:1px solid var(--line);color:var(--fg);
  border-radius:8px;padding:6px 10px;font-size:12px;min-width:200px}
.switch{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:12px;cursor:pointer}
.applyall{margin-left:auto;font-size:11px;color:var(--mut);display:flex;align-items:center;gap:6px}
#tl, #gc{width:100%;height:56vh;min-height:360px}
section.blk.tl-full{position:fixed;inset:0;z-index:200;margin:0;border-radius:0;
  display:flex;flex-direction:column;background:var(--panel)}
section.blk.tl-full #tl{flex:1 1 auto;height:auto;min-height:0}
.tl-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 12px}
.tl-tools .grow{flex:1 1 auto}
.tl-tools select{background:var(--bg);border:1px solid var(--line);color:var(--fg);
  border-radius:8px;padding:5px 8px;font-size:12px}
.tl-tools button{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
  border-radius:8px;padding:5px 12px;cursor:pointer;font-size:12px}
.tl-tools button:hover{border-color:var(--acc)}
.legend{display:flex;gap:14px;flex-wrap:wrap;color:var(--mut);font-size:12px;margin:6px 0}
.legend span.sw{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:4px}
table{border-collapse:collapse;width:100%;font-size:12px}
.tablewrap{width:100%;overflow-x:auto}
th,td{border:1px solid var(--line);padding:6px 8px;vertical-align:top;text-align:left;
  overflow-wrap:anywhere;word-break:break-word}
th{background:var(--panel2);color:var(--mut);text-transform:uppercase;font-size:10px;
  letter-spacing:.6px}
tr:hover td{background:#1a1e29}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10px;
  background:#1b1e2b;margin:1px 3px 1px 0;border:1px solid var(--line);color:#c9cede}
.badge{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10px;font-weight:600}
.b-high{background:#3a1214;color:#ff9a9e;border:1px solid #6e2226}
.b-medium{background:#33260c;color:#f2cc60;border:1px solid #6b5220}
.b-low{background:#12233a;color:#9cc7ff;border:1px solid #27456e}
.b-benign{background:#232838;color:#aab0c0}
.matrix{display:flex;gap:10px;overflow-x:auto;padding-bottom:8px}
.tac{min-width:150px;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px}
.tac h4{margin:0 0 8px;font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.tech{display:block;background:#2a2160;color:#cfcaff;border:1px solid #4b41b0;
  border-radius:6px;padding:3px 7px;margin:4px 0;font-size:11px}
.tech.hi{background:#5a1620;border-color:#8e2430;color:#ffd0d4}
.tech.md{background:#2a2160;border-color:#4b41b0}
.tech.lo{background:#1a2333;border-color:#2c3a52;color:#b9c6dd}
.tree-host{margin:0 0 20px}
.tree-host h3{margin:6px 0;font-size:14px}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:16px}
.proc{border-left:3px solid var(--line);padding:3px 10px;margin:3px 0;border-radius:0 6px 6px 0;
  background:var(--panel2)}
.proc.hit{border-left-color:var(--crit)}
.proc .nm{font-weight:600;font-family:ui-monospace,monospace}
.proc .cmd{color:var(--mut);font-size:11px;word-break:break-all}
.proc .meta{color:#6e7681;font-size:10px}
.empty{color:var(--mut);padding:14px;font-style:italic}
.stats{display:flex;gap:10px;flex-wrap:wrap}
.stat{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:8px 14px;
  min-width:110px}
.stat .n{font-size:20px;font-weight:700}.stat .l{color:var(--mut);font-size:10px;
  text-transform:uppercase;letter-spacing:.6px}
iframe.embed{width:100%;height:70vh;border:1px solid var(--line);border-radius:10px;background:#0d1117}
/* report markdown */
.report-md{max-width:none}
.report-md table{width:100%;table-layout:fixed;overflow-wrap:anywhere;word-break:break-word}
.report-md h1{font-size:22px;border-bottom:1px solid var(--line);padding-bottom:6px}
.report-md h2{font-size:18px;margin-top:22px;border-bottom:1px solid var(--line);padding-bottom:4px}
.report-md h3{font-size:15px;margin-top:16px}
.report-md blockquote{border-left:3px solid var(--acc);margin:10px 0;padding:2px 12px;
  color:var(--mut);background:var(--bg)}
.report-md code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px}
.report-md img{border:1px solid var(--line);border-radius:8px;margin:8px 0}
footer{color:#6e7681;font-size:11px;padding:0 34px 40px;max-width:1600px;margin:0 auto}
@media (max-width:900px){
  .layout{grid-template-columns:1fr}
  nav.toc{position:sticky;top:69px;height:auto;max-height:38vh;border-right:none;
    border-bottom:1px solid var(--line);background:var(--bg);z-index:50}
  th{top:auto}
}
</style>
</head><body>
<header class="top">
  <h1>$title</h1>
  <div class="sub">$subtitle</div>
</header>
<div class="layout">
  <nav class="toc" id="toc"><div class="lbl">On this page</div></nav>
  <main>
    <section class="blk" id="sec-report">
      <h2 class="blk-title"><span><span class="accent">Report</span>Incident narrative</span></h2>
      <p class="blk-sub">Full write-up. The data sections below each carry their own filter.</p>
      <div class="report-md" id="reportMd"></div>
    </section>

    <section class="blk" id="sec-overview">
      <h2 class="blk-title"><span><span class="accent">Summary</span>Per-endpoint overview</span></h2>
      <div class="stats" id="overviewCards"></div>
    </section>

    <section class="blk" id="sec-timeline" data-sect="timeline">
      <h2 class="blk-title"><span><span class="accent">Chronology</span>Attack timeline (UTC)</span></h2>
      <p class="blk-sub">Shows only the curated attack chain (suspect/malicious
        events) by default; switch the mode to see all events. Hover an item for
        its source record. Scroll vertically to navigate, Ctrl+wheel or −/+ to zoom.</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
        <input class="search" data-q placeholder="search…">
      </div>
      <div class="tl-tools">
        <label class="switch">show
          <select data-tl-mode>
            <option value="attack" selected>attack chain</option>
            <option value="all">all events</option>
          </select>
        </label>
        <label class="switch">rows
          <select data-tl-group>
            <option value="collapse" selected>collapse identical</option>
            <option value="none">every row</option>
          </select>
        </label>
        <span class="grow"></span>
        <button data-tl-out title="Zoom out (keep the time axis in view)">−</button>
        <button data-tl-in title="Zoom in">+</button>
        <button data-tl-fit title="Recenter / reset zoom on the displayed events">⟲ recenter</button>
        <button data-tl-full title="Toggle full screen">⛶ full screen</button>
      </div>
      <div id="tl"></div>
    </section>

    <section class="blk" id="sec-graph" data-sect="graph">
      <h2 class="blk-title"><span><span class="accent">Relations</span>Actor graph</span></h2>
      <p class="blk-sub">Attacker / victim / observable relationships. Drag nodes; hover for source.</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
      </div>
      <div class="legend" id="graphLegend"></div>
      <div id="gc"></div>
    </section>

    <section class="blk" id="sec-trees" data-sect="trees">
      <h2 class="blk-title"><span><span class="accent">Execution</span>Process trees</span></h2>
      <p class="blk-sub">$treehint</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
      </div>
      <div id="trees"></div>
    </section>

    <section class="blk" id="sec-observables" data-sect="observables">
      <h2 class="blk-title"><span><span class="accent">Observables</span>All indicators</span></h2>
      <p class="blk-sub">Includes benign/responder. Oldest first.</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
        <input class="search" data-q placeholder="search…">
        <label class="switch"><input type="checkbox" data-benign> hide benign / responder</label>
      </div>
      <div id="obsTable"></div>
    </section>

    <section class="blk" id="sec-iocs" data-sect="iocs">
      <h2 class="blk-title"><span><span class="accent">Threat intel</span>IOCs (non-benign)</span></h2>
      <p class="blk-sub">Benign/responder observables removed.</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
        <input class="search" data-q placeholder="search…">
      </div>
      <div id="iocTable"></div>
    </section>

    <section class="blk" id="sec-matrix" data-sect="matrix">
      <h2 class="blk-title"><span><span class="accent">MITRE</span>ATT&amp;CK coverage</span></h2>
      <p class="blk-sub">Techniques from observables in scope for this section.</p>
      <div class="filters" data-role="filters">
        <span class="flabel">Endpoints</span><div class="chips" data-chips></div>
      </div>
      <div class="matrix" id="matrix"></div>
    </section>

    $embeds
  </main>
</div>
<footer>Generated $generated by incident_dashboard.py (document layout) — offline, self-contained.</footer>
<style>$viscss</style>
<script>$visnet</script>
<script>$vistimeline</script>
<script>
const DATA = $data;
const TACTICS = $tactics;
const TECH_TACTICS = $tech_tactics;
const TAG_COLORS = $tag_colors;
const ALL = "__ALL__";

/* ---- per-section state ---- */
const SECTIONS = ['timeline','graph','trees','observables','iocs','matrix'];
const S = {};
SECTIONS.forEach(id => S[id] = {host: ALL, q: "", hideBenign: false, tlMode: "attack", tlGroup: "collapse"});
function secEl(id){ return document.getElementById('sec-'+id); }
function inHost(sec, hosts){ return sec.host===ALL || (hosts||[]).includes(sec.host); }
function textMatch(sec, blob){ return !sec.q || (blob||"").toLowerCase().includes(sec.q.toLowerCase()); }
function isBenign(o){
  const t=(o.tags||[]).join(" ").toLowerCase()+" "+(o.confidence||"");
  return /benign|responder|internal/.test(t);
}
function filtObs(sec, list){
  return list.filter(o => inHost(sec,o.hosts) && textMatch(sec,JSON.stringify(o)) &&
    (!sec.hideBenign || !isBenign(o)));
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

/* ---- build per-section filter bars ---- */
function hostSet(){
  const s=new Set();
  DATA.timeline.forEach(r=>r.host&&s.add(r.host));
  [].concat(...DATA.observables.map(o=>o.hosts||[]),[].concat(...DATA.graph.nodes.map(n=>n.hosts||[]))).forEach(h=>h&&s.add(h));
  return [...s];
}
const HOSTS = DATA.hosts.length ? DATA.hosts : hostSet();
function buildFilters(){
  document.querySelectorAll('.blk[data-sect]').forEach(blk=>{
    const id=blk.dataset.sect, bar=blk.querySelector('[data-role=filters]');
    if(!bar) return;
    const chipbox=bar.querySelector('[data-chips]');
    if(chipbox){
      chipbox.innerHTML=[ALL].concat(HOSTS).map(h=>
        `<div class="chip ${S[id].host===h?'active':''}" data-h="${h}">${h===ALL?'All':h}</div>`).join('');
      chipbox.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{
        S[id].host=c.dataset.h;
        chipbox.querySelectorAll('.chip').forEach(x=>x.classList.toggle('active',x===c));
        renderSection(id);
      });
    }
    const q=bar.querySelector('[data-q]');
    if(q) q.oninput=e=>{ S[id].q=e.target.value; renderSection(id); };
    const b=bar.querySelector('[data-benign]');
    if(b) b.onchange=e=>{ S[id].hideBenign=e.target.checked; renderSection(id); };
  });
  // timeline-only controls (mode / rows / recenter / full screen)
  const blk=document.getElementById('sec-timeline'); if(!blk) return;
  const mode=blk.querySelector('[data-tl-mode]');
  if(mode) mode.onchange=e=>{ S.timeline.tlMode=e.target.value; renderSection('timeline'); };
  const grp=blk.querySelector('[data-tl-group]');
  if(grp) grp.onchange=e=>{ S.timeline.tlGroup=e.target.value; renderSection('timeline'); };
  const zin=blk.querySelector('[data-tl-in]');
  if(zin) zin.onclick=()=>tlZoomDoc(1);
  const zout=blk.querySelector('[data-tl-out]');
  if(zout) zout.onclick=()=>tlZoomDoc(-1);
  const fit=blk.querySelector('[data-tl-fit]');
  if(fit) fit.onclick=()=>{ if(VIS.timeline){try{VIS.timeline.fit();}catch(e){} VIS.timeline.redraw();} };
  const full=blk.querySelector('[data-tl-full]');
  if(full) full.onclick=()=>{
    blk.classList.toggle('tl-full');
    full.textContent=blk.classList.contains('tl-full')?'⛶ exit':'⛶ full screen';
    if(VIS.timeline){try{VIS.timeline.fit();}catch(e){} VIS.timeline.redraw();
      setTimeout(()=>{try{VIS.timeline.fit();VIS.timeline.redraw();}catch(e){}},60);}
  };
}

/* ---- renderers ---- */
const VIS={};
function renderSection(id){
  const sec=S[id];
  try{
    if(id==='timeline') renderTimeline(sec);
    else if(id==='graph') renderGraph(sec);
    else if(id==='trees') renderTrees(sec);
    else if(id==='observables') renderTable('obsTable', filtObs(sec,DATA.observables));
    else if(id==='iocs') renderTable('iocTable', filtObs(sec,DATA.observables).filter(o=>!isBenign(o)));
    else if(id==='matrix') renderMatrix(sec);
  }catch(e){ console.error('[document]',id,e); }
}
function tlRowsDoc(mode){
  if(mode==='all') return DATA.timeline;
  return DATA.attack_timeline && DATA.attack_timeline.length ? DATA.attack_timeline : DATA.timeline;
}
function groupRowsDoc(rows,group){
  if(group==='none') return rows.map(r=>({r,count:1}));
  const m=new Map();
  for(const r of rows){
    const k=[r.time_utc,r.host,r.event,r.actor,r.technique,r.tags,r.evidence].join('\x1f');
    const e=m.get(k);
    if(e) e.count++; else m.set(k,{r,count:1});
  }
  return [...m.values()];
}
/* clamp user zoom to the displayed rows so the time axis always shows
   incident-relevant timestamps (no de-zoom back to 1990). */
function tlBoundsDoc(rows){
  let lo=null, hi=null;
  (rows||[]).forEach(r=>{ const t=Date.parse(r.time_utc); if(!isNaN(t)){ if(lo===null||t<lo)lo=t; if(hi===null||t>hi)hi=t; } });
  if(lo===null) return {};
  const pad=Math.max((hi-lo)*0.04, 1800000);
  return {min:new Date(lo-pad), max:new Date(hi+pad)};
}
function tlZoomDoc(dir){
  if(!VIS.timeline) return;
  try{ dir>0 ? VIS.timeline.zoomIn(0.3,{animation:false})
             : VIS.timeline.zoomOut(0.3,{animation:false}); }catch(e){}
  try{ VIS.timeline.redraw(); }catch(e){}
}
function renderTimeline(sec){
  const rows=tlRowsDoc(sec.tlMode).filter(r=>inHost(sec,[r.host]) && textMatch(sec,JSON.stringify(r)));
  const grouped=groupRowsDoc(rows,sec.tlGroup);
  const el=document.getElementById('tl');
  const items=[],groups=[],seen=new Set();
  grouped.forEach((g,i)=>{
    const r=g.r, host=r.host;
    if(!seen.has(host)){seen.add(host);groups.push({id:host,content:esc(host)});}
    const tags=(r.tags||'').split(';').filter(Boolean), ptag=tags[0]||'default';
    const linked=(r.observables||[]).length>0, bg=TAG_COLORS[ptag]||'#3498db';
    const lines=[r.time_utc,'host: '+host,'actor: '+r.actor,'technique: '+r.technique,
      'tags: '+r.tags,'evidence: '+r.evidence];
    if(linked) lines.push('IOCs: '+(r.observables||[]).join('; '));
    const label=(r.event||'').slice(0,70)+(g.count>1?'  ×'+g.count:'');
    items.push({id:i,group:host,start:r.time_utc||null,
      content:esc(label),
      style:'background:'+bg+';border-color:'+(linked?'#e5484d':bg)+';color:#fff;'
        +(linked?'border-width:2px':''),
      title:esc(lines.filter(x=>x.split(': ')[1]).join('\n'))});
  });
  if(VIS.timeline){try{VIS.timeline.destroy();}catch(e){} VIS.timeline=null;}
  el.innerHTML='';
  if(!items.length){el.innerHTML='<div class="empty">No timeline rows for this filter.</div>';return;}
  if(!(window.vis&&vis.Timeline)){el.innerHTML='<div class="empty">Timeline library unavailable.</div>';return;}
  const opts=Object.assign(
    {stack:true,zoomable:true,moveable:true,selectable:true,horizontalScroll:true,
     height:'100%',maxHeight:'100%',verticalScroll:true,zoomKey:'ctrlKey',
     margin:{item:{horizontal:4}}}, tlBoundsDoc(rows));
  VIS.timeline=new vis.Timeline(el,new vis.DataSet(items),new vis.DataSet(groups),opts);
  try{ VIS.timeline.fit(); }catch(e){}
}
function renderGraph(sec){
  const nodes=DATA.graph.nodes.filter(n=>inHost(sec,n.hosts));
  const ids=new Set(nodes.map(n=>n.id));
  const edges=DATA.graph.edges.filter(e=>ids.has(e.from)&&ids.has(e.to));
  const el=document.getElementById('gc');
  if(VIS.graph){try{VIS.graph.destroy();}catch(e){} VIS.graph=null;}
  el.innerHTML='';
  if(!nodes.length){el.innerHTML='<div class="empty">No graph nodes for this filter.</div>';return;}
  if(!(window.vis&&vis.Network)){el.innerHTML='<div class="empty">Graph library unavailable.</div>';return;}
  const types=[...new Set(nodes.map(n=>n.type))];
  document.getElementById('graphLegend').innerHTML=types.map(t=>
    `<span><span class="sw" style="background:${(DATA.type_colors[t]||'#3498db')}"></span>${esc(t)}</span>`).join('');
  const safeNodes=nodes.map(n=>Object.assign({},n,{label:esc(n.label||''),title:esc(n.title||'')}));
  VIS.graph=new vis.Network(el,{nodes:new vis.DataSet(safeNodes),edges:new vis.DataSet(edges)},
    {physics:{stabilization:true},nodes:{shape:'dot',font:{size:14,color:'#e6e8ee'}},
     edges:{arrows:'to',font:{size:10,color:'#8b90a0',align:'middle'},
            color:{color:'#3d4b5c',highlight:'#6d6afc'}},interaction:{hover:true,tooltipDelay:120}});
}
function procNode(n){
  const kids=n.children.map(procNode).join('');
  return `<li><div class="proc ${n.interesting?'hit':''}">
    <div class="nm">${esc(n.name)} <span class="meta">pid ${n.pid} · ${esc(n.user||'')} · ${esc(n.ts)}${n.repeat>1?' · ×'+n.repeat+' identical':''}</span></div>
    ${n.cmd?`<div class="cmd">${esc(n.cmd)}</div>`:''}${kids?`<ul>${kids}</ul>`:''}</div></li>`;
}
function countNodes(roots){let n=0;const w=r=>{n++;r.children.forEach(w);};roots.forEach(w);return n;}
function renderTrees(sec){
  const box=document.getElementById('trees');const parts=[];
  for(const host of HOSTS){
    if(sec.host!==ALL && sec.host!==host) continue;
    const roots=(DATA.trees[host]||[]);
    if(!roots.length) continue;
    parts.push(`<div class="tree-host"><h3>${host} <span class="meta">${countNodes(roots)} processes kept</span></h3>
      <ul class="tree">${roots.map(procNode).join('')}</ul></div>`);
  }
  box.innerHTML=parts.length?parts.join(''):'<div class="empty">No process data for this filter.</div>';
}
function seenCell(ts,derived,ref){
  if(!ts) return '';
  if(derived) return `<span class="mono" title="derived from ${esc(ref||'evidence')}">${esc(ts)}<sup>*</sup></span>`;
  return `<span class="mono">${esc(ts)}</span>`;
}
function obsRow(o){
  const val=o.defanged?`<span class="mono">${esc(o.defanged)}</span>`:`<span class="mono">${esc(o.value)}</span>`;
  const hs=(o.hosts||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join('');
  const tags=(o.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
  const conf=o.confidence?`<span class="badge b-${o.confidence}">${o.confidence}</span>`:'';
  return `<tr><td>${seenCell(o.first_seen_utc,o.first_seen_derived,o.first_seen_ref)}</td>
    <td>${seenCell(o.last_seen_utc,false,'')}</td>
    <td>${esc(o.type)}</td><td>${val}</td><td>${esc(o.role||'')}</td>
    <td>${hs}</td><td>${conf}</td><td>${esc(o.mitre||'')}</td><td>${tags}</td>
    <td>${esc(o.context||'')}</td><td>${esc(o.source||'')}</td></tr>`;
}
const OBS_HEAD=['first seen (UTC)','last seen (UTC)','type','value (defanged)','role','endpoints','confidence','mitre','tags','context','source'];
function renderTable(elId,list){
  const el=document.getElementById(elId);
  if(!list.length){el.innerHTML='<div class="empty">No rows for this filter.</div>';return;}
  const rows=[...list].sort((a,b)=>{const x=a.first_seen_utc||'',y=b.first_seen_utc||'';
    if(!x)return 1;if(!y)return -1;return x.localeCompare(y);});
  el.innerHTML=`<div class="tablewrap"><table><thead><tr>${OBS_HEAD.map(h=>`<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(obsRow).join('')}</tbody></table></div>
    <p class="blk-sub"><sup>*</sup> first/last seen derived from cited evidence (source reference or the matching timeline record); hover the value for the reference.</p>`;
}
function renderMatrix(sec){
  const obs=filtObs(sec,DATA.observables);
  const tech={};
  obs.forEach(o=>{(o.mitre||"").split(/[,\s]+/).filter(t=>/^T\d{4}/.test(t)).forEach(t=>{
    tech[t]=tech[t]||{n:0,vals:[]};tech[t].n++;if(o.value)tech[t].vals.push(o.value);});});
  const grid={};TACTICS.forEach(t=>grid[t]=[]);
  for(const t in tech){const base=t.split('.')[0];
    grid[TECH_TACTICS[t]||TECH_TACTICS[base]||'Other'].push({id:t,n:tech[t].n,vals:tech[t].vals});}
  const cols=TACTICS.filter(t=>grid[t].length);
  const el=document.getElementById('matrix');
  if(!cols.length){el.innerHTML='<div class="empty">No ATT&CK techniques for this filter.</div>';return;}
  el.innerHTML=cols.map(t=>`<div class="tac"><h4>${t}</h4>${grid[t].sort((a,b)=>b.n-a.n)
    .map(d=>`<span class="tech ${d.n>=3?'hi':(d.n===2?'md':'lo')}" title="${esc([...new Set(d.vals)].slice(0,8).join('; '))}">${esc(d.id)} ×${d.n}</span>`).join('')}</div>`).join('');
}
function renderReport(){
  const el=document.getElementById('reportMd'); if(!el) return;
  el.innerHTML=(DATA.report_html&&DATA.report_html.length)?DATA.report_html:'<div class="empty">No report embedded.</div>';
}
function renderOverview(){
  const parts=[];
  for(const host of HOSTS){
    const tl=DATA.timeline.filter(r=>r.host===host);
    const obs=DATA.observables.filter(o=>(o.hosts||[]).includes(host));
    const atk=obs.filter(o=>!isBenign(o));
    const first=tl[0]?tl[0].time_utc:'—', last=tl.length?tl[tl.length-1].time_utc:'—';
    const tech=[...new Set(tl.flatMap(r=>(r.technique||'').split(/[,\s]+/)).filter(Boolean))];
    parts.push(`<div class="stat" style="min-width:220px">
      <div style="font-weight:700;font-size:15px;margin-bottom:6px">${esc(host)}</div>
      <div style="font-size:12px;color:var(--mut)">Window: ${esc(first)} → ${esc(last)}</div>
      <div style="margin-top:6px">events <b>${tl.length}</b> · observables <b>${obs.length}</b>
        · attacker IOCs <b>${atk.length}</b> · techniques <b>${tech.length}</b></div>
      <div style="margin-top:8px">${tech.map(t=>`<span class="tech lo" style="display:inline-block">${esc(t)}</span>`).join('')}</div>
    </div>`);
  }
  document.getElementById('overviewCards').innerHTML=`<div class="stats">${parts.join('')}</div>`;
}

/* ---- TOC + scroll-spy ---- */
function buildToc(){
  const toc=document.getElementById('toc');
  document.querySelectorAll('main section.blk').forEach(sec=>{
    const h=sec.querySelector('h2.blk-title'); if(!h) return;
    const clone=h.cloneNode(true);
    const acc=clone.querySelector('.accent'); if(acc) acc.remove();
    const label=(clone.textContent||'').replace(/\s+/g,' ').trim();
    toc.insertAdjacentHTML('beforeend',`<a href="#${sec.id}" data-t="${sec.id}">${label}</a>`);
  });
  const links={}; toc.querySelectorAll('a').forEach(a=>links[a.dataset.t]=a);
  const obs=new IntersectionObserver(es=>{
    es.forEach(e=>{ if(e.isIntersecting){
      Object.values(links).forEach(a=>a.classList.remove('active'));
      if(links[e.target.id]) links[e.target.id].classList.add('active');
    }});
  },{rootMargin:'-70px 0px -70% 0px',threshold:0});
  document.querySelectorAll('main section.blk').forEach(s=>obs.observe(s));
}

buildFilters();
buildToc();
['timeline','graph','trees','observables','iocs','matrix'].forEach(renderSection);
renderReport(); renderOverview();
</script>
</body></html>
"""


def render_document(title: str, subtitle: str, data: dict, treehint: str = "",
                    embeds: str = "") -> str:
    visnet = _load_asset("vis-network.min.js")
    vistimeline = _load_asset("vis-timeline-graph2d.min.js")
    css = _load_asset("vis-timeline-graph2d.min.css")
    subs = {
        "$title": html.escape(title),
        "$subtitle": html.escape(subtitle),
        "$treehint": html.escape(treehint or
            "Attacker-relevant processes + lineage. Endpoint-filtered."),
        "$generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "$viscss": css, "$visnet": visnet, "$vistimeline": vistimeline,
        "$data": json_for_script(data),
        "$tactics": json_for_script(TACTIC_ORDER),
        "$tech_tactics": json_for_script(TECHNIQUE_TACTICS),
        "$tag_colors": json_for_script(TAG_COLORS),
        "$embeds": embeds,
    }
    return _apply_template(HTML_DOC, subs)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a single filterable incident dashboard HTML.")
    ap.add_argument("--iocs", required=True, help="structured IOC JSON")
    ap.add_argument("--timeline", help="normalized timeline CSV")
    ap.add_argument("--attack-timeline",
                    help="curated attack-chain CSV (time_utc,host,actor,event,"
                         "technique,evidence,tags). Shown by default on the "
                         "timeline; the full --timeline stays the 'all events' "
                         "fallback. Defaults to analysis/attack_timeline.csv "
                         "if present.")
    ap.add_argument("--graph", help="prebuilt graph.json (else rebuilt from IOCs + Zeek)")
    ap.add_argument("--zeek", help="directory of Zeek *.log")
    ap.add_argument("--proc", action="append", default=[],
                    help="flattened Security.tsv (4688); repeatable")
    ap.add_argument("--proc-host", default="", help="override host name for --proc files")
    ap.add_argument("--proc-linux", action="append", default=[],
                    help="proctree.json from linux_proctree.py; repeatable")
    ap.add_argument("--report-md", default="",
                    help="Markdown report to embed as the first 'Report' tab")
    ap.add_argument("--report-base", default="",
                    help="base dir for resolving the report's relative image paths "
                         "(default: the report's own directory)")
    ap.add_argument("--embed", action="append", default=[],
                    help="name=path: embed an HTML file as an <iframe srcdoc> "
                         "section in the document layout; repeatable")
    ap.add_argument("--layout", default="both", choices=["dashboard", "document", "both"],
                    help="which HTML to write: dashboard.html, report.html, or both")
    ap.add_argument("--signatures", default="",
                    help="optional per-case signatures JSON (default: "
                         "analysis/signatures.json if present)")
    ap.add_argument("--ip-map", default="",
                    help="JSON host map (IP/FQDN/alias -> display name); defaults "
                         "to the endpoints block of --iocs")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--title", default="Incident", help="case title")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)

    set_signatures(args.signatures)

    # host map: explicit --ip-map wins, else the IOC endpoints inventory
    if args.ip_map:
        set_host_map(args.ip_map)
    elif hm is not None:
        try:
            _HOST_MAP.update(hm.load_map_from_obj(
                json.load(open(args.iocs, encoding="utf-8"))))
        except (OSError, ValueError):
            pass

    iocs = read_iocs(args.iocs)
    if args.title == "Incident" and iocs.get("case"):
        args.title = iocs["case"]
    obs = iocs["observables"]
    endpoints = iocs.get("endpoints", {})
    ipmap = ip_host_map(obs, endpoints)

    timeline = read_timeline(args.timeline) if args.timeline else []

    # curated attack-chain timeline (shown by default); full timeline is the
    # "all events" fallback. Default path mirrors the other analysis/ inputs.
    attack_path = args.attack_timeline
    if not attack_path and os.path.isfile(os.path.join("analysis",
                                                       "attack_timeline.csv")):
        attack_path = os.path.join("analysis", "attack_timeline.csv")
    attack_timeline = []
    if attack_path and os.path.isfile(attack_path):
        attack_timeline = read_timeline(attack_path)
    else:
        if attack_path:
            print(f"[incident_dashboard] --attack-timeline {attack_path}: "
                  f"not found; timeline falls back to the full set",
                  file=sys.stderr)

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
    for p in args.proc_linux:
        if os.path.isfile(p):
            lhost, lroots = read_linux_tree(p)
            if lroots:
                trees[lhost] = lroots
            else:
                trees.setdefault(lhost, [])

    # host universe ---------------------------------------------------------
    # Rule: an endpoint is only shown when it has data in at least one of the
    # four Overview metrics -- timeline events, observables, non-benign IOCs,
    # or ATT&CK techniques. Host names surfaced from EVTX `computer` fields /
    # empty trees (all-zero cards) are dropped. Because renderChips,
    # renderOverview and the Endpoints stat all iterate DATA.hosts, this alone
    # removes the zeros everywhere.
    def _is_benign(o):
        t = " ".join(o.get("tags") or []).lower() + " " + (o.get("confidence") or "")
        return bool(re.search(r"benign|responder|internal", t))

    tl_hosts, obs_hosts, ioc_hosts, atk_hosts = set(), set(), set(), set()
    for r in timeline:
        if r["host"]:
            tl_hosts.add(r["host"])
    for r in attack_timeline:
        if r["host"]:
            tl_hosts.add(r["host"])
    for o in obs:
        hs = o.get("hosts") or []
        obs_hosts.update(hs)
        if not _is_benign(o):
            ioc_hosts.update(hs)
        if re.search(r"\bT\d{4}", o.get("mitre") or ""):
            atk_hosts.update(hs)

    keep = tl_hosts | obs_hosts | ioc_hosts | atk_hosts
    hosts = set(keep)
    hosts.discard("")
    # drop tree entries for endpoints that are no longer shown
    trees = {h: r for h, r in trees.items() if h in hosts}

    # display order: case-declared endpoint order, then alphabetical; the
    # synthetic "Network" bucket always sorts last.
    order = endpoint_order(endpoints)
    hosts_sorted = sorted(
        hosts,
        key=lambda h: (order.index(h) if h in order else 99, h != "Network", h))

    # correlate timeline rows with observables (adds row["observables"]) and
    # back-fill any observable missing a first_seen_utc from cited evidence
    link_timeline(timeline, obs)
    link_timeline(attack_timeline, obs)
    _derived = backfill_first_seen(obs, timeline)

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
        "attack_timeline": attack_timeline,
        "observables": obs,
        "graph": {"nodes": gnodes, "edges": edges},
        "trees": trees,
        "type_colors": TYPE_COLORS,
    }

    # embedded narrative report (all-in-one "Report" tab)
    if args.report_md and os.path.isfile(args.report_md):
        base = args.report_base or os.path.dirname(os.path.abspath(args.report_md))
        with open(args.report_md, encoding="utf-8") as fh:
            data["report_html"] = render_markdown(fh.read(), base)
    else:
        data["report_html"] = ""

    subtitle = ("Single-file incident dashboard — filter by endpoint; "
                "'All endpoints' is the global view.")
    doc_subtitle = ("Single-file incident report — narrative + per-endpoint "
                    "data sections, each with its own filter.")

    # process-tree panel hint: name only the sources actually supplied
    parts, notes = [], []
    if any(os.path.isfile(p) for p in args.proc):
        parts.append("Windows Security 4688")
    if any(os.path.isfile(p) for p in args.proc_linux):
        parts.append("the Linux /proc snapshot")
        notes.append("journal/auth events are in the standalone tree")
    if parts:
        treehint = ("Process trees from " + " and ".join(parts) +
                    " — attacker-relevant processes + lineage, endpoint-filtered.")
        if notes:
            treehint += " (" + "; ".join(notes) + ")"
    else:
        treehint = "No process-tree sources provided."

    written = []

    # ---- dashboard (tabbed) layout ----
    if args.layout in ("dashboard", "both"):
        out_html = os.path.join(args.out, "dashboard.html")
        with open(out_html, "w", encoding="utf-8") as fh:
            fh.write(render_html(args.title, subtitle, data, treehint))
        written.append(out_html)

    # ---- document (single-scroll) layout ----
    if args.layout in ("document", "both"):
        embeds = []
        for spec in args.embed:
            if "=" not in spec:
                continue
            name, path = spec.split("=", 1)
            if not os.path.isfile(path):
                print(f"[incident_dashboard] --embed {name}: {path} not found",
                      file=sys.stderr)
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            embeds.append(
                f'<section class="blk" id="sec-{html.escape(name)}">'
                f'<h2 class="blk-title"><span><span class="accent">Embedded</span>'
                f'{html.escape(name)}</span></h2>'
                f'<iframe class="embed" title="{html.escape(name)}" '
                f'srcdoc="{html.escape(content, quote=True)}"></iframe>'
                f'</section>')
        out_doc = os.path.join(args.out, "report.html")
        with open(out_doc, "w", encoding="utf-8") as fh:
            fh.write(render_document(args.title, doc_subtitle, data, treehint,
                                     "\n".join(embeds)))
        written.append(out_doc)

    # also drop the machine-readable payload for reuse
    with open(os.path.join(args.out, "dashboard_data.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    print(f"[incident_dashboard] wrote {', '.join(written)}", file=sys.stderr)
    print(f"  hosts: {', '.join(hosts_sorted)}", file=sys.stderr)
    print(f"  timeline: {len(timeline)} | attack-timeline: "
          f"{len(attack_timeline) if attack_timeline else 'none (full set)'} | "
          f"observables: {len(obs)} | "
          f"graph: {len(gnodes)}n/{len(edges)}e | tree-hosts: {len(trees)}", file=sys.stderr)
    print(f"  timeline linked to observables: "
          f"{sum(1 for r in timeline if r.get('observables'))} | "
          f"first-seen derived: {_derived}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
