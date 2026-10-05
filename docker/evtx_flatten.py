#!/usr/bin/env python3
"""Flatten EVTX JSONL (from evtx_dump_rs) into a normalized TSV timeline.

Usage: evtx_flatten.py <input.jsonl> [output.tsv]

Columns: time_utc, record_id, event_id, level, provider, channel, computer,
         user_sid, process_id, thread_id, activity_id, data (Name=Value; ...)

The ``data`` blob packs the event's fields into one TSV column as
``Name=Value | Name=Value``. Values are **escaped** (``\\`` -> ``\\\\``,
``|`` -> ``\\p``, tab/CR/LF -> ``\\t``/``\\r``/``\\n``) so a literal ``|``
inside a value (common in ``CommandLine``) cannot be mistaken for a field
separator. Use ``split_data``/``escape_value`` from this module to decode;
do **not** hand-split on ``" | "``.

Stdlib only. Handles the deeply nested `Event` structure produced by
omerbenamram/evtx `-o jsonl` and tolerates missing fields.
"""
import json
import sys
import re
from datetime import datetime, timezone

# ---- data-blob codec (pipe-safe) -------------------------------------------- #
# Escape table for values packed into the single ``data`` column. ``|`` becomes
# ``\p`` so it can never be confused with the field separator `` | ``.
_ESCAPE = {"\\": "\\\\", "|": "\\p", "\t": "\\t", "\r": "\\r", "\n": "\\n"}
_UNESCAPE = {"\\": "\\", "p": "|", "t": "\t", "r": "\r", "n": "\n"}


def escape_value(text):
    """Escape a value (or field name) for safe packing into the data blob."""
    return "".join(_ESCAPE.get(ch, ch) for ch in str(text))


def unescape_value(text):
    """Reverse :func:`escape_value`. Unknown escapes are left as-is."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            out.append(_UNESCAPE.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def join_data(pairs):
    """Join ``(name, value)`` pairs into an escaped ``Name=Value | ...`` blob."""
    return " | ".join(f"{escape_value(k)}={escape_value(v)}" for k, v in pairs)


def split_data(blob):
    """Parse a flattened data blob into an ordered dict (pipe-safe).

    Empty field names are dropped, matching the legacy behaviour for bare
    list items. This is the single canonical splitter: consumers must use it
    instead of splitting on ``" | "`` themselves.
    """
    out = {}
    for part in (blob or "").split(" | "):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = unescape_value(k.strip())
        if k:
            out[k] = unescape_value(v)
    return out


def walk_data(ed):
    """Return an escaped ``Name=Value | ...`` blob from EventData/UserData."""
    if ed is None:
        return ""
    if isinstance(ed, list):
        return " | ".join(escape_value(str(item)) for item in ed)

    pairs = []

    def rec(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "#attributes":
                    for ak, av in (v or {}).items():
                        pairs.append((ak, av))
                    continue
                if isinstance(v, (dict, list)):
                    rec(v)
                else:
                    pairs.append((k, v))
        elif isinstance(node, list):
            for v in node:
                rec(v)
        else:
            pairs.append(("", node))

    rec(ed)
    return join_data(pairs)


def attrs(node):
    if isinstance(node, dict):
        a = node.get("#attributes") or {}
        return a
    return {}


def scalar_text(v):
    """Robustly extract a scalar's text from the several shapes evtx_dump uses.

    Handles the plain scalar (``"EventID": 4688``), the attribute-only form
    (``{"#attributes": {"value": 4688}}``), the mixed form
    (``{"#attributes": {...}, "value": 4688}``), ``{"$": ...}``, and lists
    (joined with ``", "``). Previously the attribute-only form was stripped to
    ``{"value": 4688}`` and then re-read as attributes, yielding an empty
    string.
    """
    if v is None:
        return ""
    if isinstance(v, dict):
        for k in ("value", "$", "#text"):
            if k in v and not isinstance(v[k], (dict, list)):
                return str(v[k])
        a = v.get("#attributes")
        if isinstance(a, dict):
            for k in ("value", "$", "#text"):
                if k in a:
                    return scalar_text(a[k])
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(scalar_text(x) for x in v)
    return str(v)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    fh = open(out, "w", encoding="utf-8") if out else sys.stdout
    fh.write(
        "time_utc\trecord_id\tevent_id\tlevel\tprovider\tchannel\tcomputer\t"
        "user_sid\tprocess_id\tthread_id\tactivity_id\tdata\n"
    )
    n = 0
    with open(inp, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            evt = obj.get("Event", obj)
            sysd = evt.get("System", {}) or {}
            tc = attrs(sysd.get("TimeCreated") or {}).get("SystemTime", "")
            evid = scalar_text(sysd.get("EventID"))
            prov = ""
            p = sysd.get("Provider")
            if isinstance(p, dict):
                prov = (p.get("#attributes") or {}).get("Name", "")
            chan = scalar_text(sysd.get("Channel"))
            comp = scalar_text(sysd.get("Computer"))
            rid = scalar_text(sysd.get("EventRecordID"))
            lvl = scalar_text(sysd.get("Level"))
            sec = sysd.get("Security")
            usid = attrs(sec).get("UserID", "") if isinstance(sec, dict) else ""
            ex = attrs(sysd.get("Execution") or {})
            pid = ex.get("ProcessID", "")
            tid = ex.get("ThreadID", "")
            corr = attrs(sysd.get("Correlation") or {})
            aid = corr.get("ActivityID", "")
            data = walk_data(evt.get("EventData"))
            ud = walk_data(evt.get("UserData"))
            if ud:
                data = (data + " | " + ud) if data else ud
            row = [
                str(tc), str(rid), str(evid), str(lvl), str(prov), str(chan),
                str(comp), str(usid), str(pid), str(tid), str(aid),
                data.replace("\t", " ").replace("\n", " ").replace("\r", " "),
            ]
            fh.write("\t".join(row) + "\n")
            n += 1
    if out:
        fh.close()
    print(f"[evtx_flatten] {n} records -> {out or 'stdout'}", file=sys.stderr)


if __name__ == "__main__":
    main()
