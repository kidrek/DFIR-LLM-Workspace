#!/usr/bin/env python3
"""Flatten EVTX JSONL (from evtx_dump_rs) into a normalized TSV timeline.

Usage: evtx_flatten.py <input.jsonl> [output.tsv]

Columns: time_utc, record_id, event_id, level, provider, channel, computer,
         user_sid, process_id, thread_id, activity_id, data (Name=Value; ...)

Stdlib only. Handles the deeply nested `Event` structure produced by
omerbenamram/evtx `-o jsonl` and tolerates missing fields.
"""
import json
import sys
import re
from datetime import datetime, timezone


def walk_data(ed):
    """Return 'k=v; k=v' from EventData/UserData which may be list or dict."""
    out = []
    if ed is None:
        return ""
    if isinstance(ed, list):
        for item in ed:
            out.append(str(item))
        return " | ".join(out)

    def rec(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "#attributes":
                    for ak, av in (v or {}).items():
                        out.append(f"{ak}={av}")
                    continue
                if isinstance(v, (dict, list)):
                    rec(v)
                else:
                    out.append(f"{k}={v}")
        elif isinstance(node, list):
            for v in node:
                rec(v)
        else:
            out.append(str(node))

    rec(ed)
    return " | ".join(out)


def attrs(node):
    if isinstance(node, dict):
        a = node.get("#attributes") or {}
        return a
    return {}


def get(evt, key):
    v = evt.get(key)
    if isinstance(v, dict):
        # leaf may hold attributes only
        return v.get("#attributes") if set(v.keys()) <= {"#attributes"} else v
    return v


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
            evid = get(sysd, "EventID")
            if isinstance(evid, dict):
                evid = attrs(evid).get("value", "")
            prov = ""
            p = sysd.get("Provider")
            if isinstance(p, dict):
                prov = (p.get("#attributes") or {}).get("Name", "")
            chan = get(sysd, "Channel") or ""
            comp = get(sysd, "Computer") or ""
            rid = get(sysd, "EventRecordID")
            lvl = get(sysd, "Level")
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
