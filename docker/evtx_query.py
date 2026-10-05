#!/usr/bin/env python3
"""evtx_query.py -- parameterized fact extractor for flattened EVTX TSVs.

Companion to ``evtx_flatten.py``. Reads the normalized TSV
(``time_utc, record_id, event_id, level, provider, channel, computer,
user_sid, process_id, thread_id, activity_id, data``) and prints the rows you
care about, with the ``data`` blob split into named fields.

The helper is intentionally **case-free**: no host names, dates or incident
strings are baked in. Everything comes from the command line.

Usage
-----
    evtx_query.py <flat.tsv> [filter] [output]

Filters (all optional, AND-combined)
    --eid ID[,ID...]        keep only these event IDs
    --time-from TS          inclusive lower bound (ISO-8601 prefix match)
    --time-to TS            inclusive upper bound
    --grep REGEX            regex searched across the whole ``data`` text
    --field NAME=REGEX      keep rows whose parsed field NAME matches REGEX
                            (repeatable; NAME is case-insensitive)
    --computer REGEX        match the ``computer`` column
    --exclude REGEX         drop rows whose whole ``data`` matches REGEX

Output
    --fields A,B,C          columns to print (default: sensible per-EID set)
    --format tsv|csv|json   default tsv
    --out PATH              write to PATH instead of stdout
    --count                 print only the number of matching rows

Examples
--------
    # process creations mentioning a staged tool
    evtx_query.py Security.tsv --eid 4688 \\
        --grep 'certutil|nc\\.exe' --fields NewProcessName,CommandLine,SubjectUserName

    # Kerberos TGS requests from a given host in a window
    evtx_query.py Security.tsv --eid 4769 --time-from 2026-03-09T19:30 \\
        --field SrcIP=192\\.168\\.186\\.

Stdlib only.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evtx_flatten import split_data  # canonical pipe-safe data-blob parser


# Columns of evtx_flatten.py output.
BASE_COLS = [
    "time_utc", "record_id", "event_id", "level", "provider", "channel",
    "computer", "user_sid", "process_id", "thread_id", "activity_id", "data",
]

# Identifier columns always emitted so every row is citable
# (file + channel + record/event id + UTC time).
ID_COLS = ["time_utc", "record_id", "event_id", "channel", "computer"]

# Convenient default field sets per common Windows event ID. Only used when the
# caller does not pass --fields.
DEFAULT_FIELDS = {
    "4688": ["NewProcessName", "CommandLine", "ParentProcessName",
             "SubjectUserName", "SubjectLogonId"],
    "4624": ["TargetUserName", "LogonType", "IpAddress", "WorkstationName",
             "TargetLogonId", "LogonGuid"],
    "4672": ["SubjectUserName", "SubjectLogonId"],
    "4768": ["TargetUserName", "IpAddress", "TicketEncryptionType", "Status"],
    "4769": ["ServiceName", "TargetUserName", "IpAddress",
             "TicketEncryptionType", "Status"],
    "4771": ["TargetUserName", "IpAddress", "Status"],
    "4776": ["TargetUserName", "Workstation", "Status"],
    "7045": ["ServiceName", "ImagePath", "ServiceType", "StartType",
             "AccountName"],
    "4698": ["TaskName", "SubjectUserName"],
    "5140": ["ShareName", "SubjectUserName", "IpAddress"],
    "5145": ["ShareName", "RelativeTargetName", "SubjectUserName", "IpAddress"],
}


def parse_data(blob: str) -> dict:
    """Split the flattened ``Name=Value | Name=Value`` blob into a dict.

    Delegates to :func:`evtx_flatten.split_data`, which un-escapes literal
    ``|`` characters so a ``CommandLine`` containing pipes cannot corrupt the
    field boundaries. Keys preserve their original casing; lookups are
    case-insensitive via :func:`ci_get`.
    """
    if not blob:
        return {}
    return split_data(blob)


def ci_get(d: dict, name: str) -> str:
    """Case-insensitive get from a parsed-data dict."""
    if name in d:
        return d[name]
    low = name.lower()
    for k, v in d.items():
        if k.lower() == low:
            return v
    return ""


def compile_or_none(pat: str):
    return re.compile(pat) if pat else None


def resolve_fields(args, rows, parsed):
    """Pick which columns to emit."""
    extra = [f.strip() for f in (args.fields or "").split(",") if f.strip()]
    base = [c for c in BASE_COLS if c != "data"]
    if extra:
        # Keep the citable identifier columns plus the requested fields.
        cols = list(ID_COLS)
        cols.extend(extra)
        return cols, extra
    # No --fields: use the per-EID default for a single-EID query, else 'data'.
    eids = {r["event_id"] for r in rows}
    if len(eids) == 1:
        eid = next(iter(eids))
        chosen = DEFAULT_FIELDS.get(eid)
        if chosen:
            return list(ID_COLS) + chosen, chosen
    return base + ["data"], None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Query a flattened EVTX TSV (evtx_flatten.py output).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("tsv", help="flattened EVTX TSV path")
    ap.add_argument("--eid", help="comma-separated event IDs to keep")
    ap.add_argument("--time-from", dest="time_from", help="inclusive lower bound")
    ap.add_argument("--time-to", dest="time_to", help="inclusive upper bound")
    ap.add_argument("--grep", help="regex over the whole data blob")
    ap.add_argument("--field", action="append", default=[],
                    metavar="NAME=REGEX", help="field match (repeatable)")
    ap.add_argument("--computer", help="regex over the computer column")
    ap.add_argument("--exclude", help="regex; drop whole-data matches")
    ap.add_argument("--fields", help="comma-separated columns to print")
    ap.add_argument("--format", choices=("tsv", "csv", "json"), default="tsv")
    ap.add_argument("--out", help="output path (default stdout)")
    ap.add_argument("--count", action="store_true", help="print match count only")
    args = ap.parse_args(argv)

    eids = set()
    if args.eid:
        eids = {e.strip() for e in args.eid.split(",") if e.strip()}
    grep_re = compile_or_none(args.grep)
    excl_re = compile_or_none(args.exclude)
    comp_re = compile_or_none(args.computer)
    field_filters = []
    for spec in args.field:
        if "=" in spec:
            name, _, pat = spec.partition("=")
            field_filters.append((name.strip(), re.compile(pat)))
        else:
            field_filters.append((spec.strip(), re.compile(".+")))

    try:
        fh = open(args.tsv, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"evtx_query: cannot open {args.tsv}: {exc}", file=sys.stderr)
        return 2

    matched = []
    with fh:
        reader = csv.DictReader(fh, delimiter="\t")
        if "data" not in (reader.fieldnames or []):
            print("evtx_query: input does not look like evtx_flatten output "
                  "(missing 'data' column)", file=sys.stderr)
            return 2
        for row in reader:
            if eids and row.get("event_id", "") not in eids:
                continue
            t = row.get("time_utc", "")
            if args.time_from and t < args.time_from:
                continue
            if args.time_to and t > args.time_to:
                continue
            if comp_re and not comp_re.search(row.get("computer", "")):
                continue
            blob = row.get("data", "") or ""
            if grep_re and not grep_re.search(blob):
                continue
            if excl_re and excl_re.search(blob):
                continue
            parsed = None
            ok = True
            if field_filters:
                parsed = {k.lower(): v for k, v in parse_data(blob).items()}
                for name, cre in field_filters:
                    if not cre.search(parsed.get(name.lower(), "")):
                        ok = False
                        break
            if not ok:
                continue
            matched.append((row, parsed if parsed is not None else parse_data(blob)))

    if args.count:
        print(len(matched))
        return 0

    if not matched:
        print("evtx_query: no matching records", file=sys.stderr)

    cols, extra = resolve_fields(args, [r for r, _ in matched], None)

    def value_for(row, parsed, col):
        if col in row and col != "data":
            return row.get(col, "")
        if col in BASE_COLS and col != "data":
            return row.get(col, "")
        return ci_get(parsed, col) if parsed else ci_get(parse_data(row.get("data", "")), col)

    out_fh = open(args.out, "w", encoding="utf-8", newline="") if args.out else sys.stdout
    try:
        if args.format == "json":
            payload = []
            for row, parsed in matched:
                payload.append({c: value_for(row, parsed, c) for c in cols})
            out_fh.write(json.dumps(payload, indent=2) + "\n")
        else:
            delim = "," if args.format == "csv" else "\t"
            w = csv.writer(out_fh, delimiter=delim)
            w.writerow(cols)
            for row, parsed in matched:
                w.writerow([value_for(row, parsed, c) for c in cols])
    finally:
        if args.out:
            out_fh.close()

    print(f"[evtx_query] {len(matched)} record(s) -> {args.out or 'stdout'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
