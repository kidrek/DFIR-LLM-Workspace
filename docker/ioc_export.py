#!/usr/bin/env python3
"""ioc_export.py -- normalize a structured IOC definition into CSV.

Part of the container-only DFIR workspace. Reads a JSON or YAML definition and
writes a flat, deterministic CSV suitable for SIEM/CTI ingestion.

Input schema (JSON or YAML)::

    {
      "case": "<case name>",
      "endpoints": {                       # optional, generic example
        "10.0.0.5": {"name": "Attacker", "role": "attacker", "order": 1}
      },
      "observables": [
        {
          "type": "ipv4",                 # required
          "value": "10.0.0.5",            # required
          "defanged": "10[.]0[.]0[.]5",
          "role": "attacker-host",
          "first_seen_utc": "2026-01-01T00:00:00Z",
          "last_seen_utc":  "2026-01-01T01:00:00Z",
          "confidence": "high",           # high|medium|low|benign
          "source": "pcap; Security EID=4624",
          "context": "external attacker host",
          "mitre": "T1595,T1190",         # optional, comma-separated
          "tags": ["c2", "attacker"],     # optional list -> 'c2;attacker'
          "hosts": ["Attacker"]           # optional endpoint attribution
        }
      ]
    }

Usage::

    docker/dfir.sh python3 /data/tools/ioc_export.py \
        --in  /data/analysis/iocs.json \
        --out /data/analysis/iocs.csv

Options:
    --exclude-benign   drop observables tagged 'benign'
    --exclude-tag TAG  drop observables carrying TAG (repeatable)

Exit codes: 0 ok, 1 usage/schema error.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import ioc_schema  # shared types / defang / validation
except Exception:  # noqa: BLE001
    ioc_schema = None

COLUMNS = [
    "type", "value", "defanged", "role",
    "first_seen_utc", "last_seen_utc", "confidence",
    "source", "context", "mitre", "tags",
]


def load(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # optional
    except ImportError:
        sys.exit(f"ERROR: {path} is not valid JSON and PyYAML is unavailable")
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"ERROR: {path} is neither valid JSON nor YAML: {exc}")


def as_tags(value) -> str:
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(v) for v in value)
    return "" if value is None else str(value)


def _prepare(observables, drop_tags, dedupe):
    """Filter/dedupe/enrich observables into CSV-ready rows."""
    rows = []
    seen = set()
    for item in observables:
        if not isinstance(item, dict):
            continue
        tags = as_tags(item.get("tags"))
        tagset = set(t for t in tags.split(";") if t)
        if tagset & drop_tags:
            continue
        row = {c: item.get(c, "") for c in COLUMNS}
        row["tags"] = tags
        # Fill a missing defanged rendering from the type.
        if ioc_schema is not None and not row.get("defanged"):
            row["defanged"] = ioc_schema.defang(row.get("value", ""),
                                                str(row.get("type", "")))
        row = {c: ("" if row[c] is None else row[c]) for c in COLUMNS}
        if dedupe and ioc_schema is not None:
            key = (row["type"], ioc_schema.normalize(row["type"], row["value"]))
            if key in seen:
                continue
            seen.add(key)
        rows.append(row)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export structured IOCs to CSV.")
    ap.add_argument("--in", dest="inp", required=True, help="input JSON/YAML")
    ap.add_argument("--out", dest="out", required=True, help="output CSV")
    ap.add_argument("--exclude-benign", action="store_true",
                    help="drop observables tagged 'benign'")
    ap.add_argument("--exclude-tag", action="append", default=[],
                    help="drop observables carrying this tag (repeatable)")
    ap.add_argument("--validate", action="store_true",
                    help="validate the schema and exit 1 on any error")
    ap.add_argument("--no-dedupe", dest="dedupe", action="store_false",
                    help="keep duplicate (type,value) observables")
    args = ap.parse_args(argv)

    data = load(args.inp)
    if isinstance(data, list):
        doc = {"observables": data}
    elif isinstance(data, dict):
        doc = data
    else:
        sys.exit("ERROR: input must be an object with 'observables' or a list")

    # Schema validation (shared with ioc_collect.py).
    errors = ioc_schema.validate(doc) if ioc_schema is not None else []
    if errors:
        if args.validate:
            print(f"ioc_export: {len(errors)} schema error(s) in {args.inp}:",
                  file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print(f"ioc_export: WARNING {len(errors)} schema issue(s); "
              f"run with --validate for details", file=sys.stderr)

    observables = doc.get("observables", [])

    drop_tags = set(args.exclude_tag)
    if args.exclude_benign:
        drop_tags.add("benign")

    rows = _prepare(observables, drop_tags, args.dedupe)
    rows.sort(key=lambda r: (str(r["type"]), str(r["value"])))

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    counts = Counter(r["type"] for r in rows)
    print(f"wrote {args.out} ({len(rows)} observables)", file=sys.stderr)
    for typ, n in sorted(counts.items()):
        print(f"  {typ:<14} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
