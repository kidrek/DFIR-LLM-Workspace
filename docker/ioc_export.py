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
import sys
from collections import Counter

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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export structured IOCs to CSV.")
    ap.add_argument("--in", dest="inp", required=True, help="input JSON/YAML")
    ap.add_argument("--out", dest="out", required=True, help="output CSV")
    ap.add_argument("--exclude-benign", action="store_true",
                    help="drop observables tagged 'benign'")
    ap.add_argument("--exclude-tag", action="append", default=[],
                    help="drop observables carrying this tag (repeatable)")
    args = ap.parse_args(argv)

    data = load(args.inp)
    if isinstance(data, list):
        observables = data
    elif isinstance(data, dict):
        observables = data.get("observables", [])
    else:
        sys.exit("ERROR: input must be an object with 'observables' or a list")

    drop_tags = set(args.exclude_tag)
    if args.exclude_benign:
        drop_tags.add("benign")

    rows = []
    for item in observables:
        if not isinstance(item, dict):
            continue
        tags = as_tags(item.get("tags"))
        tagset = set(t for t in tags.split(";") if t)
        if tagset & drop_tags:
            continue
        row = {c: item.get(c, "") for c in COLUMNS}
        row["tags"] = tags
        rows.append({c: ("" if row[c] is None else row[c]) for c in COLUMNS})

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
