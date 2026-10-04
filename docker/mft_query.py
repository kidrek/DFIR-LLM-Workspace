#!/usr/bin/env python3
"""mft_query.py -- query MFTECmd CSV output for ``$MFT`` or ``$J`` (USN).

One tool for both schemas; it sniffs the header and adapts. Case-free: no host
names, paths or filenames are baked in.

Usage
-----
    mft_query.py --csv MFTECmd.csv [filters] [output]

Filters (all optional, AND-combined)
    --name REGEX            match the file ``FileName``/``Name`` (not path)
    --ext .exe,.dll         match the ``Extension`` (leading dot optional)
    --path REGEX            match ``ParentPath`` + name (full path)
    --exclude-path REGEX    drop rows whose full path matches
    --reason LIST           USN only: match UpdateReasons (any of, comma-sep),
                            e.g. FileCreate,DataOverwrite,RenameNewName
    --time-from STAMP       inclusive lower bound on the file timestamp
    --time-to STAMP         inclusive upper bound
    --deleted               ``$MFT`` only: keep IsDeleted records
    --in-use                ``$MFT`` only: keep InUse records
    --files-only            drop directory records

Output
    --fields A,B,C          columns to print (default: schema-dependent)
    --format tsv|csv|json   default tsv
    --out PATH              write to PATH instead of stdout
    --count                 print only the number of matching rows

Timestamp note: ``$MFT`` rows carry several ``Created0x..``/``LastModified0x..``
columns; ``--time-from/--time-to`` filter on ``Created0x10`` by default (override
with ``--time-field``). USN rows use ``UpdateTimestamp``.

Examples
--------
    # dropped executables by exact name
    mft_query.py --csv HOST_MFT.csv --name 'mimikatz\\.exe|nc\\.exe'

    # pre-log-clear USN file creations outside servicing noise
    mft_query.py --csv HOST_USN.csv --reason FileCreate --ext .exe \\
        --time-from 14:16 --time-to 19:25 --exclude-path '\\WinSxS\\'

Stdlib only.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys

csv.field_size_limit(10 ** 9)


def norm_ext_list(value: str):
    out = []
    for e in value.split(","):
        e = e.strip().lower()
        if not e:
            continue
        out.append(e if e.startswith(".") else "." + e)
    return out


def sniff(schema_cols):
    """Return 'mft' or 'usn' based on the header columns."""
    s = {c.strip().lower() for c in schema_cols}
    if "updatereasons" in s or "updatetimestamp" in s:
        return "usn"
    if "filename" in s and ("created0x10" in s or "isdeleted" in s):
        return "mft"
    # Fall back: USN has 'Name' but no 'FileName'
    if "name" in s and "filename" not in s:
        return "usn"
    return "mft"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Query MFTECmd CSV output ($MFT or $J/USN).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--csv", required=True, help="MFTECmd CSV path")
    ap.add_argument("--name", help="regex on file name")
    ap.add_argument("--ext", help="comma-separated extensions")
    ap.add_argument("--path", help="regex on full path")
    ap.add_argument("--exclude-path", dest="exclude_path", help="regex to drop paths")
    ap.add_argument("--reason", help="USN UpdateReasons (any of, comma-sep)")
    ap.add_argument("--time-from", dest="time_from", help="inclusive lower bound")
    ap.add_argument("--time-to", dest="time_to", help="inclusive upper bound")
    ap.add_argument("--time-field", dest="time_field",
                    help="override timestamp column ($MFT; default Created0x10)")
    ap.add_argument("--deleted", action="store_true", help="$MFT: keep deleted")
    ap.add_argument("--in-use", dest="in_use", action="store_true",
                    help="$MFT: keep InUse")
    ap.add_argument("--files-only", dest="files_only", action="store_true",
                    help="drop directory records")
    ap.add_argument("--fields", help="comma-separated columns to print")
    ap.add_argument("--format", choices=("tsv", "csv", "json"), default="tsv")
    ap.add_argument("--out", help="output path (default stdout)")
    ap.add_argument("--count", action="store_true", help="print match count only")
    args = ap.parse_args(argv)

    try:
        fh = open(args.csv, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"mft_query: cannot open {args.csv}: {exc}", file=sys.stderr)
        return 2

    with fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        if not cols:
            print("mft_query: empty CSV", file=sys.stderr)
            return 2
        schema = sniff(cols)
        name_col = "FileName" if schema == "mft" else "Name"
        ts_col = args.time_field or ("Created0x10" if schema == "mft" else "UpdateTimestamp")
        full_cols = [c for c in cols]

        def col(row, *names):
            for n in names:
                if n in row and row[n] not in (None, ""):
                    return row[n]
            return ""

        name_re = re.compile(args.name) if args.name else None
        path_re = re.compile(args.path) if args.path else None
        excl_re = re.compile(args.exclude_path) if args.exclude_path else None
        ext_set = norm_ext_list(args.ext) if args.ext else None
        reasons = [r.strip().lower() for r in args.reason.split(",")] if args.reason else None

        rows_out = []
        for row in reader:
            nm = (row.get(name_col) or "").strip()
            ext = (row.get("Extension") or "").strip().lower()
            if ext and not ext.startswith("."):
                ext = "." + ext
            parent = (row.get("ParentPath") or "").strip()
            full = (parent + "\\" + nm) if parent else nm

            if args.files_only:
                if (row.get("IsDirectory", "").strip().lower() in ("true", "1")
                        or (row.get("FileAttributes") or "").lower().find("directory") >= 0
                        or (ext == "" and (row.get("FileAttributes") or "").lower().find("directory") >= 0)):
                    continue
            if args.deleted and schema == "mft":
                if (row.get("IsDeleted") or "").strip().lower() not in ("true", "1"):
                    continue
            if args.in_use and schema == "mft":
                if (row.get("InUse") or "").strip().lower() not in ("true", "1"):
                    continue
            if name_re and not name_re.search(nm):
                continue
            if ext_set is not None and ext not in ext_set:
                continue
            if path_re and not path_re.search(full):
                continue
            if excl_re and excl_re.search(full):
                continue
            if reasons is not None:
                rr = (row.get("UpdateReasons") or "").lower()
                if not any(x in rr for x in reasons):
                    continue
            ts = row.get(ts_col, "")
            if args.time_from and ts and ts < args.time_from:
                continue
            if args.time_to and ts and ts > args.time_to:
                continue
            rows_out.append(row)

    if args.count:
        print(len(rows_out))
        return 0
    if not rows_out:
        print("mft_query: no matching records", file=sys.stderr)

    if args.fields:
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    elif schema == "mft":
        fields = ["EntryNumber", "FileName", "ParentPath", "FileSize",
                  "Created0x10", "LastModified0x10", "IsDeleted"]
    else:
        fields = ["EntryNumber", "Name", "ParentPath", "UpdateTimestamp",
                  "UpdateReasons"]
    fields = [f for f in fields if f in full_cols] or full_cols

    out_fh = open(args.out, "w", encoding="utf-8", newline="") if args.out else sys.stdout
    try:
        if args.format == "json":
            out_fh.write(json.dumps([{f: r.get(f, "") for f in fields}
                                     for r in rows_out], indent=2) + "\n")
        else:
            delim = "," if args.format == "csv" else "\t"
            w = csv.writer(out_fh, delimiter=delim)
            w.writerow(fields)
            for r in rows_out:
                w.writerow([r.get(f, "") for f in fields])
    finally:
        if args.out:
            out_fh.close()

    print(f"[mft_query] schema={schema} {len(rows_out)} record(s) -> "
          f"{args.out or 'stdout'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
