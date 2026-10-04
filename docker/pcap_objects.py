#!/usr/bin/env python3
"""pcap_objects.py -- carve protocol objects from a PCAP and hash them.

Wraps ``tshark --export-objects`` and adds a SHA-256 manifest, so network-borne
payloads can be hashed and tracked as IOCs. Case-free.

Usage
-----
    pcap_objects.py -r capture.pcapng [--proto http] [--out DIR]
                    [--tshark PATH] [--no-types]

Outputs (into --out, default ``./objects``):
    <protocol objects>            as exported by tshark
    objects_manifest.csv          protocol,filename,size,sha256,file_type

``--proto`` may be repeated and may be a comma-separated list
(e.g. ``http,smb`` / ``--proto http --proto tftp``); the default is ``http``.

Stdlib only (uses the ``file`` binary when available, else magic bytes).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import shutil
import subprocess
import sys

csv.field_size_limit(10 ** 9)


def magic_type(path: str) -> str:
    """Best-effort file type: prefer the ``file`` binary, else magic bytes."""
    if shutil.which("file"):
        try:
            out = subprocess.run(["file", "-b", path], capture_output=True,
                                 text=True, timeout=30)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unknown"
    if head[:2] == b"MZ":
        return "PE executable"
    if head[:4] == b"\x7fELF":
        return "ELF executable"
    if head[:2] == b"PK":
        return "ZIP archive"
    if head[:5] == b"%PDF-":
        return "PDF document"
    if head[:3] == b"GIF":
        return "GIF image"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image"
    return "data"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Carve PCAP objects with tshark and hash them.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("-r", "--read", required=True, help="input PCAP/PCAPNG")
    ap.add_argument("--proto", action="append", default=[],
                    help="protocol(s) to export (repeatable; default http)")
    ap.add_argument("--out", default="objects", help="output directory")
    ap.add_argument("--tshark", default="tshark", help="tshark binary")
    ap.add_argument("--no-types", dest="types", action="store_false",
                    help="skip file-type identification")
    args = ap.parse_args(argv)

    protos = []
    for p in (args.proto or ["http"]):
        protos.extend(x.strip() for x in p.split(",") if x.strip())

    if not os.path.isfile(args.read):
        print(f"pcap_objects: no such capture: {args.read}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)

    before = set(os.listdir(args.out))
    for proto in protos:
        cmd = [args.tshark, "-r", args.read, "--export-objects",
               f"{proto},{args.out}", "-q"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            print(f"pcap_objects: cannot run {args.tshark}: {exc}", file=sys.stderr)
            return 2
        if proc.returncode != 0:
            print(f"pcap_objects: tshark failed for {proto}: "
                  f"{proc.stderr.strip()}", file=sys.stderr)
            return proc.returncode

    after = set(os.listdir(args.out))
    new_files = sorted(after - before)
    manifest_path = os.path.join(args.out, "objects_manifest.csv")

    rows = []
    for name in new_files:
        path = os.path.join(args.out, name)
        if not os.path.isfile(path) or name == "objects_manifest.csv":
            continue
        rows.append({
            "protocol": ",".join(protos),
            "filename": name,
            "size": os.path.getsize(path),
            "sha256": sha256(path),
            "file_type": magic_type(path) if args.types else "",
        })

    with open(manifest_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["protocol", "filename", "size",
                                           "sha256", "file_type"])
        w.writeheader()
        w.writerows(rows)

    for r in rows:
        print(f"{r['size']:>10}  {r['sha256']}  {r['filename']}")
    print(f"[pcap_objects] {len(rows)} object(s) -> {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
