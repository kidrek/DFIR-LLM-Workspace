#!/usr/bin/env python3
"""custody.py -- chain-of-custody hashing for evidence (hash / verify).

Part of the container-only DFIR workspace. Turns the workspace rule
"hash evidence before analysis and again after, and confirm they match" into
two commands so it is *applied*, not merely asserted.

The tool is **case-free**: no host names, dates or paths are baked in. It reads
evidence **read-only** and writes only under ``analysis/hashes`` (or --outdir).

Usage
-----
    # Baseline BEFORE analysis (writes analysis/hashes/<label>.sha256)
    docker/dfir.sh python3 /data/tools/custody.py hash \
        --label intake /data/evidences

    # AFTER analysis: re-hash and compare (exit 1 on any change)
    docker/dfir.sh python3 /data/tools/custody.py verify \
        --label intake /data/evidences

Options
    --label NAME    manifest name (default: intake). Files:
                    <outdir>/<label>.sha256  and  <outdir>/<label>.json
    --outdir DIR    where manifests live (default: analysis/hashes)
    --algo NAME     hash algorithm (default: sha256)
    --exclude REGEX skip paths (relative) matching this regex (repeatable);
                    e.g. --exclude '^(\\./)?_carved/'
    --quiet         only print the summary line

Exit codes
    hash:   0 ok, 2 usage/IO error
    verify: 0 unchanged, 1 evidence changed/added/removed, 2 usage/IO error

The ``.sha256`` file is standard ``sha256sum`` output (``<hash>  <relpath>``),
so it can also be checked with ``sha256sum -c``. Paths are relative to the
scanned root and POSIX-normalised, so a manifest is portable across mounts.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys

CHUNK = 1 << 20
DEFAULT_OUTDIR = "analysis/hashes"


def _now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_files(root: str, excludes: list[re.Pattern]):
    """Yield (relpath, abspath) for every regular file under root, sorted.

    Symlinks are skipped (they are not evidence bytes and could escape the
    read-only mount). Unreadable entries are reported and skipped.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            abspath = os.path.join(dirpath, name)
            if os.path.islink(abspath) or not os.path.isfile(abspath):
                continue
            rel = os.path.relpath(abspath, root).replace(os.sep, "/")
            if any(rx.search(rel) for rx in excludes):
                continue
            found.append((rel, abspath))
    found.sort(key=lambda t: t[0])
    return found


def _hash_file(path: str, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan(root: str, algo: str, excludes: list[re.Pattern]) -> dict[str, str]:
    result = {}
    for rel, abspath in _iter_files(root, excludes):
        try:
            result[rel] = _hash_file(abspath, algo)
        except OSError as exc:
            print(f"custody: cannot read {rel}: {exc}", file=sys.stderr)
    return result


def _write_manifest(outdir: str, label: str, algo: str, root: str,
                    digests: dict[str, str]) -> tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    sha_path = os.path.join(outdir, f"{label}.{algo}")
    json_path = os.path.join(outdir, f"{label}.json")
    with open(sha_path, "w", encoding="utf-8") as fh:
        for rel in sorted(digests):
            fh.write(f"{digests[rel]}  {rel}\n")
    meta = {
        "label": label,
        "algorithm": algo,
        "root": root,
        "generated_utc": _now_utc(),
        "file_count": len(digests),
        "manifest_sha256": _hash_file(sha_path, "sha256"),
        "digests": dict(sorted(digests.items())),
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=False)
        fh.write("\n")
    return sha_path, json_path


def _load_manifest(outdir: str, label: str, algo: str) -> dict[str, str]:
    json_path = os.path.join(outdir, f"{label}.json")
    if os.path.isfile(json_path):
        try:
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
            digests = data.get("digests")
            if isinstance(digests, dict):
                return {str(k): str(v) for k, v in digests.items()}
        except (OSError, ValueError):
            pass
    sha_path = os.path.join(outdir, f"{label}.{algo}")
    if not os.path.isfile(sha_path):
        raise FileNotFoundError(
            f"no manifest for label '{label}' in {outdir} "
            f"(expected {json_path} or {sha_path}); run 'hash' first")
    out = {}
    with open(sha_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, _, rel = line.partition("  ")
            if rel:
                out[rel] = digest
    return out


def cmd_hash(args) -> int:
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"custody: not a directory: {root}", file=sys.stderr)
        return 2
    excludes = [re.compile(p) for p in args.exclude]
    digests = _scan(root, args.algo, excludes)
    sha_path, json_path = _write_manifest(args.outdir, args.label, args.algo,
                                          root, digests)
    if not args.quiet:
        for rel in sorted(digests):
            print(f"{digests[rel]}  {rel}")
    print(f"[custody] hashed {len(digests)} file(s) -> {sha_path} (+ .json)",
          file=sys.stderr)
    return 0


def cmd_verify(args) -> int:
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"custody: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        baseline = _load_manifest(args.outdir, args.label, args.algo)
    except FileNotFoundError as exc:
        print(f"custody: {exc}", file=sys.stderr)
        return 2

    excludes = [re.compile(p) for p in args.exclude]
    current = _scan(root, args.algo, excludes)

    changed = sorted(p for p in baseline
                     if p in current and current[p] != baseline[p])
    added = sorted(p for p in current if p not in baseline)
    removed = sorted(p for p in baseline if p not in current)
    ok = not (changed or added or removed)

    status = "UNCHANGED" if ok else "CHANGED"
    print(f"[custody] {status}: {len(baseline)} baseline file(s), "
          f"{len(current)} current file(s)", file=sys.stderr)
    for p in changed:
        print(f"  CHANGED  {p}", file=sys.stderr)
        print(f"           expected {baseline[p]}", file=sys.stderr)
        print(f"           actual   {current[p]}", file=sys.stderr)
    for p in added:
        print(f"  ADDED    {p}", file=sys.stderr)
    for p in removed:
        print(f"  REMOVED  {p}", file=sys.stderr)

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)) or ".",
                    exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump({
                "label": args.label,
                "algorithm": args.algo,
                "verified_utc": _now_utc(),
                "status": "unchanged" if ok else "changed",
                "changed": changed,
                "added": added,
                "removed": removed,
            }, fh, indent=2)
            fh.write("\n")

    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Chain-of-custody hashing: hash a baseline, verify later.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("root", help="evidence root directory (read-only)")
        p.add_argument("--label", default="intake",
                       help="manifest name (default: intake)")
        p.add_argument("--outdir", default=DEFAULT_OUTDIR,
                       help=f"manifest directory (default: {DEFAULT_OUTDIR})")
        p.add_argument("--algo", default="sha256", help="hash algorithm")
        p.add_argument("--exclude", action="append", default=[],
                       metavar="REGEX", help="skip matching relpaths (repeatable)")
        p.add_argument("--quiet", action="store_true",
                       help="only print the summary line")

    common(sub.add_parser("hash", help="write a baseline manifest"))
    vp = sub.add_parser("verify", help="re-hash and compare to the baseline")
    common(vp)
    vp.add_argument("--report", help="also write a JSON verification report")

    args = ap.parse_args(argv)
    if getattr(args, "algo", "sha256") not in hashlib.algorithms_available:
        print(f"custody: unsupported algorithm: {args.algo}", file=sys.stderr)
        return 2
    return cmd_hash(args) if args.cmd == "hash" else cmd_verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
