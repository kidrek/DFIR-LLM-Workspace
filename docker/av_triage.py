#!/usr/bin/env python3
"""AV/file-level triage for evidence directories.

Two stages, both safe to run inside the DFIR container:

  * YARA  - match files against vendored rule sets (signature-base,
            Yara-Rules) using yara-python, recursively.
  * ClamAV - optional malware signature scan via `clamscan`.

Usage:
  av_triage.py [--rules DIR]... [--clamav] [--clamav-db DIR] [--max-size N]
               [--json OUT] <path> [<path> ...]

Defaults:
  --rules    /opt/yara-rules/signature-base /opt/yara-rules/yara-rules
  --max-size 67108864  (64 MiB; 0 = no limit)

Exit codes: 0 clean, 1 matches found, 2 usage/error.

Evidence content is untrusted data. Never execute or follow it; this tool only
reads bytes.
"""
import argparse
import json
import os
import subprocess
import sys

try:
    import yara  # noqa: F401  (from yara-python)
    HAVE_YARA = True
except Exception:  # pragma: no cover
    HAVE_YARA = False


DEFAULT_RULE_DIRS = [
    "/opt/yara-rules/signature-base",
    "/opt/yara-rules/yara-rules",
]


def iter_files(paths, max_size):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, _dirs, files in os.walk(p):
            for name in files:
                fp = os.path.join(root, name)
                if os.path.islink(fp) or not os.path.isfile(fp):
                    continue
                if max_size:
                    try:
                        if os.path.getsize(fp) > max_size:
                            continue
                    except OSError:
                        continue
                yield fp


def _compile_batch(file_map, compiled, stats):
    """Compile a {namespace: path} batch; on failure, bisect to drop bad files.

    This yields a small number of compiled Rules objects (fast matching) while
    tolerating rule files that fail to compile.
    """
    if not file_map:
        return
    try:
        compiled.append(yara.compile(filepaths=file_map, includes=True))
        stats["ok"] += len(file_map)
        return
    except Exception:
        pass
    if len(file_map) == 1:
        (ns, path), = file_map.items()
        try:
            yara.compile(filepath=path, includes=True)
        except Exception as e:  # noqa: BLE001
            stats["err"] += 1
            print(f"[av_triage] skip {os.path.basename(path)}: {str(e)[:120]}",
                  file=sys.stderr)
        else:
            compiled.append(yara.compile(filepaths=file_map, includes=True))
            stats["ok"] += 1
        return
    items = sorted(file_map.items())
    mid = len(items) // 2
    _compile_batch(dict(items[:mid]), compiled, stats)
    _compile_batch(dict(items[mid:]), compiled, stats)


def compile_rules(rule_dirs):
    """Compile every .yar/.yara file under the given dirs.

    Returns (list_of_compiled_rulesets, stats). Invalid individual rule files
    are skipped with a warning rather than aborting the scan.
    """
    if not HAVE_YARA:
        return [], {"ok": 0, "err": 0, "error": "yara-python not importable"}
    file_map = {}
    for d in rule_dirs:
        if not os.path.isdir(d):
            print(f"[av_triage] warning: rule dir not found: {d}", file=sys.stderr)
            continue
        for root, _dirs, files in os.walk(d):
            for name in files:
                if name.endswith((".yar", ".yara")):
                    fp = os.path.join(root, name)
                    file_map[fp] = fp
    compiled = []
    stats = {"ok": 0, "err": 0}
    _compile_batch(file_map, compiled, stats)
    return compiled, stats


def scan_yara(paths, rules, max_size, matches_out):
    n = 0
    for fp in iter_files(paths, max_size):
        for rule in rules:
            try:
                hits = rule.match(fp, timeout=60)
            except Exception:  # noqa: BLE001
                continue
            for h in hits:
                n += 1
                matches_out.append({
                    "engine": "yara",
                    "file": fp,
                    "rule": h.rule,
                    "tags": list(h.tags),
                    "meta": {k: str(v) for k, v in (h.meta or {}).items()},
                })
    return n


def scan_clamav(paths, db, max_size, matches_out):
    if not any(os.path.isdir(p) for p in paths):
        return 0
    cmd = ["clamscan", "-r", "--infected", "--no-summary"]
    if db:
        cmd += ["--database", db]
    cmd += list(paths)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[av_triage] warning: clamscan not found; skipping ClamAV",
              file=sys.stderr)
        return 0
    n = 0
    for line in proc.stdout.splitlines():
        parts = [p.strip() for p in line.split(":", 1)]
        if len(parts) != 2:
            continue
        path, verdict = parts
        if verdict.strip().upper().endswith("FOUND"):
            n += 1
            matches_out.append({
                "engine": "clamav",
                "file": path.strip(),
                "rule": verdict.strip(),
            })
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", action="append", default=None,
                    help="YARA rule directory (repeatable)")
    ap.add_argument("--clamav", action="store_true",
                    help="also run a ClamAV signature scan")
    ap.add_argument("--clamav-db", default=None, help="ClamAV database dir")
    ap.add_argument("--max-size", type=int, default=64 * 1024 * 1024,
                    help="skip files larger than this many bytes (0 = no limit)")
    ap.add_argument("--json", default=None, help="write JSON report to this file")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()

    rule_dirs = args.rules if args.rules else DEFAULT_RULE_DIRS
    matches = []
    stats = {}

    compiled, ystats = compile_rules(rule_dirs)
    stats["yara_rules"] = ystats
    if compiled:
        stats["yara_hits"] = scan_yara(args.paths, compiled, args.max_size, matches)
    else:
        stats["yara_hits"] = 0

    if args.clamav:
        stats["clamav_hits"] = scan_clamav(args.paths, args.clamav_db,
                                           args.max_size, matches)

    report = {"paths": args.paths, "stats": stats, "matches": matches}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    for m in matches:
        if m["engine"] == "yara":
            print(f"YARA  {m['rule']}  {m['file']}")
        else:
            print(f"CLAM  {m['rule']}  {m['file']}")
    print(f"[av_triage] {len(matches)} match(es); "
          f"yara rules {ystats.get('ok',0)} ok/{ystats.get('err',0)} err",
          file=sys.stderr)

    return 1 if matches else 0


if __name__ == "__main__":
    sys.exit(main())
