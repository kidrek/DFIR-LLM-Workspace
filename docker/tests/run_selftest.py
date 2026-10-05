#!/usr/bin/env python3
"""Self-tests for the reusable DFIR helpers (case-free, stdlib only).

Runs entirely inside the toolkit container against small synthetic fixtures in
``docker/tests/fixtures`` -- no case evidence is required. Used by
``docker/selftest.sh`` and safe to run ad-hoc:

    docker/dfir.sh python3 /data/tools/tests/run_selftest.py

Each check is independent; the process exits non-zero if any check fails, so it
can gate a change to a helper. Add a new fixture under ``fixtures/`` and a
matching ``test_*`` function here when you extend a helper.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import json

HERE = os.path.dirname(os.path.abspath(__file__))
DOCKER = os.path.dirname(HERE)          # /data/tools
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, DOCKER)

_FAILS: list[str] = []
_PASSES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _PASSES
    if cond:
        _PASSES += 1
        print(f"  ok   {name}")
    else:
        _FAILS.append(f"{name}: {detail}" if detail else name)
        print(f"  FAIL {name}  {detail}")


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


# --------------------------------------------------------------------------- #
def test_pipe_codec() -> None:
    """evtx_flatten join/split must round-trip a value containing '|'."""
    print("pipe-safe data codec (evtx_flatten)")
    import evtx_flatten as flat

    value = 'cmd /c "echo a | findstr b"'
    blob = flat.join_data([("CommandLine", value), ("SubjectUserName", "SYSTEM")])
    check("blob has exactly one separator",
          blob.count(" | ") == 1, f"unexpected separators in {blob!r}")
    parsed = flat.split_data(blob)
    check("pipe preserved in value",
          parsed.get("CommandLine") == value, f"got {parsed.get('CommandLine')!r}")
    check("second field intact",
          parsed.get("SubjectUserName") == "SYSTEM")

    weird = "a|b|c\\d\te\nf"
    round_trip = flat.split_data(flat.join_data([("k", weird)]))
    check("arbitrary value round-trips", round_trip.get("k") == weird)


def test_evtx_flatten_end_to_end() -> None:
    """evtx_flatten decodes a real evtx_dump JSONL event (codec in the loop)."""
    print("evtx_flatten (JSONL -> pipe-safe TSV)")
    jsonl = os.path.join(FIX, "sample_security.jsonl")
    with tempfile.TemporaryDirectory() as td:
        tsv = os.path.join(td, "out.tsv")
        p = run([os.path.join(DOCKER, "evtx_flatten.py"), jsonl, tsv])
        check("exit 0", p.returncode == 0, p.stderr.strip())
        with open(tsv, encoding="utf-8") as fh:
            body = fh.read()
        check("event id captured", "4688" in body, body[:200])
        # On disk the pipe is escaped as \p; the field after it stays intact.
        check("pipe escaped on disk", r"echo a \p findstr b" in body, body[:300])
        check("field after the pipe intact",
              "SubjectUserName=SYSTEM" in body, body[:300])
        # And the query helper reads it back intact (unescaped).
        out = os.path.join(td, "q.tsv")
        p2 = run([os.path.join(DOCKER, "evtx_query.py"), tsv, "--eid", "4688",
                  "--fields", "CommandLine,SubjectUserName", "--out", out])
        check("query exit 0", p2.returncode == 0, p2.stderr.strip())
        with open(out, encoding="utf-8") as fh:
            q = fh.read()
        check("queried command line intact",
              "echo a | findstr b" in q, q[:300])


def test_evtx_query() -> None:
    """evtx_query must emit channel and keep a piped CommandLine intact."""
    print("evtx_query (channel + pipe-safety)")
    tsv = os.path.join(FIX, "sample_security.tsv")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "q.tsv")
        p = run([os.path.join(DOCKER, "evtx_query.py"), tsv, "--eid", "4688",
                 "--fields", "NewProcessName,CommandLine,SubjectUserName",
                 "--out", out])
        check("exit 0", p.returncode == 0, p.stderr.strip())
        with open(out, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        header = lines[0].split("\t") if lines else []
        check("channel column present", "channel" in header, str(header))
        body = lines[1] if len(lines) > 1 else ""
        check("command line keeps its pipe",
              "echo a | findstr b" in body, body)

        p2 = run([os.path.join(DOCKER, "evtx_query.py"), tsv, "--eid", "4769",
                  "--fields", "ServiceName,TargetUserName,TicketEncryptionType",
                  "--format", "json"])
        check("json output exit 0", p2.returncode == 0, p2.stderr.strip())
        check("json has channel", '"channel"' in p2.stdout)


def test_mft_query() -> None:
    print("mft_query (USN schema sniff + name filter)")
    csv_path = os.path.join(FIX, "sample_usn.csv")
    p = run([os.path.join(DOCKER, "mft_query.py"), "--csv", csv_path,
             "--name", r"mimikatz\.exe", "--format", "json"])
    check("exit 0", p.returncode == 0, p.stderr.strip())
    check("finds the dropped binary",
          "mimikatz.exe" in p.stdout, p.stdout[:200])
    check("reports usn schema", "schema=usn" in p.stderr, p.stderr.strip())


def test_custody() -> None:
    print("custody (hash -> verify, tamper detected)")
    with tempfile.TemporaryDirectory() as td:
        ev = os.path.join(td, "evidences")
        os.makedirs(os.path.join(ev, "C"))
        target = os.path.join(ev, "C", "file.bin")
        with open(target, "wb") as fh:
            fh.write(b"original evidence")
        outdir = os.path.join(td, "hashes")
        tool = os.path.join(DOCKER, "custody.py")

        p = run([tool, "hash", "--label", "intake", "--outdir", outdir, ev,
                 "--quiet"])
        check("hash exit 0", p.returncode == 0, p.stderr.strip())
        check("manifest written",
              os.path.isfile(os.path.join(outdir, "intake.sha256")))

        p = run([tool, "verify", "--label", "intake", "--outdir", outdir, ev])
        check("unchanged verify exit 0", p.returncode == 0, p.stderr.strip())
        check("reports UNCHANGED", "UNCHANGED" in p.stderr, p.stderr.strip())

        with open(target, "ab") as fh:
            fh.write(b"tampered")
        p = run([tool, "verify", "--label", "intake", "--outdir", outdir, ev])
        check("tamper verify exit 1", p.returncode == 1, f"rc={p.returncode}")
        check("reports CHANGED", "CHANGED" in p.stderr, p.stderr.strip())


def test_launchers() -> None:
    """Every Zimmerman wrapper must point at an existing DLL (in-container)."""
    print("tool launchers (Zimmerman .dll targets)")
    tools = ["MFTECmd", "PECmd", "LECmd", "JLECmd", "SBECmd", "AmcacheParser",
             "AppCompatCacheParser", "SrumECmd", "RECmd", "EvtxECmd"]
    import shutil
    if not os.path.isdir("/opt/zimmerman"):
        check("zimmerman image present", True, "skipped (host run)")
        return
    for t in tools:
        launch = shutil.which(t)
        if not launch:
            check(f"{t} launcher on PATH", False, "not found")
            continue
        with open(launch, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        import re as _re
        m = _re.search(r'["\s](/[^"\s]+\.dll)', body)
        target = m.group(1) if m else ""
        check(f"{t} -> existing dll", bool(target) and os.path.isfile(target),
              f"target={target or '?'}")


def test_merge_timeline() -> None:
    """merge_timeline consolidates EVTX + Zeek into the normalized schema."""
    print("merge_timeline (EVTX + Zeek -> normalized CSV)")
    tsv = os.path.join(FIX, "sample_security.tsv")
    zeek = os.path.join(FIX, "zeek")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "timeline.csv")
        p = run([os.path.join(DOCKER, "merge_timeline.py"),
                 "--evtx-tsv", tsv, "--zeek", zeek, "--out", out])
        check("exit 0", p.returncode == 0, p.stderr.strip())
        import csv as _csv
        with open(out, encoding="utf-8") as fh:
            rows = list(_csv.DictReader(fh))
        header = list(rows[0].keys()) if rows else []
        check("schema header",
              header == ["time_utc", "host", "actor", "event", "technique",
                         "evidence", "tags"], str(header))
        check("curated events present", len(rows) >= 3, f"{len(rows)} rows")
        joined = " ".join(r["event"] for r in rows)
        check("process event rendered", "cmd.exe" in joined, joined[:200])
        check("logon event rendered", "logon" in joined.lower(), joined[:200])
        check("technique mapped",
              any(r["technique"].startswith("T") for r in rows),
              str([r["technique"] for r in rows]))
        check("network event from zeek",
              any("evil.local" in r["event"] for r in rows), joined[:300])
        check("sorted by time",
              all(rows[i]["time_utc"] <= rows[i + 1]["time_utc"]
                  for i in range(len(rows) - 1)))


def test_hostmap() -> None:
    """hostmap.norm_host must never truncate a literal IP and buckets noise.

    Regression guard: an earlier ``v.split('.')[0]`` collapsed every IPv4 to
    its first octet, merging distinct endpoints under '192'.
    """
    print("hostmap (host-label normalisation)")
    import hostmap as hm

    m = {"10.0.0.30": "FILESRV", "filesrv": "FILESRV",
         "filesrv.corp.example": "FILESRV", "10.0.0.9": "Gateway"}
    check("FQDN reduced to short name",
          hm.norm_host("filesrv.corp.example", m) == "FILESRV",
          hm.norm_host("filesrv.corp.example", m))
    check("FQDN without alias -> first label",
          hm.norm_host("web01.corp.example", m) == "web01",
          hm.norm_host("web01.corp.example", m))
    check("IPv4 not truncated (mapped)",
          hm.norm_host("10.0.0.30", m) == "FILESRV", hm.norm_host("10.0.0.30", m))
    check("IPv4 not truncated (unmapped)",
          hm.norm_host("192.168.1.20", m) == "192.168.1.20",
          hm.norm_host("192.168.1.20", m))
    check("short-name alias resolves",
          hm.norm_host("FILESRV", m) == "FILESRV", hm.norm_host("FILESRV", m))
    check("IPv6 link-local -> Network",
          hm.norm_host("fe80::1", m) == hm.NETWORK_BUCKET,
          hm.norm_host("fe80::1", m))
    check("multicast -> Network",
          hm.norm_host("224.0.0.251", m) == hm.NETWORK_BUCKET,
          hm.norm_host("224.0.0.251", m))
    check("broadcast -> Network",
          hm.norm_host("10.0.0.255", m) == hm.NETWORK_BUCKET,
          hm.norm_host("10.0.0.255", m))
    check("empty -> Unknown", hm.norm_host("", m) == "Unknown")


def test_ioc_schema_and_export() -> None:
    """ioc_export validates/dedupes; the shared schema flags bad input."""
    print("ioc_export / ioc_schema (validate, dedupe, defang)")
    import ioc_schema
    good = {"observables": [
        {"type": "ipv4", "value": "10.0.0.5"},
        {"type": "ipv4", "value": "10.0.0.5"},          # duplicate
    ]}
    errs = ioc_schema.validate(good)
    check("duplicate detected", any("duplicate" in e for e in errs), str(errs))
    bad = {"observables": [{"type": "bogus", "value": "x"},
                          {"value": "no-type"}]}
    errs = ioc_schema.validate(bad)
    check("bad type flagged", any("not in" in e for e in errs), str(errs))
    check("missing type flagged", any("missing required 'type'" in e for e in errs))
    check("defang url", ioc_schema.defang("http://evil.local/x", "url")
          == "hxxp://evil[.]local/x")
    check("defang ipv4", ioc_schema.defang("10.0.0.5", "ipv4") == "10[.]0[.]0[.]5")

    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "iocs.json")
        with open(src, "w", encoding="utf-8") as fh:
            json.dump({"observables": [
                {"type": "ipv4", "value": "10.0.0.5", "tags": ["attacker"]},
                {"type": "ipv4", "value": "10.0.0.5"},
                {"type": "domain", "value": "Evil.local."},
            ]}, fh)
        out = os.path.join(td, "iocs.csv")
        # Export (no --validate): duplicates are deduped, not fatal.
        p = run([os.path.join(DOCKER, "ioc_export.py"), "--in", src,
                 "--out", out])
        check("export exit 0", p.returncode == 0, p.stderr.strip())
        import csv as _csv
        with open(out, encoding="utf-8") as fh:
            rows = list(_csv.DictReader(fh))
        check("duplicate dropped by default", len(rows) == 2, f"{len(rows)} rows")
        check("defang auto-filled",
              any(r["defanged"] == "10[.]0[.]0[.]5" for r in rows), str(rows))
        # Strict validation flags the duplicate and exits 1.
        p2 = run([os.path.join(DOCKER, "ioc_export.py"), "--in", src,
                  "--out", os.path.join(td, "x.csv"), "--validate"])
        check("--validate exit 1 on duplicate", p2.returncode == 1,
              f"rc={p2.returncode}")


def test_ioc_collect() -> None:
    """ioc_collect drafts a valid, defanged iocs.json from artifacts."""
    print("ioc_collect (artifacts -> IOC draft)")
    tsv = os.path.join(FIX, "sample_security.tsv")
    usn = os.path.join(FIX, "sample_usn.csv")
    zeek = os.path.join(FIX, "zeek")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "draft.json")
        p = run([os.path.join(DOCKER, "ioc_collect.py"),
                 "--evtx-tsv", tsv, "--usn-csv", usn, "--zeek", zeek,
                 "--host", "FILE01", "--case", "unit-test", "--out", out,
                 "--include-internal"])
        check("exit 0", p.returncode == 0, p.stderr.strip())
        with open(out, encoding="utf-8") as fh:
            doc = json.load(fh)
        import ioc_schema
        check("draft passes schema", ioc_schema.validate(doc) == [],
              str(ioc_schema.validate(doc)))
        vals = {o["value"] for o in doc["observables"]}
        check("external ip collected", "10.0.0.5" in vals, str(sorted(vals)))
        check("domain collected", "evil.local" in vals, str(sorted(vals)))
        check("payload path collected",
              any("mimikatz.exe" in v for v in vals), str(sorted(vals)))
        check("defanged present",
              all(o.get("defanged") for o in doc["observables"]))
        check("endpoints inferred", "endpoints" in doc, str(doc.get("endpoints")))
        # A web Host header must not become an endpoint (only real hosts do).
        eps = doc.get("endpoints", {})
        check("web host not an endpoint", "evil.local" not in eps, str(list(eps)))
        check("host endpoint present", any(k for k in eps), str(list(eps)))
        # De-dup across sources: the same IP from conn/dns/http is one entry.
        ips = [o for o in doc["observables"] if o["type"] == "ipv4"
               and o["value"] == "10.0.0.5"]
        check("ip de-duplicated", len(ips) == 1, f"{len(ips)} entries")


# --------------------------------------------------------------------------- #
def main() -> int:
    for fn in (test_pipe_codec, test_evtx_flatten_end_to_end, test_evtx_query,
               test_mft_query, test_custody,
               test_merge_timeline, test_hostmap, test_ioc_schema_and_export,
               test_ioc_collect, test_launchers):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"raised {exc!r}")
        print()
    print(f"selftest: {_PASSES} passed, {len(_FAILS)} failed")
    for f in _FAILS:
        print(f"  - {f}")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
