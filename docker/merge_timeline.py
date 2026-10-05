#!/usr/bin/env python3
"""merge_timeline.py -- consolidate artifacts into the normalized timeline CSV.

Part of the container-only DFIR workspace. Reads the parsed outputs produced
earlier in the workflow and emits the normalized super-timeline that
``incident_viz.py`` and ``incident_dashboard.py`` consume:

    time_utc,host,actor,event,technique,evidence,tags

Sources (all optional; mix any):
    --evtx-tsv PATH     flattened EVTX TSV from evtx_flatten.py (repeatable)
    --mft-csv PATH      MFTECmd ``$MFT`` CSV (repeatable)
    --usn-csv PATH      MFTECmd ``$J``/USN CSV (repeatable)
    --zeek DIR          Zeek log directory (conn/http/dns/smb_mapping/kerberos)
    --esxi-timeline PATH  esxi_triage.py timeline.csv (repeatable)

Output:
    --out PATH          normalized timeline CSV
    --all-evtx          emit every EVTX event, not just the curated set
    --host NAME         fallback host label for sources without one

Case-free: event descriptions and MITRE mapping are generic public knowledge;
no host names, IPs or case strings are baked in. Timestamps are normalized to
UTC ISO-8601 seconds.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import evtx_flatten as flat  # canonical pipe-safe data-blob parser
except Exception:  # noqa: BLE001
    flat = None
try:
    import dfir_signatures as siglib  # optional per-case patterns
except Exception:  # noqa: BLE001
    siglib = None
try:
    import hostmap as hm  # generic host-label normalisation (case-free)
except Exception:  # noqa: BLE001
    hm = None

UTC = timezone.utc
OUT_COLS = ["time_utc", "host", "actor", "event", "technique", "evidence", "tags"]

# Extension sets used for file-event tagging (generic).
_EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
              ".vbs", ".vbe", ".js", ".jse", ".hta", ".msi", ".jar", ".lnk"}
_SCRIPT_EXTS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sh", ".py"}

# Curated Windows event map: EID -> event template / technique / tags / actor.
# Templates use EventData field names; a missing field becomes "".
EVTX_EVENTS = {
    "4688": {"event": "process: {NewProcessName}",
             "technique": "T1059", "tags": ["process"], "actor": "SubjectUserName"},
    "4624": {"event": "logon type {LogonType} from {IpAddress}",
             "technique": "T1078", "tags": ["logon"], "actor": "TargetUserName"},
    "4625": {"event": "failed logon '{TargetUserName}' from {IpAddress}",
             "technique": "T1110", "tags": ["logon", "failed"], "actor": "IpAddress"},
    "4634": {"event": "logoff {TargetUserName}", "technique": "",
             "tags": ["logon"], "actor": "TargetUserName"},
    "4672": {"event": "special privileges for {SubjectUserName}",
             "technique": "T1078", "tags": ["privilege"], "actor": "SubjectUserName"},
    "4720": {"event": "account created: {TargetUserName}",
             "technique": "T1136", "tags": ["account", "persistence"], "actor": "SubjectUserName"},
    "4726": {"event": "account deleted: {TargetUserName}",
             "technique": "T1531", "tags": ["account"], "actor": "SubjectUserName"},
    "4728": {"event": "added to global group: {MemberName}",
             "technique": "T1098", "tags": ["account", "persistence"], "actor": "SubjectUserName"},
    "4732": {"event": "added to local group: {MemberName}",
             "technique": "T1098", "tags": ["account", "persistence"], "actor": "SubjectUserName"},
    "4756": {"event": "added to universal group: {MemberName}",
             "technique": "T1098", "tags": ["account", "persistence"], "actor": "SubjectUserName"},
    "4768": {"event": "Kerberos TGT for {TargetUserName} from {IpAddress}",
             "technique": "T1558", "tags": ["kerberos", "credential"], "actor": "TargetUserName"},
    "4769": {"event": "Kerberos TGS {ServiceName} for {TargetUserName} ({TicketEncryptionType})",
             "technique": "T1558.003", "tags": ["kerberos", "credential"], "actor": "TargetUserName"},
    "4771": {"event": "Kerberos pre-auth failed {TargetUserName} from {IpAddress}",
             "technique": "T1110", "tags": ["kerberos", "failed"], "actor": "IpAddress"},
    "4776": {"event": "NTLM validation {TargetUserName} from {Workstation}",
             "technique": "", "tags": ["ntlm"], "actor": "TargetUserName"},
    "7045": {"event": "service installed: {ServiceName}",
             "technique": "T1543.003", "tags": ["service", "persistence"], "actor": "AccountName"},
    "4698": {"event": "scheduled task: {TaskName}",
             "technique": "T1053.005", "tags": ["task", "persistence"], "actor": "SubjectUserName"},
    "1102": {"event": "audit log cleared by {SubjectUserName}",
             "technique": "T1070.001", "tags": ["anti-forensics"], "actor": "SubjectUserName"},
    "4104": {"event": "PowerShell script block",
             "technique": "T1059.001", "tags": ["execution", "powershell"], "actor": "SubjectUserName"},
    "5140": {"event": "share accessed: {ShareName}",
             "technique": "T1021.002", "tags": ["lateral", "share"], "actor": "SubjectUserName"},
    "5145": {"event": "share object: {ShareName}\\{RelativeTargetName}",
             "technique": "T1021.002", "tags": ["lateral", "share"], "actor": "IpAddress"},
    "4662": {"event": "directory service access ({Properties})",
             "technique": "T1003.006", "tags": ["dcsync", "credential"], "actor": "SubjectUserName"},
}

# esxi_triage.py category -> MITRE technique.
ESXI_TECH = {
    "authentication": "T1078",
    "execution": "T1059",
    "integrity": "T1543",
    "ransomware": "T1486",
    "vm-escape": "T1611",
}


class _SafeDict(dict):
    """format_map target that resolves missing keys case-insensitively to ''."""

    def __missing__(self, key):
        low = str(key).lower()
        for k, v in self.items():
            if str(k).lower() == low:
                return v
        return ""


def iso_from_epoch(ts: str) -> str:
    try:
        return datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return ""


def iso_utc(text: str) -> str:
    """Normalize a timestamp string to ISO-8601 UTC seconds."""
    s = ("" if text is None else str(text)).strip()
    if not s:
        return ""
    if re.fullmatch(r"\d{9,}(?:\.\d+)?", s):  # epoch seconds
        return iso_from_epoch(s)
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(**kw) -> dict:
    r = {c: "" for c in OUT_COLS}
    r.update(kw)
    if isinstance(r["tags"], (list, tuple)):
        r["tags"] = ";".join(str(t) for t in r["tags"] if t)
    return r


# --------------------------------------------------------------------------- #
# EVTX
# --------------------------------------------------------------------------- #
def parse_evtx(tsv_path: str, all_evtx: bool, sig) -> list[dict]:
    rows = []
    try:
        fh = open(tsv_path, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"merge_timeline: cannot open {tsv_path}: {exc}", file=sys.stderr)
        return rows
    with fh:
        rdr = csv.DictReader(fh, delimiter="\t")
        for r in rdr:
            eid = str(r.get("event_id", "")).strip()
            spec = EVTX_EVENTS.get(eid)
            if spec is None and not all_evtx:
                continue
            data = flat.split_data(r.get("data", "")) if flat else {}
            sd = _SafeDict(data)
            host = (r.get("computer") or "").strip()
            chan = (r.get("channel") or "").strip()
            rid = (r.get("record_id") or "").strip()
            if spec:
                desc = spec["event"].format_map(sd)
                tech = spec.get("technique", "")
                tags = list(spec.get("tags", []))
                actor = data.get(spec.get("actor", ""), "") if spec.get("actor") else ""
            else:
                desc = f"event {eid}"
                tech, tags, actor = "", [], ""
            if sig:
                pat = (sd.get("NewProcessName", "") + " " + sd.get("CommandLine", ""))
                if any(re.search(p, pat) for p in
                       sig.get("windows_process_patterns", []) if p):
                    tags.append("interesting")
            rows.append(_row(time_utc=iso_utc(r.get("time_utc", "")), host=host,
                             actor=actor, event=desc.rstrip(), technique=tech,
                             evidence=f"{chan} EID={eid} Rec={rid}",
                             tags=tags))
    return rows


# --------------------------------------------------------------------------- #
# MFT / USN
# --------------------------------------------------------------------------- #
def _file_event(path: str, ts: str, evid: str, sig, host: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    tags = ["file"]
    if ext in _EXEC_EXTS:
        tags.append("executable")
    if ext in _SCRIPT_EXTS:
        tags.append("script")
    if sig and any(re.search(p, path) for p in
                   sig.get("windows_process_patterns", []) if p):
        tags.append("interesting")
    return _row(time_utc=ts, host=host, actor="", event=f"file: {path}",
                technique="", evidence=evid, tags=tags)


def parse_mft(csv_path: str, time_field: str, sig, host: str) -> list[dict]:
    rows = []
    try:
        fh = open(csv_path, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"merge_timeline: cannot open {csv_path}: {exc}", file=sys.stderr)
        return rows
    with fh:
        for r in csv.DictReader(fh):
            nm = (r.get("FileName") or "").strip()
            if not nm:
                continue
            parent = (r.get("ParentPath") or "").strip()
            path = (parent + "\\" + nm) if parent else nm
            ts = iso_utc(r.get(time_field, ""))
            if not ts:
                continue
            evid = f"$MFT EntryNumber={r.get('EntryNumber', '')}"
            rows.append(_file_event(path, ts, evid, sig, host))
    return rows


def parse_usn(csv_path: str, sig, host: str) -> list[dict]:
    rows = []
    try:
        fh = open(csv_path, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"merge_timeline: cannot open {csv_path}: {exc}", file=sys.stderr)
        return rows
    with fh:
        for r in csv.DictReader(fh):
            nm = (r.get("Name") or "").strip()
            if not nm:
                continue
            parent = (r.get("ParentPath") or "").strip()
            path = (parent + "\\" + nm) if parent else nm
            ts = iso_utc(r.get("UpdateTimestamp", ""))
            if not ts:
                continue
            reason = (r.get("UpdateReasons") or "").strip()
            evid = f"$J EntryNumber={r.get('EntryNumber', '')} {reason}".strip()
            rows.append(_file_event(path, ts, evid, sig, host))
    return rows


# --------------------------------------------------------------------------- #
# Zeek
# --------------------------------------------------------------------------- #
def _read_zeek(path: str):
    fields, out = None, []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif line.strip():
                    out.append(line.rstrip("\n").split("\t"))
    except OSError:
        return None, []
    return fields, out


def _zget(fields, row, name, default=""):
    try:
        i = fields.index(name)
        return row[i] if i < len(row) else default
    except (ValueError, IndexError):
        return default


def parse_zeek_dir(zdir: str, include_conn: bool) -> list[dict]:
    rows = []
    spec = {
        "http.log": ("T1071.001", ["network", "http"],
                     lambda f, r: f"{_zget(f, r, 'method')} "
                                  f"{_zget(f, r, 'host')}{_zget(f, r, 'uri')}"),
        "dns.log": ("T1071.004", ["network", "dns"],
                    lambda f, r: f"dns query {_zget(f, r, 'query')}"),
        "smb_mapping.log": ("T1021.002", ["network", "smb"],
                            lambda f, r: f"smb {_zget(f, r, 'service')} "
                                         f"{_zget(f, r, 'path')}"),
        "kerberos.log": ("T1558", ["network", "kerberos"],
                         lambda f, r: f"kerberos {_zget(f, r, 'request_type')} "
                                      f"{_zget(f, r, 'service')}"),
    }
    for name, (tech, tags, mk) in spec.items():
        path = os.path.join(zdir, name)
        if not os.path.isfile(path):
            continue
        fields, data = _read_zeek(path)
        if not fields:
            continue
        for r in data:
            ts = iso_from_epoch(_zget(fields, r, "ts"))
            if not ts:
                continue
            host = _zget(fields, r, "id.orig_h")
            actor = _zget(fields, r, "id.resp_h")
            uid = _zget(fields, r, "uid")
            rows.append(_row(time_utc=ts, host=host, actor=actor,
                             event=mk(fields, r), technique=tech,
                             evidence=f"zeek {name} uid={uid}", tags=tags))
    if include_conn:
        path = os.path.join(zdir, "conn.log")
        if os.path.isfile(path):
            fields, data = _read_zeek(path)
            for r in data or []:
                ts = iso_from_epoch(_zget(fields, r, "ts"))
                if not ts:
                    continue
                svc = _zget(fields, r, "service")
                rows.append(_row(time_utc=ts, host=_zget(fields, r, "id.orig_h"),
                                 actor=_zget(fields, r, "id.resp_h"),
                                 event=f"conn {svc} "
                                       f":{_zget(fields, r, 'id.resp_p')}",
                                 technique="", tags=["network"],
                                 evidence=f"zeek conn.log uid={_zget(fields, r, 'uid')}"))
    return rows


# --------------------------------------------------------------------------- #
# ESXi
# --------------------------------------------------------------------------- #
def parse_esxi(csv_path: str, host_fallback: str) -> list[dict]:
    rows = []
    try:
        fh = open(csv_path, encoding="utf-8-sig", newline="")
    except OSError as exc:
        print(f"merge_timeline: cannot open {csv_path}: {exc}", file=sys.stderr)
        return rows
    with fh:
        for r in csv.DictReader(fh):
            ts = iso_utc(r.get("time_utc", ""))
            if not ts:
                continue
            category = (r.get("category") or "").strip().lower()
            tags = [t for t in (r.get("category", ""), r.get("severity", "")) if t]
            rows.append(_row(
                time_utc=ts,
                host=(r.get("component") or host_fallback).strip(),
                actor=(r.get("user") or r.get("src_ip") or "").strip(),
                event=(r.get("event") or r.get("detail") or "").strip(),
                technique=ESXI_TECH.get(category, ""),
                evidence=f"esxi {r.get('source_log', '')}:{r.get('line_no', '')}",
                tags=tags))
    return rows


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Consolidate parsed artifacts into the normalized timeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--evtx-tsv", action="append", default=[])
    ap.add_argument("--mft-csv", action="append", default=[])
    ap.add_argument("--usn-csv", action="append", default=[])
    ap.add_argument("--zeek", default="")
    ap.add_argument("--esxi-timeline", action="append", default=[])
    ap.add_argument("--mft-time-field", default="Created0x10")
    ap.add_argument("--all-evtx", action="store_true")
    ap.add_argument("--zeek-conn", action="store_true")
    ap.add_argument("--host", default="", help="fallback host label")
    ap.add_argument("--ip-map", default="",
                    help="JSON host map (IP/FQDN/alias -> display name); e.g. the "
                         "endpoints block of analysis/iocs.json")
    ap.add_argument("--drop-noise", dest="drop_noise", action="store_true",
                    default=True,
                    help="drop link-local/multicast/broadcast hosts (default: on)")
    ap.add_argument("--keep-noise", dest="drop_noise", action="store_false",
                    help="keep link-local/multicast/broadcast host rows")
    ap.add_argument("--signatures", default="",
                    help="optional signatures JSON (default analysis/signatures.json)")
    ap.add_argument("--out", required=True, help="output timeline CSV")
    args = ap.parse_args(argv)

    sig = siglib.load_signatures(args.signatures) if siglib else None
    hostmap = hm.load_map(args.ip_map) if (hm and args.ip_map) else {}

    rows = []
    for p in args.evtx_tsv:
        rows += parse_evtx(p, args.all_evtx, sig)
    for p in args.mft_csv:
        rows += parse_mft(p, args.mft_time_field, sig, args.host)
    for p in args.usn_csv:
        rows += parse_usn(p, sig, args.host)
    if args.zeek:
        rows += parse_zeek_dir(args.zeek, args.zeek_conn)
    for p in args.esxi_timeline:
        rows += parse_esxi(p, args.host)

    # Normalise host labels (IP -> case name, FQDN -> short, noise -> Network)
    # before de-duplication so the same host does not appear under two spellings.
    if hm:
        for r in rows:
            r["host"] = hm.norm_host(r.get("host", ""), hostmap)
            if r.get("actor") and hm.parse_ip(r["actor"]):
                r["actor"] = hm.norm_host(r["actor"], hostmap)

    # Drop rows without a time, de-duplicate, then sort.
    seen = set()
    uniq = []
    for r in rows:
        if not r["time_utc"]:
            continue
        if args.drop_noise and r["host"] == hm.NETWORK_BUCKET:
            continue
        key = (r["time_utc"], r["host"], r["event"], r["evidence"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    uniq.sort(key=lambda r: (r["time_utc"], r["host"], r["event"]))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OUT_COLS)
        w.writeheader()
        w.writerows(uniq)

    print(f"[merge_timeline] {len(uniq)} event(s) "
          f"(from {len(rows)} parsed) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
