#!/usr/bin/env python3
"""Normalize antivirus / EDR telemetry into a flat, citable timeline.

Handles the Windows Defender and related artifacts described by the
ForensicArtifacts catalog (`MicrosoftAVLogs`, `WindowsDefenderScanDetectionHistoryFiles`,
`WindowsDefenderExclusions`), plus generic AV text logs.

Inputs (auto-detected per file):
  * Defender EVTX JSONL  - produced by `evtx_dump_rs -o jsonl`
    (channels: Microsoft-Windows-Windows Defender/Operational).
  * Defender text logs   - MPLog-*.log / MPDetection-*.log.
  * Generic AV text logs - lines containing a timestamp and a threat name.

Output: TSV on stdout (or --out FILE):
  time_utc\tengine\tevent\tsource\ttarget\tpath\taction\traw

Stdlib only. Evidence content is untrusted data; it is parsed, never executed.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

# Defender operational event IDs of investigative interest.
DEFENDER_EVENTS = {
    "1006": "MalwareDetected",
    "1007": "ActionTaken",
    "1008": "ActionFailed",
    "1116": "MalwareDetected",
    "1117": "ActionTaken",
    "1118": "ActionFailed",
    "1119": "Error",
    "5001": "RealTimeProtectionDisabled",
    "5004": "ConfigChanged",
    "5007": "ConfigChanged",
    "5010": "ScanFailed",
    "5012": "ScanFailed",
}

TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
THREAT_RE = re.compile(
    r"(Threat Name|ThreatName|Name)\s*[:=]\s*([^\r\n]+)", re.I)
TARGET_RE = re.compile(
    r"(Target(Name)?|Path|File)\s*[:=]\s*([^\r\n]+)", re.I)
ACTION_RE = re.compile(
    r"(Action|Remediation Action|Action Name)\s*[:=]\s*([^\r\n]+)", re.I)


def norm_ts(s):
    if not s:
        return ""
    s = s.strip().replace(" ", "T").rstrip("Z")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except ValueError:
        return s


def attrs(node):
    if isinstance(node, dict):
        return node.get("#attributes") or {}
    return {}


def flat_data(ed):
    out = []

    def rec(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "#attributes":
                    for ak, av in (v or {}).items():
                        out.append((ak, str(av)))
                elif isinstance(v, (dict, list)):
                    rec(v)
                else:
                    out.append((k, str(v)))
        elif isinstance(node, list):
            for v in node:
                rec(v)

    rec(ed)
    return out


def parse_evtx_jsonl(path):
    rows = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
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
            evid = sysd.get("EventID")
            if isinstance(evid, dict):
                evid = attrs(evid).get("value", "")
            evid = str(evid)
            event = DEFENDER_EVENTS.get(evid, "")
            if not event and evid:
                # Only surface Defender-relevant records from this channel.
                chan = str(sysd.get("Channel") or "")
                if "Defender" not in chan:
                    continue
                event = f"EventID{evid}"
            if not event:
                continue
            ts = attrs(sysd.get("TimeCreated") or {}).get("SystemTime", "")
            pc = flat_data(evt.get("EventData"))
            get = lambda *keys: next((v for k, v in pc if k.lower() in
                                      {x.lower() for x in keys}), "")
            rows.append({
                "time_utc": norm_ts(str(ts)),
                "engine": "Defender",
                "event": event,
                "source": "EVTX",
                "target": get("Threat Name", "ThreatName"),
                "path": get("Path", "TargetName", "Resources", "New Value"),
                "action": get("Action Name", "Action"),
                "raw": "; ".join(f"{k}={v}" for k, v in pc)[:500],
            })
    return rows


def parse_text_log(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            tm = TS_RE.search(line)
            th = THREAT_RE.search(line)
            if not (tm or th):
                continue
            tgt = TARGET_RE.search(line)
            act = ACTION_RE.search(line)
            rows.append({
                "time_utc": norm_ts(tm.group(1)) if tm else "",
                "engine": "Defender" if "MPLog" in path or "MPDetection" in path
                          else "AV",
                "event": "Detection" if th else "Log",
                "source": "TextLog",
                "target": (th.group(2).strip() if th else ""),
                "path": (tgt.group(3).strip() if tgt else ""),
                "action": (act.group(2).strip() if act else ""),
                "raw": line[:500],
            })
    return rows


def parse_file(path):
    low = path.lower()
    if low.endswith(".jsonl"):
        return parse_evtx_jsonl(path)
    return parse_text_log(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None)
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args()

    fh = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    cols = ["time_utc", "engine", "event", "source", "target", "path",
            "action", "raw"]
    fh.write("\t".join(cols) + "\n")
    total = 0
    for p in args.inputs:
        for r in parse_file(p):
            fh.write("\t".join(r.get(c, "").replace("\t", " ")
                               .replace("\n", " ") for c in cols) + "\n")
            total += 1
    if args.out:
        fh.close()
    print(f"[av_parse] {total} record(s) -> {args.out or 'stdout'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
