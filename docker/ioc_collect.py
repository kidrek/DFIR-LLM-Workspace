#!/usr/bin/env python3
"""ioc_collect.py -- draft analysis/iocs.json from parsed artifacts.

Part of the container-only DFIR workspace. Scans the outputs of earlier parsing
steps and proposes a de-duplicated, defanged observable list, so an analyst
starts from a draft instead of a blank file. The draft is a **proposal**: review,
enrich context/role/confidence, then save as ``analysis/iocs.json``.

Sources (all optional; mix any):
    --evtx-tsv PATH     flattened EVTX TSV (repeatable) -> IPs, accounts,
                        hosts, dropped-file paths
    --mft-csv PATH      MFTECmd ``$MFT`` CSV (repeatable) -> executable paths
    --usn-csv PATH      MFTECmd ``$J``/USN CSV (repeatable) -> executable paths
    --zeek DIR          Zeek log dir -> IPs, domains, URLs, hosts

Output:
    --out PATH          draft IOC JSON (default: analysis/iocs_draft.json)
    --include-internal  keep private/loopback IPs (default: still kept but
                        tagged 'internal','benign')
    --no-endpoints      omit the inferred endpoints block
    --host NAME         fallback host label in source/citation text

Case-free: only public, well-known file extensions are recognised; no host
names, IPs or case strings are baked in.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import evtx_flatten as flat
except Exception:  # noqa: BLE001
    flat = None
try:
    import ioc_schema
except Exception:  # noqa: BLE001
    ioc_schema = None

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_PATH_RE = re.compile(
    r"[A-Za-z]:\\[^\s\"'<>|]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|vbe|js|jse|"
    r"hta|msi|scr|com|jar|lnk)\b", re.I)
_EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
              ".vbs", ".vbe", ".js", ".jse", ".hta", ".msi", ".jar", ".lnk"}

# EventData fields that carry an account name.
_ACCOUNT_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName",
                   "MemberName", "ServiceAccount")
# Synthetic / machine accounts that are noise, not IOCs.
_ACCOUNT_SKIP = {"system", "local service", "network service", "anonymous logon",
                 "-", ""}
# EventData fields that carry a remote address.
_IP_FIELDS = ("IpAddress", "SrcIP", "ClientAddress", "SourceIp",
              "RemoteAddress")
# EventData fields that carry a host name.
_HOST_FIELDS = ("WorkstationName", "Workstation", "Computer", "TargetServerName")


def _valid_ipv4(v: str):
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


def _is_internal(ip) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast)


class Collector:
    def __init__(self):
        self.obs = {}          # (type, norm) -> observable dict
        self.endpoints = {}    # hostname -> {name, role, order}

    # -- add helpers ------------------------------------------------------- #
    def _add(self, typ, value, source, context="", role="", tags=None,
             confidence="medium", hosts=None):
        value = str(value).strip()
        if not value:
            return
        norm = (ioc_schema.normalize(typ, value) if ioc_schema
                else value.lower())
        key = (typ, norm)
        if key in self.obs:
            o = self.obs[key]
            if source and source not in o["source"]:
                o["source"] = (o["source"] + "; " + source).strip("; ")
            for t in (tags or []):
                if t not in o["tags"]:
                    o["tags"].append(t)
            for h in (hosts or []):
                if h and h not in o["hosts"]:
                    o["hosts"].append(h)
            return
        o = {
            "type": typ,
            "value": value,
            "defanged": (ioc_schema.defang(value, typ) if ioc_schema else value),
            "role": role,
            "confidence": confidence,
            "source": source,
            "context": context,
            "tags": list(tags or []),
            "hosts": list(hosts or []),
        }
        self.obs[key] = o

    def add_ip(self, ip_str, source, context="", host=""):
        ip = _valid_ipv4(ip_str)
        if ip is None:
            return
        internal = _is_internal(ip)
        self._add(
            "ipv4", str(ip), source,
            context=context or ("internal address" if internal else "external address"),
            role="internal-host" if internal else "external-host",
            tags=(["internal", "benign"] if internal else ["external"]),
            confidence="low" if internal else "medium",
            hosts=[host] if host else None)

    def add_account(self, name, source, host=""):
        n = (name or "").strip()
        if n.lower() in _ACCOUNT_SKIP or n.endswith("$"):
            return
        self._add("account", n, source, role="account",
                  tags=["account"], hosts=[host] if host else None)

    def add_host(self, name, source, role="host"):
        n = (name or "").strip()
        if not n or n.lower() in _ACCOUNT_SKIP:
            return
        self._add("hostname", n, source, role=role, tags=["host"],
                  hosts=[n])
        if n not in self.endpoints:
            self.endpoints[n] = {"name": n, "role": role,
                                 "order": len(self.endpoints) + 1}

    def add_domain(self, name, source, role="c2", tags=None, host=""):
        n = (name or "").strip().rstrip(".")
        if not n or _valid_ipv4(n) is not None:
            # IP addresses are handled by add_ip, not as domains.
            return
        self._add("domain", n, source, role=role,
                  tags=(tags or ["network"]), hosts=[host] if host else None)

    def add_path(self, path, source, host=""):
        p = (path or "").strip()
        if not p:
            return
        ext = os.path.splitext(p)[1].lower()
        tags = ["payload", "executable"]
        if ext in (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"):
            tags.append("script")
        self._add("file-path", p, source, role="payload", tags=tags,
                  hosts=[host] if host else None)

    # -- parsers ----------------------------------------------------------- #
    def from_evtx(self, path, host_fallback):
        try:
            fh = open(path, encoding="utf-8-sig", newline="")
        except OSError as exc:
            print(f"ioc_collect: cannot open {path}: {exc}", file=sys.stderr)
            return
        with fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                host = (r.get("computer") or host_fallback or "").strip()
                eid = str(r.get("event_id", "")).strip()
                chan = (r.get("channel") or "").strip()
                rid = (r.get("record_id") or "").strip()
                src = f"{chan} EID={eid} Rec={rid}"
                data = flat.split_data(r.get("data", "")) if flat else {}
                for f in _IP_FIELDS:
                    if f in data:
                        self.add_ip(data[f], src, host=host)
                for f in _ACCOUNT_FIELDS:
                    if f in data:
                        self.add_account(data[f], src, host=host)
                for f in _HOST_FIELDS:
                    if f in data:
                        self.add_host(data[f], src, role="host")
                for f in ("NewProcessName", "ParentProcessName", "ImagePath",
                          "TargetFilename"):
                    if f in data:
                        for m in _PATH_RE.findall(data[f]):
                            self.add_path(m, src, host=host)
                cmd = data.get("CommandLine", "")
                for m in _PATH_RE.findall(cmd):
                    self.add_path(m, src, host=host)
                for m in _URL_RE.findall(cmd):
                    self._add("url", m, src, role="c2",
                              tags=["network"], hosts=[host] if host else None)

    def from_mft(self, path, host):
        try:
            fh = open(path, encoding="utf-8-sig", newline="")
        except OSError as exc:
            print(f"ioc_collect: cannot open {path}: {exc}", file=sys.stderr)
            return
        with fh:
            for r in csv.DictReader(fh):
                nm = (r.get("FileName") or "").strip()
                if not nm or os.path.splitext(nm)[1].lower() not in _EXEC_EXTS:
                    continue
                parent = (r.get("ParentPath") or "").strip()
                full = (parent + "\\" + nm) if parent else nm
                src = f"$MFT EntryNumber={r.get('EntryNumber', '')}"
                self.add_path(full, src, host=host)

    def from_usn(self, path, host):
        try:
            fh = open(path, encoding="utf-8-sig", newline="")
        except OSError as exc:
            print(f"ioc_collect: cannot open {path}: {exc}", file=sys.stderr)
            return
        with fh:
            for r in csv.DictReader(fh):
                nm = (r.get("Name") or "").strip()
                if not nm or os.path.splitext(nm)[1].lower() not in _EXEC_EXTS:
                    continue
                parent = (r.get("ParentPath") or "").strip()
                full = (parent + "\\" + nm) if parent else nm
                reason = (r.get("UpdateReasons") or "").strip()
                src = f"$J EntryNumber={r.get('EntryNumber', '')} {reason}".strip()
                self.add_path(full, src, host=host)

    def from_zeek(self, zdir):
        def read(name):
            p = os.path.join(zdir, name)
            if not os.path.isfile(p):
                return None, []
            fields, rows = None, []
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#fields"):
                        fields = line.rstrip("\n").split("\t")[1:]
                    elif line.startswith("#"):
                        continue
                    elif line.strip():
                        rows.append(line.rstrip("\n").split("\t"))
            return fields, rows

        def get(fields, row, name):
            try:
                i = fields.index(name)
                return row[i] if i < len(row) else ""
            except (ValueError, IndexError):
                return ""

        f, rows = read("conn.log")
        for r in rows or []:
            uid = get(f, r, "uid")
            self.add_ip(get(f, r, "id.orig_h"), f"zeek conn.log uid={uid}")
            self.add_ip(get(f, r, "id.resp_h"), f"zeek conn.log uid={uid}")
        f, rows = read("dns.log")
        for r in rows or []:
            uid = get(f, r, "uid")
            self.add_domain(get(f, r, "query"), f"zeek dns.log uid={uid}",
                            role="c2", tags=["network", "dns"])
            self.add_ip(get(f, r, "id.orig_h"), f"zeek dns.log uid={uid}")
        f, rows = read("http.log")
        for r in rows or []:
            uid = get(f, r, "uid")
            hosthdr = get(f, r, "host")
            uri = get(f, r, "uri")
            if hosthdr:
                # The Host header is a remote web endpoint, not an internal
                # endpoint; record it as a domain, never an endpoint.
                self.add_domain(hosthdr, f"zeek http.log uid={uid}",
                                role="c2", tags=["network", "http"])
                if uri:
                    self._add("url", f"http://{hosthdr}{uri}",
                              f"zeek http.log uid={uid}", role="c2",
                              tags=["network", "http"])
            self.add_ip(get(f, r, "id.orig_h"), f"zeek http.log uid={uid}")
            self.add_ip(get(f, r, "id.resp_h"), f"zeek http.log uid={uid}")

    # -- output ------------------------------------------------------------ #
    def document(self, case, include_internal, with_endpoints):
        obs = []
        for o in self.obs.values():
            if not include_internal and "internal" in o["tags"]:
                continue
            obs.append(o)
        obs.sort(key=lambda o: (o["type"], o["value"].lower()))
        doc = {"case": case, "observables": obs}
        if with_endpoints and self.endpoints:
            doc["endpoints"] = self.endpoints
        return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Draft analysis/iocs.json from parsed artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--evtx-tsv", action="append", default=[])
    ap.add_argument("--mft-csv", action="append", default=[])
    ap.add_argument("--usn-csv", action="append", default=[])
    ap.add_argument("--zeek", default="")
    ap.add_argument("--host", default="")
    ap.add_argument("--case", default="", help="case name for the document")
    ap.add_argument("--include-internal", action="store_true",
                    help="drop private/loopback IPs from the draft")
    ap.add_argument("--no-endpoints", dest="endpoints", action="store_false")
    ap.add_argument("--out", default="analysis/iocs_draft.json")
    args = ap.parse_args(argv)

    c = Collector()
    for p in args.evtx_tsv:
        c.from_evtx(p, args.host)
    for p in args.mft_csv:
        c.from_mft(p, args.host)
    for p in args.usn_csv:
        c.from_usn(p, args.host)
    if args.zeek:
        c.from_zeek(args.zeek)

    doc = c.document(args.case, args.include_internal, args.endpoints)
    errors = ioc_schema.validate(doc) if ioc_schema else []
    if errors:
        print(f"ioc_collect: internal draft has {len(errors)} issue(s) "
              f"(first: {errors[0]})", file=sys.stderr)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    if os.path.exists(args.out):
        print(f"ioc_collect: refusing to overwrite {args.out} "
              f"(choose another --out or remove it)", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")

    from collections import Counter
    counts = Counter(o["type"] for o in doc["observables"])
    print(f"[ioc_collect] draft {len(doc['observables'])} observable(s), "
          f"{len(doc.get('endpoints', {}))} endpoint(s) -> {args.out}",
          file=sys.stderr)
    for t, n in sorted(counts.items()):
        print(f"  {t:<12} {n}", file=sys.stderr)
    print("  review, then save as analysis/iocs.json", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
