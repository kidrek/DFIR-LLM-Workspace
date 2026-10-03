#!/usr/bin/env python3
"""ESXi / VMware log parser, analyser and hunter.

Ingests a VMware ESXi support bundle (`vm-support` output: .tgz/.tar.gz/.zip),
a bare directory of logs (e.g. `/var/log` or `/var/run/log`), or a single
`.log`/`.log.gz` file. Produces:

  * timeline.csv   - one normalized row per interesting log line
  * findings.json  - categorized security findings with severity
  * summary.txt    - human-readable summary

Detection content covers authentication, execution, integrity/config change,
ransomware (ESXiArgs and peers) and VM-escape CVEs, based on the
ForensicArtifacts `esxi.yaml` artifact set.

Usage:
  esxi_triage.py [--out DIR] [--datastore DIR] [--no-av] [--min-severity LVL]
                 <bundle-or-dir> [<more> ...]

Exit codes: 0 no HIGH/CRITICAL findings, 1 HIGH/CRITICAL present, 2 error.

Evidence content is untrusted data. Nothing here executes evidence.
Stdlib only.
"""
import argparse
import csv
import gzip
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile

# --------------------------------------------------------------------------- #
# ESXi log grammar
# --------------------------------------------------------------------------- #
# Examples:
#   2025-02-19T18:21:13.088Z Hostd[526002]: [Originator@6876 sub=...] Event 832 : ...
#   2025-02-19T18:21:13.152Z sftp-server[1711241]: open "/scratch/logs.tar" ...
#   2025-02-19T18:21:09.170Z sshd[1711235]: Connection from 10.100.40.16 port 58232
#   2025-02-19T18:15:33.891Z shell[1711193]: [root]: cd /scratch/
#   2025-02-19T18:16:55.911Z envoy-access[525191]: GET /screen?id=... HTTP/2 200 ...
TS_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
)
COMP_RE = re.compile(
    r"(?P<comp>[A-Za-z0-9_.\-]+)\[(?P<pid>\d+)\]:\s*(?P<msg>.*)"
)
# vmkernel style: "2025-..Z cpu12:2097152)WARNING: ..." or "vmkernel: ..."
VMK_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
                    r"(?:(?P<cpu>cpu\d+:\d+)\))?(?P<msg>.*)")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"(?:user|for|as)\s+'?([A-Za-z0-9_][A-Za-z0-9_.\-\\]*)'?", re.I)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "INFO": 0}

# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
# Each: (family_regex_or_None, compiled_regex, category, event, severity)
RULES = [
    # ---- Authentication ----
    (r"^auth$", re.compile(r"Invalid user .* from ", re.I),
     "Authentication", "SSH invalid user", "MEDIUM"),
    (r"^auth$", re.compile(r"Failed password|authentication failure", re.I),
     "Authentication", "SSH auth failure", "MEDIUM"),
    (r"^auth$", re.compile(r"Connection from ", re.I),
     "Authentication", "SSH incoming connection", "LOW"),
    (r"^auth$", re.compile(r"Accepted (password|keyboard-interactive|publickey)", re.I),
     "Authentication", "SSH logon accepted", "MEDIUM"),
    (r"^auth$", re.compile(r"Accepted .* for root from ", re.I),
     "Authentication", "SSH logon as root", "HIGH"),
    (r"^auth$", re.compile(r"^sshd.*: Accepted .* for ([A-Za-z0-9_]+) from (\S+)", re.I),
     "Authentication", "SSH logon", "MEDIUM"),
    (r"^(hostd|vobd|syslog)$", re.compile(r"SSH session was opened for '(?P<u>[^'@]+)@?", re.I),
     "Authentication", "SSH session opened", "HIGH"),
    (r"^(hostd|vobd|syslog)$", re.compile(r"SSH session was closed for '(?P<u>[^'@]+)@?", re.I),
     "Authentication", "SSH session closed", "LOW"),
    (r"^hostd$", re.compile(r"User (?P<u>[^@\s]+)@\S+ logged in as (?!$)", re.I),
     "Authentication", "WebUI logon", "MEDIUM"),
    (r"^(hostd|vobd|syslog)$", re.compile(r"Authentication of user (?P<u>\S+) has", re.I),
     "Authentication", "Authentication event", "MEDIUM"),
    (r"^(hostd|vobd|syslog)$", re.compile(r"Login password for user (?P<u>\S+)", re.I),
     "Authentication", "Password changed", "HIGH"),

    # ---- Execution / shell ----
    (r"^shell$", re.compile(r"\[(?P<u>[A-Za-z0-9_.\-]+)\]:\s*(?P<cmd>.+)$"),
     "Execution", "Shell command", "MEDIUM"),
    (r"^shell$", re.compile(r"Interactive shell session started", re.I),
     "Execution", "Interactive shell started", "MEDIUM"),
    (r"^esxcli$", re.compile(r".+"),
     "Execution", "esxcli invocation", "MEDIUM"),
    (r"^rhttpproxy$", re.compile(r"New proxy client", re.I),
     "Execution", "rhttpproxy remote client", "LOW"),
    (r"^syslog$", re.compile(r"sftp-server\[.*\]:\s*(?P<act>open|close|opendir)\s+\"(?P<path>[^\"]+)\"",
     re.I),
     "Execution", "SFTP file activity", "MEDIUM"),
    (r"^vmkernel$", re.compile(r"sh: exec denied", re.I),
     "Execution", "Execution denied", "HIGH"),
    (r"^hostd$", re.compile(r"Execution of unknown \(non VIB installed\) binary.*prevented", re.I),
     "Execution", "Unsigned binary execution prevented", "HIGH"),

    # ---- Integrity / configuration change ----
    (r"^(hostd|vobd|syslog|vmkernel)$", re.compile(r"SSH access has been enabled", re.I),
     "Configuration", "SSH enabled", "HIGH"),
    (r"^(hostd|vobd|syslog|vmkernel)$", re.compile(r"SSH access has been disabled", re.I),
     "Configuration", "SSH disabled", "MEDIUM"),
    (r"^hostd$", re.compile(r"[Hh]ost acceptance level changed", re.I),
     "Integrity", "VIB acceptance level changed", "HIGH"),
    (r"^hostd$", re.compile(r"updateAcceptanceLevel", re.I),
     "Integrity", "VIB acceptance level changed", "HIGH"),
    (r"^hostd$", re.compile(r"Account (?P<u>\S+) was created on host", re.I),
     "Persistence", "Local account created", "HIGH"),
    (r"^hostd$", re.compile(r"Account (?P<u>\S+) was removed on host", re.I),
     "Persistence", "Local account removed", "MEDIUM"),
    (r"^hostd$", re.compile(r"The ESXi command line shell has been (enabled|disabled)", re.I),
     "Configuration", "ESXi shell toggled", "HIGH"),
    (r"^hostd$", re.compile(r"Administrator access to the host has been (enabled|disabled)", re.I),
     "Configuration", "Admin access toggled", "HIGH"),

    # ---- Ransomware / destructive ----
    (r"^(hostd|syslog|shell|vmkernel)$",
     re.compile(r"\.(esxiargs|babyk|royal|blackbasta|akira|blackcat|alphv|encrypted|locked|crypted|enc|crypt|siege)\b", re.I),
     "Ransomware", "Ransomware extension referenced", "CRITICAL"),
    (r".", re.compile(r"HOW_TO_(RESTORE|DECRYPT)", re.I),
     "Ransomware", "Ransom note referenced", "CRITICAL"),
    (r"^(hostd|shell|syslog|esxcli)$",
     re.compile(r"\b(encrypt\.sh|ksmd|autobackup\.bin)\b", re.I),
     "Ransomware", "Known ESXi ransomware artifact", "CRITICAL"),
    (r"^hostd$", re.compile(r"file delete.*\.vmdk|Deletion of file or directory.*\.vmdk", re.I),
     "Ransomware", "VMDK deletion", "CRITICAL"),

    # ---- VM escape / CVE indicators ----
    (r"^vmkernel$", re.compile(r"\b(slp|slpd|openslp)\b|port\.427", re.I),
     "CVE", "OpenSLP activity (CVE-2019-5544/2020-3992)", "HIGH"),
    (r"^vmkernel$", re.compile(r"(cdrom|cd-rom|ide).*(error|overflow)", re.I),
     "CVE", "CD-ROM emulation error (CVE-2021-22045)", "MEDIUM"),
    (r"^vmkernel$", re.compile(r"(vmci|vsock).*(error)|heap.overflow|memory.corruption", re.I),
     "CVE", "VMCI/vSock corruption (CVE-2022-31696)", "HIGH"),
    (r"^hostd$", re.compile(r"Guest.*Operation.*Failed|GuestOperation|vmtoolsd.*error", re.I),
     "CVE", "VMware Tools guest ops (CVE-2023-20867)", "MEDIUM"),
    (r"^vmkernel$", re.compile(r"(uhci|xhci|usb).*(error|overflow|corrupt)|vmx.*usb.*exception", re.I),
     "CVE", "USB controller error (CVE-2024-22252/3/4)", "HIGH"),
]

# File-system indicators scanned when a datastore / extracted tree is present.
RANSOM_EXT = {".esxiargs", ".babyk", ".royal", ".blackbasta", ".akira", ".blackcat",
              ".alphv", ".encrypted", ".locked", ".crypted", ".enc", ".crypt", ".siege"}
RANSOM_NOTES = re.compile(r"(HOW_TO_RESTORE|HOW_TO_DECRYPT|README_TO_RESTORE|RECOVER|"
                          r"DECRYPT|!README!|ransom|restore_files|unlock).*\.txt$", re.I)
SUSPICIOUS_SCRIPTS = re.compile(r"(encrypt\.sh|ksmd|tools|update|autobackup\.bin)$", re.I)
PERSIST_SCRIPT = "vmware_local.sh"


def norm_dir_name(family, name):
    """Map a log filename (with rotation/.gz) to its family key."""
    base = name
    for suffix in (".gz",):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
    base = re.sub(r"\.\d+$", "", base)          # hostd.log.1
    base = re.sub(r"-\d{8}$", "", base)          # hostd-20250101
    if base.endswith(".log"):
        base = base[:-4]
    base = base.lower()
    # Strip bundle-side directory components.
    base = base.rsplit("/", 1)[-1]
    return base


def extract_input(path, tmpdir):
    """Return a directory containing the extracted/copied logs."""
    if os.path.isdir(path):
        return path
    dest = os.path.join(tmpdir, os.path.basename(path) + ".d")
    os.makedirs(dest, exist_ok=True)
    lower = path.lower()
    if lower.endswith((".tgz", ".tar.gz", ".tar")):
        with tarfile.open(path, "r:*") as tf:
            tf.extractall(dest)
    elif lower.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            zf.extractall(dest)
    elif lower.endswith(".gz"):
        out = os.path.join(dest, os.path.basename(path)[:-3])
        with gzip.open(path, "rb") as fin, open(out, "wb") as fout:
            fout.write(fin.read())
        return dest
    elif lower.endswith(".log"):
        with open(path, "rb") as fin, open(os.path.join(dest, os.path.basename(path)), "wb") as fout:
            fout.write(fin.read())
    else:
        raise ValueError(f"unsupported input: {path}")
    return dest


def parse_line(line):
    ts = ""
    m = TS_RE.match(line)
    if m:
        ts = m.group("ts")
    comp = ""
    pid = ""
    msg = line.strip()
    cm = COMP_RE.search(line)
    if cm:
        comp = cm.group("comp")
        pid = cm.group("pid")
        msg = cm.group("msg")
    else:
        vm = VMK_RE.match(line)
        if vm and vm.group("msg"):
            msg = vm.group("msg")
    return ts, comp, pid, msg


def find_logs(root):
    """Yield (family, fullpath) for every ESXi log file under root."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            fam = norm_dir_name(family="", name=name)
            if not fam:
                continue
            yield fam, os.path.join(dirpath, name)


def hunt(root, min_sev):
    timeline = []
    findings = []
    for family, fpath in find_logs(root):
        opener = gzip.open if fpath.endswith(".gz") else open
        try:
            fh = opener(fpath, "rt", encoding="utf-8", errors="replace")
        except Exception:
            continue
        with fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line:
                    continue
                ts, comp, pid, msg = parse_line(line)
                compkey = (comp or family).lower()
                matched = []
                for fam_re, rx, category, event, sev in RULES:
                    if family and not re.match(fam_re, family):
                        continue
                    m = rx.search(msg)
                    if not m:
                        continue
                    if SEVERITY_ORDER[sev] < SEVERITY_ORDER[min_sev]:
                        continue
                    user = ""
                    src_ip = ""
                    gi = m.groupdict() or {}
                    if gi.get("u"):
                        user = gi["u"]
                    ipm = IP_RE.search(msg)
                    if ipm:
                        src_ip = ipm.group(1)
                    matched.append({"severity": sev, "category": category,
                                    "event": event, "user": user, "src_ip": src_ip})
                if not matched:
                    continue
                rel = os.path.relpath(fpath, root)
                # Findings: keep every distinct match (a line can be both a
                # shell command and a ransomware indicator).
                seen = set()
                for mm in matched:
                    key = (mm["event"], mm["category"])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "severity": mm["severity"], "category": mm["category"],
                        "event": mm["event"], "time_utc": ts, "source_log": rel,
                        "line_no": lineno, "user": mm["user"],
                        "src_ip": mm["src_ip"], "detail": msg[:500],
                    })
                # Timeline: one row per line, using the highest-severity match.
                best = max(matched, key=lambda x: SEVERITY_ORDER[x["severity"]])
                timeline.append({
                    "time_utc": ts, "source_log": rel, "line_no": lineno,
                    "component": compkey, "severity": best["severity"],
                    "category": best["category"], "event": best["event"],
                    "user": best["user"], "src_ip": best["src_ip"],
                    "detail": msg[:500], "raw": line[:1000],
                })
    return timeline, findings


def scan_files(root, datastore):
    """File-system ransomware / persistence indicators."""
    findings = []
    roots = [r for r in ([datastore] if datastore else []) if r]
    for base in [root] + roots:
        for dirpath, _dirs, files in os.walk(base):
            for name in files:
                low = name.lower()
                ext = os.path.splitext(low)[1]
                full = os.path.join(dirpath, name)
                if ext in RANSOM_EXT:
                    findings.append({"severity": "CRITICAL", "category": "Ransomware",
                                     "event": "Encrypted file extension", "detail": full})
                if RANSOM_NOTES.search(low):
                    findings.append({"severity": "CRITICAL", "category": "Ransomware",
                                     "event": "Ransom note file", "detail": full})
                if SUSPICIOUS_SCRIPTS.search(low):
                    findings.append({"severity": "HIGH", "category": "Ransomware",
                                     "event": "Suspicious script/binary", "detail": full})
                if low == PERSIST_SCRIPT and "rc.local.d" in dirpath.replace("\\", "/"):
                    findings.append({"severity": "HIGH", "category": "Persistence",
                                     "event": "Malicious VIB startup script", "detail": full})
    return findings


ESXI_ARTIFACTS = {
    "ESXiHostAgentLog": ["hostd.log"],
    "ESXiSystemMessageslog": ["syslog.log"],
    "ESXiShellLog": ["shell.log"],
    "ESXiAuthenticationLog": ["auth.log"],
    "ESXiVMKernelLog": ["vmkernel.log"],
    "ESXiVMKernelSummaryLog": ["vmksummarylog.log"],
    "ESXiVMKernelWarningsLog": ["vmkwarning.log"],
    "ESXiQuickBootLog": ["loadESX.log"],
    "vCenterServerAgentLog": ["vxpa.log"],
    "ESXiSystemLogsDirectory": ["vobd.log", "esxcli.log", "rhttpproxy.log", "vmauthd.log"],
    "ESXApiForwarder": ["esxapiadapter.log"],
    "ESXiAttestationService": ["attestd.log"],
    "ESXiKeyProviderService": ["kmxd.log"],
    "ESXTokenService": ["esxtokend.log"],
    "ESXiTrustedInfrastructureAgentLog": ["kmxa.log"],
}


def coverage(root):
    present = set()
    for _fam, fpath in find_logs(root):
        present.add(os.path.basename(fpath).lower())
    out = {}
    for art, files in ESXI_ARTIFACTS.items():
        out[art] = any(f.lower() in present for f in files)
    return out


def run_av(paths, outdir, enabled):
    if not enabled:
        return None
    helper = "/data/tools/av_triage.py"
    if not os.path.exists(helper):
        helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "av_triage.py")
    if not os.path.exists(helper):
        return None
    import subprocess
    js = os.path.join(outdir, "av_hits.json")
    cmd = [sys.executable, helper, "--clamav", "--json", js, "--max-size", "67108864"] + paths
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return {"exit": proc.returncode, "json": js,
                "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:]}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="esxi_out", help="output directory")
    ap.add_argument("--datastore", default=None,
                    help="datastore directory to scan for ransomware/persistence files")
    ap.add_argument("--no-av", action="store_true", help="skip YARA/ClamAV handoff")
    ap.add_argument("--min-severity", default="LOW",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    timeline, findings = [], []
    cov_agg = {a: False for a in ESXI_ARTIFACTS}
    with tempfile.TemporaryDirectory() as tmp:
        for inp in args.inputs:
            try:
                root = extract_input(inp, tmp)
            except Exception as e:  # noqa: BLE001
                print(f"[esxi_triage] cannot read {inp}: {e}", file=sys.stderr)
                continue
            t, f = hunt(root, args.min_severity)
            timeline += t
            findings += f
            findings += scan_files(root, args.datastore)
            cov = coverage(root)
            for k, v in cov.items():
                cov_agg[k] = cov_agg[k] or v
            av = run_av([root] + ([args.datastore] if args.datastore else []),
                        args.out, not args.no_av)
    with open(os.path.join(args.out, "coverage.json"), "w") as cf:
        json.dump(cov_agg, cf, indent=2)

    timeline.sort(key=lambda r: (r["time_utc"], r["source_log"], r["line_no"]))
    tpath = os.path.join(args.out, "timeline.csv")
    cols = ["time_utc", "source_log", "line_no", "component", "severity",
            "category", "event", "user", "src_ip", "detail", "raw"]
    with open(tpath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in timeline:
            w.writerow(r)

    findings.sort(key=lambda x: -SEVERITY_ORDER[x["severity"]])
    with open(os.path.join(args.out, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    counts = {}
    for r in findings:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    with open(os.path.join(args.out, "summary.txt"), "w", encoding="utf-8") as f:
        f.write("ESXi triage summary\n===================\n")
        f.write(f"timeline events : {len(timeline)}\n")
        f.write(f"findings        : {len(findings)}\n")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts.get(sev):
                f.write(f"  {sev:8s}: {counts[sev]}\n")
        f.write("\nTop findings:\n")
        for r in findings[:50]:
            f.write(f"  [{r['severity']:8s}] {r['category']}: {r['event']} "
                    f"({r.get('source_log','')}"
                    f"{':' + str(r['line_no']) if r.get('line_no') else ''}) "
                    f"{r.get('detail','')[:160]}\n")
    if av:
        with open(os.path.join(args.out, "av_result.json"), "w") as af:
            json.dump(av, af, indent=2)

    print(f"[esxi_triage] {len(timeline)} timeline rows, {len(findings)} findings -> {args.out}",
          file=sys.stderr)
    top = max((SEVERITY_ORDER[r["severity"]] for r in findings), default=0)
    return 1 if top >= SEVERITY_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
