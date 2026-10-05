#!/usr/bin/env bash
# build_dashboard.sh -- assemble the full incident_dashboard.py invocation so a
# step is never silently omitted (the empty "Process trees" panel came from a
# generation that forgot --proc).
#
# It discovers the standard artifacts under analysis/ and reports/, passes one
# --proc per Security.tsv, and runs the dashboard inside the DFIR container via
# docker/dfir.sh. Any extra arguments are forwarded verbatim.
#
# Usage:
#   docker/build_dashboard.sh [--title "Case name"] [--strict] [extra args...]
#
# Environment overrides (host paths):
#   DFIR_TITLE        dashboard title (default: from iocs.json "case")
#   DFIR_EXTRA        extra args appended to the incident_dashboard invocation
#
# Examples:
#   docker/build_dashboard.sh
#   docker/build_dashboard.sh --title "ACME intrusion" --strict
set -euo pipefail

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TITLE=""
STRICT=0
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --title)  TITLE="$2"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    *)        EXTRA+=("$1"); shift ;;
  esac
done

# ---- required input: IOC JSON ----------------------------------------------
IOCS_HOST="$WS/analysis/iocs.json"
if [[ ! -f "$IOCS_HOST" ]]; then
  echo "ERROR: $IOCS_HOST not found (run IOC collection first)." >&2
  exit 1
fi

# default title from the case field
if [[ -z "$TITLE" ]]; then
  TITLE="$(grep -m1 -oE '"case"[[:space:]]*:[[:space:]]*"[^"]*"' "$IOCS_HOST" 2>/dev/null \
           | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/' || true)"
  [[ -n "$TITLE" ]] || TITLE="Incident"
fi

# ---- optional inputs (host path -> container path) --------------------------
args=(--iocs /data/analysis/iocs.json --out /data/reports --title "$TITLE")

add_if() {  # add_if <host-path> <flag>
  [[ -f "$1" ]] && args+=("$2" "/data/${1#"$WS"/}")
}

# timeline: prefer the curated viz timeline, fall back to the full one
if [[ -f "$WS/reports/viz/timeline.csv" ]]; then
  args+=(--timeline /data/reports/viz/timeline.csv)
elif [[ -f "$WS/analysis/timeline.csv" ]]; then
  args+=(--timeline /data/analysis/timeline.csv)
fi
add_if "$WS/analysis/attack_timeline.csv" --attack-timeline
add_if "$WS/analysis/ip_map.json"        --ip-map
add_if "$WS/reports/incident_report.md"  --report-md

[[ -d "$WS/analysis/network/zeek" ]] && args+=(--zeek /data/analysis/network/zeek)

# ---- process trees: one --proc per discovered Security.tsv ------------------
shopt -s nullglob
proc_found=0
for tsv in "$WS"/analysis/*/evtx/tsv/Security.tsv "$WS"/analysis/*/evtx/Security.tsv; do
  [[ -f "$tsv" ]] || continue
  args+=(--proc "/data/${tsv#"$WS"/}")
  proc_found=$((proc_found + 1))
done
shopt -u nullglob

# Linux snapshots, when present
for pt in "$WS"/analysis/*/proctree/proctree.json; do
  [[ -f "$pt" ]] || continue
  args+=(--proc-linux "/data/${pt#"$WS"/}")
done

if [[ "$proc_found" -eq 0 ]]; then
  echo "WARNING: no analysis/*/evtx/tsv/Security.tsv found -- the Process-trees" >&2
  echo "         panel will be empty (pass --proc or run the EVTX flatten step)." >&2
fi

[[ "$STRICT" -eq 1 ]] && args+=(--strict)
args+=("${EXTRA[@]}")

echo "[build_dashboard] ${proc_found} process source(s); title='${TITLE}'" >&2
exec "$WS/docker/dfir.sh" python3 /data/tools/incident_dashboard.py "${args[@]}"
