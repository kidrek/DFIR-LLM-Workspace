#!/usr/bin/env bash
# reset_case.sh -- reset this DFIR workspace for a new case.
#
# Removes case-specific content (evidence, derived analysis, reports, scratch)
# while preserving the reusable template (docker/, skills/, .opencode/, docs,
# and every .gitkeep). This deliberately overrides the workspace rule "do not
# delete evidence" -- it is a TEMPLATE RESET, not analysis. Never run it on a
# live case mid-investigation: archive any evidence you still need first.
#
# Safe by default: with no arguments it only prints what WOULD be removed.
# Nothing is deleted until --yes is passed.
#
# Usage:
#   ./reset_case.sh                 # dry-run (show what would be removed)
#   ./reset_case.sh --yes           # perform the reset
#   ./reset_case.sh --yes --keep-evidence
#   ./reset_case.sh --yes --scrub-refs
#   ./reset_case.sh --yes --reset-git
#
# Flags:
#   --yes            actually perform the reset (required to delete anything)
#   --keep-evidence  keep evidences/ intact; reset only analysis/reports/notes
#   --scrub-refs     genericize leftover case examples in reusable files
#   --reset-git      rm -rf .git && git init (off by default)
#   -h, --help       show this help
set -euo pipefail

# ---- locate workspace root --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$SCRIPT_DIR"

# ---- options ----------------------------------------------------------------
DO_IT=0
KEEP_EVIDENCE=0
SCRUB_REFS=0
RESET_GIT=0

usage() {
  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)           DO_IT=1; shift ;;
    --keep-evidence) KEEP_EVIDENCE=1; shift ;;
    --scrub-refs)    SCRUB_REFS=1; shift ;;
    --reset-git)     RESET_GIT=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- guard: confirm this is a DFIR workspace --------------------------------
if [[ ! -f "$WS/docker/dfir.sh" || ! -f "$WS/CLAUDE.md" ]]; then
  echo "ERROR: $WS does not look like a DFIR workspace" >&2
  echo "       (expected docker/dfir.sh and CLAUDE.md). Refusing to run." >&2
  exit 1
fi

# ---- what gets cleaned ------------------------------------------------------
# Directory -> whether to clean it under the current flags.
DIRS=()
[[ "$KEEP_EVIDENCE" -eq 0 ]] && DIRS+=("evidences")
DIRS+=("analysis" "reports" "notes")

# ---- detect the case name (best effort, for reporting) ----------------------
detect_case() {
  local iocs="$WS/analysis/iocs.json"
  if [[ -f "$iocs" ]]; then
    local c
    c="$(grep -m1 -oE '"case"[[:space:]]*:[[:space:]]*"[^"]*"' "$iocs" 2>/dev/null \
         | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/' || true)"
    [[ -n "$c" ]] && { echo "$c"; return; }
  fi
  local rpt
  for rpt in "$WS"/reports/*.md; do
    [[ -f "$rpt" ]] || continue
    local t
    t="$(head -1 "$rpt" | sed -nE 's/^#[[:space:]]*//p')"
    [[ -n "$t" ]] && { echo "$t"; return; }
  done
  echo "(unknown)"
}

CASE_NAME="$(detect_case)"

# ---- enumerate items to remove (files/dirs directly under each dir) ---------
mapfile -t ITEMS < <(
  for d in "${DIRS[@]}"; do
    [[ -d "$WS/$d" ]] || continue
    find "$WS/$d" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -printf '%p\n' | sort
  done
)

echo "DFIR workspace reset"
echo "  workspace : $WS"
echo "  case      : $CASE_NAME"
echo "  mode      : $([[ "$DO_IT" -eq 1 ]] && echo 'APPLY' || echo 'DRY-RUN (pass --yes to apply)')"
echo "  evidence  : $([[ "$KEEP_EVIDENCE" -eq 1 ]] && echo 'KEEP' || echo 'remove')"
echo "  scrub refs: $([[ "$SCRUB_REFS" -eq 1 ]] && echo 'yes' || echo 'no')"
echo "  reset git : $([[ "$RESET_GIT" -eq 1 ]] && echo 'yes' || echo 'no')"
echo

if [[ "${#ITEMS[@]}" -eq 0 ]]; then
  echo "Nothing to remove -- already clean."
else
  echo "Would remove (${#ITEMS[@]} top-level item(s), recursing):"
  for it in "${ITEMS[@]}"; do
    if [[ -d "$it" ]]; then
      n="$(find "$it" -mindepth 1 | wc -l | tr -d ' ')"
      echo "  [dir ] $it  ($n entries)"
    else
      echo "  [file] $it"
    fi
  done
fi

echo
echo "Preserved: docker/, skills/, .opencode/, opencode.jsonc,"
echo "           AGENTS.md, CLAUDE.md, README.md, reset_case.sh, .gitignore,"
echo "           and every .gitkeep."

# ---- apply ------------------------------------------------------------------
if [[ "$DO_IT" -eq 0 ]]; then
  echo
  echo "DRY-RUN complete. Re-run with --yes to apply."
  exit 0
fi

echo
echo "Removing..."
for it in "${ITEMS[@]}"; do
  rm -rf -- "$it"
done

# ---- optional: reset git history -------------------------------------------
if [[ "$RESET_GIT" -eq 1 ]]; then
  echo "Resetting git history (rm -rf .git && git init)..."
  rm -rf "$WS/.git"
  ( cd "$WS" && git init -q )
fi

# ---- optional: scrub leftover case references ------------------------------
if [[ "$SCRUB_REFS" -eq 1 ]]; then
  echo "Scrubbing leftover case references from reusable files..."
  # The tools themselves hold no case data; only the docstrings/reference
  # examples may carry it, so genericize those samples.
  for f in "$WS/docker/ioc_export.py" "$WS/docker/incident_viz.py" \
           "$WS/docker/incident_dashboard.py" "$WS/docker/linux_proctree.py" \
           "$WS/docker/evtx_query.py" "$WS/docker/mft_query.py" \
           "$WS/docker/pcap_objects.py" \
           "$WS/skills/dfir/SKILL.md" \
           "$WS"/skills/dfir/examples/*.json; do
    [[ -f "$f" ]] || continue
    sed -i \
      -e 's#SaSync / shanocorp\.htb#ACME / example.local#g' \
      -e 's#SaSync#ACME#g' \
      -e 's#dbc?-test\.shanocorp\.htb#example.local#g' \
      -e 's#shanocorp\.htb#example.local#g' \
      -e 's#192\[\.\]168\[\.\]186\[\.\]135#10[.]0[.]0[.]5#g' \
      -e 's#192\.168\.186\.135#10.0.0.5#g' \
      "$f"
    echo "  scrubbed $(realpath --relative-to="$WS" "$f")"
  done
fi

# ---- post-run: verify reusable tree + scan for residual case refs ----------
echo
echo "Reusable tree intact:"
for p in docker skills .opencode opencode.jsonc AGENTS.md CLAUDE.md README.md .gitignore; do
  if [[ -e "$WS/$p" ]]; then echo "  ok  $p"; else echo "  MISSING  $p" >&2; fi
done

echo
echo "Residual case-reference scan (docker/, skills/, .opencode/, docs):"
# Only scan AFTER cleaning; pre-existing examples may remain unless --scrub-refs.
FOUND="$(grep -rniE 'SaSync|shanocorp\.htb|192\.168\.186\.135|192\[\.\]168\[\.\]186\[\.\]135' \
  "$WS/docker" "$WS/skills" "$WS/.opencode" \
  "$WS/README.md" "$WS/CLAUDE.md" "$WS/AGENTS.md" 2>/dev/null || true)"
if [[ -n "$FOUND" ]]; then
  echo "  NOTE: the following case references remain in reusable files:"
  echo "$FOUND" | sed 's/^/    /'
  [[ "$SCRUB_REFS" -eq 0 ]] && echo "  (re-run with --scrub-refs to genericize known examples)"
else
  echo "  none"
fi

# ---- reset scratch gitkeep ownership / dirs exist --------------------------
for d in evidences analysis reports notes; do
  mkdir -p "$WS/$d"
done

echo
echo "Done. Drop new evidence into evidences/ and start the new case."
