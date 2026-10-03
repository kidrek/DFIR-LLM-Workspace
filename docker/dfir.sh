#!/usr/bin/env bash
# dfir.sh -- run forensic tools in the DFIR container with strict, read-only
# evidence handling.
#
# Discipline enforced here:
#   * evidences/  mounted READ-ONLY at /data/evidences
#   * analysis/   mounted read-write at /data/analysis  (also /data/out)
#   * reports/    mounted read-write at /data/reports
#   * notes/      mounted read-write at /data/notes
#   * container is ephemeral (--rm) and runs as the calling uid:gid
#   * no network by default (--network none); pass --net to enable
#
# Usage:
#   docker/dfir.sh [--net] [--image IMG] [--shell] <command> [args...]
#
# Examples:
#   docker/dfir.sh evtx_dump_rs /data/evidences/<HOST>/C/Windows/System32/winevt/Logs/Security.evtx
#   docker/dfir.sh MFTECmd -f '/data/evidences/<HOST>/C/$MFT' --csv /data/analysis/mft/
#   docker/dfir.sh tshark -r /data/evidences/traffic.pcapng -Y 'tcp.port==445'
#   docker/dfir.sh --shell          # interactive bash in the image
set -euo pipefail

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DFIR_IMAGE:-dfir-toolkit}"
NETWORK="none"
USE_SHELL=0

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --net)   NETWORK="bridge"; shift ;;
    --image) IMAGE="$2"; shift 2 ;;
    --shell) USE_SHELL=1; shift ;;
    --)      shift; POSITIONAL+=("$@"); break ;;
    *)       POSITIONAL+=("$1"); shift ;;
  esac
done

# Ensure output dirs exist and are owned by the caller
mkdir -p "$WS/analysis" "$WS/reports" "$WS/notes"

TTY_ARGS=()
if [[ -t 0 && -t 1 ]]; then TTY_ARGS=(-it); fi

if [[ "$USE_SHELL" -eq 1 ]]; then
  set -- /bin/bash
else
  set -- "${POSITIONAL[@]}"
fi

exec docker run --rm "${TTY_ARGS[@]}" \
  --network "$NETWORK" \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$WS/evidences:/data/evidences:ro" \
  -v "$WS/docker:/data/tools:ro" \
  -v "$WS/analysis:/data/analysis:rw" \
  -v "$WS/reports:/data/reports:rw" \
  -v "$WS/notes:/data/notes:rw" \
  -w /data \
  "$IMAGE" "$@"
