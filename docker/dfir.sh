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
#   * hardened by default: all Linux capabilities dropped, no-new-privileges,
#     noexec/nosuid/nodev on /tmp, pids/memory/cpu limits
#
# Usage:
#   docker/dfir.sh [--net] [--image IMG] [--shell] [--privileged-cap] \
#                  [--no-hardening] <command> [args...]
#
# Flags:
#   --net             enable networking (bridge) instead of the default none
#   --image IMG       use IMG instead of $DFIR_IMAGE / dfir-toolkit
#   --shell           open an interactive bash shell in the image
#   --privileged-cap  add SYS_ADMIN + /dev/fuse + apparmor:unconfined, needed
#                     for the read-only VMFS/VMDK mounts (vmfs-fuse, qemu-nbd)
#   --no-hardening    disable the container hardening flags (last resort)
#
# Examples:
#   docker/dfir.sh evtx_dump_rs /data/evidences/<HOST>/C/Windows/System32/winevt/Logs/Security.evtx
#   docker/dfir.sh MFTECmd -f '/data/evidences/<HOST>/C/$MFT' --csv /data/analysis/mft/
#   docker/dfir.sh tshark -r /data/evidences/traffic.pcapng -Y 'tcp.port==445'
#   docker/dfir.sh --privileged-cap vmfs-fuse -o ro /data/evidences/ds /mnt/vmfs
#   docker/dfir.sh --shell          # interactive bash in the image
set -euo pipefail

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${DFIR_IMAGE:-dfir-toolkit}"
NETWORK="none"
USE_SHELL=0
HARDEN=1
PRIV_CAP=0
MEM="${DFIR_MEM:-4g}"
CPUS="${DFIR_CPUS:-4}"
TMP_SIZE="${DFIR_TMP_SIZE:-2g}"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --net)            NETWORK="bridge"; shift ;;
    --image)          IMAGE="$2"; shift 2 ;;
    --shell)          USE_SHELL=1; shift ;;
    --privileged-cap) PRIV_CAP=1; shift ;;
    --no-hardening)   HARDEN=0; shift ;;
    --)               shift; POSITIONAL+=("$@"); break ;;
    *)                POSITIONAL+=("$1"); shift ;;
  esac
done

# Ensure output dirs exist and are owned by the caller
mkdir -p "$WS/analysis" "$WS/reports" "$WS/notes"

TTY_ARGS=()
if [[ -t 0 && -t 1 ]]; then TTY_ARGS=(-it); fi

HARDEN_ARGS=(
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=${TMP_SIZE}
  --pids-limit=4096
  --memory "$MEM"
  --cpus "$CPUS"
)
# The tool mount is read-only; bind mounts do not support noexec, and the
# tools are our own trusted repo, so exec prevention is not needed there.
TOOLS_FLAGS="ro"

if [[ "$PRIV_CAP" -eq 1 ]]; then
  HARDEN_ARGS+=(--cap-add=SYS_ADMIN --device /dev/fuse
                --security-opt=apparmor:unconfined)
fi
if [[ "$HARDEN" -eq 0 ]]; then
  HARDEN_ARGS=()
fi

if [[ "$USE_SHELL" -eq 1 ]]; then
  set -- /bin/bash
else
  set -- "${POSITIONAL[@]}"
fi

exec docker run --rm "${TTY_ARGS[@]}" \
  --network "$NETWORK" \
  --user "$(id -u):$(id -g)" \
  "${HARDEN_ARGS[@]}" \
  -e HOME=/tmp \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e MPLCONFIGDIR=/tmp/matplotlib \
  -v "$WS/evidences:/data/evidences:ro" \
  -v "$WS/docker:/data/tools:${TOOLS_FLAGS}" \
  -v "$WS/analysis:/data/analysis:rw" \
  -v "$WS/analysis:/data/out:rw" \
  -v "$WS/reports:/data/reports:rw" \
  -v "$WS/notes:/data/notes:rw" \
  -w /data \
  "$IMAGE" "$@"
