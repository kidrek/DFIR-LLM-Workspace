#!/usr/bin/env bash
# selftest.sh -- run the reusable toolkit's self-tests inside the DFIR container.
#
# Case-free: exercises only the synthetic fixtures under docker/tests/fixtures,
# so it never touches evidences/. Use it as a gate after changing a helper:
#
#     ./docker/selftest.sh
#
# Wraps docker/dfir.sh (read-only evidence, ephemeral, non-root, no network).
set -euo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$WS/docker/dfir.sh" python3 /data/tools/tests/run_selftest.py "$@"
