#!/usr/bin/env python3
"""dfir_signatures.py -- optional, case-specific detection signatures loader.

Part of the container-only DFIR workspace.

The reusable toolkit contains **no case-specific patterns**. Well-known public
tooling (``mimikatz``, ``psexec``, ``certutil``, ``nc.exe`` ...) stays in the
scripts as generic rules. Anything derived from a particular engagement --

  * random binary names seen in one incident,
  * responder/collection tools specific to one case,
  * attacker/responder actor keywords,

belongs in an **optional** ``signatures.json`` that the analyst creates per case.
It is loaded only when present; when it is absent the tools behave exactly as
before, with the generic rules only.

Convention / lifecycle
----------------------
The file normally lives at ``analysis/signatures.json`` inside the workspace.
``analysis/`` is wiped by ``reset_case.sh``, so the signatures do **not** survive
into the next case -- which is the point: no example data is ever reused.

Schema (all keys optional)::

    {
      "windows_process_patterns": ["<regex fragment>", ...],
      "linux_process_patterns":   ["<regex fragment>", ...],
      "actor_keywords": {"<role>": ["<keyword>", ...]}
    }

See ``skills/dfir/examples/signatures.example.json`` for a documented example.
Neither this module nor any tool reads that example automatically.
"""
from __future__ import annotations

import json
import os

# Neutral defaults -- no case data. Extra patterns come from the analyst's file.
DEFAULTS = {
    "windows_process_patterns": [],
    "linux_process_patterns": [],
    "actor_keywords": {},
}

# Where the analyst file is looked for when --signatures is not given.
_CONVENTIONAL_PATHS = (
    "/data/analysis/signatures.json",
    os.path.join(os.environ.get("DFIR_ANALYSIS", ""), "signatures.json")
    if os.environ.get("DFIR_ANALYSIS") else "",
)


def conventional_path() -> str:
    """Return the first existing conventional signatures path, else ''."""
    for p in _CONVENTIONAL_PATHS:
        if p and os.path.isfile(p):
            return p
    return ""


def load_signatures(path: str = "") -> dict:
    """Load an optional signatures file, merged over the neutral defaults.

    An empty/absent file yields the defaults (generic rules only). Malformed
    input is ignored rather than aborting the analysis.
    """
    sig = dict(DEFAULTS)
    sig["windows_process_patterns"] = []
    sig["linux_process_patterns"] = []
    sig["actor_keywords"] = {}

    chosen = path or conventional_path()
    if not chosen:
        return sig
    try:
        with open(chosen, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return sig
    if not isinstance(data, dict):
        return sig

    for key in ("windows_process_patterns", "linux_process_patterns"):
        val = data.get(key)
        if isinstance(val, list):
            sig[key] = [str(x) for x in val if str(x).strip()]
    ak = data.get("actor_keywords")
    if isinstance(ak, dict):
        sig["actor_keywords"] = {
            str(role): [str(k) for k in (kws or []) if str(k).strip()]
            for role, kws in ak.items()
            if isinstance(kws, (list, tuple))
        }
    return sig


def compile_with(base, extra):
    """Return a compiled regex: ``base`` pattern extended with ``extra`` frags."""
    import re

    pat = base.pattern
    for frag in extra or []:
        frag = str(frag)
        if frag:
            pat = pat + "|" + frag
    return re.compile(pat, base.flags)
