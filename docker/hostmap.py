#!/usr/bin/env python3
"""hostmap.py -- generic host-label normalisation shared by the timeline and
visualisation helpers (``merge_timeline.py``, ``incident_viz.py``,
``incident_dashboard.py``).

Case-free: **no host name or IP is baked in.** A per-case mapping
(IP / FQDN / short-name -> display name) is supplied as JSON -- typically the
``endpoints`` block of ``analysis/iocs.json``, optionally with an ``aliases``
list per endpoint::

    {"endpoints": {
        "10.0.0.30": {"name": "FILESRV", "role": "file-server", "order": 3,
                      "aliases": ["filesrv", "filesrv.corp.example"]}}}

A plain ``{"<key>": "<name>"}`` mapping is also accepted.

``norm_host`` never truncates a literal IP address (the historical
``v.split(".")[0]`` bug collapsed every IPv4 to its first octet) and buckets
link-local / multicast / broadcast / loopback noise under ``Network``.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re

NETWORK_BUCKET = "Network"

_FQDN_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _endpoint_name(meta) -> str:
    """Extract a display name from an endpoint value.

    Accepts a plain string (``{"key": "NAME"}``) or an object
    (``{"key": {"name": "NAME", ...}}``). Returns the name only -- never the
    ``repr`` of a dict, which is how an earlier version produced labels like
    ``"{'name': 'Attacker', ...}"`` instead of ``Attacker``.
    """
    if isinstance(meta, dict):
        return str(meta.get("name") or meta.get("host") or "")
    return str(meta) if meta not in (None, "") else ""


def _aliases_of(meta) -> list[str]:
    """Return the optional ``aliases`` list from an endpoint object."""
    if isinstance(meta, dict):
        return [str(a) for a in (meta.get("aliases") or []) if str(a)]
    return []


def load_map(path: str) -> dict[str, str]:
    """Load a host map from JSON.

    Accepts either an ``endpoints`` inventory (with optional ``aliases``) or a
    flat ``{"key": "name"}`` object. Keys may be IPs, FQDNs or short names;
    lookups are case-insensitive for non-IP keys.

    Both the documented ``{"endpoints": {...}}`` form and the legacy flat
    ``{"key": {"name": "NAME", "aliases": [...]}}`` form are accepted, so a
    case file written either way resolves to real display names rather than the
    stringified dict.
    """
    if not path or not os.path.isfile(path):
        return {}
    try:
        d = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: dict[str, str] = {}
    if isinstance(d, dict) and isinstance(d.get("endpoints"), dict):
        src = d["endpoints"]
    elif isinstance(d, dict):
        src = d
    else:
        return out
    for key, meta in src.items():
        name = _endpoint_name(meta) or str(key)
        out[str(key)] = name
        for a in _aliases_of(meta):
            out[a] = name
    return out


def parse_ip(value: str):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def is_noise(value: str) -> bool:
    """True for addresses that are not real endpoints (link-local, multicast,
    broadcast, loopback, unspecified)."""
    ip = parse_ip(value)
    if ip is None:
        return False
    if ip.is_multicast or ip.is_loopback or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and str(ip).endswith(".255"):
        return True
    return False


def norm_host(value: str, hostmap: dict[str, str] | None = None) -> str:
    """Normalise a host label to a short display name.

    Resolution order:
      1. literal IP -> ``hostmap`` lookup; noise -> ``Network``; else the IP
         itself (never truncated);
      2. exact (case-insensitive) ``hostmap`` key match on the raw value;
      3. FQDN -> first label, then another ``hostmap`` match;
      4. the value unchanged (or ``Unknown`` if empty).
    """
    v = (value or "").strip()
    if not v:
        return "Unknown"
    hm = hostmap or {}

    ip = parse_ip(v)
    if ip is not None:
        if is_noise(v):
            return NETWORK_BUCKET
        return hm.get(v, v)  # exact IP key, else the address as-is

    if v in hm:
        return hm[v]
    low = {k.lower(): val for k, val in hm.items()}
    if v.lower() in low:
        return low[v.lower()]

    if _FQDN_RE.match(v):
        short = v.split(".")[0]
        return hm.get(short, low.get(short.lower(), short))

    return hm.get(v, low.get(v.lower(), v))


def load_map_from_obj(d) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(d, dict) and isinstance(d.get("endpoints"), dict):
        src = d["endpoints"]
    elif isinstance(d, dict):
        src = d
    else:
        return out
    for key, meta in src.items():
        name = _endpoint_name(meta) or str(key)
        out[str(key)] = name
        for a in _aliases_of(meta):
            out[a] = name
    return out
