#!/usr/bin/env python3
"""ioc_schema.py -- shared IOC schema: types, defanging, validation.

Part of the container-only DFIR workspace. One source of truth for the
``analysis/iocs.json`` schema so ``ioc_export.py``, ``ioc_collect.py`` and the
visualization helpers agree. Case-free: no host names, IPs or case strings.

Schema (see skills/dfir): an object with an optional ``endpoints`` map and an
``observables`` list; each observable requires ``type`` and ``value``.
"""
from __future__ import annotations

import ipaddress
import re

# Allowed observable types (skills/dfir IOC schema).
ALLOWED_TYPES = {
    "ipv4", "ipv6", "mac", "hostname", "port", "url", "file-path",
    "file-hash", "share", "account", "command", "event-id", "guid",
    "mutex", "registry", "domain",
}

# Text fields expected to be strings; list fields expected to be lists.
_STR_FIELDS = ("value", "defanged", "role", "first_seen_utc", "last_seen_utc",
               "confidence", "source", "context", "mitre")
_LIST_FIELDS = ("tags", "hosts")

# Types whose dotted/colon notation is defanged.
_DOT_TYPES = {"ipv4", "domain", "hostname", "file-path", "registry"}
_COLON_TYPES = {"ipv6", "mac"}

_CONFIDENCE = {"high", "medium", "low", "benign"}
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def defang(value, typ: str = "") -> str:
    """Return a defanged rendering of ``value`` for reports/feeds."""
    v = "" if value is None else str(value)
    v = re.sub(r"(?i)^http", "hxxp", v) if typ == "url" else v
    if typ in _DOT_TYPES or typ == "url":
        v = v.replace(".", "[.]")
    if typ in _COLON_TYPES:
        v = v.replace(":", "[:]")
    return v


def _is_private_ipv4(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def is_internal(value: str, typ: str, extra_cidrs=()) -> bool:
    """Heuristic: is this observable internal/benign infrastructure?"""
    if typ != "ipv4":
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if _is_private_ipv4(value):
        return True
    for cidr in extra_cidrs or ():
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def normalize(type_: str, value: str) -> str:
    """Canonicalise a value for de-duplication."""
    v = "" if value is None else str(value).strip()
    if type_ in ("domain", "hostname"):
        return v.rstrip(".").lower()
    if type_ == "url":
        return v.lower()
    return v


def validate(data) -> list[str]:
    """Validate an IOC document. Return a list of 'path: message' errors."""
    errs: list[str] = []
    if not isinstance(data, dict):
        if isinstance(data, list):
            return ["root: expected an object with 'observables', got a list "
                    "(wrap it as {\"observables\": [...]})"]
        return [f"root: expected an object, got {type(data).__name__}"]

    endpoints = data.get("endpoints")
    if endpoints is not None:
        if not isinstance(endpoints, dict):
            errs.append("endpoints: must be an object mapping ip -> {name,role,order}")
        else:
            for key, ep in endpoints.items():
                if not isinstance(ep, dict):
                    errs.append(f"endpoints.{key}: must be an object")
                    continue
                if "name" not in ep:
                    errs.append(f"endpoints.{key}: missing 'name'")

    obs = data.get("observables")
    if obs is None:
        errs.append("observables: missing (expected a list)")
        return errs
    if not isinstance(obs, list):
        errs.append("observables: must be a list")
        return errs

    seen = {}
    for i, item in enumerate(obs):
        p = f"observables[{i}]"
        if not isinstance(item, dict):
            errs.append(f"{p}: must be an object")
            continue
        typ = item.get("type")
        val = item.get("value")
        if not typ:
            errs.append(f"{p}: missing required 'type'")
        elif typ not in ALLOWED_TYPES:
            errs.append(f"{p}.type: '{typ}' not in {sorted(ALLOWED_TYPES)}")
        if val in (None, ""):
            errs.append(f"{p}: missing required 'value'")
        for f in _STR_FIELDS:
            if f in item and item[f] is not None and not isinstance(item[f], str):
                errs.append(f"{p}.{f}: must be a string")
        for f in _LIST_FIELDS:
            if f in item and item[f] is not None and not isinstance(item[f], list):
                errs.append(f"{p}.{f}: must be a list")
        conf = item.get("confidence")
        if conf and conf not in _CONFIDENCE:
            errs.append(f"{p}.confidence: '{conf}' not in {sorted(_CONFIDENCE)}")
        mitre = item.get("mitre")
        if mitre:
            for tok in str(mitre).split(","):
                tok = tok.strip()
                if tok and not _MITRE_RE.match(tok):
                    errs.append(f"{p}.mitre: '{tok}' is not a Txxxx[.xxx] id")
        if typ and val not in (None, ""):
            key = (typ, normalize(typ, val))
            if key in seen:
                errs.append(f"{p}: duplicate of observables[{seen[key]}] "
                            f"({typ} {val})")
            else:
                seen[key] = i
    return errs
