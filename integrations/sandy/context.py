"""Embedding adapter for bounded, source-labelled memory and procedure context.

The host remains the owner of storage, permissions and approvals. This module
uses Hermes' actual scanner and write-origin implementation without starting
an agent, scheduler, gateway or filesystem-backed memory store.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


def _load(name: str, filename: str):
    path = Path(__file__).resolve().parents[2] / "tools" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Pinned context implementation is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_threats = _load("hermes_host_threats", "threat_patterns.py")
_origin = _load("hermes_host_provenance", "skill_provenance.py")


def review_context(entries: list[dict[str, Any]], *, max_chars: int = 8000,
                   origin: str = "foreground") -> dict[str, Any]:
    if not 1 <= max_chars <= 32000 or len(entries) > 100:
        raise ValueError("Context exceeds the embedding limits")
    if origin not in ("foreground", _origin.BACKGROUND_REVIEW):
        raise ValueError("Unknown context origin")
    token = _origin.set_current_write_origin(origin)
    try:
        selected, refused, used = [], [], 0
        for entry in entries:
            source = str(entry.get("source") or "").strip()
            text = str(entry.get("text") or "").strip()
            if not source or not text or len(text) > _threats.MAX_SCAN_CHARS:
                refused.append({"source": source, "reason": "invalid_or_oversized"})
                continue
            findings = _threats.scan_for_threats(text, scope="strict")
            if findings:
                refused.append({"source": source, "reason": "unsafe_context", "findings": findings})
                continue
            if used + len(text) > max_chars:
                refused.append({"source": source, "reason": "budget"})
                continue
            selected.append({"source": source, "text": text})
            used += len(text)
        return {
            "entries": selected, "refused": refused,
            "origin": _origin.get_current_write_origin(),
            "requires_review": _origin.is_background_review(),
        }
    finally:
        _origin.reset_current_write_origin(token)
