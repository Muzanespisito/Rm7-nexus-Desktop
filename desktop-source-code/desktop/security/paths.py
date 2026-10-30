from __future__ import annotations

import re
import unicodedata
from pathlib import Path

_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class UnsafePath(ValueError):
    pass


def ensure_within(base: Path, candidate: Path) -> Path:
    base = Path(base).resolve()
    candidate = Path(candidate).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise UnsafePath("Path escapes the allowed directory") from exc
    return candidate


def safe_filename(name: str, fallback: str = "upload.bin", max_length: int = 120) -> str:
    raw = unicodedata.normalize("NFKC", str(name or "")).replace("\\", "/")
    raw = raw.rsplit("/", 1)[-1]
    raw = re.sub(r"[\x00-\x1f\x7f]", "", raw).strip().strip(".")
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    if not raw:
        raw = fallback
    stem = raw.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raw = "_" + raw
    if len(raw) > max_length:
        suffix = Path(raw).suffix[:16]
        raw = raw[: max(1, max_length - len(suffix))] + suffix
    return raw or fallback


def safe_join(base: Path, *parts: str) -> Path:
    target = Path(base)
    for part in parts:
        target = target / safe_filename(part, fallback="file")
    return ensure_within(base, target)
