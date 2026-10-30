from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

_SENSITIVE = ("token", "secret", "password", "authorization", "cookie", "license_key", "api_key")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in _SENSITIVE):
                out[key] = "[redacted]"
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class StructuredLogger:
    def __init__(self, path: Path, echo: bool = True) -> None:
        self.path = Path(path)
        self.echo = echo
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, name: str, **fields: Any) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": name,
            **_redact(fields),
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        if self.echo:
            print(line, file=sys.stderr, flush=True)

    def text(self, message: str) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "log",
            "message": str(message),
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        if self.echo:
            print(str(message), file=sys.stderr, flush=True)
