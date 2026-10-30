from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable

from ..config import Config
from .base import EngineError, minimal_env, run_process


class AmxEngine:
    name = "amx"
    label = "AMX to PWN"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runner = config.desktop_root / "engines" / "amx_runner.mjs"
        self.adapter = config.project_root / "lib" / "deamx.js"
        self.deamx_dir = config.project_root / "api" / "DeAmx"
        self.glue = config.project_root / "api" / "glue.wasm"

    def validate(self) -> None:
        if not self.config.node_binary:
            raise EngineError("Node.js is unavailable.")
        for path in (self.runner, self.adapter, self.glue):
            if not path.is_file():
                raise EngineError(f"Required engine file is missing: {path}")
        for name in (
            "deamx.lua",
            "deamx_util.lua",
            "deamx_opcodes.lua",
            "deamx_events.lua",
            "deamx_syscalls.lua",
        ):
            if not (self.deamx_dir / name).is_file():
                raise EngineError(f"Required DeAMX source is missing: {name}")

    def run(
        self,
        input_path: Path,
        output_path: Path,
        work_dir: Path,
        on_progress: Callable[[int, str], None],
        cancel_event: threading.Event,
        options: dict | None = None,
    ) -> dict:
        self.validate()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        on_progress(3, "Starting the local DeAMX engine")
        command = [
            self.config.node_binary,
            str(self.runner),
            str(Path(input_path).resolve()),
            str(Path(output_path).resolve()),
        ]
        env = minimal_env(
            {
                "DEAMX_TIMEOUT_MS": str(max(1000, self.config.amx_timeout_seconds * 1000)),
            }
        )
        result: dict | None = None
        failure: str | None = None
        log_lines: list[str] = []

        def handle(line: str) -> None:
            nonlocal result, failure
            stripped = line.strip()
            if stripped.startswith("{"):
                try:
                    event = json.loads(stripped)
                except ValueError:
                    event = None
                if isinstance(event, dict):
                    kind = event.get("type")
                    if kind == "progress":
                        try:
                            value = int(event.get("value", 0))
                        except (TypeError, ValueError):
                            value = 0
                        on_progress(max(3, min(97, value)), str(event.get("message") or ""))
                        return
                    if kind == "result":
                        result = event
                        return
                    if kind == "error":
                        failure = str(event.get("error") or "The DeAMX engine failed.")
                        log_lines.append(failure)
                        return
            log_lines.append(line)

        outcome = run_process(
            command,
            cwd=work_dir,
            timeout=self.config.amx_timeout_seconds,
            cancel_event=cancel_event,
            on_line=handle,
            env=env,
        )
        if outcome.returncode != 0:
            detail = failure or (log_lines[-1] if log_lines else "")
            raise EngineError(detail or f"The DeAMX engine exited with code {outcome.returncode}.")
        if not Path(output_path).is_file():
            raise EngineError(failure or "The DeAMX engine did not produce an output file.")
        size = Path(output_path).stat().st_size
        if size <= 0:
            raise EngineError("The DeAMX engine produced an empty output file.")
        on_progress(100, "Decompilation complete")
        meta = result or {}
        meta.pop("type", None)
        meta.pop("source", None)
        return {
            "output_path": str(output_path),
            "output_name": output_path.name,
            "size": size,
            "meta": {
                **meta,
                "deamx_fail_count": result.get("failCount", 0) if result else 0,
                "deamx_log": result.get("log", "") if result else "",
            },
            "log": "\n".join(log_lines),
        }
