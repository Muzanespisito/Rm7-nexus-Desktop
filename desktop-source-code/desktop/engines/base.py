from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200


class EngineError(RuntimeError):
    pass


class EngineCancelled(EngineError):
    pass


class EngineTimeout(EngineError):
    pass


@dataclass
class ProcessOutcome:
    returncode: int
    timed_out: bool
    cancelled: bool


def minimal_env(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    allow = (
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "windir",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "LANG",
        "LC_ALL",
    )
    env = {key: os.environ[key] for key in allow if key in os.environ}
    if overrides:
        env.update({str(key): str(value) for key, value in overrides.items()})
    return env


def kill_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
                env=minimal_env(),
            )
        else:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (OSError, ProcessLookupError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def run_process(
    command: list[str],
    cwd: Path,
    timeout: float,
    cancel_event: threading.Event,
    on_line: Callable[[str], None],
    env: Mapping[str, str] | None = None,
) -> ProcessOutcome:
    creationflags = 0
    start_new_session = False
    if sys.platform == "win32":
        creationflags = _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP
    else:
        start_new_session = True
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=dict(env) if env is not None else minimal_env(),
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
    except OSError as exc:
        raise EngineError(f"Could not start the {Path(command[0]).name} engine: {exc}") from exc

    stop = threading.Event()
    state = {"cancelled": False, "timed_out": False}

    def watchdog() -> None:
        deadline = time.monotonic() + max(1.0, timeout)
        while not stop.wait(0.1):
            if cancel_event.is_set():
                state["cancelled"] = True
                kill_process_tree(process)
                return
            if time.monotonic() >= deadline:
                state["timed_out"] = True
                kill_process_tree(process)
                return

    thread = threading.Thread(target=watchdog, daemon=True, name="rm7-engine-watchdog")
    thread.start()
    try:
        if process.stdout is not None:
            for raw in process.stdout:
                line = raw.rstrip("\r\n")
                if line:
                    try:
                        on_line(line)
                    except Exception:
                        pass
        returncode = process.wait()
    finally:
        stop.set()
        thread.join(timeout=2)
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass

    if state["cancelled"]:
        raise EngineCancelled("The job was cancelled.")
    if state["timed_out"]:
        raise EngineTimeout("The engine exceeded its time limit.")
    return ProcessOutcome(returncode=returncode, timed_out=False, cancelled=False)
