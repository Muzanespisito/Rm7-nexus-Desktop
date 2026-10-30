from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class PlatformError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlatformInfo:
    key: str
    label: str
    artifact_kind: str
    data_directory_name: str


_PLATFORMS = {
    "windows": PlatformInfo("windows", "Windows", "exe", "RM7Nexus"),
    "linux": PlatformInfo("linux", "Linux", "deb", "rm7nexus"),
}


def current_platform() -> PlatformInfo | None:
    if sys.platform == "win32":
        return _PLATFORMS["windows"]
    if sys.platform.startswith("linux"):
        return _PLATFORMS["linux"]
    return None


def current_platform_key(default: str = "linux") -> str:
    info = current_platform()
    return info.key if info else default


def platform_for_key(key: str) -> PlatformInfo | None:
    return _PLATFORMS.get(str(key or "").strip().lower())


def platform_label() -> str:
    info = current_platform()
    if info:
        return info.label
    return platform.system() or "Unsupported"


def default_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / _PLATFORMS["windows"].data_directory_name
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / _PLATFORMS["linux"].data_directory_name


def supported_installer(path: Path, key: str | None = None) -> bool:
    info = platform_for_key(key) if key else current_platform()
    if not info:
        return False
    suffix = Path(path).suffix.lower()
    return suffix == "." + info.artifact_kind


def launch_installer(path: Path) -> None:
    target = Path(path).resolve()
    if not target.is_file():
        raise PlatformError("The downloaded installer is missing.")
    if not supported_installer(target):
        raise PlatformError("The downloaded file is not a valid installer for this platform.")
    if sys.platform == "win32":
        try:
            os.startfile(str(target))
        except OSError as exc:
            raise PlatformError("The Windows installer could not be opened.") from exc
        return
    if sys.platform.startswith("linux"):
        opener = shutil.which("xdg-open") or shutil.which("gio")
        if not opener:
            raise PlatformError("No application launcher is available for the installer.")
        command = [opener, "open", str(target)] if Path(opener).name == "gio" else [opener, str(target)]
        try:
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            raise PlatformError("The package manager could not be opened.") from exc
        return
    raise PlatformError("This platform does not support installer packages.")
