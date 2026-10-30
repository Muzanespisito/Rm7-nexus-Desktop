from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .os_support import PlatformInfo, current_platform, default_data_dir

APP_NAME = "RM7 Nexus Desktop"
APP_VERSION = "0.1.1"
DEFAULT_API_BASE = "https://YOUR_API_DOMAIN.example"
UPDATE_PUBLIC_KEY = "YOUR_ED25519_PUBLIC_KEY_BASE64"

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    PROJECT_ROOT = Path(sys._MEIPASS).resolve()
    DESKTOP_ROOT = PROJECT_ROOT / "desktop"
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    DESKTOP_ROOT = Path(__file__).resolve().parent


def _default_node_binary() -> str:
    override = os.environ.get("RM7_NODE", "").strip()
    if override:
        return override
    executable = "node.exe" if sys.platform == "win32" else "node"
    for candidate in (
        PROJECT_ROOT / "vendor" / "node" / executable,
        DESKTOP_ROOT / "vendor" / "node" / executable,
    ):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("node") or ""


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


@dataclass
class Config:
    project_root: Path = PROJECT_ROOT
    desktop_root: Path = DESKTOP_ROOT
    data_dir: Path = field(default_factory=default_data_dir)
    api_base: str = field(
        default_factory=lambda: (os.environ.get("RM7_API_BASE") or DEFAULT_API_BASE).rstrip("/")
    )
    version: str = APP_VERSION
    server_host: str = "127.0.0.1"
    max_upload_bytes: int = 128 * 1024 * 1024
    amx_timeout_seconds: int = 300
    job_concurrency: int = 1
    min_free_disk_bytes: int = 512 * 1024 * 1024
    open_ui: bool = True
    node_binary: str = field(default_factory=_default_node_binary)
    update_channel: str = field(
        default_factory=lambda: (os.environ.get("RM7_UPDATE_CHANNEL") or "stable").strip().lower()
    )
    update_public_key: str = field(
        default_factory=lambda: (
            os.environ.get("RM7_UPDATE_PUBLIC_KEY") or UPDATE_PUBLIC_KEY
        ).strip()
    )
    update_timeout_seconds: int = 12
    max_update_bytes: int = 1536 * 1024 * 1024

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root).resolve()
        self.desktop_root = Path(self.desktop_root).resolve()
        self.data_dir = Path(self.data_dir).expanduser().resolve()
        self.amx_timeout_seconds = _env_int("RM7_AMX_TIMEOUT_SECONDS", self.amx_timeout_seconds, 10, 1800)
        self.job_concurrency = _env_int("RM7_JOB_CONCURRENCY", self.job_concurrency, 1, 4)
        self.max_upload_bytes = _env_int(
            "RM7_MAX_UPLOAD_BYTES", self.max_upload_bytes, 1024, 512 * 1024 * 1024
        )
        self.update_timeout_seconds = _env_int(
            "RM7_UPDATE_TIMEOUT_SECONDS", self.update_timeout_seconds, 3, 120
        )
        self.max_update_bytes = _env_int(
            "RM7_MAX_UPDATE_BYTES", self.max_update_bytes, 1024 * 1024, 4096 * 1024 * 1024
        )

    @property
    def platform(self) -> PlatformInfo | None:
        return current_platform()

    @property
    def platform_key(self) -> str:
        item = self.platform
        return item.key if item else "unsupported"

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def outputs_dir(self) -> Path:
        return self.data_dir / "outputs"

    @property
    def config_dir(self) -> Path:
        return self.data_dir / "config"

    @property
    def session_file(self) -> Path:
        return self.config_dir / "session.bin"

    @property
    def updates_dir(self) -> Path:
        return self.data_dir / "updates"

    @property
    def lua_library_dir(self) -> Path:
        return self.data_dir / "lua-libraries"

    @property
    def lua_library_staging_dir(self) -> Path:
        return self.data_dir / "lua-library-staging"

    @property
    def update_state_file(self) -> Path:
        return self.config_dir / "update-state.json"

    def ensure_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.jobs_dir,
            self.logs_dir,
            self.outputs_dir,
            self.config_dir,
            self.updates_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def api_is_local_http(self) -> bool:
        return self.api_base.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]"))

    def api_is_https(self) -> bool:
        return self.api_base.startswith("https://")
