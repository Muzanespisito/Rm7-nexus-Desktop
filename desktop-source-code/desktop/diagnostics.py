from __future__ import annotations

import os
import platform
import shutil
import socket
import struct
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .config import Config
from .os_support import current_platform
from .security.lua_libraries import LuaLibraryCatalog

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
}

_DEAMX_FILES = (
    "deamx.lua",
    "deamx_util.lua",
    "deamx_opcodes.lua",
    "deamx_events.lua",
    "deamx_syscalls.lua",
)


@dataclass
class Check:
    id: str
    label: str
    category: str
    required: bool
    status: str
    detail: str = ""
    action: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category,
            "required": self.required,
            "status": self.status,
            "detail": self.detail,
            "action": self.action,
        }


@dataclass
class DiagnosticsReport:
    environment: list[Check] = field(default_factory=list)
    compatibility: list[Check] = field(default_factory=list)
    network: list[Check] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    @property
    def required_failed(self) -> list[Check]:
        return [
            check
            for check in [*self.environment, *self.compatibility]
            if check.required and check.status == "fail"
        ]

    @property
    def ok(self) -> bool:
        return not self.required_failed

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "generated_at": self.generated_at,
            "required_failed": [check.to_dict() for check in self.required_failed],
            "environment": [check.to_dict() for check in self.environment],
            "compatibility": [check.to_dict() for check in self.compatibility],
            "network": [check.to_dict() for check in self.network],
        }


def _writable(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path, prefix="rm7_", delete=True) as handle:
            handle.write(b"ok")
            handle.flush()
        return True, str(path)
    except OSError as exc:
        return False, str(exc)


def read_pe_machine(path: Path) -> str | None:
    try:
        with Path(path).open("rb") as handle:
            header = handle.read(0x40)
            if len(header) < 0x40 or header[:2] != b"MZ":
                return None
            offset = struct.unpack_from("<I", header, 0x3C)[0]
            handle.seek(offset)
            pe = handle.read(6)
            if len(pe) < 6 or pe[:4] != b"PE\x00\x00":
                return None
            machine = struct.unpack_from("<H", pe, 4)[0]
            return PE_MACHINES.get(machine, f"0x{machine:04x}")
    except OSError:
        return None


def _directory_check(check_id: str, label: str, path: Path, required: bool) -> Check:
    ok, detail = _writable(path)
    return Check(
        id=check_id,
        label=label,
        category="environment",
        required=required,
        status="ok" if ok else "fail",
        detail=detail,
        action="" if ok else "Change RM7 data directory permissions or free the path.",
    )


def _platform_checks(config: Config) -> list[Check]:
    checks: list[Check] = []
    info = current_platform()
    checks.append(
        Check(
            "platform",
            "Operating system",
            "environment",
            True,
            "ok" if info else "fail",
            f"{platform.system()} {platform.release()} ({platform.version()})",
            "" if info else "Use the Windows x64 or Debian x64 desktop build.",
        )
    )
    bits = 64 if sys.maxsize > 2**32 else 32
    checks.append(
        Check(
            "architecture",
            "Process architecture",
            "environment",
            True,
            "ok" if bits == 64 else "fail",
            f"{bits}-bit {platform.machine() or ''}".strip(),
            "Use a 64-bit desktop build." if bits != 64 else "",
        )
    )
    version = ".".join(str(part) for part in sys.version_info[:3])
    checks.append(
        Check(
            "python",
            "Bundled Python runtime",
            "environment",
            sys.version_info >= (3, 10),
            "ok" if sys.version_info >= (3, 10) else "fail",
            version,
            "Rebuild the desktop package with Python 3.10 or newer."
            if sys.version_info < (3, 10)
            else "",
        )
    )
    checks.append(
        Check(
            "app_version",
            "Application version",
            "environment",
            True,
            "ok",
            config.version,
        )
    )
    checks.extend(
        [
            _directory_check("data_dir", "Data directory", config.data_dir, True),
            _directory_check("jobs_dir", "Job workspace", config.jobs_dir, True),
            _directory_check("logs_dir", "Log directory", config.logs_dir, True),
            _directory_check("outputs_dir", "Output directory", config.outputs_dir, True),
            _directory_check("updates_dir", "Update directory", config.updates_dir, True),
        ]
    )
    if sys.platform.startswith("linux"):
        try:
            __import__("secretstorage")
            available = bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("XDG_RUNTIME_DIR"))
            checks.append(
                Check(
                    "credential_store",
                    "Secure credential storage",
                    "environment",
                    False,
                    "ok" if available else "warn",
                    "Secret Service backend detected."
                    if available
                    else "No desktop Secret Service session was detected.",
                    ""
                    if available
                    else "Unlock a Secret Service keyring before linking an account.",
                )
            )
        except ImportError:
            checks.append(
                Check(
                    "credential_store",
                    "Secure credential storage",
                    "environment",
                    False,
                    "warn",
                    "Secret Service support is not installed.",
                    "Install the Linux desktop package to restore secure session storage.",
                )
            )
    elif sys.platform == "win32":
        checks.append(
            Check(
                "credential_store",
                "Secure credential storage",
                "environment",
                False,
                "ok",
                "Windows Credential Manager",
            )
        )
    try:
        usage = shutil.disk_usage(config.data_dir)
        free = usage.free
        enough = free >= config.min_free_disk_bytes
        checks.append(
            Check(
                "disk_space",
                "Free disk space",
                "environment",
                True,
                "ok" if enough else "fail",
                f"{free / (1024 ** 3):.2f} GiB free",
                "Free at least 512 MiB before processing large files." if not enough else "",
            )
        )
    except OSError as exc:
        checks.append(
            Check("disk_space", "Free disk space", "environment", True, "fail", str(exc))
        )
    ok, detail = _writable(Path(tempfile.gettempdir()))
    checks.append(
        Check(
            "temp_dir",
            "Writable temporary directory",
            "environment",
            True,
            "ok" if ok else "fail",
            detail,
            "" if ok else "Fix TEMP permissions or set a writable TEMP directory.",
        )
    )
    memory = _total_memory()
    if memory:
        checks.append(
            Check(
                "memory",
                "System memory",
                "environment",
                False,
                "ok" if memory >= 2 * 1024 ** 3 else "warn",
                f"{memory / (1024 ** 3):.2f} GiB total",
                "Large AMX files need additional memory." if memory < 2 * 1024 ** 3 else "",
            )
        )
    return checks


def _total_memory() -> int | None:
    if sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except (AttributeError, OSError, ValueError):
            return None
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages) * int(page_size)
    except (AttributeError, OSError, ValueError):
        return None


def _dll_profile(config: Config) -> Check:
    report = LuaLibraryCatalog(config).report()
    if not report["selected_path"]:
        return Check(
            "lua_library_profile",
            "Local Lua libraries",
            "compatibility",
            False,
            "skip",
            "No local Lua library directory is selected.",
            "Select a library folder in the Grab Detector panel to inspect its modules.",
        )
    if report["error"] or not report["readable"]:
        return Check(
            "lua_library_profile",
            "Local Lua libraries",
            "compatibility",
            False,
            "warn",
            report["error"] or "The selected directory is not readable.",
            "Choose a readable folder containing Lua modules.",
        )
    native = report["native_dependencies_unavailable"]
    summary = (
        f"{report['discovered_module_count']} modules discovered; "
        f"{report['compatible_module_count']} compatible, "
        f"{report['conditional_module_count']} environment-dependent, "
        f"{report['unsupported_module_count']} unsupported."
    )
    if native:
        summary += " Native modules are not loaded."
    return Check(
        "lua_library_profile",
        "Local Lua libraries",
        "compatibility",
        False,
        "ok" if report["compatible_module_count"] or report["conditional_module_count"] else "warn",
        summary,
        "Libraries are snapshotted read-only into the isolated runtime. Native modules are never loaded.",
    )


def _node_check(config: Config) -> Check:
    if config.node_binary and Path(config.node_binary).exists():
        return Check(
            "node_runtime",
            "Node.js engine host",
            "compatibility",
            True,
            "ok",
            config.node_binary,
        )
    found = shutil.which("node")
    if found:
        config.node_binary = found
        return Check("node_runtime", "Node.js engine host", "compatibility", True, "ok", found)
    return Check(
        "node_runtime",
        "Node.js engine host",
        "compatibility",
        True,
        "fail",
        "Node.js was not found.",
        "Install the bundled Node.js runtime or set RM7_NODE.",
    )


def _amx_checks(config: Config) -> list[Check]:
    checks: list[Check] = []
    deamx_dir = config.project_root / "api" / "DeAmx"
    missing = [name for name in _DEAMX_FILES if not (deamx_dir / name).is_file()]
    checks.append(
        Check(
            "amx_engine_sources",
            "DeAMX engine sources",
            "compatibility",
            True,
            "ok" if not missing else "fail",
            "All DeAMX Lua sources present." if not missing else "Missing: " + ", ".join(missing),
            "Reinstall the desktop package; api/DeAmx is incomplete.",
        )
    )
    glue = config.project_root / "api" / "glue.wasm"
    checks.append(
        Check(
            "amx_wasm_runtime",
            "DeAMX WebAssembly runtime",
            "compatibility",
            True,
            "ok" if glue.is_file() else "fail",
            str(glue) if glue.is_file() else "api/glue.wasm is missing.",
        )
    )
    adapter = config.project_root / "lib" / "deamx.js"
    checks.append(
        Check(
            "amx_adapter",
            "AMX adapter",
            "compatibility",
            True,
            "ok" if adapter.is_file() else "fail",
            str(adapter) if adapter.is_file() else "lib/deamx.js is missing.",
        )
    )
    wasmoon = config.project_root / "node_modules" / "wasmoon" / "package.json"
    checks.append(
        Check(
            "amx_wasmoon",
            "wasmoon dependency",
            "compatibility",
            True,
            "ok" if wasmoon.is_file() else "fail",
            str(wasmoon) if wasmoon.is_file() else "node_modules/wasmoon is missing.",
            "Install production dependencies before packaging.",
        )
    )
    return checks


def _grab_checks(config: Config) -> list[Check]:
    sandbox = config.project_root / "grab-detector-sandbox"
    runtime = sandbox / "runtime.mjs"
    prelude = sandbox / "sandbox-prelude.lua"
    vendor = sandbox / "vendor" / "wasmoon" / "glue.wasm"
    engine_candidates = (
        config.project_root / "lib" / "grab_detector_engine.py",
        config.project_root / "lib" / "grab_detector_engine.pyc",
    )
    engine = next((path for path in engine_candidates if path.is_file()), engine_candidates[0])
    core_missing = [path.name for path in (runtime, prelude, vendor, engine) if not path.is_file()]
    status = "ok" if not core_missing else "fail"
    detail = "Isolated Lua runtime assets detected." if not core_missing else "Missing: " + ", ".join(core_missing)
    return [
        Check(
            "grab_detector_runtime",
            "Grab Detector isolated runtime",
            "compatibility",
            False,
            status,
            detail,
            "" if status == "ok" else "Static analysis remains available; reinstall to restore the full mission.",
        )
    ]


def environment_checks(config: Config) -> list[Check]:
    config.ensure_dirs()
    return _platform_checks(config)


def compatibility_checks(config: Config) -> list[Check]:
    checks = [_node_check(config)]
    checks.extend(_amx_checks(config))
    checks.extend(_grab_checks(config))
    checks.append(_dll_profile(config))
    return checks


def network_check(config: Config, timeout: float = 4.0) -> list[Check]:
    parsed = urlparse(config.api_base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return [
            Check(
                "api_connectivity",
                "Account service connectivity",
                "network",
                False,
                "fail",
                "Invalid API base URL.",
            )
        ]
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000
        return [
            Check(
                "api_connectivity",
                "Account service connectivity",
                "network",
                False,
                "ok",
                f"{host}:{port} reachable in {elapsed:.0f} ms",
            )
        ]
    except OSError as exc:
        return [
            Check(
                "api_connectivity",
                "Account service connectivity",
                "network",
                False,
                "warn",
                f"{host}:{port} unavailable: {exc}",
                "Local missions remain unavailable until the account service is reachable.",
            )
        ]


def run_diagnostics(config: Config, include_network: bool = False) -> DiagnosticsReport:
    report = DiagnosticsReport()
    report.environment = environment_checks(config)
    report.compatibility = compatibility_checks(config)
    if include_network:
        report.network = network_check(config)
    return report


def flatten(report: DiagnosticsReport) -> Iterable[Check]:
    yield from report.environment
    yield from report.compatibility
    yield from report.network
