from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable

from .paths import UnsafePath

MODULE_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
REQUIRE_RE = re.compile(r"\brequire\s*(?:\(\s*)?[\"']([^\"']{1,160})[\"']")
NATIVE_EXTENSIONS = {".dll", ".so", ".dylib", ".bundle", ".luac", ".a", ".lib"}
MAX_MODULES = 2000
MAX_MODULE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REPORTED_MODULES = 500

RUNTIME_MODULES = {
    "base64",
    "bit",
    "bit32",
    "cjson",
    "cjson.safe",
    "encoding",
    "http",
    "json",
    "lib.moonloader",
    "lib.samp.events",
    "ltn12",
    "memory",
    "mime",
    "mime.core",
    "md5",
    "monet",
    "monetloader",
    "moonloader",
    "requests",
    "samp.events",
    "sampfuncs",
    "socket",
    "socket.headers",
    "socket.http",
    "socket.url",
    "ssl",
    "ssl.https",
    "vkeys",
    "xml",
}
STANDARD_MODULES = {"coroutine", "math", "string", "table", "utf8"}
CONDITIONAL_MODULES = {"lib.moonloader", "lib.samp.events", "memory", "moonloader", "samp.events", "sampfuncs"}
UNSAFE_MODULES = {"ffi"}
UNSAFE_SOURCE_REASONS = (
    (re.compile(r"\brequire\s*(?:\(\s*)?[\"']ffi[\"']"), "LuaJIT FFI requires native code and is disabled."),
    (re.compile(r"\bffi\s*\."), "LuaJIT FFI requires native code and is disabled."),
    (re.compile(r"\bpackage\s*\.\s*loadlib\b|\bloadlib\s*\("), "Dynamic native-library loading is disabled."),
    (re.compile(r"\b(?:io\s*\.\s*open|loadfile|dofile)\s*\("), "The module requires filesystem access outside its approved library snapshot."),
    (re.compile(r"\bos\s*\.\s*execute\s*\("), "Operating-system command execution is disabled."),
)
ENVIRONMENT_RE = re.compile(r"\b(?:samp|sampfuncs|moonloader|memory)\s*\.")


class LuaLibraryError(ValueError):
    pass


def valid_module_name(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 160:
        return False
    if "/" in value or "\\" in value or ":" in value or ".." in value:
        return False
    return all(MODULE_SEGMENT_RE.fullmatch(part) for part in value.split("."))


def _module_name(relative: Path) -> str | None:
    parts = list(relative.parts)
    if not parts:
        return None
    if parts[-1].lower() in ("init.lua", "init.dll", "init.so", "init.dylib"):
        parts.pop()
    else:
        parts[-1] = Path(parts[-1]).stem
    if not parts:
        return None
    name = ".".join(parts)
    return name if valid_module_name(name) else None


class LuaLibraryCatalog:
    def __init__(self, config) -> None:
        self.config = config
        self.settings_path = config.config_dir / "lua-library.json"
        config.ensure_dirs()

    def _stored_path(self) -> Path | None:
        try:
            value = json.loads(self.settings_path.read_text(encoding="utf-8"))
            raw_path = value.get("directory") if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
        try:
            return Path(raw_path).expanduser()
        except (OSError, RuntimeError):
            return None

    def selected_path(self) -> Path | None:
        stored = self._stored_path()
        if stored is None:
            return None
        try:
            selected = stored.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not selected.is_dir() or not os.access(selected, os.R_OK | os.X_OK):
            return None
        return selected

    @staticmethod
    def required_modules(source: str) -> list[str]:
        return sorted(
            {
                name
                for name in REQUIRE_RE.findall(str(source or ""))
                if valid_module_name(name)
            }
        )

    def set_directory(self, directory: str | os.PathLike[str]) -> Path:
        try:
            selected = Path(directory).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LuaLibraryError("The selected Lua library directory does not exist.") from exc
        if not selected.is_dir():
            raise LuaLibraryError("Select an existing directory containing Lua libraries.")
        if not os.access(selected, os.R_OK | os.X_OK):
            raise LuaLibraryError("The selected directory is not readable.")
        self._store_path(selected)
        return selected

    def select_manual_directory(self, directory: str | os.PathLike[str]) -> Path:
        raw = str(directory or "").strip().strip('"').strip("'")
        if not raw:
            raise LuaLibraryError("Enter the full path of a Lua library folder.")
        try:
            selected = Path(os.path.expandvars(raw)).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LuaLibraryError("The Lua library path does not exist.") from exc
        if not selected.is_dir():
            raise LuaLibraryError("The Lua library path is not a folder.")
        if not os.access(selected, os.R_OK | os.X_OK):
            raise LuaLibraryError("The Lua library folder is not readable.")
        modules, _native, _total_bytes = self._scan(selected)
        if not modules:
            raise LuaLibraryError("No Lua library modules were found in that folder.")
        self._store_path(selected)
        return selected

    def clear(self) -> None:
        try:
            self.settings_path.unlink()
        except FileNotFoundError:
            pass
        managed = self.config.lua_library_dir
        try:
            if managed.is_dir():
                shutil.rmtree(managed)
        except OSError as exc:
            raise LuaLibraryError("The managed Lua library snapshot could not be cleared.") from exc

    def install_upload(self, staging: Path) -> Path:
        staging = Path(staging)
        try:
            source_root = staging.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LuaLibraryError("The uploaded Lua library is unavailable.") from exc
        if not source_root.is_dir():
            raise LuaLibraryError("The uploaded Lua library is not a directory.")
        target = self.config.lua_library_dir
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}-{secrets.token_hex(8)}.tmp")
        backup = target.with_name(f".{target.name}-{secrets.token_hex(8)}.old")
        copied = 0
        total = 0
        try:
            if temporary.exists():
                shutil.rmtree(temporary)
            temporary.mkdir(parents=True)
            for current, dirs, filenames in os.walk(source_root, followlinks=False):
                current_path = Path(current)
                dirs[:] = sorted(
                    name for name in dirs if not (current_path / name).is_symlink()
                )
                for filename in sorted(filenames):
                    source = current_path / filename
                    metadata = source.lstat()
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    if source.suffix.lower() not in (".lua", *NATIVE_EXTENSIONS):
                        continue
                    relative = source.relative_to(source_root)
                    if len(relative.parts) > 8 or ".." in relative.parts:
                        raise LuaLibraryError("The uploaded Lua library contains an unsafe path.")
                    if metadata.st_size > MAX_MODULE_BYTES:
                        raise LuaLibraryError("A Lua library module exceeds the 2 MiB per-module limit.")
                    copied += 1
                    total += metadata.st_size
                    if copied > MAX_MODULES:
                        raise LuaLibraryError(f"The library exceeds the {MAX_MODULES}-module limit.")
                    if total > MAX_TOTAL_BYTES:
                        raise LuaLibraryError("The library exceeds the 64 MiB safe scan limit.")
                    destination = temporary.joinpath(*relative.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination, follow_symlinks=False)
                    if os.name != "nt":
                        os.chmod(destination, 0o444)
            if copied == 0:
                raise LuaLibraryError("No Lua library modules were found in the selected folder.")
            if target.exists():
                os.replace(target, backup)
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
        try:
            shutil.rmtree(backup, ignore_errors=True)
        except OSError:
            pass
        self._store_path(target)
        return target

    def _store_path(self, directory: Path) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.settings_path.parent,
                prefix=".lua-library-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                os.chmod(temporary_path, 0o600)
                json.dump({"directory": str(directory)}, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.settings_path)
            if os.name != "nt":
                os.chmod(self.settings_path, 0o600)
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def report(self, required_modules: Iterable[str] = ()) -> dict:
        stored = self._stored_path()
        report = {
            "selected_path": str(stored) if stored else None,
            "exists": False,
            "readable": False,
            "runtime_version": "Wasmoon Lua 5.4 with Lua 5.1/LuaJIT compatibility shims",
            "discovered_module_count": 0,
            "compatible_module_count": 0,
            "conditional_module_count": 0,
            "unsupported_module_count": 0,
            "modules": [],
            "required_modules": [],
            "missing_modules": [],
            "native_dependencies_unavailable": [],
            "sandbox_can_access_snapshot": sys.platform == "linux" and shutil.which("bwrap") is not None,
            "error": None,
        }
        if stored is None:
            return report
        try:
            directory = stored.resolve(strict=True)
        except (OSError, RuntimeError):
            report["error"] = "The selected Lua library directory no longer exists. Select it again or clear the selection."
            return report
        report["selected_path"] = str(directory)
        report["exists"] = directory.is_dir()
        report["readable"] = bool(report["exists"] and os.access(directory, os.R_OK | os.X_OK))
        if not report["exists"]:
            report["error"] = "The selected Lua library path is not a directory."
            return report
        if not report["readable"]:
            report["error"] = "The selected Lua library directory is not readable."
            return report
        try:
            modules, native, total_bytes = self._scan(directory)
        except (OSError, LuaLibraryError) as exc:
            report["error"] = str(exc)
            return report
        report["discovered_module_count"] = len(modules)
        report["compatible_module_count"] = sum(item["status"] == "compatible" for item in modules.values())
        report["conditional_module_count"] = sum(item["status"] == "conditional" for item in modules.values())
        report["unsupported_module_count"] = sum(item["status"] == "unsupported" for item in modules.values())
        report["modules"] = [modules[name]["public"] for name in sorted(modules)[:MAX_REPORTED_MODULES]]
        report["native_dependencies_unavailable"] = native[:MAX_REPORTED_MODULES]
        required = []
        for name in required_modules:
            module = str(name or "")
            if not valid_module_name(module):
                continue
            if module in modules:
                continue
            if module in RUNTIME_MODULES or module in STANDARD_MODULES:
                continue
            required.append(module)
        report["required_modules"] = sorted(set(required))
        report["missing_modules"] = sorted(set(required))[:MAX_REPORTED_MODULES]
        report["snapshot_size_bytes"] = total_bytes
        return report

    def create_snapshot(self, destination: Path) -> Path:
        stored = self._stored_path()
        directory = self.selected_path()
        if stored is not None and directory is None:
            raise LuaLibraryError(
                "The selected Lua library directory is missing or unreadable. Select it again or clear the selection."
            )
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        if directory is None:
            manifest = {"modules": {}, "runtime_modules": sorted(RUNTIME_MODULES | STANDARD_MODULES)}
        else:
            modules, _native, _total_bytes = self._scan(directory)
            manifest_modules = {}
            for name, item in sorted(modules.items()):
                record = dict(item["public"])
                if item["status"] in ("compatible", "conditional") and item.get("relative_path"):
                    relative = PurePosixPath(item["relative_path"])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise LuaLibraryError("A library module has an unsafe relative path.")
                    source = directory.joinpath(*relative.parts)
                    content = self._read_safe_file(directory, source)
                    target = destination.joinpath(*relative.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                    if os.name != "nt":
                        os.chmod(target, 0o444)
                    record["path"] = relative.as_posix()
                manifest_modules[name] = record
            manifest = {"modules": manifest_modules, "runtime_modules": sorted(RUNTIME_MODULES | STANDARD_MODULES)}
        manifest_path = destination / ".rm7-library-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        if os.name != "nt":
            os.chmod(manifest_path, 0o444)
        return manifest_path

    def _scan(self, directory: Path) -> tuple[dict[str, dict], list[str], int]:
        try:
            root = Path(directory).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LuaLibraryError("The selected Lua library directory is unavailable.") from exc
        if not root.is_dir():
            raise LuaLibraryError("The selected Lua library path is not a directory.")
        if not os.access(root, os.R_OK | os.X_OK):
            raise LuaLibraryError("The selected Lua library directory is not readable.")

        candidates: list[tuple[Path, Path, str, str]] = []
        native_dependencies: list[str] = []
        total_bytes = 0
        for current, dirs, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
            for filename in sorted(filenames):
                source = current_path / filename
                try:
                    metadata = source.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    continue
                suffix = source.suffix.lower()
                if suffix not in NATIVE_EXTENSIONS and suffix != ".lua":
                    continue
                try:
                    relative = source.relative_to(root)
                except ValueError:
                    continue
                name = _module_name(relative)
                if not name:
                    continue
                if suffix in NATIVE_EXTENSIONS:
                    native_dependencies.append(f"{name} ({suffix[1:]})")
                    candidates.append((source, relative, name, "native"))
                    continue
                if len(candidates) >= MAX_MODULES:
                    raise LuaLibraryError(f"The library directory exceeds the {MAX_MODULES}-module scan limit.")
                if metadata.st_size > MAX_MODULE_BYTES:
                    candidates.append((source, relative, name, "oversized"))
                    continue
                total_bytes += metadata.st_size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise LuaLibraryError("The library directory exceeds the 64 MiB safe scan limit.")
                candidates.append((source, relative, name, "lua"))

        grouped: dict[str, list[tuple[Path, Path, str]]] = {}
        for source, relative, name, kind in candidates:
            grouped.setdefault(name, []).append((source, relative, kind))

        modules: dict[str, dict] = {}
        for name, entries in grouped.items():
            if len(entries) > 1:
                modules[name] = self._module_record(name, "unsupported", "Multiple files resolve to this module name.")
                continue
            source, relative, kind = entries[0]
            if kind == "native":
                modules[name] = self._module_record(name, "unsupported", "Native modules are never loaded in the desktop host or Lua runtime.")
                continue
            if kind == "oversized":
                modules[name] = self._module_record(name, "unsupported", "Lua module exceeds the 2 MiB per-module limit.")
                continue
            try:
                content = self._read_safe_file(root, source).decode("utf-8")
            except (OSError, UnicodeError, UnsafePath) as exc:
                modules[name] = self._module_record(name, "unsupported", f"Lua source cannot be safely read: {str(exc)[:120]}")
                continue
            reason = next((message for pattern, message in UNSAFE_SOURCE_REASONS if pattern.search(content)), None)
            if name in UNSAFE_MODULES:
                reason = "LuaJIT FFI is not available in the isolated runtime."
            if reason:
                modules[name] = self._module_record(name, "unsupported", reason, relative)
                continue
            dependencies = sorted(set(REQUIRE_RE.findall(content)))
            missing = [dep for dep in dependencies if valid_module_name(dep) and dep not in RUNTIME_MODULES and dep not in STANDARD_MODULES and dep not in grouped]
            if missing:
                modules[name] = self._module_record(
                    name,
                    "unsupported",
                    "Missing dependency module(s): " + ", ".join(missing[:8]) + ".",
                    relative,
                )
                continue
            blocked = [dep for dep in dependencies if dep in grouped and grouped[dep][0][2] != "lua"]
            if blocked:
                modules[name] = self._module_record(
                    name,
                    "unsupported",
                    "Depends on native or unsupported module(s): " + ", ".join(blocked[:8]) + ".",
                    relative,
                )
                continue
            environment_dependent = bool(ENVIRONMENT_RE.search(content)) or any(dep in CONDITIONAL_MODULES for dep in dependencies)
            status = "conditional" if environment_dependent else "compatible"
            note = "Uses mocked MoonLoader/SA-MP/game APIs; behavior is environment-dependent." if environment_dependent else "Pure Lua source with available dependencies."
            modules[name] = self._module_record(name, status, note, relative)

        return modules, sorted(set(native_dependencies)), total_bytes

    @staticmethod
    def _module_record(name: str, status: str, reason: str, relative: Path | None = None) -> dict:
        public = {"name": name, "status": status, "reason": reason}
        if relative is not None:
            public["relative_path"] = relative.as_posix()
        return {"status": status, "reason": reason, "relative_path": relative.as_posix() if relative else None, "public": public}

    @staticmethod
    def _read_safe_file(root: Path, source: Path) -> bytes:
        resolved_root = Path(root).resolve(strict=True)
        resolved_source = Path(source).resolve(strict=True)
        try:
            relative = resolved_source.relative_to(resolved_root)
        except ValueError as exc:
            raise UnsafePath("A library module escapes the selected directory.") from exc
        if ".." in relative.parts:
            raise UnsafePath("A library module has an unsafe path.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MODULE_BYTES:
                raise LuaLibraryError("A library module changed after validation or exceeds the safe size limit.")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(MAX_MODULE_BYTES + 1)
            if len(content) > MAX_MODULE_BYTES:
                raise LuaLibraryError("A library module exceeds the safe size limit.")
            return content
        finally:
            os.close(descriptor)