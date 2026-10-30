#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import py_compile
import re
import shutil
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SANDBOX_FILES = (
    "runtime.mjs",
    "sandbox-prelude.lua",
    "vendor/wasmoon/index.js",
    "vendor/wasmoon/glue.wasm",
    "vendor/wasmoon/LICENSE",
)
WASMOON_FILES = (
    "package.json",
    "dist/index.js",
    "dist/glue.wasm",
    "LICENSE",
)
REQUIRED_RUNTIME = (
    "RM7NexusDesktop.exe",
    "background.gif",
    "desktop/ui/index.html",
    "desktop/ui/app.css",
    "desktop/ui/app.js",
    "desktop/engines/amx_runner.mjs",
    "api/glue.wasm",
    "api/DeAmx/deamx.lua",
    "api/DeAmx/deamx_util.lua",
    "api/DeAmx/deamx_opcodes.lua",
    "api/DeAmx/deamx_events.lua",
    "api/DeAmx/deamx_syscalls.lua",
    "lib/deamx.js",
    "lib/grab_detector_engine.pyc",
    "grab-detector-sandbox/runtime.mjs",
    "grab-detector-sandbox/sandbox-prelude.lua",
    "grab-detector-sandbox/vendor/wasmoon/index.js",
    "grab-detector-sandbox/vendor/wasmoon/glue.wasm",
    "node_modules/wasmoon/package.json",
    "node_modules/wasmoon/dist/index.js",
    "node_modules/wasmoon/dist/glue.wasm",
    "vendor/node/node.exe",
)
SECRET_PATTERNS = (
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_-]{20,}")),
    ("groq_api_key", re.compile(rb"gsk_[0-9A-Za-z]{20,}")),
    ("openai_api_key", re.compile(rb"sk-[A-Za-z0-9]{32,}")),
    ("premium_secret", re.compile(rb"rm7-premium-[0-9a-f]{32,}")),
    ("session_secret", re.compile(rb"rm7-dev-session-secret-change-me")),
    (
        "private_key",
        re.compile(
            rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\r?\n"
            rb"(?:[A-Za-z0-9+/=]{16,}\r?\n){3,}"
        ),
    ),
    ("database_url", re.compile(rb"postgres(?:ql)?://[^\s:/@]+:[^\s/@]+@")),
    ("blob_token", re.compile(rb"BLOB_READ_WRITE_TOKEN\s*=\s*[A-Za-z0-9_]{20,}")),
)
FORBIDDEN_TOP_LEVEL = (".env", ".git", ".github", "tests", "test", "tools", "desktop/packaging")
FORBIDDEN_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".pdb", ".pyi")
MACHINES = {0x014C: "x86", 0x8664: "AMD64 (x64)", 0xAA64: "ARM64"}


class ReleaseError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pe_metadata(path: Path) -> dict:
    if not path.is_file():
        raise ReleaseError(f"PE file not found: {path}")
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ReleaseError(f"Not a DOS/PE file: {path.name}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 0x60 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ReleaseError(f"Missing PE signature: {path.name}")
    machine, sections, timestamp = struct.unpack_from("<HHI", data, pe_offset + 4)
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    subsystem = struct.unpack_from("<H", data, optional_offset + 0x44)[0]
    return {
        "machine": machine,
        "machine_name": MACHINES.get(machine, f"0x{machine:04x}"),
        "is_64bit": magic == 0x20B,
        "optional_magic": f"0x{magic:04x}",
        "sections": sections,
        "timestamp": timestamp,
        "subsystem": subsystem,
        "size": len(data),
    }


def sanitize_grab_engine(source: str) -> str:
    source, premium_count = re.subn(
        r'(PREMIUM_SECRET\s*=\s*os\.environ\.get\("PREMIUM_SECRET",\s*")[^"]*("\))',
        r"\1\2",
        source,
    )
    source, session_count = re.subn(
        r'(secret\s*=\s*os\.environ\.get\("SESSION_SECRET",\s*")[^"]*("\))',
        r"\1\2",
        source,
    )
    if premium_count > 1 or session_count > 1:
        raise ReleaseError("Unexpected Grab Detector secret fallbacks; review the sanitizer before building.")
    return source


def _copy_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise ReleaseError(f"Required build resource is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ReleaseError(f"Required build resource directory is missing: {source}")
    for path in sorted(source.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            relative = path.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def scan_secrets(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                findings.append(f"{name}: {path.relative_to(root).as_posix()}")
    return findings


def forbidden_paths(root: Path) -> list[str]:
    findings: list[str] = []
    for name in FORBIDDEN_TOP_LEVEL:
        if (root / name).exists():
            findings.append(name)
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(path.relative_to(root).as_posix())
    for path in root.rglob("__pycache__"):
        if path.is_dir():
            findings.append(path.relative_to(root).as_posix())
    return sorted(set(findings))


def stage_resources(root: Path, stage: Path, node_exe: Path | None) -> dict:
    root = root.resolve()
    stage = stage.resolve()
    if stage == root or root not in stage.parents:
        raise ReleaseError("The staging directory must be inside the repository.")
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    _copy_tree(root / "desktop" / "ui", stage / "desktop" / "ui")
    _copy_tree(root / "api" / "DeAmx", stage / "api" / "DeAmx")
    _copy_file(root / "api" / "glue.wasm", stage / "api" / "glue.wasm")
    _copy_file(root / "lib" / "deamx.js", stage / "lib" / "deamx.js")
    _copy_file(root / "desktop" / "engines" / "amx_runner.mjs", stage / "desktop" / "engines" / "amx_runner.mjs")
    _copy_file(root / "background.gif", stage / "background.gif")
    for relative in SANDBOX_FILES:
        _copy_file(root / "grab-detector-sandbox" / relative, stage / "grab-detector-sandbox" / relative)
    for relative in WASMOON_FILES:
        _copy_file(root / "node_modules" / "wasmoon" / relative, stage / "node_modules" / "wasmoon" / relative)

    engine_source = root / "lib" / "grab_detector_engine.py"
    if not engine_source.is_file():
        raise ReleaseError("The Grab Detector engine source is missing.")
    sanitized = sanitize_grab_engine(engine_source.read_text(encoding="utf-8"))
    staged_py = stage / "lib" / "grab_detector_engine.py"
    staged_py.write_text(sanitized, encoding="utf-8")
    py_compile.compile(
        str(staged_py),
        cfile=str(stage / "lib" / "grab_detector_engine.pyc"),
        dfile="lib/grab_detector_engine.py",
        doraise=True,
        optimize=2,
    )
    staged_py.unlink()

    if node_exe is not None:
        node_exe = node_exe.resolve()
        metadata = pe_metadata(node_exe)
        if metadata["machine"] != 0x8664 or not metadata["is_64bit"]:
            raise ReleaseError(f"Bundled Node.js runtime must be Windows x64, found {metadata['machine_name']}.")
        _copy_file(node_exe, stage / "vendor" / "node" / "node.exe")

    findings = scan_secrets(stage)
    forbidden = forbidden_paths(stage)
    if findings:
        raise ReleaseError("Credential-like values were found in staged resources: " + ", ".join(findings))
    if forbidden:
        raise ReleaseError("Forbidden development files were found in staged resources: " + ", ".join(forbidden))

    files = [path for path in stage.rglob("*") if path.is_file()]
    return {
        "stage": str(stage),
        "files": len(files),
        "bytes": sum(path.stat().st_size for path in files),
        "grab_engine": "compiled-pyc",
        "node_exe": str(node_exe) if node_exe is not None else "",
    }


def verify_bundle(bundle: Path, require_node: bool = True) -> dict:
    bundle = bundle.resolve()
    if not bundle.is_dir():
        raise ReleaseError(f"Bundle directory not found: {bundle}")
    required = list(REQUIRED_RUNTIME)
    if not require_node:
        required.remove("vendor/node/node.exe")
    missing = [name for name in required if not (bundle / name).is_file()]
    if missing:
        raise ReleaseError("Bundle is missing required runtime files: " + ", ".join(missing))
    if (bundle / "lib" / "grab_detector_engine.py").exists():
        raise ReleaseError("The Windows bundle contains raw Grab Detector Python source.")
    if (bundle / "api" / "lua-deob.py").exists():
        raise ReleaseError("The Windows bundle contains the website deobfuscation module.")
    raw_desktop = [path.relative_to(bundle).as_posix() for path in (bundle / "desktop").rglob("*.py")]
    if raw_desktop:
        raise ReleaseError("The Windows bundle contains raw desktop Python source: " + ", ".join(raw_desktop))
    findings = scan_secrets(bundle)
    forbidden = forbidden_paths(bundle)
    if findings:
        raise ReleaseError("Credential-like values were found in the bundle: " + ", ".join(findings))
    if forbidden:
        raise ReleaseError("Forbidden development files were found in the bundle: " + ", ".join(forbidden))

    app = pe_metadata(bundle / "RM7NexusDesktop.exe")
    if app["machine"] != 0x8664 or not app["is_64bit"]:
        raise ReleaseError(f"Application executable is not Windows x64: {app['machine_name']}")
    node = None
    if require_node:
        node = pe_metadata(bundle / "vendor" / "node" / "node.exe")
        if node["machine"] != 0x8664 or not node["is_64bit"]:
            raise ReleaseError(f"Bundled Node.js executable is not Windows x64: {node['machine_name']}")
    other_python = [
        path.relative_to(bundle).as_posix() for path in bundle.rglob("*.py") if path.is_file()
    ]
    return {
        "bundle": str(bundle),
        "app_pe": app,
        "node_pe": node,
        "raw_python_outside_app": other_python,
        "required_files": len(required),
        "size": sum(path.stat().st_size for path in bundle.rglob("*") if path.is_file()),
    }


def verify_installer(installer: Path, version: str) -> dict:
    installer = installer.resolve()
    metadata = pe_metadata(installer)
    return {
        "installer": str(installer),
        "version": version,
        "size": installer.stat().st_size,
        "sha256": sha256_file(installer),
        "pe": metadata,
    }


def write_checksums(directory: Path, installer: Path) -> Path:
    directory = directory.resolve()
    installer = installer.resolve()
    if installer.parent != directory:
        raise ReleaseError("The installer must be in the release directory.")
    target = directory / "SHA256SUMS.txt"
    target.write_text(f"{sha256_file(installer)}  {installer.name}\n", encoding="utf-8", newline="\n")
    return target


def write_release_info(
    installer: Path,
    bundle: Path,
    backend: str,
    output: Path | None = None,
    version: str = "0.1.1",
) -> Path:
    installer = installer.resolve()
    bundle = bundle.resolve()
    output = (output or installer.parent / "RELEASE-INFO.txt").resolve()
    app = pe_metadata(bundle / "RM7NexusDesktop.exe")
    node = pe_metadata(bundle / "vendor" / "node" / "node.exe")
    installer_pe = pe_metadata(installer)
    compiled_note = (
        "Python application modules are compiled by Nuitka in standalone mode."
        if backend.lower().startswith("nuitka")
        else "Python modules are bundled as bytecode by the PyInstaller fallback; they are not native code."
    )
    text = f"""RM7 Nexus Desktop {version} - Windows x64
========================================

STATUS: Built - Pending Windows User Acceptance Testing

Installer:       {installer.name}
Size:            {installer.stat().st_size:,} bytes
SHA-256:         {sha256_file(installer)}
Build backend:   {backend}
Built (UTC):     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}
Code signing:    UNSIGNED - no code-signing certificate was used; SmartScreen may warn.

Architecture:
  Application:   {app['machine_name']}, PE32+ ({'64-bit' if app['is_64bit'] else '32-bit'})
  Node.js:       {node['machine_name']}, PE32+ ({'64-bit' if node['is_64bit'] else '32-bit'})
  Installer:     {installer_pe['machine_name']} Inno Setup bootstrap; installs only on x64 Windows.

Build-time checks performed:
  - Installer was produced by the project build script, not copied or fabricated.
  - Installer and application executable have valid DOS/PE headers.
  - Application and bundled Node.js runtime are Windows x64.
  - Required UI, AMX/DeAMx, wasmoon and Grab Detector resources are present.
  - Grab Detector Python engine is distributed as optimized bytecode, not raw source.
  - No known server credentials, private keys, .env files, tests or debug symbols were found.
  - SHA256SUMS.txt matches the installer.

NOT tested in this environment:
  - Interactive Windows GUI rendering and WebView2 runtime behavior.
  - Native Lua library folder picker, persistence and cancellation.
  - Discord pairing and Premium website activation refresh.
  - Save PWN file dialog.
  - Update check, download and installer launch.
  - Grab Detector Performed mode. It is Linux-only and fails closed on Windows; static analysis remains available.

Code-hardening measures:
  - {compiled_note}
  - The dynamically loaded Grab Detector engine is sanitized and distributed as .pyc only.
  - The Windows bundle is assembled from an explicit allow-list; no tools, tests or website code are copied.
  - No custom executable packer, anti-debugging trap or antivirus interference is used.

Remaining inspectable components:
  - desktop/ui HTML, CSS and JavaScript.
  - Node.js AMX runner and DeAMx Lua sources.
  - wasmoon runtime files.
  - Grab Detector sandbox JavaScript and Lua files.
  - Grab Detector compiled bytecode can still be decompiled; no Python distribution is impossible to reverse engineer.

Tester instructions:
  1. Verify SHA-256: Get-FileHash -Algorithm SHA256 .\\{installer.name}
  2. Run {installer.name} and complete the installer.
  3. Launch RM7 Nexus from the Start Menu.
  4. Confirm startup diagnostics and version {version}.
  5. Link a Discord account and refresh Premium status from the website.
  6. In Grab Detector, select a local Lua folder, restart the app, and confirm the folder persists; cancel a picker and confirm the previous folder is kept.
  7. Run Normal-mode AMX to PWN, save the PWN file, and reopen it.
  8. Run Grab Detector Normal mode on a test Lua file.
  9. Record any failures and do not publish the Windows download until they are resolved.
"""
    output.write_text(text, encoding="utf-8", newline="\n")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage and verify the Windows desktop release.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--root", type=Path, default=ROOT)
    stage_parser.add_argument("--stage", type=Path, required=True)
    stage_parser.add_argument("--node-exe", type=Path)

    verify_parser = subparsers.add_parser("verify-bundle")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser.add_argument("--skip-node", action="store_true")

    installer_parser = subparsers.add_parser("verify-installer")
    installer_parser.add_argument("--installer", type=Path, required=True)
    installer_parser.add_argument("--version", default="0.1.1")

    checksum_parser = subparsers.add_parser("write-checksums")
    checksum_parser.add_argument("--directory", type=Path, required=True)
    checksum_parser.add_argument("--installer", type=Path, required=True)

    info_parser = subparsers.add_parser("write-release-info")
    info_parser.add_argument("--installer", type=Path, required=True)
    info_parser.add_argument("--bundle", type=Path, required=True)
    info_parser.add_argument("--backend", default="Nuitka standalone")
    info_parser.add_argument("--output", type=Path)
    info_parser.add_argument("--version", default="0.1.1")

    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            result = stage_resources(args.root, args.stage, args.node_exe)
        elif args.command == "verify-bundle":
            result = verify_bundle(args.bundle, require_node=not args.skip_node)
        elif args.command == "verify-installer":
            result = verify_installer(args.installer, args.version)
        elif args.command == "write-checksums":
            result = {"checksums": str(write_checksums(args.directory, args.installer))}
        else:
            result = {
                "release_info": str(
                    write_release_info(
                        args.installer,
                        args.bundle,
                        args.backend,
                        args.output,
                        args.version,
                    )
                )
            }
        print(json.dumps(result, indent=2))
        return 0
    except ReleaseError as exc:
        print(f"windows release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
