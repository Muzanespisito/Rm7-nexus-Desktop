# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

spec_dir = Path(SPECPATH).resolve()
project = spec_dir.parents[1]
stage = Path(os.environ["RM7_WINDOWS_STAGE"]).resolve()
icon = spec_dir / "assets" / "rm7nexus.ico"

if not stage.is_dir():
    raise SystemExit(f"Sanitized Windows staging directory is missing: {stage}")
if not (stage / "vendor" / "node" / "node.exe").is_file():
    raise SystemExit("The staged Node.js x64 runtime is missing.")

datas = []
for path in sorted(stage.rglob("*")):
    if not path.is_file():
        continue
    relative = path.relative_to(stage)
    if relative.as_posix() == "vendor/node/node.exe":
        continue
    destination = "." if relative.parent.as_posix() == "." else relative.parent.as_posix()
    datas.append((str(path), destination))

hiddenimports = ["cryptography"]
try:
    datas.extend(collect_data_files("cryptography"))
except Exception:
    pass

a = Analysis(
    [str(spec_dir / "entry_windows.py")],
    pathex=[str(project), str(stage)],
    binaries=[(str(stage / "vendor" / "node" / "node.exe"), "vendor/node")],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "PyQt5", "PyQt6", "PySide2", "PySide6", "gi"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RM7NexusDesktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon) if icon.is_file() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="RM7NexusDesktop",
)
