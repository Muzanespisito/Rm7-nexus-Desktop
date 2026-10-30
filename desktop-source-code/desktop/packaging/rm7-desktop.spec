# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

spec_dir = Path(SPECPATH).resolve()
project = spec_dir.parents[1]
desktop = project / "desktop"
node_name = "node.exe" if sys.platform == "win32" else "node"
node_exe = project / "vendor" / "node" / node_name
if not node_exe.is_file():
    raise SystemExit(f"Bundled Node.js runtime is missing: {node_exe}")

icon = spec_dir / "assets" / ("rm7nexus.ico" if sys.platform == "win32" else "rm7nexus.png")

datas = [
    (str(desktop / "ui"), "desktop/ui"),
    (str(project / "api" / "DeAmx"), "api/DeAmx"),
    (str(project / "api" / "glue.wasm"), "api"),
    (str(project / "lib" / "deamx.js"), "lib"),
    (str(project / "lib" / "grab_detector_engine.py"), "lib"),
    (str(project / "grab-detector-sandbox"), "grab-detector-sandbox"),
    (str(desktop / "engines" / "amx_runner.mjs"), "desktop/engines"),
    (str(project / "node_modules" / "wasmoon"), "node_modules/wasmoon"),
    (str(project / "background.gif"), "."),
]
if icon.is_file():
    datas.append((str(icon), "desktop/packaging/assets"))

hiddenimports = []
for package in ("secretstorage", "jeepney"):
    try:
        hiddenimports.extend(collect_submodules(package))
        datas.extend(collect_data_files(package))
    except Exception:
        pass

for required in (
    project / "api" / "DeAmx",
    project / "api" / "glue.wasm",
    project / "lib" / "deamx.js",
    project / "lib" / "grab_detector_engine.py",
    project / "grab-detector-sandbox" / "runtime.mjs",
    project / "grab-detector-sandbox" / "sandbox-prelude.lua",
    project / "grab-detector-sandbox" / "vendor" / "wasmoon" / "index.js",
    project / "grab-detector-sandbox" / "vendor" / "wasmoon" / "glue.wasm",
    project / "node_modules" / "wasmoon" / "package.json",
    desktop / "ui" / "index.html",
):
    if not required.exists():
        raise SystemExit(f"Required desktop runtime file is missing: {required}")

a = Analysis(
    [str(spec_dir / "entry.py")],
    pathex=[str(project)],
    binaries=[(str(node_exe), "vendor/node")],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "PyQt5", "PyQt6", "PySide2", "PySide6"],
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
