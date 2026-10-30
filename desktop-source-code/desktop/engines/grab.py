from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import threading
from importlib.machinery import SourcelessFileLoader
from pathlib import Path
from typing import Callable

from ..config import Config
from ..security.lua_libraries import LuaLibraryCatalog
from .base import EngineCancelled, EngineError, EngineTimeout, minimal_env, run_process

LOCAL_RUNTIME_LABEL = "Local Bubblewrap Lua Runtime"


class GrabEngine:
    name = "grab-detector"
    label = "Grab Detector"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.engine_path = config.project_root / "lib" / "grab_detector_engine.py"
        self.sandbox_root = config.project_root / "grab-detector-sandbox"
        self._module = None

    @property
    def engine_candidates(self) -> tuple[Path, Path]:
        return (self.engine_path, self.engine_path.with_suffix(".pyc"))

    def _load(self):
        if self._module is not None:
            return self._module
        path = next((candidate for candidate in self.engine_candidates if candidate.is_file()), None)
        if path is None:
            raise EngineError("The Grab Detector engine is missing.")
        if path.suffix == ".pyc":
            loader = SourcelessFileLoader("rm7_desktop_grab_engine", str(path))
            spec = importlib.util.spec_from_loader("rm7_desktop_grab_engine", loader)
        else:
            spec = importlib.util.spec_from_file_location("rm7_desktop_grab_engine", path)
        if spec is None or spec.loader is None:
            raise EngineError("The Grab Detector engine could not be loaded.")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._module = module
        return module

    def validate(self, require_sandbox: bool = False) -> None:
        engine_path = next((candidate for candidate in self.engine_candidates if candidate.is_file()), self.engine_path)
        paths = [engine_path]
        if require_sandbox:
            paths.extend(
                (
                    self.sandbox_root / "runtime.mjs",
                    self.sandbox_root / "sandbox-prelude.lua",
                    self.sandbox_root / "vendor" / "wasmoon" / "index.js",
                    self.sandbox_root / "vendor" / "wasmoon" / "glue.wasm",
                )
            )
        for path in paths:
            if not path.is_file():
                raise EngineError(f"Required Grab Detector file is missing: {path}")

    def _unavailable(self, code: str, message: str, coverage: list[str] | None = None) -> dict:
        module = self._load()
        return module._sandbox_result(
            "unavailable",
            code,
            message,
            coverage_notes=coverage or ["The file was not executed. Static results remain available."],
        )

    def _copy_assets(self, root: Path) -> None:
        shutil.copy2(self.sandbox_root / "runtime.mjs", root / "runtime.mjs")
        shutil.copy2(self.sandbox_root / "sandbox-prelude.lua", root / "sandbox-prelude.lua")
        vendor = root / "vendor" / "wasmoon"
        vendor.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.sandbox_root / "vendor" / "wasmoon" / "index.js", vendor / "index.js")
        shutil.copy2(self.sandbox_root / "vendor" / "wasmoon" / "glue.wasm", vendor / "glue.wasm")

    def _bwrap_command(self, sandbox: Path, node_binary: Path, bwrap: str, extra_env: dict[str, str]) -> list[str]:
        command = [
            bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        for path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(path).exists():
                command.extend(["--ro-bind", path, path])
        node_target = node_binary
        if not str(node_binary).startswith(("/usr/", "/bin/")):
            command.extend(["--ro-bind", str(node_binary.parent), "/node"])
            node_target = Path("/node") / node_binary.name
        command.extend(
            [
                "--bind",
                str(sandbox),
                "/sandbox",
                "--dir",
                "/libraries",
                "--ro-bind",
                str(sandbox / "libraries"),
                "/libraries",
                "--chdir",
                "/sandbox",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "TMPDIR",
                "/tmp",
                "--setenv",
                "LANG",
                "C",
            ]
        )
        for key, value in extra_env.items():
            command.extend(["--setenv", str(key), str(value)])
        command.extend(
            [
                str(node_target),
                "--max-old-space-size=256",
                "runtime.mjs",
            ]
        )
        return command

    def _local_dynamic(self, source: str, filename: str, options: dict | None = None) -> dict:
        options = options or {}
        if sys.platform != "linux":
            return self._unavailable(
                "LOCAL_ISOLATION_UNAVAILABLE",
                "Performed runtime isolation is only available on Linux. Windows fails closed.",
                ["The file was not executed. Use Normal static analysis or a supported Linux host."],
            )
        bwrap = shutil.which("bwrap")
        if not bwrap:
            return self._unavailable(
                "BUBBLEWRAP_UNAVAILABLE",
                "Bubblewrap is not installed, so the local Lua runtime was not started.",
                ["The file was not executed. Install bubblewrap to enable Performed mode on Linux."],
            )
        node_binary = Path(self.config.node_binary or "").resolve()
        if not node_binary.is_file():
            return self._unavailable(
                "NODE_UNAVAILABLE",
                "The bundled Node.js runtime is missing, so the local Lua runtime was not started.",
            )
        module = self._load()
        source_bytes = source.encode("utf-8", "replace")
        if len(source_bytes) > module.MAX_UPLOAD_BYTES:
            return self._unavailable(
                "DYNAMIC_INPUT_TOO_LARGE",
                "The source is too large for local dynamic analysis.",
            )
        work_root = Path(str(options.get("work_dir") or tempfile.gettempdir()))
        sandbox = Path(tempfile.mkdtemp(prefix=".grab-sandbox-", dir=str(work_root)))
        catalog = LuaLibraryCatalog(self.config)
        library_report = catalog.report(catalog.required_modules(source))

        def with_library(result: dict) -> dict:
            result["library"] = library_report
            return result

        try:
            self._copy_assets(sandbox)
            try:
                library_manifest = catalog.create_snapshot(sandbox / "libraries")
            except Exception as exc:
                return with_library(
                    self._unavailable(
                        "LIBRARY_UNAVAILABLE",
                        str(exc)[:300] or "The selected Lua library folder is unavailable.",
                        ["The file was not executed. The selected library selection must be fixed or cleared."],
                    )
                )
            (sandbox / "input").mkdir()
            (sandbox / "input" / "scan.lua").write_text(source, encoding="utf-8", errors="replace")
            timeout = module._sandbox_kill_after(options)
            lines: list[str] = []

            def handle(line: str) -> None:
                if len(lines) < 20000:
                    lines.append(line)

            extra_env = {
                "GD_MAX_REQUESTS": str(min(module.MAX_REQUESTS, 500)),
                "GD_MAX_BODY": "8192",
                "GD_SOURCE_PATH": "input/scan.lua",
                "GD_PRELUDE_PATH": "sandbox-prelude.lua",
                "GD_REQUESTS_PATH": "requests.ndjson",
                "GD_RESULT_PATH": "result.json",
                "GD_LIBRARY_ROOT": "/libraries",
                "GD_LIBRARY_MANIFEST": "/libraries/" + library_manifest.name,
                "GD_FILE_NAME": module.safe_filename(filename),
                "GD_LUA_BUDGET_MS": str(module.SANDBOX_LUA_BUDGET_MS),
                "GD_EVENT_BUDGET_MS": str(module.SANDBOX_EVENT_BUDGET_MS),
                "GD_SIMULATION_BUDGET_MS": str(module.SANDBOX_SIMULATION_BUDGET_MS),
                "GD_MAX_WAIT_CALLS": str(module.SANDBOX_MAX_WAIT_CALLS),
                "GD_MAX_VIRTUAL_MS": str(module.SANDBOX_MAX_VIRTUAL_MS),
                "GD_MAX_INSTRUCTIONS": str(module.SANDBOX_MAX_INSTRUCTIONS),
            }
            command = self._bwrap_command(sandbox, node_binary, bwrap, extra_env)
            env = minimal_env({"PATH": "/usr/bin:/bin"})
            try:
                outcome = run_process(
                    command,
                    cwd=sandbox,
                    timeout=timeout,
                    cancel_event=options.get("cancel_event") or threading.Event(),
                    on_line=handle,
                    env=env,
                )
            except EngineTimeout:
                captured = self._read_captured(module, sandbox, lines)
                return with_library(module._sandbox_result(
                    "failed",
                    "EXECUTION_TIMEOUT",
                    "Local Lua execution exceeded the time limit.",
                    requests=captured,
                    timed_out=True,
                    runtime=LOCAL_RUNTIME_LABEL,
                    coverage_notes=[
                        "Execution was stopped at the local Bubblewrap timeout.",
                        "Requests captured before the timeout are included.",
                    ],
                ))
            except EngineCancelled:
                raise
            except EngineError:
                captured = self._read_captured(module, sandbox, lines)
                return with_library(module._sandbox_result(
                    "failed",
                    "LOCAL_SANDBOX_FAILED",
                    "The local Bubblewrap Lua runtime could not be started.",
                    requests=captured,
                    runtime=LOCAL_RUNTIME_LABEL,
                    coverage_notes=["The file was not executed inside the local runtime."],
                ))

            captured, final = module._parse_sandbox_output("\n".join(lines))
            captured = module._merge_sandbox_requests(captured, self._read_captured(module, sandbox, []))
            file_final = self._read_result(sandbox)
            if final is None:
                final = file_final
            if final is None:
                return with_library(module._sandbox_result(
                    "incomplete" if outcome.returncode == 0 else "failed",
                    "LOCAL_SANDBOX_NO_RESULT",
                    "The local Lua runtime ended without a complete result.",
                    requests=captured,
                    runtime=LOCAL_RUNTIME_LABEL,
                    coverage_notes=["Requests captured before the runtime ended are included."],
                ))
            status = str(final.get("status") or "incomplete")
            if status not in ("completed", "incomplete", "failed", "timeout"):
                status = "incomplete"
            timed_out = bool(final.get("timed_out"))
            execution_completed = bool(final.get("execution_completed")) and not timed_out
            if status in ("completed", "timeout") and not execution_completed:
                status = "incomplete" if status != "timeout" else "timeout"
            notes = list(final.get("coverage_notes") or [])
            notes.append("Executed inside a local Bubblewrap namespace with outbound networking unshared.")
            return with_library(module._sandbox_result(
                status,
                final.get("error_code"),
                module._redact_text(final.get("error"), 300) if final.get("error") else None,
                requests=module._merge_sandbox_requests(final.get("requests") or [], captured),
                execution_completed=execution_completed,
                timed_out=timed_out,
                runtime=str(final.get("runtime") or LOCAL_RUNTIME_LABEL)[:80],
                coverage_notes=notes,
                metadata=final.get("metadata"),
                unsupported_api=final.get("unsupported_api"),
                compatibility=final.get("compatibility"),
                simulated_inputs=final.get("simulated_inputs"),
                observations=final.get("observations"),
                events_run=final.get("events_run"),
                runtime_limits=final.get("runtime_limits"),
                missing_module=final.get("missing_module"),
            ))
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

    def _read_captured(self, module, sandbox: Path, lines: list[str]) -> list:
        captured, _ = module._parse_sandbox_output("\n".join(lines))
        try:
            text = (sandbox / "requests.ndjson").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        file_captured, _ = module._parse_sandbox_output(text)
        return module._merge_sandbox_requests(captured, file_captured)

    def _read_result(self, sandbox: Path) -> dict | None:
        try:
            value = json.loads((sandbox / "result.json").read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def _public_report(self, module, value):
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                if key in ("raw_url", "rawUrl") and isinstance(item, str):
                    cleaned[key] = module.redact_url(item)
                else:
                    cleaned[key] = self._public_report(module, item)
            return cleaned
        if isinstance(value, list):
            return [self._public_report(module, item) for item in value]
        return value

    def run(
        self,
        input_path: Path,
        output_path: Path,
        work_dir: Path,
        on_progress: Callable[[int, str], None],
        cancel_event: threading.Event,
        options: dict | None = None,
    ) -> dict:
        mode = str((options or {}).get("mode") or "normal").lower()
        if mode not in ("normal", "performed"):
            raise EngineError("Unknown Grab Detector mode.")
        module = self._load()
        self.validate(require_sandbox=mode == "performed")
        on_progress(8, "Reading the Lua file")
        try:
            data = Path(input_path).read_bytes()
        except OSError as exc:
            raise EngineError("The Lua file could not be read.") from exc
        try:
            module.classify_file(data, input_path.name)
        except module.FileValidationError as exc:
            raise EngineError(str(exc)) from exc
        on_progress(20, "Running static analysis")
        dynamic_client = self._local_dynamic if mode == "performed" else None
        scan_options = {"work_dir": str(work_dir), "cancel_event": cancel_event}
        on_progress(35, "Starting the isolated Lua runtime" if mode == "performed" else "Finalizing static analysis")
        try:
            report = module.analyze(
                data,
                input_path.name,
                mode=mode,
                options=scan_options,
                dynamic_client=dynamic_client,
            )
        except EngineCancelled:
            raise
        except Exception as exc:
            raise EngineError("Grab Detector analysis failed: " + str(exc)[:300]) from exc
        on_progress(92, "Writing the analysis report")
        report = self._public_report(module, report)
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        size = output_path.stat().st_size
        if size <= 0:
            raise EngineError("Grab Detector produced an empty report.")
        threat = report.get("threat") if isinstance(report.get("threat"), dict) else {}
        dynamic = report.get("dynamic_analysis") if isinstance(report.get("dynamic_analysis"), dict) else {}
        meta = {
            "overall_status": report.get("overall_status"),
            "threat_level": threat.get("level"),
            "threat_score": threat.get("score"),
            "static_url_count": report.get("static_url_count"),
            "http_requests_captured": report.get("http_requests_captured"),
            "dynamic_status": dynamic.get("status"),
            "mode": mode,
        }
        log_lines = [
            f"Mode: {mode}",
            f"Overall status: {meta['overall_status']}",
            f"Threat: {meta['threat_level']} ({meta['threat_score']})",
            f"Static URLs: {meta['static_url_count']}",
            f"Captured requests: {meta['http_requests_captured']}",
            f"Dynamic runtime: {meta['dynamic_status']}",
        ]
        on_progress(100, "Analysis complete")
        return {
            "output_path": str(output_path),
            "output_name": output_path.name,
            "size": size,
            "meta": meta,
            "log": "\n".join(log_lines),
        }
