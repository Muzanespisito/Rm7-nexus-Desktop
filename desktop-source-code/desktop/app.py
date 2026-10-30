from __future__ import annotations

import platform
import sys
import threading
import time
from pathlib import Path

from .auth.client import AccountServiceUnavailable, AuthError, DesktopAuthClient
from .auth.credentials import build_credential_store
from .config import APP_NAME, Config
from .diagnostics import DiagnosticsReport, run_diagnostics
from .engines.amx import AmxEngine
from .engines.grab import GrabEngine
from .jobs.manager import Job, JobManager
from .logging_setup import StructuredLogger
from .security.file_save import (
    SaveError,
    open_job_output_folder,
    save_job_output,
)
from .security.lua_libraries import LuaLibraryCatalog
from .updates import UpdateDecision, UpdateError, UpdateService

NORMAL_MAX = 2 * 1024 * 1024
PERFORMED_MAX = 20 * 1024 * 1024
GRAB_MAX = 3 * 1024 * 1024

MISSION_META = {
    "amx": {
        "label": "AMX to PWN",
        "description": "Decompile SA-MP AMX bytecode into Pawn source locally.",
        "implemented": True,
        "modes": {
            "normal": {"label": "Normal", "max_bytes": NORMAL_MAX, "premium": False},
            "performed": {"label": "Performed", "max_bytes": PERFORMED_MAX, "premium": True},
        },
    },
    "grab-detector": {
        "label": "Grab Detector",
        "description": "Inspect Lua files locally for request evidence and isolated runtime behavior.",
        "implemented": True,
        "modes": {
            "normal": {"label": "Normal", "max_bytes": GRAB_MAX, "premium": False},
            "performed": {"label": "Performed", "max_bytes": GRAB_MAX, "premium": True},
        },
    },
}


class PolicyError(RuntimeError):
    def __init__(self, message: str, code: str, status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class DesktopApp:
    def __init__(self, config: Config, logger: StructuredLogger | None = None) -> None:
        self.config = config
        self.config.ensure_dirs()
        self.logger = logger or StructuredLogger(config.logs_dir / "desktop.jsonl")
        self.jobs = JobManager(config.jobs_dir, concurrency=config.job_concurrency)
        self.auth = DesktopAuthClient(config, build_credential_store())
        self.updates = UpdateService(config, self.logger)
        self.amx = AmxEngine(config)
        self.grab = GrabEngine(config)
        self.lua_libraries = LuaLibraryCatalog(config)
        self._lock = threading.RLock()
        self._report: DiagnosticsReport | None = None
        self._report_at = 0.0
        self._account: dict | None = None
        self._account_at = 0.0
        self._shutdown = threading.Event()

    def refresh_checks(self, include_network: bool = True, force: bool = True) -> DiagnosticsReport:
        with self._lock:
            age = time.time() - self._report_at
            if not force and self._report is not None and age < 120:
                return self._report
        report = run_diagnostics(self.config, include_network=include_network)
        with self._lock:
            self._report = report
            self._report_at = time.time()
        self.logger.event(
            "diagnostics.complete",
            ok=report.ok,
            required_failures=[check.id for check in report.required_failed],
            checks=len(report.environment) + len(report.compatibility) + len(report.network),
        )
        return report

    def get_report(self) -> DiagnosticsReport:
        with self._lock:
            report = self._report
        if report is None:
            report = self.refresh_checks()
        return report

    def refresh_update(self, force: bool = False) -> UpdateDecision:
        decision = self.updates.check(force=force)
        self.logger.event(
            "update.refresh",
            status=decision.status,
            current=decision.current_version,
            latest=decision.latest_version,
            blocking=decision.blocking,
        )
        return decision

    def update(self) -> UpdateDecision:
        return self.updates.snapshot()

    def download_update(self) -> UpdateDecision:
        session = self.auth.load_session()
        if not session:
            raise UpdateError("Sign in to the desktop app to download updates.", "AUTH_REQUIRED", 401)
        decision = self.updates.download(session.token)
        self.logger.event(
            "update.download",
            status=decision.status,
            version=decision.latest_version,
            platform=decision.artifact.platform if decision.artifact else "",
        )
        return decision

    def install_update(self) -> None:
        decision = self.updates.snapshot()
        if not decision.artifact:
            raise UpdateError("No installer is available for this platform.", "RELEASE_UNAVAILABLE", 404)
        self.updates.install(self.config.updates_dir / decision.artifact.name)
        self.logger.event("update.install", version=decision.latest_version)

    def refresh_account(self) -> dict:
        state = self.auth.account_state()
        with self._lock:
            self._account = state
            self._account_at = time.time()
        self.logger.event(
            "account.refresh",
            linked=state.get("linked"),
            online=state.get("online"),
            authenticated=state.get("authenticated"),
            premium=state.get("premium"),
        )
        return state

    def account(self) -> dict:
        with self._lock:
            state = self._account
            age = time.time() - self._account_at
        if state is None:
            return self.refresh_account()
        if age > 60 and state.get("linked"):
            return self.refresh_account()
        return state

    def start_pairing(self, device_name: str) -> dict:
        result = self.auth.start_pairing(device_name)
        self.logger.event("account.pairing_started", user_code=result["user_code"])
        return result

    def poll_pairing(self, request_id: str) -> dict:
        result = self.auth.poll_pairing(request_id)
        if result.get("status") == "approved":
            self.refresh_account()
        return result

    def logout(self) -> None:
        self.auth.logout()
        with self._lock:
            self._account = {
                "linked": False,
                "online": True,
                "authenticated": False,
                "premium": False,
                "user": None,
                "missions": {},
                "warning": "",
            }
            self._account_at = time.time()
        self.logger.event("account.logout")

    def _check_status(self, check_id: str) -> str:
        report = self.get_report()
        for check in [*report.environment, *report.compatibility, *report.network]:
            if check.id == check_id:
                return check.status
        return "skip"

    def missions(self) -> dict:
        account = self.account()
        authenticated = bool(account.get("authenticated"))
        premium = bool(account.get("premium"))
        desired = {}
        for mission_id, meta in MISSION_META.items():
            item = {
                "id": mission_id,
                "label": meta["label"],
                "description": meta["description"],
                "implemented": meta["implemented"],
                "requires_account": True,
                "premium": premium,
                "modes": {},
            }
            for mode_id, mode in meta["modes"].items():
                item["modes"][mode_id] = {
                    "label": mode["label"],
                    "max_bytes": mode["max_bytes"],
                    "premium": mode["premium"],
                    "requires_session": True,
                    "enabled": bool(meta["implemented"] and authenticated and (premium or not mode["premium"])),
                }
            desired[mission_id] = item
        return desired

    def authorize_amx(self, mode: str, size: int) -> None:
        if mode not in ("normal", "performed"):
            raise PolicyError("Unknown AMX mode.", "INVALID_MODE", 400)
        if self.updates.snapshot().blocking:
            raise PolicyError(
                "Install the required desktop update before processing files.",
                "UPDATE_REQUIRED",
                426,
            )
        if not self.get_report().ok:
            raise PolicyError(
                "Required environment checks failed. Fix them before processing files.",
                "REQUIREMENTS_FAILED",
                503,
            )
        account = self.account()
        if not account.get("online"):
            raise PolicyError(
                "The account service is unavailable. Mission access cannot be verified.",
                "ACCOUNT_SERVICE_UNAVAILABLE",
                503,
            )
        if not account.get("authenticated"):
            raise PolicyError("Connect your Discord account first.", "AUTH_REQUIRED", 401)
        missions = account.get("missions") or {}
        entry = missions.get("amx") if isinstance(missions.get("amx"), dict) else {}
        if entry.get("allowed") is False:
            raise PolicyError("Your account does not have access to AMX to PWN.", "MISSION_DENIED", 403)
        mode_entry = (entry.get("modes") or {}).get(mode) if isinstance(entry.get("modes"), dict) else None
        if isinstance(mode_entry, dict) and mode_entry.get("allowed") is False:
            raise PolicyError(f"Your account does not have access to {mode} mode.", "MODE_DENIED", 403)
        limit = NORMAL_MAX if mode == "normal" else PERFORMED_MAX
        if size <= 0:
            raise PolicyError("The file is empty.", "EMPTY_FILE", 400)
        if size > limit:
            if mode == "normal":
                raise PolicyError(
                    "Normal mode accepts files up to 2 MiB. Use Performed mode for larger files.",
                    "FILE_TOO_LARGE",
                    400,
                )
            raise PolicyError("Performed mode accepts files up to 20 MiB.", "FILE_TOO_LARGE", 400)
        if mode == "performed" and not account.get("premium"):
            raise PolicyError(
                "Performed mode requires an active Premium entitlement.",
                "PREMIUM_REQUIRED",
                403,
            )

    def create_amx_job(self, filename: str) -> Job:
        return self.jobs.new_job("amx", filename, output_suffix=".pwn")

    def start_amx(self, job: Job, mode: str) -> None:
        self.jobs.start(job, self.amx, {"mode": mode})
        self.logger.event("job.started", job_id=job.id, mission="amx", mode=mode)

    def authorize_grab(self, mode: str, size: int) -> None:
        if mode not in ("normal", "performed"):
            raise PolicyError("Unknown Grab Detector mode.", "INVALID_MODE", 400)
        if self.updates.snapshot().blocking:
            raise PolicyError("Install the required desktop update before processing files.", "UPDATE_REQUIRED", 426)
        if not self.get_report().ok:
            raise PolicyError("Required environment checks failed. Fix them before processing files.", "REQUIREMENTS_FAILED", 503)
        account = self.account()
        if not account.get("online"):
            raise PolicyError("The account service is unavailable. Mission access cannot be verified.", "ACCOUNT_SERVICE_UNAVAILABLE", 503)
        if not account.get("authenticated"):
            raise PolicyError("Connect your Discord account first.", "AUTH_REQUIRED", 401)
        missions = account.get("missions") or {}
        entry = missions.get("grab-detector") if isinstance(missions.get("grab-detector"), dict) else {}
        if entry.get("allowed") is False:
            raise PolicyError("Your account does not have access to Grab Detector.", "MISSION_DENIED", 403)
        mode_entry = (entry.get("modes") or {}).get(mode) if isinstance(entry.get("modes"), dict) else None
        if isinstance(mode_entry, dict) and mode_entry.get("allowed") is False:
            raise PolicyError(f"Your account does not have access to {mode} mode.", "MODE_DENIED", 403)
        if size <= 0:
            raise PolicyError("The file is empty.", "EMPTY_FILE", 400)
        if size > GRAB_MAX:
            raise PolicyError("Grab Detector accepts files up to 3 MiB.", "FILE_TOO_LARGE", 400)
        if mode == "performed" and sys.platform != "linux":
            raise PolicyError(
                "Performed mode requires Linux Bubblewrap isolation and is unavailable on this platform.",
                "LOCAL_ISOLATION_UNAVAILABLE",
                503,
            )
        if mode == "performed" and not account.get("premium"):
            raise PolicyError("Performed mode requires an active Premium entitlement.", "PREMIUM_REQUIRED", 403)

    def create_grab_job(self, filename: str) -> Job:
        return self.jobs.new_job("grab-detector", filename, output_suffix=".json")

    def start_grab(self, job: Job, mode: str) -> None:
        self.jobs.start(job, self.grab, {"mode": mode})
        self.logger.event("job.started", job_id=job.id, mission="grab-detector", mode=mode)

    def cancel_job(self, job_id: str) -> bool:
        return self.jobs.cancel(job_id)

    def get_job(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def job_payload(self, job: Job) -> dict:
        return self.jobs.to_dict(job)

    def save_output(self, job_id: str, destination: Path | None = None) -> dict:
        job = self.jobs.get(job_id)
        if not job:
            raise SaveError("Job not found.", "JOB_NOT_FOUND", 404)
        result = save_job_output(job, destination)
        self.logger.event(
            "job.output_saved",
            job_id=job.id,
            size=result["size"],
            directory=result["directory"],
        )
        return result

    def open_output_folder(self, job_id: str) -> dict:
        job = self.jobs.get(job_id)
        if not job:
            raise SaveError("Job not found.", "JOB_NOT_FOUND", 404)
        result = open_job_output_folder(job)
        self.logger.event("job.output_folder_opened", job_id=job.id, directory=result["path"])
        return result

    def state(self) -> dict:
        report = self.get_report()
        account = self.account()
        return {
            "app": {
                "name": APP_NAME,
                "version": self.config.version,
                "platform": platform.platform(),
                "platform_key": self.config.platform_key,
                "api_base": self.config.api_base,
                "max_upload_bytes": self.config.max_upload_bytes,
            },
            "checks": report.to_dict(),
            "lua_libraries": self.lua_libraries.report(),
            "account": account,
            "update": self.updates.snapshot().to_dict(),
            "missions": self.missions(),
            "jobs": [self.jobs.to_dict(job) for job in self.jobs.list()[:20]],
        }

    def request_shutdown(self) -> None:
        self._shutdown.set()

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown.is_set()

    def welcome(self) -> str:
        return (
            f"{APP_NAME} {self.config.version} for {self.config.platform_key}. "
            "Local processing stays on this computer. Account and Premium checks require the RM7 Nexus service."
        )
