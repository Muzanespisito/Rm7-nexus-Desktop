from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..engines.base import EngineCancelled, EngineError
from ..security.paths import ensure_within, safe_filename


@dataclass
class Job:
    id: str
    mission: str
    input_name: str
    work_dir: Path
    input_path: Path
    output_path: Path
    output_name: str
    status: str = "queued"
    progress: int = 0
    message: str = "Queued"
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    exit_code: int | None = None
    size_in: int = 0
    size_out: int = 0
    meta: dict = field(default_factory=dict)
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    log_path: Path = field(default=None, repr=False)

    def to_dict(self, log_tail: str = "") -> dict:
        return {
            "id": self.id,
            "mission": self.mission,
            "input_name": self.input_name,
            "output_name": self.output_name if self.status == "completed" else "",
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "size_in": self.size_in,
            "size_out": self.size_out,
            "meta": self.meta,
            "log": log_tail,
            "output_url": f"/api/jobs/{self.id}/output" if self.status == "completed" else "",
        }


class JobManager:
    def __init__(self, root: Path, concurrency: int = 1) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._slots = threading.Semaphore(max(1, concurrency))

    def new_job(
        self,
        mission: str,
        filename: str,
        output_suffix: str = ".pwn",
    ) -> Job:
        job_id = uuid.uuid4().hex
        work_dir = self.root / job_id
        input_dir = work_dir / "input"
        output_dir = work_dir / "output"
        input_dir.mkdir(parents=True, exist_ok=False)
        output_dir.mkdir(parents=True, exist_ok=False)
        name = safe_filename(filename, fallback="input.bin")
        input_path = ensure_within(work_dir, input_dir / name)
        stem = Path(name).stem or "output"
        output_name = safe_filename(stem + output_suffix, fallback="output" + output_suffix)
        output_path = ensure_within(work_dir, output_dir / output_name)
        log_path = work_dir / "job.log"
        job = Job(
            id=job_id,
            mission=mission,
            input_name=name,
            work_dir=work_dir,
            input_path=input_path,
            output_path=output_path,
            output_name=output_name,
            log_path=log_path,
        )
        log_path.touch()
        with self._lock:
            self._jobs[job_id] = job
        return job

    def start(self, job: Job, engine: Any, options: dict | None = None) -> None:
        thread = threading.Thread(
            target=self._execute,
            args=(job, engine, options or {}),
            daemon=True,
            name=f"rm7-job-{job.id[:8]}",
        )
        thread.start()

    def _execute(self, job: Job, engine: Any, options: dict) -> None:
        with self._slots:
            if job.cancel_event.is_set():
                self._finish(job, "cancelled", "Cancelled before start")
                return
            with self._lock:
                job.status = "running"
                job.started_at = time.time()
                job.message = "Running"
            self._append(job, "Job started")
            try:
                job.size_in = job.input_path.stat().st_size if job.input_path.exists() else 0
            except OSError:
                job.size_in = 0

            def progress(value: int, message: str) -> None:
                with self._lock:
                    job.progress = max(0, min(100, int(value)))
                    if message:
                        job.message = str(message)[:300]
                if message:
                    self._append(job, f"[{job.progress:>3}%] {message}")

            try:
                result = engine.run(
                    job.input_path,
                    job.output_path,
                    job.work_dir,
                    progress,
                    job.cancel_event,
                    options,
                )
                output = Path(result.get("output_path") or job.output_path)
                ensure_within(job.work_dir, output)
                if not output.is_file():
                    raise EngineError("The engine did not produce an output file.")
                with self._lock:
                    job.size_out = output.stat().st_size
                    job.meta = result.get("meta") or {}
                    job.output_path = output
                    job.output_name = str(result.get("output_name") or output.name)
                if result.get("log"):
                    for line in str(result["log"]).splitlines()[-200:]:
                        self._append(job, line)
                self._finish(job, "completed", "Completed")
            except EngineCancelled as exc:
                self._finish(job, "cancelled", str(exc))
            except EngineError as exc:
                self._finish(job, "failed", str(exc))
            except Exception as exc:
                self._finish(job, "failed", f"Unexpected engine failure: {exc}")

    def _finish(self, job: Job, status: str, message: str) -> None:
        with self._lock:
            job.status = status
            job.finished_at = time.time()
            job.message = message[:500]
            if status == "failed":
                job.error = message[:2000]
            if status == "completed":
                job.progress = 100
        self._append(job, message)

    def _append(self, job: Job, line: str) -> None:
        if job.log_path is None:
            return
        stamp = time.strftime("%H:%M:%S", time.localtime())
        try:
            with job.log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"[{stamp}] {line}\n")
        except OSError:
            pass

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status in ("completed", "failed", "cancelled"):
                return False
            job.cancel_event.set()
            if job.status == "queued":
                job.status = "cancelled"
                job.message = "Cancelled"
                job.finished_at = time.time()
            return True

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def logs(self, job: Job, max_bytes: int = 262144) -> str:
        path = job.log_path
        if not path or not path.is_file():
            return ""
        try:
            with path.open("rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - max_bytes))
                raw = handle.read()
            return raw.decode("utf-8", errors="replace")
        except OSError:
            return ""

    def to_dict(self, job: Job) -> dict:
        return job.to_dict(self.logs(job))

    def discard(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if job:
            job.cancel_event.set()
            try:
                for child in sorted(job.work_dir.rglob("*"), reverse=True):
                    if child.is_file():
                        child.unlink(missing_ok=True)
                    elif child.is_dir():
                        child.rmdir()
                job.work_dir.rmdir()
            except OSError:
                pass

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)

    def cancel_all(self) -> None:
        for job in self.list():
            self.cancel(job.id)
