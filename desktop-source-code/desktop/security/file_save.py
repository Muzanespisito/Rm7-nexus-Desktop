from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .paths import ensure_within


class SaveError(RuntimeError):
    def __init__(self, message: str, code: str, status: int = 500) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def output_path_for_job(job) -> Path:
    if job.status != "completed":
        raise SaveError("The job is not complete yet.", "JOB_NOT_READY", 409)
    try:
        output = ensure_within(job.work_dir, job.output_path)
    except ValueError as exc:
        raise SaveError("The job output path is invalid.", "INVALID_OUTPUT_PATH", 403) from exc
    if not output.is_file():
        raise SaveError("The generated output file does not exist.", "OUTPUT_NOT_FOUND", 404)
    try:
        size = output.stat().st_size
    except OSError as exc:
        raise SaveError("The generated output file cannot be read.", "OUTPUT_UNREADABLE", 500) from exc
    if size <= 0:
        raise SaveError("The generated output file is empty.", "OUTPUT_EMPTY", 500)
    return output


def downloads_directory() -> Path:
    home = Path.home()
    downloads = home / "Downloads"
    if downloads.is_dir():
        return downloads
    return home


def unique_destination(directory: Path, name: str) -> Path:
    directory = Path(directory)
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem = Path(name).stem or "output"
    suffix = Path(name).suffix
    for index in range(1, 1000):
        candidate = directory / f"{stem} ({index}){suffix}"
        if not candidate.exists():
            return candidate
    raise SaveError("Could not find an available filename.", "NAME_CONFLICT", 409)


def _atomic_copy(source: Path, destination: Path) -> None:
    destination = Path(destination).expanduser()
    if not destination.is_absolute():
        raise SaveError("Choose an absolute destination path.", "INVALID_DESTINATION", 400)
    if destination.exists() and destination.is_dir():
        raise SaveError("The destination is a directory.", "INVALID_DESTINATION", 400)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SaveError("The destination folder cannot be created.", "DESTINATION_UNAVAILABLE", 403) from exc
    if not destination.parent.is_dir():
        raise SaveError("The destination folder does not exist.", "DESTINATION_UNAVAILABLE", 400)
    temp_path: Path | None = None
    try:
        fd, raw = tempfile.mkstemp(
            prefix=".rm7-",
            suffix=destination.suffix or ".tmp",
            dir=str(destination.parent),
        )
        temp_path = Path(raw)
        with os.fdopen(fd, "wb") as handle, source.open("rb") as reader:
            shutil.copyfileobj(reader, handle, length=1024 * 1024)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
        temp_path = None
    except OSError as exc:
        code = "DISK_FULL" if getattr(exc, "errno", None) == 28 else "SAVE_FAILED"
        message = (
            "There is not enough free disk space to save the file."
            if code == "DISK_FULL"
            else "The output file could not be saved. Check permissions and disk space."
        )
        raise SaveError(message, code, 507 if code == "DISK_FULL" else 500) from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    try:
        final_size = destination.stat().st_size
    except OSError as exc:
        raise SaveError("The saved file could not be verified.", "SAVE_VERIFY_FAILED", 500) from exc
    if final_size <= 0:
        raise SaveError("The saved file is empty.", "SAVE_VERIFY_FAILED", 500)


def save_job_output(job, destination: Path | None = None) -> dict:
    source = output_path_for_job(job)
    if destination is None:
        destination = unique_destination(downloads_directory(), job.output_name or source.name)
    else:
        destination = Path(destination).expanduser()
        if destination.suffix == "":
            destination = destination.with_suffix(source.suffix or ".pwn")
    _atomic_copy(source, destination)
    return {
        "path": str(destination.resolve()),
        "name": destination.name,
        "size": destination.stat().st_size,
        "directory": str(destination.resolve().parent),
    }


def open_job_output_folder(job) -> dict:
    output = output_path_for_job(job)
    folder = output.resolve().parent
    if sys.platform == "win32":
        try:
            os.startfile(str(folder))
        except OSError as exc:
            raise SaveError("The output folder could not be opened.", "OPEN_FOLDER_FAILED", 500) from exc
        return {"path": str(folder)}
    opener = shutil.which("xdg-open") or shutil.which("gio")
    if not opener:
        raise SaveError("No file manager launcher is available.", "OPEN_FOLDER_UNAVAILABLE", 503)
    command = [opener, "open", str(folder)] if Path(opener).name == "gio" else [opener, str(folder)]
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise SaveError("The output folder could not be opened.", "OPEN_FOLDER_FAILED", 500) from exc
    return {"path": str(folder)}
