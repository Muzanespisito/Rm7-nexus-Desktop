from __future__ import annotations

import hmac
import html
import ipaddress
import json
import re
import secrets
import shutil
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..app import DesktopApp, PolicyError
from ..auth.client import AccountServiceUnavailable, AuthError
from ..security.file_save import SaveError
from ..updates import UpdateError
from .lua_libraries import LuaLibraryError
from .paths import ensure_within

MAX_JSON_BYTES = 64 * 1024
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MODE_RE = re.compile(r"^(normal|performed)$")
SESSION_COOKIE = "rm7_session"

STATIC_TYPES = {
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class RequestRejected(Exception):
    def __init__(self, status: int, message: str, code: str = "REQUEST_REJECTED") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class LocalServer:
    def __init__(self, app: DesktopApp, host: str = "127.0.0.1") -> None:
        self.app = app
        self.host = host
        self.bootstrap_nonce = secrets.token_urlsafe(32)
        self.session_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.port = 0
        self._bootstrap_used = False
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._library_lock = threading.RLock()
        self._library_staging: Path | None = None
        self._library_files = 0
        self._library_bytes = 0
        self._library_paths: set[str] = set()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def bootstrap_url(self) -> str:
        return f"{self.url}/?bootstrap={self.bootstrap_nonce}"

    def allowed_origins(self) -> set[str]:
        return {self.url, f"http://localhost:{self.port}"}

    def consume_bootstrap(self, value: str) -> bool:
        with self._lock:
            if self._bootstrap_used:
                return False
            if not value or not hmac.compare_digest(value, self.bootstrap_nonce):
                return False
            self._bootstrap_used = True
            return True

    def start(self) -> None:
        with self._lock:
            if self._httpd is not None:
                return
            handler = _handler_for(self)
            self._httpd = ThreadingHTTPServer((self.host, 0), handler)
            self._httpd.daemon_threads = True
            self.port = int(self._httpd.server_address[1])
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                name="rm7-local-server",
                daemon=True,
            )
            self._thread.start()
        self.app.logger.event("local_server.started", host=self.host, port=self.port)

    def stop(self) -> None:
        with self._lock:
            httpd = self._httpd
            if httpd is None:
                return
            self._httpd = None
            httpd.shutdown()
            httpd.server_close()
            if self._thread:
                self._thread.join(timeout=3)
            self._thread = None
        self.discard_library_upload()
        self.app.logger.event("local_server.stopped")

    def staging_directory(self) -> Path:
        with self._library_lock:
            if self._library_staging is None:
                root = self.app.config.lua_library_staging_dir
                root.mkdir(parents=True, exist_ok=True)
                staging = root / secrets.token_hex(16)
                staging.mkdir(mode=0o700)
                self._library_staging = staging
                self._library_files = 0
                self._library_bytes = 0
                self._library_paths = set()
            return self._library_staging

    def stage_library_file(self, relative: str, content: bytes) -> None:
        from pathlib import PurePosixPath

        if not content or len(content) > 2 * 1024 * 1024:
            raise RequestRejected(400, "A Lua module must be between 1 byte and 2 MiB", "INVALID_LIBRARY_FILE")
        path = PurePosixPath(str(relative or "").replace("\\", "/"))
        if (
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or len(path.parts) > 8
            or any(part in ("", ".") for part in path.parts)
        ):
            raise RequestRejected(400, "Unsafe Lua library path", "INVALID_LIBRARY_PATH")
        if path.suffix.lower() not in (".lua", ".luac", ".dll", ".so", ".dylib", ".bundle", ".a", ".lib"):
            raise RequestRejected(400, "Unsupported Lua library file type", "INVALID_LIBRARY_FILE")
        normalized = path.as_posix()
        with self._library_lock:
            if normalized in self._library_paths:
                raise RequestRejected(409, "Duplicate Lua library path", "DUPLICATE_LIBRARY_PATH")
            if self._library_files >= 2000:
                raise RequestRejected(413, "The library exceeds the 2000-module limit", "LIBRARY_TOO_LARGE")
            if self._library_bytes + len(content) > 64 * 1024 * 1024:
                raise RequestRejected(413, "The library exceeds the 64 MiB limit", "LIBRARY_TOO_LARGE")
            staging = self.staging_directory()
            destination = staging.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            self._library_paths.add(normalized)
            self._library_files += 1
            self._library_bytes += len(content)

    def commit_library_upload(self):
        with self._library_lock:
            staging = self._library_staging
            files = self._library_files
        if staging is None or files == 0:
            raise RequestRejected(400, "Upload at least one Lua library file", "EMPTY_LIBRARY")
        try:
            report = self.app.lua_libraries.install_upload(staging)
        finally:
            self.discard_library_upload()
        return report

    def discard_library_upload(self) -> None:
        with self._library_lock:
            staging = self._library_staging
            self._library_staging = None
            self._library_files = 0
            self._library_bytes = 0
            self._library_paths = set()
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _handler_for(owner: LocalServer):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "RM7NexusDesktop"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            return

        def do_OPTIONS(self) -> None:
            self._json(405, {"ok": False, "error": "Method not allowed", "code": "METHOD_NOT_ALLOWED"})

        def do_HEAD(self) -> None:
            self._json(405, {"ok": False, "error": "Method not allowed", "code": "METHOD_NOT_ALLOWED"})

        def do_GET(self) -> None:
            try:
                self._base_guard()
                self._route_get()
            except RequestRejected as exc:
                self._json(exc.status, {"ok": False, "error": str(exc), "code": exc.code})
            except UpdateError as exc:
                self._json(exc.status or 500, {"ok": False, "error": str(exc), "code": exc.code})
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                owner.app.logger.event("local_server.error", path=self.path, error=str(exc)[:300])
                self._json(500, {"ok": False, "error": "Internal desktop error", "code": "INTERNAL_ERROR"})

        def do_POST(self) -> None:
            try:
                self._base_guard()
                self._route_post()
            except RequestRejected as exc:
                self._json(exc.status, {"ok": False, "error": str(exc), "code": exc.code})
            except AccountServiceUnavailable as exc:
                self._json(503, {"ok": False, "error": str(exc), "code": exc.code})
            except AuthError as exc:
                self._json(exc.status or 400, {"ok": False, "error": str(exc), "code": exc.code})
            except PolicyError as exc:
                self._json(exc.status, {"ok": False, "error": str(exc), "code": exc.code})
            except UpdateError as exc:
                self._json(exc.status or 500, {"ok": False, "error": str(exc), "code": exc.code})
            except SaveError as exc:
                self._json(exc.status or 500, {"ok": False, "error": str(exc), "code": exc.code})
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                owner.app.logger.event("local_server.error", path=self.path, error=str(exc)[:300])
                self._json(500, {"ok": False, "error": "Internal desktop error", "code": "INTERNAL_ERROR"})

        def _base_guard(self) -> None:
            try:
                address = ipaddress.ip_address(self.client_address[0])
            except ValueError as exc:
                raise RequestRejected(403, "Non-loopback request rejected", "NON_LOOPBACK") from exc
            if not address.is_loopback:
                raise RequestRejected(403, "Non-loopback request rejected", "NON_LOOPBACK")
            host_header = str(self.headers.get("Host") or "").strip().lower()
            if host_header not in {f"127.0.0.1:{owner.port}", f"localhost:{owner.port}"}:
                raise RequestRejected(400, "Invalid Host header", "INVALID_HOST")
            origin = self.headers.get("Origin")
            if origin is not None and origin not in owner.allowed_origins():
                raise RequestRejected(403, "Cross-origin request rejected", "INVALID_ORIGIN")
            fetch_site = str(self.headers.get("Sec-Fetch-Site") or "").lower()
            if fetch_site == "cross-site":
                raise RequestRejected(403, "Cross-site request rejected", "INVALID_ORIGIN")

        def _session_cookie(self) -> str:
            try:
                cookie = SimpleCookie(self.headers.get("Cookie") or "")
            except Exception:
                return ""
            morsel = cookie.get(SESSION_COOKIE)
            return morsel.value if morsel else ""

        def _require_session(self) -> None:
            presented = self._session_cookie()
            if not presented or not hmac.compare_digest(presented, owner.session_token):
                raise RequestRejected(403, "Local session required", "INVALID_SESSION")

        def _require_csrf(self) -> None:
            presented = self.headers.get("X-RM7-CSRF") or ""
            if not presented or not hmac.compare_digest(presented, owner.csrf_token):
                raise RequestRejected(403, "Invalid CSRF token", "INVALID_CSRF")

        def _route_get(self) -> None:
            path = urlparse(self.path).path
            if path.startswith("/api/"):
                self._require_session()
            if path in ("/", "/index.html"):
                self._serve_index()
                return
            if path in STATIC_TYPES:
                filename, content_type = STATIC_TYPES[path]
                self._serve_file(owner.app.config.desktop_root / "ui" / filename, content_type)
                return
            if path == "/assets/background.gif":
                self._serve_file(owner.app.config.project_root / "background.gif", "image/gif")
                return
            if path == "/favicon.ico":
                self._bytes(204, b"", "image/x-icon")
                return
            if path == "/api/session":
                self._json(200, {"ok": True, "csrf": owner.csrf_token})
                return
            if path == "/api/lua-library":
                self._json(200, {"ok": True, "lua_libraries": owner.app.lua_libraries.report()})
                return
            if path == "/api/state":
                self._json(200, {"ok": True, **owner.app.state()})
                return
            if path == "/api/checks":
                query = urlparse(self.path).query
                refresh = "refresh=1" in query
                report = (
                    owner.app.refresh_checks(include_network=True, force=True)
                    if refresh
                    else owner.app.get_report()
                )
                self._json(200, {"ok": True, "checks": report.to_dict()})
                return
            if path == "/api/jobs":
                self._json(
                    200,
                    {
                        "ok": True,
                        "jobs": [owner.app.job_payload(job) for job in owner.app.jobs.list()[:50]],
                    },
                )
                return
            if path == "/api/update":
                query = urlparse(self.path).query
                decision = (
                    owner.app.refresh_update(force=True)
                    if "refresh=1" in query
                    else owner.app.update()
                )
                self._json(200, {"ok": True, "update": decision.to_dict()})
                return
            match = re.match(r"^/api/jobs/([0-9a-f]{32})(/output)?$", path)
            if match:
                job = owner.app.get_job(match.group(1))
                if not job:
                    raise RequestRejected(404, "Job not found", "JOB_NOT_FOUND")
                if match.group(2):
                    self._serve_output(job)
                else:
                    self._json(200, {"ok": True, "job": owner.app.job_payload(job)})
                return
            raise RequestRejected(404, "Not found", "NOT_FOUND")

        def _route_post(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/session/bootstrap":
                self._handle_bootstrap()
                return
            self._require_session()
            self._require_csrf()
            if path == "/api/pair/start":
                body = self._read_json()
                result = owner.app.start_pairing(str(body.get("device_name") or "Windows desktop"))
                self._json(200, {"ok": True, **result})
                return
            if path == "/api/pair/poll":
                body = self._read_json()
                request_id = str(body.get("request_id") or "")
                if not request_id:
                    raise RequestRejected(400, "Missing pairing request", "INVALID_REQUEST")
                result = owner.app.poll_pairing(request_id)
                self._json(200, {"ok": True, **result, "account": owner.app.account()})
                return
            if path == "/api/account/refresh":
                self._read_json(allow_empty=True)
                account = owner.app.refresh_account()
                self._json(200, {"ok": True, "account": account, "missions": owner.app.missions()})
                return
            if path == "/api/premium/activate":
                raise RequestRejected(
                    410,
                    "Activate Premium on the official RM7 Nexus website, then refresh Premium status.",
                    "DESKTOP_ACTIVATION_DISABLED",
                )
            if path == "/api/update/check":
                self._read_json(allow_empty=True)
                decision = owner.app.refresh_update(force=True)
                self._json(200, {"ok": True, "update": decision.to_dict()})
                return
            if path == "/api/update/download":
                self._read_json(allow_empty=True)
                decision = owner.app.download_update()
                self._json(200, {"ok": True, "update": decision.to_dict()})
                return
            if path == "/api/update/install":
                self._read_json(allow_empty=True)
                owner.app.install_update()
                self._json(200, {"ok": True})
                return
            if path == "/api/logout":
                self._read_json(allow_empty=True)
                owner.app.logout()
                self._json(200, {"ok": True})
                return
            if path == "/api/lua-library/select":
                body = self._read_json()
                raw = str(body.get("path") or "").strip()
                if not raw:
                    raise RequestRejected(400, "Enter a Lua library folder path", "INVALID_LIBRARY_PATH")
                try:
                    owner.app.lua_libraries.select_manual_directory(raw)
                except LuaLibraryError as exc:
                    raise RequestRejected(400, str(exc), "INVALID_LIBRARY_PATH") from exc
                self._json(200, {"ok": True, "lua_libraries": owner.app.lua_libraries.report()})
                return
            if path == "/api/lua-library/upload":
                self._handle_library_upload()
                return
            if path == "/api/lua-library/commit":
                self._read_json(allow_empty=True)
                owner.commit_library_upload()
                self._json(200, {"ok": True, "lua_libraries": owner.app.lua_libraries.report()})
                return
            if path == "/api/lua-library/cancel":
                self._read_json(allow_empty=True)
                owner.discard_library_upload()
                self._json(200, {"ok": True})
                return
            if path == "/api/lua-library/clear":
                self._read_json(allow_empty=True)
                owner.discard_library_upload()
                owner.app.lua_libraries.clear()
                self._json(200, {"ok": True, "lua_libraries": owner.app.lua_libraries.report()})
                return
            if path == "/api/jobs/amx":
                self._handle_amx_job()
                return
            if path == "/api/jobs/grab":
                self._handle_grab_job()
                return
            if path == "/api/shutdown":
                self._read_json(allow_empty=True)
                owner.app.request_shutdown()
                self._json(200, {"ok": True})
                threading.Thread(target=owner.stop, daemon=True, name="rm7-server-stop").start()
                return
            match = re.match(r"^/api/jobs/([0-9a-f]{32})/save$", path)
            if match:
                self._read_json(allow_empty=True)
                result = owner.app.save_output(match.group(1))
                self._json(200, {"ok": True, **result})
                return
            match = re.match(r"^/api/jobs/([0-9a-f]{32})/open-folder$", path)
            if match:
                self._read_json(allow_empty=True)
                result = owner.app.open_output_folder(match.group(1))
                self._json(200, {"ok": True, **result})
                return
            match = re.match(r"^/api/jobs/([0-9a-f]{32})/cancel$", path)
            if match:
                self._read_json(allow_empty=True)
                cancelled = owner.app.cancel_job(match.group(1))
                self._json(200 if cancelled else 409, {"ok": cancelled})
                return
            raise RequestRejected(404, "Not found", "NOT_FOUND")

        def _handle_bootstrap(self) -> None:
            body = self._read_json(allow_empty=True)
            nonce = str(self.headers.get("X-RM7-Bootstrap") or body.get("bootstrap") or "")
            if not owner.consume_bootstrap(nonce):
                raise RequestRejected(403, "Bootstrap link is invalid or has already been used", "BOOTSTRAP_REJECTED")
            cookie = (
                f"{SESSION_COOKIE}={owner.session_token}; HttpOnly; SameSite=Strict; Path=/"
            )
            self._json(200, {"ok": True, "csrf": owner.csrf_token}, headers={"Set-Cookie": cookie})

        def _handle_library_upload(self) -> None:
            relative = unquote(str(self.headers.get("X-RM7-Library-Path") or ""))
            try:
                length = int(str(self.headers.get("Content-Length") or ""))
            except ValueError as exc:
                raise RequestRejected(400, "Missing Content-Length", "INVALID_LENGTH") from exc
            if length <= 0:
                raise RequestRejected(400, "Empty library file", "EMPTY_FILE")
            if length > 2 * 1024 * 1024:
                raise RequestRejected(413, "A Lua module is limited to 2 MiB", "FILE_TOO_LARGE")
            content = self.rfile.read(length)
            if len(content) != length:
                raise RequestRejected(400, "Incomplete upload", "INCOMPLETE_UPLOAD")
            owner.stage_library_file(relative, content)
            self._json(200, {"ok": True})

        def _handle_amx_job(self) -> None:
            filename = unquote(str(self.headers.get("X-RM7-Filename") or "input.amx"))[:200]
            mode = str(self.headers.get("X-RM7-Mode") or "normal").strip().lower()
            if not MODE_RE.match(mode):
                raise RequestRejected(400, "Unknown AMX mode", "INVALID_MODE")
            try:
                length = int(str(self.headers.get("Content-Length") or ""))
            except ValueError as exc:
                raise RequestRejected(400, "Missing Content-Length", "INVALID_LENGTH") from exc
            if length <= 0:
                raise RequestRejected(400, "Empty request body", "EMPTY_FILE")
            if length > owner.app.config.max_upload_bytes:
                raise RequestRejected(413, "File exceeds the desktop upload limit", "FILE_TOO_LARGE")
            job = owner.app.create_amx_job(filename)
            written = 0
            try:
                with job.input_path.open("wb") as handle:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise RequestRejected(400, "Incomplete upload", "INCOMPLETE_UPLOAD")
                        handle.write(chunk)
                        written += len(chunk)
                        remaining -= len(chunk)
                if written != length:
                    raise RequestRejected(400, "Incomplete upload", "INCOMPLETE_UPLOAD")
                owner.app.authorize_amx(mode, written)
                owner.app.start_amx(job, mode)
            except Exception:
                owner.app.jobs.discard(job.id)
                raise
            self._json(202, {"ok": True, "job": owner.app.job_payload(job)})

        def _handle_grab_job(self) -> None:
            filename = unquote(str(self.headers.get("X-RM7-Filename") or "input.lua"))[:200]
            mode = str(self.headers.get("X-RM7-Mode") or "normal").strip().lower()
            if not MODE_RE.match(mode):
                raise RequestRejected(400, "Unknown Grab Detector mode", "INVALID_MODE")
            try:
                length = int(str(self.headers.get("Content-Length") or ""))
            except ValueError as exc:
                raise RequestRejected(400, "Missing Content-Length", "INVALID_LENGTH") from exc
            if length <= 0:
                raise RequestRejected(400, "Empty request body", "EMPTY_FILE")
            if length > owner.app.config.max_upload_bytes:
                raise RequestRejected(413, "File exceeds the desktop upload limit", "FILE_TOO_LARGE")
            owner.app.authorize_grab(mode, length)
            job = owner.app.create_grab_job(filename)
            written = 0
            try:
                with job.input_path.open("wb") as handle:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise RequestRejected(400, "Incomplete upload", "INCOMPLETE_UPLOAD")
                        handle.write(chunk)
                        written += len(chunk)
                        remaining -= len(chunk)
                if written != length:
                    raise RequestRejected(400, "Incomplete upload", "INCOMPLETE_UPLOAD")
                owner.app.start_grab(job, mode)
            except Exception:
                owner.app.jobs.discard(job.id)
                raise
            self._json(202, {"ok": True, "job": owner.app.job_payload(job)})

        def _serve_index(self) -> None:
            path = owner.app.config.desktop_root / "ui" / "index.html"
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                raise RequestRejected(500, "Desktop UI is unavailable", "UI_UNAVAILABLE")
            text = text.replace("__RM7_VERSION__", html.escape(owner.app.config.version, quote=True))
            body = text.encode("utf-8")
            self._bytes(
                200,
                body,
                "text/html; charset=utf-8",
                {
                    "Content-Security-Policy": (
                        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                        "script-src 'self' 'unsafe-eval'; connect-src 'self'; font-src 'self'; base-uri 'none'; "
                        "form-action 'none'; frame-ancestors 'none'"
                    ),
                    "X-Frame-Options": "DENY",
                },
            )

        def _serve_file(self, path: Path, content_type: str) -> None:
            try:
                body = Path(path).read_bytes()
            except OSError:
                raise RequestRejected(404, "Not found", "NOT_FOUND")
            self._bytes(200, body, content_type)

        def _serve_output(self, job) -> None:
            if job.status != "completed":
                raise RequestRejected(409, "Job is not complete", "JOB_NOT_READY")
            try:
                output = ensure_within(job.work_dir, job.output_path)
            except ValueError as exc:
                raise RequestRejected(403, "Invalid output path", "INVALID_PATH") from exc
            if not output.is_file():
                raise RequestRejected(404, "Output not found", "OUTPUT_NOT_FOUND")
            size = output.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{job.output_name}"')
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with output.open("rb") as handle:
                shutil.copyfileobj(handle, self.wfile, length=1024 * 1024)

        def _read_json(self, allow_empty: bool = False) -> dict:
            try:
                length = int(str(self.headers.get("Content-Length") or "0"))
            except ValueError as exc:
                raise RequestRejected(400, "Invalid Content-Length", "INVALID_LENGTH") from exc
            if length <= 0:
                if allow_empty:
                    return {}
                raise RequestRejected(400, "Missing JSON body", "INVALID_BODY")
            if length > MAX_JSON_BYTES:
                raise RequestRejected(413, "JSON body is too large", "BODY_TOO_LARGE")
            raw = self.rfile.read(length)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RequestRejected(400, "Invalid JSON body", "INVALID_BODY") from exc
            if not isinstance(value, dict):
                raise RequestRejected(400, "JSON body must be an object", "INVALID_BODY")
            return value

        def _json(self, status: int, payload: dict, headers: dict | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._bytes(status, body, "application/json; charset=utf-8", headers)

        def _bytes(self, status: int, body: bytes, content_type: str, headers: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

    return Handler
