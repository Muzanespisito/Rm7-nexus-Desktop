from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import Config
from .os_support import PlatformInfo, platform_for_key

MANIFEST_PATH = "/releases/manifest.json"
SIGNATURE_PATH = "/releases/manifest.json.sig"
DOWNLOAD_PATH = "/api/desktop/download"
CHECK_INTERVAL = 600
MAX_MANIFEST_BYTES = 512 * 1024
MAX_SIGNATURE_BYTES = 4096
VERSION_RE = re.compile(r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]{1,64}))?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,299}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
PLATFORMS = ("windows", "linux")


class UpdateError(RuntimeError):
    def __init__(self, message: str, code: str = "UPDATE_ERROR", status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple[tuple[int, Any], ...] = ()

    def _key(self) -> tuple:
        return (self.major, self.minor, self.patch, 0 if self.prerelease else 1, self.prerelease)

    def __lt__(self, other: "Version") -> bool:
        return self._key() < other._key()

    def __le__(self, other: "Version") -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: "Version") -> bool:
        return self._key() > other._key()


def parse_version(value: Any) -> Version:
    text = str(value or "").strip()
    match = VERSION_RE.match(text)
    if not match:
        raise UpdateError("The release version is invalid.", "INVALID_VERSION")
    parts = (match.group(1), match.group(2), match.group(3))
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        raise UpdateError("The release version is invalid.", "INVALID_VERSION")
    major, minor, patch = (int(part) for part in parts)
    prerelease: list[tuple[int, Any]] = []
    if match.group(4):
        for part in match.group(4).split("."):
            if not part or (part.isdigit() and len(part) > 1 and part.startswith("0")):
                raise UpdateError("The release version is invalid.", "INVALID_VERSION")
            prerelease.append((0, int(part)) if part.isdigit() else (1, part.lower()))
    return Version(major, minor, patch, tuple(prerelease))


def compare_versions(left: Any, right: Any) -> int:
    first = parse_version(left)
    second = parse_version(right)
    if first < second:
        return -1
    if first > second:
        return 1
    return 0


@dataclass(frozen=True)
class Artifact:
    platform: str
    pathname: str
    name: str
    sha256: str
    size: int
    content_type: str = ""

    def public(self) -> dict:
        return {
            "platform": self.platform,
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "content_type": self.content_type,
        }


@dataclass(frozen=True)
class Release:
    version: str
    minimum_version: str
    mandatory: bool
    notes: tuple[str, ...]
    published_at: str
    channel: str
    artifacts: dict[str, Artifact | None] = field(default_factory=dict)

    def minimum_for(self, platform: str) -> str:
        entry = self.artifacts.get(platform)
        return self.minimum_version if entry is None else self.minimum_version

    def platform_mandatory(self, platform: str) -> bool:
        return self.mandatory


@dataclass
class UpdateDecision:
    status: str = "unknown"
    current_version: str = ""
    latest_version: str = ""
    minimum_version: str = ""
    mandatory: bool = False
    message: str = ""
    notes: tuple[str, ...] = ()
    published_at: str = ""
    channel: str = ""
    artifact: Artifact | None = None
    downloaded: bool = False

    @property
    def blocking(self) -> bool:
        return self.status == "required"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "blocking": self.blocking,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "minimum_version": self.minimum_version,
            "mandatory": self.mandatory,
            "message": self.message,
            "notes": list(self.notes),
            "published_at": self.published_at,
            "channel": self.channel,
            "artifact": self.artifact.public() if self.artifact else None,
            "downloaded": self.downloaded,
        }


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", "").strip()[:limit]


def _public_key(value: str) -> Ed25519PublicKey:
    raw = str(value or "").strip()
    if not raw:
        raise UpdateError("Update verification is not configured.", "UPDATE_DISABLED", 503)
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise UpdateError("The update verification key is invalid.", "UPDATE_CONFIG_ERROR", 503) from exc
    if len(decoded) != 32:
        raise UpdateError("The update verification key is invalid.", "UPDATE_CONFIG_ERROR", 503)
    return Ed25519PublicKey.from_public_bytes(decoded)


def verify_signature(payload: bytes, signature: bytes | str, public_key: str) -> None:
    key = _public_key(public_key)
    if isinstance(signature, str):
        encoded = signature.strip().encode("ascii", "ignore")
    elif isinstance(signature, (bytes, bytearray)):
        encoded = bytes(signature).strip()
    else:
        raise UpdateError("The release signature is invalid.", "INVALID_SIGNATURE")
    if len(encoded) != 64:
        try:
            encoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise UpdateError("The release signature is invalid.", "INVALID_SIGNATURE") from exc
    if len(encoded) != 64:
        raise UpdateError("The release signature is invalid.", "INVALID_SIGNATURE")
    try:
        key.verify(encoded, payload)
    except InvalidSignature as exc:
        raise UpdateError("The release signature could not be verified.", "INVALID_SIGNATURE") from exc


def _artifact(platform: str, value: Any) -> Artifact | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise UpdateError("The release artifact is invalid.", "INVALID_MANIFEST")
    pathname = _text(value.get("pathname"), 300)
    sha256 = _text(value.get("sha256"), 64).lower()
    size = value.get("size")
    content_type = _text(value.get("content_type"), 160)
    if not PATH_RE.match(pathname) or ".." in pathname.split("/") or pathname.endswith("/"):
        raise UpdateError("The release artifact path is invalid.", "INVALID_MANIFEST")
    if not SHA256_RE.match(sha256):
        raise UpdateError("The release artifact hash is invalid.", "INVALID_MANIFEST")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 2 * 1024 * 1024 * 1024:
        raise UpdateError("The release artifact size is invalid.", "INVALID_MANIFEST")
    name = Path(pathname).name
    if not NAME_RE.match(name):
        raise UpdateError("The release artifact name is invalid.", "INVALID_MANIFEST")
    expected = ".exe" if platform == "windows" else ".deb"
    if not name.lower().endswith(expected):
        raise UpdateError("The release artifact type is invalid.", "INVALID_MANIFEST")
    return Artifact(platform, pathname, name, sha256, int(size), content_type)


def parse_manifest(payload: bytes | str | dict, expected_channel: str = "") -> Release:
    try:
        value = json.loads(payload) if isinstance(payload, (bytes, str)) else payload
    except (TypeError, ValueError) as exc:
        raise UpdateError("The release manifest is invalid.", "INVALID_MANIFEST") from exc
    if not isinstance(value, dict):
        raise UpdateError("The release manifest is invalid.", "INVALID_MANIFEST")
    if value.get("schema") != 1:
        raise UpdateError("The release manifest schema is unsupported.", "INVALID_MANIFEST")
    channel = _text(value.get("channel"), 32).lower()
    if not channel:
        raise UpdateError("The release channel is missing.", "INVALID_MANIFEST")
    if expected_channel and channel != expected_channel:
        raise UpdateError("The release is for a different update channel.", "CHANNEL_MISMATCH")
    version = _text(value.get("version"), 64)
    minimum = _text(value.get("minimum_version"), 64)
    parse_version(version)
    parse_version(minimum)
    if parse_version(minimum) > parse_version(version):
        raise UpdateError("The minimum version exceeds the release version.", "INVALID_MANIFEST")
    mandatory = value.get("mandatory", False)
    if not isinstance(mandatory, bool):
        raise UpdateError("The release policy is invalid.", "INVALID_MANIFEST")
    published_at = _text(value.get("published_at"), 64)
    try:
        datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UpdateError("The release date is invalid.", "INVALID_MANIFEST") from exc
    notes_value = value.get("notes", [])
    if not isinstance(notes_value, list) or len(notes_value) > 20:
        raise UpdateError("The release notes are invalid.", "INVALID_MANIFEST")
    notes: list[str] = []
    for item in notes_value:
        if not isinstance(item, str):
            raise UpdateError("The release notes are invalid.", "INVALID_MANIFEST")
        clean = _text(item, 500)
        if clean:
            notes.append(clean)
    platforms = value.get("platforms", {})
    if not isinstance(platforms, dict):
        raise UpdateError("The release platforms are invalid.", "INVALID_MANIFEST")
    artifacts: dict[str, Artifact | None] = {}
    for name in PLATFORMS:
        entry = platforms.get(name)
        if entry is None:
            artifacts[name] = None
            continue
        if not isinstance(entry, dict):
            raise UpdateError("The release platform entry is invalid.", "INVALID_MANIFEST")
        entry_minimum = _text(entry.get("minimum_version", minimum), 64)
        parse_version(entry_minimum)
        if parse_version(entry_minimum) > parse_version(version):
            raise UpdateError("The platform minimum version is invalid.", "INVALID_MANIFEST")
        entry_mandatory = entry.get("mandatory", mandatory)
        if not isinstance(entry_mandatory, bool):
            raise UpdateError("The platform update policy is invalid.", "INVALID_MANIFEST")
        if entry_mandatory != mandatory or entry_minimum != minimum:
            raise UpdateError("Platform policy overrides are not supported.", "INVALID_MANIFEST")
        artifacts[name] = _artifact(name, entry.get("artifact"))
    return Release(version, minimum, mandatory, tuple(notes), published_at, channel, artifacts)


def decision_for(
    release: Release,
    current_version: str,
    platform: str,
    downloaded: bool = False,
    message: str = "",
) -> UpdateDecision:
    current = parse_version(current_version)
    latest = parse_version(release.version)
    minimum = parse_version(release.minimum_version)
    artifact = release.artifacts.get(platform)
    if current < minimum:
        status = "required"
        mandatory = True
        detail = message or "This version is no longer supported. Install the required update to continue."
    elif current < latest:
        mandatory = release.mandatory
        status = "required" if mandatory else "optional"
        detail = message or (
            "A required update is available." if mandatory else "A new desktop update is available."
        )
    else:
        mandatory = False
        status = "current"
        detail = message or "The desktop app is up to date."
    return UpdateDecision(
        status=status,
        current_version=str(current_version),
        latest_version=release.version,
        minimum_version=release.minimum_version,
        mandatory=mandatory,
        message=detail,
        notes=release.notes,
        published_at=release.published_at,
        channel=release.channel,
        artifact=artifact,
        downloaded=downloaded,
    )


def _safe_url(url: str, allow_loopback_http: bool = False) -> str:
    try:
        parsed = urlparse(str(url))
    except ValueError as exc:
        raise UpdateError("The release download URL is invalid.", "INVALID_DOWNLOAD_URL") from exc
    if parsed.username or parsed.password:
        raise UpdateError("The release download URL is invalid.", "INVALID_DOWNLOAD_URL")
    local = parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not (allow_loopback_http and local):
        raise UpdateError("The release download URL must use HTTPS.", "INVALID_DOWNLOAD_URL")
    if not parsed.hostname:
        raise UpdateError("The release download URL is invalid.", "INVALID_DOWNLOAD_URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
        if not (allow_loopback_http and local):
            raise UpdateError("The release download URL is invalid.", "INVALID_DOWNLOAD_URL")
    return str(url)


class UpdateService:
    def __init__(
        self,
        config: Config,
        logger=None,
        fetcher: Callable[[str, int, int, dict | None], bytes] | None = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self._fetcher = fetcher or self._fetch
        self._lock = threading.RLock()
        self._decision = UpdateDecision(current_version=config.version)
        self._checked_at = 0.0
        self._state = self._read_state()

    def _log(self, name: str, **fields) -> None:
        if self.logger is not None:
            try:
                self.logger.event(name, **fields)
            except Exception:
                pass

    def _read_state(self) -> dict:
        try:
            value = json.loads(self.config.update_state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write_state(self) -> None:
        data = json.dumps(self._state, ensure_ascii=False, separators=(",", ":"))
        path = self.config.update_state_file
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".update-",
            delete=False,
        )
        try:
            with handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(handle.name, 0o600)
            os.replace(handle.name, path)
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def _platform(self) -> PlatformInfo:
        info = self.config.platform
        if info is None:
            raise UpdateError("This operating system is not supported.", "UNSUPPORTED_PLATFORM", 403)
        return info

    def _url(self, path: str) -> str:
        return self.config.api_base.rstrip("/") + path

    def _fetch(self, url: str, timeout: int, max_bytes: int, headers: dict | None = None) -> bytes:
        _safe_url(url, self.config.api_is_local_http())
        request = Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": f"RM7NexusDesktop/{self.config.version}",
                **(headers or {}),
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                final_url = response.geturl()
                _safe_url(final_url, self.config.api_is_local_http())
                length = response.headers.get("Content-Length")
                if length:
                    try:
                        if int(length) > max_bytes:
                            raise UpdateError("The update response is too large.", "UPDATE_TOO_LARGE")
                    except ValueError:
                        pass
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise UpdateError("The update response is too large.", "UPDATE_TOO_LARGE")
                    chunks.append(chunk)
                return b"".join(chunks)
        except HTTPError as exc:
            if exc.code == 404:
                raise UpdateError("No signed desktop release is published yet.", "RELEASE_UNAVAILABLE", 404) from exc
            raise UpdateError(
                f"The release service returned HTTP {exc.code}.",
                "UPDATE_SERVICE_ERROR",
                502,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise UpdateError("The release service is unavailable.", "UPDATE_SERVICE_UNAVAILABLE", 503) from exc

    def check(self, force: bool = False) -> UpdateDecision:
        with self._lock:
            if not force and self._checked_at and time.time() - self._checked_at < CHECK_INTERVAL:
                return self._decision
            try:
                platform = self._platform()
                manifest = self._fetcher(
                    self._url(MANIFEST_PATH),
                    self.config.update_timeout_seconds,
                    MAX_MANIFEST_BYTES,
                    None,
                )
                signature = self._fetcher(
                    self._url(SIGNATURE_PATH),
                    self.config.update_timeout_seconds,
                    MAX_SIGNATURE_BYTES,
                    None,
                )
                verify_signature(manifest, signature, self.config.update_public_key)
                release = parse_manifest(manifest, self.config.update_channel)
                highest = str(self._state.get("highest_version") or "")
                if highest:
                    try:
                        if parse_version(release.version) < parse_version(highest):
                            raise UpdateError(
                                "The release manifest is older than a previously verified release.",
                                "UPDATE_ROLLBACK",
                            )
                    except UpdateError as exc:
                        if exc.code == "UPDATE_ROLLBACK":
                            raise
                artifact = release.artifacts.get(platform.key)
                downloaded = self._is_downloaded(artifact)
                decision = decision_for(
                    release,
                    self.config.version,
                    platform.key,
                    downloaded=downloaded,
                )
                if not artifact and decision.status != "current":
                    decision.message += " The installer for this platform is not published yet."
                self._state["highest_version"] = max(
                    [release.version, highest] if highest else [release.version],
                    key=parse_version,
                )
                self._state["checked_at"] = int(time.time())
                if decision.blocking:
                    self._state["required_version"] = release.minimum_version
                else:
                    self._state.pop("required_version", None)
                    self._state.pop("required_message", None)
                self._write_state()
                self._decision = decision
                self._checked_at = time.time()
                self._log(
                    "update.checked",
                    status=decision.status,
                    current=decision.current_version,
                    latest=decision.latest_version,
                    platform=platform.key,
                )
                return decision
            except UpdateError as exc:
                previous = self._persisted_gate()
                if previous is not None:
                    self._decision = previous
                else:
                    self._decision = UpdateDecision(
                        status="unavailable",
                        current_version=self.config.version,
                        message=str(exc),
                    )
                self._checked_at = time.time() - CHECK_INTERVAL + 60
                self._log("update.check_failed", code=exc.code, error=str(exc)[:240])
                return self._decision

    def _persisted_gate(self) -> UpdateDecision | None:
        required = str(self._state.get("required_version") or "")
        if not required:
            return None
        try:
            if parse_version(self.config.version) >= parse_version(required):
                self._state.pop("required_version", None)
                self._state.pop("required_message", None)
                self._write_state()
                return None
        except UpdateError:
            return None
        return UpdateDecision(
            status="required",
            current_version=self.config.version,
            latest_version=str(self._state.get("highest_version") or required),
            minimum_version=required,
            mandatory=True,
            message=str(self._state.get("required_message") or "A required update was previously detected."),
        )

    def snapshot(self) -> UpdateDecision:
        with self._lock:
            if self._decision.status in ("unknown", "unavailable"):
                gate = self._persisted_gate()
                if gate is not None:
                    return gate
            return self._decision

    def _is_downloaded(self, artifact: Artifact | None) -> bool:
        if artifact is None:
            return False
        if str(self._state.get("downloaded_sha256") or "") != artifact.sha256:
            return False
        return self._target(artifact).is_file()

    def _target(self, artifact: Artifact) -> Path:
        return self.config.updates_dir / artifact.name

    def _download_url(self, platform: str, token: str) -> str:
        if not token:
            raise UpdateError("Sign in to the desktop app to download updates.", "AUTH_REQUIRED", 401)
        url = self._url(DOWNLOAD_PATH) + "?platform=" + platform
        raw = self._fetcher(
            url,
            self.config.update_timeout_seconds,
            MAX_MANIFEST_BYTES,
            {
                "Authorization": "Bearer " + token,
                "Accept": "application/json",
                "X-RM7-Platform": platform,
            },
        )
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise UpdateError("The release service returned an invalid response.", "INVALID_DOWNLOAD_URL") from exc
        if not isinstance(value, dict) or value.get("ok") is not True:
            message = _text(value.get("error") if isinstance(value, dict) else "", 240)
            raise UpdateError(message or "The installer is unavailable.", "RELEASE_UNAVAILABLE", 404)
        return _safe_url(str(value.get("url") or ""), self.config.api_is_local_http())

    def download(self, token: str) -> UpdateDecision:
        decision = self.check(force=False)
        if not decision.artifact:
            raise UpdateError("No installer is published for this platform.", "RELEASE_UNAVAILABLE", 404)
        if decision.status == "current":
            return decision
        target = self._target(decision.artifact)
        if self._is_downloaded(decision.artifact):
            return decision
        url = self._download_url(decision.artifact.platform, token)
        _safe_url(url, self.config.api_is_local_http())
        target.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "wb",
            dir=target.parent,
            prefix=".download-",
            delete=False,
        )
        digest = hashlib.sha256()
        total = 0
        try:
            request = Request(
                url,
                headers={
                    "Accept": "application/octet-stream",
                    "User-Agent": f"RM7NexusDesktop/{self.config.version}",
                },
                method="GET",
            )
            with urlopen(request, timeout=self.config.update_timeout_seconds) as response:
                _safe_url(response.geturl(), self.config.api_is_local_http())
                with handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > decision.artifact.size or total > self.config.max_update_bytes:
                            raise UpdateError("The downloaded installer has an invalid size.", "INVALID_ARTIFACT")
                        digest.update(chunk)
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            if total != decision.artifact.size:
                raise UpdateError("The downloaded installer has an invalid size.", "INVALID_ARTIFACT")
            if digest.hexdigest() != decision.artifact.sha256:
                raise UpdateError("The downloaded installer failed verification.", "INVALID_ARTIFACT")
            os.chmod(handle.name, 0o600)
            os.replace(handle.name, target)
            with self._lock:
                self._state["downloaded_sha256"] = decision.artifact.sha256
                self._state["downloaded_version"] = decision.latest_version
                self._state["downloaded_at"] = int(time.time())
                self._write_state()
                decision.downloaded = True
                self._decision = decision
            self._log(
                "update.downloaded",
                version=decision.latest_version,
                platform=decision.artifact.platform,
                size=total,
            )
            return decision
        except UpdateError:
            raise
        except HTTPError as exc:
            raise UpdateError(
                f"The installer download returned HTTP {exc.code}.",
                "UPDATE_SERVICE_ERROR",
                502,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise UpdateError("The installer download failed.", "UPDATE_DOWNLOAD_FAILED", 503) from exc
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass

    def install(self, path: Path) -> None:
        decision = self.check(force=False)
        if not decision.artifact or not decision.downloaded:
            raise UpdateError("Download the update before installing it.", "UPDATE_NOT_DOWNLOADED", 409)
        target = Path(path).resolve()
        expected = self._target(decision.artifact).resolve()
        if target != expected or not target.is_file():
            raise UpdateError("The downloaded installer is unavailable.", "UPDATE_NOT_DOWNLOADED", 409)
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != decision.artifact.sha256:
            raise UpdateError("The downloaded installer failed verification.", "INVALID_ARTIFACT", 409)
        from .os_support import launch_installer

        try:
            launch_installer(target)
        except Exception as exc:
            raise UpdateError(str(exc), "UPDATE_INSTALL_FAILED", 500) from exc
        self._log("update.install_started", version=decision.latest_version)
