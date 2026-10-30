from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from ..config import Config
from .credentials import CredentialError, CredentialStore, decode_session, encode_session

DEFAULT_INTERVAL = 5
PAIRING_TTL = 600
REQUEST_TIMEOUT = 12


class AuthError(RuntimeError):
    def __init__(self, message: str, code: str = "AUTH_ERROR", status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class AccountServiceUnavailable(AuthError):
    def __init__(self, message: str = "The account service is temporarily unavailable.") -> None:
        super().__init__(message, "ACCOUNT_SERVICE_UNAVAILABLE")


class UpdateRequired(AuthError):
    def __init__(
        self,
        message: str = "A required desktop update is available.",
        minimum_version: str = "",
        download_url: str = "",
    ) -> None:
        super().__init__(message, "DESKTOP_UPDATE_REQUIRED", 426)
        self.minimum_version = minimum_version
        self.download_url = download_url


@dataclass
class Session:
    token: str
    uid: str
    username: str
    global_name: str
    avatar: str | None
    expires_at: float

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "uid": self.uid,
            "username": self.username,
            "global_name": self.global_name,
            "avatar": self.avatar,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, value: dict) -> "Session | None":
        try:
            token = str(value["token"])
            uid = str(value["uid"])
            expires_at = float(value["expires_at"])
        except (KeyError, TypeError, ValueError):
            return None
        if not token or not uid:
            return None
        return cls(
            token=token,
            uid=uid,
            username=str(value.get("username") or ""),
            global_name=str(value.get("global_name") or value.get("username") or ""),
            avatar=value.get("avatar"),
            expires_at=expires_at,
        )

    def public(self) -> dict:
        return {
            "uid": self.uid,
            "username": self.username,
            "global_name": self.global_name,
            "avatar": self.avatar,
            "expires_at": self.expires_at,
        }


def _safe_verification_uri(base: str, value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise AuthError("The account service did not return a verification URL.", "INVALID_RESPONSE")
    target = urljoin(base + "/", raw)
    parsed = urlparse(target)
    base_parsed = urlparse(base)
    if parsed.scheme != "https" and not (
        base_parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
    ):
        raise AuthError("The verification URL must use HTTPS.", "INVALID_RESPONSE")
    if parsed.netloc != base_parsed.netloc:
        raise AuthError("The verification URL host does not match the account service.", "INVALID_RESPONSE")
    return target


class DesktopAuthClient:
    def __init__(self, config: Config, store: CredentialStore) -> None:
        self.config = config
        self.store = store
        self._pending: dict[str, dict] = {}

    def _url(self, path: str) -> str:
        return self.config.api_base.rstrip("/") + "/" + path.lstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        token: str | None = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict:
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": f"RM7NexusDesktop/{self.config.version}",
            "X-RM7-Desktop-Version": self.config.version,
            "X-RM7-Platform": self.config.platform_key,
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self._url(path), data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=timeout) as response:
                raw = response.read(4 * 1024 * 1024)
                status = response.status
        except HTTPError as exc:
            status = exc.code
            raw = exc.read(512 * 1024)
            fields = _error_fields(raw)
            message = fields.get("error", "")
            code = fields.get("code", "")
            if status == 426 or code == "DESKTOP_UPDATE_REQUIRED":
                raise UpdateRequired(
                    message or "A required desktop update is available.",
                    str(fields.get("minimum_version") or ""),
                    str(fields.get("download_url") or ""),
                ) from exc
            if status >= 500 or (status in (404, 405) and not code):
                raise AccountServiceUnavailable(message or "The account service is temporarily unavailable.") from exc
            if code:
                raise AuthError(message or f"Account service returned HTTP {status}.", code, status) from exc
            if status in (401, 403):
                raise AuthError(message or "Authorization failed.", "UNAUTHORIZED", status) from exc
            raise AuthError(message or f"Account service returned HTTP {status}.", "ACCOUNT_API_ERROR", status) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise AccountServiceUnavailable() from exc
        if not 200 <= status < 300:
            raise AuthError(f"Account service returned HTTP {status}.", "ACCOUNT_API_ERROR", status)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AuthError("The account service returned invalid JSON.", "INVALID_RESPONSE") from exc
        if not isinstance(parsed, dict):
            raise AuthError("The account service returned an invalid response.", "INVALID_RESPONSE")
        return parsed

    def start_pairing(self, device_name: str) -> dict:
        verifier = secrets.token_urlsafe(32)
        challenge = hashlib.sha256(verifier.encode("utf-8")).hexdigest()
        body = {
            "challenge": challenge,
            "device_name": str(device_name)[:120],
            "app_version": self.config.version,
            "platform": self.config.platform_key,
        }
        result = self._request("POST", "/api/desktop/device-start", body)
        if result.get("ok") is False:
            raise AuthError(
                str(result.get("error") or "Pairing could not be started."),
                str(result.get("code") or "PAIRING_FAILED"),
            )
        request_id = str(result.get("request_id") or "").strip()
        if not request_id:
            raise AuthError("The account service did not return a pairing request.", "INVALID_RESPONSE")
        interval = _positive_int(result.get("interval"), DEFAULT_INTERVAL)
        expires_in = _positive_int(result.get("expires_in"), PAIRING_TTL)
        verification_uri = _safe_verification_uri(self.config.api_base, result.get("verification_uri"))
        user_code = str(result.get("user_code") or "").strip()
        if not user_code:
            raise AuthError("The account service did not return a pairing code.", "INVALID_RESPONSE")
        self._pending[request_id] = {
            "verifier": verifier,
            "created_at": time.time(),
            "expires_at": time.time() + expires_in,
        }
        return {
            "request_id": request_id,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "interval": interval,
            "expires_in": expires_in,
        }

    def poll_pairing(self, request_id: str) -> dict:
        pending = self._pending.get(request_id)
        if not pending:
            raise AuthError("Unknown or expired pairing request.", "PAIRING_NOT_FOUND", 404)
        if time.time() > pending["expires_at"]:
            self._pending.pop(request_id, None)
            return {"status": "expired"}
        result = self._request(
            "POST",
            "/api/desktop/device-poll",
            {"request_id": request_id, "verifier": pending["verifier"]},
        )
        status = str(result.get("status") or "").lower()
        if status == "pending":
            return {"status": "pending", "retry_after": _positive_int(result.get("interval"), DEFAULT_INTERVAL)}
        if status in ("expired", "denied"):
            self._pending.pop(request_id, None)
            return {"status": status}
        if status != "approved":
            raise AuthError("The account service returned an unknown pairing state.", "INVALID_RESPONSE")
        token = str(result.get("token") or "").strip()
        user = result.get("user") if isinstance(result.get("user"), dict) else {}
        uid = str(user.get("id") or user.get("uid") or "").strip()
        if not token or not uid:
            raise AuthError("The account service did not return a valid session.", "INVALID_RESPONSE")
        expires_in = _positive_int(
            result.get("expires_in"),
            max(300, int(float(result.get("expires_at") or 0) - time.time()))
            if result.get("expires_at")
            else 7 * 24 * 3600,
        )
        session = Session(
            token=token,
            uid=uid,
            username=str(user.get("username") or ""),
            global_name=str(user.get("global_name") or user.get("username") or ""),
            avatar=user.get("avatar"),
            expires_at=time.time() + expires_in,
        )
        self._save(session)
        self._pending.pop(request_id, None)
        return {"status": "approved", "user": session.public()}

    def _save(self, session: Session) -> None:
        try:
            self.store.set(encode_session(session.to_dict()))
        except CredentialError as exc:
            raise AuthError(
                str(exc),
                "CREDENTIAL_STORE_UNAVAILABLE",
                503,
            ) from exc

    def _read_session(self) -> Session | None:
        try:
            raw = self.store.get()
        except CredentialError as exc:
            raise AuthError(
                str(exc),
                "CREDENTIAL_STORE_UNAVAILABLE",
                503,
            ) from exc
        value = decode_session(raw)
        if not value:
            return None
        session = Session.from_dict(value)
        if not session:
            try:
                self.store.delete()
            except CredentialError as exc:
                raise AuthError(
                    str(exc),
                    "CREDENTIAL_STORE_UNAVAILABLE",
                    503,
                ) from exc
            return None
        if session.expires_at <= time.time():
            try:
                self.store.delete()
            except CredentialError as exc:
                raise AuthError(
                    str(exc),
                    "CREDENTIAL_STORE_UNAVAILABLE",
                    503,
                ) from exc
            return None
        if "premium_token" in value:
            self._save(session)
        return session

    def load_session(self) -> Session | None:
        return self._read_session()

    def clear_session(self) -> None:
        try:
            self.store.delete()
        except CredentialError as exc:
            raise AuthError(
                str(exc),
                "CREDENTIAL_STORE_UNAVAILABLE",
                503,
            ) from exc
        self._pending.clear()

    def logout(self) -> None:
        session = self.load_session()
        if session:
            try:
                self._request("POST", "/api/desktop/logout", {}, token=session.token)
            except AuthError:
                pass
        self.clear_session()

    def fetch_account(self) -> dict:
        session = self.load_session()
        if not session:
            raise AuthError("Not authenticated.", "AUTH_REQUIRED", 401)
        try:
            result = self._request("GET", "/api/desktop/session", token=session.token)
        except AuthError as exc:
            if exc.status == 401 or exc.code in ("UNAUTHORIZED", "AUTH_REQUIRED"):
                self.clear_session()
            raise
        user = result.get("user") if isinstance(result.get("user"), dict) else {}
        return {
            "user": {
                "id": str(user.get("id") or session.uid),
                "username": str(user.get("username") or session.username),
                "global_name": str(user.get("global_name") or session.global_name),
                "avatar": user.get("avatar", session.avatar),
            },
            "session": session.public(),
        }

    def fetch_entitlements(self) -> dict:
        session = self.load_session()
        if not session:
            raise AuthError("Not authenticated.", "AUTH_REQUIRED", 401)
        try:
            result = self._request(
                "GET",
                "/api/desktop/entitlements",
                token=session.token,
            )
        except AuthError as exc:
            if exc.status == 401 or exc.code in ("UNAUTHORIZED", "AUTH_REQUIRED"):
                self.clear_session()
            raise
        return result

    def account_state(self) -> dict:
        try:
            session = self.load_session()
        except AuthError as exc:
            return {
                "linked": False,
                "online": True,
                "authenticated": False,
                "premium": False,
                "user": None,
                "missions": {},
                "warning": str(exc),
                "code": exc.code,
            }
        if not session:
            return {
                "linked": False,
                "online": True,
                "authenticated": False,
                "premium": False,
                "user": None,
                "missions": {},
                "warning": "",
            }
        try:
            account = self.fetch_account()
            entitlements = self.fetch_entitlements()
        except AccountServiceUnavailable as exc:
            return {
                "linked": True,
                "online": False,
                "authenticated": False,
                "premium": False,
                "user": session.public(),
                "missions": {},
                "warning": str(exc),
            }
        except AuthError as exc:
            return {
                "linked": False,
                "online": True,
                "authenticated": False,
                "premium": False,
                "user": None,
                "missions": {},
                "warning": str(exc),
            }
        premium = entitlements.get("premium") if isinstance(entitlements.get("premium"), dict) else {}
        missions = entitlements.get("missions") if isinstance(entitlements.get("missions"), dict) else {}
        return {
            "linked": True,
            "online": True,
            "authenticated": True,
            "premium": bool(premium.get("active")),
            "user": account["user"],
            "missions": missions,
            "warning": "",
        }


def _positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _error_fields(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
