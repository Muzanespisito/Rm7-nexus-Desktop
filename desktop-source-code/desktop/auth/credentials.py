from __future__ import annotations

import ctypes
import json
import sys
from ctypes import wintypes
from typing import Protocol

TARGET = "RM7NexusDesktop/session"
USERNAME = "RM7 Nexus Desktop"
SECRET_SERVICE_LABEL = "RM7 Nexus desktop session"
SECRET_SERVICE_ATTRIBUTES = {
    "application": "rm7n3xus-desktop",
    "service": TARGET,
}


class CredentialError(RuntimeError):
    pass


class CredentialStore(Protocol):
    def get(self) -> str | None: ...

    def set(self, value: str) -> None: ...

    def delete(self) -> None: ...


class MemoryCredentialStore:
    def __init__(self, value: str | None = None) -> None:
        self._value = value

    def get(self) -> str | None:
        return self._value

    def set(self, value: str) -> None:
        self._value = value

    def delete(self) -> None:
        self._value = None


class UnavailableCredentialStore:
    def __init__(self, message: str) -> None:
        self.message = message

    def get(self) -> str | None:
        return None

    def set(self, value: str) -> None:
        raise CredentialError(self.message)

    def delete(self) -> None:
        return None


class LinuxSecretServiceStore:
    def __init__(self) -> None:
        self._backend_error = ""

    def _run(self, action):
        try:
            import secretstorage
        except ImportError as exc:
            raise CredentialError("Secret Service support is not installed.") from exc
        connection = None
        try:
            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)
            if collection.is_locked() and not collection.unlock():
                raise CredentialError("The system keyring is locked.")
            return action(collection)
        except CredentialError:
            raise
        except Exception as exc:
            self._backend_error = str(exc)[:200]
            raise CredentialError(
                "Secure credential storage is unavailable. Unlock the system keyring and try again."
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    @staticmethod
    def _item(collection):
        items = list(collection.search_items(SECRET_SERVICE_ATTRIBUTES))
        if not items:
            return None
        for extra in items[1:]:
            try:
                extra.delete()
            except Exception:
                pass
        return items[0]

    def get(self) -> str | None:
        def action(collection):
            item = self._item(collection)
            if item is None:
                return None
            raw = item.get_secret()
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CredentialError("The stored desktop session is unreadable.") from exc

        return self._run(action)

    def set(self, value: str) -> None:
        raw = str(value).encode("utf-8")

        def action(collection):
            item = self._item(collection)
            if item is not None:
                item.set_secret(raw)
                return
            collection.create_item(
                SECRET_SERVICE_LABEL,
                dict(SECRET_SERVICE_ATTRIBUTES),
                raw,
                replace=True,
            )

        self._run(action)

    def delete(self) -> None:
        def action(collection):
            item = self._item(collection)
            if item is not None:
                item.delete()

        self._run(action)


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class WindowsCredentialStore:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    def __init__(self, target: str = TARGET) -> None:
        self.target = target
        self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._advapi32.CredWriteW.argtypes = [
            ctypes.POINTER(_CREDENTIALW),
            wintypes.DWORD,
        ]
        self._advapi32.CredWriteW.restype = wintypes.BOOL
        self._advapi32.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
        ]
        self._advapi32.CredReadW.restype = wintypes.BOOL
        self._advapi32.CredDeleteW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self._advapi32.CredDeleteW.restype = wintypes.BOOL
        self._advapi32.CredFree.argtypes = [ctypes.c_void_p]
        self._advapi32.CredFree.restype = None

    def _error(self, action: str) -> CredentialError:
        code = ctypes.get_last_error()
        return CredentialError(f"{action} failed (Win32 error {code})")

    def get(self) -> str | None:
        pointer = ctypes.POINTER(_CREDENTIALW)()
        if not self._advapi32.CredReadW(
            self.target, self.CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)
        ):
            code = ctypes.get_last_error()
            if code == 1168:
                return None
            raise self._error("Credential read")
        try:
            credential = pointer.contents
            size = int(credential.CredentialBlobSize)
            if size <= 0 or not credential.CredentialBlob:
                return None
            raw = ctypes.string_at(credential.CredentialBlob, size)
            return raw.decode("utf-8")
        finally:
            self._advapi32.CredFree(pointer)

    def set(self, value: str) -> None:
        raw = str(value).encode("utf-8")
        blob = (ctypes.c_byte * len(raw)).from_buffer_copy(raw)
        credential = _CREDENTIALW()
        credential.Type = self.CRED_TYPE_GENERIC
        credential.TargetName = self.target
        credential.Comment = "RM7 Nexus desktop session"
        credential.CredentialBlobSize = len(raw)
        credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_byte))
        credential.Persist = self.CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = USERNAME
        if not self._advapi32.CredWriteW(ctypes.byref(credential), 0):
            raise self._error("Credential write")

    def delete(self) -> None:
        if not self._advapi32.CredDeleteW(self.target, self.CRED_TYPE_GENERIC, 0):
            code = ctypes.get_last_error()
            if code not in (1168, 5):
                raise self._error("Credential delete")


def build_credential_store() -> CredentialStore:
    if sys.platform == "win32":
        return WindowsCredentialStore()
    if sys.platform.startswith("linux"):
        return LinuxSecretServiceStore()
    return UnavailableCredentialStore("Secure credential storage is not supported on this platform.")


def encode_session(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def decode_session(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None
