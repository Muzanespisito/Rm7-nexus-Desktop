#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERSION_RE = re.compile(r"^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]{1,64}))?$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,299}$")
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024


class ReleaseToolError(RuntimeError):
    pass


def parse_version(value: str) -> tuple[int, ...]:
    match = VERSION_RE.match(str(value or "").strip())
    if not match:
        raise ReleaseToolError(f"Invalid version: {value!r}")
    core = (match.group(1), match.group(2), match.group(3))
    if any(len(part) > 1 and part.startswith("0") for part in core):
        raise ReleaseToolError(f"Invalid version: {value!r}")
    pre_parts = (match.group(4) or "").split(".") if match.group(4) else []
    if any(
        not part or (part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in pre_parts
    ):
        raise ReleaseToolError(f"Invalid version: {value!r}")
    pre = tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in pre_parts
    )
    return tuple(int(part) for part in core) + ((0 if pre else 1,), pre)


def load_private_key(path: Path, allow_insecure: bool) -> Ed25519PrivateKey:
    if not path.is_file():
        raise ReleaseToolError(f"Signing key not found: {path}")
    if os.name != "nt" and not allow_insecure:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ReleaseToolError("Signing key permissions are too open; use chmod 600.")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise ReleaseToolError("Signing key could not be read.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseToolError("Signing key must be an unencrypted Ed25519 PEM key.")
    return key


def artifact_entry(path: Path, platform: str, pathname: str | None) -> dict[str, Any]:
    if not path.is_file():
        raise ReleaseToolError(f"Artifact not found: {path}")
    suffix = ".exe" if platform == "windows" else ".deb"
    if path.suffix.lower() != suffix:
        raise ReleaseToolError(f"{platform} artifact must end with {suffix}.")
    name = path.name
    if not NAME_RE.match(name):
        raise ReleaseToolError(f"Artifact name is unsafe: {name!r}")
    size = path.stat().st_size
    if not 1 <= size <= MAX_ARTIFACT_BYTES:
        raise ReleaseToolError(f"Artifact size is invalid: {size}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    content_type = (
        "application/octet-stream"
        if platform == "windows"
        else "application/vnd.debian.binary-package"
    )
    pathname = pathname or f"releases/{name}"
    if (
        not PATH_RE.match(pathname)
        or ".." in pathname.split("/")
        or pathname.endswith("/")
        or not pathname.startswith("releases/")
    ):
        raise ReleaseToolError(f"Artifact pathname is invalid: {pathname!r}")
    return {
        "pathname": pathname,
        "sha256": digest.hexdigest(),
        "size": size,
        "content_type": content_type,
    }


def build_manifest(args: argparse.Namespace, key: Ed25519PrivateKey) -> tuple[bytes, str]:
    parse_version(args.version)
    parse_version(args.minimum_version)
    if parse_version(args.minimum_version) > parse_version(args.version):
        raise ReleaseToolError("Minimum version cannot exceed the release version.")
    if args.channel != args.channel.strip().lower() or not re.fullmatch(r"[a-z0-9._-]{1,32}", args.channel):
        raise ReleaseToolError("Channel must be lowercase letters, digits, dot, dash or underscore.")
    platforms: dict[str, Any] = {"windows": None, "linux": None}
    if args.windows:
        platforms["windows"] = {
            "artifact": artifact_entry(args.windows, "windows", args.windows_pathname)
        }
    if args.linux:
        platforms["linux"] = {
            "artifact": artifact_entry(args.linux, "linux", args.linux_pathname)
        }
    if not any(platforms.values()):
        raise ReleaseToolError("At least one platform artifact is required.")
    notes = list(args.notes)
    if args.notes_file:
        notes.extend(
            line.strip()
            for line in args.notes_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    notes = [note.replace("\x00", "").strip()[:500] for note in notes if note.strip()]
    if len(notes) > 20:
        raise ReleaseToolError("At most 20 release notes are allowed.")
    published = args.published_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseToolError("Published timestamp is invalid.") from exc
    manifest = {
        "schema": 1,
        "channel": args.channel,
        "version": args.version,
        "minimum_version": args.minimum_version,
        "mandatory": bool(args.mandatory),
        "published_at": published,
        "notes": notes,
        "platforms": platforms,
    }
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return payload, base64.b64encode(raw_public).decode("ascii")


def write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".release-", delete=False)
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a signed RM7 Nexus desktop release manifest.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--minimum-version", default="")
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--mandatory", action="store_true")
    parser.add_argument("--windows", type=Path)
    parser.add_argument("--linux", type=Path)
    parser.add_argument("--windows-pathname")
    parser.add_argument("--linux-pathname")
    parser.add_argument("--notes", action="append", default=[])
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--published-at", default="")
    parser.add_argument("--output-dir", type=Path, default=Path("releases"))
    parser.add_argument("--key", type=Path, default=Path(os.environ.get("RM7_UPDATE_SIGNING_KEY", "")))
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--allow-insecure-key", action="store_true")
    args = parser.parse_args(argv)
    if not args.minimum_version:
        args.minimum_version = args.version if args.mandatory else "0.0.0"
    if not args.key or str(args.key) in ("", "."):
        parser.error("--key or RM7_UPDATE_SIGNING_KEY is required")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        key = load_private_key(args.key, args.allow_insecure_key)
        payload, public_key = build_manifest(args, key)
        public_file = args.output_dir / "public-key.txt"
        if public_file.is_file() and public_file.read_text(encoding="utf-8").strip() != public_key:
            raise ReleaseToolError("The signing key does not match releases/public-key.txt.")
        manifest_file = args.output_dir / "manifest.json"
        signature_file = args.output_dir / "manifest.json.sig"
        if not args.force and (manifest_file.exists() or signature_file.exists()):
            raise ReleaseToolError("Release manifest already exists; pass --force to replace it.")
        signature = key.sign(payload)
        write_atomic(manifest_file, payload)
        write_atomic(signature_file, base64.b64encode(signature) + b"\n")
        print(f"Signed {args.version} ({args.channel}) -> {manifest_file}")
        print(f"Public key: {public_key}")
        print("Artifacts were not uploaded. Upload them to Blob at the exact signed pathnames.")
        return 0
    except ReleaseToolError as exc:
        print(f"release signing failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
