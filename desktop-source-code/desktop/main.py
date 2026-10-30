from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

from .app import DesktopApp
from .config import Config
from .security.local_server import LocalServer


def _valid_api_base(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="rm7-desktop", description="RM7 Nexus desktop control plane")
    parser.add_argument("--no-ui", action="store_true", help="run the local API without opening a browser")
    parser.add_argument("--no-browser", action="store_true", help="print the local URL without opening a browser")
    parser.add_argument("--api-base", default="", help="override the RM7 Nexus account service URL")
    args = parser.parse_args(argv)
    if args.api_base and not _valid_api_base(args.api_base.rstrip("/")):
        parser.error("--api-base must be HTTPS or a loopback HTTP URL")
    return args


class InstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            handle.seek(0)
            handle.write(b"0")
            handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()).encode("ascii"))
        handle.flush()
        self._handle = handle
        return True

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            handle.close()
        except OSError:
            pass


def _prewarm(app: DesktopApp) -> None:
    try:
        app.refresh_checks(include_network=True, force=True)
    except Exception as exc:
        app.logger.event("diagnostics.prewarm_failed", error=str(exc)[:300])
    try:
        app.refresh_update(force=True)
    except Exception as exc:
        app.logger.event("update.prewarm_failed", error=str(exc)[:300])
    try:
        app.refresh_account()
    except Exception as exc:
        app.logger.event("account.prewarm_failed", error=str(exc)[:300])


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    config = Config()
    if args.api_base:
        config.api_base = args.api_base.rstrip("/")
    config.ensure_dirs()

    lock = InstanceLock(config.config_dir / "desktop.lock")
    if not lock.acquire():
        print(
            "RM7 Nexus Desktop is already running. Use the existing browser window or close it before starting again.",
            file=sys.stderr,
            flush=True,
        )
        return 1

    app = DesktopApp(config)
    server = LocalServer(app, host=config.server_host)
    try:
        server.start()
        url = server.url

        app.logger.event(
            "app.started",
            version=config.version,
            platform=sys.platform,
            port=server.port,
            ui=not args.no_ui,
        )

        def request_shutdown(signum=None, frame=None) -> None:
            app.request_shutdown()

        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            signum = getattr(signal, name, None)
            if signum is not None:
                try:
                    signal.signal(signum, request_shutdown)
                except (OSError, ValueError):
                    pass

        threading.Thread(target=_prewarm, args=(app,), name="rm7-prewarm", daemon=True).start()

        print(app.welcome(), file=sys.stderr, flush=True)
        print(f"Local control plane: {url}", file=sys.stderr, flush=True)

        opened = False
        if not args.no_ui and not args.no_browser:
            try:
                opened = webbrowser.open(server.bootstrap_url, new=2, autoraise=True)
            except Exception as exc:
                app.logger.event("ui.browser_failed", error=str(exc)[:300])
        if not opened:
            print(
                f"Open this one-time link to use the desktop UI: {server.bootstrap_url}",
                file=sys.stderr,
                flush=True,
            )

        while not app.shutdown_requested:
            time.sleep(0.25)
    except KeyboardInterrupt:
        app.request_shutdown()
    finally:
        app.logger.event("app.stopping")
        app.jobs.cancel_all()
        time.sleep(0.2)
        server.stop()
        app.logger.event("app.stopped")
        lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
