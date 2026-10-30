# RM7 Nexus Desktop — Sanitized Source Export

This directory is a source-only export of the RM7 Nexus desktop application. It
contains application-owned Python, JavaScript, HTML, CSS, Lua, packaging scripts,
and safe documentation. It does not contain credentials, private keys, production
environment values, user data, installers, compiled executables, or build output.

The export is intentionally smaller than the private build repository. Binary
runtime assets (icons, GIF background, `glue.wasm`, bundled Node.js, vendored
`node_modules`) and website-only code are not copied. See
`SECURITY_REVIEW.md` and `SOURCE_INVENTORY.md` for the exact scope.

## What the application is

RM7 Nexus Desktop is a local control plane for RM7 Nexus tools. The desktop process
starts a loopback-only HTTP server, opens the user's default browser, and serves a
local web UI. The UI talks only to the local server. The local server performs
account pairing and authorization against the RM7 Nexus service, runs local
processing engines, manages job files, and handles signed updates.

The application does not embed a WebView. It uses the system browser, which keeps
the GUI portable across Windows and Linux.

## Architecture

### Entry points

| Entry point | Purpose |
| --- | --- |
| `desktop/main.py` | Canonical application entry point. Parses arguments, acquires a single-instance lock, starts the local server, opens the browser, and handles shutdown. |
| `desktop/__main__.py` | Allows `python -m desktop`. |
| `desktop/packaging/entry.py` | PyInstaller/Linux entry wrapper. |
| `desktop/packaging/entry_windows.py` | Nuitka/PyInstaller Windows entry wrapper. |
| `desktop/app.py` | `DesktopApp` orchestrator: state, jobs, engines, account, updates, diagnostics, and policy. |

### Main modules

| Module | Responsibility |
| --- | --- |
| `desktop/config.py` | Runtime configuration, data directories, API base, update key, limits, and Node.js discovery. |
| `desktop/os_support.py` | Platform detection, per-platform data directories, installer validation and launch. |
| `desktop/logging_setup.py` | Structured JSON-lines logging with key-based redaction. |
| `desktop/diagnostics.py` | Environment, compatibility, and network checks. |
| `desktop/auth/client.py` | Device-code style pairing, session persistence, account and entitlement requests. |
| `desktop/auth/credentials.py` | Windows Credential Manager and Linux Secret Service storage; memory/unavailable fallbacks. |
| `desktop/engines/amx.py` | Runs the local DeAMX JavaScript/Lua engine through Node.js. |
| `desktop/engines/grab.py` | Loads the Grab Detector engine and runs the isolated Lua sandbox. |
| `desktop/engines/base.py` | Subprocess execution, timeouts, cancellation, process-tree termination, and minimal environment. |
| `desktop/jobs/manager.py` | Job records, concurrency, cancellation, outputs, and cleanup. |
| `desktop/security/local_server.py` | Loopback HTTP server, bootstrap/session/CSRF protection, UI routes, and local API. |
| `desktop/security/paths.py` | Path containment and safe filename handling. |
| `desktop/security/file_save.py` | Output saving and opening output folders. |
| `desktop/security/lua_libraries.py` | Lua library catalog, upload staging, validation, and installation. |
| `desktop/updates.py` | Signed manifest verification, update policy, download, SHA-256/size verification, and installer launch. |

### Runtime helper source

The desktop engines depend on source outside the `desktop/` package:

| Path | Purpose |
| --- | --- |
| `lib/deamx.js` | Node.js adapter used by the AMX engine. |
| `lib/grab_detector_engine.py` | Grab Detector analysis engine loaded by the desktop process. |
| `api/DeAmx/*.lua` | DeAMX Lua implementation used by the AMX engine. |
| `grab-detector-sandbox/runtime.mjs` | Isolated Lua runtime entry point. |
| `grab-detector-sandbox/sandbox-prelude.lua` | Lua compatibility and mock layer. |
| `grab-detector-sandbox/vendor/wasmoon/index.js` | Vendored Lua/WASM runtime (MIT). |
| `grab-detector-sandbox/vendor/wasmoon/LICENSE` | Third-party license. |

Binary runtime assets required by packaging but excluded from this source export:

- `api/glue.wasm`
- `grab-detector-sandbox/vendor/wasmoon/glue.wasm`
- `background.gif`
- `desktop/packaging/assets/rm7nexus.ico`
- `desktop/packaging/assets/rm7nexus.png`
- `node_modules/wasmoon/*`
- `vendor/node/node` or `vendor/node/node.exe`

## How the GUI talks to the local backend

1. `main.py` creates `LocalServer` bound to `127.0.0.1` on an ephemeral port.
2. It generates a one-time bootstrap nonce, a local session token, and a CSRF
   token using `secrets`.
3. It opens the browser at `http://127.0.0.1:<port>/?bootstrap=<nonce>`.
4. The UI posts the nonce to `/api/session/bootstrap`; the server consumes the
   nonce once and returns an `HttpOnly`, `SameSite=Strict` session cookie plus a
   CSRF token.
5. Every `/api/*` GET requires the local session cookie. Every state-changing POST
   also requires the `X-RM7-CSRF` header.
6. The server rejects non-loopback clients, invalid `Host` headers, cross-origin
   `Origin` values, and cross-site `Sec-Fetch-Site` requests.
7. The UI sends JSON to local routes such as `/api/state`, `/api/pair/start`,
   `/api/jobs/amx`, `/api/jobs/grab`, `/api/update`, and `/api/shutdown`.

The local server is not a general proxy. It serves the local UI, local state, and
local job APIs only.

## Local processing

### AMX to PWN

`AmxEngine` validates the runner, adapter, WASM glue, and DeAMX Lua files, then runs
`desktop/engines/amx_runner.mjs` under Node.js in a temporary job directory. The
Node process is started with `minimal_env()`, a timeout, and cancellation support.

### Grab Detector

`GrabEngine` loads `lib/grab_detector_engine.py` (or its compiled `.pyc` in packaged
builds). Normal mode uses static analysis. Performed mode uses the isolated Lua
sandbox and requires Linux Bubblewrap; the Windows build fails closed for performed
mode. The sandbox blocks outbound network access and records only synthetic request
evidence.

## Configuration loading

Configuration is loaded in `desktop/config.py`:

- `Config` dataclass defaults are code-level defaults.
- Environment variables override selected values.
- `RM7_API_BASE` must be HTTPS, or loopback HTTP for local development.
- `RM7_UPDATE_CHANNEL` must match the signed release manifest channel.
- `RM7_UPDATE_PUBLIC_KEY` is a Base64-encoded Ed25519 **public** key.
- Numeric limits are clamped to safe ranges.
- Data lives under the platform data directory:
  - Windows: `%LOCALAPPDATA%\RM7Nexus`
  - Linux: `$XDG_DATA_HOME/rm7nexus` or `~/.local/share/rm7nexus`

See `ENVIRONMENT_VARIABLES.md` for the full list. No real values are included.

## Update flow

The desktop updater fetches `/releases/manifest.json` and
`/releases/manifest.json.sig` from the configured API base, verifies the Ed25519
signature, validates the manifest schema and platform artifact, then downloads the
installer through the authenticated `/api/desktop/download` endpoint. Downloads are
size-limited and SHA-256 verified before installation.

The website download page is separate: it requires an authenticated website
session, requests `/api/desktop/download`, and sends the browser to the returned
URL. It does not proxy installer bytes through the website.

## Packaging

### Linux

`desktop/packaging/build-linux.sh` performs a PyInstaller build using
`desktop/packaging/rm7-desktop.spec`, stages the runtime files, creates a Debian
package with `dpkg-deb`, and writes a SHA-256 file. The package targets Debian
amd64 and depends on `xdg-utils`.

### Windows

`desktop/packaging/build.ps1` supports two backends:

- Nuitka standalone (default)
- PyInstaller one-folder fallback (`RM7_WINDOWS_STAGE`)

The Windows path uses `windows_release.py` to stage an allow-listed runtime set,
compile the Grab Detector engine, scan for credential-like values and forbidden
files, verify PE architecture, and write checksums/release metadata. Inno Setup
(`rm7nexus.iss`) produces the installer.

These scripts are included for understanding the build. Building requires external
tools and binary assets not present in this export.

## Development

Safe local development outline:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r desktop/packaging/requirements-desktop.txt
python -m desktop --no-browser --api-base https://YOUR_API_DOMAIN.example
```

Node.js 24.x is required for the AMX and Grab sandbox engines. The desktop runtime
Node dependency is `wasmoon`; the private build expects it under
`node_modules/wasmoon`.

The application rejects non-loopback binds and non-HTTPS API bases (except loopback
HTTP). Do not set production secrets in a shell history file.

## External services and dependencies

- RM7 Nexus account/release API (HTTPS; configured, not hardcoded in this export).
- Discord-based account authorization handled by the RM7 Nexus service.
- Node.js 24.x runtime.
- Python 3.11–3.13.
- `cryptography`, `pyinstaller`, and Linux `secretstorage`.
- `wasmoon` (MIT) for Lua/WASM execution.
- Windows Credential Manager or Linux Secret Service for session storage.
- Linux Bubblewrap for performed-mode sandboxing.
- Inno Setup and Nuitka/PyInstaller for packaging.

No credentials are included. No external service is contacted by this export.

## Readiness note

This is a source export, not a functional installer bundle. It is suitable for code
review and architecture understanding. Rebuilding requires the excluded binary
runtime assets, the Node.js runtime, `node_modules/wasmoon`, and the normal build
toolchain.
