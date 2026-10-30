# Environment Variables

No real environment values are included in this export. Use placeholders from
`.env.example` and obtain real values from the private deployment environment.

The desktop process reads variables directly from its process environment. It does
not ship a `.env` file and does not automatically load one.

## Desktop application

| Variable | Required | Sensitive | Controls | How it is obtained |
| --- | --- | --- | --- | --- |
| `RM7_API_BASE` | Optional | No | Base URL for account and release APIs. Defaults to a placeholder domain in this export. Must be HTTPS or loopback HTTP. | Environment or `--api-base`. |
| `RM7_UPDATE_CHANNEL` | Optional | No | Expected release channel. Defaults to `stable`. Must match the signed manifest. | Environment. |
| `RM7_UPDATE_PUBLIC_KEY` | Optional | No (public key) | Base64 Ed25519 public key used to verify release signatures. | Environment, otherwise the source default placeholder. |
| `RM7_NODE` | Optional | No | Absolute path to the Node.js binary used by local engines. | Environment, otherwise bundled/vendor discovery, then `PATH`. |
| `RM7_AMX_TIMEOUT_SECONDS` | Optional | No | AMX engine timeout, clamped to 10–1800 seconds. | Environment. |
| `RM7_JOB_CONCURRENCY` | Optional | No | Concurrent local jobs, clamped to 1–4. | Environment. |
| `RM7_MAX_UPLOAD_BYTES` | Optional | No | Maximum upload size, clamped to 1 KiB–512 MiB. | Environment. |
| `RM7_UPDATE_TIMEOUT_SECONDS` | Optional | No | Update network timeout, clamped to 3–120 seconds. | Environment. |
| `RM7_MAX_UPDATE_BYTES` | Optional | No | Maximum update download size, clamped to 1 MiB–4 GiB. | Environment. |

Platform variables read but not normally set by users:

| Variable | Purpose |
| --- | --- |
| `LOCALAPPDATA` | Windows base for the per-user data directory. |
| `XDG_DATA_HOME` | Linux base for the per-user data directory. |
| `XDG_RUNTIME_DIR` | Linux runtime/session environment. |
| `DBUS_SESSION_BUS_ADDRESS` | Linux Secret Service access. |

## Release signing tool

| Variable | Required | Sensitive | Controls |
| --- | --- | --- | --- |
| `RM7_UPDATE_SIGNING_KEY` | Required for `sign-release.py` if `--key` is omitted | **Yes — private key path** | Offline Ed25519 private key used to sign release metadata. Never set for the desktop client and never store in the repository. |

## Grab Detector engine

These are normally set by the private service or the desktop process. Limits are
clamped by code.

| Variable | Required | Sensitive | Controls |
| --- | --- | --- | --- |
| `GRAB_DETECTOR_MAX_BYTES` | Optional | No | Maximum uploaded Lua size. |
| `GRAB_DETECTOR_MAX_REQUESTS` | Optional | No | Maximum captured requests. |
| `GRAB_DETECTOR_HOURLY_LIMIT` | Optional | No | Hourly scan quota. |
| `GRAB_DETECTOR_DAILY_LIMIT` | Optional | No | Daily scan quota. |
| `GRAB_DETECTOR_SANDBOX_TIMEOUT_MS` | Optional | No | Sandbox wall-clock timeout. |
| `GRAB_DETECTOR_SANDBOX_MONTHLY_LIMIT` | Optional | No | Performed-scan monthly quota. |
| `GRAB_DETECTOR_LUA_BUDGET_MS` | Optional | No | Lua execution budget. |
| `GRAB_DETECTOR_EVENT_BUDGET_MS` | Optional | No | Synthetic event budget. |
| `GRAB_DETECTOR_SIMULATION_BUDGET_MS` | Optional | No | Mock simulation budget. |
| `GRAB_DETECTOR_MAX_WAIT_CALLS` | Optional | No | Maximum `wait()` calls. |
| `GRAB_DETECTOR_MAX_VIRTUAL_MS` | Optional | No | Maximum virtual clock advance. |
| `GRAB_DETECTOR_MAX_INSTRUCTIONS` | Optional | No | Maximum Lua instructions. |
| `GRAB_DETECTOR_FREE_DELAY_SECONDS` | Optional | No | Delay before free performed scans. |
| `GRAB_DETECTOR_SANDBOX_DISABLED` | Optional | No | Disables sandbox execution when set. |
| `PREMIUM_SECRET` | Optional | **Yes** | Server-side premium token signing secret. Not needed by the desktop client. |
| `SESSION_SECRET` | Optional | **Yes** | Server-side web session signing secret. Not needed by the desktop client. |
| `STORE_URL` | Optional | No | Audit-store endpoint. Default is a placeholder in this export. |
| `STORE_SECRET` | Optional | **Yes** | Shared secret for the audit store. |
| `VIRUSTOTAL_API_KEY` | Optional | **Yes** | VirusTotal API key used by the website analysis path. |
| `DATABASE_URL` | Optional | **Yes** | Database connection string used by the website, not the desktop client. |

## Sandbox child process

`runtime.mjs` receives only these values from the parent engine:

`GD_SOURCE_PATH`, `GD_RESULT_PATH`, `GD_REQUESTS_PATH`, `GD_PRELUDE_PATH`,
`GD_FILE_NAME`, `GD_LIBRARY_ROOT`, `GD_LIBRARY_MANIFEST`, `GD_MAX_BODY`,
`GD_MAX_REQUESTS`, `GD_MAX_INSTRUCTIONS`, `GD_MAX_WAIT_CALLS`, `GD_MAX_VIRTUAL_MS`,
`GD_LUA_BUDGET_MS`, `GD_EVENT_BUDGET_MS`, `GD_SIMULATION_BUDGET_MS`, and
`DEAMX_TIMEOUT_MS` for the AMX runner.

These are runtime plumbing values, not credentials.

## Website distribution variables (not used by the desktop client)

The website download flow uses separate Vercel variables:

- `DESKTOP_DOWNLOAD_WINDOWS_URL`
- `DESKTOP_DOWNLOAD_LINUX_URL`
- `DESKTOP_DOWNLOAD_HOSTS`
- `DESKTOP_DOWNLOAD_WINDOWS_SHA256`
- `DESKTOP_DOWNLOAD_LINUX_SHA256`
- `DESKTOP_DOWNLOAD_WINDOWS_SIZE`
- `DESKTOP_DOWNLOAD_LINUX_SIZE`

They are documented in the release audit report, not configured by this export.
