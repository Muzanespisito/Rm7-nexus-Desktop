# Grab Detector isolated runtime

Developer notes for the Lua execution sandbox. Public reports use the label
`Isolated Lua Runtime` and do not expose the deployment backend.

## Execution model

- `runtime.mjs` starts an embedded Lua engine, loads `sandbox-prelude.lua`, then runs the uploaded chunk.
- Outbound network access is blocked. HTTP APIs are replaced by local mocks.
- No request is ever sent by a mock. Captured entries carry `sent: false`.
- `wait()` advances a virtual clock and is bounded by wait-count, virtual-time, instruction, wall-clock, and event budgets.
- Lua 5.1 / LuaJIT compatibility shims cover `setfenv`, `getfenv`, `unpack`, `string.gfind`, `table.getn`, legacy math aliases (`mod`, `pow`, `ldexp`, `frexp`), `newproxy`, `jit`, and 32-bit `bit` operations.
- SAMP getters include `sampGetPlayerNickname`, `sampGetCurrentServerAddress`, and `sampGetPlayerIdByCharHandle`.
- The `requests` mock accepts both `requests.post(url, options)` and `requests.post({url = ..., data = ...})` forms.

## Captured evidence

Each request records:

- method, redacted URL, redacted headers, redacted body
- originating mock API, Lua caller, and synthetic event
- `synthetic_login_input: true` when the fake dialog password appears in the request
- `engine` and `observed_by` so duplicate evidence from multiple capture mechanisms can be merged

Requests are normalised and deduplicated in `lib/grab_detector_engine.py`.

## Synthetic events

The runtime delivers, when registered:

- `onScriptLoad`
- `onShowDialog`
- `onSendDialogResponse` with `inputText = RM7_FAKE_TEST_PASSWORD`
- server, player, sync, stream, and disconnect events

Synthetic values:

- player: `RM7_TestPlayer`
- server: `RM7 Sandbox Server`
- server IP: `192.0.2.10`
- login input: `RM7_FAKE_TEST_PASSWORD`

The password is fake and is redacted from public reports. Dialog handlers can
still run after a top-level runtime error; a compile failure prevents event
delivery.

## Compatibility diagnostics

An uninitialised upvalue such as `v8` is reported as `LUA_VM_COMPATIBILITY`,
not `UNSUPPORTED_API`. This distinguishes closure/runtime state from a missing
MoonLoader global. Obfuscator-generated closures commonly use this pattern.

## Known limits

- Only mocked APIs are visible. Native libraries and raw sockets are not executed.
- A proxy cannot observe native traffic because no native traffic leaves the runtime.
- A clean run or zero captured requests is not a safety verdict.
- Wall-clock and CPU budgets are intentionally lower than a real game client.

## Threat assessment

`assess_threat()` in `lib/grab_detector_engine.py` scores request evidence:

- captured requests and request bodies
- credential-like field names
- synthetic login input
- known webhook/bot sinks
- obfuscation combined with credential evidence
- static-only evidence, capped to avoid critical labels without runtime proof

The score drives a prominent report warning, but the report never declares a
file safe or definitely malicious.

## Tests

```sh
node --test tests/grab-detector.test.cjs
```
