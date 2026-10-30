import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { LuaFactory } = require("./vendor/wasmoon/index.js");

const RUNTIME_LABEL = "Isolated Lua Runtime";
const MAX_REQUESTS = clamp(Number(process.env.GD_MAX_REQUESTS) || 100, 1, 500);
const MAX_BODY = clamp(Number(process.env.GD_MAX_BODY) || 8192, 256, 131072);
const LUA_BUDGET_MS = clamp(Number(process.env.GD_LUA_BUDGET_MS) || 2500, 100, 10000);
const EVENT_BUDGET_MS = clamp(Number(process.env.GD_EVENT_BUDGET_MS) || 500, 100, 5000);
const SIMULATION_BUDGET_MS = clamp(Number(process.env.GD_SIMULATION_BUDGET_MS) || 3000, 500, 10000);
const MAX_WAIT_CALLS = clamp(Number(process.env.GD_MAX_WAIT_CALLS) || 400, 20, 2000);
const MAX_VIRTUAL_MS = clamp(Number(process.env.GD_MAX_VIRTUAL_MS) || 5000, 100, 60000);
const MAX_INSTRUCTIONS = clamp(Number(process.env.GD_MAX_INSTRUCTIONS) || 5000000, 100000, 50000000);
const SYNTHETIC_LOGIN_INPUT = "RM7_FAKE_TEST_PASSWORD";
const SOURCE_PATH = process.env.GD_SOURCE_PATH || "input/scan.lua";
const PRELUDE_PATH = process.env.GD_PRELUDE_PATH || "sandbox-prelude.lua";
const REQUESTS_PATH = process.env.GD_REQUESTS_PATH || "requests.ndjson";
const RESULT_PATH = process.env.GD_RESULT_PATH || "result.json";
const FILE_NAME = String(process.env.GD_FILE_NAME || "script.lua").slice(0, 120);
const LIBRARY_ROOT = process.env.GD_LIBRARY_ROOT ? path.resolve(process.env.GD_LIBRARY_ROOT) : "";
const LIBRARY_MANIFEST_PATH = process.env.GD_LIBRARY_MANIFEST || "";

const requests = [];
const metadata = {};
let capReached = false;
let libraryManifest = { modules: {} };

try {
  const manifest = JSON.parse(fs.readFileSync(LIBRARY_MANIFEST_PATH, "utf8"));
  if (manifest && manifest.modules && typeof manifest.modules === "object") libraryManifest = manifest;
} catch {}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

function emit(value) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

function cleanError(error) {
  return String(error?.message ?? error ?? "Lua execution failed")
    .split("stack traceback:")[0]
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\[string [\s\S]*?\]:\d+:\s*/g, "")
    .replace(/@\/[^\s:]+:\d+:\s*/g, "")
    .slice(0, 300);
}

function compatibilityIssue(error) {
  const message = cleanError(error);
  const match = message.match(/attempt to (?:call|index) a nil value \(upvalue '([^']+)'\)/);
  if (!match) return null;
  return {
    code: "LUA_VM_COMPATIBILITY",
    name: match[1].slice(0, 120),
    note: "A closure referenced an uninitialized upvalue. This is a Lua runtime-compatibility signal, not evidence that a MoonLoader API is missing. Obfuscator-generated closures commonly use short names such as this.",
  };
}

function unsupportedApi(error) {
  const message = cleanError(error);
  const patterns = [
    /attempt to call a nil value \(global '([^']+)'\)/,
    /attempt to call a nil value \(field '([^']+)'\)/,
    /attempt to index a nil value \(global '([^']+)'\)/,
    /attempt to index a nil value \(field '([^']+)'\)/,
  ];
  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (match) return match[1].slice(0, 120);
  }
  return null;
}

function missingModule(error) {
  const match = cleanError(error).match(/module '([^']+)' not found:/);
  return match ? match[1].slice(0, 120) : null;
}

function validModuleName(name) {
  return typeof name === "string" && name.length > 0 && name.length <= 160 &&
    !name.includes("..") && !/[\\/:]/.test(name) &&
    name.split(".").every((part) => /^[A-Za-z_][A-Za-z0-9_-]*$/.test(part));
}

function libraryModuleError(name) {
  if (!validModuleName(name)) return "module name is not a valid dotted Lua identifier";
  if (name === "ffi") return "LuaJIT FFI is unavailable; native modules are never loaded";
  const item = libraryManifest.modules?.[name];
  if (item?.status === "unsupported") return item.reason || "module is incompatible with the isolated runtime";
  if (!item) return "module was not found in the selected library directory or runtime mocks";
  return "module source is unavailable in the approved read-only snapshot";
}

function readLibraryModule(name) {
  if (!validModuleName(name) || !LIBRARY_ROOT) return undefined;
  const item = libraryManifest.modules?.[name];
  if (!item || !["compatible", "conditional"].includes(item.status) || typeof item.path !== "string") return undefined;
  const relative = item.path;
  if (path.isAbsolute(relative) || relative.split(/[\\/]/).includes("..")) return undefined;
  const resolved = path.resolve(LIBRARY_ROOT, relative);
  if (!resolved.startsWith(LIBRARY_ROOT + path.sep)) return undefined;
  try {
    const stat = fs.lstatSync(resolved);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) return undefined;
    const real = fs.realpathSync(resolved);
    if (!real.startsWith(LIBRARY_ROOT + path.sep)) return undefined;
    return fs.readFileSync(real, "utf8");
  } catch {
    return undefined;
  }
}

function pushMetadata(key, value) {
  const name = String(key || "").slice(0, 80);
  if (!name) return;
  metadata[name] = String(value ?? "").slice(0, 1000);
}

function pushRequest(item) {
  if (requests.length >= MAX_REQUESTS) {
    capReached = true;
    return;
  }
  if (!item || typeof item !== "object") return;
  const body = item.body;
  const bodyText = typeof body === "string" ? body : body == null ? "" : String(body);
  const entry = {
    method: String(item.method || "UNKNOWN").slice(0, 16),
    url: String(item.url || "").slice(0, 4000),
    body: typeof body === "string" ? body.slice(0, MAX_BODY) : body == null ? null : String(body).slice(0, MAX_BODY),
    headers: item.headers && typeof item.headers === "object" ? item.headers : {},
    api: String(item.api || "unknown").slice(0, 80),
    source: item.source == null ? null : String(item.source).slice(0, 120),
    event: item.event == null ? null : String(item.event).slice(0, 80),
    synthetic_login_input: Boolean(item.synthetic_login_input) || bodyText.includes(SYNTHETIC_LOGIN_INPUT),
    intercepted: true,
    blocked: true,
    sent: false,
    timestamp: new Date().toISOString(),
  };
  requests.push(entry);
  try {
    fs.appendFileSync(REQUESTS_PATH, JSON.stringify({ type: "request", request: entry }) + "\n");
  } catch {}
  emit({ type: "request", request: entry });
}

function asObject(value) {
  return value && typeof value === "object" ? value : {};
}

function normalizeObservations(value) {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, 50)
    .map((item) => {
      const raw = cleanError(item?.error || "");
      return {
        event: String(item?.event || "event").slice(0, 80),
        reason: String(item?.reason || "error").slice(0, 40),
        error: raw.startsWith("__rm7_") ? "" : raw.slice(0, 300),
      };
    })
    .filter((item) => item.error || item.reason !== "error");
}

function friendlyError(reason, message) {
  if (reason === "observation_window") {
    return "The script kept waiting or exceeded the observation window. Captured evidence is partial.";
  }
  if (reason === "instruction_limit" || reason === "lua_timeout") {
    return "The script exceeded the sandbox execution budget.";
  }
  return message || "Lua execution stopped before the chunk finished.";
}

function finish(result) {
  const payload = {
    execution_completed: false,
    timed_out: false,
    requests,
    metadata: { ...metadata },
    unsupported_api: null,
    missing_module: null,
    compatibility: null,
    simulated_inputs: [],
    error_code: null,
    error: null,
    observations: [],
    events_run: [],
    coverage_notes: [],
    runtime: RUNTIME_LABEL,
    runtime_limits: {
      lua_budget_ms: LUA_BUDGET_MS,
      event_budget_ms: EVENT_BUDGET_MS,
      simulation_budget_ms: SIMULATION_BUDGET_MS,
      max_wait_calls: MAX_WAIT_CALLS,
      max_virtual_ms: MAX_VIRTUAL_MS,
      max_instructions: MAX_INSTRUCTIONS,
      virtual_clock: true,
      lua_compatibility: "Lua 5.1 / LuaJIT shims",
      network: "deny-all",
    },
    ...result,
  };
  if (Array.isArray(payload.events_run) && payload.events_run.includes("onSendDialogResponse")) {
    payload.simulated_inputs = [{ event: "onSendDialogResponse", field: "inputText", kind: "login_password", synthetic: true }];
  }
  try {
    fs.writeFileSync(RESULT_PATH, JSON.stringify(payload));
  } catch {}
  emit({ type: "result", result: payload });
}

function statusForReason(reason, unsupported, compatibility, missing) {
  if (reason === "lua_timeout" || reason === "instruction_limit") {
    return { status: "timeout", error_code: "LUA_TIMEOUT", timed_out: true };
  }
  if (reason === "observation_window") {
    return { status: "incomplete", error_code: "OBSERVATION_WINDOW", timed_out: false };
  }
  if (reason === "compile") {
    return { status: "failed", error_code: "LUA_COMPILE_ERROR", timed_out: false };
  }
  return {
    status: "incomplete",
    error_code: missing ? "MISSING_LUA_MODULE" : compatibility ? "LUA_VM_COMPATIBILITY" : unsupported ? "UNSUPPORTED_API" : "LUA_RUNTIME_ERROR",
    timed_out: false,
  };
}

async function main() {
  let source;
  try {
    source = fs.readFileSync(SOURCE_PATH, "utf8");
  } catch {
    finish({
      status: "failed",
      error_code: "SANDBOX_INPUT_MISSING",
      error: "The Lua source could not be read inside the sandbox.",
      coverage_notes: ["The isolated runtime did not receive the uploaded source."],
    });
    return;
  }

  if (!source.trim()) {
    finish({
      status: "incomplete",
      error_code: "EMPTY_SOURCE",
      error: "No Lua source was provided.",
    });
    return;
  }

  let prelude;
  try {
    prelude = fs.readFileSync(PRELUDE_PATH, "utf8");
  } catch {
    finish({
      status: "failed",
      error_code: "SANDBOX_ASSETS_MISSING",
      error: "The Lua sandbox prelude is missing.",
      coverage_notes: ["The isolated runtime could not load its HTTP capture layer."],
    });
    return;
  }

  const factory = new LuaFactory();
  const lua = await factory.createEngine();

  try {
    lua.global.set("__capture", pushRequest);
    lua.global.set("__capture_metadata", pushMetadata);
    lua.global.set("__max_requests", MAX_REQUESTS);
    lua.global.set("__max_body", MAX_BODY);
    lua.global.set("__now_ms", () => Date.now());
    lua.global.set("__rm7_lua_budget_ms", LUA_BUDGET_MS);
    lua.global.set("__rm7_event_budget_ms", EVENT_BUDGET_MS);
    lua.global.set("__rm7_simulation_budget_ms", SIMULATION_BUDGET_MS);
    lua.global.set("__rm7_max_wait_calls", MAX_WAIT_CALLS);
    lua.global.set("__rm7_max_virtual_ms", MAX_VIRTUAL_MS);
    lua.global.set("__rm7_max_instructions", MAX_INSTRUCTIONS);
    lua.global.set("__rm7_read_module", readLibraryModule);
    lua.global.set("__rm7_module_error", libraryModuleError);
    await lua.doString(prelude, "sandbox-prelude.lua");

    const coverage = [
      "Lua code ran in an isolated runtime with outbound network access blocked.",
      "HTTP-style calls were routed through local mocks; no request was sent.",
      "Native socket and proxy traffic is not executed in this runtime.",
      "wait() advanced a virtual clock and was bounded; wall-clock sleeps never ran.",
      "Only mocked APIs are visible; unsupported native libraries may bypass inspection.",
    ];

    lua.global.set("__rm7_source", source);
    lua.global.set("__rm7_source_name", FILE_NAME);

    let sourceResult = {};
    let sourceFailure = null;
    try {
      sourceResult = asObject(await lua.doString("return __rm7_run_source()"));
    } catch (error) {
      sourceFailure = error;
      sourceResult = { ok: false, reason: "error", error: cleanError(error) };
    }

    const reason = String(sourceResult.reason || "");
    const sourceMessage = cleanError(sourceResult.error || sourceFailure || "");
    const sourceError = friendlyError(reason, sourceMessage);
    const unsupported = unsupportedApi(sourceError);
    const compatibility = compatibilityIssue(sourceError);
    const missing = missingModule(sourceError);
    const sourceOk = sourceResult.ok === true;

    let simulation = { events: [], observations: [] };
    let eventFailure = null;
    if (sourceResult.reason !== "compile") {
      try {
        simulation = asObject(
          await lua.doString(
            "local ok, res = pcall(__rm7_simulate); if not ok then return {ok=false, error=tostring(res)} end; return res"
          )
        );
      } catch (error) {
        eventFailure = error;
      }
    }

    let report = {};
    try {
      report = asObject(await lua.doString("return __rm7_dynamic_report()"));
    } catch {}

    const observations = normalizeObservations(
      Array.isArray(simulation.observations) ? simulation.observations : report.observations
    );
    const rawEvents = Array.isArray(simulation.events)
      ? simulation.events
      : Array.isArray(report.events_run)
        ? report.events_run
        : [];
    const eventsRun = rawEvents.map((name) => String(name).slice(0, 80)).slice(0, 30);

    if (!sourceOk) {
      const classification = statusForReason(reason, unsupported, compatibility, missing);
      coverage.push("The Lua chunk did not finish. Requests captured before the error are included.");
      if (reason === "compile") coverage.push("Synthetic events were not delivered because the source did not compile.");
      else if (eventsRun.length) coverage.push("Registered synthetic events were still delivered after the source error.");
      if (unsupported) {
        coverage.push(`Unsupported Lua/API symbol: ${unsupported}. Previously captured evidence remains valid.`);
      }
      if (compatibility) {
        coverage.push(`Lua runtime compatibility issue at upvalue '${compatibility.name}'. This is not classified as a missing MoonLoader API.`);
      }
      if (missing) coverage.push(`Missing or unsupported Lua module: ${missing}.`);
      coverage.push("A runtime error is not proof that the file is safe or malicious.");
      if (reason === "observation_window") {
        coverage.push("Execution stopped at the observation-window budget (wait calls or virtual time).");
      }
      if (classification.timed_out) {
        coverage.push("The script exceeded the wall-clock or instruction budget inside the sandbox.");
      }
      if (capReached || report.request_cap_reached) coverage.push("The request capture limit was reached.");
      finish({
        status: classification.status,
        execution_completed: false,
        timed_out: classification.timed_out,
        error_code: classification.error_code,
        error: sourceError || "Lua execution stopped before the chunk finished.",
        unsupported_api: unsupported,
        missing_module: missing,
        compatibility,
        observations,
        events_run: eventsRun,
        coverage_notes: coverage.filter(Boolean),
      });
      return;
    }

    if (eventFailure || simulation.ok === false) {
      const eventError = cleanError(eventFailure || simulation.error || "Synthetic event delivery failed");
      const eventUnsupported = unsupportedApi(eventError);
      const eventCompatibility = compatibilityIssue(eventError);
      const eventMissing = missingModule(eventError);
      coverage.push("The chunk loaded, but synthetic event delivery stopped.");
      if (eventUnsupported) coverage.push(`Unsupported Lua/API symbol: ${eventUnsupported}.`);
      if (eventCompatibility) coverage.push(`Lua runtime compatibility issue at upvalue '${eventCompatibility.name}'.`);
      if (eventMissing) coverage.push(`Missing or unsupported Lua module: ${eventMissing}.`);
      if (capReached || report.request_cap_reached) coverage.push("The request capture limit was reached.");
      finish({
        status: "incomplete",
        execution_completed: true,
        error_code: eventMissing ? "MISSING_LUA_MODULE" : eventCompatibility ? "LUA_VM_COMPATIBILITY" : eventUnsupported ? "UNSUPPORTED_API" : "EVENT_DELIVERY_ERROR",
        error: eventError,
        unsupported_api: eventUnsupported,
        missing_module: eventMissing,
        compatibility: eventCompatibility,
        observations,
        events_run: eventsRun,
        coverage_notes: coverage.filter(Boolean),
      });
      return;
    }

    const eventProblems = observations.length > 0;
    const eventTimedOut = observations.some((item) =>
      ["observation_window", "lua_timeout", "instruction_limit"].includes(item.reason)
    );
    const firstEventError = observations.find((item) => item.error)?.error || "";
    const eventUnsupported = observations.map((item) => unsupportedApi(item.error)).find(Boolean) || null;
    const eventCompatibility = observations.map((item) => compatibilityIssue(item.error)).find(Boolean) || null;
    const eventMissing = observations.map((item) => missingModule(item.error)).find(Boolean) || null;
    if (eventProblems) {
      coverage.push(
        eventTimedOut
          ? "One or more synthetic events stopped at the sandbox budget; evidence captured so far is included."
          : "One or more synthetic events raised a Lua error; evidence captured so far is included."
      );
      if (eventUnsupported) coverage.push(`Unsupported Lua/API symbol: ${eventUnsupported}.`);
      if (eventCompatibility) coverage.push(`Lua runtime compatibility issue at upvalue '${eventCompatibility.name}'.`);
      if (eventMissing) coverage.push(`Missing or unsupported Lua module: ${eventMissing}.`);
    }
    if (simulation.simulation_truncated || report.simulation_truncated) {
      coverage.push("Synthetic event simulation stopped at its total budget.");
    }
    if (capReached || report.request_cap_reached) coverage.push("The request capture limit was reached.");
    coverage.push("No synthetic event was sent to a real server; all captured URLs are observations, not proof of delivery.");

    finish({
      status: eventProblems ? "incomplete" : "completed",
      execution_completed: true,
      timed_out: false,
      error_code: eventProblems
        ? eventTimedOut
          ? "EVENT_OBSERVATION_WINDOW"
          : eventMissing
            ? "MISSING_LUA_MODULE"
            : eventCompatibility
            ? "LUA_VM_COMPATIBILITY"
            : eventUnsupported
              ? "UNSUPPORTED_API"
              : "EVENT_RUNTIME_ERROR"
        : null,
      error: eventProblems
        ? eventTimedOut
          ? "An event exceeded the sandbox budget."
          : friendlyError("error", firstEventError) || "A synthetic event raised an error."
        : null,
      unsupported_api: eventUnsupported,
      missing_module: eventMissing,
      compatibility: eventCompatibility,
      observations,
      events_run: eventsRun,
      coverage_notes: coverage.filter(Boolean),
    });
  } catch (error) {
    finish({
      status: "failed",
      error_code: "SANDBOX_FAILURE",
      error: cleanError(error),
      coverage_notes: ["The isolated Lua runtime failed before execution completed."],
    });
  } finally {
    try {
      lua.global.close();
    } catch {}
  }
}

main().catch((error) => {
  finish({
    status: "failed",
    error_code: "SANDBOX_FAILURE",
    error: cleanError(error),
    coverage_notes: ["The isolated Lua runtime failed before execution completed."],
  });
});
