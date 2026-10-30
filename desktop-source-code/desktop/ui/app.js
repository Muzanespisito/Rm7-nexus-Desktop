(() => {
  "use strict";

  const VERSION = document.querySelector('meta[name="rm7-version"]').content;
  const $ = (id) => document.getElementById(id);
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let CSRF = "";

  let state = null;
  let selectedFile = null;
  let mode = "normal";
  let pairTimer = null;
  let pairBusy = false;
  let jobTimer = null;
  let currentJobId = null;
  let grabFile = null;
  let grabMode = "normal";
  let grabJobId = null;
  let grabTimer = null;
  let grabReportData = null;
  let updateState = null;
  let updateBannerDismissed = false;
  let updateBusy = false;

  class ApiError extends Error {
    constructor(message, code, status) {
      super(message);
      this.code = code || "REQUEST_FAILED";
      this.status = status || 0;
    }
  }

  async function bootstrapSession() {
    const url = new URL(window.location.href);
    const nonce = url.searchParams.get("bootstrap");
    if (nonce) {
      const response = await fetch("/api/session/bootstrap", {
        method: "POST",
        headers: { "X-RM7-Bootstrap": nonce, "Content-Type": "application/json" },
        body: "{}",
        cache: "no-store",
        credentials: "same-origin",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new ApiError(data.error || "The desktop session could not be initialized.", data.code, response.status);
      }
      CSRF = data.csrf || "";
      url.searchParams.delete("bootstrap");
      window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
      return;
    }
    const response = await fetch("/api/session", { cache: "no-store", credentials: "same-origin" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) {
      throw new ApiError(
        data.error || "The desktop session is no longer valid. Restart RM7 Nexus Desktop.",
        data.code || "SESSION_EXPIRED",
        response.status
      );
    }
    CSRF = data.csrf || "";
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "X-RM7-CSRF": CSRF }, options.headers || {});
    if (typeof options.body === "string" && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body,
      cache: "no-store",
      credentials: "same-origin",
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }
    if (!response.ok || data.ok === false) {
      throw new ApiError(data.error || `Request failed (${response.status})`, data.code, response.status);
    }
    return data;
  }

  async function formHeaders(extra = {}) {
    return Object.assign({ "X-RM7-CSRF": CSRF }, extra);
  }

  function withTimeout(promise, ms) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    return Promise.race([
      promise,
      new Promise((_, reject) => {
        controller.signal.addEventListener("abort", () => reject(new ApiError("Startup request timed out", "TIMEOUT", 0)));
      }),
    ]).finally(() => clearTimeout(timer));
  }

  function setLibraryStatus(message) {
    $("luaLibraryStatus").textContent = message;
    if ($("grabLibraryStatus")) $("grabLibraryStatus").textContent = message;
  }

  function setStage(name, status, label) {
    const node = document.querySelector(`.boot-stage[data-stage="${name}"]`);
    if (!node) return;
    node.dataset.state = status;
    node.querySelector(".boot-state").textContent = label || status.toUpperCase();
  }

  function bootProgress(value, message) {
    $("bootBar").style.width = `${Math.max(4, Math.min(100, value))}%`;
    if (message) $("bootMessage").textContent = message;
  }

  function stageFromChecks(report, key) {
    const checks = (report && report[key]) || [];
    const required = checks.filter((item) => item.required);
    if (required.some((item) => item.status === "fail")) return "fail";
    if (checks.some((item) => item.status === "warn")) return "warn";
    return "ok";
  }

  async function boot() {
    ["environment", "compatibility", "update", "account", "entitlements", "dashboard"].forEach((name) =>
      setStage(name, "running", "CHECK")
    );
    bootProgress(12, "Reading local environment…");
    $("bootRetry").classList.add("hidden");
    try {
      await withTimeout(bootstrapSession(), 10000);
      const data = await withTimeout(api("/api/state"), 25000);
      state = data;
      bootProgress(48, "Evaluating mission engines…");
      const env = stageFromChecks(data.checks, "environment");
      const compat = stageFromChecks(data.checks, "compatibility");
      setStage("environment", env, env.toUpperCase());
      setStage("compatibility", compat, compat.toUpperCase());
      bootProgress(56, "Verifying the signed update policy…");
      let update = data.update || null;
      try {
        const result = await withTimeout(api("/api/update?refresh=1"), 15000);
        update = result.update || update;
      } catch (error) {
        setStage("update", "warn", "UNAVAILABLE");
      }
      const updateBlocked = applyUpdate(update);
      if (updateBlocked) {
        setStage("update", "warn", "REQUIRED");
        setStage("account", "warn", "LOCKED");
        setStage("entitlements", "warn", "LOCKED");
        setStage("dashboard", "fail", "BLOCKED");
        bootProgress(100, "A required desktop update must be installed.");
        $("boot").classList.add("hidden");
        $("updateGate").classList.remove("hidden");
        return;
      }
      if (update && update.status === "unavailable") {
        setStage("update", "warn", "UNAVAILABLE");
      } else {
        setStage("update", "ok", update && update.downloaded ? "DOWNLOADED" : "CURRENT");
      }
      bootProgress(68, "Verifying account session…");
      const account = data.account || {};
      if (account.authenticated) {
        setStage("account", "ok", "VERIFIED");
        setStage("entitlements", "ok", "READY");
      } else if (account.online === false) {
        setStage("account", "warn", "OFFLINE");
        setStage("entitlements", "warn", "UNAVAILABLE");
      } else {
        setStage("account", "warn", "UNLINKED");
        setStage("entitlements", "warn", "LOCKED");
      }
      render(data);
      bootProgress(92, "Building mission dashboard…");
      setStage("dashboard", "ok", "READY");
      bootProgress(100, "Ready.");
      const delay = reduceMotion ? 0 : 420;
      setTimeout(() => {
        $("boot").classList.add("hidden");
        $("app").classList.remove("hidden");
      }, delay);
    } catch (error) {
      ["environment", "compatibility", "update", "account", "entitlements", "dashboard"].forEach((name) => {
        const node = document.querySelector(`.boot-stage[data-stage="${name}"]`);
        if (node && node.dataset.state === "running") setStage(name, "fail", "ERROR");
      });
      bootProgress(100, error.message || "Startup failed");
      $("bootRetry").classList.remove("hidden");
    }
  }

  function render(data) {
    state = data;
    const account = data.account || {};
    const checks = data.checks || {};

    const conn = $("connPill");
    if (account.online === false) {
      conn.className = "pill warn";
      conn.textContent = "OFFLINE";
    } else if (account.authenticated) {
      conn.className = "pill ok";
      conn.textContent = "CONNECTED";
    } else {
      conn.className = "pill muted";
      conn.textContent = "ONLINE";
    }

    $("statPlatform").textContent = window.navigator.platform || "—";
    $("statAccount").textContent = account.authenticated
      ? account.user && (account.user.global_name || account.user.username) || "LINKED"
      : account.linked
        ? "UNVERIFIED"
        : "UNLINKED";
    $("statPremium").textContent = account.authenticated ? (account.premium ? "ACTIVE" : "INACTIVE") : "—";

    renderChecks(checks);
    renderAccount(account);
    renderLuaLibraries(data.lua_libraries || {});
    renderMissions(data.missions || {}, account);
    updateGrabAction();
    const update = updateState && updateState.status !== "unknown" ? updateState : data.update;
    applyUpdate(update);
    resumeJob(data.jobs || []);
  }

  function applyUpdate(update) {
    updateState = update || null;
    const gate = $("updateGate");
    const banner = $("updateBanner");
    if (!update || !update.blocking) {
      gate.classList.add("hidden");
      const optional = update && update.status === "optional";
      banner.classList.toggle("hidden", !optional || updateBannerDismissed);
      if (optional) {
        $("updateBannerTitle").textContent = update.downloaded ? "UPDATE READY TO INSTALL" : "UPDATE AVAILABLE";
        $("updateBannerText").textContent = `v${update.latest_version} is available.`;
        $("updateBannerDownload").textContent = update.downloaded ? "INSTALL" : "DOWNLOAD";
      }
      return false;
    }
    $("updateGateMessage").textContent = update.message || "Install the required update before continuing.";
    $("updateGateCurrent").textContent = update.current_version || VERSION;
    $("updateGateMinimum").textContent = update.minimum_version || update.latest_version || "—";
    $("updateGateLatest").textContent = update.latest_version || "—";
    const notes = $("updateGateNotes");
    notes.replaceChildren();
    for (const text of update.notes || []) {
      const item = document.createElement("li");
      item.textContent = text;
      notes.appendChild(item);
    }
    const artifact = update.artifact;
    const download = $("updateDownload");
    download.disabled = !artifact || updateBusy;
    download.classList.toggle("hidden", !artifact || update.downloaded);
    const install = $("updateInstall");
    install.classList.toggle("hidden", !update.downloaded);
    install.disabled = updateBusy;
    const base = (state && state.app && state.app.api_base) || "";
    $("updatePageLink").href = base ? base + "/download.html" : "#";
    gate.classList.remove("hidden");
    if (state) {
      $("boot").classList.add("hidden");
      $("app").classList.add("hidden");
    }
    return true;
  }

  function setUpdateStatus(message, error) {
    const node = $("updateGateStatus");
    node.textContent = message || "";
    node.dataset.status = error ? "error" : "";
    $("updateBannerText").textContent = message || $("updateBannerText").textContent;
  }

  async function refreshUpdate() {
    const result = await api("/api/update?refresh=1");
    updateState = result.update;
    applyUpdate(updateState);
    return updateState;
  }

  async function downloadUpdate() {
    if (updateBusy) return;
    if (updateState && updateState.downloaded) {
      await installUpdate();
      return;
    }
    updateBusy = true;
    setUpdateStatus("Downloading and verifying the signed installer…", false);
    if (updateState) applyUpdate(updateState);
    try {
      const result = await api("/api/update/download", { method: "POST", body: "{}" });
      updateState = result.update;
      updateBannerDismissed = false;
      applyUpdate(updateState);
      setUpdateStatus("Installer verified. Install it to finish updating.", false);
    } catch (error) {
      const note = error.code === "AUTH_REQUIRED"
        ? "Sign in to the desktop app, or use the authenticated download page."
        : error.message;
      setUpdateStatus(note, true);
    } finally {
      updateBusy = false;
      if (updateState) applyUpdate(updateState);
    }
  }

  async function installUpdate() {
    if (updateBusy) return;
    updateBusy = true;
    setUpdateStatus("Launching the verified installer…", false);
    if (updateState) applyUpdate(updateState);
    try {
      await api("/api/update/install", { method: "POST", body: "{}" });
      setUpdateStatus("The installer was launched. Close and reopen the app after it completes.", false);
    } catch (error) {
      setUpdateStatus(error.message, true);
    } finally {
      updateBusy = false;
      if (updateState) applyUpdate(updateState);
    }
  }

  async function retryUpdate() {
    if (updateBusy) return;
    updateBusy = true;
    setUpdateStatus("Checking the signed release manifest…", false);
    try {
      await refreshUpdate();
      setUpdateStatus(updateState && updateState.blocking ? "A required update is still pending." : "Update check complete.", !!(updateState && updateState.blocking));
    } catch (error) {
      setUpdateStatus(error.message, true);
    } finally {
      updateBusy = false;
    }
  }

  function renderChecks(checks) {
    const root = $("checkGroups");
    root.replaceChildren();
    const groups = [
      ["ENVIRONMENT", checks.environment || []],
      ["COMPATIBILITY", checks.compatibility || []],
      ["NETWORK", checks.network || []],
    ];
    let count = 0;
    for (const [label, items] of groups) {
      if (!items.length) continue;
      const heading = document.createElement("p");
      heading.className = "check-group-title";
      heading.textContent = label;
      root.appendChild(heading);
      for (const item of items) {
        const row = document.createElement("div");
        row.className = "check";
        row.dataset.status = item.status;
        const dot = document.createElement("span");
        dot.className = "dot";
        const body = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = item.label;
        const detail = document.createElement("small");
        detail.textContent = item.detail || item.action || "";
        body.append(title, detail);
        if (item.action && item.detail) {
          const action = document.createElement("small");
          action.textContent = item.action;
          body.appendChild(action);
        }
        const req = document.createElement("span");
        req.className = "req";
        req.textContent = item.required ? "REQ" : "OPT";
        row.append(dot, body, req);
        root.appendChild(row);
        count += 1;
      }
    }
    if (!count) {
      const empty = document.createElement("p");
      empty.className = "account-note";
      empty.textContent = "No checks available. Run RE-CHECK.";
      root.appendChild(empty);
    }
  }

  function renderLuaLibraries(report) {
    const path = $("luaLibraryPath");
    const status = $("luaLibraryStatus");
    const modules = $("luaLibraryModules");
    const clear = $("luaLibraryClear");
    const grabPath = $("grabLibraryPath");
    const grabStatus = $("grabLibraryStatus");
    const summary = report.error
      ? report.error
      : report.selected_path
        ? `${report.discovered_module_count || 0} modules · ${report.compatible_module_count || 0} compatible · ${report.conditional_module_count || 0} environment-dependent · ${report.unsupported_module_count || 0} unsupported`
        : "Standard Lua / No External Libraries";
    path.textContent = report.selected_path || "No folder selected";
    if (grabPath) grabPath.textContent = report.selected_path || "Standard Lua / No External Libraries";
    if (grabStatus) grabStatus.textContent = summary;
    clear.disabled = !report.selected_path;
    modules.replaceChildren();
    if (report.error) {
      status.textContent = report.error;
      return;
    }
    if (!report.selected_path) {
      status.textContent = "Select a local Lua library folder to inspect module compatibility, or continue with Standard Lua only.";
      return;
    }
    status.textContent = `${report.discovered_module_count || 0} modules · ${report.compatible_module_count || 0} compatible · ${report.conditional_module_count || 0} environment-dependent · ${report.unsupported_module_count || 0} unsupported · Lua ${report.runtime_version || "runtime"}`;
    for (const item of report.modules || []) {
      const row = document.createElement("div");
      row.className = "library-module";
      row.dataset.status = item.status || "unsupported";
      const name = document.createElement("strong");
      name.textContent = item.name || "unknown";
      const detail = document.createElement("small");
      detail.textContent = `${String(item.status || "unsupported").replaceAll("_", " ")} · ${item.reason || "No compatibility details"}`;
      row.append(name, detail);
      modules.appendChild(row);
    }
    const missing = report.missing_modules || [];
    for (const name of missing) {
      const row = document.createElement("div");
      row.className = "library-module";
      row.dataset.status = "missing";
      const detail = document.createElement("small");
      detail.textContent = `${name} · required by the selected Lua source but not found`;
      row.appendChild(detail);
      modules.appendChild(row);
    }
  }

  async function refreshLuaLibraryReport() {
    setLibraryStatus("Refreshing module inventory…");
    try {
      const data = await api("/api/lua-library");
      renderLuaLibraries(data.lua_libraries);
      setLibraryStatus("Module inventory refreshed.");
    } catch (error) {
      setLibraryStatus(error.message || "Library settings could not be updated.");
    }
  }

  async function applyLuaLibraryPath(inputId) {
    const input = $(inputId);
    if (!input) return;
    const value = input.value.trim();
    if (!value) {
      setLibraryStatus("Enter the full path of the Lua library folder.");
      input.focus();
      return;
    }
    setLibraryStatus("Checking the Lua library folder…");
    try {
      const data = await api("/api/lua-library/select", {
        method: "POST",
        body: JSON.stringify({ path: value }),
      });
      renderLuaLibraries(data.lua_libraries);
      const report = data.lua_libraries || {};
      if (report.error) {
        setLibraryStatus(report.error);
        return;
      }
      setLibraryStatus(
        `Lua library selected · ${report.discovered_module_count || 0} modules · ${report.compatible_module_count || 0} compatible · ${report.conditional_module_count || 0} environment-dependent · ${report.unsupported_module_count || 0} unsupported.`
      );
      input.value = "";
    } catch (error) {
      setLibraryStatus(error.message || "That path does not contain a valid Lua library folder.");
      input.focus();
    }
  }

  function bindManualLibraryPath(inputId, buttonId) {
    const input = $(inputId);
    const button = $(buttonId);
    if (!input || !button) return;
    button.addEventListener("click", () => applyLuaLibraryPath(inputId));
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      applyLuaLibraryPath(inputId);
    });
  }

  async function clearLuaLibrary() {
    setLibraryStatus("Switching to Standard Lua only…");
    try {
      const data = await api("/api/lua-library/clear", { method: "POST", body: "{}" });
      renderLuaLibraries(data.lua_libraries);
      setLibraryStatus("External Lua libraries cleared.");
    } catch (error) {
      setLibraryStatus(error.message || "The library selection could not be cleared.");
    }
  }

  function librarySuffixAllowed(name) {
    return /\.(lua|luac|dll|so|dylib|bundle|a|lib)$/i.test(String(name || ""));
  }

  async function uploadLuaLibrary(entries) {
    const allowed = (entries || []).filter((entry) => entry && entry.file && librarySuffixAllowed(entry.file.name));
    if (!allowed.length) {
      setLibraryStatus("No Lua library modules were found in the selected folder.");
      return;
    }
    const parts = allowed.map((entry) => String(entry.path || entry.file.name).split("/").filter(Boolean));
    const roots = new Set(parts.map((item) => (item.length > 1 ? item[0] : "")));
    const stripRoot = roots.size === 1 && !roots.has("") ? parts[0][0] : null;
    setLibraryStatus(`Uploading ${allowed.length} module(s) to the local snapshot…`);
    try {
      for (let index = 0; index < allowed.length; index += 1) {
        const relative = parts[index].slice(stripRoot ? 1 : 0).join("/");
        const response = await fetch("/api/lua-library/upload", {
          method: "POST",
          headers: await formHeaders({
            "X-RM7-Library-Path": encodeURIComponent(relative),
            "Content-Type": "application/octet-stream",
          }),
          body: allowed[index].file,
          cache: "no-store",
          credentials: "same-origin",
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.ok) {
          throw new ApiError(data.error || "A Lua library module could not be uploaded.", data.code, response.status);
        }
        if ((index + 1) % 10 === 0 || index + 1 === allowed.length) {
          setLibraryStatus(`Uploaded ${index + 1} of ${allowed.length} module(s)…`);
        }
      }
      const data = await api("/api/lua-library/commit", { method: "POST", body: "{}" });
      renderLuaLibraries(data.lua_libraries);
      setLibraryStatus("Lua library snapshot updated.");
    } catch (error) {
      api("/api/lua-library/cancel", { method: "POST", body: "{}" }).catch(() => {});
      setLibraryStatus(error.message || "The Lua library could not be uploaded.");
    }
  }

  function filesFromInput(input) {
    return Array.from(input.files || []).map((file) => ({ file, path: file.webkitRelativePath || file.name }));
  }

  function readDirectoryEntries(reader) {
    return new Promise((resolve, reject) => {
      reader.readEntries(resolve, reject);
    });
  }

  async function readEntry(entry, path) {
    if (!entry) return [];
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      return [{ file, path: path ? `${path}/${file.name}` : file.name }];
    }
    if (!entry.isDirectory) return [];
    const reader = entry.createReader();
    const collected = [];
    for (;;) {
      const batch = await readDirectoryEntries(reader);
      if (!batch.length) break;
      for (const child of batch) {
        collected.push(...(await readEntry(child, path ? `${path}/${entry.name}` : entry.name)));
      }
    }
    return collected;
  }

  async function libraryEntriesFromDrop(event) {
    const transfer = event.dataTransfer;
    if (!transfer) return [];
    const items = Array.from(transfer.items || []);
    const supportsEntries = items.some((item) => typeof item.webkitGetAsEntry === "function");
    if (!supportsEntries) {
      return Array.from(transfer.files || []).map((file) => ({ file, path: file.webkitRelativePath || file.name }));
    }
    const entries = items
      .map((item) => (typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null))
      .filter(Boolean);
    const collected = [];
    for (const entry of entries) collected.push(...(await readEntry(entry, "")));
    return collected;
  }

  function renderAccount(account) {
    const badge = $("accountBadge");
    const body = $("accountBody");
    body.replaceChildren();
    if (account.authenticated && account.user) {
      badge.className = account.premium ? "pill purple" : "pill ok";
      badge.textContent = account.premium ? "PREMIUM" : "VERIFIED";
      const user = document.createElement("div");
      user.className = "account-user";
      const avatar = document.createElement("div");
      avatar.className = "avatar";
      const name = account.user.global_name || account.user.username || "RM7";
      avatar.textContent = name.slice(0, 1).toUpperCase();
      const meta = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = name;
      const small = document.createElement("small");
      small.textContent = `Discord ID ${account.user.id || account.user.uid || "—"}`;
      meta.append(strong, small);
      user.append(avatar, meta);
      body.appendChild(user);
      const note = document.createElement("p");
      note.className = "account-note";
      note.textContent = "Premium and mission access are re-checked by the RM7 Nexus service. Local files are never uploaded for processing.";
      body.appendChild(note);
      if (!account.premium) {
        const note = document.createElement("p");
        note.className = "account-note";
        note.textContent = "Activate Premium on the official RM7 Nexus website while signed in, then refresh Premium status here. License keys are never entered or stored in this desktop app.";
        const link = document.createElement("a");
        link.className = "btn wide";
        link.href = "https://YOUR_API_DOMAIN.example/token.html";
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "ACTIVATE PREMIUM ON WEBSITE";
        body.appendChild(note);
        body.appendChild(link);
      }
      body.appendChild(actionButton("REFRESH PREMIUM STATUS", "ghost", refreshAccount));
      body.appendChild(actionButton("LOG OUT", "ghost", logout));
    } else if (account.linked) {
      badge.className = "pill warn";
      badge.textContent = "UNVERIFIED";
      const note = document.createElement("p");
      note.className = "account-note";
      note.textContent = account.warning || "The account service is unreachable. Premium access is not granted offline.";
      body.appendChild(note);
      body.appendChild(actionButton("RETRY VERIFICATION", "ghost", refreshAccount));
      body.appendChild(actionButton("LOG OUT", "ghost", logout));
    } else {
      badge.className = "pill muted";
      badge.textContent = "UNLINKED";
      const note = document.createElement("p");
      note.className = "account-note";
      note.textContent = account.warning || "Connect your Discord account to verify mission access. Browser login alone does not authorize the desktop process.";
      body.appendChild(note);
      body.appendChild(actionButton("CONNECT DISCORD ACCOUNT", "", connectAccount));
    }
  }

  function actionButton(label, variant, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `btn wide ${variant || ""}`.trim();
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
  }

  function renderMissions(missions, account) {
    const amx = missions.amx || {};
    const badge = $("amxBadge");
    if (!account.authenticated) {
      badge.className = "pill muted";
      badge.textContent = "LOCKED";
    } else if (account.premium) {
      badge.className = "pill purple";
      badge.textContent = "PREMIUM READY";
    } else {
      badge.className = "pill ok";
      badge.textContent = "ACCOUNT READY";
    }
    const grabBadge = $("grabBadge");
    if (!account.authenticated) {
      grabBadge.className = "pill muted";
      grabBadge.textContent = "LOCKED";
    } else if (account.premium) {
      grabBadge.className = "pill purple";
      grabBadge.textContent = "PREMIUM READY";
    } else {
      grabBadge.className = "pill ok";
      grabBadge.textContent = "ACCOUNT READY";
    }
    updateAmxAction();
  }

  function updateAmxAction() {
    const button = $("amxStart");
    const account = (state && state.account) || {};
    const requirementsOk = !!(state && state.checks && state.checks.ok);
    const permitted = account.authenticated && (mode === "normal" || account.premium);
    button.disabled = !(selectedFile && permitted && requirementsOk);
    if (!selectedFile) {
      setStatus("Connect an account and choose an AMX file.", "");
    } else if (!account.authenticated) {
      setStatus("Connect your Discord account to verify mission access.", "");
    } else if (!requirementsOk) {
      setStatus("Required environment checks failed. Use RE-CHECK for details.", "err");
    } else if (mode === "performed" && !account.premium) {
      setStatus("Performed mode requires an active Premium entitlement.", "err");
    } else {
      setStatus("Ready to process locally.", "");
    }
  }

  function setStatus(message, kind) {
    const node = $("amxStatus");
    node.textContent = message || "";
    node.className = `status-line ${kind || ""}`.trim();
  }

  async function connectAccount() {
    const pairBox = $("pairBox");
    try {
      pairBox.classList.remove("hidden");
      $("pairCode").textContent = "…";
      $("pairLink").removeAttribute("href");
      $("pairStatus").textContent = "Requesting a one-time pairing code…";
      const result = await api("/api/pair/start", {
        method: "POST",
        body: JSON.stringify({ device_name: `${navigator.platform || "Windows"} desktop` }),
      });
      $("pairCode").textContent = result.user_code;
      $("pairLink").href = result.verification_uri;
      $("pairStatus").textContent = "Waiting for authorization in your browser…";
      try {
        window.open(result.verification_uri, "_blank", "noopener,noreferrer");
      } catch {
        /* the link remains available */
      }
      clearInterval(pairTimer);
      pairTimer = setInterval(() => pollPair(result), Math.max(3, result.interval || 5) * 1000);
    } catch (error) {
      $("pairStatus").textContent = error.message;
    }
  }

  async function pollPair(result) {
    if (pairBusy) return;
    pairBusy = true;
    try {
      const response = await api("/api/pair/poll", {
        method: "POST",
        body: JSON.stringify({ request_id: result.request_id }),
      });
      if (response.status === "pending") {
        $("pairStatus").textContent = "Waiting for authorization in your browser…";
        return;
      }
      clearInterval(pairTimer);
      pairTimer = null;
      if (response.status === "approved") {
        $("pairStatus").textContent = "Account linked.";
        $("pairBox").classList.add("hidden");
        await refreshState();
      } else if (response.status === "expired") {
        $("pairStatus").textContent = "The pairing code expired. Start again.";
      } else {
        $("pairStatus").textContent = "Authorization was denied.";
      }
    } catch (error) {
      $("pairStatus").textContent = error.message;
    } finally {
      pairBusy = false;
    }
  }

  async function refreshAccount() {
    try {
      const result = await api("/api/account/refresh", { method: "POST", body: "{}" });
      if (state) {
        state.account = result.account;
        state.missions = result.missions;
        render(state);
      }
    } catch (error) {
      setStatus(error.message, "err");
    }
  }

  async function logout() {
    try {
      await api("/api/logout", { method: "POST", body: "{}" });
      clearInterval(pairTimer);
      $("pairBox").classList.add("hidden");
      await refreshState();
    } catch (error) {
      setStatus(error.message, "err");
    }
  }

  async function refreshState() {
    const data = await api("/api/state");
    render(data);
  }

  async function refreshChecks() {
    $("refreshChecks").disabled = true;
    try {
      const result = await api("/api/checks?refresh=1");
      if (state) {
        state.checks = result.checks;
        renderChecks(result.checks);
        updateAmxAction();
      }
    } catch (error) {
      setStatus(error.message, "err");
    } finally {
      $("refreshChecks").disabled = false;
    }
  }

  function hideSaveResult() {
    $("amxSaveRow").classList.add("hidden");
    $("amxSavedPath").classList.add("hidden");
    $("amxSavedPath").textContent = "";
  }

  function showSavedPath(path) {
    $("amxSavedPath").textContent = path;
    $("amxSavedPath").classList.remove("hidden");
  }

  function chooseFile(file) {
    if (!file) return;
    selectedFile = file;
    $("amxFileName").textContent = `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MiB`;
    hideSaveResult();
    $("amxLogWrap").classList.add("hidden");
    $("amxProgress").classList.add("hidden");
    updateAmxAction();
  }

  async function startAmx() {
    if (!selectedFile) return;
    const button = $("amxStart");
    button.disabled = true;
    $("amxCancel").classList.remove("hidden");
    $("amxProgress").classList.remove("hidden");
    $("amxProgress").querySelector("i").style.width = "2%";
    $("amxLogWrap").classList.add("hidden");
    hideSaveResult();
    setStatus("Uploading to the local job workspace…", "");
    try {
      const response = await fetch("/api/jobs/amx", {
        method: "POST",
        headers: await formHeaders({
          "X-RM7-Filename": encodeURIComponent(selectedFile.name),
          "X-RM7-Mode": mode,
        }),
        body: selectedFile,
        cache: "no-store",
        credentials: "same-origin",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new ApiError(data.error || `Request failed (${response.status})`, data.code, response.status);
      }
      currentJobId = data.job.id;
      renderJob(data.job);
      pollJob(currentJobId);
    } catch (error) {
      setStatus(error.message, "err");
      $("amxCancel").classList.add("hidden");
      $("amxProgress").classList.add("hidden");
      button.disabled = false;
    }
  }

  async function pollJob(jobId) {
    clearTimeout(jobTimer);
    try {
      const data = await api(`/api/jobs/${jobId}`);
      renderJob(data.job);
      if (["queued", "running"].includes(data.job.status)) {
        jobTimer = setTimeout(() => pollJob(jobId), 700);
      }
    } catch (error) {
      setStatus(error.message, "err");
    }
  }

  function renderJob(job) {
    if (!job) return;
    $("amxProgress").classList.remove("hidden");
    $("amxProgress").querySelector("i").style.width = `${job.progress || 0}%`;
    const detail = job.status === "completed" ? "Decompilation complete." : job.message || job.status;
    setStatus(detail, job.status === "completed" ? "ok" : job.status === "failed" ? "err" : "");
    if (job.log) {
      $("amxLogWrap").classList.remove("hidden");
      const log = $("amxLog");
      log.textContent = job.log;
      log.scrollTop = log.scrollHeight;
    }
    if (job.status === "completed") {
      currentJobId = job.id;
      $("amxCancel").classList.add("hidden");
      $("amxStart").disabled = false;
      $("amxSaveRow").classList.remove("hidden");
      refreshState().catch(() => {});
    } else if (job.status === "failed" || job.status === "cancelled") {
      $("amxCancel").classList.add("hidden");
      $("amxStart").disabled = false;
      hideSaveResult();
    }
  }

  function setGrabStatus(message, kind) {
    const node = $("grabStatus");
    node.textContent = message || "";
    node.className = `status-line ${kind || ""}`.trim();
  }

  function updateGrabAction() {
    const button = $("grabStart");
    const account = (state && state.account) || {};
    const requirementsOk = !!(state && state.checks && state.checks.ok);
    const platform = (state && state.app && state.app.platform_key) || "";
    const platformOk = grabMode !== "performed" || !platform || platform === "linux";
    const permitted = account.authenticated && (grabMode === "normal" || account.premium);
    button.disabled = !(grabFile && permitted && requirementsOk && platformOk);
    if (!grabFile) {
      setGrabStatus("Connect an account and choose a Lua file.", "");
    } else if (!account.authenticated) {
      setGrabStatus("Connect your Discord account to verify mission access.", "");
    } else if (!requirementsOk) {
      setGrabStatus("Required environment checks failed. Use RE-CHECK for details.", "err");
    } else if (grabMode === "performed" && !platformOk) {
      setGrabStatus("Performed mode requires Linux Bubblewrap isolation on this desktop.", "err");
    } else if (grabMode === "performed" && !account.premium) {
      setGrabStatus("Performed mode requires an active Premium entitlement.", "err");
    } else {
      setGrabStatus("Ready to analyze locally.", "");
    }
  }

  function chooseGrabFile(file) {
    if (!file) return;
    grabFile = file;
    $("grabFileName").textContent = `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MiB`;
    $("grabLogWrap").classList.add("hidden");
    $("grabProgress").classList.add("hidden");
    $("grabReport").classList.add("hidden");
    if ($("grabEnvironment")) $("grabEnvironment").textContent = "Environment: detected after static analysis.";
    updateGrabAction();
  }

  async function startGrab() {
    if (!grabFile) return;
    const button = $("grabStart");
    button.disabled = true;
    $("grabCancel").classList.remove("hidden");
    $("grabProgress").classList.remove("hidden");
    $("grabProgress").querySelector("i").style.width = "2%";
    $("grabLogWrap").classList.add("hidden");
    $("grabReport").classList.add("hidden");
    setGrabStatus("Uploading to the local job workspace…", "");
    try {
      const response = await fetch("/api/jobs/grab", {
        method: "POST",
        headers: await formHeaders({
          "X-RM7-Filename": encodeURIComponent(grabFile.name),
          "X-RM7-Mode": grabMode,
        }),
        body: grabFile,
        cache: "no-store",
        credentials: "same-origin",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new ApiError(data.error || `Request failed (${response.status})`, data.code, response.status);
      }
      grabJobId = data.job.id;
      renderGrabJob(data.job);
      pollGrab(grabJobId);
    } catch (error) {
      setGrabStatus(error.message, "err");
      $("grabCancel").classList.add("hidden");
      $("grabProgress").classList.add("hidden");
      button.disabled = false;
    }
  }

  async function pollGrab(jobId) {
    clearTimeout(grabTimer);
    try {
      const data = await api(`/api/jobs/${jobId}`);
      renderGrabJob(data.job);
      if (["queued", "running"].includes(data.job.status)) {
        grabTimer = setTimeout(() => pollGrab(jobId), 700);
      }
    } catch (error) {
      setGrabStatus(error.message, "err");
    }
  }

  function metric(label, value, tone) {
    const box = document.createElement("div");
    box.className = "grab-metric";
    const key = document.createElement("span");
    key.textContent = label;
    const val = document.createElement("strong");
    val.textContent = value == null || value === "" ? "—" : String(value);
    if (tone) val.dataset.tone = tone;
    box.append(key, val);
    return box;
  }

  const PRIVATE_REPORT_KEY = /^(raw_url|raw_headers|raw_body|raw_request|raw_response|raw_cookies)$/i;

  function redactReport(report) {
    const scrub = (value) => {
      if (Array.isArray(value)) return value.map(scrub);
      if (value && typeof value === "object") {
        const result = {};
        for (const [key, item] of Object.entries(value)) {
          if (PRIVATE_REPORT_KEY.test(key)) continue;
          result[key] = scrub(item);
        }
        return result;
      }
      return value;
    };
    return scrub(JSON.parse(JSON.stringify(report || {})));
  }

  function secretNode(value, label) {
    const node = document.createElement("span");
    node.className = "gd-secret";
    node.tabIndex = 0;
    node.textContent = String(value);
    node.title = "Click, hover, or focus to reveal the original value";
    node.setAttribute("aria-label", `Reveal ${label || "sensitive value"}`);
    return node;
  }

  function grabReportName(kind) {
    const base = (grabFile && grabFile.name ? grabFile.name : "grab-report").replace(/\.(lua|luac)$/i, "");
    return `${base}.${kind}.json`;
  }

  function downloadJson(payload, filename) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function copyRedactedReport() {
    if (!grabReportData) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(redactReport(grabReportData), null, 2));
      setGrabStatus("Redacted report copied to the clipboard.", "ok");
    } catch {
      setGrabStatus("The clipboard is unavailable in this browser. Use the redacted download instead.", "err");
    }
  }

  function downloadGrabReport(privateMode) {
    if (!grabReportData) return;
    if (privateMode) {
      const confirmed = window.confirm(
        "This private export contains exact request URLs and tokens. Anyone with the file can read them. Export only if you trust this device."
      );
      if (!confirmed) return;
      downloadJson(grabReportData, grabReportName("private"));
      setGrabStatus("Private unredacted report downloaded.", "warn");
      return;
    }
    downloadJson(redactReport(grabReportData), grabReportName("redacted"));
    setGrabStatus("Redacted report downloaded.", "ok");
  }

  function renderGrabEvidenceList(title, entries) {
    if (!entries.length) return null;
    const heading = document.createElement("h3");
    heading.textContent = title;
    const list = document.createElement("ul");
    for (const entry of entries) {
      const row = document.createElement("li");
      if (entry.meta) {
        const meta = document.createElement("span");
        meta.className = "gd-evidence-meta";
        meta.textContent = `${entry.meta} `;
        row.appendChild(meta);
      }
      row.appendChild(secretNode(entry.value, entry.label || title));
      list.appendChild(row);
    }
    return [heading, list];
  }

  function renderGrabReport(report) {
    grabReportData = report;
    const threat = report.threat || {};
    const summary = $("grabSummary");
    summary.replaceChildren(
      metric("THREAT", threat.level || "unknown", threat.level),
      metric("SCORE", threat.score == null ? "—" : `${threat.score}/100`),
      metric("STATUS", report.overall_status || "unknown"),
      metric("STATIC URLS", report.static_url_count || 0),
      metric("REQUESTS", report.http_requests_captured || 0),
      metric("DYNAMIC", (report.dynamic_analysis || {}).status || "skipped"),
      metric("ENVIRONMENT", (report.environment || {}).label || "unknown")
    );
    const environment = report.environment || {};
    const envNode = $("grabEnvironment");
    if (envNode) {
      envNode.textContent = `Environment: ${environment.label || "unknown"} · ${environment.dynamic_supported ? "isolated runtime supported" : "static-only"} · ${environment.note || ""}`;
    }
    const evidence = $("grabEvidence");
    evidence.replaceChildren();
    const addList = (title, items) => {
      if (!items || !items.length) return;
      const heading = document.createElement("h3");
      heading.textContent = title;
      const list = document.createElement("ul");
      for (const item of items) {
        const row = document.createElement("li");
        row.textContent = typeof item === "string" ? item : JSON.stringify(item);
        list.appendChild(row);
      }
      evidence.append(heading, list);
    };
    if (threat.summary) {
      const note = document.createElement("p");
      note.className = "grab-summary-copy";
      note.textContent = threat.summary;
      evidence.appendChild(note);
    }
    addList("WHY THIS SCORE", threat.reasons || []);
    const urlEvidence = ((report.static_analysis || {}).urls || [])
      .map((item) => ({ value: item.raw_url || item.url, label: "static URL" }))
      .filter((item) => item.value);
    const urlBlock = renderGrabEvidenceList("STATIC URLS", urlEvidence.slice(0, 50));
    if (urlBlock) {
      const note = document.createElement("p");
      note.className = "grab-summary-copy";
      note.textContent = "Exact URLs are blurred until hovered, focused, or clicked. Redacted exports omit the original value.";
      evidence.append(...urlBlock, note);
    }
    const requestEvidence = ((report.dynamic_analysis || {}).requests || [])
      .map((item) => ({
        value: item.raw_url || item.url,
        meta: `${item.method || "REQUEST"}${item.api ? ` · ${item.api}` : ""}`,
        label: "request URL",
      }))
      .filter((item) => item.value);
    const requestBlock = renderGrabEvidenceList("CAPTURED REQUESTS", requestEvidence.slice(0, 50));
    if (requestBlock) evidence.append(...requestBlock);
    const dynamic = report.dynamic_analysis || {};
    const library = dynamic.library || {};
    const libraryDiagnostics = [];
    if (library.error) libraryDiagnostics.push(library.error);
    if (dynamic.missing_module) {
      libraryDiagnostics.push(`Missing module: ${dynamic.missing_module}`);
    }
    for (const name of library.missing_modules || []) {
      libraryDiagnostics.push(`Required module not found: ${name}`);
    }
    for (const item of library.modules || []) {
      if ((library.required_modules || []).includes(item.name) && item.status !== "compatible") {
        libraryDiagnostics.push(`${item.name}: ${String(item.status || "unsupported").replaceAll("_", " ")} · ${item.reason || "unsupported"}`);
      }
    }
    for (const item of library.native_dependencies_unavailable || []) {
      libraryDiagnostics.push(`Native dependency not loaded: ${item}`);
    }
    addList("LUA LIBRARY DIAGNOSTICS", libraryDiagnostics.slice(0, 50));
    addList("LIMITATIONS", report.limitations || []);
    const badges = (report.status_badges || []).map((item) => item.label).filter(Boolean);
    addList("STATUS BADGES", badges);
    $("grabJson").textContent = JSON.stringify(redactReport(report), null, 2);
    $("grabReport").classList.remove("hidden");
  }

  async function renderGrabJob(job) {
    if (!job) return;
    $("grabProgress").classList.remove("hidden");
    $("grabProgress").querySelector("i").style.width = `${job.progress || 0}%`;
    const detail = job.status === "completed" ? "Analysis complete." : job.message || job.status;
    setGrabStatus(detail, job.status === "completed" ? "ok" : job.status === "failed" ? "err" : "");
    if (job.log) {
      $("grabLogWrap").classList.remove("hidden");
      const log = $("grabLog");
      log.textContent = job.log;
      log.scrollTop = log.scrollHeight;
    }
    if (job.status === "completed") {
      grabJobId = job.id;
      $("grabCancel").classList.add("hidden");
      $("grabStart").disabled = false;
      try {
        const response = await fetch(`/api/jobs/${job.id}/output`, {
          headers: await formHeaders(),
          cache: "no-store",
          credentials: "same-origin",
        });
        if (!response.ok) throw new Error("The report could not be loaded.");
        renderGrabReport(await response.json());
      } catch (error) {
        setGrabStatus(error.message, "err");
      }
    } else if (job.status === "failed" || job.status === "cancelled") {
      $("grabCancel").classList.add("hidden");
      $("grabStart").disabled = false;
      $("grabReport").classList.add("hidden");
    }
  }

  async function cancelGrab() {
    if (!grabJobId) return;
    try {
      await api(`/api/jobs/${grabJobId}/cancel`, { method: "POST", body: "{}" });
    } catch (error) {
      setGrabStatus(error.message, "err");
    }
  }

  async function cancelAmx() {
    if (!currentJobId) return;
    try {
      await api(`/api/jobs/${currentJobId}/cancel`, { method: "POST", body: "{}" });
    } catch (error) {
      setStatus(error.message, "err");
    }
  }

  async function saveOutput() {
    const jobId = currentJobId;
    if (!jobId) return;
    const button = $("amxSave");
    button.disabled = true;
    setStatus("Preparing download…", "");
    try {
      const jobData = await api(`/api/jobs/${jobId}`);
      const response = await fetch(`/api/jobs/${jobId}/output`, {
        headers: await formHeaders(),
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new ApiError(data.error || "The output file could not be downloaded.", data.code, response.status);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="([^"]+)"/i);
      const filename = match ? match[1] : jobData.job.output_name || "output.pwn";
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      showSavedPath(`Downloaded ${filename}`);
      setStatus("PWN download started.", "ok");
    } catch (error) {
      setStatus(error.message, "err");
    } finally {
      button.disabled = false;
    }
  }

  function resumeJob(jobs) {
    if (currentJobId || grabJobId) return;
    const active = jobs.find((job) => job.mission === "amx" && ["queued", "running"].includes(job.status));
    if (active) {
      currentJobId = active.id;
      $("amxCancel").classList.remove("hidden");
      renderJob(active);
      pollJob(active.id);
      return;
    }
    const activeGrab = jobs.find(
      (job) => job.mission === "grab-detector" && ["queued", "running"].includes(job.status)
    );
    if (activeGrab) {
      grabJobId = activeGrab.id;
      $("grabCancel").classList.remove("hidden");
      renderGrabJob(activeGrab);
      pollGrab(activeGrab.id);
    }
  }

  async function quitApp() {
    const button = $("quitBtn");
    button.disabled = true;
    button.textContent = "STOPPING";
    clearInterval(pairTimer);
    clearTimeout(jobTimer);
    try {
      await api("/api/shutdown", { method: "POST", body: "{}" });
    } catch {
      /* the server may stop before the response is read */
    }
    const screen = document.createElement("div");
    screen.className = "boot";
    const card = document.createElement("div");
    card.className = "boot-card";
    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = "// SESSION CLOSED";
    const title = document.createElement("h1");
    title.className = "boot-title";
    title.textContent = "RM7//N3XUS STOPPED";
    const note = document.createElement("p");
    note.className = "boot-message";
    note.textContent = "The local control plane is offline. This window can be closed.";
    card.append(eyebrow, title, note);
    screen.appendChild(card);
    document.body.appendChild(screen);
  }

  function bindEvents() {
    $("bootRetry").addEventListener("click", boot);
    $("quitBtn").addEventListener("click", quitApp);
    $("refreshChecks").addEventListener("click", refreshChecks);
    bindManualLibraryPath("luaLibraryManual", "luaLibraryManualApply");
    bindManualLibraryPath("grabLibraryManual", "grabLibraryManualApply");
    $("luaLibraryChoose").addEventListener("click", () => $("luaLibraryInput").click());
    $("luaLibraryRefresh").addEventListener("click", refreshLuaLibraryReport);
    $("luaLibraryClear").addEventListener("click", clearLuaLibrary);
    $("luaLibraryInput").addEventListener("change", (event) => {
      const entries = filesFromInput(event.target);
      event.target.value = "";
      uploadLuaLibrary(entries);
    });
    if ($("grabLibraryChoose")) $("grabLibraryChoose").addEventListener("click", () => $("grabLibraryInput").click());
    if ($("grabLibraryRefresh")) $("grabLibraryRefresh").addEventListener("click", refreshLuaLibraryReport);
    if ($("grabLibraryNone")) $("grabLibraryNone").addEventListener("click", clearLuaLibrary);
    if ($("grabLibraryInput")) $("grabLibraryInput").addEventListener("change", (event) => {
      const entries = filesFromInput(event.target);
      event.target.value = "";
      uploadLuaLibrary(entries);
    });
    for (const selector of [".lua-library-panel", '[data-mission="grab-detector"] .grab-setup']) {
      const target = document.querySelector(selector);
      if (!target) continue;
      ["dragenter", "dragover"].forEach((name) => target.addEventListener(name, (event) => {
        event.preventDefault();
        target.classList.add("drag");
      }));
      ["dragleave", "drop"].forEach((name) => target.addEventListener(name, (event) => {
        event.preventDefault();
        target.classList.remove("drag");
      }));
      target.addEventListener("drop", async (event) => {
        if (event.target.closest("#grabDrop")) return;
        uploadLuaLibrary(await libraryEntriesFromDrop(event));
      });
    }
    $("amxFile").addEventListener("change", (event) => chooseFile(event.target.files[0]));
    $("amxStart").addEventListener("click", startAmx);
    $("amxCancel").addEventListener("click", cancelAmx);
    $("amxSave").addEventListener("click", saveOutput);
    $("updateDownload").addEventListener("click", downloadUpdate);
    $("updateInstall").addEventListener("click", installUpdate);
    $("updateRetry").addEventListener("click", retryUpdate);
    $("updateQuit").addEventListener("click", quitApp);
    $("updateBannerDownload").addEventListener("click", downloadUpdate);
    $("updateBannerDismiss").addEventListener("click", () => {
      if (updateState && updateState.blocking) return;
      updateBannerDismissed = true;
      $("updateBanner").classList.add("hidden");
    });

    document.querySelectorAll('[data-mission="amx"] .mode').forEach((button) => {
      button.addEventListener("click", () => {
        mode = button.dataset.mode;
        document.querySelectorAll('[data-mission="amx"] .mode').forEach((item) => {
          const active = item === button;
          item.classList.toggle("active", active);
          item.setAttribute("aria-checked", active ? "true" : "false");
        });
        updateAmxAction();
      });
    });

    document.querySelectorAll(".grab-mode").forEach((button) => {
      button.addEventListener("click", () => {
        grabMode = button.dataset.grabMode;
        document.querySelectorAll(".grab-mode").forEach((item) => {
          const active = item === button;
          item.classList.toggle("active", active);
          item.setAttribute("aria-checked", active ? "true" : "false");
        });
        updateGrabAction();
      });
    });

    const grabDrop = $("grabDrop");
    ["dragenter", "dragover"].forEach((name) =>
      grabDrop.addEventListener(name, (event) => {
        event.preventDefault();
        grabDrop.classList.add("drag");
      })
    );
    ["dragleave", "drop"].forEach((name) =>
      grabDrop.addEventListener(name, (event) => {
        event.preventDefault();
        grabDrop.classList.remove("drag");
      })
    );
    grabDrop.addEventListener("drop", (event) => {
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) chooseGrabFile(file);
    });
    $("grabFile").addEventListener("change", (event) => {
      const file = event.target.files && event.target.files[0];
      if (file) chooseGrabFile(file);
    });
    $("grabStart").addEventListener("click", startGrab);
    $("grabCancel").addEventListener("click", cancelGrab);
    $("grabCopyRedacted").addEventListener("click", copyRedactedReport);
    $("grabDownloadRedacted").addEventListener("click", () => downloadGrabReport(false));
    $("grabDownloadPrivate").addEventListener("click", () => downloadGrabReport(true));
    document.addEventListener("click", (event) => {
      const target = event.target && event.target.closest ? event.target.closest(".gd-secret") : null;
      if (target) target.classList.toggle("revealed");
    });
    document.addEventListener("keydown", (event) => {
      if (!["Enter", " "].includes(event.key)) return;
      const target = event.target && event.target.closest ? event.target.closest(".gd-secret") : null;
      if (!target) return;
      event.preventDefault();
      target.classList.toggle("revealed");
    });

    const drop = $("amxDrop");
    ["dragenter", "dragover"].forEach((name) =>
      drop.addEventListener(name, (event) => {
        event.preventDefault();
        drop.classList.add("drag");
      })
    );
    ["dragleave", "drop"].forEach((name) =>
      drop.addEventListener(name, (event) => {
        event.preventDefault();
        drop.classList.remove("drag");
      })
    );
    drop.addEventListener("drop", (event) => {
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) chooseFile(file);
    });

    window.addEventListener("beforeunload", () => {
      clearInterval(pairTimer);
      clearTimeout(jobTimer);
      clearTimeout(grabTimer);
    });
  }

  bindEvents();
  boot();
})();
