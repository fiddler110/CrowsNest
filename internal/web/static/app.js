const CSRF_TOKEN = document.querySelector('meta[name=csrf-token]').content;
const POLL_INTERVAL_MS = 5000;
const STATS_POLL_MS = 3000;
const INFO_POLL_MS = 5000;
const MAX_LOG_LINES = 300;

const logSources = {};
const progressSources = {};
const progressDone = {};      // id -> true once a run's progress hit 100%
const shownStartErrors = {};  // id -> start_error_at already toasted
const statsTimers = {};
const infoTimers = {};

// poll runs fn every ms like setInterval, but skips ticks while the tab is
// hidden and fires once immediately when it becomes visible again. Returns a
// handle for stopPoll.
function poll(fn, ms) {
  const handle = { fn, id: setInterval(() => { if (!document.hidden) fn(); }, ms) };
  handle.onVisible = () => { if (!document.hidden) fn(); };
  document.addEventListener("visibilitychange", handle.onVisible);
  return handle;
}

function stopPoll(handle) {
  clearInterval(handle.id);
  document.removeEventListener("visibilitychange", handle.onVisible);
}

function cardFor(id) {
  return document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
}

function setPressed(btn, pressed) {
  btn.setAttribute("aria-pressed", String(pressed));
}

function setStatus(id, status) {
  const card = cardFor(id);
  if (!card) return;
  const badge = card.querySelector(".status");
  const prevStatus = card.dataset.status;
  badge.className = `status status-${status}`;
  badge.querySelector(".status-text").textContent = status;
  card.dataset.status = status;

  // Start makes sense only for a stopped/unknown game; Stop only for one
  // that's running or coming up. (A game that's up while a *different* one
  // is chosen still goes through the switch dialog on the server's 409.)
  card.querySelector(".start-btn").disabled = ["online", "starting", "stopping"].includes(status);
  card.querySelector(".stop-btn").disabled = status === "offline" || status === "stopping";

  // While starting, (re)open the progress stream on every poll: it ends
  // early while the image is still being pulled (no container yet), and
  // startProgressTracking is a no-op while one is already open.
  if (status === "starting") {
    if (!progressDone[id]) startProgressTracking(id);
  } else {
    delete progressDone[id];
    stopProgressTracking(id);
  }
  updateFleet();
}

// updateFleet refreshes the hero banner from what the cards currently show.
function updateFleet() {
  const cards = [...document.querySelectorAll(".game-card")];
  const active = cards.filter((c) => ["online", "starting"].includes(c.dataset.status));
  const crew = cards.reduce((n, c) => n + (parseInt(c.dataset.players, 10) || 0), 0);

  const hero = document.getElementById("fleet");
  const title = document.getElementById("fleet-title");
  const sub = document.getElementById("fleet-sub");
  hero.classList.toggle("is-active", active.length > 0);

  if (cards.length === 0) {
    title.textContent = "No vessels charted";
    sub.textContent = "Add a game to config.yaml to see it here.";
  } else if (active.length === 0) {
    title.textContent = "All quiet on the horizon";
    sub.textContent = "No server is running. Pick a vessel below and start it when the crew is ready.";
  } else {
    const c = active[0];
    const name = c.dataset.name;
    if (c.dataset.status === "starting") {
      title.textContent = `${name} is getting under way`;
      sub.textContent = "The server is starting up. It will appear online once it's ready for the crew.";
    } else {
      title.textContent = `${name} is under sail`;
      sub.textContent = crew === 1 ? "1 player aboard." : `${crew} players aboard.`;
    }
  }

  document.getElementById("stat-vessels").textContent = cards.length;
  document.getElementById("stat-active").textContent = active.length;
  document.getElementById("stat-crew").textContent = crew;
}

let toastTimer;
function toast(message) {
  const el = document.getElementById("toast");
  document.getElementById("toast-text").textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 6000);
}

function startProgressTracking(id) {
  if (progressSources[id]) return;
  const card = cardFor(id);
  if (!card) return;
  const wrap = card.querySelector(".progress-wrap");
  const bar = card.querySelector(".progress-bar");
  const label = card.querySelector(".progress-label");

  const es = new EventSource(`/api/games/${id}/startup-progress`);
  progressSources[id] = es;

  es.addEventListener("progress", (e) => {
    const data = JSON.parse(e.data);
    wrap.hidden = false;
    bar.style.width = data.pct + "%";
    label.textContent = data.label;
    if (data.pct >= 100) {
      progressDone[id] = true;
      stopProgressTracking(id);
    }
  });
  es.addEventListener("unsupported", () => {
    progressDone[id] = true;
    stopProgressTracking(id);
  });
  // Stream ended (e.g. still pulling): close it but keep the bar showing;
  // the next status poll reopens it.
  es.onerror = () => closeProgressSource(id);
}

function closeProgressSource(id) {
  const es = progressSources[id];
  if (es) {
    es.close();
    delete progressSources[id];
  }
}

function stopProgressTracking(id) {
  const es = progressSources[id];
  if (es) {
    es.close();
    delete progressSources[id];
  }
  const card = cardFor(id);
  if (card) card.querySelector(".progress-wrap").hidden = true;
}

function setPlayerCount(id, count) {
  const card = cardFor(id);
  if (!card) return;
  const row = card.querySelector(".crew");
  const el = card.querySelector(".player-count");
  if (count == null) {
    row.hidden = true;
    delete card.dataset.players;
  } else {
    row.hidden = false;
    card.dataset.players = count;
    el.textContent = count === 1 ? "1 player online" : `${count} players online`;
  }
  updateFleet();
}

// Game containers often colour their output with ANSI escapes, which a
// <div> would show as garbage boxes.
const ANSI_RE = /\u001b\[[0-9;?]*[A-Za-z]/g;
function stripAnsi(text) {
  return text.replace(ANSI_RE, "");
}

function toggleLogs(id) {
  const card = cardFor(id);
  if (!card) return;
  const panel = card.querySelector(".log-panel");
  const output = card.querySelector(".log-output");
  const btn = card.querySelector(".logs-btn");

  if (logSources[id]) {
    logSources[id].close();
    delete logSources[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }

  output.textContent = "";
  panel.hidden = false;
  panel.scrollTop = 0; // empty panel counts as "at the bottom", so it follows
  setPressed(btn, true);

  const es = new EventSource(`/api/games/${id}/logs`);
  logSources[id] = es;
  // Plain lines arrive as default "message" events; games with a log
  // formatter tag lines warn/error/verbose, which only named listeners see.
  // Follow the newest line unless the reader has scrolled back; scrolling
  // back down to the end resumes following. The scroller is the panel.
  const addLine = (kind) => (e) => {
    const atBottom = panel.scrollHeight - panel.scrollTop - panel.clientHeight < 24;
    const line = document.createElement("div");
    if (kind) line.className = `ln-${kind}`;
    line.textContent = stripAnsi(e.data);
    output.appendChild(line);
    while (output.children.length > MAX_LOG_LINES) {
      output.removeChild(output.firstChild);
    }
    if (atBottom) panel.scrollTop = panel.scrollHeight;
  };
  es.onmessage = addLine("");
  ["warn", "error", "verbose"].forEach((kind) => es.addEventListener(kind, addLine(kind)));
  es.onerror = () => {
    es.close();
    delete logSources[id];
    setPressed(btn, false);
  };
}

function setStatBar(fillEl, valueEl, pct, text) {
  fillEl.style.width = Math.min(Math.max(pct, 0), 100) + "%";
  fillEl.classList.remove("stat-warn", "stat-danger");
  if (pct >= 90) fillEl.classList.add("stat-danger");
  else if (pct >= 70) fillEl.classList.add("stat-warn");
  valueEl.textContent = text;
}

function clearStatBar(fillEl, valueEl) {
  fillEl.style.width = "0%";
  fillEl.classList.remove("stat-warn", "stat-danger");
  valueEl.textContent = "N/A";
}

async function fetchStats(id) {
  const card = cardFor(id);
  if (!card) return;
  let res;
  try {
    res = await fetch(`/api/games/${id}/stats`);
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const d = await res.json();

  if (d.cpu != null) {
    const pct = parseFloat(d.cpu);
    setStatBar(card.querySelector(".stat-cpu-fill"), card.querySelector(".stat-cpu-val"), pct, pct.toFixed(1) + "%");
  } else {
    clearStatBar(card.querySelector(".stat-cpu-fill"), card.querySelector(".stat-cpu-val"));
  }

  if (d.mem_pct != null) {
    const pct = parseFloat(d.mem_pct);
    setStatBar(card.querySelector(".stat-mem-fill"), card.querySelector(".stat-mem-val"), pct, `${d.mem_used || "?"} / ${d.mem_total || "?"}`);
  } else {
    clearStatBar(card.querySelector(".stat-mem-fill"), card.querySelector(".stat-mem-val"));
  }

  const gpuRow = card.querySelector(".stat-gpu-row");
  if (d.gpu_util != null) {
    gpuRow.hidden = false;
    const pct = parseFloat(d.gpu_util);
    setStatBar(card.querySelector(".stat-gpu-fill"), card.querySelector(".stat-gpu-val"), pct, pct.toFixed(0) + "%");
  } else {
    gpuRow.hidden = true;
  }

  const gpuMemRow = card.querySelector(".stat-gpu-mem-row");
  if (d.gpu_mem_used != null && d.gpu_mem_total != null) {
    gpuMemRow.hidden = false;
    const used = parseFloat(d.gpu_mem_used);
    const total = parseFloat(d.gpu_mem_total);
    const pct = total > 0 ? (used / total) * 100 : 0;
    setStatBar(card.querySelector(".stat-gpu-mem-fill"), card.querySelector(".stat-gpu-mem-val"), pct, `${d.gpu_mem_used} / ${d.gpu_mem_total}`);
  } else {
    gpuMemRow.hidden = true;
  }
}

function toggleStats(id) {
  const card = cardFor(id);
  if (!card) return;
  const panel = card.querySelector(".stats-panel");
  const btn = card.querySelector(".stats-btn");

  if (statsTimers[id]) {
    stopPoll(statsTimers[id]);
    delete statsTimers[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }

  panel.hidden = false;
  setPressed(btn, true);
  fetchStats(id);
  statsTimers[id] = poll(() => fetchStats(id), STATS_POLL_MS);
}

// fetchInfo fills the info panel's key/value list from
// /api/games/{id}/info. Nested values (players, multipliers) are skipped —
// the panel is a flat fact sheet, not a full data browser.
async function fetchInfo(id) {
  const card = cardFor(id);
  if (!card) return;
  let res;
  try {
    res = await fetch(`/api/games/${id}/info`);
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const data = await res.json();

  const emptyEl = card.querySelector(".info-empty");
  const fieldsEl = card.querySelector(".info-fields");
  fieldsEl.innerHTML = "";

  if (!data.available) {
    emptyEl.hidden = false;
    return;
  }
  emptyEl.hidden = true;
  for (const [key, value] of Object.entries(data)) {
    if (key === "available" || value == null || typeof value === "object") continue;
    const dt = document.createElement("dt");
    dt.textContent = key.replace(/_/g, " ");
    const dd = document.createElement("dd");
    dd.textContent = String(value);
    fieldsEl.appendChild(dt);
    fieldsEl.appendChild(dd);
  }
}

function toggleInfo(id) {
  const card = cardFor(id);
  if (!card) return;
  const panel = card.querySelector(".info-panel");
  const btn = card.querySelector(".info-btn");

  if (infoTimers[id]) {
    stopPoll(infoTimers[id]);
    delete infoTimers[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }

  panel.hidden = false;
  setPressed(btn, true);
  fetchInfo(id);
  infoTimers[id] = poll(() => fetchInfo(id), INFO_POLL_MS);
}

// Idle countdown: the server reports seconds left on each poll; between polls
// a 1s ticker counts down locally. Hidden once players are aboard.
function setIdleTimer(id, secsLeft) {
  const card = cardFor(id);
  if (!card) return;
  const hasPlayers = (parseInt(card.dataset.players, 10) || 0) > 0;
  if (secsLeft == null || hasPlayers) {
    delete card.dataset.idleDeadline;
  } else {
    card.dataset.idleDeadline = String(Date.now() + secsLeft * 1000);
  }
  renderIdleTimer(card);
}

function renderIdleTimer(card) {
  const el = card.querySelector(".idle-timer");
  const deadline = parseInt(card.dataset.idleDeadline, 10);
  if (!deadline) {
    el.hidden = true;
    return;
  }
  const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
  el.hidden = false;
  el.querySelector(".idle-text").textContent = left === 0
    ? "No players: stopping now…"
    : `No players: stops in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}

setInterval(() => document.querySelectorAll(".game-card").forEach(renderIdleTimer), 1000);

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    if (res.ok) document.getElementById("docker-banner").hidden = (await res.json()).docker !== false;
  } catch (err) {
    // transient; the next poll retries
  }
}

async function refreshStatuses() {
  refreshHealth();
  let res;
  try {
    res = await fetch("/api/games");
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const games = await res.json();
  games.forEach((g) => {
    setStatus(g.id, g.status);
    setPlayerCount(g.id, g.player_count);
    setIdleTimer(g.id, g.idle_seconds_left);
    // Starts run in the background, so a failure arrives here rather than
    // as the Start button's HTTP response.
    if (g.start_error && shownStartErrors[g.id] !== g.start_error_at) {
      shownStartErrors[g.id] = g.start_error_at;
      if (Date.now() / 1000 - g.start_error_at > 600) return; // stale; don't replay on reload
      const card = cardFor(g.id);
      const name = card ? card.dataset.name : g.id;
      const isStartFailure = !/^(stop failed|switch from )/.test(g.start_error);
      toast(`${name}${isStartFailure ? " failed to start" : ""}: ${g.start_error.slice(-300)}`);
    }
  });
}

function callAPI(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": CSRF_TOKEN,
      ...(options.headers || {}),
    },
  });
}

// confirmSwitch asks which running game to stop in favour of targetId.
// activeIds is every active game; with exactly one the dialog is a plain
// confirm, with several the user picks one (radio group). Resolves to the
// chosen game id, or null if cancelled. Focus is trapped in the dialog and
// restored to the opener afterwards; Escape cancels.
function confirmSwitch(activeIds, targetId) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("conflict-dialog");
    const nameOf = (id) => (cardFor(id) ? cardFor(id).dataset.name : id);
    const choices = document.getElementById("conflict-choices");
    const confirmBtn = document.getElementById("conflict-confirm");
    const cancelBtn = document.getElementById("conflict-cancel");
    const opener = document.activeElement;

    choices.querySelectorAll("label").forEach((l) => l.remove());
    const multiple = activeIds.length > 1;
    choices.hidden = !multiple;
    if (multiple) {
      document.getElementById("conflict-message").textContent =
        `Only so many games can run at once. Stop one to start ${nameOf(targetId)}.`;
      activeIds.forEach((id, i) => {
        const label = document.createElement("label");
        label.className = "dialog-choice";
        const input = document.createElement("input");
        input.type = "radio";
        input.name = "conflict-from";
        input.value = id;
        input.checked = i === 0;
        label.appendChild(input);
        label.appendChild(document.createTextNode(nameOf(id)));
        choices.appendChild(label);
      });
      confirmBtn.textContent = "Stop and start";
    } else {
      document.getElementById("conflict-message").textContent =
        `${nameOf(activeIds[0])} is currently running. Stop it and start ${nameOf(targetId)}?`;
      confirmBtn.textContent = "Switch";
    }
    dialog.hidden = false;
    (multiple ? choices.querySelector("input:checked") : confirmBtn).focus();

    const done = (answer) => {
      dialog.hidden = true;
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      document.removeEventListener("keydown", onKey);
      if (opener && opener.focus) opener.focus();
      resolve(answer);
    };
    const onConfirm = () => {
      const picked = multiple ? choices.querySelector("input:checked").value : activeIds[0];
      done(picked);
    };
    const onCancel = () => done(null);
    const onKey = (e) => {
      if (e.key === "Escape") { done(null); return; }
      if (e.key !== "Tab") return;
      const focusable = [...dialog.querySelectorAll("input, button")].filter((el) => !el.disabled && el.offsetParent !== null);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    document.addEventListener("keydown", onKey);
  });
}

// withBusy marks a button as working for the duration of an async action.
async function withBusy(btn, fn) {
  btn.classList.add("busy");
  btn.disabled = true;
  try {
    await fn();
  } finally {
    btn.classList.remove("busy");
    await refreshStatuses(); // re-derives which buttons should be enabled
    if (window.refreshActivity) setTimeout(window.refreshActivity, 1500);
  }
}

async function checkOK(res, action) {
  if (res.ok) return true;
  if (res.status === 403) toast(`${action} rejected — reload the page and try again.`);
  else if (res.status === 401) window.location.href = "/login";
  else toast(`${action} failed (HTTP ${res.status}).`);
  return false;
}

async function startGame(id, btn) {
  await withBusy(btn, async () => {
    const res = await callAPI(`/api/games/${id}/start`, { method: "POST" });
    if (res.status === 409) {
      const body = await res.json();
      if (body.busy) {
        toast(body.message.replace(/^exclusivity: /, ""));
        return;
      }
      const active = body.active_games && body.active_games.length ? body.active_games : [body.active_game];
      const from = await confirmSwitch(active, id);
      if (from) {
        const sw = await callAPI(`/api/games/${id}/switch`, {
          method: "POST",
          body: JSON.stringify({ from }),
        });
        if (sw.status === 409) {
          const b = await sw.json();
          toast((b.message || "That game is busy.").replace(/^exclusivity: /, ""));
        } else {
          await checkOK(sw, "Switch");
        }
      }
      return;
    }
    if (res.status === 429) {
      toast((await res.text()).replace(/^exclusivity: /, ""));
      return;
    }
    await checkOK(res, "Start");
  });
}

async function stopGame(id, btn) {
  await withBusy(btn, async () => {
    await checkOK(await callAPI(`/api/games/${id}/stop`, { method: "POST" }), "Stop");
  });
}

document.querySelectorAll(".game-card").forEach((card) => {
  const id = card.dataset.id;
  const startBtn = card.querySelector(".start-btn");
  const stopBtn = card.querySelector(".stop-btn");
  startBtn.addEventListener("click", () => startGame(id, startBtn));
  stopBtn.addEventListener("click", () => stopGame(id, stopBtn));
  card.querySelector(".logs-btn").addEventListener("click", () => toggleLogs(id));
  card.querySelector(".stats-btn").addEventListener("click", () => toggleStats(id));
  card.querySelector(".info-btn").addEventListener("click", () => toggleInfo(id));
  const backupsBtn = card.querySelector(".backups-btn");
  if (backupsBtn) backupsBtn.addEventListener("click", () => toggleBackups(id));
  const consoleBtn = card.querySelector(".console-btn");
  if (consoleBtn) consoleBtn.addEventListener("click", () => toggleConsole(id));
  const backupNow = card.querySelector(".backup-now-btn");
  if (backupNow) backupNow.addEventListener("click", () => backupGame(id, backupNow));

  // Paint the initial (server-rendered) status through the same path as
  // live updates so button states and the hero match from first paint.
  const status = card.dataset.status;
  card.dataset.status = "";
  setStatus(id, status);
});

refreshStatuses();

document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy"; }, 1500);
    } catch (err) {
      toast("Couldn't copy automatically. Select the text and copy it by hand.");
    }
  });
});

// Settings dialog: loads the live values, saves them with PUT /api/settings.
(() => {
  const settingsBtn = document.getElementById("settings-btn");
  if (!settingsBtn) return; // players don't get the settings dialog
  const dialog = document.getElementById("settings-dialog");
  const form = document.getElementById("settings-form");
  const errorEl = document.getElementById("settings-error");
  const fields = ["idle_enabled", "idle_minutes", "night_enabled", "night_start_hour",
    "night_end_hour", "max_active_games", "auto_update", "raw_console"];
  const input = (name) => form.elements[name];
  let opener = null;

  const close = () => {
    dialog.hidden = true;
    if (opener) opener.focus();
  };

  settingsBtn.addEventListener("click", async (e) => {
    opener = e.currentTarget;
    errorEl.hidden = true;
    try {
      const res = await callAPI("/api/settings");
      if (!res.ok) throw new Error(await res.text());
      const v = await res.json();
      fields.forEach((n) => {
        if (input(n).type === "checkbox") input(n).checked = !!v[n];
        else input(n).value = v[n];
      });
    } catch (err) {
      toast(`Could not load settings: ${err.message}`);
      return;
    }
    dialog.hidden = false;
    input("idle_enabled").focus();
  });

  document.getElementById("settings-cancel").addEventListener("click", close);
  dialog.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close(); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {};
    fields.forEach((n) => {
      body[n] = input(n).type === "checkbox" ? input(n).checked : parseInt(input(n).value, 10);
    });
    const res = await callAPI("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    if (!res.ok) {
      errorEl.textContent = (await res.text()).trim();
      errorEl.hidden = false;
      return;
    }
    close();
    toast("Settings saved.");
  });
})();

// Users dialog: list, add, edit (role / password reset), sign out everywhere, delete.
(() => {
  const btn = document.getElementById("users-btn");
  if (!btn) return; // players don't get user management
  const dialog = document.getElementById("users-dialog");
  const list = document.getElementById("users-list");
  const form = document.getElementById("user-form");
  const errorEl = document.getElementById("users-error");
  const title = document.getElementById("user-form-title");
  const submit = document.getElementById("user-form-submit");
  const cancelEdit = document.getElementById("user-form-cancel");
  const pwLabel = document.getElementById("user-pw-label");
  const googleField = document.getElementById("user-google-field");
  let editing = null; // username being edited, or null when adding
  let googleEnabled = false;

  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
  const close = () => { dialog.hidden = true; btn.focus(); };

  const resetForm = () => {
    editing = null;
    form.reset();
    form.elements.username.readOnly = false;
    form.elements.role.disabled = false;
    googleField.hidden = !googleEnabled;
    title.textContent = "Add a user";
    submit.textContent = "Add user";
    pwLabel.textContent = googleEnabled ? "Password (8+ characters, optional for Google users)" : "Password (8+ characters)";
    cancelEdit.hidden = true;
    showError("");
  };

  const startEdit = (u) => {
    resetForm();
    editing = u.username;
    form.elements.username.value = u.username;
    form.elements.username.readOnly = true;
    form.elements.role.value = u.role;
    form.elements.role.disabled = u.self;
    form.elements.google_email.value = u.google_email || "";
    title.textContent = `Edit ${u.username}`;
    submit.textContent = "Save changes";
    pwLabel.textContent = "New password (leave blank to keep)";
    cancelEdit.hidden = false;
    form.elements.password.focus();
  };

  const request = async (path, method, body) => {
    // Remember Google availability from every users response.
    const res = await callAPI(path, { method, body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) {
      showError((await res.text()).trim());
      return null;
    }
    showError("");
    const data = await res.json();
    if ("google_enabled" in data) googleEnabled = data.google_enabled;
    return data.users;
  };

  const render = (users) => {
    list.replaceChildren();
    users.forEach((u) => {
      const li = document.createElement("li");
      li.className = "user-row";
      const name = document.createElement("span");
      name.className = "user-name";
      name.textContent = u.username + (u.self ? " (you)" : "");
      const tags = document.createElement("span");
      tags.className = "user-tags";
      tags.textContent = [u.role, u.google_email ? `google: ${u.google_email}` : (u.google ? "google" : ""),
        u.has_password ? "" : "no password"].filter(Boolean).join(" · ");
      li.append(name, tags);
      if (u.managed) {
        const actions = document.createElement("span");
        actions.className = "user-actions";
        const mk = (label, fn, danger) => {
          const b = document.createElement("button");
          b.type = "button";
          b.className = "btn btn-ghost" + (danger ? " btn-danger" : "");
          b.textContent = label;
          b.addEventListener("click", fn);
          return b;
        };
        actions.append(mk("Edit", () => startEdit(u)));
        if (!u.self) {
          actions.append(mk("Sign out", async () => {
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "PUT", { revoke_sessions: true });
            if (r) toast(`Signed ${u.username} out everywhere.`);
          }));
          actions.append(mk("Delete", async () => {
            if (!confirm(`Delete user ${u.username}? They will be signed out.`)) return;
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "DELETE");
            if (r) { render(r); if (editing === u.username) resetForm(); }
          }, true));
        }
        li.append(actions);
      }
      list.append(li);
    });
  };

  btn.addEventListener("click", async () => {
    const res = await callAPI("/api/users");
    if (!res.ok) { toast(`Could not load users: ${(await res.text()).trim()}`); return; }
    const data = await res.json();
    googleEnabled = !!data.google_enabled;
    resetForm();
    render(data.users);
    dialog.hidden = false;
    form.elements.username.focus();
  });
  document.getElementById("users-close").addEventListener("click", close);
  cancelEdit.addEventListener("click", () => { form.elements.role.disabled = false; resetForm(); });
  dialog.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close(); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = form.elements;
    let users;
    if (editing) {
      const body = {};
      if (!f.role.disabled) body.role = f.role.value;
      if (f.password.value) body.password = f.password.value;
      if (googleEnabled) body.google_email = f.google_email.value.trim();
      users = await request(`/api/users/${encodeURIComponent(editing)}`, "PUT", body);
    } else {
      users = await request("/api/users", "POST",
        { username: f.username.value.trim(), password: f.password.value, role: f.role.value,
          google_email: googleEnabled ? f.google_email.value.trim() : "" });
    }
    if (!users) return;
    f.role.disabled = false;
    render(users);
    toast(editing ? "User updated." : "User added.");
    resetForm();
  });
})();

document.getElementById("logout-btn").addEventListener("click", async () => {
  await callAPI("/logout", { method: "POST" });
  window.location.href = "/login";
});

window.addEventListener("beforeunload", () => {
  Object.values(logSources).forEach((es) => es.close());
  Object.values(progressSources).forEach((es) => es.close());
  Object.values(statsTimers).forEach(stopPoll);
  Object.values(infoTimers).forEach(stopPoll);
});

poll(refreshStatuses, POLL_INTERVAL_MS);


// Logbook: recent activity plus playtime per player.
(() => {
  const list = document.getElementById("activity-list");
  const wrap = document.getElementById("playtime-wrap");
  const table = document.querySelector("#playtime-table tbody");
  if (!list) return;
  const nameOf = (id) => (id && cardFor(id) ? cardFor(id).dataset.name : id || "");

  const describe = (e) => {
    const game = nameOf(e.game);
    const who = e.actor || "Someone";
    const note = e.detail ? ` (${e.detail})` : "";
    switch (e.kind) {
      case "start": return [`${who} started ${game}`, false];
      case "stop": return [`${who} stopped ${game}${note}`, false];
      case "auto_stop": return [`${game} stopped automatically${note}`, false];
      case "start_failed": return [`${game} failed to start${note}`, true];
      case "stop_failed": return [`${game} failed to stop${note}`, true];
      case "join": return [`${who} joined ${game}`, false];
      case "leave": return [`${who} left ${game}`, false];
      case "settings": return [`${who} changed settings${note}`, false];
      case "users": return [`${who} ${e.detail || "changed users"}`, false];
      case "backup": return [`${who} backed up ${game}${note}`, false];
      case "console": return [`${who} used the ${game} console${note}`, false];
      default: return [`${e.kind} ${game}${note}`, false];
    }
  };
  const duration = (secs) => {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return h > 0 ? `${h}h ${m}m` : `${Math.max(m, 1)}m`;
  };

  async function refreshActivity() {
    let data;
    try {
      const res = await fetch("/api/activity?limit=25");
      if (!res.ok) return;
      data = await res.json();
    } catch (err) {
      return;
    }
    list.replaceChildren();
    if (data.events.length === 0) {
      const li = document.createElement("li");
      li.className = "empty";
      li.textContent = "Nothing logged yet.";
      list.appendChild(li);
    }
    data.events.forEach((e) => {
      const li = document.createElement("li");
      const time = document.createElement("time");
      time.dateTime = e.t;
      time.textContent = new Date(e.t).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      const [text, bad] = describe(e);
      const span = document.createElement("span");
      span.textContent = text;
      if (bad) span.className = "bad";
      li.append(time, span);
      list.appendChild(li);
    });

    table.replaceChildren();
    wrap.hidden = data.playtime.length === 0;
    data.playtime.slice(0, 10).forEach((p) => {
      const tr = document.createElement("tr");
      const a = document.createElement("td");
      a.textContent = `${p.player} · ${nameOf(p.game)}`;
      const b = document.createElement("td");
      b.textContent = duration(p.seconds);
      tr.append(a, b);
      table.appendChild(tr);
    });
  }
  refreshActivity();
  poll(refreshActivity, 30000);
  window.refreshActivity = refreshActivity;
})();


// Host health: memory, load and free disk, refreshed every 15s.
(() => {
  const panel = document.getElementById("host-panel");
  if (!panel) return;
  const gb = (n) => (n / 1024 ** 3).toFixed(n >= 100 * 1024 ** 3 ? 0 : 1);
  const item = (label, value, low) => {
    const el = document.createElement("span");
    if (low) el.className = "low";
    el.append(`${label} `);
    const b = document.createElement("b");
    b.textContent = value;
    el.appendChild(b);
    return el;
  };
  async function refreshHost() {
    let h;
    try {
      const res = await fetch("/api/host");
      if (!res.ok) return;
      h = await res.json();
    } catch (err) {
      return;
    }
    const items = [];
    if (h.mem_total > 0) {
      const used = h.mem_total - h.mem_available;
      items.push(item("memory", `${gb(used)} / ${gb(h.mem_total)} GB`, used / h.mem_total > 0.92));
    }
    if (h.load1 > 0) items.push(item("load", h.load1.toFixed(2), false));
    h.disks.forEach((d) => {
      if (d.total === 0) return;
      items.push(item(`disk ${d.path}`, `${gb(d.free)} GB free`, d.free / d.total < 0.1));
    });
    panel.replaceChildren(...items);
    panel.hidden = items.length === 0;
  }
  refreshHost();
  poll(refreshHost, 15000);
})();


// Backups panel (admins only): list the game's backup files, take a new one.
const backupTimers = {};

async function fetchBackups(id) {
  const card = cardFor(id);
  if (!card) return;
  let data;
  try {
    const res = await fetch(`/api/games/${id}/backups`);
    if (!res.ok) return;
    data = await res.json();
  } catch (err) {
    return;
  }
  const note = card.querySelector(".backups-note");
  const list = card.querySelector(".backups-list");
  note.textContent = data.running ? "Backing up…" : data.unavailable ? "Start the game to list or take backups." : "";
  card.querySelector(".backup-now-btn").disabled = !!data.running || !!data.unavailable;
  list.replaceChildren();
  const mb = (n) => (n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)} GB` : `${(n / 1024 ** 2).toFixed(1)} MB`);
  data.files.forEach((f) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = f.name;
    const meta = document.createElement("span");
    meta.textContent = `${mb(f.size)} · ${new Date(f.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`;
    li.append(name, meta);
    list.appendChild(li);
  });
}

function toggleBackups(id) {
  const card = cardFor(id);
  if (!card) return;
  const panel = card.querySelector(".backups-panel");
  const btn = card.querySelector(".backups-btn");
  if (backupTimers[id]) {
    stopPoll(backupTimers[id]);
    delete backupTimers[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }
  panel.hidden = false;
  setPressed(btn, true);
  fetchBackups(id);
  backupTimers[id] = poll(() => fetchBackups(id), 5000);
}

async function backupGame(id, btn) {
  btn.disabled = true;
  const res = await callAPI(`/api/games/${id}/backup`, { method: "POST" });
  if (res.status === 409) toast((await res.text()).trim());
  else await checkOK(res, "Backup");
  fetchBackups(id);
}


// Console panel (admins only): fixed actions per game, plus a raw RCON box
// when an admin has enabled it in Settings. Output is shown as text only.
const consoleLoaded = {};

function consoleLog(card, line) {
  const out = card.querySelector(".console-output");
  out.textContent += line + "\n";
  out.scrollTop = out.scrollHeight;
}

async function consoleCall(id, kind, payload, label) {
  const card = cardFor(id);
  consoleLog(card, `> ${label}`);
  try {
    const res = await callAPI(`/api/games/${id}/console/${kind}`, { method: "POST", body: JSON.stringify(payload) });
    if (res.ok) consoleLog(card, (await res.json()).output || "(no output)");
    else consoleLog(card, `! ${(await res.text()).trim() || res.statusText}`);
  } catch (err) {
    consoleLog(card, "! request failed");
  }
}

async function loadConsole(id) {
  const card = cardFor(id);
  let data;
  try {
    const res = await fetch(`/api/games/${id}/console`);
    if (!res.ok) return;
    data = await res.json();
  } catch (err) {
    return;
  }
  const bar = card.querySelector(".console-actions");
  const form = card.querySelector(".console-form");
  const fieldsEl = card.querySelector(".console-fields");
  const raw = card.querySelector(".console-raw");
  const note = card.querySelector(".console-note");
  bar.replaceChildren();
  form.hidden = true;
  let current = null;
  data.actions.forEach((a) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn btn-ghost" + (a.danger ? " btn-danger" : "");
    b.textContent = a.label;
    b.addEventListener("click", () => {
      if (!a.fields || a.fields.length === 0) {
        form.hidden = true;
        consoleCall(id, "action", { action: a.id }, a.label);
        return;
      }
      current = a;
      fieldsEl.replaceChildren();
      a.fields.forEach((f) => {
        const label = document.createElement("label");
        label.textContent = f.label;
        const input = document.createElement("input");
        input.type = "text";
        input.name = f.name;
        input.required = !f.optional;
        input.maxLength = 200;
        input.autocomplete = "off";
        label.appendChild(input);
        fieldsEl.appendChild(label);
      });
      form.hidden = false;
      fieldsEl.querySelector("input").focus();
    });
    bar.appendChild(b);
  });
  form.onsubmit = (e) => {
    e.preventDefault();
    if (!current) return;
    const args = {};
    new FormData(form).forEach((v, k) => { args[k] = String(v); });
    if (current.danger && !confirm(`${current.label}: are you sure?`)) return;
    consoleCall(id, "action", { action: current.id, args }, `${current.label} ${Object.values(args).filter(Boolean).join(" ")}`.trim());
    form.hidden = true;
  };
  card.querySelector(".console-cancel").onclick = () => { form.hidden = true; };
  raw.hidden = !data.raw_enabled;
  raw.onsubmit = (e) => {
    e.preventDefault();
    const input = raw.querySelector(".console-raw-input");
    const command = input.value.trim();
    if (!command) return;
    input.value = "";
    consoleCall(id, "raw", { command }, command);
  };
  note.textContent = data.raw_available && !data.raw_enabled ? "The raw console is off. An admin can enable it in Settings." : "";
  consoleLoaded[id] = true;
}

function toggleConsole(id) {
  const card = cardFor(id);
  if (!card) return;
  const panel = card.querySelector(".console-panel");
  const btn = card.querySelector(".console-btn");
  panel.hidden = !panel.hidden;
  setPressed(btn, !panel.hidden);
  // Reload each time it opens so a Settings change takes effect.
  if (!panel.hidden) loadConsole(id);
}
