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
  card.querySelector(".start-btn").disabled = status === "online" || status === "starting";
  card.querySelector(".stop-btn").disabled = status === "offline";

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
  setPressed(btn, true);

  const es = new EventSource(`/api/games/${id}/logs`);
  logSources[id] = es;
  // Plain lines arrive as default "message" events; games with a log
  // formatter tag lines warn/error/verbose, which only named listeners see.
  const addLine = (kind) => (e) => {
    const line = document.createElement("div");
    if (kind) line.className = `ln-${kind}`;
    line.textContent = stripAnsi(e.data);
    output.appendChild(line);
    while (output.children.length > MAX_LOG_LINES) {
      output.removeChild(output.firstChild);
    }
    output.scrollTop = output.scrollHeight;
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
    clearInterval(statsTimers[id]);
    delete statsTimers[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }

  panel.hidden = false;
  setPressed(btn, true);
  fetchStats(id);
  statsTimers[id] = setInterval(() => fetchStats(id), STATS_POLL_MS);
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
    clearInterval(infoTimers[id]);
    delete infoTimers[id];
    panel.hidden = true;
    setPressed(btn, false);
    return;
  }

  panel.hidden = false;
  setPressed(btn, true);
  fetchInfo(id);
  infoTimers[id] = setInterval(() => fetchInfo(id), INFO_POLL_MS);
}

async function refreshStatuses() {
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
    // Starts run in the background, so a failure arrives here rather than
    // as the Start button's HTTP response.
    if (g.start_error && shownStartErrors[g.id] !== g.start_error_at) {
      shownStartErrors[g.id] = g.start_error_at;
      if (Date.now() / 1000 - g.start_error_at > 600) return; // stale; don't replay on reload
      const card = cardFor(g.id);
      const name = card ? card.dataset.name : g.id;
      toast(`${name} failed to start: ${g.start_error.slice(-300)}`);
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
      const active = body.active_games && body.active_games.length ? body.active_games : [body.active_game];
      const from = await confirmSwitch(active, id);
      if (from) {
        const sw = await callAPI(`/api/games/${id}/switch`, {
          method: "POST",
          body: JSON.stringify({ from }),
        });
        await checkOK(sw, "Switch");
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
      toast("Couldn't copy automatically. Select the address and copy it by hand.");
    }
  });
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await callAPI("/logout", { method: "POST" });
  window.location.href = "/login";
});

window.addEventListener("beforeunload", () => {
  Object.values(logSources).forEach((es) => es.close());
  Object.values(progressSources).forEach((es) => es.close());
  Object.values(statsTimers).forEach((t) => clearInterval(t));
  Object.values(infoTimers).forEach((t) => clearInterval(t));
});

setInterval(refreshStatuses, POLL_INTERVAL_MS);
