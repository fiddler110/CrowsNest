// Dashboard: vessel cards (status, start/stop/switch, panels), fleet banner,
// logbook and host health. callAPI, checkOK, errorText, toast, openModal and
// confirmAction come from api.js.
const POLL_INTERVAL_MS = 5000;
const HEALTH_POLL_MS = 30000;
const STATS_POLL_MS = 3000;
const INFO_POLL_MS = 30000; // the fact sheet barely changes; every poll is a call to the game server
const BACKUPS_POLL_MS = 5000;
const MAX_LOG_LINES = 300;
const MAX_CONSOLE_LINES = 300;

const logSources = {};
const progressSources = {};
const progressDone = {};      // id -> true once a run's progress hit 100%
const shownStartErrors = {};  // id -> start_error_at already toasted
const panelTimers = {};       // id -> poll handle of the open tab (stats, info, backups)
const openTab = {};           // id -> name of the card's open tab, if any

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

const isOffline = (card) => card.dataset.status === "offline";

function setStatus(id, status) {
  const card = cardFor(id);
  if (!card) return;
  const prevStatus = card.dataset.status;
  // Until the first poll answers, a server-rendered "unknown" keeps its
  // neutral "checking…" badge rather than flashing the red unknown one.
  if (!(prevStatus === "" && status === "unknown")) {
    const badge = card.querySelector(".status");
    badge.className = `status status-${status}`;
    badge.querySelector(".status-text").textContent = status;
  }
  card.dataset.status = status;

  // Start makes sense only for a stopped/unknown game; Stop only for one
  // that's running or coming up. (A game that's up while a *different* one
  // is chosen still goes through the switch dialog on the server's 409.)
  card.querySelector(".start-btn").disabled = ["online", "starting", "stopping"].includes(status);
  card.querySelector(".stop-btn").disabled = status === "offline" || status === "stopping";

  // While starting, (re)open the progress stream on every update: it ends
  // early while the image is still being pulled (no container yet), and
  // startProgressTracking is a no-op while one is already open.
  if (status === "starting") {
    if (!progressDone[id]) startProgressTracking(id);
  } else {
    delete progressDone[id];
    stopProgressTracking(id);
  }
  if (prevStatus && prevStatus !== status) {
    const tab = openTab[id] && TABS[openTab[id]];
    if (tab && tab.onStatus) tab.onStatus(id, card, status);
  }
  updateFleet();
}

// listNames joins names as "A", "A and B", "A, B and C".
function listNames(names) {
  if (names.length < 2) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

const playersOf = (c) => parseInt(c.dataset.players, 10) || 0;
const aboard = (n) => (n === 1 ? "1 player aboard" : `${n} players aboard`);

// updateFleet refreshes the hero banner from what the cards currently show.
function updateFleet() {
  const cards = [...document.querySelectorAll(".game-card")];
  const active = cards.filter((c) => ["online", "starting"].includes(c.dataset.status));
  const crew = active.reduce((n, c) => n + playersOf(c), 0);

  const hero = document.getElementById("fleet");
  const title = document.getElementById("fleet-title");
  const sub = document.getElementById("fleet-sub");
  hero.classList.toggle("is-active", active.length > 0);

  if (cards.length === 0) {
    title.textContent = "No vessels charted";
    sub.textContent = document.body.hasAttribute("data-admin")
      ? "Add a game on the Games page to see it here."
      : "Ask an admin to add a game.";
  } else if (active.length === 0) {
    title.textContent = "All quiet on the horizon";
    sub.textContent = "No server is running. Pick a vessel below and start it when the crew is ready.";
  } else if (active.length === 1) {
    const c = active[0];
    const name = c.dataset.name;
    if (c.dataset.status === "starting") {
      title.textContent = `${name} is getting under way`;
      sub.textContent = "The server is starting up. It will appear online once it's ready for the crew.";
    } else {
      title.textContent = `${name} is under sail`;
      sub.textContent = `${aboard(crew)}.`;
    }
  } else {
    title.textContent = `${active.length} vessels under way: ${listNames(active.map((c) => c.dataset.name))}`;
    const starting = active.filter((c) => c.dataset.status === "starting").map((c) => c.dataset.name);
    const parts = [`${aboard(crew)} across them.`];
    if (starting.length) parts.push(`${listNames(starting)} ${starting.length === 1 ? "is" : "are"} still getting under way.`);
    sub.textContent = parts.join(" ");
  }

  document.getElementById("stat-vessels").textContent = cards.length;
  document.getElementById("stat-active").textContent = active.length;
  document.getElementById("stat-crew").textContent = crew;
}

function startProgressTracking(id) {
  if (progressSources[id]) return;
  const card = cardFor(id);
  if (!card) return;
  const wrap = card.querySelector(".progress-wrap");
  const bar = card.querySelector(".progress-bar");
  const label = card.querySelector(".progress-label");

  const es = new EventSource(`/api/games/${encodeURIComponent(id)}/startup-progress`);
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
  // Stream ended (e.g. still pulling, no container yet): close it but keep
  // the bar showing, and reopen it shortly if the game is still starting.
  es.onerror = () => {
    closeProgressSource(id);
    setTimeout(() => {
      const c = cardFor(id);
      if (c && c.dataset.status === "starting" && !progressDone[id]) startProgressTracking(id);
    }, POLL_INTERVAL_MS);
  };
}

function closeProgressSource(id) {
  const es = progressSources[id];
  if (es) {
    es.close();
    delete progressSources[id];
  }
}

function stopProgressTracking(id) {
  closeProgressSource(id);
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

// ---------- card tabs ----------
// Each card's panels are one tab group: at most one is open. Opening a tab
// starts its stream or poll; closing it, or switching to another, stops it.
// Clicking the open tab closes it.

const tabButton = (card, name) => card.querySelector(`.tab[data-tab="${name}"]`);
const tabPanel = (card, name) => card.querySelector(`[role="tabpanel"][data-panel="${name}"]`);

function stopPanelTimer(id) {
  if (panelTimers[id]) {
    stopPoll(panelTimers[id]);
    delete panelTimers[id];
  }
}

function selectTab(id, name) {
  const card = cardFor(id);
  if (!card) return;
  const current = openTab[id];
  if (current) {
    TABS[current].stop(id, card);
    tabPanel(card, current).hidden = true;
    tabButton(card, current).setAttribute("aria-selected", "false");
    delete openTab[id];
  }
  if (!name || name === current || !TABS[name]) return;
  openTab[id] = name;
  tabPanel(card, name).hidden = false;
  const btn = tabButton(card, name);
  btn.setAttribute("aria-selected", "true");
  focusableTab(card, btn);
  TABS[name].start(id, card);
}

// focusableTab makes btn the tab group's single Tab stop (roving tabindex).
function focusableTab(card, btn) {
  card.querySelectorAll(".tab").forEach((t) => { t.tabIndex = t === btn ? 0 : -1; });
}

function wireTabs(card) {
  const id = card.dataset.id;
  const tabs = [...card.querySelectorAll(".tab")];
  if (!tabs.length) return;
  focusableTab(card, tabs[0]);
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => selectTab(id, openTab[id] === btn.dataset.tab ? null : btn.dataset.tab));
  });
  // Arrow keys move between tabs; Enter or Space opens one. (Moving does not
  // open: every tab starts a stream or a poll.)
  card.querySelector(".tabs").addEventListener("keydown", (e) => {
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    let next;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = tabs[(i + 1) % tabs.length];
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = tabs[(i - 1 + tabs.length) % tabs.length];
    else if (e.key === "Home") next = tabs[0];
    else if (e.key === "End") next = tabs[tabs.length - 1];
    if (!next) return;
    e.preventDefault();
    focusableTab(card, next);
    next.focus();
  });
}

// Game containers often colour their output with ANSI escapes, which a
// <div> would show as garbage boxes.
const ANSI_RE = /\u001b\[[0-9;?]*[A-Za-z]/g;
function stripAnsi(text) {
  return text.replace(ANSI_RE, "");
}

// appendLines adds one row per line to out, follows the newest line unless
// the reader has scrolled back (scroller is the scrolling box), and keeps at
// most max rows.
function appendLines(out, scroller, text, kind, max) {
  const atBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 24;
  String(text).split("\n").forEach((t) => {
    const line = document.createElement("div");
    if (kind) line.className = `ln-${kind}`;
    line.textContent = t;
    out.appendChild(line);
  });
  while (out.childElementCount > max) out.firstElementChild.remove();
  if (atBottom) scroller.scrollTop = scroller.scrollHeight;
}

// startLogs follows the container's log. With resume the lines already shown
// stay (a stream that ended is picking up again).
function startLogs(id, card, resume) {
  const panel = tabPanel(card, "logs");
  const output = card.querySelector(".log-output");
  if (!resume) {
    output.replaceChildren();
    panel.scrollTop = 0; // empty panel counts as "at the bottom", so it follows
  }
  const es = new EventSource(`/api/games/${encodeURIComponent(id)}/logs`);
  logSources[id] = es;
  // Plain lines arrive as default "message" events; games with a log
  // formatter tag lines warn/error/verbose, which only named listeners see.
  const addLine = (kind) => (e) => appendLines(output, panel, stripAnsi(e.data), kind, MAX_LOG_LINES);
  es.onmessage = addLine("");
  ["warn", "error", "verbose"].forEach((kind) => es.addEventListener(kind, addLine(kind)));
  es.onerror = () => {
    es.close();
    if (logSources[id] !== es) return;
    delete logSources[id];
    appendLines(output, panel, "— stream ended (container stopped?) —", "muted", MAX_LOG_LINES);
  };
}

function stopLogs(id) {
  const es = logSources[id];
  if (es) {
    delete logSources[id];
    es.close();
  }
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

function clearStats(card) {
  clearStatBar(card.querySelector(".stat-cpu-fill"), card.querySelector(".stat-cpu-val"));
  clearStatBar(card.querySelector(".stat-mem-fill"), card.querySelector(".stat-mem-val"));
  card.querySelector(".stat-gpu-row").hidden = true;
  card.querySelector(".stat-gpu-mem-row").hidden = true;
}

async function fetchStats(id) {
  const card = cardFor(id);
  if (!card || isOffline(card)) return;
  let res;
  try {
    res = await fetch(`/api/games/${encodeURIComponent(id)}/stats`);
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const d = await res.json();
  if (openTab[id] !== "stats" || isOffline(card)) return; // closed or stopped meanwhile

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

// startStats polls the container's figures, or, while the game is offline,
// shows N/A without polling (the status poll restarts it when it comes up).
function startStats(id, card) {
  stopPanelTimer(id);
  const offline = isOffline(card);
  card.querySelector(".stats-note").hidden = !offline;
  if (offline) {
    clearStats(card);
    return;
  }
  fetchStats(id);
  panelTimers[id] = poll(() => fetchStats(id), STATS_POLL_MS);
}

// fetchInfo fills the info panel's key/value list from
// /api/games/{id}/info. Nested values (players, multipliers) are skipped —
// the panel is a flat fact sheet, not a full data browser.
async function fetchInfo(id) {
  const card = cardFor(id);
  if (!card) return;
  let res;
  try {
    res = await fetch(`/api/games/${encodeURIComponent(id)}/info`);
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const data = await res.json();
  if (openTab[id] !== "info") return;

  const emptyEl = card.querySelector(".info-empty");
  const fieldsEl = card.querySelector(".info-fields");
  fieldsEl.replaceChildren();

  if (!data.available) {
    emptyEl.textContent = "No info right now. The server may still be starting.";
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
    fieldsEl.append(dt, dd);
  }
}

function startInfo(id, card) {
  stopPanelTimer(id);
  if (isOffline(card)) {
    const emptyEl = card.querySelector(".info-empty");
    card.querySelector(".info-fields").replaceChildren();
    emptyEl.textContent = "Offline: start the server to see its info.";
    emptyEl.hidden = false;
    return;
  }
  fetchInfo(id);
  panelTimers[id] = poll(() => fetchInfo(id), INFO_POLL_MS);
}

// TABS: what opening and closing each tab does. onStatus runs when the
// card's status changes while that tab is open.
const TABS = {
  logs: {
    start: (id, card) => startLogs(id, card, false),
    stop: (id) => stopLogs(id),
    // A stream that ended (container stopped, or not created yet) picks up
    // again once the game is coming up or running.
    onStatus: (id, card, status) => {
      if (!logSources[id] && (status === "starting" || status === "online")) startLogs(id, card, true);
    },
  },
  stats: {
    start: startStats,
    stop: stopPanelTimer,
    onStatus: (id, card, status) => {
      if ((status === "offline") !== !panelTimers[id]) startStats(id, card);
    },
  },
  info: {
    start: startInfo,
    stop: stopPanelTimer,
    onStatus: (id, card, status) => {
      if ((status === "offline") !== !panelTimers[id]) startInfo(id, card);
    },
  },
  backups: {
    start: (id) => {
      stopPanelTimer(id);
      fetchBackups(id);
      panelTimers[id] = poll(() => fetchBackups(id), BACKUPS_POLL_MS);
    },
    stop: stopPanelTimer,
  },
  console: {
    // Reload each time it opens so a Settings change takes effect.
    start: (id) => loadConsole(id),
    stop: (id, card) => { card.querySelector(".console-form").hidden = true; },
  },
};

// Idle countdown: the server reports seconds left on each poll; between polls
// a 1s ticker counts down locally. Hidden once players are aboard.
function setIdleTimer(id, secsLeft) {
  const card = cardFor(id);
  if (!card) return;
  const hasPlayers = playersOf(card) > 0;
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

// Docker reachability: pushed by the live stream, or (while polling) checked
// every 30s, and straight away whenever the game list fails to load.
function applyHealth(health) {
  document.getElementById("docker-banner").hidden = health.docker !== false;
  const bb = document.getElementById("backups-banner");
  if (bb) bb.hidden = health.backups !== false;
}

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    if (res.ok) applyHealth(await res.json());
  } catch (err) {
    // transient; the next poll retries
  }
}

// applyGames paints one /api/games body (from the stream or a poll).
function applyGames(games) {
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
      toast(`${name}${isStartFailure ? " failed to start" : ""}: ${g.start_error.slice(-300)}`, "error");
    }
  });
}

async function refreshStatuses() {
  let res;
  try {
    res = await fetch("/api/games");
  } catch (err) {
    refreshHealth();
    return; // transient network hiccup; next poll retries
  }
  if (res.status === 401) {
    window.location.href = "/login";
    return;
  }
  if (!res.ok) {
    refreshHealth();
    return;
  }
  applyGames(await res.json());
}

// Live updates: /api/events pushes the /api/games and /api/health bodies
// whenever they change. While the stream is down, poll both instead, and
// try the stream again every STREAM_RETRY_MS.
const STREAM_RETRY_MS = 30000;
let liveEvents = null;
let fallbackPolls = null;

function startFallbackPolling() {
  if (fallbackPolls) return;
  fallbackPolls = [poll(refreshStatuses, POLL_INTERVAL_MS), poll(refreshHealth, HEALTH_POLL_MS)];
}

function stopFallbackPolling() {
  if (!fallbackPolls) return;
  fallbackPolls.forEach(stopPoll);
  fallbackPolls = null;
}

function connectLiveEvents() {
  if (liveEvents) return;
  if (typeof EventSource === "undefined") {
    refreshStatuses();
    refreshHealth();
    startFallbackPolling();
    return;
  }
  const es = new EventSource("/api/events");
  liveEvents = es;
  es.addEventListener("games", (e) => {
    stopFallbackPolling();
    applyGames(JSON.parse(e.data));
  });
  es.addEventListener("health", (e) => applyHealth(JSON.parse(e.data)));
  es.onerror = () => {
    es.close();
    liveEvents = null;
    refreshStatuses(); // also sends a signed-out tab to the login page
    startFallbackPolling();
    setTimeout(connectLiveEvents, STREAM_RETRY_MS);
  };
}

// confirmSwitch asks which running game to stop in favour of targetId.
// activeIds is every active game; with exactly one the dialog is a plain
// confirm, with several the user picks one (radio group). Resolves to the
// chosen game id, or null if cancelled.
function confirmSwitch(activeIds, targetId) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("conflict-dialog");
    const nameOf = (id) => (cardFor(id) ? cardFor(id).dataset.name : id);
    const choices = document.getElementById("conflict-choices");
    const confirmBtn = document.getElementById("conflict-confirm");
    const cancelBtn = document.getElementById("conflict-cancel");

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
        label.append(input, document.createTextNode(nameOf(id)));
        choices.appendChild(label);
      });
      confirmBtn.textContent = "Stop and start";
    } else {
      document.getElementById("conflict-message").textContent =
        `${nameOf(activeIds[0])} is currently running. Stop it and start ${nameOf(targetId)}?`;
      confirmBtn.textContent = "Switch";
    }

    let close;
    const done = (answer) => {
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      close();
      resolve(answer);
    };
    const onConfirm = () => done(multiple ? choices.querySelector("input:checked").value : activeIds[0]);
    const onCancel = () => done(null);
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    close = openModal(dialog, multiple ? choices.querySelector("input:checked") : confirmBtn, onCancel);
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

async function startGame(id, btn) {
  await withBusy(btn, async () => {
    const path = `/api/games/${encodeURIComponent(id)}`;
    const res = await callAPI(`${path}/start`, { method: "POST" });
    if (res.status === 409) {
      const body = await res.json();
      if (body.busy) {
        toast(body.message.replace(/^exclusivity: /, ""), "info");
        return;
      }
      const active = body.active_games && body.active_games.length ? body.active_games : [body.active_game];
      const from = await confirmSwitch(active, id);
      if (from) {
        const sw = await callAPI(`${path}/switch`, {
          method: "POST",
          body: JSON.stringify({ from }),
        });
        if (sw.status === 409) {
          const b = await sw.json();
          toast((b.message || "That game is busy.").replace(/^exclusivity: /, ""), "info");
        } else {
          await checkOK(sw, "Switch");
        }
      }
      return;
    }
    if (res.status === 429) {
      toast(await errorText(res), "info");
      return;
    }
    await checkOK(res, "Start");
  });
}

async function stopGame(id, btn) {
  await withBusy(btn, async () => {
    await checkOK(await callAPI(`/api/games/${encodeURIComponent(id)}/stop`, { method: "POST" }), "Stop");
  });
}

const ACCENT_RE = /^#[0-9a-f]{6}$/i;

document.querySelectorAll(".game-card").forEach((card) => {
  const id = card.dataset.id;
  // The module's accent colour; the CSP allows setting it through the CSSOM.
  if (ACCENT_RE.test(card.dataset.accent || "")) card.style.setProperty("--vessel", card.dataset.accent);
  const startBtn = card.querySelector(".start-btn");
  const stopBtn = card.querySelector(".stop-btn");
  startBtn.addEventListener("click", () => startGame(id, startBtn));
  stopBtn.addEventListener("click", () => stopGame(id, stopBtn));
  wireTabs(card);
  const backupNow = card.querySelector(".backup-now-btn");
  if (backupNow) backupNow.addEventListener("click", () => backupGame(id, backupNow));

  // Paint the initial (server-rendered) status through the same path as
  // live updates so button states and the hero match from first paint.
  const status = card.dataset.status;
  card.dataset.status = "";
  setStatus(id, status);
});

connectLiveEvents(); // its first events paint every card and the health banner

document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy"; }, 1500);
    } catch (err) {
      toast("Couldn't copy automatically. Select the text and copy it by hand.", "info");
    }
  });
});

window.addEventListener("beforeunload", () => {
  Object.values(logSources).forEach((es) => es.close());
  Object.values(progressSources).forEach((es) => es.close());
  Object.values(panelTimers).forEach(stopPoll);
  if (liveEvents) liveEvents.close();
});


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
      case "crash": return [`${game} crashed (${e.detail})`, true];
      case "crash_loop": return [`${game} is crash-looping (${e.detail})`, true];
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
async function fetchBackups(id) {
  const card = cardFor(id);
  if (!card) return;
  let data;
  try {
    const res = await fetch(`/api/games/${encodeURIComponent(id)}/backups`);
    if (!res.ok) return;
    data = await res.json();
  } catch (err) {
    return;
  }
  const note = card.querySelector(".backups-note");
  const list = card.querySelector(".backups-list");
  note.textContent = data.restoring ? "Restoring…" : data.running ? "Backing up…" : data.unavailable ? "Start the game to list or take backups." : "";
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
    if (data.restorable) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-ghost restore-btn";
      btn.textContent = "Restore";
      btn.disabled = !!data.running;
      btn.addEventListener("click", () => restoreGame(id, f.name, btn));
      li.appendChild(btn);
    }
    list.appendChild(li);
  });
}

async function restoreGame(id, file, btn) {
  const name = cardFor(id).dataset.name;
  const ok = await confirmAction({
    title: `Restore ${name}?`,
    message: `This stops ${name}, replaces its current world with ${file}, and starts it again if it was running. ` +
      "A fresh backup of the current world is taken first when the game keeps backups before stopping. Players will be disconnected.",
    confirmLabel: "Restore",
    danger: true,
    eyebrow: "// restore",
  });
  if (!ok) return;
  btn.disabled = true;
  const res = await callAPI(`/api/games/${encodeURIComponent(id)}/restore`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file }),
  });
  if (res.status === 409 || res.status === 400) toast(await errorText(res), "info");
  else if (await checkOK(res, "Restore")) toast(`${name}: restoring ${file}.`, "ok");
  fetchBackups(id);
}

async function backupGame(id, btn) {
  btn.disabled = true;
  const res = await callAPI(`/api/games/${encodeURIComponent(id)}/backup`, { method: "POST" });
  if (res.status === 409) toast(await errorText(res), "info");
  else if (await checkOK(res, "Backup")) toast(`${cardFor(id).dataset.name}: backup started.`, "ok");
  fetchBackups(id);
}


// Console panel (admins only): fixed actions per game, plus a raw RCON box
// when an admin has enabled it in Settings. Output is shown as text only.
function consoleLog(card, text, kind) {
  const out = card.querySelector(".console-output");
  appendLines(out, out, text, kind, MAX_CONSOLE_LINES);
}

async function consoleCall(id, kind, payload, label) {
  const card = cardFor(id);
  consoleLog(card, `> ${label}`, "cmd");
  try {
    const res = await callAPI(`/api/games/${encodeURIComponent(id)}/console/${kind}`, { method: "POST", body: JSON.stringify(payload) });
    if (res.ok) consoleLog(card, (await res.json()).output || "(no output)");
    else consoleLog(card, `! ${await errorText(res)}`, "error");
  } catch (err) {
    consoleLog(card, "! request failed", "error");
  }
}

// confirmDanger asks before a console action marked danger (kick, ban,
// shut down…). Resolves true for actions that are not dangerous.
function confirmDanger(card, action, detail) {
  if (!action.danger) return Promise.resolve(true);
  return confirmAction({
    eyebrow: "// console",
    title: `${action.label} on ${card.dataset.name}?`,
    message: detail ? `This runs “${action.label} ${detail}” on the game server.` : `This runs “${action.label}” on the game server.`,
    confirmLabel: action.label,
    danger: true,
  });
}

async function loadConsole(id) {
  const card = cardFor(id);
  let data;
  try {
    const res = await fetch(`/api/games/${encodeURIComponent(id)}/console`);
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
    b.addEventListener("click", async () => {
      if (!a.fields || a.fields.length === 0) {
        form.hidden = true;
        if (!(await confirmDanger(card, a))) return;
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
  form.onsubmit = async (e) => {
    e.preventDefault();
    if (!current) return;
    const action = current;
    const args = {};
    new FormData(form).forEach((v, k) => { args[k] = String(v); });
    const detail = Object.values(args).filter(Boolean).join(" ");
    if (!(await confirmDanger(card, action, detail))) return;
    consoleCall(id, "action", { action: action.id, args }, `${action.label} ${detail}`.trim());
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
}
