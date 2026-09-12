const CSRF_TOKEN = document.querySelector('meta[name=csrf-token]').content;
const POLL_INTERVAL_MS = 5000;
const STATS_POLL_MS = 3000;
const INFO_POLL_MS = 5000;
const MAX_LOG_LINES = 300;

const logSources = {};
const progressSources = {};
const statsTimers = {};
const infoTimers = {};

function setStatus(id, status) {
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  const badge = card.querySelector(".status");
  const prevStatus = badge.dataset.status;
  badge.textContent = status;
  badge.className = `status status-${status}`;
  badge.dataset.status = status;

  if (status === "starting" && prevStatus !== "starting") {
    startProgressTracking(id);
  } else if (status !== "starting") {
    stopProgressTracking(id);
  }
}

function startProgressTracking(id) {
  if (progressSources[id]) return;
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
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
      stopProgressTracking(id);
    }
  });
  es.addEventListener("unsupported", () => stopProgressTracking(id));
  es.onerror = () => stopProgressTracking(id);
}

function stopProgressTracking(id) {
  const es = progressSources[id];
  if (es) {
    es.close();
    delete progressSources[id];
  }
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (card) card.querySelector(".progress-wrap").hidden = true;
}

function setPlayerCount(id, count) {
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  const el = card.querySelector(".player-count");
  if (count == null) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  el.textContent = count === 1 ? "1 player" : `${count} players`;
}

function toggleLogs(id) {
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  const panel = card.querySelector(".log-panel");
  const output = card.querySelector(".log-output");
  const btn = card.querySelector(".logs-btn");

  if (logSources[id]) {
    logSources[id].close();
    delete logSources[id];
    panel.hidden = true;
    btn.textContent = "Logs";
    return;
  }

  output.textContent = "";
  panel.hidden = false;
  btn.textContent = "Hide Logs";

  const es = new EventSource(`/api/games/${id}/logs`);
  logSources[id] = es;
  es.onmessage = (e) => {
    const line = document.createElement("div");
    line.textContent = e.data;
    output.appendChild(line);
    while (output.children.length > MAX_LOG_LINES) {
      output.removeChild(output.firstChild);
    }
    output.scrollTop = output.scrollHeight;
  };
  es.onerror = () => {
    es.close();
    delete logSources[id];
    btn.textContent = "Logs";
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
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
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
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  const panel = card.querySelector(".stats-panel");
  const btn = card.querySelector(".stats-btn");

  if (statsTimers[id]) {
    clearInterval(statsTimers[id]);
    delete statsTimers[id];
    panel.hidden = true;
    btn.textContent = "Stats";
    return;
  }

  panel.hidden = false;
  btn.textContent = "Hide Stats";
  fetchStats(id);
  statsTimers[id] = setInterval(() => fetchStats(id), STATS_POLL_MS);
}

// fetchInfo fills the info panel's key/value list from
// /api/games/{id}/info. Nested values (players, multipliers) are skipped —
// the panel is a flat fact sheet, not a full data browser.
async function fetchInfo(id) {
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
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
  const card = document.querySelector(`.game-card[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  const panel = card.querySelector(".info-panel");
  const btn = card.querySelector(".info-btn");

  if (infoTimers[id]) {
    clearInterval(infoTimers[id]);
    delete infoTimers[id];
    panel.hidden = true;
    btn.textContent = "Info";
    return;
  }

  panel.hidden = false;
  btn.textContent = "Hide Info";
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

function confirmSwitch(activeId, targetId) {
  return new Promise((resolve) => {
    const dialog = document.getElementById("conflict-dialog");
    document.getElementById("conflict-message").textContent =
      `${activeId} is currently running. Stop it and start ${targetId}?`;
    dialog.hidden = false;

    const confirmBtn = document.getElementById("conflict-confirm");
    const cancelBtn = document.getElementById("conflict-cancel");
    const cleanup = () => {
      dialog.hidden = true;
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
    };
    const onConfirm = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
  });
}

async function startGame(id) {
  const res = await callAPI(`/api/games/${id}/start`, { method: "POST" });
  if (res.status === 409) {
    const body = await res.json();
    if (await confirmSwitch(body.active_game, id)) {
      await callAPI(`/api/games/${id}/switch`, {
        method: "POST",
        body: JSON.stringify({ from: body.active_game }),
      });
    }
  }
  refreshStatuses();
}

async function stopGame(id) {
  await callAPI(`/api/games/${id}/stop`, { method: "POST" });
  refreshStatuses();
}

document.querySelectorAll(".game-card").forEach((card) => {
  const id = card.dataset.id;
  card.querySelector(".start-btn").addEventListener("click", () => startGame(id));
  card.querySelector(".stop-btn").addEventListener("click", () => stopGame(id));
  card.querySelector(".logs-btn").addEventListener("click", () => toggleLogs(id));
  card.querySelector(".stats-btn").addEventListener("click", () => toggleStats(id));
  card.querySelector(".info-btn").addEventListener("click", () => toggleInfo(id));

  const status = card.querySelector(".status").textContent.trim();
  if (status === "starting") startProgressTracking(id);
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
