const CSRF_TOKEN = window.CROWSNEST_CSRF;
const POLL_INTERVAL_MS = 5000;
const MAX_LOG_LINES = 300;

const logSources = {};
const progressSources = {};

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

async function refreshStatuses() {
  let res;
  try {
    res = await fetch("/api/games");
  } catch (err) {
    return; // transient network hiccup; next poll retries
  }
  if (!res.ok) return;
  const games = await res.json();
  games.forEach((g) => setStatus(g.id, g.status));
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
});

setInterval(refreshStatuses, POLL_INTERVAL_MS);
