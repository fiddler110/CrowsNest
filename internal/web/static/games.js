// Games page: fleet, catalogue, one-page setup form with a live summary, and an install progress view.
const CSRF_TOKEN = document.querySelector("meta[name=csrf-token]").content;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

let toastTimer;
function toast(message) {
  $("toast-text").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("toast").hidden = true; }, 6000);
}

function callAPI(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN, ...(options.headers || {}) },
  });
}

const form = $("setup");
let modules = [];
let games = [];
let selected = null; // module id
let editing = null; // game id while editing
let idTouched = false;
let previewTimer = null;
let previewSeq = 0;
let fitOK = false;
let installId = null;
let pollTimer = null;
let seenInstalling = {};

const moduleById = (id) => modules.find((m) => m.id === id);
const showError = (msg) => { $("form-error").textContent = msg; $("form-error").hidden = !msg; };
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").replace(/^[^a-z]+/, "").slice(0, 31);

// ---------- fleet ----------
function stateBadge(state) {
  const b = el("span", "status status-" + (state === "ready" ? "online" : state === "failed" ? "unknown" : "starting"));
  b.append(el("i", "beacon"), el("span", "status-text", state === "installing" ? "installing…" : state));
  return b;
}

function fleetCard(title, sub, badge) {
  const c = el("article", "fleet-card");
  const head = el("div", "fleet-head");
  head.append(el("div", "emblem", (title[0] || "?").toUpperCase()));
  const t = el("div", "fleet-title");
  t.append(el("h3", "", title), el("p", "fleet-sub", sub));
  head.append(t);
  if (badge) head.append(badge);
  c.append(head);
  return c;
}

function renderFleet(configured) {
  const root = $("fleet");
  root.replaceChildren();
  games.forEach((g) => {
    const m = moduleById(g.module);
    const c = fleetCard(g.display_name || g.id, `${m ? m.name : g.module} · added here`, stateBadge(g.state));
    if (g.state === "failed" && g.error) c.append(el("p", "settings-error", g.error.slice(-300)));
    const row = el("div", "fleet-actions");
    const busy = g.state === "installing";
    const edit = el("button", "btn btn-ghost", "Settings");
    edit.type = "button"; edit.disabled = busy;
    edit.addEventListener("click", () => startEdit(g));
    const upd = el("button", "btn btn-ghost", "Update image");
    upd.type = "button"; upd.disabled = busy;
    upd.addEventListener("click", async () => {
      upd.disabled = true;
      const res = await callAPI(`/api/managed/games/${g.id}/refresh`, { method: "POST" });
      if (!res.ok) toast((await res.text()).trim()); else toast(`${g.display_name || g.id}: pulling the latest image…`);
      await loadGames();
    });
    const del = el("button", "btn btn-danger", "Disable");
    del.type = "button"; del.disabled = busy;
    del.addEventListener("click", async () => {
      if (!confirm(`Disable ${g.display_name || g.id}? The container is removed; its data folder is kept.`)) return;
      del.disabled = true;
      const res = await callAPI(`/api/managed/games/${g.id}`, { method: "DELETE" });
      if (!res.ok) { toast((await res.text()).trim()); del.disabled = false; return; }
      toast(`${g.display_name || g.id} disabled.`);
      await loadGames();
    });
    row.append(edit, upd, del);
    c.append(row);
    root.append(c);
  });
  configured.forEach((g) => {
    const c = fleetCard(g.display_name || g.id, [g.container, g.connect_address].filter(Boolean).join(" · "),
      el("span", "tag", "set in files"));
    root.append(c);
  });
  if (!root.children.length) root.append(el("p", "empty", "No games yet. Choose one below."));
}

async function loadGames() {
  const [gr, cr] = await Promise.all([callAPI("/api/managed/games"), callAPI("/api/managed/configured")]);
  if (gr.ok) games = await gr.json();
  const configured = cr.ok ? await cr.json() : [];
  // A game that was installing and is now ready or failed finishes the progress view.
  games.forEach((g) => {
    if (g.state === "installing") seenInstalling[g.id] = true;
  });
  renderFleet(configured);
  if (installId) updateProgress();
  if (games.some((g) => g.state === "installing")) schedulePoll(); else stopPoll();
}

const schedulePoll = () => { if (!pollTimer) pollTimer = setInterval(loadGames, 2000); };
const stopPoll = () => { clearInterval(pollTimer); pollTimer = null; };

// ---------- catalogue ----------
function renderCatalogue() {
  const root = $("catalogue");
  root.replaceChildren();
  modules.forEach((m) => {
    const b = el("button", "pick");
    b.type = "button";
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(m.id === selected));
    b.dataset.module = m.id;
    const blocked = m.fits === false;
    b.append(el("span", "pick-name", m.name || m.id));
    if (m.description) b.append(el("span", "pick-desc", m.description));
    const meta = [m.image, (m.ports || []).join(", ")].filter(Boolean).join(" · ");
    if (meta) b.append(el("span", "pick-meta", meta));
    if (m.fits !== undefined && m.fits !== null) {
      b.append(el("span", "pick-badge " + (m.fits ? "ok" : "no"), m.fits ? "Allowed by policy" : "Not allowed by policy"));
    }
    if (m.fits && m.fit_id) b.append(el("span", "pick-meta", `Use an id the policy allows, such as ${m.fit_id}.`));
    if (blocked && m.reason) b.append(el("span", "pick-reason", m.reason));
    b.addEventListener("click", () => choose(m.id));
    root.append(b);
  });
}

function choose(id) {
  if (editing) return;
  selected = id;
  renderCatalogue();
  form.elements.connect_address.value = "";
  buildForm();
  form.hidden = false;
  $("progress").hidden = true;
  schedulePreview();
  $("setup").scrollIntoView({ behavior: "smooth", block: "nearest" });
  form.elements.display_name.focus();
}

// ---------- form ----------
function buildForm(values = {}) {
  const m = moduleById(selected);
  $("image-field").hidden = !(m && m.needs_image);
  form.elements.image.required = !!(m && m.needs_image);
  $("options").replaceChildren();
  $("options-more").replaceChildren();
  if (!m) return;
  // Settings that need an answer (required or secret) come first; the rest sit under "More settings".
  const opts = (m.options || []).filter((o) => o.key !== "image");
  const main = opts.filter((o) => !o.auto && (o.required || o.secret || /eula/i.test(o.key)));
  const more = opts.filter((o) => !main.includes(o));
  const addTo = (root, o) => {
    const label = el("label", "field");
    label.append(document.createTextNode(o.label || o.key));
    const input = document.createElement("input");
    input.name = "opt:" + o.key;
    input.type = o.secret ? "password" : "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    if (o.secret) {
      input.placeholder = editing ? "leave empty to keep the current value" : "";
      input.required = !!o.required && !editing;
    } else if (o.auto) {
      // Wiring that follows from the game itself: left empty, it is filled in automatically.
      input.value = values[o.key] !== undefined ? values[o.key] : "";
      input.placeholder = "automatic";
    } else {
      input.value = values[o.key] !== undefined ? values[o.key] : (o.default || "");
      input.required = !!o.required;
    }
    label.append(input);
    root.append(label);
  };
  main.forEach((o) => addTo($("options"), o));
  more.forEach((o) => addTo($("options-more"), o));
  const connect = form.elements.connect_address;
  connect.placeholder = m.connect_hint ? `e.g. ${m.connect_hint}` : "e.g. 10.0.0.2:25565";
  if (!editing && m.connect_hint && !connect.value) connect.value = m.connect_hint;
  $("more").hidden = !more.length;
  $("options").hidden = !main.length;
}

function collect() {
  const m = moduleById(selected) || { options: [] };
  const req = {
    id: form.elements.id.value.trim(),
    module: selected,
    display_name: form.elements.display_name.value.trim(),
    connect_address: form.elements.connect_address.value.trim(),
    options: {}, secrets: {},
  };
  if (m.needs_image && form.elements.image.value.trim()) req.options.image = form.elements.image.value.trim();
  (m.options || []).forEach((o) => {
    const f = form.elements["opt:" + o.key];
    if (!f) return;
    const v = f.value.trim();
    if (o.secret) { if (v) req.secrets[o.key] = v; } else if (v !== "") req.options[o.key] = v;
  });
  return req;
}

form.addEventListener("input", (e) => {
  if (e.target === form.elements.id) idTouched = true;
  if (e.target === form.elements.display_name && !idTouched && !editing) form.elements.id.value = slug(e.target.value);
  schedulePreview();
});

// ---------- live summary ----------
function schedulePreview() {
  clearTimeout(previewTimer);
  fitOK = false;
  $("enable").disabled = true;
  previewTimer = setTimeout(runPreview, 350);
}

function sumRow(dl, label, values) {
  if (!values || !values.length) return;
  dl.append(el("dt", "", label));
  const dd = el("dd");
  values.forEach((v) => dd.append(el("div", "", v)));
  dl.append(dd);
}

async function runPreview() {
  const m = moduleById(selected);
  const dl = $("sum-list");
  $("sum-title").textContent = m ? (form.elements.display_name.value.trim() || m.name) : "Pick a game";
  if (!m) return;
  showError("");
  const seq = ++previewSeq;
  const req = collect();
  const res = await callAPI("/api/managed/preview", { method: "POST", body: JSON.stringify(req) });
  if (seq !== previewSeq) return; // a newer keystroke superseded this one
  dl.replaceChildren();
  $("tech").hidden = true;
  if (!res.ok) {
    const msg = (await res.text()).trim();
    $("sum-status").className = "sum-status wait";
    $("sum-status").textContent = "Almost there: " + msg;
    sumRow(dl, "Image", m.needs_image ? [] : [m.image]);
    sumRow(dl, "Ports", m.ports);
    return;
  }
  const p = await res.json();
  fitOK = !!p.fits;
  $("sum-status").className = "sum-status " + (p.fits ? "ok" : "no");
  $("sum-status").textContent = p.fits ? "✓ Allowed by the operator's policy" : "✗ Outside the policy: " + (p.reason || "not allowed");
  sumRow(dl, "Container", [p.container]);
  sumRow(dl, "Image", [p.image]);
  sumRow(dl, "Ports", p.ports);
  sumRow(dl, "Data folder", p.folders);
  sumRow(dl, "Memory limit", p.memory ? [p.memory] : []);
  $("tech-service").textContent = p.service || "";
  $("tech-scope").textContent = p.scope || "";
  $("tech").hidden = false;
  $("enable").disabled = !fitOK;
}

// ---------- enable / edit ----------
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!fitOK) return;
  showError("");
  const req = collect();
  $("enable").disabled = true;
  const res = editing
    ? await callAPI(`/api/managed/games/${editing}`, { method: "PUT", body: JSON.stringify(req) })
    : await callAPI("/api/managed/games", { method: "POST", body: JSON.stringify(req) });
  if (!res.ok) { showError((await res.text()).trim()); $("enable").disabled = false; return; }
  installId = req.id;
  seenInstalling[req.id] = true;
  showProgress(editing ? "Applying your changes…" : `Setting up ${req.display_name || req.id}…`);
  await loadGames();
});

function showProgress(title) {
  form.hidden = true;
  $("progress").hidden = false;
  $("progress-title").textContent = title;
  $("progress-error").hidden = true;
  $("progress-done").hidden = true;
  $("progress-again").hidden = true;
  $("progress-bar").className = "progress-bar progress-indeterminate";
  document.querySelectorAll("#progress-steps li").forEach((li) => {
    li.className = li.dataset.step === "record" ? "done" : li.dataset.step === "install" ? "active" : "";
  });
  $("progress").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function updateProgress() {
  const g = games.find((x) => x.id === installId);
  if (!g || g.state === "installing") return;
  const steps = document.querySelectorAll("#progress-steps li");
  if (g.state === "ready") {
    steps.forEach((li) => { li.className = "done"; });
    $("progress-title").textContent = `${g.display_name || g.id} is ready`;
    $("progress-bar").className = "progress-bar progress-full";
    $("progress-done").hidden = false;
  } else {
    steps.forEach((li) => { if (li.dataset.step !== "record") li.className = li.dataset.step === "install" ? "failed" : ""; });
    $("progress-title").textContent = `${g.display_name || g.id} could not be set up`;
    $("progress-bar").className = "progress-bar progress-failed";
    $("progress-error").textContent = g.error || "The install failed. See the panel logs.";
    $("progress-error").hidden = false;
    $("progress-again").hidden = false;
  }
  installId = null;
}

$("progress-again").addEventListener("click", () => {
  $("progress").hidden = true;
  form.hidden = !selected;
  schedulePreview();
});

function startEdit(g) {
  editing = g.id;
  selected = g.module;
  idTouched = true;
  renderCatalogue();
  document.querySelectorAll(".pick").forEach((b) => { b.disabled = true; });
  form.reset();
  buildForm(g.options || {});
  form.elements.display_name.value = g.display_name || "";
  form.elements.id.value = g.id;
  form.elements.id.readOnly = true;
  form.elements.connect_address.value = g.connect_address || "";
  if (g.options && g.options.image) form.elements.image.value = g.options.image;
  $("basics-title").textContent = `Settings for ${g.display_name || g.id}`;
  $("enable").textContent = "Save and recreate";
  $("cancel-edit").hidden = false;
  form.hidden = false;
  $("progress").hidden = true;
  schedulePreview();
  form.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("cancel-edit").addEventListener("click", () => {
  editing = null;
  selected = null;
  form.hidden = true;
  form.elements.id.readOnly = false;
  $("basics-title").textContent = "Name it";
  $("enable").textContent = "Enable";
  $("cancel-edit").hidden = true;
  renderCatalogue();
});

// ---------- policy ----------
const pf = $("policy-form");
const listFields = ["names", "images", "networks", "ports", "host_ips"];
let policyState = null;
const setPolicyEditing = (on) => {
  [...pf.elements].forEach((f) => { if (f.name) f.disabled = !on; });
  $("policy-edit").hidden = on || !(policyState && policyState.editable);
  $("policy-cancel").hidden = !on;
  $("policy-save").hidden = !on;
};
function fillPolicy() {
  const p = policyState.policy;
  pf.elements.games_root.value = p.games_root;
  listFields.forEach((k) => { const v = (p[k] || []).join("\n"); pf.elements[k].value = v; pf.elements[k].rows = Math.max(2, (p[k] || []).length); });
  pf.elements.max_scopes.value = p.max_scopes;
  pf.elements.exec.checked = !!p.exec;
  $("policy-note").textContent = policyState.editable
    ? "What this panel is allowed to create. Saved changes apply within a few seconds, and a game that no longer fits is dropped by the guard."
    : "What this panel is allowed to create. It is read-only here on purpose: it is edited in policy.yaml on the host, so a compromised panel cannot widen its own limits.";
  setPolicyEditing(false);
}
async function loadPolicy() {
  const res = await callAPI("/api/managed/policy");
  if (!res.ok) { $("policy-note").textContent = "The policy could not be read: " + (await res.text()).trim(); return; }
  policyState = await res.json();
  fillPolicy();
}
const lines = (v) => v.split("\n").map((x) => x.trim()).filter(Boolean);
$("policy-edit").addEventListener("click", () => { $("policy-error").hidden = true; setPolicyEditing(true); });
$("policy-cancel").addEventListener("click", () => { $("policy-error").hidden = true; fillPolicy(); });
pf.addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = { games_root: pf.elements.games_root.value.trim(), exec: pf.elements.exec.checked,
    max_scopes: parseInt(pf.elements.max_scopes.value, 10) || 0 };
  listFields.forEach((k) => { body[k] = lines(pf.elements[k].value); });
  const res = await callAPI("/api/managed/policy", { method: "PUT", body: JSON.stringify(body) });
  if (!res.ok) { $("policy-error").textContent = (await res.text()).trim(); $("policy-error").hidden = false; return; }
  policyState = await res.json();
  fillPolicy();
  toast("Policy saved.");
  const mres = await callAPI("/api/managed/modules");
  if (mres.ok) { modules = await mres.json(); renderCatalogue(); if (selected) schedulePreview(); }
});

// ---------- start ----------
(async () => {
  const mres = await callAPI("/api/managed/modules");
  if (mres.status === 404) {
    $("games-off").hidden = false;
    $("setup-section").hidden = true;
    return;
  }
  if (mres.status === 401) { window.location.href = "/login"; return; }
  if (mres.ok) modules = await mres.json();
  renderCatalogue();
  await loadGames();
  await loadPolicy();
})();
