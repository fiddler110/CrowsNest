// Games page: fleet, catalogue, one-page setup form with a live summary, and an install progress view.
// callAPI, errorText, toast and confirmAction come from api.js.
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

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
const pendingImage = {}; // game id -> "refresh" | "rollback", reported once the game settles

const moduleById = (id) => modules.find((m) => m.id === id);
const showError = (msg) => { $("form-error").textContent = msg; $("form-error").hidden = !msg; };
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").replace(/^[^a-z]+/, "").slice(0, 31);

// ---------- fleet ----------
const shortDigest = (d) => (d || "").replace(/^sha256:/, "").slice(0, 12);

// The image line of a card: the tag it follows and the exact image (digest) it runs.
function imageLine(g) {
  const p = el("p", "fleet-image");
  if (g.image) p.append(el("span", "fleet-image-tag", g.image));
  if (g.digest) {
    const d = el("code", "fleet-digest", shortDigest(g.digest));
    d.title = g.digest;
    p.append(d);
  } else if (g.state !== "installing") {
    p.append(el("span", "fleet-image-note", "not pinned yet: Update image pins it"));
  }
  return p;
}

// reportImage tells the outcome of an Update image or Roll back once the game has settled.
function reportImage(g) {
  const kind = pendingImage[g.id];
  if (!kind || g.state === "installing") return;
  delete pendingImage[g.id];
  const name = g.display_name || g.id;
  if (g.state === "failed") { toast(`${name}: ${g.error || "the image change failed"}`, "error"); return; }
  if (kind === "rollback") toast(`${name} rolled back to ${shortDigest(g.digest)}.`, "ok");
  else if (g.refresh === "up_to_date") toast(`${name} is already up to date.`, "info");
  else toast(`${name} updated${g.digest ? " to " + shortDigest(g.digest) : ""}.`, "ok");
}

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
    c.append(imageLine(g));
    if (g.state === "failed" && g.error) c.append(el("p", "settings-error", g.error.slice(-300)));
    const row = el("div", "fleet-actions");
    const busy = g.state === "installing";
    const edit = el("button", "btn btn-ghost", "Settings");
    edit.type = "button"; edit.disabled = busy;
    edit.addEventListener("click", () => startEdit(g));
    const upd = el("button", "btn btn-ghost", "Update image");
    upd.type = "button"; upd.disabled = busy;
    upd.addEventListener("click", async () => {
      const name = g.display_name || g.id;
      const ok = await confirmAction({
        eyebrow: "// refit",
        title: `Update ${name}?`,
        message: `This pulls ${g.image || "the image"} again. If it points to a new image, the container is recreated on it (the game must be stopped; the data folder is kept) and the current image is kept for Roll back. If nothing changed, the container is left alone.`,
        confirmLabel: "Update image",
      });
      if (!ok) return;
      upd.disabled = true;
      const res = await callAPI(`/api/managed/games/${encodeURIComponent(g.id)}/refresh`, { method: "POST" });
      if (!res.ok) toast(await errorText(res, "Update"), "error");
      else { pendingImage[g.id] = "refresh"; toast(`${name}: checking for a new image…`, "info"); }
      await loadGames();
    });
    const back = el("button", "btn btn-ghost", "Roll back");
    back.type = "button"; back.disabled = busy;
    back.hidden = !g.previous_digest;
    back.addEventListener("click", async () => {
      const name = g.display_name || g.id;
      const ok = await confirmAction({
        eyebrow: "// roll back",
        title: `Roll ${name} back?`,
        message: `The container is recreated on the image it ran before (${shortDigest(g.previous_digest)} instead of ${shortDigest(g.digest)}). The game must be stopped; the data folder is kept, but a world already saved by the newer version may not load in the older one. Rolling back again returns to the current image.`,
        confirmLabel: "Roll back",
      });
      if (!ok) return;
      back.disabled = true;
      const res = await callAPI(`/api/managed/games/${encodeURIComponent(g.id)}/rollback`, { method: "POST" });
      if (!res.ok) { toast(await errorText(res, "Roll back"), "error"); back.disabled = false; return; }
      pendingImage[g.id] = "rollback";
      toast(`${name}: rolling back…`, "info");
      await loadGames();
    });
    const del = el("button", "btn btn-danger", "Disable");
    del.type = "button"; del.disabled = busy;
    del.addEventListener("click", async () => {
      const name = g.display_name || g.id;
      const ok = await confirmAction({
        eyebrow: "// decommission",
        title: `Disable ${name}?`,
        message: "The container is removed and the game leaves the dashboard. Its data folders and backups are kept, so it can be enabled again later. To delete them too, use \u201cDisable and delete…\u201d.",
        confirmLabel: "Disable",
        danger: true,
      });
      if (!ok) return;
      del.disabled = true;
      const res = await callAPI(`/api/managed/games/${encodeURIComponent(g.id)}`, { method: "DELETE" });
      if (!res.ok) { toast(await errorText(res, "Disable"), "error"); del.disabled = false; return; }
      toast(`${name} disabled.`, "ok");
      await loadGames();
    });
    const wipe = el("button", "btn btn-danger", "Disable and delete…");
    wipe.type = "button"; wipe.disabled = busy;
    const form = el("div", "wipe-form");
    form.hidden = true;
    wipe.addEventListener("click", () => { form.hidden = !form.hidden; });
    buildWipeForm(form, g, wipe);
    row.append(edit, upd, back, del, wipe);
    c.append(row, form);
    root.append(c);
  });
  configured.forEach((g) => {
    const c = fleetCard(g.display_name || g.id, [g.container, g.connect || g.connect_address].filter(Boolean).join(" · "),
      el("span", "tag", "set in files"));
    root.append(c);
  });
  if (!root.children.length) root.append(el("p", "empty", "No games yet. Choose one below."));
}

async function loadGames() {
  let gr, cr;
  try {
    [gr, cr] = await Promise.all([callAPI("/api/managed/games"), callAPI("/api/managed/configured")]);
  } catch (err) {
    return; // transient; the install poll (if any) retries
  }
  if (gr.status === 401) { window.location.href = "/login"; return; }
  if (gr.ok) games = await gr.json();
  const configured = cr.ok ? await cr.json() : [];
  // A game that was installing and is now ready or failed finishes the progress view.
  games.forEach((g) => {
    if (g.state === "installing") seenInstalling[g.id] = true;
    reportImage(g);
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
    b.id = `module-${m.id}`;
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(m.id === selected));
    b.dataset.module = m.id;
    const blocked = m.fits === false;
    b.append(el("span", "pick-name", m.name || m.id));
    if (m.description) b.append(el("span", "pick-desc", m.description));
    const meta = [m.image, (m.ports || []).join(", ")].filter(Boolean).join(" · ");
    if (meta) b.append(el("span", "pick-meta", meta));
    if (m.fits !== undefined && m.fits !== null) {
      b.append(el("span", "pick-badge " + (m.fits ? "ok" : "no"), m.fits ? "Allowed by policy" : m.needs_exception ? "Needs a policy exception" : m.bundled && !m.allowed ? "Switch it on below to use it" : "Not allowed by policy"));
    }
    if (m.fits && m.fit_id) b.append(el("span", "pick-meta", `Use an id the policy allows, such as ${m.fit_id}.`));
    if (blocked && m.reason) b.append(el("span", "pick-reason", m.reason));
    b.addEventListener("click", () => choose(m.id));
    const wrap = el("div", "pick-wrap");
    wrap.append(b, allowBar(m));
    root.append(wrap);
  });
}

// Under each card: the ports the game publishes and why, and the switch that lets the guard accept them.
function allowBar(m) {
  const bar = el("div", "allow-bar");
  if ((m.port_notes || []).length) {
    const ul = el("ul", "port-notes");
    m.port_notes.forEach((p) => {
      const li = el("li");
      li.append(el("code", "", p.port), document.createTextNode(p.why ? " " + p.why : ""));
      ul.append(li);
    });
    bar.append(ul);
  }
  if (!m.bundled && !m.gated) {
    if (m.ports && m.ports.length) bar.append(el("p", "allow-note", "Its ports are allowed in policy.yaml on the host."));
    return bar;
  }
  const label = el("label", "allow-switch");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !!m.allowed;
  box.setAttribute("role", "switch");
  label.append(box, el("span", "", m.allowed ? "Allowed" : "Not allowed yet"));
  bar.append(label);
  const ask = el("form", "allow-ask");
  ask.hidden = true;
  ask.autocomplete = "off";
  const pw = document.createElement("input");
  pw.type = "password";
  pw.placeholder = "Your password";
  pw.autocomplete = "current-password";
  const ok = el("button", "btn btn-primary", "Allow");
  ok.type = "submit";
  const no = el("button", "btn btn-ghost", "Cancel");
  no.type = "button";
  const err = el("p", "settings-error");
  err.hidden = true;
  ask.append(el("p", "allow-note", m.gated ? "Switching it on lets the dashboard offer this game. Enter your password to confirm." : "Allowing a game lets the guard accept its ports. Enter your password to confirm."), pw, ok, no, err);
  bar.append(ask);
  if (m.gated) {
    const d = el("details", "allow-policy");
    d.append(el("summary", "", "Also needed in policy.yaml"));
    d.append(el("p", "allow-note", "This module was installed, so the guard does not take its image or ports from it. Add these on the host:"));
    d.append(el("pre", "", m.policy_lines || "(nothing: it needs no image or ports)"));
    bar.append(d);
  }
  const send = async (allowed, password) => {
    const res = await callAPI(`/api/managed/modules/${encodeURIComponent(m.id)}/allow`, { method: "PUT", body: JSON.stringify({ allowed, password }) });
    if (!res.ok) return errorText(res);
    return "";
  };
  box.addEventListener("change", async () => {
    err.hidden = true;
    if (box.checked) { ask.hidden = false; pw.focus(); return; }
    ask.hidden = true;
    const msg = await send(false, "");
    if (msg) { box.checked = true; toast(msg, "error"); return; }
    await reloadModules();
  });
  no.addEventListener("click", () => { ask.hidden = true; box.checked = false; pw.value = ""; });
  ask.addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = await send(true, pw.value);
    pw.value = "";
    if (msg) { err.textContent = msg; err.hidden = false; return; }
    toast(`${m.name || m.id} allowed.`, "ok");
    await reloadModules();
  });
  return bar;
}

async function reloadModules() {
  const res = await callAPI("/api/managed/modules");
  if (res.ok) { modules = await res.json(); renderCatalogue(); if (selected && !editing) schedulePreview(); }
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
  // Every game has these two; they are what keeps two servers of one game apart.
  const have = new Set(opts.map((o) => o.key));
  [
    ["data_dir", "Data folder name", "automatic (one folder per game)"],
    ["ports", "Published ports (host:container/proto, comma-separated)", "automatic (the game's defaults)"],
    ["ram", "Memory the game needs (for example 6g)", "automatic (the module's figure, then the measured peak)"],
  ].forEach(([key, label, hint]) => {
    if (have.has(key)) return;
    addTo($("options-more"), { key, label, auto: true });
    const f = form.elements["opt:" + key];
    if (f) f.placeholder = hint;
  });
  const first = firstPort(m);
  $("port-field").hidden = !first; // a game on its own LAN address (Windrose) publishes no host port
  form.elements.game_port.placeholder = first ? `${first.port} (the standard port)` : "";
  $("more").hidden = false;
  $("options").hidden = !main.length;
}

// firstPort is the module's main game port (the first it publishes), from "8211/udp" style entries.
function firstPort(m) {
  const list = portsOf(m);
  return list.length ? list[0] : null;
}

function portsOf(m) {
  return (m.ports || []).map((p) => {
    const [num, proto] = String(p).split("/");
    return { port: parseInt(num, 10), proto: proto || "udp" };
  }).filter((p) => p.port > 0);
}

// publishedPorts turns the one "Game port" the person chose into the full host:container/proto list. The
// module's other ports keep their distance from the first, so a pair like Valheim's 2456 and 2457 stays a pair.
function publishedPorts(m, chosen) {
  const list = portsOf(m);
  if (!list.length || !chosen || chosen === list[0].port) return "";
  return list.map((p) => `${chosen + (p.port - list[0].port)}:${p.port}/${p.proto}`).join(",");
}

// chosenPort reads the host port back out of a saved ports option, for the edit form.
function chosenPort(m, spec) {
  const list = portsOf(m);
  if (!spec || !list.length) return "";
  const host = parseInt(String(spec).split(",")[0].split(":").slice(-2, -1)[0] || String(spec).split(":")[0], 10);
  return host > 0 && host !== list[0].port && publishedPorts(m, host) === spec ? String(host) : "";
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
  [...(m.options || []), { key: "data_dir" }, { key: "ports" }, { key: "ram" }].forEach((o) => {
    const f = form.elements["opt:" + o.key];
    if (!f) return;
    const v = f.value.trim();
    if (o.secret) { if (v) req.secrets[o.key] = v; } else if (v !== "") req.options[o.key] = v;
  });
  // The "Game port" box fills the ports option, unless the ports were typed under More settings.
  if (!req.options.ports) {
    const chosen = parseInt(form.elements.game_port.value, 10);
    const spec = publishedPorts(m, chosen);
    if (spec) req.options.ports = spec;
  }
  return req;
}

form.addEventListener("input", (e) => {
  if (e.target === form.elements.id) idTouched = true;
  if (e.target === form.elements.game_port && form.elements["opt:ports"]) form.elements["opt:ports"].value = ""; // the simple box takes over
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
    const msg = await errorText(res);
    $("sum-status").className = "sum-status wait";
    $("sum-status").textContent = "Almost there: " + msg;
    sumRow(dl, "Image", m.needs_image ? [] : [m.image]);
    sumRow(dl, "Ports", m.ports);
    renderSetup([]);
    return;
  }
  const p = await res.json();
  fitOK = !!p.fits;
  $("sum-status").className = "sum-status " + (p.fits ? "ok" : "no");
  $("sum-status").textContent = p.fits ? "✓ Allowed by the operator's policy" : "✗ Outside the policy: " + (p.reason || "not allowed");
  sumRow(dl, "Container", [p.container]);
  sumRow(dl, "Image", [p.image, p.pinning ? "pinned by digest when installed" : ""].filter(Boolean));
  sumRow(dl, "Players connect to", p.connect ? [p.connect] : []);
  sumRow(dl, "Ports", p.ports);
  sumRow(dl, "Data folder", p.folders);
  sumRow(dl, "Memory limit", p.memory ? [p.memory] : []);
  renderSetup(p.setup || []);
  $("tech-service").textContent = p.service || "";
  $("tech-scope").textContent = p.scope || "";
  $("tech").hidden = false;
  $("enable").disabled = !fitOK;
}

// Host-side steps the dashboard cannot do for the operator (policy exception, network, firewall).
function renderSetup(steps) {
  $("host-setup").hidden = steps.length === 0;
  const ol = $("host-setup-list");
  ol.replaceChildren();
  steps.forEach((st) => {
    const li = el("li", st.done ? "setup-step done" : "setup-step");
    li.append(el("strong", "", (st.done ? "✓ " : "") + st.title));
    if (st.detail) li.append(el("p", "settings-help", st.detail));
    if (st.command) {
      const pre = el("pre", "", st.command);
      const copy = el("button", "btn btn-ghost", "Copy");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(st.command); copy.textContent = "Copied"; } catch { copy.textContent = "Select and copy"; }
        setTimeout(() => { copy.textContent = "Copy"; }, 2000);
      });
      li.append(pre, copy);
    }
    ol.append(li);
  });
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
  if (!res.ok) { showError(await errorText(res)); $("enable").disabled = false; return; }
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
  // A ports option that is just a different first port shows in the simple "Game port" box, not twice.
  const gp = chosenPort(moduleById(g.module), (g.options || {}).ports);
  if (gp) {
    form.elements.game_port.value = gp;
    const adv = form.elements["opt:ports"];
    if (adv) adv.value = "";
  }
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

// ---------- start ----------
(async () => {
  const mres = await callAPI("/api/managed/modules");
  if (mres.status === 404) {
    $("games-off").hidden = false;
    $("setup-section").hidden = true;
    return;
  }
  if (mres.ok) modules = await mres.json();
  else { toast(await errorText(mres, "Loading the games"), "error"); return; }
  renderCatalogue();
  await loadGames();
  selectFromHash();
})();

// /games#module-<id> (linked from Settings → Game modules) picks that game.
function selectFromHash() {
  const m = /^#module-(.+)$/.exec(location.hash);
  if (!m || editing || !moduleById(decodeURIComponent(m[1]))) return;
  const id = decodeURIComponent(m[1]);
  choose(id);
  const card = document.getElementById(`module-${id}`);
  if (card) card.scrollIntoView({ behavior: "smooth", block: "start" });
}
window.addEventListener("hashchange", selectFromHash);

// buildWipeForm fills the inline "Disable and delete" form of one game: two
// separate ticks (data folders, backups), the game's id typed out, and the
// admin's password. Nothing is deleted without all of them.
function buildWipeForm(form, g, toggle) {
  const name = g.display_name || g.id;
  const tick = (label) => {
    const l = el("label", "wipe-tick");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    l.append(cb, document.createTextNode(" " + label));
    return [l, cb];
  };
  const [dataL, dataCB] = tick("Delete its data folders (the world, configs and everything else the game saved)");
  const [bakL, bakCB] = tick("Delete its backups too (without them a deleted world cannot be restored)");
  const id = document.createElement("input");
  id.type = "text"; id.placeholder = `Type ${g.id} to confirm`; id.autocomplete = "off";
  const pw = document.createElement("input");
  pw.type = "password"; pw.placeholder = "Your password"; pw.autocomplete = "current-password";
  const go = el("button", "btn btn-danger", "Disable and delete");
  go.type = "button";
  const no = el("button", "btn btn-ghost", "Cancel");
  no.type = "button";
  const err = el("p", "settings-error");
  err.hidden = true;
  no.addEventListener("click", () => { form.hidden = true; });
  go.addEventListener("click", async () => {
    err.hidden = true;
    if (!dataCB.checked && !bakCB.checked) { err.textContent = "Tick what to delete, or use plain Disable."; err.hidden = false; return; }
    go.disabled = true;
    const res = await callAPI(`/api/managed/games/${encodeURIComponent(g.id)}`, {
      method: "DELETE",
      body: JSON.stringify({ delete_data: dataCB.checked, delete_backups: bakCB.checked, confirm_id: id.value.trim(), password: pw.value }),
    });
    go.disabled = false;
    pw.value = "";
    if (!res.ok) { err.textContent = await errorText(res, "Disable"); err.hidden = false; return; }
    toast(`${name} disabled and its data deleted.`, "ok");
    await loadGames();
  });
  form.append(
    el("p", "allow-note", "The game must be stopped. This cannot be undone."),
    dataL, bakL, id, pw, go, no, err);
  toggle.setAttribute("aria-expanded", "false");
}
