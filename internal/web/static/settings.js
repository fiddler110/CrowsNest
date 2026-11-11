// Settings page: a sidebar of panes (General, Users, Game policy, Game modules). The pane is chosen by the URL hash.
// callAPI, errorText, toast and confirmAction come from api.js.
const $ = (id) => document.getElementById(id);

// ---------- navigation ----------
const loaded = {};
const loaders = {};
function showPane() {
  const want = (location.hash || "#general").slice(1);
  const name = document.querySelector(`.settings-pane[data-pane="${want}"]`) ? want : "general";
  document.querySelectorAll(".settings-pane").forEach((p) => { p.hidden = p.dataset.pane !== name; });
  document.querySelectorAll(".settings-nav a").forEach((a) => {
    if (a.dataset.pane === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  if (!loaded[name] && loaders[name]) { loaded[name] = true; loaders[name](); }
}
window.addEventListener("hashchange", showPane);

// ---------- General ----------
loaders.general = () => {
  const form = $("settings-form");
  const errorEl = $("settings-error");
  const fields = ["idle_enabled", "idle_minutes", "night_enabled", "night_start_hour",
    "night_end_hour", "max_active_games", "auto_update", "raw_console"];
  const input = (n) => form.elements[n];
  (async () => {
    const res = await callAPI("/api/settings");
    if (!res.ok) { toast(await errorText(res, "Loading settings"), "error"); return; }
    const v = await res.json();
    fields.forEach((n) => {
      if (input(n).type === "checkbox") input(n).checked = !!v[n]; else input(n).value = v[n];
    });
    renderPerGame(v);
    // tz is for display only; the body sent back is built from fields alone.
    if (v.tz) {
      $("night-tz").textContent = `Hours are in the server's time zone, ${v.tz}.`;
      $("night-tz").hidden = false;
    }
  })();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {};
    fields.forEach((n) => {
      body[n] = input(n).type === "checkbox" ? input(n).checked : parseInt(input(n).value, 10);
    });
    const res = await callAPI("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    if (!res.ok) { errorEl.textContent = await errorText(res); errorEl.hidden = false; return; }
    errorEl.hidden = true;
    toast("Settings saved.", "ok");
  });
};

// ---------- Per-game overrides (General pane) ----------
// One row per game; an empty box means "no override". The whole per_game map
// is sent on save, with null for games left entirely empty.
function renderPerGame(v) {
  const form = $("pergame-form");
  const list = $("pergame-list");
  const errorEl = $("pergame-error");
  const games = v.games || [];
  if (!games.length) return;
  form.hidden = false;
  const per = v.per_game || {};
  const numberField = (label, name, max, value, hint) => {
    const l = document.createElement("label");
    l.className = "field";
    l.append(label);
    const i = document.createElement("input");
    i.type = "number"; i.name = name; i.min = name === "idle_minutes" ? "1" : "0"; i.max = String(max);
    i.placeholder = hint;
    if (value != null) i.value = value;
    l.append(i);
    return l;
  };
  games.forEach((g) => {
    const o = per[g.id] || {};
    const fs = document.createElement("fieldset");
    fs.className = "pergame-row";
    fs.dataset.game = g.id;
    const lg = document.createElement("legend");
    lg.textContent = g.name || g.id;
    const row = document.createElement("div");
    row.className = "setting-row";
    row.append(
      numberField("Idle minutes", "idle_minutes", 1440, o.idle_minutes, `${v.idle_minutes} (global)`),
      numberField("Restart wait (seconds)", "restart_cooldown_seconds", 3600, o.restart_cooldown_seconds,
        `${g.restart_cooldown_seconds} (game default)`),
    );
    const night = document.createElement("label");
    night.className = "field";
    night.append("Overnight shutdown");
    const sel = document.createElement("select");
    sel.name = "night_shutdown";
    [["", `Default (${g.night_shutdown ? "included" : "left running"})`], ["true", "Included"], ["false", "Left running"]]
      .forEach(([val, text]) => { const op = new Option(text, val); sel.append(op); });
    sel.value = o.night_shutdown == null ? "" : String(o.night_shutdown);
    night.append(sel);
    row.append(night);
    fs.append(lg, row);
    list.append(fs);
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const per_game = {};
    list.querySelectorAll("fieldset").forEach((fs) => {
      const int = (n) => { const x = fs.querySelector(`[name=${n}]`).value; return x === "" ? null : parseInt(x, 10); };
      const ns = fs.querySelector("[name=night_shutdown]").value;
      const g = { idle_minutes: int("idle_minutes"), restart_cooldown_seconds: int("restart_cooldown_seconds"),
        night_shutdown: ns === "" ? null : ns === "true" };
      per_game[fs.dataset.game] = Object.values(g).every((x) => x === null) ? null : g;
    });
    const res = await callAPI("/api/settings", { method: "PUT", body: JSON.stringify({ per_game }) });
    if (!res.ok) { errorEl.textContent = await errorText(res); errorEl.hidden = false; return; }
    errorEl.hidden = true;
    toast("Per-game settings saved.", "ok");
  });
}

// ---------- Users ----------
loaders.users = () => {
  const list = $("users-list");
  const form = $("user-form");
  const errorEl = $("users-error");
  const title = $("user-form-title");
  const submit = $("user-form-submit");
  const cancelEdit = $("user-form-cancel");
  const pwLabel = $("user-pw-label");
  const googleField = $("user-google-field");
  let editing = null;
  let googleEnabled = false;
  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };

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
    const res = await callAPI(path, { method, body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) { showError(await errorText(res)); return null; }
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
            if (r) toast(`Signed ${u.username} out everywhere.`, "ok");
          }));
          actions.append(mk("Delete", async () => {
            const ok = await confirmAction({
              eyebrow: "// crew list",
              title: `Delete ${u.username}?`,
              message: "They are signed out everywhere and can no longer sign in. This can't be undone.",
              confirmLabel: "Delete user",
              danger: true,
            });
            if (!ok) return;
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "DELETE");
            if (r) { render(r); if (editing === u.username) resetForm(); }
          }, true));
        }
        li.append(actions);
      }
      list.append(li);
    });
  };

  (async () => {
    const res = await callAPI("/api/users");
    if (!res.ok) { toast(await errorText(res, "Loading users"), "error"); return; }
    const data = await res.json();
    googleEnabled = !!data.google_enabled;
    resetForm();
    render(data.users);
  })();
  cancelEdit.addEventListener("click", () => { form.elements.role.disabled = false; resetForm(); });
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
    toast(editing ? "User updated." : "User added.", "ok");
    resetForm();
  });
};

// ---------- Game policy ----------
loaders.policy = () => {
  const pf = $("policy-form");
  const listFields = ["names", "images", "networks", "ports"];
  let state = null;
  const setEditing = (on) => {
    [...pf.elements].forEach((f) => { if (f.name) f.disabled = !on; });
    syncHost();
    $("policy-edit").hidden = on || !(state && state.editable);
    $("policy-cancel").hidden = !on;
    $("policy-save").hidden = !on;
  };
  // Host addresses as three plain choices: any (an empty list in the file), this machine, or one address.
  const hostMode = () => (pf.querySelector("input[name=host_mode]:checked") || {}).value;
  const syncHost = () => { pf.elements.host_specific.disabled = pf.elements.host_specific.disabled || hostMode() !== "specific"; };
  pf.querySelectorAll("input[name=host_mode]").forEach((r) => r.addEventListener("change", () => {
    pf.elements.host_specific.disabled = hostMode() !== "specific";
    if (hostMode() === "specific") pf.elements.host_specific.focus();
  }));
  const hostIPs = () => {
    const m = hostMode();
    if (m === "local") return ["127.0.0.1"];
    if (m === "specific") return pf.elements.host_specific.value.split(/[\s,]+/).filter(Boolean);
    return [];
  };
  const fill = () => {
    const p = state.policy;
    const ips = p.host_ips || [];
    const mode = ips.length === 0 ? "any" : (ips.length === 1 && ips[0] === "127.0.0.1" ? "local" : "specific");
    pf.querySelectorAll("input[name=host_mode]").forEach((r) => { r.checked = r.value === mode; });
    pf.elements.host_specific.value = mode === "specific" ? ips.join(", ") : "";
    pf.elements.games_root.value = p.games_root;
    listFields.forEach((k) => { pf.elements[k].value = (p[k] || []).join("\n"); pf.elements[k].rows = Math.max(2, (p[k] || []).length); });
    pf.elements.max_scopes.value = p.max_scopes;
    pf.elements.exec.checked = !!p.exec;
    pf.elements.pin_digests.checked = !!p.pin_digests;
    $("policy-note").textContent = state.editable
      ? "What the panel may create when you add a game. You can tighten it here: remove entries or lower a limit. Saved changes apply within a few seconds, and a game that no longer fits is dropped by the guard. Adding entries or turning a limit off is done in policy.yaml on the host."
      : "What the panel may create when you add a game. It is read-only here on purpose: it lives in policy.yaml on the host, so a compromised panel cannot widen its own limits.";
    setEditing(false);
    const ex = p.exceptions || [];
    $("policy-exceptions").hidden = ex.length === 0;
    const exList = $("policy-exceptions-list");
    exList.replaceChildren();
    ex.forEach((e) => {
      const li = document.createElement("li");
      li.className = "user-row";
      const name = document.createElement("span");
      name.className = "user-name";
      name.textContent = e.name;
      const tags = document.createElement("span");
      tags.className = "user-tags";
      const nets = Object.entries(e.networks || {}).map(([n, a]) => (a && a.length ? `${n} (${a.join(", ")})` : n));
      tags.textContent = [e.image, nets.length ? "networks: " + nets.join(", ") : "", (e.secopts || []).length ? "security: " + e.secopts.join(", ") : ""]
        .filter(Boolean).join(" · ");
      li.append(name, tags);
      exList.append(li);
    });
  };
  (async () => {
    const res = await callAPI("/api/managed/policy");
    if (res.status === 404) { $("policy-off").hidden = false; pf.hidden = true; return; }
    if (!res.ok) { $("policy-note").textContent = "The policy could not be read: " + await errorText(res); return; }
    state = await res.json();
    fill();
  })();
  const lines = (v) => v.split("\n").map((x) => x.trim()).filter(Boolean);
  $("policy-edit").addEventListener("click", () => { $("policy-error").hidden = true; setEditing(true); });
  $("policy-cancel").addEventListener("click", () => { $("policy-error").hidden = true; fill(); });
  pf.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = { games_root: pf.elements.games_root.value.trim(), exec: pf.elements.exec.checked, pin_digests: pf.elements.pin_digests.checked,
      max_scopes: parseInt(pf.elements.max_scopes.value, 10) || 0 };
    listFields.forEach((k) => { body[k] = lines(pf.elements[k].value); });
    body.host_ips = hostIPs();
    if (hostMode() === "specific" && body.host_ips.length === 0) { $("policy-error").textContent = "Enter the address, or choose another option."; $("policy-error").hidden = false; return; }
    const res = await callAPI("/api/managed/policy", { method: "PUT", body: JSON.stringify(body) });
    if (!res.ok) { $("policy-error").textContent = await errorText(res); $("policy-error").hidden = false; return; }
    state = await res.json();
    fill();
    toast("Policy saved.", "ok");
  });
};

// ---------- Game modules ----------
loaders.modules = async () => {
  const list = $("modules-list");
  const res = await callAPI("/api/managed/modules");
  if (res.status === 404) { $("modules-off").hidden = false; return; }
  if (!res.ok) { toast(await errorText(res, "Loading modules"), "error"); return; }
  (await res.json()).forEach((m) => {
    const li = document.createElement("li");
    li.className = "user-row";
    // Each entry opens that game's card on the Games page.
    const name = document.createElement("a");
    name.className = "user-name module-link";
    name.href = `/games#module-${encodeURIComponent(m.id)}`;
    name.textContent = m.name;
    const tags = document.createElement("span");
    tags.className = "user-tags";
    let verdict;
    if (m.fits === true) verdict = "ready to add";
    else if (m.fits === false) verdict = "blocked by policy";
    else verdict = m.needs_image ? "you choose the image" : "";
    tags.textContent = [m.image || "", verdict, m.needs_exception ? "needs a policy exception" : ""].filter(Boolean).join(" · ");
    li.append(name, tags);
    if (m.fits === false && m.reason) {
      const why = document.createElement("small");
      why.className = "settings-help";
      why.textContent = m.reason;
      li.append(why);
    }
    list.append(li);
  });
};

showPane();
