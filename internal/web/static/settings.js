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
    "night_end_hour", "max_active_games", "auto_update", "raw_console", "require_admin_mfa"];
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

// ---------- Schedule ----------
loaders.schedule = async () => {
  const rows = $("schedule-rows");
  const errorEl = $("schedule-error");
  const fail = (m) => { errorEl.textContent = m; errorEl.hidden = !m; };
  const [sres, gres] = await Promise.all([callAPI("/api/schedules"), callAPI("/api/settings")]);
  if (!sres.ok) { toast(await errorText(sres, "Loading schedules"), "error"); return; }
  const sv = await sres.json();
  const games = gres.ok ? ((await gres.json()).games || []) : [];
  $("schedule-tz").textContent = sv.tz || "UTC";
  const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
  const refreshNone = () => { $("schedule-none").hidden = rows.children.length > 0; };
  const addRow = (e) => {
    const row = el("div", { className: "setting-row schedule-row" });
    row.dataset.id = e.id;
    const game = el("select", { name: "game" }, ...games.map((g) => el("option", { value: g.id, textContent: g.name || g.id })));
    game.value = e.game;
    const action = el("select", { name: "action" }, el("option", { value: "start", textContent: "Start" }), el("option", { value: "stop", textContent: "Stop" }));
    action.value = e.action;
    const time = el("input", { type: "time", name: "time", value: e.time, required: true });
    const days = el("span", { className: "schedule-days" });
    dayNames.forEach((n, i) => {
      const cb = el("input", { type: "checkbox", value: String(i), checked: (e.days || []).includes(i) });
      days.append(el("label", {}, cb, " " + n + " "));
    });
    const empty = el("input", { type: "checkbox", name: "only_if_empty", checked: !!e.only_if_empty });
    const enabled = el("input", { type: "checkbox", name: "enabled", checked: e.enabled !== false });
    const remove = el("button", { type: "button", className: "btn btn-ghost btn-danger", textContent: "Remove" });
    remove.addEventListener("click", () => { row.remove(); refreshNone(); });
    row.append(game, action, time, days, el("label", {}, empty, " only if empty "), el("label", {}, enabled, " on "), remove);
    rows.append(row);
    refreshNone();
  };
  rows.replaceChildren();
  (sv.schedules || []).forEach(addRow);
  refreshNone();
  $("schedule-add").onclick = () => addRow({
    id: "s" + Date.now().toString(36), game: games[0] ? games[0].id : "", action: "start", days: [5], time: "18:00", enabled: true,
  });
  $("schedule-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const list = [...rows.children].map((row) => ({
      id: row.dataset.id,
      game: row.querySelector("[name=game]").value,
      action: row.querySelector("[name=action]").value,
      time: row.querySelector("[name=time]").value,
      days: [...row.querySelectorAll(".schedule-days input:checked")].map((c) => Number(c.value)),
      enabled: row.querySelector("[name=enabled]").checked,
      only_if_empty: row.querySelector("[name=only_if_empty]").checked,
    }));
    const res = await callAPI("/api/schedules", { method: "PUT", body: JSON.stringify({ schedules: list }) });
    if (!res.ok) { fail(await errorText(res)); return; }
    fail("");
    toast("Schedules saved.", "ok");
  };
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

// ---------- Audit log ----------
loaders.audit = () => {
  const form = $("audit-form");
  const rows = $("audit-rows");
  const more = $("audit-more");
  const PAGE = 50;
  const KINDS = ["start", "stop", "auto_stop", "start_failed", "stop_failed", "join", "leave",
    "settings", "users", "games", "backup", "restore", "console", "files", "crash", "crash_loop"];
  KINDS.forEach((k) => form.elements.kind.append(new Option(k.replace("_", " "), k)));
  let offset = 0;
  const params = () => {
    const p = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    ["game", "kind", "actor", "q", "since"].forEach((n) => { if (form.elements[n].value.trim()) p.set(n, form.elements[n].value.trim()); });
    // "To" is inclusive of the chosen day; the API's bound is exclusive.
    const to = form.elements.until.value;
    if (to) { const d = new Date(to + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + 1); p.set("until", d.toISOString().slice(0, 10)); }
    return p;
  };
  const load = async (reset) => {
    if (reset) { offset = 0; rows.replaceChildren(); }
    const res = await callAPI("/api/audit?" + params());
    if (!res.ok) { toast(await errorText(res, "Loading the audit log"), "error"); return; }
    const data = await res.json();
    data.events.forEach((e) => {
      const tr = document.createElement("tr");
      const when = document.createElement("td");
      when.textContent = new Date(e.t).toLocaleString([], { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
      tr.append(when);
      [e.kind, e.game || "", e.actor || "", e.detail || ""].forEach((v) => {
        const td = document.createElement("td");
        td.textContent = v;
        tr.append(td);
      });
      rows.append(tr);
    });
    offset += data.events.length;
    more.hidden = !data.more;
    $("audit-empty").hidden = rows.children.length > 0;
  };
  // Game choices come from the settings feed, which lists every game.
  (async () => {
    const res = await callAPI("/api/settings");
    if (res.ok) ((await res.json()).games || []).forEach((g) => form.elements.game.append(new Option(g.name || g.id, g.id)));
  })();
  form.addEventListener("submit", (e) => { e.preventDefault(); load(true); });
  $("audit-reset").addEventListener("click", () => { form.reset(); load(true); });
  more.addEventListener("click", () => load(false));
  load(true);
};

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
  const oidcField = $("user-oidc-field");
  let oidcAvailable = false;
  const gamesBox = $("user-games");
  const gamesField = $("user-games-field");
  let editing = null;
  let editingUser = null; // the row being edited, to tell what changed
  let googleEnabled = false;
  let gameRefs = [];
  const buildGames = () => {
    gamesBox.replaceChildren();
    gameRefs.forEach((g) => {
      const l = document.createElement("label");
      const c = document.createElement("input");
      c.type = "checkbox";
      c.value = g.id;
      l.append(c, " " + g.name);
      gamesBox.append(l);
    });
  };
  const pickedGames = () => [...gamesBox.querySelectorAll("input:checked")].map((c) => c.value);
  const setPicked = (ids) => gamesBox.querySelectorAll("input").forEach((c) => { c.checked = ids.includes(c.value); });
  const syncGamesField = () => { gamesField.hidden = form.elements.role.value === "admin"; };
  form.elements.role.addEventListener("change", syncGamesField);
  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };

  // Changes that decide who can sign in as whom ask for the admin's own password again.
  const askPassword = (title, message, confirmLabel) =>
    confirmAction({ eyebrow: "// crew list", title, message, confirmLabel, danger: true, askPassword: true });

  const resetForm = () => {
    editing = null;
    editingUser = null;
    form.reset();
    form.elements.username.readOnly = false;
    form.elements.role.disabled = false;
    googleField.hidden = !googleEnabled;
    oidcField.hidden = !oidcAvailable;
    title.textContent = "Add a user";
    submit.textContent = "Add user";
    pwLabel.textContent = googleEnabled ? "Password (8+ characters, optional for Google users)" : "Password (8+ characters)";
    cancelEdit.hidden = true;
    setPicked([]);
    syncGamesField();
    showError("");
  };
  const startEdit = (u) => {
    resetForm();
    editing = u.username;
    editingUser = u;
    form.elements.username.value = u.username;
    form.elements.username.readOnly = true;
    form.elements.role.value = u.role;
    form.elements.role.disabled = u.self;
    form.elements.google_email.value = u.google_email || "";
    form.elements.oidc_email.value = u.oidc_email || "";
    setPicked(u.games || []);
    syncGamesField();
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
      tags.textContent = [u.role, u.mfa ? "2FA" : "", u.role === "player" && u.games && u.games.length ? `games: ${u.games.join(", ")}` : "",
        u.google_email ? `google: ${u.google_email}` : (u.google ? "google" : ""), u.oidc_email ? `sso: ${u.oidc_email}` : "",
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
        if (u.mfa) {
          actions.append(mk("Reset 2FA", async () => {
            const pw = await askPassword(`Reset ${u.username}'s authenticator app?`,
              (u.self ? "You will be asked to set it up again." : "They are signed out everywhere and can sign in with just their password until they set it up again.") + " Enter your password to confirm.",
              "Reset");
            if (!pw) return;
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "PUT", { reset_mfa: true, confirm_password: pw });
            if (r) { render(r); toast(`Reset ${u.username}'s authenticator app.`, "ok"); }
          }));
        }
        if (!u.self) {
          actions.append(mk("Sign out", async () => {
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "PUT", { revoke_sessions: true });
            if (r) toast(`Signed ${u.username} out everywhere.`, "ok");
          }));
          actions.append(mk("Delete", async () => {
            const pw = await askPassword(`Delete ${u.username}?`,
              "They are signed out everywhere and can no longer sign in. This can't be undone. Enter your password to confirm.",
              "Delete user");
            if (!pw) return;
            const r = await request(`/api/users/${encodeURIComponent(u.username)}`, "DELETE", { confirm_password: pw });
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
    gameRefs = data.games || [];
    oidcAvailable = (await callAPI("/api/auth/oidc")).ok;
    buildGames();
    resetForm();
    render(data.users);
  })();
  cancelEdit.addEventListener("click", () => { form.elements.role.disabled = false; resetForm(); });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = form.elements;
    let users;
    const lower = (v) => (v || "").trim().toLowerCase();
    const sensitive = editing
      ? (!f.role.disabled && f.role.value !== editingUser.role) || !!f.password.value ||
        (googleEnabled && lower(f.google_email.value) !== lower(editingUser.google_email)) ||
        (oidcAvailable && lower(f.oidc_email.value) !== lower(editingUser.oidc_email))
      : f.role.value === "admin";
    let confirmPw = "";
    if (sensitive) {
      confirmPw = await askPassword(editing ? `Save changes to ${editing}?` : "Add an admin?",
        "This changes who can sign in as this user, or what they can do. Enter your password to confirm.", editing ? "Save changes" : "Add admin");
      if (!confirmPw) return;
    }
    if (editing) {
      const body = {};
      if (confirmPw) body.confirm_password = confirmPw;
      if (!f.role.disabled) body.role = f.role.value;
      if (f.password.value) body.password = f.password.value;
      body.games = pickedGames();
      if (oidcAvailable) body.oidc_email = f.oidc_email.value.trim();
      if (googleEnabled) body.google_email = f.google_email.value.trim();
      users = await request(`/api/users/${encodeURIComponent(editing)}`, "PUT", body);
    } else {
      users = await request("/api/users", "POST",
        { username: f.username.value.trim(), password: f.password.value, role: f.role.value, games: pickedGames(),
          google_email: googleEnabled ? f.google_email.value.trim() : "",
          oidc_email: oidcAvailable ? f.oidc_email.value.trim() : "", confirm_password: confirmPw || undefined });
    }
    if (!users) return;
    f.role.disabled = false;
    render(users);
    toast(editing ? "User updated." : "User added.", "ok");
    resetForm();
  });
};

// ---------- Sign-in ----------
loaders.signin = () => {
  initPasswordSwitch();
  initOIDC();
  const form = $("signin-form");
  const errorEl = $("signin-error");
  const reset = $("signin-reset");
  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
  const SOURCES = {
    dashboard: "These settings were saved here.",
    environment: "These settings come from config.yaml and the environment. Saving here replaces them.",
    none: "Google sign-in is not set up yet.",
  };
  const show = (v) => {
    const f = form.elements;
    f.enabled.checked = v.enabled;
    f.client_id.value = v.client_id || "";
    f.client_secret.value = "";
    f.client_secret.placeholder = v.has_secret ? "set (leave blank to keep)" : "";
    f.redirect_url.value = v.redirect_url || (location.origin + v.callback_path);
    f.password.value = "";
    $("signin-source").textContent = SOURCES[v.source] || "";
    reset.hidden = v.source !== "dashboard";
  };
  (async () => {
    const res = await callAPI("/api/auth/google");
    if (res.status === 404) { form.hidden = true; $("signin-off").hidden = false; return; }
    if (!res.ok) { toast(await errorText(res, "Loading sign-in settings"), "error"); return; }
    show(await res.json());
  })();
  const send = async (method, body) => {
    const res = await callAPI("/api/auth/google", { method, body: JSON.stringify(body) });
    if (!res.ok) { showError(await errorText(res)); return null; }
    showError("");
    return res.json();
  };
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = form.elements;
    const body = { enabled: f.enabled.checked, client_id: f.client_id.value.trim(), redirect_url: f.redirect_url.value.trim(), password: f.password.value };
    if (f.client_secret.value) body.client_secret = f.client_secret.value;
    const v = await send("PUT", body);
    if (v) { show(v); toast("Sign-in settings saved.", "ok"); }
  });
  reset.addEventListener("click", async () => {
    const f = form.elements;
    if (!f.password.value) { showError("Enter your password to remove the saved settings."); f.password.focus(); return; }
    const ok = await confirmAction({
      eyebrow: "// sign-in",
      title: "Remove the saved settings?",
      message: "Google sign-in goes back to whatever config.yaml and the environment say, which may mean it turns off.",
      confirmLabel: "Remove",
      danger: true,
    });
    if (!ok) return;
    const v = await send("DELETE", { password: f.password.value });
    if (v) { show(v); toast("Saved settings removed.", "ok"); }
  });
};

// ---------- OpenID Connect providers (inside the Sign-in pane) ----------
function initOIDC() {
  const section = $("oidc-section");
  const list = $("oidc-list");
  const form = $("oidc-form");
  const errorEl = $("oidc-error");
  const cancel = $("oidc-cancel");
  let editing = null;
  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
  const redirectFor = (id) => `${location.origin}/auth/oidc/${id || "<id>"}/callback`;
  const reset = () => {
    editing = null;
    form.reset();
    form.elements.id.readOnly = false;
    form.elements.redirect_url.value = redirectFor("");
    $("oidc-form-title").textContent = "Add a provider";
    $("oidc-submit").textContent = "Add provider";
    $("oidc-secret-note").textContent = "Stored encrypted and never shown again.";
    form.elements.client_secret.required = true;
    cancel.hidden = true;
    showError("");
  };
  form.elements.id.addEventListener("input", () => {
    if (!editing) form.elements.redirect_url.value = redirectFor(form.elements.id.value.trim());
  });
  const edit = (p) => {
    reset();
    editing = p.id;
    const f = form.elements;
    f.id.value = p.id; f.id.readOnly = true;
    f.name.value = p.name; f.issuer.value = p.issuer; f.client_id.value = p.client_id;
    f.redirect_url.value = p.redirect_url; f.enabled.checked = p.enabled;
    f.client_secret.required = false;
    f.client_secret.placeholder = p.has_secret ? "set (leave blank to keep)" : "";
    $("oidc-form-title").textContent = `Edit ${p.name}`;
    $("oidc-submit").textContent = "Save changes";
    cancel.hidden = false;
    f.password.focus();
  };
  const render = (providers) => {
    list.replaceChildren();
    providers.forEach((p) => {
      const li = document.createElement("li");
      li.className = "user-row";
      const name = document.createElement("span");
      name.className = "user-name";
      name.textContent = p.name;
      const tags = document.createElement("span");
      tags.className = "user-tags";
      tags.textContent = [p.enabled ? "on" : "off", new URL(p.issuer).host].join(" · ");
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
      actions.append(mk("Edit", () => edit(p)), mk("Remove", async () => {
        const pw = form.elements.password.value;
        if (!pw) { showError(`Enter your password below to remove ${p.name}.`); form.elements.password.focus(); return; }
        const ok = await confirmAction({ eyebrow: "// sign-in", title: `Remove ${p.name}?`,
          message: "People linked to it can no longer sign in through it.", confirmLabel: "Remove", danger: true });
        if (!ok) return;
        const r = await send(`/api/auth/oidc/${encodeURIComponent(p.id)}`, "DELETE", { password: pw });
        if (r) { render(r.providers); if (editing === p.id) reset(); toast(`Removed ${p.name}.`, "ok"); }
      }, true));
      li.append(name, tags, actions);
      list.append(li);
    });
  };
  // send answers the parsed body, asking once to confirm when the change would lock people out.
  const send = async (path, method, body) => {
    let res = await callAPI(path, { method, body: JSON.stringify(body) });
    if (res.status === 409) {
      const b = await res.json();
      if (b.refused) { showError(b.message); return null; }
      if (b.needs_confirm) {
        const ok = await confirmAction({ eyebrow: "// sign-in", title: "Lock these people out?",
          message: `${b.message}\n\nLocked out: ${b.locked_out.join(", ")}.` + (b.you_locked_out ? "\n\nThat includes you." : ""),
          confirmLabel: "Go ahead", danger: true });
        if (!ok) return null;
        res = await callAPI(path, { method, body: JSON.stringify({ ...body, confirm: true }) });
      }
    }
    if (!res.ok) { showError(await errorText(res)); return null; }
    showError("");
    return res.json();
  };
  (async () => {
    const res = await callAPI("/api/auth/oidc");
    if (!res.ok) return;
    section.hidden = false;
    reset();
    render((await res.json()).providers);
  })();
  cancel.addEventListener("click", reset);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = form.elements;
    const body = { name: f.name.value.trim(), issuer: f.issuer.value.trim(), client_id: f.client_id.value.trim(),
      redirect_url: f.redirect_url.value.trim(), enabled: f.enabled.checked, password: f.password.value };
    if (f.client_secret.value) body.client_secret = f.client_secret.value;
    const r = await send(`/api/auth/oidc/${encodeURIComponent(f.id.value.trim())}`, "PUT", body);
    if (r) { render(r.providers); toast("Provider saved.", "ok"); reset(); }
  });
}

// ---------- Password sign-in switch (inside the Sign-in pane) ----------
function initPasswordSwitch() {
  const form = $("pwlogin-form");
  const errorEl = $("pwlogin-error");
  const toggle = $("pwlogin-toggle");
  let enabled = true;
  const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
  const show = (v) => {
    enabled = v.enabled;
    $("pwlogin-state").textContent = enabled
      ? "Password sign-in is on. Turn it off to let people in only through Google."
      : "Password sign-in is off. Only Google accounts can sign in. If you are ever locked out, run `crowsnest enable-password-login` on the host and restart.";
    toggle.textContent = enabled ? "Turn password sign-in off" : "Turn password sign-in on";
    toggle.className = "btn " + (enabled ? "btn-ghost btn-danger" : "btn-primary");
    form.elements.password.value = "";
  };
  (async () => {
    const res = await callAPI("/api/auth/password-login");
    if (!res.ok) return; // 404: not editable here
    form.hidden = false;
    show(await res.json());
  })();
  const put = (confirm) => callAPI("/api/auth/password-login", {
    method: "PUT",
    body: JSON.stringify({ enabled: !enabled, password: form.elements.password.value, confirm }),
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError("");
    let res = await put(false);
    if (res.status === 409) {
      const body = await res.json();
      if (body.refused) { showError(body.message); return; }
      if (body.needs_confirm) {
        const who = body.locked_out.join(", ");
        const ok = await confirmAction({
          eyebrow: "// sign-in",
          title: "Lock these people out?",
          message: `${body.message}\n\nLocked out: ${who}.` + (body.you_locked_out ? "\n\nThat includes you: you will be signed out now." : ""),
          confirmLabel: "Turn password sign-in off",
          danger: true,
        });
        if (!ok) return;
        res = await put(true);
      }
    }
    if (!res.ok) { showError(await errorText(res)); return; }
    show(await res.json());
    toast(enabled ? "Password sign-in is on." : "Password sign-in is off.", "ok");
  });
}

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

loaders.backups = async () => {
  const res = await callAPI("/api/backups/overview");
  if (!res.ok) { toast(await errorText(res, "Loading backups"), "error"); return; }
  const v = await res.json();
  const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };
  const ago = (iso) => {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 172800) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} days ago`;
  };
  const mb = (n) => (n >= 1 << 30 ? (n / (1 << 30)).toFixed(1) + " GiB" : Math.max(1, Math.round(n / (1 << 20))) + " MiB");
  const list = $("backups-list");
  list.replaceChildren();
  v.games.forEach((g) => {
    let text;
    if (g.unavailable) text = "can't be listed right now (start the game to see its backups)";
    else if (!g.latest) text = "no backups yet";
    else text = `${g.count} kept, newest ${ago(g.latest.time)} (${mb(g.latest.size)}, ${g.latest.name})`;
    list.append(el("div", { className: "setting-row" }, el("b", { textContent: g.name }), " ", g.running ? "working… " : "", text, g.restorable ? "" : " (no restore)"));
  });
  $("backups-none").hidden = v.games.length > 0;
  const h = v.health;
  const problem = $("backups-problem");
  const off = v.offsite && v.offsite.configured && v.offsite.state !== "ok" ? v.offsite.message || "The offsite copy is failing." : "";
  const text = [...((h && h.problems) || []), off].filter(Boolean).join(" ");
  problem.textContent = text;
  problem.hidden = !text;
  $("backups-folder").textContent = h ? `Shared folder: ${h.ok ? "healthy" : "has problems"}, ${mb(h.free)} free.` : "No shared backups folder is set up; each game keeps its own.";
  const orphans = $("backups-orphans");
  orphans.hidden = !(h && h.orphans && h.orphans.length);
  if (!orphans.hidden) orphans.textContent = `Folders no game uses (kept, never deleted by CrowsNest): ${h.orphans.join(", ")}.`;
};
