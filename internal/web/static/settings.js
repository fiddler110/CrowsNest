// Settings page: a sidebar of panes (General, Users, Game policy). The pane is chosen by the URL hash.
const CSRF_TOKEN = document.querySelector("meta[name=csrf-token]").content;
const $ = (id) => document.getElementById(id);

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
    if (!res.ok) { toast(`Could not load settings: ${(await res.text()).trim()}`); return; }
    const v = await res.json();
    fields.forEach((n) => {
      if (input(n).type === "checkbox") input(n).checked = !!v[n]; else input(n).value = v[n];
    });
  })();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {};
    fields.forEach((n) => {
      body[n] = input(n).type === "checkbox" ? input(n).checked : parseInt(input(n).value, 10);
    });
    const res = await callAPI("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    if (!res.ok) { errorEl.textContent = (await res.text()).trim(); errorEl.hidden = false; return; }
    errorEl.hidden = true;
    toast("Settings saved.");
  });
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
    if (!res.ok) { showError((await res.text()).trim()); return null; }
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

  (async () => {
    const res = await callAPI("/api/users");
    if (!res.ok) { toast(`Could not load users: ${(await res.text()).trim()}`); return; }
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
    toast(editing ? "User updated." : "User added.");
    resetForm();
  });
};

// ---------- Game policy ----------
loaders.policy = () => {
  const pf = $("policy-form");
  const listFields = ["names", "images", "networks", "ports", "host_ips"];
  let state = null;
  const setEditing = (on) => {
    [...pf.elements].forEach((f) => { if (f.name) f.disabled = !on; });
    $("policy-edit").hidden = on || !(state && state.editable);
    $("policy-cancel").hidden = !on;
    $("policy-save").hidden = !on;
  };
  const fill = () => {
    const p = state.policy;
    pf.elements.games_root.value = p.games_root;
    listFields.forEach((k) => { pf.elements[k].value = (p[k] || []).join("\n"); pf.elements[k].rows = Math.max(2, (p[k] || []).length); });
    pf.elements.max_scopes.value = p.max_scopes;
    pf.elements.exec.checked = !!p.exec;
    $("policy-note").textContent = state.editable
      ? "What the panel may create when you add a game. Saved changes apply within a few seconds, and a game that no longer fits is dropped by the guard."
      : "What the panel may create when you add a game. It is read-only here on purpose: it lives in policy.yaml on the host, so a compromised panel cannot widen its own limits.";
    setEditing(false);
  };
  (async () => {
    const res = await callAPI("/api/managed/policy");
    if (res.status === 404) { $("policy-off").hidden = false; pf.hidden = true; return; }
    if (!res.ok) { $("policy-note").textContent = "The policy could not be read: " + (await res.text()).trim(); return; }
    state = await res.json();
    fill();
  })();
  const lines = (v) => v.split("\n").map((x) => x.trim()).filter(Boolean);
  $("policy-edit").addEventListener("click", () => { $("policy-error").hidden = true; setEditing(true); });
  $("policy-cancel").addEventListener("click", () => { $("policy-error").hidden = true; fill(); });
  pf.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = { games_root: pf.elements.games_root.value.trim(), exec: pf.elements.exec.checked,
      max_scopes: parseInt(pf.elements.max_scopes.value, 10) || 0 };
    listFields.forEach((k) => { body[k] = lines(pf.elements[k].value); });
    const res = await callAPI("/api/managed/policy", { method: "PUT", body: JSON.stringify(body) });
    if (!res.ok) { $("policy-error").textContent = (await res.text()).trim(); $("policy-error").hidden = false; return; }
    state = await res.json();
    fill();
    toast("Policy saved.");
  });
};

showPane();
