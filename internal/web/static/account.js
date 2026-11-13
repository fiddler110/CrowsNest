// Account page: the signed-in user's own security (authenticator app).
// callAPI, errorText, toast and confirmAction come from api.js.
const $ = (id) => document.getElementById(id);
const errorEl = $("totp-error");
const showError = (msg) => { errorEl.textContent = msg; errorEl.hidden = !msg; };
const parts = ["totp-begin", "totp-confirm", "totp-codes", "totp-manage"];
const only = (id) => parts.forEach((p) => { $(p).hidden = p !== id; });

async function post(path, body) {
  const res = await callAPI(path, { method: "POST", body: JSON.stringify(body) });
  if (!res.ok) { showError(await errorText(res)); return null; }
  showError("");
  return res.json();
}

async function load() {
  const res = await callAPI("/api/account/security");
  if (!res.ok) { toast(await errorText(res, "Loading your account"), "error"); return; }
  const v = await res.json();
  $("password").hidden = !v.has_password;
  $("mfa-required").hidden = !v.mfa_required;
  if (!v.totp_available) return;
  $("totp").hidden = false;
  $("totp-nopw").hidden = v.has_password;
  if (!v.has_password) { $("totp-state").textContent = ""; only(""); return; }
  if (v.totp_enabled) {
    $("totp-state").textContent = "On. You are asked for a code from your app after your password.";
    $("totp-left").textContent = `${v.recovery_left} recovery code${v.recovery_left === 1 ? "" : "s"} left.`;
    only("totp-manage");
  } else {
    $("totp-state").textContent = "Off. Add a second step to your password sign-in.";
    only("totp-begin");
  }
  document.querySelectorAll("#totp form").forEach((f) => f.reset());
}

function showCodes(codes) {
  $("totp-codes-list").textContent = codes.join("\n");
  only("totp-codes");
}

$("totp-begin").addEventListener("submit", async (e) => {
  e.preventDefault();
  const v = await post("/api/account/totp/begin", { password: e.target.elements.password.value });
  if (!v) return;
  $("totp-secret").textContent = v.secret.replace(/(.{4})/g, "$1 ").trim();
  $("totp-qr").src = "/api/account/totp/qr?" + Date.now();
  e.target.reset();
  only("totp-confirm");
  $("totp-confirm").elements.code.focus();
});

$("totp-confirm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const v = await post("/api/account/totp/confirm", { code: e.target.elements.code.value });
  if (!v) return;
  e.target.reset();
  $("totp-state").textContent = "On.";
  showCodes(v.recovery_codes);
});

$("totp-codes-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("totp-codes-list").textContent); toast("Copied.", "ok"); }
  catch { toast("Couldn't copy: select the codes and copy them by hand.", "error"); }
});
$("totp-codes-done").addEventListener("click", () => { $("totp-codes-list").textContent = ""; load(); });

$("totp-recovery").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target.elements;
  const v = await post("/api/account/totp/recovery", { password: f.password.value, code: f.code.value });
  if (v) { e.target.reset(); showCodes(v.recovery_codes); }
});

$("totp-off").addEventListener("click", async () => {
  const f = $("totp-recovery").elements;
  if (!f.password.value || !f.code.value) { showError("Enter your password and a code from your app to turn it off."); return; }
  const ok = await confirmAction({
    eyebrow: "// account",
    title: "Turn off the authenticator app?",
    message: "Your account goes back to password-only sign-in.",
    confirmLabel: "Turn it off",
    danger: true,
  });
  if (!ok) return;
  if (await post("/api/account/totp/disable", { password: f.password.value, code: f.code.value })) {
    toast("Authenticator app turned off.", "ok");
    load();
  }
});

// ---- display name and signed-in devices ----
$("profile-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const res = await callAPI("/api/account/profile", { method: "POST", body: JSON.stringify({ display_name: e.target.elements.display_name.value }) });
  if (!res.ok) { toast(await errorText(res, "Saving your name"), "error"); return; }
  const v = await res.json();
  const chip = document.querySelector(".user-chip b");
  if (chip) chip.textContent = v.display_name || chip.dataset.username || chip.textContent;
  toast(v.display_name ? "Name saved." : "Name cleared: reload to see your sign-in name.", "ok");
});

const sessionsErr = $("sessions-error");
const showSessionsError = (msg) => { sessionsErr.textContent = msg; sessionsErr.hidden = !msg; };
const when = (iso) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

async function revoke(body, done) {
  const res = await callAPI("/api/account/sessions/revoke", { method: "POST", body: JSON.stringify(body) });
  if (!res.ok) { showSessionsError(await errorText(res)); return; }
  showSessionsError("");
  const v = await res.json();
  if (v.signed_out) { window.location.href = "/login"; return; }
  toast(done, "ok");
  loadSessions();
}

async function loadSessions() {
  const res = await callAPI("/api/account/profile");
  if (!res.ok) { showSessionsError(await errorText(res, "Loading your devices")); return; }
  const v = await res.json();
  const notice = $("signin-notice");
  notice.hidden = !v.new_sign_in;
  if (v.new_sign_in) {
    $("signin-notice-text").textContent = `New sign-in from ${v.new_sign_in.device}${v.new_sign_in.ip ? " (" + v.new_sign_in.ip + ")" : ""} on ${when(v.new_sign_in.at)}, a browser or system you had not used before. If it was not you, sign it out below and change your password.`;
  }
  const list = $("sessions-list");
  list.replaceChildren();
  if (!v.per_device) {
    $("sessions-note").textContent = "This server does not keep a list of devices.";
    return;
  }
  $("sessions-note").textContent = "Sessions end by themselves after a few hours. Sign out any you don't recognise.";
  for (const s of v.sessions) {
    const li = document.createElement("li");
    li.className = "session-row";
    const info = document.createElement("div");
    const title = document.createElement("b");
    title.textContent = s.device + (s.current ? " (this device)" : "");
    if (s.user_agent) title.title = s.user_agent;
    const meta = document.createElement("small");
    meta.textContent = `${s.ip ? s.ip + " · " : ""}signed in ${when(s.created)} · last seen ${when(s.last_seen)}`;
    info.append(title, document.createElement("br"), meta);
    li.append(info);
    if (!s.current) {
      const b = document.createElement("button");
      b.type = "button"; b.className = "btn btn-ghost"; b.textContent = "Sign out";
      b.addEventListener("click", () => revoke({ id: s.id }, "Device signed out."));
      li.append(b);
    }
    list.append(li);
  }
  $("sessions-others").hidden = v.sessions.length < 2;
  $("sessions-all").hidden = v.sessions.length < 1;
}

$("signin-notice-dismiss").addEventListener("click", async () => {
  await callAPI("/api/account/sign-in-notice/dismiss", { method: "POST" });
  $("signin-notice").hidden = true;
});
$("sessions-others").addEventListener("click", () => revoke({ others: true }, "Other devices signed out."));
$("sessions-all").addEventListener("click", async () => {
  const ok = await confirmAction({ eyebrow: "// account", title: "Sign out everywhere?",
    message: "Every device, including this one, is signed out and must sign in again.", confirmLabel: "Sign out everywhere", danger: true });
  if (ok) revoke({ all: true }, "");
});

load();
loadSessions();

// ---- change password ----
$("password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target.elements;
  const err = $("password-error");
  const fail = (m) => { err.textContent = m; err.hidden = !m; };
  if (f.new.value !== f.again.value) { fail("The two new passwords don't match."); return; }
  const res = await callAPI("/api/account/password", { method: "POST", body: JSON.stringify({ current: f.current.value, new: f.new.value }) });
  if (!res.ok) { fail(await errorText(res)); return; }
  fail("");
  e.target.reset();
  const v = await res.json();
  toast(v.signed_out ? `Password changed. ${v.signed_out} other device${v.signed_out === 1 ? "" : "s"} signed out.` : "Password changed.", "ok");
});

// ---- Discord pings ----
async function loadMentions() {
  const res = await callAPI("/api/account/mentions");
  if (!res.ok) return;
  const v = await res.json();
  $("mentions").hidden = !v.available;
  $("mentions-form").elements.discord_id.value = v.discord_id || "";
  const box = $("mentions-games");
  box.replaceChildren();
  v.games.forEach((g) => {
    const label = document.createElement("label");
    label.className = "check";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = g.id;
    cb.checked = g.checked;
    label.append(cb, " ", g.name);
    box.append(label);
  });
}
$("mentions-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const games = [...$("mentions-games").querySelectorAll("input:checked")].map((c) => c.value);
  const res = await callAPI("/api/account/mentions", { method: "PUT", body: JSON.stringify({ discord_id: e.target.elements.discord_id.value.trim(), games }) });
  if (!res.ok) { toast(await errorText(res, "Saving Discord pings"), "error"); return; }
  toast("Saved.", "ok");
  loadMentions();
});
loadMentions();
