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

load();
