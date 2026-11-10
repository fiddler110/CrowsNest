// Shared by the signed-in pages (loaded before app.js, games.js, settings.js):
// API calls with the CSRF header, one way to turn a failed response into a
// message, stackable toasts, a themed confirm dialog, and Log out.
// Classic script: these names are globals, so page scripts must not redeclare them.

const CSRF_TOKEN = (document.querySelector("meta[name=csrf-token]") || {}).content || "";
const SVG_NS = "http://www.w3.org/2000/svg";
const MAX_TOASTS = 4;

function callAPI(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN, ...(options.headers || {}) },
  });
}

// errorText reads a failed response into one message. 401 means the session
// is gone: it sends the browser to the login page (and returns ""). A 403 is
// shown as the server worded it ("this action needs an admin account"),
// except a stale CSRF token, which only a reload fixes.
async function errorText(res, action) {
  if (res.status === 401) {
    window.location.href = "/login";
    return "";
  }
  let text = "";
  try { text = (await res.text()).trim().slice(0, 300); } catch (err) { /* body unreadable */ }
  text = text.replace(/^exclusivity: /, "");
  if (res.status === 403 && /csrf/i.test(text)) {
    return `${action || "That"} was refused because this page is out of date. Reload it and try again.`;
  }
  const detail = text || `HTTP ${res.status}`;
  return action ? `${action} failed: ${detail}` : detail;
}

// checkOK toasts the failure (if any) and reports whether res succeeded.
async function checkOK(res, action) {
  if (res.ok) return true;
  const msg = await errorText(res, action);
  if (msg) toast(msg, "error");
  return false;
}

function svgIcon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#${name}`);
  svg.appendChild(use);
  return svg;
}

// toast shows a message at the bottom of the page. kind is "error" (the
// default), "ok" or "info". Toasts stack; each closes itself after a while or
// with its close button.
function toast(message, kind = "error") {
  const root = document.getElementById("toasts");
  if (!root || !message) return;
  const t = document.createElement("div");
  t.className = `toast toast-${kind}`;
  if (kind === "error") t.setAttribute("role", "alert");
  const text = document.createElement("span");
  text.className = "toast-text";
  text.textContent = message;
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss");
  close.appendChild(svgIcon("i-x"));
  t.append(svgIcon(kind === "ok" ? "i-check" : "i-alert"), text, close);

  let timer;
  const dismiss = () => { clearTimeout(timer); t.remove(); };
  const arm = () => { timer = setTimeout(dismiss, kind === "error" ? 10000 : 5000); };
  close.addEventListener("click", dismiss);
  // Hovering or focusing a toast keeps it up long enough to read.
  t.addEventListener("mouseenter", () => clearTimeout(timer));
  t.addEventListener("mouseleave", arm);
  t.addEventListener("focusin", () => clearTimeout(timer));
  root.appendChild(t);
  while (root.children.length > MAX_TOASTS) root.firstChild.remove();
  arm();
}

// openModal shows a .dialog, traps Tab inside it, and calls onCancel on
// Escape. Returns close(), which hides it and gives focus back to the opener.
function openModal(dialog, focusEl, onCancel) {
  const opener = document.activeElement;
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); onCancel(); return; }
    if (e.key !== "Tab") return;
    const focusable = [...dialog.querySelectorAll("input, button, select, textarea, a[href]")]
      .filter((el) => !el.disabled && el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  dialog.hidden = false;
  document.addEventListener("keydown", onKey);
  if (focusEl) focusEl.focus();
  return () => {
    dialog.hidden = true;
    document.removeEventListener("keydown", onKey);
    if (opener && opener.focus) opener.focus();
  };
}

// confirmAction asks a yes/no question in the themed dialog. Resolves true
// when confirmed. danger styles the confirm button as destructive.
function confirmAction({ title, message = "", confirmLabel = "Confirm", danger = false, eyebrow = "// confirm" }) {
  const dialog = document.getElementById("confirm-dialog");
  if (!dialog) return Promise.resolve(false);
  const ok = document.getElementById("confirm-ok");
  const cancel = document.getElementById("confirm-cancel");
  document.getElementById("confirm-eyebrow").textContent = eyebrow;
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-message").textContent = message;
  ok.textContent = confirmLabel;
  ok.className = danger ? "btn btn-danger" : "btn btn-primary";
  return new Promise((resolve) => {
    let close;
    const done = (answer) => {
      ok.removeEventListener("click", onOK);
      cancel.removeEventListener("click", onCancel);
      close();
      resolve(answer);
    };
    const onOK = () => done(true);
    const onCancel = () => done(false);
    ok.addEventListener("click", onOK);
    cancel.addEventListener("click", onCancel);
    // Destructive actions start on Cancel so a stray Enter does no harm.
    close = openModal(dialog, danger ? cancel : ok, onCancel);
  });
}

(() => {
  const logout = document.getElementById("logout-btn");
  if (!logout) return;
  logout.addEventListener("click", async () => {
    logout.disabled = true;
    try { await callAPI("/logout", { method: "POST" }); } catch (err) { /* leave anyway */ }
    window.location.href = "/login";
  });
})();
