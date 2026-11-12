const form = document.getElementById("login-form");
const card = document.getElementById("login-card");
const alertEl = document.getElementById("login-alert");
const errorEl = document.getElementById("login-error");
const submitBtn = document.getElementById("submit");
const submitTxt = submitBtn.querySelector(".txt");
const pwInput = form.password;
const reveal = document.getElementById("reveal");
const caps = document.getElementById("caps");

// The show/hide toggle needs JS, so it stays hidden without it.
reveal.hidden = false;
reveal.addEventListener("click", () => {
  const show = pwInput.type === "password";
  pwInput.type = show ? "text" : "password";
  reveal.classList.toggle("on", show);
  reveal.setAttribute("aria-pressed", String(show));
  reveal.setAttribute("aria-label", show ? "Hide password" : "Show password");
  pwInput.focus();
});

pwInput.addEventListener("keydown", (e) => {
  if (e.getModifierState) caps.hidden = !e.getModifierState("CapsLock");
});
pwInput.addEventListener("blur", () => { caps.hidden = true; });

function fail(message) {
  errorEl.textContent = message;
  alertEl.hidden = false;
  card.classList.remove("shake");
  void card.offsetWidth; // restart the shake animation
  card.classList.add("shake");
}

function setBusy(busy) {
  submitBtn.disabled = busy;
  submitBtn.classList.toggle("busy", busy);
  submitTxt.textContent = busy ? "Hailing the lookout…" : "Take the helm";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  alertEl.hidden = true;
  if (!form.username.value || !pwInput.value) {
    fail("Enter your username and passphrase.");
    return;
  }
  setBusy(true);

  let res;
  try {
    res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: form.username.value, password: pwInput.value }),
    });
  } catch (err) {
    setBusy(false);
    fail("Network error — please try again.");
    return;
  }

  if (res.ok) {
    let body = {};
    try { body = await res.json(); } catch (err) { /* a plain success */ }
    if (body.mfa_required) {
      setBusy(false);
      pwInput.value = "";
      form.hidden = true;
      mfaForm.hidden = false;
      mfaForm.code.focus();
      return;
    }
    submitTxt.textContent = "Welcome aboard";
    window.location.href = "/";
    return;
  }
  setBusy(false);
  pwInput.select();
  fail(res.status === 429
    ? "Too many attempts — try again later."
    : "Invalid username or password.");
});

// Second step: the code from the authenticator app (or a recovery code).
const mfaForm = document.getElementById("mfa-form");
if (mfaForm) {
  mfaForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    alertEl.hidden = true;
    const code = mfaForm.code.value.trim();
    if (!code) { fail("Enter the code from your authenticator app."); return; }
    mfaForm.querySelector("button").disabled = true;
    let res;
    try {
      res = await fetch("/login/mfa", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
    } catch (err) {
      mfaForm.querySelector("button").disabled = false;
      fail("Network error — please try again.");
      return;
    }
    if (res.ok) { window.location.href = "/"; return; }
    mfaForm.querySelector("button").disabled = false;
    if (res.status === 401 && /expired/.test(await res.text())) {
      // The five minutes ran out: start again from the password.
      mfaForm.hidden = true;
      form.hidden = false;
      fail("That sign-in timed out. Enter your password again.");
      return;
    }
    mfaForm.code.select();
    fail(res.status === 429 ? "Too many wrong codes — try again in a few minutes." : "That code is not right.");
  });
}
