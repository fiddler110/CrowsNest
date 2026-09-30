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
