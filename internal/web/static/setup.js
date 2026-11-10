const form = document.getElementById("setup-form");
const card = document.getElementById("setup-card");
const alertEl = document.getElementById("setup-alert");
const errorEl = document.getElementById("setup-error");
const submitBtn = document.getElementById("submit");
const submitTxt = submitBtn.querySelector(".txt");

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
  submitTxt.textContent = busy ? "Creating…" : "Create admin";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  alertEl.hidden = true;
  const f = form.elements;
  if (!f.code.value.trim() || !f.username.value.trim()) {
    fail("Enter the setup code and a username.");
    return;
  }
  if (f.password && f.password.value !== f.confirm.value) {
    fail("The two passphrases don't match.");
    return;
  }
  setBusy(true);
  let res;
  try {
    res = await fetch("/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: f.code.value.trim(),
        username: f.username.value.trim(),
        password: f.password ? f.password.value : "",
        google_email: f.google_email ? f.google_email.value.trim() : "",
      }),
    });
  } catch (err) {
    setBusy(false);
    fail("Network error — please try again.");
    return;
  }
  if (res.ok) {
    submitTxt.textContent = "Done";
    window.location.href = "/login";
    return;
  }
  setBusy(false);
  fail((await res.text()).trim() || "Setup failed.");
});
