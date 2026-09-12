document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const errorEl = document.getElementById("login-error");
  errorEl.hidden = true;

  let res;
  try {
    res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: form.username.value,
        password: form.password.value,
      }),
    });
  } catch (err) {
    errorEl.textContent = "Network error — please try again.";
    errorEl.hidden = false;
    return;
  }

  if (res.ok) {
    window.location.href = "/";
    return;
  }
  errorEl.textContent = res.status === 429
    ? "Too many attempts — try again later."
    : "Invalid username or password.";
  errorEl.hidden = false;
});
