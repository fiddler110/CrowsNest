// "Sign in with a passkey": no username needed, the browser offers the passkeys it holds for this site.
const pkButton = document.getElementById("passkey-signin");
if (pkButton && window.PublicKeyCredential) {
  pkButton.hidden = false;
  pkButton.addEventListener("click", async () => {
    const alertEl = document.getElementById("login-alert");
    const errorEl = document.getElementById("login-error");
    const fail = (m) => { errorEl.textContent = m; alertEl.hidden = false; };
    alertEl.hidden = true;
    pkButton.disabled = true;
    try {
      const begin = await fetch("/login/passkey/begin", { method: "POST" });
      if (!begin.ok) { fail(begin.status === 429 ? "Too many attempts — try again later." : "Passkeys are not available."); return; }
      const body = await passkeyGet(await begin.json());
      const fin = await fetch("/login/passkey/finish", { method: "POST", headers: { "Content-Type": "application/json" }, body });
      if (fin.ok) { window.location.href = "/"; return; }
      fail(fin.status === 429 ? "Too many attempts — try again later." : "That passkey was not accepted.");
    } catch (err) {
      if (err && err.name !== "NotAllowedError") fail("Could not use a passkey here.");
    } finally {
      pkButton.disabled = false;
    }
  });
}
