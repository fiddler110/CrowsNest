# Accounts, sign-in and protecting what is stored

Roles, sessions, Google and other sign-in methods, the authenticator app, and what CrowsNest encrypts on disk.

Back to the [README](../README.md).

## Users and roles

There are two roles. An **admin** can do everything. A **player** can start, stop and switch games and see status,
players, stats and activity, but can't open Settings or the Games page, read container logs, use the console or
touch backups.

Admins manage users on the **Users** tab in Settings. From the command line,
`docker compose exec crowsnest crowsnest set-role <user> <admin|player>` does the same. A password account with no
role is an admin, so accounts from before roles existed behave as they did. A Google sign-in user with no role is a
player, so promote yourself with `crowsnest set-role <you> admin` before relying on Google sign-in (CrowsNest logs a
warning at startup when no user resolves to admin). Role changes apply within seconds, and a demotion applies on the
user's very next request.

## Sessions

A session is a signed cookie that lasts 3 hours without activity (`server.session_idle_minutes`, default 180).
Using the panel renews it (an open, visible dashboard counts: it checks in every 10 minutes), but never past
`server.session_max_hours` after sign-in (default 12), so everyone signs in again at least that often. Set the
maximum to no more than the idle time to turn renewal off and get a fixed lifetime. The server also keeps a list of live sessions
(`sessions.json` next to `settings.json`: an id, device, address and times; nothing in it can sign anyone in). There's
no "remember me": you log in again once it expires. Anyone with a password can change it on the **Account** page (it asks for the current one and signs their other devices out). Every signed-in person can see their own devices on the
**Account** page, sign out one device, every other device, or everywhere, and set a display name (shown in the top
bar; the sign-in name stays what the audit log and permissions use). A restart keeps people signed in. Sessions
made before this list existed (a cookie with no session id) are ended once on upgrade. An admin can still revoke all
of a user's sessions from the command line with `docker compose exec crowsnest crowsnest revoke-sessions <username>`. It edits the users file,
which a running CrowsNest watches, so it applies within a few seconds (as does `set-password`). It works for Google
users too, even though they have no password entry.

If someone now signs in only with Google, run `crowsnest clear-password <username>` to drop their stored password
hash. It refuses unless Google sign-in is set up for that user, keeps their role, and revokes their sessions.
`crowsnest doctor` lists users who still have a hash while password login is off.

To remove someone entirely, delete them under Settings, Users (applies within seconds). A session only stays valid while its username still has a way to sign in. Rotating or
deleting the session-secret file logs everyone out at once.

## Signing in with Google

CrowsNest can do "Sign in with Google" itself (OpenID Connect, server side) with its own allowlist, so it doesn't
need a separate auth proxy and a Google account only gets in if you listed it.

1. In Google Cloud Console, go to APIs & Services, then Credentials, and create an OAuth client ID of type **Web
   application** with the authorized redirect URI `https://<your host>/auth/google/callback`. On the consent
   screen, `openid` and `email` are the only scopes CrowsNest asks for.
2. In `.env`, set `CROWSNEST_GOOGLE_CLIENT_ID` and `CROWSNEST_GOOGLE_CLIENT_SECRET` (or enter them in the dashboard,
   below). Who may sign in is set per user under Settings, Users: give each person a Google email. A Google account
   that isn't listed there is refused, even though Google signed it in.
3. In `config.yaml`, add `auth.google.redirect_url` with the same URL, and `auth.password_login: false` if Google
   should be the only way in. An https redirect URL also needs `server.secure_cookies: true`.

**From the dashboard instead:** an admin can do steps 2 and 3 under Settings, Sign-in: the client ID, the client
secret, the redirect URL and an on/off switch, applied at once with no restart. Saving asks for the admin's own
password again. The secret is stored encrypted in `auth.json` (next to `settings.json`), under a key in `auth-key`
(next to the session secret); it is never sent back to the browser. What is saved there wins over `config.yaml` and
the environment, and "Remove saved settings" puts those back. Which Google accounts may sign in is set per user
under Users, which is the only place the list is kept. An old `CROWSNEST_GOOGLE_USERS` (`name=email` pairs) is
copied into the users file once at the first start after the first admin exists, then ignored (a
`google-users-imported` marker file stops it coming back); remove the variable afterwards. Turning Google off is refused while
`auth.password_login: false`, since nobody could then sign in. Back up `auth-key` with the data folder: without it
the saved secret can't be read and has to be entered again.

Addresses must be plain ASCII and match the Google
account's exactly (case aside), so `j.doe@gmail.com` and `jdoe@gmail.com` are different entries.

The first sign-in with a listed, verified address binds that person to the Google account's own subject id. After
that the subject decides, so Google reporting a different address for the account changes nothing, and a different
Google account that ends up with the same address is refused. Changing or removing the person's Google email under
Users drops the binding, and the next sign-in binds whoever the new address belongs to.

The flow uses a signed 10 minute state cookie (state, nonce and PKCE) and exchanges the code with Google's token
endpoint directly over TLS. The ID token's signature is also checked against the keys Google publishes
(RS256 or ES256; other algorithms are refused). Once signed in, it's the same 3 hour session as a password login. Requests to Google
need outbound HTTPS from the container.

## Passkeys

A passkey signs someone in with a fingerprint, face, PIN or security key, no password. It counts as both steps, so the
authenticator-app code is skipped, and "require admins to use an authenticator app" is met by having one.

Turn it on in `config.yaml`. Both values are fixed by you and never taken from a request, because a passkey is bound
to them: changing either later makes existing passkeys stop working.

```yaml
auth:
  passkeys:
    rp_id: crowsnest.example.com            # the host in the address bar, or its parent domain
    origins: ["https://crowsnest.example.com"]   # https only (http://localhost for trying it out)
```

People add them on the **Account** page (up to 10 each; asks for the password again, as removing one does). The
login page then shows "Sign in with a passkey", which needs no username. A passkey must verify the person (PIN or
biometric) or it is refused, a response can be used once, and a passkey whose account was deleted cannot sign in.
Passkeys are kept in `passkeys.json` beside `settings.json`: public keys and credential ids only, nothing that can
sign anyone in. An account needs a password to add or remove one (the same re-check as the authenticator app), so a
Google-only account sets a password first. Deleting a user deletes their passkeys.

## Sign-in options, and protecting what CrowsNest stores

Everything below is managed from the dashboard (Settings, Sign-in, Users; Account for each person).

**Methods.** Password, Google, and any number of other OpenID Connect providers (Authentik, Keycloak, Entra, Okta,
Auth0…). Add a provider with its issuer URL, client ID and secret; CrowsNest reads the provider's discovery document,
refuses one that names a different issuer or lacks PKCE (S256), and always uses state, nonce and PKCE. When the
discovery document names a `jwks_uri`, each ID token's signature (RS256 or ES256) is verified against those keys;
a provider saved before this was added has no key address stored, so open it in Settings and save it again to
switch the check on. Link a person
with their **SSO email** under Users. The first sign-in with a *verified* matching email binds them to the provider's
own subject id; after that the subject decides, so a changed or reused email can't take the account over, and a second
provider account with the same email is refused.

**Password sign-in switch.** Turning it off asks for your password, shows who would be locked out (you included) and
needs a second confirmation. It is refused outright if no admin could still sign in. If you are ever shut out, run
`crowsnest enable-password-login` on the host and restart.

**Authenticator app (TOTP, RFC 6238).** Each person sets it up on their Account page (password again, scan the QR
code, enter a code, get 10 one-time recovery codes shown once). It is asked after the password at sign-in. A code can't
be reused, five wrong codes lock that account for 15 minutes, and turning it off or making new recovery codes needs the
password plus a code. An admin can reset someone's app from Users (a lost phone), which signs them out. It applies to
password sign-in only: Google and OIDC sign-ins rely on the provider's own protections. It stays optional for each
person unless an admin turns on **Settings, General, Require admins to set up an authenticator app**: then an admin who
signs in with a password and has no app yet can reach only their Account page (pages redirect there, API calls get a
403) until they enrol. Admins who sign in through Google or another provider are not asked. Not built: forcing
players, and WebAuthn/passkeys.

**What is encrypted on disk.** The Google and OIDC client secrets, TOTP secrets, game secrets (`secrets.json`) and the
session-signing key are sealed with AES-256-GCM, each bound to its own field so a copied value won't open elsewhere.
Recovery codes and passwords are stored only as bcrypt hashes. Older plain-text files are encrypted on first start.
The key is `CROWSNEST_MASTER_KEY` (24+ characters, e.g. `openssl rand -base64 32`) when set; keep it **outside** the
data volume (the host's `.env`, a Docker secret). Otherwise a key file `master.key` is created beside the session
secret and the server warns: that still protects a copied single file or backup, but not a copy of the whole volume.
Lose the key and the sealed secrets can't be read: re-enter the client secrets and game secrets, and everyone re-enrols
their authenticator app. Secrets are never sent back to the browser (fields show "set"), and recovery codes and QR
codes are served uncacheable. Not encrypted: the users file (bcrypt hashes and emails), the settings, and the activity
log. Game join passwords shown on a card are shown on purpose.

**Setting the key, and changing it.** Setting `CROWSNEST_MASTER_KEY` is the recommended setup (the key file works, but
sits in the folder it protects). The AES key is derived from it with Argon2id (a typed passphrase) or HKDF (the random
key file); sealed values read `enc:v2:`. Values written by older versions (`enc:v1:`) still open and are moved to v2 the
next time they are saved. To move every file at once, or to change the key (a leak, a leaver, a move from the key file to
the environment), stop the panel, run `crowsnest state export` for a snapshot, then
`CROWSNEST_NEW_MASTER_KEY=<new> crowsnest rekey` with the current key set as usual. It re-seals the session secret, the
Google and SSO client secrets, authenticator apps and the dashboard games' passwords, and is safe to run again if it was
interrupted. Then set `CROWSNEST_MASTER_KEY` to the new value, remove `CROWSNEST_NEW_MASTER_KEY`, delete `master.key` if
you had one, and start the panel. With no new key, `crowsnest rekey` just brings every value to the newest scheme.
