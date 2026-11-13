# Threat model

What CrowsNest defends, against whom, and where each defence lives. It is written for the operator deciding how far
to trust it, and for anyone reviewing a change. It is a description of the design, not a proof: the guard has had a
review and fuzzing (2026-11-10) and the rest was read, not audited. Report a gap through [SECURITY.md](../SECURITY.md).

## What is being protected

1. **The host.** The panel's whole purpose is to run containers, so the worst outcome is a path from the browser
   or a game container to the host's Docker socket.
2. **Secrets:** the session secret, the vault key (`master.key` or `CROWSNEST_MASTER_KEY`), sign-in client secrets,
   game passwords, webhook URLs, passphrase hashes.
3. **Availability of the game server** for the people who play on it, and the data in it (worlds and backups).
4. **The record of who did what** (the activity log and the audit file).

## Trust boundaries

```
 browser ──HTTPS──▶ reverse proxy ──▶ panel ──(internal network)──▶ guard ──▶ /var/run/docker.sock
                                        │                                         │
                                        └── modules (module.yaml) ──▶ game containers (own networks)
```

| Boundary | Who is on each side | What enforces it |
|---|---|---|
| Browser → panel | Anyone who can reach the port vs. a signed-in admin or player | Sign-in (passphrase, Google or OIDC, optional TOTP); a signed session cookie (`HttpOnly`, `SameSite=Lax`, `__Host-` and `Secure` when `secure_cookies` is on) plus a server-side session list; CSRF token on every state change; per-address and per-user sign-in throttling; CSP with a nonce and the other security headers; two roles, with admin-only routes behind `RequireAdmin`; sessions are renewed only up to an absolute limit |
| Panel → guard | A web-facing process that may be compromised vs. the Docker API | The panel never mounts the Docker socket. It reaches the guard over an `internal` network, and the guard allows only the containers, images, networks, binds, ports and security options its scope lists (named container, no privileged mode, no host binds outside the game folder) |
| Guard → Docker | A filter vs. the daemon | The guard is the only container with the socket. `policy.yaml` is mounted read-only into it and **not writable by the panel**, so what the dashboard can create is bounded by something the dashboard cannot edit. A managed scope that does not fit the policy is dropped |
| Panel → game containers | The panel vs. code it did not write | Game containers get their own networks; `exec` is refused unless the policy turns it on and the command is one a game's module declares for backups or for reading and writing its declared config files (the exec allowlist runs in the guard's process) |
| Module sources → panel | Third-party game definitions vs. the engine | A module is data (`module.yaml`), not code. A URL install must be signed by a key in `managed.trusted_keys`, which lives in `config.yaml` and not in anything the dashboard edits; the command-line install is pinned to a hash. A module cannot widen the policy: it can only ask for what the policy already admits |
| Panel → outside | Webhook receivers, OAuth providers, the module host | Outbound only. Webhook URLs come from the environment, never from `config.yaml`, and are redacted from logs and errors |
| Disk → attacker | Files at rest | Secrets in the settings and game files are sealed by the vault (a key that is not on the same disk as the data if you set `CROWSNEST_MASTER_KEY`); the state snapshot never contains the vault key or the session secret |

## Threats and what answers them

| Threat | Answer | Residual risk |
|---|---|---|
| Stolen or guessed passphrase | bcrypt (cost 12, upgraded at sign-in), throttling, optional TOTP, per-device sign-out, "revoke sessions" | No second factor is *required* yet; passkeys are not supported (roadmap P3) |
| Stolen session cookie | Server-side session list (sign out the device), absolute session limit, per-user revocation marker | A cookie stolen from a signed-in browser works until it ends or is revoked |
| CSRF / XSS | CSRF token, `SameSite=Lax`, nonce CSP, output escaping in templates | The dashboard JS was skimmed in the 2026-11-12 review, not audited |
| A bug lets a player act as admin | Server-side role checks on every route, not only in the UI | Players can start and stop games by design; that is the point of the role |
| Compromised panel process | It has no socket; the guard confines what Docker calls it can make; the exec allowlist and policy bound the rest | The panel still controls the games in its scope (start, stop, delete their data), and holds the vault key in memory |
| Malicious or careless module | Signed installs, hash-pinned CLI installs, no code in a module, policy envelope, `crowsnest module check` | A trusted publisher's signed module that asks for something the policy already allows will get it; keep the policy tight. Game images are pulled by tag unless a module pins a digest |
| A game container escapes or attacks its neighbours | Capabilities dropped and no-new-privileges on CrowsNest's own containers; per-game networks; no host bind outside the games folder | A kernel or runtime escape is out of scope; the images are other people's code |
| Someone rewrites history after a break-in | The audit file's hash chain (`crowsnest audit verify`) | Whole-file rewrites and tail truncation are not detectable from the file alone; copy the last hash or ship the file elsewhere |
| Lost or leaked backups | Backups stay on the folder you choose; offsite copy is the operator's `rclone` remote | Backups are not encrypted by CrowsNest; encrypt the remote |
| Unreachable notification channel hides an incident | Retries, then a dashboard banner naming the failing channel | A notification is best effort, not a guarantee |
| Supply chain (CrowsNest's own image) | Images are built in CI, scanned (Trivy, amd64 and arm64), carry an SBOM and provenance and are signed with cosign; Actions are pinned by commit | You have to verify the signature yourself (`cosign verify`, see [publishing](publishing.md)) |

## Out of scope

These are assumptions, the same as in [SECURITY.md](../SECURITY.md):

- An attacker who already controls the host, the Docker socket or `policy.yaml` has won.
- Running on the open internet without HTTPS, or with the raw Docker socket mounted into the panel (`crowsnest
  doctor` warns about both).
- Vulnerabilities inside a game server image.
- Players' own devices and the game's own protocol security (see [connecting](connecting.md) for why the panel
  does not proxy game traffic).
