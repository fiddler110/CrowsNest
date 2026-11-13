# CrowsNest — Roadmap

Single source of truth for work that is **still to do**. Finished work lives in
[`CHANGELOG.md`](CHANGELOG.md); the design detail behind the modular-games rework is in
[`docs/modularization-plan.md`](docs/modularization-plan.md). When an item lands, delete it here and add it to
`CHANGELOG.md` with the date.

Origin: a full-repo review (2026-09-12), the modular-games design review and
the accounts/settings review (2026-11-08/09).

## Active roadmap

Three tracks that share one path: **A. Modular games** (the phased rework),
**B. Accounts and settings** (largely rides on the modules), and **C. Verify
and harden** (open checks against real servers). Phase numbers match
`docs/modularization-plan.md`. Phases 0, 1, 3, 4 and 5 are done (see `CHANGELOG.md`).

### Priority order (review of 2026-11-12)

A full review of the platform and repository at `35f22b6` (v0.13.0). `go vet` and `go test ./...` passed and
`govulncheck` found nothing reachable. The findings come from reading the code, not from live exploitation;
`dockerguard`'s rules, `managed.go`, `exclusivity` and the dashboard JS were skimmed, not audited (the guard had
its own review and fuzzing on 2026-11-10). IDs are stable so commits can refer to them. Work the tiers in order;
inside a tier, top to bottom. Items that already live in track A, B or C are named here and stay tracked there.

#### P0: do now (small, and each closes a real gap)

- [ ] **R4 (ops). Upgrade production from 0.11.0 to 0.13.0.** The operator's step: run `template-check.sh`,
  compare compose and config, then pull and recreate. It signs everyone out once, and Minecraft, Source and
  Don't Starve Together are no longer bundled.
- [ ] **R5 (ops). Finish the Phase 5 live checks on the test stack:** "Make a copy" in the browser, a positive
  signed install from a public URL, the module-update diff, the offsite status banner, and Start→Switch from
  the browser (track C).

#### P1: next (security design and data safety)

- [ ] **Try the signed-module Allow switch on a real guard** (mount the modules folder, add a key to `policy.yaml`, install a signed module, switch it on, start it).
- [ ] **Try passkeys in a real browser** (Windows Hello, a phone, a security key): the server side is tested with a software authenticator only.
- [ ] **Track C checks against real servers:** idle and night auto-stop with Discord notices, the Windrose
  invite-code join, crash-loop detection against a container that really crashes, and each restore command on a
  real world (track B, Backups).

#### P2: reliability, tests and release hygiene

Done (R15 to R23); see `CHANGELOG.md`.

#### P3: features, in build order

Done (passkeys, the Allow switch); see `CHANGELOG.md`. What is left of them is the two real-world checks in P1.

#### P4: larger design work

- [ ] **R24. A separate minimal guard image.** The guard holds the Docker socket but runs the full panel image
  with the docker CLI and compose in it. Build a guard-only image (static binary, no shell).
- [ ] **Phase 6** (track A): drop the docker CLI and compose from the panel image; makes R24 simpler.
- [ ] **Tier 2 adapter-sidecar contract** (track A, Phase 2), when a module needs it.

### A. Modular games (open)

- [ ] **Phase 2 leftovers:** verify the Windrose log markers on a graceful quit; the Tier 2 adapter-sidecar
  contract is deferred until a module needs it.
- [ ] **Phase 5 leftovers:** installing a module whose image the
  policy does not list (shown as "needs policy lines"). The extra port range is edited in `policy.yaml`.
- [ ] **Phase 6 (optional):** drop the docker CLI and compose from the image (create containers through the Engine
  API behind the guard); also removes the compose-from-source Dockerfile stage and its x/net CVE churn.

### B. Accounts and settings (open)

- [ ] **Per-user permissions:** a CLI command for the game allowlist, and per-game *actions* (may start, not stop).
- [ ] **Profile page:** email/avatar, naming a device, an admin view of other people's sessions, and showing the
  new sign-in notice beyond the Account page (dashboard banner, Discord; see R19).
- [ ] **Sign-in:** editing the `name=email`
  env allowlist, requiring MFA for players,
  encrypting the users file.
- [ ] **Backups:** a restore for config-file games; try each restore command on a real world; config-file games still back up
  inside their own data and would need the bind added by hand; an optional host-side mount check.
- [ ] **File editing, next steps:** a Save-and-restart button, per-format validation (JSON first), and `files:` for
  Source, Don't Starve Together and 7 Days to Die. **Palworld:** its image rebuilds the whole
  `PalWorldSettings.ini` from environment variables on every start, so nothing declared there would last; it needs
  the module to set `DISABLE_GENERATE_SETTINGS=true` (after which the form options stop applying to the file) or a
  per-setting editor. Windrose's world settings (`WorldDescription.json`, under a world id and version folder) need a glob or directory form
  of `files:`. A settings editor in the module form, with named fields, would serve both games better than raw files.
  A stopped-game edit for games set up in `config.yaml`.
- [ ] Crash-loop detection is untested against a real crashing container (also in track C).

### C. Verify and harden (open, against real servers)

- [ ] **Start→Switch from the browser UI itself** (done via the API on 2026-11-12).
- [ ] **Windrose invite-code join** from the LAN and from outside, on the macvlan setup.
- [ ] **Valheim crossplay join code and player names** on a real server with `CROSSPLAY=1` (the log patterns are from
  the known format, not a capture).
- [ ] **Idle/night auto-stop and Discord notifications** against real servers (idle auto-stop fired on the test
  stack; Discord notices untested, no webhook there); check firewall for `:5001`/game ports.

### Backlog (parked, come back to it later)

- [ ] **Discord slash commands** (track B). Parked by the owner on 2026-11-12. Needs a Discord application and its
  public key before it can start.

### Considered, not doing

- Go `plugin` package or in-process plugins: they would run inside the panel's trust boundary. WASM (wazero)
  stays an option once the adapter contract is stable.
