# Publishing and security scanning

The image is published to `ghcr.io/fiddler110/crowsnest` (public package) by
`.github/workflows/publish.yml`.

## Automatic releases

Every push to `main` runs the CI gate. Once that passes, the workflow builds,
scans, pushes and signs the image, then creates a GitHub Release.

* **Bump:** patch by default (`v0.1.0` → `v0.1.1`). Put `#minor` or `#major`
  in any commit message in the push to raise it.
* **`[skip release]`** in a commit message publishes `:dev` (and `:sha-…`)
  only. No version tag is cut and no release is created.
* Pushing a `v*` tag by hand publishes that version and doesn't create a
  second release. Pre-release tags (`v0.3.0-rc1`) never move `:latest`.
* The git tag is the version. There's no version file to bump.

Tags on every release: `:X.Y.Z`, `:X.Y`, `:latest`, `:sha-<short>`, and `:dev`
(every push to `main`).

## Running a released image

Point your compose file at
`ghcr.io/fiddler110/crowsnest:${CROWSNEST_TAG:-latest}`. To update:

```sh
docker compose pull crowsnest && docker compose up -d crowsnest
```

Pin `CROWSNEST_TAG=0.2.0` in your `.env` to stay on one version. Set it
back to `latest` to follow releases. Watchtower is fine for CrowsNest itself,
but keep it off the game containers. Their labels already opt them out.

Verify a pulled image:

```sh
cosign verify ghcr.io/fiddler110/crowsnest:<version> \
  --certificate-identity-regexp 'https://github.com/fiddler110/CrowsNest/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Security scanning

| What | Tool | Where | Fails on |
|---|---|---|---|
| SAST (patterns) | gosec | `ci.yml` → *SAST + SCA* | medium+ severity and confidence |
| SAST (data flow) | CodeQL `security-extended` | `codeql.yml` | reported to code scanning |
| SCA (Go modules + stdlib, reachability) | govulncheck | `ci.yml` | a vulnerability the code reaches |
| SCA + Dockerfile misconfig + secrets in tree | Trivy fs | `ci.yml` | fixable HIGH/CRITICAL |
| Secrets in git history | gitleaks | `ci.yml` | any |
| Container image (OS packages + every Go binary in it) | Trivy image | `ci.yml` and again in `publish.yml` before push | fixable HIGH/CRITICAL |
| Dependency updates | Dependabot | `dependabot.yml` | opens PRs weekly (gomod, docker, compose, actions) |

`ci.yml` runs on pull requests, weekly (Mondays), on demand, and as the first
job of every publish. gosec and both Trivy scans upload SARIF, so findings show
under **Security → Code scanning** as well as failing the job.

**Exceptions:**
* gosec: a `#nosec Gxxx -- reason` comment on the statement, reviewed like any
  other change.
* Trivy: a `.trivyignore.yaml` entry with a `statement` and an `expired_at`
  date. Prefer fixing over ignoring (see the compose note below).

## Image notes

* **Bases are pinned by digest:** `docker:29.9.3-cli` for the docker CLI,
  `golang:1.26.10-alpine3.24` to build, `alpine:3.24.4` at runtime (with
  `apk upgrade`). Dependabot proposes digest bumps.
* **The compose plugin is built from source:** v5.7.0 at its tagged commit,
  with `golang.org/x/net` bumped to v0.62.0. The released v5.7.0 binary
  carries CVE-2026-78661 (HIGH) and CVE-2026-97045 (MEDIUM) via x/net v0.60.0,
  and no fixed binary exists yet. Once a compose release ships the fix, delete
  the `compose` stage in the Dockerfile and copy the plugin from `docker-cli`
  again.
* **Non-root** (uid 1000), static binaries (`CGO_ENABLED=0`, `-trimpath`),
  and a healthcheck built into the binary.
* **Scan state checked on 2026-11-06:** 0 known vulnerabilities at every
  severity (Trivy 0.76.2), gosec clean at medium+, govulncheck 0 reachable,
  gitleaks clean over all history.

## Repository settings worth enabling

Not set by these files. Do them once in the GitHub UI:
* Branch protection on `main` requiring the `ci` checks, if you start working
  through PRs.
* **Dependabot security updates** (currently disabled) and **private
  vulnerability reporting**.
