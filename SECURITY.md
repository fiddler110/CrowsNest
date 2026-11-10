# Security policy

CrowsNest controls Docker on the host it runs on, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead: on the repository page choose
**Security -> Report a vulnerability**. If that is not available to you, email scottymacleod110@gmail.com. Include what you found, the version (`docker compose images`), and the
steps to reproduce it. You will get an answer as soon as the maintainer can give one; this is a small project, so
please allow a few days.

Once a fix is released the report can be made public, and you will be credited if you wish.

## What is in scope

- Getting around sign-in, roles, sessions or CSRF protection.
- Getting the panel, a game container or a module to do more than the Docker guard, execguard and
  `policy.yaml` allow: extra containers, binds, ports, networks, capabilities or exec commands.
- Reading secrets (game passwords, session secret, setup code) without being an admin.
- Remote code execution or a path from a game container to the host.

## Not in scope

- Bugs in the game servers' images, which are built by other people (CrowsNest limits what they may do, and can
  pin them by digest).
- Anything that needs the attacker to already control the host, the Docker socket or `policy.yaml`.
- Running CrowsNest on the open internet without HTTPS, or with the raw Docker socket (`crowsnest doctor` warns
  about both).

## Supported versions

Only the latest release gets fixes.
