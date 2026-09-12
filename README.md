# CrowsNest

A self-hosted web dashboard for controlling game server Docker containers —
start/stop, live logs, status, resource stats — with a built-in guard that
keeps at most **one** game server running at a time and prompts before
switching between them.

This is a ground-up Go rewrite of the original Python/Flask CrowsNest
(single-game, Windrose-only). It is under active development; see the
[implementation plan](docs/implementation-plan.md) for scope and phasing.

## Status

Early scaffolding. Not yet functional as a dashboard — see the
[implementation plan](docs/implementation-plan.md) for what's landing next.

## Planned games (day one)

- Windrose (`indifferentbroccoli/windrose-server-docker`)
- Valheim (`lloesche/valheim-server`)
- Palworld (`thijsvanloef/palworld-server-docker`)

## Development

```bash
go build ./...
go vet ./...
go test ./...

# Run locally
go run ./cmd/crowsnest serve
```

## License

GPLv3 — see [LICENSE](LICENSE).
