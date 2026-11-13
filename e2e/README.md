# Browser tests

Playwright specs for the dashboard: sign in, start/stop/switch, add a game, restore, the account page.

The panel under test is the real dashboard code over a fake docker: `TestE2EServer` in
`internal/web/e2e_server_test.go` serves it on `E2E_ADDR` (skipped when that is unset). The fake docker keeps
container state in files, so a started game stays started. One admin user: `admin` / `correct-horse-battery`.

```sh
./e2e/run-docker.sh                       # the whole suite, browser in the official Playwright image
./e2e/run-docker.sh games --repeat-each=5 # extra arguments go to `playwright test`
```

The script starts the Go server on the host and runs the browser container on the host network, so the only
requirements are Go and Docker. To use a browser installed on the host instead: `cd e2e && npm ci &&
npx playwright install chromium && npx playwright test` (the config then starts the Go server itself).

Specs share one server and one fake docker, so they run one at a time and leave the games stopped.
