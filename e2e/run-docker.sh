#!/bin/sh
# Runs the browser tests in the official Playwright image, so no browser is installed on the host. The panel under
# test is the Go test server (internal/web/e2e_server_test.go), started here and reached over the host network.
set -eu
cd "$(dirname "$0")/.."
PORT="${E2E_PORT:-18765}"
E2E_ADDR="127.0.0.1:$PORT" go test ./internal/web -run TestE2EServer -count=1 -timeout 0 -v >/tmp/crowsnest-e2e-server.log 2>&1 &
SERVER=$!
trap 'kill -INT $SERVER 2>/dev/null || true; pkill -INT -f "[w]eb.test" 2>/dev/null || true' EXIT
for _ in $(seq 1 120); do
  curl -sf "http://127.0.0.1:$PORT/login" >/dev/null && break
  sleep 1
done
docker run --rm --network host --ipc=host -e CI -e E2E_PORT="$PORT" -e E2E_EXTERNAL_SERVER=1 \
  -v "$PWD/e2e:/work" -w /work mcr.microsoft.com/playwright:v1.49.1-noble \
  sh -c 'npm ci --no-audit --no-fund >/dev/null && npx playwright test "$@"' sh "$@"
