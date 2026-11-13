// @ts-check
const { defineConfig } = require("@playwright/test");

const port = process.env.E2E_PORT || "18765";

module.exports = defineConfig({
  testDir: "./tests",
  workers: 1, // the specs share one panel and one fake docker
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { baseURL: `http://127.0.0.1:${port}`, trace: "retain-on-failure" },
  webServer: process.env.E2E_EXTERNAL_SERVER ? undefined : {
    // The Go test is the server: the real dashboard code over a fake docker (internal/web/e2e_server_test.go).
    command: "go test ./internal/web -run TestE2EServer -count=1 -timeout 0",
    cwd: "..",
    env: { E2E_ADDR: `127.0.0.1:${port}` },
    url: `http://127.0.0.1:${port}/login`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
  },
});
