const { test, expect } = require("@playwright/test");
const { signIn } = require("./helpers");

test("add a game from the Games page", async ({ page }) => {
  await signIn(page);
  await page.goto("/games");
  await page.click("#module-demo");
  await page.fill('input[name="display_name"]', "Family Demo");
  await page.fill('input[name="id"]', "family-demo");
  await expect(page.locator("#enable")).toBeEnabled();
  await page.click("#enable");
  await expect(page.locator("#progress-title")).toContainText("is ready", { timeout: 20_000 });
  await expect(page.locator("#progress-done")).toBeVisible();
});
