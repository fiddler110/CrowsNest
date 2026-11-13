const { test, expect } = require("@playwright/test");
const { signIn, card } = require("./helpers");

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test("start and stop a game", async ({ page }) => {
  const alpha = card(page, "alpha");
  await expect(alpha).toBeVisible();
  await alpha.locator(".start-btn").click();
  await expect(alpha).toHaveAttribute("data-status", "online", { timeout: 20_000 });
  await expect(alpha.locator(".start-btn")).toBeDisabled();

  await alpha.locator(".stop-btn").click();
  await expect(alpha).toHaveAttribute("data-status", "offline", { timeout: 30_000 });
  await expect(alpha.locator(".start-btn")).toBeEnabled();
});

test("starting a second game offers to switch", async ({ page }) => {
  const alpha = card(page, "alpha");
  const bravo = card(page, "bravo");
  await alpha.locator(".start-btn").click();
  await expect(alpha).toHaveAttribute("data-status", "online", { timeout: 20_000 });

  await bravo.locator(".start-btn").click();
  await expect(page.locator("#conflict-confirm")).toBeVisible();
  await page.locator("#conflict-confirm").click();

  await expect(bravo).toHaveAttribute("data-status", "online", { timeout: 30_000 });
  await expect(alpha).toHaveAttribute("data-status", "offline", { timeout: 30_000 });

  // leave the panel as found
  await bravo.locator(".stop-btn").click();
  await expect(bravo).toHaveAttribute("data-status", "offline", { timeout: 30_000 });
});
