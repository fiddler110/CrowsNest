const { test, expect } = require("@playwright/test");
const { PASSWORD, signIn, card } = require("./helpers");

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test("restoring a backup asks for the password, then warns that a stopped game has no safety backup", async ({ page }) => {
  const charlie = card(page, "charlie");
  await charlie.locator('.tab[data-tab="backups"]').click();
  await expect(charlie.locator(".backups-list li")).toHaveCount(1);
  await charlie.locator(".restore-btn").click();

  // The first dialog wants the account password.
  await expect(page.locator("#confirm-title")).toContainText("Restore charlie");
  await expect(page.locator("#confirm-password")).toBeVisible();

  // A wrong password is refused and nothing is restored.
  await page.fill("#confirm-password", "not-the-password");
  await page.click("#confirm-ok");
  await expect(page.locator("#toasts")).not.toBeEmpty();

  // The right one gets to the second dialog: the game is stopped, so no safety backup can be taken first.
  await charlie.locator(".restore-btn").click();
  await page.fill("#confirm-password", PASSWORD);
  await page.click("#confirm-ok");
  await expect(page.locator("#confirm-title")).toContainText("charlie is stopped");
  await expect(page.locator("#confirm-ok")).toHaveText("Restore without a backup");

  // Cancelling leaves the backup in place and the button usable again.
  await page.click("#confirm-cancel");
  await expect(page.locator("#confirm-dialog")).toBeHidden();
  await expect(charlie.locator(".restore-btn")).toBeEnabled();
});
