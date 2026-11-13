const { test, expect } = require("@playwright/test");
const { USER, signIn } = require("./helpers");

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test("the account page saves a display name", async ({ page }) => {
  await page.goto("/account");
  await expect(page.locator("h1")).toContainText(USER);

  await page.fill('input[name="display_name"]', "Captain");
  await page.click('#profile-form button[type="submit"]');
  await page.reload();
  await expect(page.locator('input[name="display_name"]')).toHaveValue("Captain");
});

test("the settings page loads for an admin", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/settings");
  await expect(page.locator("h1").first()).toBeVisible();
  expect(errors).toEqual([]);
});
