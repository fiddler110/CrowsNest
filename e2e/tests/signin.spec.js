const { test, expect } = require("@playwright/test");
const { USER, signIn } = require("./helpers");

test("the dashboard needs a sign-in", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login/);
});

test("a wrong password is refused and the right one gets in", async ({ page }) => {
  await page.goto("/login");
  await page.fill('input[name="username"]', USER);
  await page.fill('input[name="password"]', "not-the-password");
  await page.click("#submit");
  await expect(page).toHaveURL(/\/login/);
  await signIn(page);
  await expect(page.locator(".game-card")).toHaveCount(3);
});

test("signing out ends the session", async ({ page }) => {
  await signIn(page);
  await page.request.post("/logout", { headers: { "X-CSRF-Token": await page.locator('meta[name="csrf-token"]').getAttribute("content") } });
  await page.goto("/");
  await expect(page).toHaveURL(/\/login/);
});
