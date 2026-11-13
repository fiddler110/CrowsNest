const { expect } = require("@playwright/test");

const USER = "admin";
const PASSWORD = "correct-horse-battery";

async function signIn(page) {
  await page.goto("/login");
  await page.fill('input[name="username"]', USER);
  await page.fill('input[name="password"]', PASSWORD);
  await page.click("#submit");
  await expect(page).toHaveURL(/\/$/);
}

const card = (page, id) => page.locator(`.game-card[data-id="${id}"]`);

module.exports = { USER, PASSWORD, signIn, card };
