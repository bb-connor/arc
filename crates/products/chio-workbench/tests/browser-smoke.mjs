// Run against `cargo run -p chio-workbench --example browser_fixture`.
// PLAYWRIGHT_MODULE points to an installed playwright/index.mjs.
import assert from "node:assert/strict";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE || "playwright"
);
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHROMIUM_PATH
    ? { executablePath: process.env.CHROMIUM_PATH }
    : {}),
});
try {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(process.argv[2]);
  await page
    .locator("#model")
    .filter({ hasText: "scripted-test-provider" })
    .waitFor();
  assert.equal(new URL(page.url()).hash, "");
  await page.screenshot({
    path: "/tmp/chio-workbench-start.png",
    fullPage: true,
  });
  await page
    .locator("#prompt")
    .fill("Fix the addition bug in calc.py and verify the result.");
  await page.locator("#start").click();
  await page
    .locator("#run-status .badge.succeeded")
    .waitFor({ timeout: 60000 });
  assert.equal(await page.locator(".task").count(), 3);
  assert.equal(await page.locator(".action").count(), 7);
  assert.deepEqual(await page.locator(".action-state").allTextContents(), [
    "succeeded",
    "failed",
    "succeeded",
    "succeeded",
    "succeeded",
    "succeeded",
    "succeeded",
  ]);
  assert.equal(
    await page.locator(".action-state").filter({ hasText: "failed" }).count(),
    1,
  );
  await page.locator(".action").first().locator("summary").click();
  await page
    .locator(".action")
    .first()
    .getByText("Signed kernel receipt", { exact: true })
    .waitFor();
  await page.screenshot({
    path: "/tmp/chio-workbench-run.png",
    fullPage: true,
  });
  await page.reload();
  await page.locator(".run-link").first().click();
  await page.locator("#run-status .badge.succeeded").waitFor();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: "/tmp/chio-workbench-mobile.png",
    fullPage: true,
  });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    true,
  );
  assert.deepEqual(errors, []);
  console.log(
    "Browser smoke passed: real delegated repair, seven receipts, persisted history, mobile layout.",
  );
} finally {
  await browser.close();
}
