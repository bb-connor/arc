// Run against `cargo run -p chio-workbench --example browser_fixture`.
// PLAYWRIGHT_MODULE points to an installed playwright/index.mjs.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
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
  const gitTasks = process.env.CHIO_BROWSER_GIT === "1";
  assert.equal(await page.locator("#workspace-mode").isVisible(), gitTasks);
  const source = await page.locator("#workspace").textContent();
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
  if (gitTasks) {
    await page.locator("#review-changes").click();
    await page.locator("#change-patch").waitFor();
    const patch = await page.locator("#change-patch").textContent();
    assert.ok(patch.includes("-    return a - b\n+    return a + b"));
    assert.ok((await readFile(`${source}/calc.py`, "utf8")).includes("return a - b"));
    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.locator("#download-patch").click(),
    ]);
    await download.saveAs("/tmp/chio-workbench-review.patch");
    const bytes = await readFile("/tmp/chio-workbench-review.patch");
    assert.equal(bytes.toString("utf8"), patch);
    assert.ok((await page.locator("#change-status").textContent()).includes(createHash("sha256").update(bytes).digest("hex")));
  }
  await page.screenshot({
    path: "/tmp/chio-workbench-run.png",
    fullPage: true,
  });
  await page.reload();
  await page.locator(".run-link").first().click();
  await page.locator("#run-status .badge.succeeded").waitFor();
  if (gitTasks) {
    await page.locator("#review-changes").click();
    await page.locator("#change-patch").waitFor();
  }
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
    `Browser smoke passed: real delegated repair, seven receipts, persisted history, mobile layout${gitTasks ? ", source preservation and patch download" : ""}.`,
  );
} finally {
  await browser.close();
}
