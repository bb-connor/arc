// Explorer smoke. Section count is pinned to SECTIONS in lib/paths.ts.
// Selecting summary.json surfaces a matching computed hash, and the filter
// input (activated via the "/" key) narrows the tree.

import { expect, test } from "@playwright/test";

// Keep in sync with SECTIONS in lib/paths.ts. Hardcoded on purpose so a
// silent drift in paths.ts surfaces as a test failure rather than a
// tautology.
const EXPECTED_SECTION_COUNT = 16;

test.describe("explorer tree and json viewer", () => {
  test("tree groups match SECTIONS and summary.json selects with matching hash", async ({ page }) => {
    await page.goto("/");

    const explorer = page.getByTestId("explorer");
    await expect(explorer).toBeVisible();

    // Wait for manifest to load (otherwise tree-group count would be 0).
    await expect(explorer.locator(".tree-group").first()).toBeVisible();

    const groupCount = await explorer.locator(".tree-group").count();
    expect(groupCount).toBe(EXPECTED_SECTION_COUNT);

    // The Verdict section is collapsed by default. Expand it and click
    // summary.json. Console wires the active beat's first artifact into
    // selectedPath on mount, so the initial json-header path is not
    // deterministic; explicit click is the stable path.
    const verdictGroup = explorer.locator(".tree-group", { hasText: "Verdict" }).first();
    const verdictHeader = verdictGroup.locator(".tree-row").first();
    await verdictHeader.click();

    const summaryRow = verdictGroup.locator(".tree-row", { hasText: /^summary\.json$/ }).first();
    await expect(summaryRow).toBeVisible();
    await summaryRow.click();

    const header = explorer.locator(".json-header .path");
    await expect(header).toHaveText("summary.json");

    // The computed hash row should carry the .match class once the
    // in-browser SHA-256 verifies against the manifest entry.
    const computedValue = explorer.locator(".json-header .hv.match").first();
    await expect(computedValue).toBeVisible();
  });

  test("pressing / focuses the filter and text narrows the tree", async ({ page }) => {
    await page.goto("/");

    const explorer = page.getByTestId("explorer");
    await expect(explorer).toBeVisible();

    const filterInput = explorer.locator(".tree-filter input");
    await expect(filterInput).toBeVisible();

    // Focus the document first so the "/" hotkey binding fires.
    await page.locator("body").click();
    await page.keyboard.press("/");
    await expect(filterInput).toBeFocused();

    // "receipts" matches the chio/receipts/... paths only. Enough to
    // narrow away most sections but keep at least the chio group.
    await filterInput.fill("receipts");

    const visibleGroups = await explorer.locator(".tree-group").count();
    expect(visibleGroups).toBeLessThan(EXPECTED_SECTION_COUNT);
    expect(visibleGroups).toBeGreaterThanOrEqual(1);

    // At least one receipt file should be reachable.
    const receiptRow = explorer.locator(".tree-row", { hasText: /receipts\// }).first();
    await expect(receiptRow).toBeVisible();
  });
});
