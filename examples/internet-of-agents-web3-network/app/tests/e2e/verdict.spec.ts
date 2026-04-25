// Verdict smoke. The good-bundle fixture carries review.ok=true, so the
// top-bar verdict pill must render PASS and the core meta items must populate
// non-empty values.

import { expect, test } from "@playwright/test";

test.describe("verdict pill and topbar meta", () => {
  test("renders PASS and populates all meta items", async ({ page }) => {
    await page.goto("/");

    const topbar = page.getByTestId("topbar");
    await expect(topbar).toBeVisible();

    const pill = page.getByTestId("verdict-pill");
    await expect(pill).toBeVisible();
    await expect(pill).toHaveAttribute("data-verdict", "PASS");
    await expect(pill).toContainText("PASS");

    // Every populated meta item must have a non-empty value. `order` must be
    // present because summary.order_id is required; `bundle` must be a 22+
    // char slice of the canonical manifest digest (either the full digest or
    // truncated with an ellipsis).
    const labels = ["order", "generated", "bundle", "files", "agents", "capabilities"] as const;
    for (const label of labels) {
      const item = topbar.locator(".meta-item", { hasText: label });
      await expect(item, `meta-item for ${label}`).toBeVisible();
      const value = (await item.locator(".meta-v").innerText()).trim();
      expect(value, `meta value for ${label}`).not.toBe("");
    }

    const bundleItem = topbar.locator(".meta-item", { hasText: "bundle" });
    const bundleValue = (await bundleItem.locator(".meta-v").innerText()).trim();
    expect(bundleValue.length, "bundle digest visible length >= 22").toBeGreaterThanOrEqual(22);
  });
});
