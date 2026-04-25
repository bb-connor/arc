// Graph smoke. Asserts that the four-quadrant topology renders the expected
// quad boxes and a sensible number of sidecar hexes, and that the edge
// popover surfaces scope-or-reason metadata when a mediated edge gets
// pointer focus.
//
// SVG path elements are narrow and awkward to hover via pointer
// coordinates, so we step along the path's bounding box until the
// popover appears. This is deterministic at the 1000x700 viewBox the
// app renders at.

import { expect, test } from "@playwright/test";

test.describe("graph topology", () => {
  test("renders quads, sidecars, and mediated edge popover", async ({ page }) => {
    await page.goto("/");

    const graph = page.getByTestId("graph");
    await expect(graph).toBeVisible();

    // Four organizations => four quad boxes.
    await expect(graph.locator(".quad-box")).toHaveCount(4);

    // At least three sidecar hex groups (atlas market broker, meridian
    // settlement desk, plus proofworks subcontract desk).
    const sidecarCount = await graph.locator(".sidecar-node").count();
    expect(sidecarCount).toBeGreaterThanOrEqual(3);

    const mediatedEdge = graph.locator(".edge.mediated").first();
    await expect(mediatedEdge).toBeAttached();

    // Walk pointer along the bounding box midline until the popover
    // appears. Covers SVG paths whose visible pixels do not line up with
    // the geometric center of the bounding rectangle.
    const box = await mediatedEdge.boundingBox();
    expect(box, "mediated edge has a bounding box").not.toBeNull();
    if (box) {
      const steps = 32;
      const popover = page.locator(".edge-popover");
      for (let i = 0; i <= steps; i += 1) {
        const t = i / steps;
        const x = box.x + t * box.width;
        const y = box.y + t * box.height;
        await page.mouse.move(x, y);
        if (await popover.isVisible().catch(() => false)) break;
      }
      await expect(popover).toBeVisible();
      const text = await popover.innerText();
      // Mediated edges always carry a label; they may carry scope or
      // (for denials/intra) reason/rule metadata. Accept either.
      const hasScope = /scope/i.test(text);
      const hasReason = /(rule|reason)/i.test(text);
      expect(hasScope || hasReason, `popover text: ${text}`).toBe(true);
    }
  });
});
