// Narrative smoke. Press "n" to reveal the narrative strip, then "]" to
// advance the active beat. Assert on the active beat index rather than on
// playback state to keep the test stable.

import { expect, test } from "@playwright/test";

test.describe("narrative beats", () => {
  test("toggling with n reveals narrative and ] advances the active beat", async ({ page }) => {
    await page.goto("/");

    // Narrative is hidden by default. Focus body and press "n" to toggle.
    await page.locator("body").click();
    await page.keyboard.press("n");

    const narrative = page.getByTestId("narrative");
    await expect(narrative).toBeVisible();

    const activeBeat = narrative.locator(".beat.active");
    await expect(activeBeat).toHaveCount(1);
    const initialText = (await activeBeat.innerText()).trim();
    expect(initialText.length).toBeGreaterThan(0);

    // Pressing "]" from the body advances by one beat. The active beat's
    // .bn number should change.
    await page.locator("body").click();
    await page.keyboard.press("]");

    const advancedText = (await narrative.locator(".beat.active").innerText()).trim();
    expect(advancedText.length).toBeGreaterThan(0);
    expect(advancedText).not.toBe(initialText);
  });
});
