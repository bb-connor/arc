// Fail-closed smoke. An empty bundle directory (no bundle-manifest.json)
// must NOT render the main console chrome. Instead the ErrorBanner is
// shown so a missing or corrupted artifact never surfaces as valid
// evidence.
//
// This spec starts its own Next server against the empty-bundle fixture
// on an ephemeral port to keep isolation from the default good-bundle
// server used by other specs.

import net from "node:net";
import path from "node:path";
import { expect, test } from "@playwright/test";

import { spawnNextServer, type SpawnedServer } from "./helpers";

test.describe.configure({ mode: "serial" });

async function pickFreePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close();
        reject(new Error("failed to pick free port"));
      }
    });
  });
}

test.describe("fail-closed when bundle is missing", () => {
  let server: SpawnedServer | null = null;

  test.beforeAll(async () => {
    const appRoot = path.resolve(__dirname, "..", "..");
    const emptyBundle = path.resolve(appRoot, "tests/fixtures/empty-bundle");
    const port = await pickFreePort();
    server = await spawnNextServer({
      port,
      bundleDir: emptyBundle,
      cwd: appRoot,
    });
  });

  test.afterAll(async () => {
    if (server) {
      await server.cleanup();
      server = null;
    }
  });

  test("renders error banner and suppresses topbar", async ({ page }) => {
    if (!server) throw new Error("empty-bundle server failed to start");
    await page.goto(server.baseUrl);

    const banner = page.getByTestId("error-banner");
    await expect(banner).toBeVisible();

    const text = await banner.innerText();
    const mentionsExpected =
      text.includes("bundle-manifest.json") ||
      text.includes("CHIO_BUNDLE_DIR") ||
      /ENOENT|not found/i.test(text);
    expect(mentionsExpected, `banner text did not mention bundle context: ${text}`).toBe(true);

    // Top bar must NOT render while the bundle is unavailable.
    await expect(page.getByTestId("topbar")).toHaveCount(0);
  });
});
