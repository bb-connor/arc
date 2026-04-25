// Playwright configuration for the Chio Evidence Console.
//
// Two run modes:
//
// 1. Standalone (developer laptop): no CHIO_E2E_BASE_URL set. Playwright
//    auto-starts `bun run start` against the good-bundle fixture on port 3211.
//
// 2. Smoke-driven (CI-style, via smoke.sh): the harness starts a Next server
//    pointing at the freshly produced ARTIFACT_ROOT and exports
//    CHIO_E2E_BASE_URL. Playwright uses that URL and does NOT launch its own
//    server. The harness is responsible for teardown.
//
// Setting CHIO_E2E_NO_WEBSERVER=1 also disables the built-in webServer, for
// cases where the caller wants to manage lifecycle manually.

import { defineConfig, devices } from "@playwright/test";
import path from "node:path";

const baseURL = process.env.CHIO_E2E_BASE_URL ?? "http://127.0.0.1:3211";
const externalServer = Boolean(
  process.env.CHIO_E2E_BASE_URL || process.env.CHIO_E2E_NO_WEBSERVER,
);
const fixtureBundleDir = path.resolve(__dirname, "tests/fixtures/good-bundle");

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report" }],
  ],
  use: {
    baseURL,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: externalServer
    ? undefined
    : {
        command: "bun run start",
        env: {
          CHIO_BUNDLE_DIR: fixtureBundleDir,
          PORT: "3211",
        },
        url: "http://127.0.0.1:3211/api/health",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
