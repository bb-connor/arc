import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("preserves the public recovery grant integer type for existing consumers", () => {
  const workspace = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
  const source = resolve(workspace, "sdks/typescript/packages/conformance/src");
  const publicEntry = readFileSync(join(source, "index.ts"), "utf8");
  const namespaceExport = publicEntry.match(/^export \* as Schemas from "\.\/_generated\/index\.js";$/m)?.[0];
  expect(namespaceExport, "the public schema namespace must remain exported").toBeDefined();
  const temporary = mkdtempSync(join(tmpdir(), "chio-public-schema-consumer-"));
  try {
    mkdirSync(join(temporary, "_generated"));
    copyFileSync(join(source, "_generated/index.ts"), join(temporary, "_generated/index.ts"));
    writeFileSync(join(temporary, "index.ts"), `${namespaceExport}\n`);
    writeFileSync(join(temporary, "consumer.ts"), [
      'import type { Schemas } from "./index.js";',
      "export type Epoch = Schemas.Recovery_GrantBinding.SafeInteger;",
      "export const epoch: Epoch = 1;",
      "",
    ].join("\n"));
    execFileSync(process.execPath, [
      resolve(workspace, "sdks/typescript/node_modules/typescript/bin/tsc"),
      "--noEmit", "--strict", "--skipLibCheck", "--target", "ES2022",
      "--module", "Node16", "--moduleResolution", "Node16",
      join(temporary, "consumer.ts"),
    ], { encoding: "utf8", timeout: 20_000, maxBuffer: 64 * 1024 });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
