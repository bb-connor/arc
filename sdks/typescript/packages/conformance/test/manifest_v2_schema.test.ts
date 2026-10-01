import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "@chio-protocol/node-http";

import type { Security_SignedToolManifestV2 } from "../src/_generated/index.js";
import { canonicalizeJson } from "../../../chio-ts/src/invariants/json.ts";

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(workspaceRoot, "spec/schemas/chio-wire/v1");
const corpus = JSON.parse(
  readFileSync(resolve(workspaceRoot, "tests/bindings/fixtures/manifest-v2-consumers.json"), "utf8"),
) as {
  cases: Array<{
    name: string;
    schema_file: string;
    valid: boolean;
    instance: Security_SignedToolManifestV2.ChioSignedToolManifestV2 | Record<string, unknown>;
  }>;
};
const validateWire = createWireSchemaValidator(
  ["tool-flow-declaration", "tool-manifest-v2", "signed-tool-manifest-v2"].map((name) =>
    JSON.parse(readFileSync(resolve(schemaRoot, `security/${name}.schema.json`), "utf8")),
  ),
);

describe("current manifest consumer wire corpus", () => {
  it("retains the complete shared inventory", () => {
    expect(corpus.cases).toHaveLength(14);
  });

  for (const fixture of corpus.cases) {
    it(fixture.name, () => {
      expect(validateWire(`https://chio.world/schemas/chio-wire/v1/${fixture.schema_file}`, fixture.instance)).toBe(fixture.valid);
      if (fixture.valid) {
        expect(JSON.parse(JSON.stringify(fixture.instance))).toEqual(fixture.instance);
        expect(createHash("sha256").update(canonicalizeJson(fixture.instance)).digest("hex")).toBe(
          "4f9a91d6859c909e118bc89d1645d20da15fc3ac90aae26c4d796e3c56e8d603",
        );
      }
    });
  }
});
