import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "@chio-protocol/node-http";

import type { Security_SignedToolManifestV1 } from "../src/_generated/index.js";
import { canonicalizeJson } from "../../../chio-ts/src/invariants/json.ts";

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(workspaceRoot, "spec/schemas/chio-wire/v1");
const corpus = JSON.parse(
  readFileSync(resolve(workspaceRoot, "tests/bindings/fixtures/manifest-consumers.json"), "utf8"),
) as {
  cases: Array<{
    name: string;
    schema_file: string;
    valid: boolean;
    instance: Security_SignedToolManifestV1.ChioSignedToolManifestV1 | Record<string, unknown>;
  }>;
};
const vector = readFileSync(resolve(workspaceRoot, "tests/bindings/vectors/security/cage/positive/signed-tool-manifest-v1.json"), "utf8");
const validateWire = createWireSchemaValidator(
  ["tool-flow-declaration", "tool-manifest-v1", "signed-tool-manifest-v1"].map((name) =>
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
        expect(canonicalizeJson(fixture.instance)).toBe(vector);
      }
    });
  }
});
