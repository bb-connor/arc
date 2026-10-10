import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "../../node-http/src/wire-schema.js";
import { assertFoundationRecoveryWire } from "../../node-http/src/recovery-wire-profile.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(root, "spec/schemas/chio-wire/v1");
const schemas = readdirSync(schemaRoot, { withFileTypes: true })
  .filter(entry => entry.isDirectory())
  .flatMap(entry => readdirSync(resolve(schemaRoot, entry.name))
    .filter(name => name.endsWith(".schema.json"))
    .flatMap(name => {
      const schema = JSON.parse(readFileSync(resolve(schemaRoot, entry.name, name), "utf8")) as { $id?: string };
      if (schema.$id === undefined) return [];
      const aliases = ["chio.computer", "chio.world"]
        .map(domain => `https://${domain}/schemas/chio-wire/v1/${entry.name}/${name}`)
        .filter(id => id !== schema.$id);
      return [schema, ...aliases.map(id => ({ ...schema, $id: id }))];
    }));
const validate = createWireSchemaValidator(schemas);
const files: Record<string, string> = {
  approval_submission: "approval-submission",
  approval_intent: "approval-intent",
  command: "command",
  grant_binding: "grant-binding",
  action: "action-intent",
};
type Vector = {
  name: string;
  contract: string;
  wire: string;
  schema_valid: boolean;
  wire_profile_valid: boolean;
  rust_typed_valid: boolean;
  nested_approval_valid?: boolean;
};
const corpus = JSON.parse(readFileSync(resolve(root, "spec/vectors/recovery/v1/byte-boundaries.json"), "utf8")) as {
  format_version: number;
  vectors: Vector[];
};

describe("same structural approval and epoch bytes", () => {
  it("requires a nonempty supported corpus", () => {
    expect(corpus.format_version).toBe(1);
    expect(corpus.vectors.length).toBeGreaterThan(0);
    expect(new Set(corpus.vectors.map(vector => vector.name)).size).toBe(corpus.vectors.length);
  });
  for (const vector of corpus.vectors) it(vector.name, () => {
    const file = files[vector.contract];
    expect(file).toBeDefined();
    const shape = validate(`https://chio.world/schemas/chio-wire/v1/recovery/${file}.schema.json`, JSON.parse(vector.wire));
    expect(shape).toBe(vector.schema_valid);
    let profile = true;
    try {
      assertFoundationRecoveryWire(vector.wire);
    } catch {
      profile = false;
    }
    expect(profile).toBe(vector.wire_profile_valid);
    expect(shape && profile).toBe(vector.rust_typed_valid);
    if (vector.nested_approval_valid !== undefined) {
      const envelope = JSON.parse(vector.wire) as { command: { approval: string } };
      expect(typeof envelope.command.approval).toBe("string");
      assertFoundationRecoveryWire(envelope.command.approval);
      expect(validate("https://chio.world/schemas/chio-wire/v1/recovery/approval-submission.schema.json", JSON.parse(envelope.command.approval)))
        .toBe(vector.nested_approval_valid);
    }
  });
});
