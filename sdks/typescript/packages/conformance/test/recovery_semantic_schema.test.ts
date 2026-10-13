import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "../../node-http/src/wire-schema.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(root, "spec/schemas/chio-wire/v1");
const schemas = readdirSync(schemaRoot, { withFileTypes: true })
  .filter(entry => entry.isDirectory())
  .flatMap(group => readdirSync(resolve(schemaRoot, group.name))
    .filter(name => name.endsWith(".schema.json"))
    .flatMap(name => {
      const schema = JSON.parse(readFileSync(resolve(schemaRoot, group.name, name), "utf8")) as { $id?: string };
      if (schema.$id === undefined) return [];
      const aliases = ["chio.computer", "chio.world", "chio-protocol.dev"]
        .map(domain => `https://${domain}/schemas/chio-wire/v1/${group.name}/${name}`)
        .filter(id => id !== schema.$id);
      return [schema, ...aliases.map(id => ({ ...schema, $id: id }))];
    }));
const validate = createWireSchemaValidator(schemas);
const corpus = JSON.parse(readFileSync(resolve(root, "spec/vectors/recovery/v1/semantic-contracts.json"), "utf8")) as {
  format_version: number;
  vectors: { name: string; schema: string; wire: string; schema_valid: boolean }[];
};

describe("semantic finite local semantic contracts", () => {
  it("uses the shared versioned corpus", () => expect(corpus.format_version).toBe(1));
  for (const vector of corpus.vectors) {
    it(vector.name, () => {
      const id = `https://chio.computer/schemas/chio-wire/v1/recovery/${vector.schema}`;
      expect(validate(id, JSON.parse(vector.wire))).toBe(vector.schema_valid);
    });
  }
});
