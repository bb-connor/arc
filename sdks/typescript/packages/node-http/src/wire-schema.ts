import { Ajv2020 } from "ajv/dist/2020.js";

/**
 * Build a public wire-shape validator from authoritative, version-pinned schemas.
 * This does not verify signatures, choose trusted keys, or authorize execution.
 * Schema compilation fails at construction; unknown schema IDs reject at use.
 *
 * Values must already be parsed JSON. Duplicate keys cannot be recovered after
 * JSON.parse and require a duplicate-rejecting ingress parser. This portable
 * number profile rejects integers outside JavaScript's safe-integer domain,
 * rather than signing or forwarding a potentially rounded authorization value.
 */
export function createWireSchemaValidator(
  schemas: readonly object[],
): (schemaId: string, value: unknown) => boolean {
  const ajv = new Ajv2020({ allErrors: false, strict: false });
  for (const schema of schemas) ajv.addSchema(schema);
  // Compile all references before accepting traffic, not lazily on first use.
  const validators = new Map<string, ReturnType<typeof ajv.compile>>();
  for (const schema of schemas) {
    const id = (schema as { $id?: unknown }).$id;
    if (typeof id !== "string" || id.length === 0) {
      throw new Error("wire schema requires an explicit identity");
    }
    const validate = ajv.getSchema(id);
    if (!validate) throw new Error("wire schema could not be compiled");
    if ("$async" in validate && validate.$async === true) {
      throw new Error("wire schema validation must be synchronous");
    }
    validators.set(id, validate);
  }
  return (schemaId, value) => {
    const validate = validators.get(schemaId);
    return validate !== undefined && preservesJsonNumbers(value, 0) && validate(value) === true;
  };
}

function preservesJsonNumbers(value: unknown, depth: number): boolean {
  if (depth > 64) return false;
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") {
    return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  }
  if (Array.isArray(value)) {
    return value.every((item) => preservesJsonNumbers(item, depth + 1));
  }
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.values(value).every((item) => preservesJsonNumbers(item, depth + 1));
  }
  return false;
}
