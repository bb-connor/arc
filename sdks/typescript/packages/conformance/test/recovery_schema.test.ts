import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createWireSchemaValidator } from "../../node-http/src/wire-schema.js";
import { describe, expect, it } from "vitest";

import type {
  Recovery_DependencyGraph,
  Recovery_EffectContract,
  Recovery_Observation,
  Recovery_ProfileRequirements,
  Recovery_Trajectory,
} from "../src/_generated/index.js";

type RecoveryContract =
  | Recovery_DependencyGraph.RecoveryDependencyGraphV1
  | Recovery_EffectContract.SemanticEffectContractV1
  | Recovery_Observation.RecoveryObservationV1
  | Recovery_ProfileRequirements.RecoveryProfileRequirementsV1
  | Recovery_Trajectory.RecoveryTrajectoryV1;

const schemaFiles = {
  observation: "observation",
  profile: "profile-requirements",
  effect_contract: "effect-contract",
  graph: "dependency-graph",
  trajectory: "trajectory",
} as const;
interface Vector {
  name: string;
  contract: keyof typeof schemaFiles;
  schema_valid: boolean;
  valid: boolean;
  wire: string;
}
const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(workspaceRoot, "spec/schemas/chio-wire/v1/recovery");
const schemas = Object.fromEntries(
  Object.entries(schemaFiles).map(([contract, filename]) => [
    contract,
    JSON.parse(readFileSync(resolve(schemaRoot, `${filename}.schema.json`), "utf8")),
  ]),
) as Record<Vector["contract"], { $id: string }>;
const validate = createWireSchemaValidator(Object.values(schemas));
const corpus = JSON.parse(
  readFileSync(resolve(workspaceRoot, "spec/vectors/recovery/v1/contracts.json"), "utf8"),
) as { vectors: Vector[] };

describe("shared recovery schema vectors", () => {
  // This checks parsed shape. The Rust signed reader separately checks raw
  // duplicate keys, canonical bytes, aggregate budgets and trusted scope binding.
  for (const vector of corpus.vectors) {
    it(vector.name, () => {
      const value: unknown = JSON.parse(vector.wire);
      expect(validate(schemas[vector.contract].$id, value)).toBe(vector.schema_valid);
      if (vector.valid) {
        const contract = value as RecoveryContract;
        expect(JSON.parse(JSON.stringify(contract))).toEqual(value);
      }
    });
  }
  it("rejects an unregistered schema identity", () => {
    expect(validate("chio.recovery.observation.v99", {})).toBe(false);
  });
});
