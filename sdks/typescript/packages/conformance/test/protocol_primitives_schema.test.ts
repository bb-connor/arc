import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { createWireSchemaValidator, parseWireJson } from "@chio-protocol/node-http";

import type {
  Agent_ActiveResponseGovernedIntent,
  Capability_AggregateInvocationBudget,
  Capability_GovernedApprovalToken,
  Capability_SupplementalAuthorization,
  Capability_ThresholdApprovalProposal,
  Capability_Token,
  Kernel_CombinedCaptureMetadata,
  Kernel_CallerDeliveryReport,
  Kernel_CallerDispatchAuthorization,
  Kernel_ExecutionNonce,
  Result_PendingApproval,
  Receipt_Record,
} from "../src/_generated/index.js";

type ProtocolPrimitive =
  | Receipt_Record.ChioReceiptRecord
  | Kernel_CallerDeliveryReport.ChioSignedCallerDeliveryReport
  | Kernel_CallerDispatchAuthorization.ChioSignedCallerDispatchAuthorization
  | Kernel_ExecutionNonce.ChioSignedExecutionNonce
  | Agent_ActiveResponseGovernedIntent.ChioGovernedActiveResponseIntentBody
  | Capability_AggregateInvocationBudget.ChioAggregateInvocationBudget
  | Capability_GovernedApprovalToken.ChioGovernedApprovalToken
  | Capability_SupplementalAuthorization.ChioOpaqueSupplementalAuthorization
  | Capability_ThresholdApprovalProposal.ChioThresholdApprovalProposal
  | Capability_Token.ChioCapabilityToken
  | Kernel_CombinedCaptureMetadata.ChioCombinedAdmissionCaptureMetadata
  | Result_PendingApproval.ChioToolCallResultPendingApproval;

interface FixtureCase {
  name: string;
  schema_file: string;
  valid: boolean;
  /** Present when only a decoder refuses the case, such as an underived id. */
  schema_valid?: boolean;
  instance: ProtocolPrimitive | Record<string, unknown>;
}

/** Exact wire bytes; duplicate keys do not survive a parse of the corpus. */
interface RawFixtureCase {
  name: string;
  schema_file: string;
  valid: false;
  instance_text: string;
}

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(workspaceRoot, "spec/schemas/chio-wire/v1");
const corpus = JSON.parse(
  readFileSync(
    resolve(workspaceRoot, "tests/bindings/fixtures/protocol-primitives-v1.json"),
    "utf8",
  ),
) as { cases: FixtureCase[]; raw_cases: RawFixtureCase[] };

const schemaFiles = new Set(
  [...corpus.cases, ...corpus.raw_cases].map((fixture) => fixture.schema_file),
);
schemaFiles.add("capability/aggregate-budget-root.schema.json");
schemaFiles.add("capability/cumulative-approval-root.schema.json");

const validateWire = createWireSchemaValidator(
  [...schemaFiles].map((file) => JSON.parse(readFileSync(resolve(schemaRoot, file), "utf8"))),
);

describe("protocol primitive generated schemas", () => {
  it("compile and validate the shared positive and negative fixtures", () => {
    for (const fixture of corpus.cases) {
      const schema = JSON.parse(
        readFileSync(resolve(schemaRoot, fixture.schema_file), "utf8"),
      ) as { $id: string };
      expect(validateWire(schema.$id, fixture.instance), fixture.name).toBe(
        fixture.schema_valid ?? fixture.valid,
      );
      if (fixture.valid) {
        expect(JSON.parse(JSON.stringify(fixture.instance))).toEqual(fixture.instance);
      }
    }

    const activeResponse = corpus.cases.find((fixture) => fixture.name === "active-response-intent");
    expect(activeResponse?.valid).toBe(true);
    const activeResponseSchema = JSON.parse(
      readFileSync(resolve(schemaRoot, "agent/active-response-governed-intent.schema.json"), "utf8"),
    ) as { $id: string };
    const structuralBounds: Record<string, Record<string, unknown>> = {
      "duplicate effects": { ordered_effects: ["throttle_session", "throttle_session"] },
      "empty target binding": { target_binding: {} },
      "empty rollback binding": { rollback_binding: {} },
      "empty plan body": { canonical_plan_body: {} },
      "camel-case hashed plan body": { canonical_plan_body: { action: "throttle", planHash: "a" } },
      "snake-case hashed plan body": { canonical_plan_body: { action: "throttle", plan_hash: "a" } },
    };
    for (const [label, mutation] of Object.entries(structuralBounds)) {
      expect(
        validateWire(activeResponseSchema.$id, { ...activeResponse?.instance, ...mutation }),
        label,
      ).toBe(false);
    }
    const bindingSchema = JSON.parse(readFileSync(
      resolve(schemaRoot, "capability/security-binding.schema.json"), "utf8",
    ));
    const bindingVectors = JSON.parse(readFileSync(resolve(
      workspaceRoot, "tests/bindings/vectors/capability/security-binding-v1.json",
    ), "utf8"));
    const binding = JSON.parse(bindingVectors.cases[0].caveats[0].predicate);
    const validateBinding = createWireSchemaValidator([bindingSchema]);
    // These are format characters, not Unicode White_Space or control characters.
    for (const marker of ["\uFEFF", "\u200B", "\u2060"]) {
      for (const value of [`${marker}id`, `id${marker}`]) {
        expect(validateWire(activeResponseSchema.$id, { ...activeResponse?.instance, plan_id: value }), value).toBe(true);
        expect(validateBinding(bindingSchema.$id, { ...binding, tenantId: value }), value).toBe(true);
      }
    }
    for (const marker of [
      " ", "\t", "\u0085", "\u00A0", "\u1680", "\u2000",
      "\u2028", "\u202F", "\u205F", "\u3000",
    ]) {
      for (const value of [`${marker}id`, `id${marker}`]) {
        expect(validateWire(activeResponseSchema.$id, { ...activeResponse?.instance, plan_id: value }), value).toBe(false);
        expect(validateBinding(bindingSchema.$id, { ...binding, tenantId: value }), value).toBe(false);
      }
    }
  });

  for (const fixture of corpus.raw_cases) {
    const schema = JSON.parse(
      readFileSync(resolve(schemaRoot, fixture.schema_file), "utf8"),
    ) as { $id: string };
    it(`raw ${fixture.name} rejects duplicate keys`, () => {
      expect(fixture.valid).toBe(false);
      // Valid once JSON.parse collapses duplicates; the wire decoder rejects the text.
      expect(validateWire(schema.$id, JSON.parse(fixture.instance_text))).toBe(true);
      expect(() => parseWireJson(fixture.instance_text)).toThrow(SyntaxError);
    });
  }
});
