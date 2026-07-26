import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import Ajv2020, {
  type AnySchema,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import { canonicalJsonBytes, canonicalJsonString } from "../src/canonical.js";
import type {
  Agent_ToolCallRequest,
  Capability_AggregateBudgetRootBinding,
  Capability_AggregateBudgetRootBindingBody,
  Capability_AggregateBudgetRootCommitment,
  Capability_AggregateFamilyPreservationEvidence,
  Capability_AggregateInvocationBudget,
  Capability_GovernedApprovalToken,
  Capability_GovernedApprovalTokenBody,
  Capability_GovernedTransactionIntent,
  Capability_ThresholdApprovalProposal,
  Capability_ThresholdApprovalProposalBody,
  Capability_VerifiedApprovalSet,
  Kernel_CapabilityList,
  Security_CorrelatedFindingReceiptBodyV1,
  Security_CorrelatedFindingV1,
  Security_DeclassificationConsumptionReceiptBodyV1,
  Security_DeclassificationOutcomeReceiptBodyV1,
  Security_DetectorHealthReceiptBodyV1,
  Security_EffectTransitionReceiptBodyV1,
  Security_FlowDenialReceiptBodyV1,
  Security_LiftRollbackCompletionReceiptBodyV1,
  Security_ResponseCompletionReceiptBodyV1,
  Security_ResponseEffectV1,
  Security_ResponsePlanReceiptBodyV1,
  Security_ResponsePlanV1,
  Security_ResponseStateTransitionReceiptBodyV1,
  Security_SchedulerHealthReceiptBodyV1,
  Security_SecurityEventBodyV1,
  Security_TripwireObservationReceiptBodyV1,
  TrustControl_AdmissionCaptureMetadata,
  TrustControl_AdmissionRequestBinding,
  TrustControl_BudgetInvocationAdmissionEvidence,
} from "../src/_generated/index.js";

const root = fileURLToPath(new URL("../../../../../", import.meta.url));
const vectorRoot = `${root}tests/bindings/vectors/security/active-defense/positive`;
const mutationCorpusPath = `${root}tests/bindings/vectors/security/active-defense/mutations-v1.json`;
const receiptMutationCorpusPath = `${root}tests/bindings/vectors/security/active-defense/receipt-body-mutations-v1.json`;
const schemaRoot = `${root}spec/schemas/chio-wire/v1/security`;
const protocolVectorRoot = `${root}tests/bindings/vectors/security/protocol-primitives`;
const wireSchemaRoot = `${root}spec/schemas/chio-wire/v1`;
const wireSchemaBase = "https://chio.world/schemas/chio-wire/v1/";
const schemaFiles = [
  "security-event-body-v1.schema.json",
  "correlated-finding-v1.schema.json",
  "response-effect-v1.schema.json",
  "response-plan-v1.schema.json",
  "response-state-transition-receipt-body-v1.schema.json",
  "effect-transition-receipt-body-v1.schema.json",
  "detector-health-receipt-body-v1.schema.json",
  "flow-denial-receipt-body-v1.schema.json",
  "declassification-consumption-receipt-body-v1.schema.json",
  "declassification-outcome-receipt-body-v1.schema.json",
  "tripwire-observation-receipt-body-v1.schema.json",
  "correlated-finding-receipt-body-v1.schema.json",
  "response-plan-receipt-body-v1.schema.json",
  "response-completion-receipt-body-v1.schema.json",
  "lift-rollback-completion-receipt-body-v1.schema.json",
  "scheduler-health-receipt-body-v1.schema.json",
] as const;

function readJson(path: string): unknown {
  return JSON.parse(fs.readFileSync(path, "utf8")) as unknown;
}

function readFixtureBytesWithoutTerminalLf(path: string): Buffer {
  const bytes = fs.readFileSync(path);
  return bytes.at(-1) === 0x0a ? bytes.subarray(0, -1) : bytes;
}

function expectCanonicalTypedBytes(value: unknown, path: string): void {
  expect(Buffer.from(canonicalJsonBytes(value))).toEqual(
    readFixtureBytesWithoutTerminalLf(path),
  );
}

function decode<T>(value: unknown, validate: ValidateFunction): T {
  if (!validate(value)) {
    throw new Error(JSON.stringify(validate.errors));
  }
  return value as T;
}

function applyJsonMutation(
  value: Record<string, unknown>,
  mutation: { op: string; path: string; value?: unknown },
): void {
  const segments = mutation.path.replace(/^\//u, "").split("/");
  let parent: Record<string, unknown> | unknown[] = value;
  for (const segment of segments.slice(0, -1)) {
    const child = Array.isArray(parent)
      ? parent[Number.parseInt(segment, 10)]
      : parent[segment];
    if (typeof child !== "object" || child === null) {
      throw new Error(`mutation path ${mutation.path} is not an object path`);
    }
    parent = child as Record<string, unknown> | unknown[];
  }
  const target = segments.at(-1);
  if (target === undefined) {
    throw new Error("mutation path is empty");
  }
  if (mutation.op === "add" || mutation.op === "replace") {
    if (Array.isArray(parent)) {
      parent[Number.parseInt(target, 10)] = mutation.value;
    } else {
      parent[target] = mutation.value;
    }
  } else if (mutation.op === "remove") {
    if (Array.isArray(parent)) {
      parent.splice(Number.parseInt(target, 10), 1);
    } else {
      delete parent[target];
    }
  } else {
    throw new Error(`unsupported mutation operation ${mutation.op}`);
  }
}

function assertGeneratedRoundTrip<T>(
  ajv: Ajv2020,
  fileName: string,
  schemaId: string,
): void {
  const validate = ajv.getSchema(schemaId);
  if (validate === undefined) {
    throw new Error(`missing exact schema ${schemaId}`);
  }
  const path = `${vectorRoot}/${fileName}`;
  const source = readJson(path);
  const decoded = decode<T>(source, validate);
  expectCanonicalTypedBytes(decoded, path);
  expect(() => decode<T>({ ...(source as object), unknown: true }, validate)).toThrow();
}

function collectSchemaRefs(value: unknown, refs: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectSchemaRefs(item, refs);
    }
    return;
  }
  if (typeof value !== "object" || value === null) {
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === "$ref" && typeof item === "string") {
      refs.add(item);
    } else {
      collectSchemaRefs(item, refs);
    }
  }
}

function registerWireSchema(
  ajv: Ajv2020,
  relativePath: string,
  registered: Set<string>,
): string {
  const schemaId = new URL(relativePath, wireSchemaBase).href;
  if (registered.has(schemaId)) {
    return schemaId;
  }
  registered.add(schemaId);

  const localPath = schemaId.slice(wireSchemaBase.length);
  const schema = readJson(`${wireSchemaRoot}/${localPath}`) as AnySchema;
  ajv.addSchema(schema, schemaId);

  const refs = new Set<string>();
  collectSchemaRefs(schema, refs);
  for (const reference of refs) {
    const target = new URL(reference, schemaId);
    target.hash = "";
    if (target.href.startsWith(wireSchemaBase)) {
      registerWireSchema(
        ajv,
        target.href.slice(wireSchemaBase.length),
        registered,
      );
    }
  }
  return schemaId;
}

function assertWireRoundTrip<T>(
  validate: ValidateFunction,
  relativePath: string,
  sourceOverride?: unknown,
): T {
  const path = `${protocolVectorRoot}/${relativePath}`;
  const source = sourceOverride ?? readJson(path);
  const decoded = decode<T>(source, validate);
  if (sourceOverride === undefined) {
    expectCanonicalTypedBytes(decoded, path);
  }
  expect(() => decode<T>({ ...(source as object), unknown: true }, validate)).toThrow();
  return decoded;
}

function assertProtocolWireRoundTrip(
  identifier: string,
  validate: ValidateFunction,
  relativePath: string,
  sourceOverride?: unknown,
): unknown {
  switch (identifier) {
    case "aggregate_root_commitment":
      return assertWireRoundTrip<Capability_AggregateBudgetRootCommitment.ChioAggregateBudgetRootCommitment>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "aggregate_root_binding_body":
      return assertWireRoundTrip<Capability_AggregateBudgetRootBindingBody.ChioAggregateBudgetRootBindingBody>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "aggregate_root_binding":
      return assertWireRoundTrip<Capability_AggregateBudgetRootBinding.ChioSignedAggregateBudgetRootBinding>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "aggregate_invocation_budget":
      return assertWireRoundTrip<Capability_AggregateInvocationBudget.ChioAggregateInvocationBudget>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "capability_list_delegation_family":
      return assertWireRoundTrip<Kernel_CapabilityList.ChioKernelMessageCapabilityList>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "aggregate_family_preservation":
      return assertWireRoundTrip<Capability_AggregateFamilyPreservationEvidence.ChioAggregateFamilyPreservationEvidence>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "threshold_proposal_body":
      return assertWireRoundTrip<Capability_ThresholdApprovalProposalBody.ChioThresholdApprovalProposalBody>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "threshold_proposal":
      return assertWireRoundTrip<Capability_ThresholdApprovalProposal.ChioSignedThresholdApprovalProposal>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "governed_token_body_alice":
    case "governed_token_body_bob":
      return assertWireRoundTrip<Capability_GovernedApprovalTokenBody.ChioGovernedApprovalTokenBody>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "governed_token_alice":
    case "governed_token_bob":
      return assertWireRoundTrip<Capability_GovernedApprovalToken.ChioSignedGovernedApprovalToken>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "governed_active_response_intent":
      return assertWireRoundTrip<Capability_GovernedTransactionIntent.ChioGovernedTransactionIntent>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "tool_call_request_singular_approval":
    case "tool_call_request_list_approval":
    case "tool_call_request_full_security":
      return assertWireRoundTrip<Agent_ToolCallRequest.ChioAgentMessageToolCallRequest>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "verified_approval_set":
      return assertWireRoundTrip<Capability_VerifiedApprovalSet.ChioVerifiedThresholdApprovalSet>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "admission_request_binding":
      return assertWireRoundTrip<TrustControl_AdmissionRequestBinding.ChioAdmissionOperationRequestBindingProjection>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "budget_admission_evidence":
      return assertWireRoundTrip<TrustControl_BudgetInvocationAdmissionEvidence.ChioBudgetInvocationAdmissionEvidence>(
        validate,
        relativePath,
        sourceOverride,
      );
    case "admission_capture_metadata":
      return assertWireRoundTrip<TrustControl_AdmissionCaptureMetadata.ChioAuthoritativeAdmissionCaptureReceiptProjection>(
        validate,
        relativePath,
        sourceOverride,
      );
    default:
      throw new Error(`protocol positive inventory has no generated type for ${identifier}`);
  }
}

describe("generated active-defense security types", () => {
  it("decode, re-encode, and reject unknown fields through exact schemas", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    for (const fileName of schemaFiles) {
      ajv.addSchema(readJson(`${schemaRoot}/${fileName}`) as AnySchema);
    }

    assertGeneratedRoundTrip<Security_SecurityEventBodyV1.ChioSecurityEventBodyV1>(
      ajv,
      "security-event-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/security-event-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_CorrelatedFindingV1.ChioCorrelatedFindingV1>(
      ajv,
      "correlated-finding-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/correlated-finding-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponsePlanV1.ChioResponsePlanV1>(
      ajv,
      "response-plan-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-plan-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseEffectV1.ChioResponseEffectV1>(
      ajv,
      "response-effect-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-effect-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseStateTransitionReceiptBodyV1.ChioResponseStateTransitionReceiptBodyV1>(
      ajv,
      "response-state-transition-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-state-transition-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseStateTransitionReceiptBodyV1.ChioResponseStateTransitionReceiptBodyV1>(
      ajv,
      "response-state-transition-receipt-body-renewal-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-state-transition-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_EffectTransitionReceiptBodyV1.ChioEffectTransitionReceiptBodyV1>(
      ajv,
      "effect-transition-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/effect-transition-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_EffectTransitionReceiptBodyV1.ChioEffectTransitionReceiptBodyV1>(
      ajv,
      "effect-transition-receipt-body-legacy-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/effect-transition-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_DetectorHealthReceiptBodyV1.ChioDetectorHealthReceiptBodyV1>(
      ajv,
      "detector-health-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_FlowDenialReceiptBodyV1.ChioFlowDenialReceiptBodyV1>(
      ajv,
      "flow-denial-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/flow-denial-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_DeclassificationConsumptionReceiptBodyV1.ChioDeclassificationConsumptionReceiptBodyV1>(
      ajv,
      "declassification-consumption-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/declassification-consumption-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_DeclassificationOutcomeReceiptBodyV1.ChioDeclassificationOutcomeReceiptBodyV1>(
      ajv,
      "declassification-outcome-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/declassification-outcome-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_TripwireObservationReceiptBodyV1.ChioTripwireObservationReceiptBodyV1>(
      ajv,
      "tripwire-observation-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/tripwire-observation-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_CorrelatedFindingReceiptBodyV1.ChioCorrelatedFindingReceiptBodyV1>(
      ajv,
      "correlated-finding-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/correlated-finding-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponsePlanReceiptBodyV1.ChioResponsePlanReceiptBodyV1>(
      ajv,
      "response-plan-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-plan-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponsePlanReceiptBodyV1.ChioResponsePlanReceiptBodyV1>(
      ajv,
      "response-plan-receipt-body-two-effects-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-plan-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseCompletionReceiptBodyV1.ChioResponseCompletionReceiptBodyV1>(
      ajv,
      "response-completion-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseCompletionReceiptBodyV1.ChioResponseCompletionReceiptBodyV1>(
      ajv,
      "response-completion-receipt-body-failed-before-effect-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_ResponseCompletionReceiptBodyV1.ChioResponseCompletionReceiptBodyV1>(
      ajv,
      "response-completion-receipt-body-failed-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_LiftRollbackCompletionReceiptBodyV1.ChioLiftOrRollbackCompletionReceiptBodyV1>(
      ajv,
      "lift-rollback-completion-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/lift-rollback-completion-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_LiftRollbackCompletionReceiptBodyV1.ChioLiftOrRollbackCompletionReceiptBodyV1>(
      ajv,
      "lift-rollback-completion-receipt-body-nonreversible-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/lift-rollback-completion-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_SchedulerHealthReceiptBodyV1.ChioSchedulerHealthReceiptBodyV1>(
      ajv,
      "scheduler-health-receipt-body-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/scheduler-health-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_DetectorHealthReceiptBodyV1.ChioDetectorHealthReceiptBodyV1>(
      ajv,
      "detector-health-receipt-body-contradictory-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json",
    );
    assertGeneratedRoundTrip<Security_DetectorHealthReceiptBodyV1.ChioDetectorHealthReceiptBodyV1>(
      ajv,
      "detector-health-receipt-body-unknown-v1.json",
      "https://chio.world/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json",
    );
  });

  it("rejects every schema-invalid detector-health mutation through Ajv", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const schemaId =
      "https://chio.world/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json";
    ajv.addSchema(
      readJson(`${schemaRoot}/detector-health-receipt-body-v1.schema.json`) as AnySchema,
    );
    const validate = ajv.getSchema(schemaId);
    if (validate === undefined) {
      throw new Error("missing detector-health schema");
    }
    const corpus = readJson(mutationCorpusPath) as {
      cases: Array<{
        base: string;
        expected: { json_schema_valid: boolean };
        id: string;
        mutation: { op: string; path: string; value?: unknown };
      }>;
    };
    const relevant = corpus.cases.filter(
      (entry) =>
        entry.id.startsWith("detector_health_") &&
        !entry.expected.json_schema_valid,
    );
    expect(relevant.length).toBeGreaterThan(0);
    for (const entry of relevant) {
      const value = readJson(
        `${root}tests/bindings/vectors/security/active-defense/${entry.base}`,
      ) as Record<string, unknown>;
      applyJsonMutation(value, entry.mutation);
      expect(validate(value), entry.id).toBe(false);
    }
  });

  it("checks every receipt mutation against schema and semantic expectations", () => {
    execFileSync("python3", [`${root}scripts/check-security-wire-vectors.py`], {
      cwd: root,
      stdio: "pipe",
    });
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const registered = new Set<string>();
    for (const fileName of schemaFiles) {
      registerWireSchema(ajv, `security/${fileName}`, registered);
    }
    const index = readJson(
      `${root}tests/bindings/vectors/security/active-defense/index.json`,
    ) as {
      positive: Array<{ file: string; schema_id: string }>;
    };
    const schemaByBase = new Map(
      index.positive.map((entry) => [entry.file, entry.schema_id]),
    );
    const corpus = readJson(receiptMutationCorpusPath) as {
      cases: Array<{
        base: string;
        expected: { json_schema_valid: boolean; semantic_valid: boolean };
        id: string;
        mutation: { op: string; path: string; value?: unknown };
      }>;
    };
    expect(corpus.cases.length).toBeGreaterThan(0);
    for (const entry of corpus.cases) {
      const schemaId = schemaByBase.get(entry.base);
      const validate = schemaId === undefined ? undefined : ajv.getSchema(schemaId);
      if (validate === undefined) {
        throw new Error(`missing schema for ${entry.base}`);
      }
      const value = readJson(
        `${root}tests/bindings/vectors/security/active-defense/${entry.base}`,
      ) as Record<string, unknown>;
      applyJsonMutation(value, entry.mutation);
      expect(validate(value), entry.id).toBe(entry.expected.json_schema_valid);
      expect(entry.expected.semantic_valid, entry.id).toBe(false);
    }
  }, 20_000);
});

describe("generated protocol security types", () => {
  it("preserves every positive protocol primitive through its exact generated type", () => {
    const ajv = new Ajv2020({
      allErrors: true,
      strict: true,
    });
    const registered = new Set<string>();
    const index = readJson(`${protocolVectorRoot}/index.json`) as {
      positive: Array<{ file: string; id: string; schema_id: string }>;
    };
    expect(index.positive).toHaveLength(26);
    expect(new Set(index.positive.map((entry) => entry.id)).size).toBe(26);
    expect(new Set(index.positive.map((entry) => entry.file)).size).toBe(26);
    for (const entry of index.positive) {
      const relativeSchema = entry.schema_id.slice(wireSchemaBase.length);
      const schemaId = registerWireSchema(ajv, relativeSchema, registered);
      const validate = ajv.getSchema(schemaId);
      if (validate === undefined) {
        throw new Error(`missing protocol schema ${entry.schema_id}`);
      }
      const decoded = assertProtocolWireRoundTrip(entry.id, validate, entry.file);
      if (entry.id === "governed_active_response_intent") {
        const intent =
          decoded as Capability_GovernedTransactionIntent.ChioGovernedTransactionIntent;
        expect(intent.kind).toBe("active_response_plan");
      } else if (entry.id === "tool_call_request_full_security") {
        const request = decoded as Agent_ToolCallRequest.ChioAgentMessageToolCallRequest;
        expect(request.capability_token.aggregate_invocation_budget).toBeDefined();
        expect(request.supplemental_authorization).toBeDefined();
        expect(request.governed_intent?.kind).toBe("tool_invocation");
        expect(request.approval_tokens).toHaveLength(2);
        expect(request).not.toHaveProperty("approval_token");
        expect(request.threshold_approval_proposal).toBeDefined();
        expect(request.declassification_grant).toBeDefined();
      }
    }
  });

  it("uses schema validation plus generated types for the exact negative protocol corpus", () => {
    execFileSync("python3", [`${root}scripts/check-protocol-primitives-vectors.py`], {
      cwd: root,
      stdio: "pipe",
    });
    const ajv = new Ajv2020({
      allErrors: true,
      strict: true,
    });
    const registered = new Set<string>();
    const index = readJson(`${protocolVectorRoot}/index.json`) as {
      positive: Array<{ file: string; id: string; schema_id: string }>;
      negative: Array<{ file: string; schema_id?: string }>;
    };
    const positiveByBase = new Map(
      index.positive.map((entry) => [entry.file, entry]),
    );
    for (const entry of index.positive) {
      registerWireSchema(
        ajv,
        entry.schema_id.slice(wireSchemaBase.length),
        registered,
      );
    }
    const directSchemaId = index.negative[0]?.schema_id;
    if (directSchemaId === undefined) {
      throw new Error("direct protocol negative has no schema ID");
    }
    const validateDirect = ajv.getSchema(directSchemaId);
    if (validateDirect === undefined) {
      throw new Error("direct protocol negative schema is missing");
    }
    expect(
      validateDirect(readJson(`${protocolVectorRoot}/${index.negative[0]?.file}`)),
    ).toBe(false);

    const corpus = readJson(`${protocolVectorRoot}/mutations-v1.json`) as {
      cases: Array<{
        base: string;
        expected: {
          json_parse_valid: boolean;
          json_schema_valid: boolean;
          semantic_valid: boolean;
        };
        id: string;
        mutation: { hex?: string; op: string; path?: string; value?: unknown };
      }>;
    };
    expect(corpus.cases).toHaveLength(43);
    expect(new Set(corpus.cases.map((entry) => entry.id)).size).toBe(43);
    let structuralRejections = 1;
    let semanticRejections = 0;
    for (const entry of corpus.cases) {
      const positive = positiveByBase.get(entry.base);
      if (positive === undefined) {
        throw new Error(`mutation base is absent from positive inventory: ${entry.base}`);
      }
      const validate = ajv.getSchema(positive.schema_id);
      if (validate === undefined) {
        throw new Error(`missing mutation schema ${positive.schema_id}`);
      }
      let value: Record<string, unknown>;
      if (entry.mutation.op === "append_bytes") {
        if (entry.mutation.hex === undefined) {
          throw new Error(`append-bytes mutation ${entry.id} has no hex suffix`);
        }
        const baseBytes = fs.readFileSync(`${protocolVectorRoot}/${entry.base}`);
        const mutatedBytes = Buffer.concat([
          baseBytes,
          Buffer.from(entry.mutation.hex, "hex"),
        ]);
        value = JSON.parse(mutatedBytes.toString("utf8")) as Record<string, unknown>;
        expect(
          Buffer.from(canonicalJsonString(value), "utf8").equals(mutatedBytes),
          entry.id,
        ).toBe(false);
      } else {
        value = readJson(`${protocolVectorRoot}/${entry.base}`) as Record<
          string,
          unknown
        >;
        applyJsonMutation(value, {
          op: entry.mutation.op,
          path: entry.mutation.path ?? "",
          value: entry.mutation.value,
        });
      }
      expect(entry.expected.json_parse_valid, entry.id).toBe(true);
      expect(validate(value), entry.id).toBe(entry.expected.json_schema_valid);
      expect(entry.expected.semantic_valid, entry.id).toBe(false);
      if (entry.expected.json_schema_valid) {
        semanticRejections += 1;
        assertProtocolWireRoundTrip(
          positive.id,
          validate,
          entry.base,
          value,
        );
      } else {
        structuralRejections += 1;
      }
    }
    expect(structuralRejections).toBe(16);
    expect(semanticRejections).toBe(28);
    expect(structuralRejections + semanticRejections).toBe(44);
  });
});
