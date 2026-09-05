// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.
//
// Source:     spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:       json-schema-to-typescript 15.0.4 (see xtask/codegen-tools.lock.toml)
// Pin file:   sdks/typescript/scripts/package.json
// Schema SHA: 97f99ae91734b0f6575d2106c86a230a5b11dc50b6f5914cc0ec0c827f8f8d51
//
// The schema-sha above is sha256 of `<rel-path>\0<bytes>\0` for every
// schema in lex order. It changes whenever any schema under
// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane
// asserts byte-equality of this entire file via `--check` mode.

/* eslint-disable */

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/active-response-governed-intent.schema.json
export namespace Agent_ActiveResponseGovernedIntent {
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/governed-transaction-intent.schema.json
export namespace Agent_GovernedTransactionIntent {
  export interface ChioGovernedTransactionIntent {
    id: string;
    server_id: string;
    tool_name: string;
    purpose: string;
    max_amount?: {
      units: number;
      currency: string;
    };
    commerce?: {};
    metered_billing?: {};
    runtime_attestation?: {};
    call_chain?: {};
    autonomy?: {};
    context?: unknown;
    body?:
      | {
          kind: "tool_invocation";
        }
      | {
          kind: "active_response_plan";
          value: ChioGovernedActiveResponseIntentBody;
        };
  }
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/heartbeat.schema.json
export namespace Agent_Heartbeat {
  export interface ChioAgentMessageHeartbeat {
    type: "heartbeat";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/list_capabilities.schema.json
export namespace Agent_ListCapabilities {
  export interface ChioAgentMessageListCapabilities {
    type: "list_capabilities";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/tool_call_request.schema.json
export namespace Agent_ToolCallRequest {
  export type ChioAgentMessageToolCallRequest = {
    [k: string]: unknown;
  } & {
    type: "tool_call_request";
    id: string;
    capability_token: ChioCapabilityToken;
    server_id: string;
    tool: string;
    params: unknown;
    governed_intent?: ChioGovernedTransactionIntent;
    approval_token?: ChioGovernedApprovalToken;
    /**
     * @maxItems 32
     */
    approval_tokens?: ChioGovernedApprovalToken[];
    threshold_approval_proposal?: ChioThresholdApprovalProposal;
    supplemental_authorization?: ChioOpaqueSupplementalAuthorization;
    execution_nonce?: ChioSignedExecutionNonce;
  };
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
    constraints?: (
      | GenericConstraint
      | LegacyApprovalConstraint
      | CumulativeApprovalDirectConstraint
      | CumulativeApprovalDelegableConstraint
    )[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind:
      | "restrict_tool"
      | "bind_session"
      | "restrict_audience"
      | "restrict_geo"
      | "restrict_time_window"
      | "bind_security_context";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
  export interface ChioGovernedTransactionIntent {
    id: string;
    server_id: string;
    tool_name: string;
    purpose: string;
    max_amount?: {
      units: number;
      currency: string;
    };
    commerce?: {};
    metered_billing?: {};
    runtime_attestation?: {};
    call_chain?: {};
    autonomy?: {};
    context?: unknown;
    body?:
      | {
          kind: "tool_invocation";
        }
      | {
          kind: "active_response_plan";
          value: ChioGovernedActiveResponseIntentBody;
        };
  }
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
  export interface ChioGovernedApprovalToken {
    id: string;
    approver: string;
    subject: string;
    governed_intent_hash: string;
    request_id: string;
    threshold_proposal_hash?: string;
    issued_at: number;
    expires_at: number;
    decision: "approved" | "denied";
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: string;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioOpaqueSupplementalAuthorization {
    /**
     * Opaque authenticated extension bytes. Adapters must not interpret these bytes as quota authority.
     */
    signed_extension: string;
  }
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/anchor/batch.schema.json
export namespace Anchor_Batch {
  /**
   * W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
   */
  export type WitnessState =
    | {
        kind: "pending";
      }
    | {
        kind: "witnessed";
        receipt: WitnessReceipt;
        observed_at: number;
      }
    | {
        kind: "stale";
        last_verified: number;
        error: string;
      };

  /**
   * Signed additive Merkle batch over receipts or checkpoints. Local receipt signatures remain authoritative; the batch adds continuity and public-witness timestamping.
   */
  export interface ChioAnchorBatchV1 {
    body: Body;
    signature: string;
  }
  export interface Body {
    schema: "chio.anchor_batch.v1";
    treeRoot: string;
    /**
     * @minItems 1
     */
    checkpointIds: [string, ...string[]];
    /**
     * @minItems 1
     */
    inclusions: [Inclusion, ...Inclusion[]];
    witness: Witness;
    issuedAt: number;
    signerKey: string;
    witnessState?: WitnessState;
  }
  export interface Inclusion {
    checkpointId: string;
    leafHash: string;
    proof: {
      [k: string]: unknown;
    };
  }
  export interface Witness {
    kind: "rekor" | "ots" | "solana_memo";
    witnessId: string;
    root: string;
    observedAt?: number;
  }
  /**
   * Verifier-bound receipt returned by a public-witness lane. OTS receipts remain advisory until the lane carries trusted Bitcoin header or calendar-backed commitment evidence.
   */
  export interface WitnessReceipt {
    kind: "rekor" | "ots" | "solana_memo";
    externalUuid: string;
    publishedAt: number;
    inclusionProof: string;
    witnessRoot: string;
    bodyHash: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root.schema.json
export namespace Capability_AggregateBudgetRoot {
  export type AggregateRootPublicKey = string;
  export type AggregateRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type AggregateRootSignature = string;

  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: AggregateRootPublicKey;
      root_subject: AggregateRootPublicKey;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: AggregateRootSigningAlgorithm;
    signature: AggregateRootSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-invocation-budget.schema.json
export namespace Capability_AggregateInvocationBudget {
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/capabilities.schema.json
export namespace Capability_Capabilities {
  /**
   * Feature bitset exchanged during federation trust establishment, including aggregate budgets, cumulative approval, threshold approval, and governed active response. Malformed feature names and unsupported schema IDs fail closed.
   */
  export interface ChioCapabilityNegotiationV1 {
    schema: "chio.capabilities.v1";
    /**
     * String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.
     */
    features?: {
      [k: string]: boolean;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/cumulative-approval-root.schema.json
export namespace Capability_CumulativeApprovalRoot {
  export type CumulativeRootPublicKey = string;
  export type CumulativeRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type CumulativeRootSignature = string;

  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: CumulativeRootPublicKey;
      root_subject: CumulativeRootPublicKey;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: CumulativeRootSigningAlgorithm;
    signature: CumulativeRootSignature;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/governed-approval-token.schema.json
export namespace Capability_GovernedApprovalToken {
  export type GovernedApprovalPublicKey = string;
  export type GovernedApprovalSignature = string;

  export interface ChioGovernedApprovalToken {
    id: string;
    approver: GovernedApprovalPublicKey;
    subject: GovernedApprovalPublicKey;
    governed_intent_hash: string;
    request_id: string;
    threshold_proposal_hash?: string;
    issued_at: number;
    expires_at: number;
    decision: "approved" | "denied";
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: GovernedApprovalSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/grant.schema.json
export namespace Capability_Grant {
  /**
   * A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/core/chio-core-types/src/capability/scope.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.
   */
  export type ChioCapabilityGrant = ToolGrant | ResourceGrant | PromptGrant;
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";

  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    /**
     * Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
     */
    server_id: string;
    /**
     * Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
     */
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    constraints?: Constraint[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    /**
     * If true, the kernel requires a valid DPoP proof for every invocation under this grant.
     */
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
   */
  export interface Constraint {
    type: string;
    value?: unknown;
  }
  /**
   * A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/revocation.schema.json
export namespace Capability_Revocation {
  /**
   * A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/kernel/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.
   */
  export interface ChioCapabilityRevocationEntry {
    /**
     * The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.
     */
    capability_id: string;
    /**
     * Unix timestamp (seconds) at which the revocation took effect. Stored as a signed integer in the kernel store; negative values are not produced by the issuer but are not rejected here in order to match the Rust `i64` shape.
     */
    revoked_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/supplemental-authorization.schema.json
export namespace Capability_SupplementalAuthorization {
  export interface ChioOpaqueSupplementalAuthorization {
    /**
     * Opaque authenticated extension bytes. Adapters must not interpret these bytes as quota authority.
     */
    signed_extension: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/threshold-approval-proposal.schema.json
export namespace Capability_ThresholdApprovalProposal {
  export type ThresholdProposalPublicKey = string;
  export type ThresholdProposalSignature = string;

  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: ThresholdProposalPublicKey;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: ThresholdProposalPublicKey;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: ThresholdProposalSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/token.schema.json
export namespace Capability_Token {
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";
  export type Constraint =
    | GenericConstraint
    | LegacyApprovalConstraint
    | CumulativeApprovalDirectConstraint
    | CumulativeApprovalDelegableConstraint;
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    constraints?: Constraint[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind:
      | "restrict_tool"
      | "bind_session"
      | "restrict_audience"
      | "restrict_geo"
      | "restrict_time_window"
      | "bind_security_context";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/verified-approval-set.schema.json
export namespace Capability_VerifiedApprovalSet {
  export interface ChioVerifiedApprovalSetBody {
    /**
     * @minItems 1
     * @maxItems 32
     */
    token_digests: [string, ...string[]];
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    threshold_proposal_hash: string;
    proposal_id: string;
    proposal_created_at: number;
    proposal_deadline: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_denied.schema.json
export namespace Error_CapabilityDenied {
  export interface ChioToolCallErrorCapabilityDenied {
    code: "capability_denied";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_expired.schema.json
export namespace Error_CapabilityExpired {
  export interface ChioToolCallErrorCapabilityExpired {
    code: "capability_expired";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_revoked.schema.json
export namespace Error_CapabilityRevoked {
  export interface ChioToolCallErrorCapabilityRevoked {
    code: "capability_revoked";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/internal_error.schema.json
export namespace Error_InternalError {
  export interface ChioToolCallErrorInternalError {
    code: "internal_error";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/policy_denied.schema.json
export namespace Error_PolicyDenied {
  export interface ChioToolCallErrorPolicyDenied {
    code: "policy_denied";
    detail: {
      guard: string;
      reason: string;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/tool_server_error.schema.json
export namespace Error_ToolServerError {
  export interface ChioToolCallErrorToolServerError {
    code: "tool_server_error";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/federation/bilateral-signature-slice-envelope.schema.json
export namespace Federation_BilateralSignatureSliceEnvelope {
  /**
   * Top-level DSSE envelope for Chio bilateral signature-slice artifacts. The base64 payload is the canonical JSON in-toto Statement described by bilateral-signature-slice.schema.json.
   */
  export interface ChioBilateralDSSESignatureSliceEnvelope {
    payloadType: "application/vnd.in-toto+json";
    payload: string;
    /**
     * @minItems 2
     * @maxItems 2
     */
    signatures: [
      {
        keyid: string;
        sig: string;
      },
      {
        keyid: string;
        sig: string;
      }
    ];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json
export namespace Federation_BilateralSignatureSlice {
  /**
   * Bounded in-toto Statement payload for Chio bilateral DSSE signature slices. This is not the strict treaty-bound bilateral invocation predicate.
   */
  export interface ChioBilateralDSSESignatureSliceStatement {
    _type: "https://in-toto.io/Statement/v1";
    /**
     * @minItems 1
     * @maxItems 1
     */
    subject: [
      {
        name: string;
        digest: {
          sha256: string;
        };
      }
    ];
    predicateType: "chio.bilateral-signature-slice.v1";
    predicate: {
      schema: "chio.bilateral-signature-slice.v1";
      invocation_id: string;
      tool_server_a: KernelIdentity;
      tool_server_b: KernelIdentity;
      tool_name: string;
      co_sign: "bilateral_required" | "bilateral_if_cross_org";
      consistency_model: "crdt-commutative";
      cross_org_visibility: "private" | "treaty_only" | "federated" | "public";
      timestamp_unix_ms: number;
      receipt_canonical_json: string;
      capability_lease_ref?: CapabilityLeaseRef;
      policy_evaluation_summary?: PolicyEvaluationSummary;
      governance_receipt_ref?: GovernanceReceiptRef;
      consistency_anchor?: string;
    };
  }
  export interface KernelIdentity {
    kernel_id: string;
    passport_key_fingerprint: string;
    alg: "ed25519";
  }
  export interface CapabilityLeaseRef {
    lease_id: string;
    issuer: string;
    expires_at_unix_ms: number;
    scope_digest?: HashRecord;
  }
  export interface HashRecord {
    alg: "sha256";
    value: string;
  }
  export interface PolicyEvaluationSummary {
    server_a_verdict: PolicyVerdict;
    server_b_verdict: PolicyVerdict;
    joint_disposition?: "allow" | "deny";
  }
  export interface PolicyVerdict {
    verdict: "allow" | "deny";
    policy_id: string;
    policy_version: string;
    rationale_code?: string;
  }
  export interface GovernanceReceiptRef {
    receipt_id: string;
    kernel_id: string;
    digest: HashRecord;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/notification.schema.json
export namespace Jsonrpc_Notification {
  /**
   * JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed by `send_notification` in `crates/protocol/chio-mcp-adapter` and the streaming-chunk and cancellation notifications in `crates/protocol/chio-mcp-edge` and `crates/protocol/chio-mcp-adapter`. A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.
   */
  export interface ChioJSONRPC20Notification {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').
     */
    method: string;
    /**
     * Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.
     */
    params?: {} | unknown[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/request.schema.json
export namespace Jsonrpc_Request {
  /**
   * JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed by `send_request` in `crates/protocol/chio-mcp-adapter` and the typed `A2aJsonRpcRequest<T>` in `crates/protocol/chio-a2a-adapter`. The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
   */
  export interface ChioJSONRPC20Request {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.
     */
    id: number | string | null;
    /**
     * RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').
     */
    method: string;
    /**
     * Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.
     */
    params?: {} | unknown[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/response.schema.json
export namespace Jsonrpc_Response {
  /**
   * JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed by `json_rpc_result` and `json_rpc_error` in `crates/protocol/chio-mcp-adapter` and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/protocol/chio-a2a-adapter`. Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in `crates/protocol/chio-mcp-adapter`). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
   */
  export type ChioJSONRPC20Response = {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
     */
    id: number | string | null;
    /**
     * Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.
     */
    result?: {
      [k: string]: unknown;
    };
    /**
     * Error payload. Present only on failure. Mutually exclusive with `result`.
     */
    error?: {
      /**
       * JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).
       */
      code: number;
      /**
       * Short human-readable error description.
       */
      message: string;
      /**
       * Optional structured detail. Shape is method- or code-specific.
       */
      data?: {
        [k: string]: unknown;
      };
    };
  } & {
    [k: string]: unknown;
  };
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_list.schema.json
export namespace Kernel_CapabilityList {
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  export interface ChioKernelMessageCapabilityList {
    type: "capability_list";
    capabilities: ChioCapabilityToken[];
  }
  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
    constraints?: (
      | GenericConstraint
      | LegacyApprovalConstraint
      | CumulativeApprovalDirectConstraint
      | CumulativeApprovalDelegableConstraint
    )[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind:
      | "restrict_tool"
      | "bind_session"
      | "restrict_audience"
      | "restrict_geo"
      | "restrict_time_window"
      | "bind_security_context";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_revoked.schema.json
export namespace Kernel_CapabilityRevoked {
  export interface ChioKernelMessageCapabilityRevoked {
    type: "capability_revoked";
    id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/combined-capture-metadata.schema.json
export namespace Kernel_CombinedCaptureMetadata {
  export interface ChioCombinedAdmissionCaptureMetadata {
    schema: "chio.admission-capture-metadata.v1";
    operation_id: string;
    hold_id: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quota_keys:
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ];
    revocation_set_digest: string;
    budget_commit_index: number;
    revocation_commit_index: number;
    leader_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/execution_nonce.schema.json
export namespace Kernel_ExecutionNonce {
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/heartbeat.schema.json
export namespace Kernel_Heartbeat {
  export interface ChioKernelMessageHeartbeat {
    type: "heartbeat";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/tool_call_chunk.schema.json
export namespace Kernel_ToolCallChunk {
  export interface ChioKernelMessageToolCallChunk {
    type: "tool_call_chunk";
    id: string;
    chunk_index: number;
    data: unknown;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/tool_call_response.schema.json
export namespace Kernel_ToolCallResponse {
  export type ChioKernelMessageToolCallResponse = {
    [k: string]: unknown;
  } & {
    type: "tool_call_response";
    id: string;
    result:
      | {
          status: "ok";
          value: unknown;
        }
      | {
          status: "stream_complete";
          total_chunks: number;
        }
      | {
          status: "cancelled";
          reason: string;
          chunks_received: number;
        }
      | {
          status: "incomplete";
          reason: string;
          chunks_received: number;
        }
      | {
          status: "err";
          error:
            | {
                code: "capability_denied";
                detail: string;
              }
            | {
                code: "capability_expired";
              }
            | {
                code: "capability_revoked";
              }
            | {
                code: "policy_denied";
                detail: {
                  guard: string;
                  reason: string;
                };
              }
            | {
                code: "tool_server_error";
                detail: string;
              }
            | {
                code: "internal_error";
                detail: string;
              };
        }
      | ChioToolCallResultPendingApproval;
    receipt: ChioReceiptRecord;
    execution_nonce?: ChioSignedExecutionNonce;
  };
  /**
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
   */
  export type ChioReceiptRecord = {
    [k: string]: unknown;
  } & {
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    action: ToolCallAction;
    decision?: Decision;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    /**
     * Kernel public key (for verification without out-of-band lookup). Supports Ed25519, uncompressed SEC1 P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes accepted by `PublicKey::from_hex`.
     */
    kernel_key: string;
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Supports Ed25519, byte-aligned DER P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes; cryptographic DER validity is checked by the verifier.
     */
    signature: string;
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        verdict: "deny";
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
      }
    | {
        verdict: "cancelled";
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
      }
    | {
        verdict: "incomplete";
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
      };

  export interface ChioToolCallResultPendingApproval {
    status: "pending_approval";
    proposal: ChioThresholdApprovalProposal;
  }
  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: string;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    schema: "chio.receipt.bbs_signature.v1";
    projection_version: "chio.bbs-projection.receipt.v1";
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    signature_hex: string;
  }
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/attestation-bundle.schema.json
export namespace Provenance_AttestationBundle {
  /**
   * One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.
   */
  export interface ChioProvenanceAttestationBundle {
    /**
     * Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.
     */
    chainId: string;
    /**
     * Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`, which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
     */
    evidenceClass: "asserted" | "observed" | "verified";
    /**
     * Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.
     */
    assembledAt: number;
    /**
     * Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.
     *
     * @minItems 1
     */
    statements: [
      {
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
        };
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
      },
      ...{
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
        };
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
      }[]
    ];
    /**
     * Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.
     */
    issuer?: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/context.schema.json
export namespace Provenance_Context {
  /**
   * One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/core/chio-core-types` (`GovernedProvenanceEvidenceClass`). Mirrors the `GovernedCallChainContext` struct in `crates/core/chio-core-types`. The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
   */
  export interface ChioProvenanceCallChainContext {
    /**
     * Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.
     */
    chainId: string;
    /**
     * Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.
     */
    parentRequestId: string;
    /**
     * Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.
     */
    parentReceiptId?: string;
    /**
     * Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).
     */
    originSubject: string;
    /**
     * Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.
     */
    delegatorSubject: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/stamp.schema.json
export namespace Provenance_Stamp {
  /**
   * One provenance stamp attached by a Chio provider adapter to every tool-call response. Names the upstream `provider`, the upstream `request_id`, the wire `api_version`, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp. Field names are snake_case to match `RuntimeAttestationEvidence`.
   */
  export interface ChioProvenanceStamp {
    /**
     * Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`).
     */
    provider: string;
    /**
     * Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.
     */
    request_id: string;
    /**
     * Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.
     */
    api_version: string;
    /**
     * Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.
     */
    principal: string;
    /**
     * Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; Chio fails closed if the value is in the future relative to the kernel clock.
     */
    received_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/verdict-link.schema.json
export namespace Provenance_VerdictLink {
  /**
   * One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union. Field names are camelCase to match the governed call-chain context family this link binds to.
   */
  export type ChioProvenanceVerdictLink = {
    /**
     * Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
     */
    verdict: "allow" | "deny" | "cancel" | "incomplete";
    /**
     * Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.
     */
    requestId: string;
    /**
     * Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
     */
    receiptId?: string;
    /**
     * Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
     */
    chainId: string;
    /**
     * Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.
     */
    renderedAt: number;
    /**
     * Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.
     */
    reason?: string;
    /**
     * Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.
     */
    guard?: string;
    /**
     * Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.
     */
    evidenceClass?: "asserted" | "observed" | "verified";
  } & (Allow | Deny | Cancel | Incomplete);

  /**
   * Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.
   */
  export interface Allow {
    verdict: "allow";
  }
  /**
   * Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.
   */
  export interface Deny {
    verdict: "deny";
  }
  /**
   * Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.
   */
  export interface Cancel {
    verdict: "cancel";
  }
  /**
   * Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.
   */
  export interface Incomplete {
    verdict: "incomplete";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/admission-metadata.schema.json
export namespace Receipt_AdmissionMetadata {
  export type Digest = string;
  export type Identifier = string;
  export type PositiveIJsonInteger = number;

  export interface ChioDurableAdmissionReceiptMetadata {
    schema: "chio.admission-receipt.v1";
    operation_id: Digest;
    request_id: Identifier;
    request_namespace_digest: Digest;
    request_binding_hash: Digest;
    projected_operation_version: PositiveIJsonInteger;
    projected_state:
      | "prepared"
      | "broker_attempt_registered"
      | "approval_required"
      | "budget_authorized"
      | "approval_reserved"
      | "ready_to_dispatch"
      | "capture_pending"
      | "dispatch_committed"
      | "finalizing"
      | "completed"
      | "compensated_before_dispatch"
      | "not_accepted_after_dispatch_commit"
      | "outcome_unknown_after_dispatch"
      | "denied_after_delivery"
      | "mutation_ready"
      | "mutation_submitted"
      | "economic_mutation_applied"
      | "economic_mutation_not_applied";
    projected_dispatch_state:
      | "not_committed"
      | "capture_pending"
      | "committed"
      | "finalizing"
      | "terminal"
      | "not_applicable";
    trusted_time_unix_ms: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    coordinator_lease_epoch: PositiveIJsonInteger;
    store_fence: StoreFence;
    retained_dispatch_commit: null | DispatchCommit;
    compensation_status: "not_compensated" | "compensated_before_dispatch" | "not_accepted_after_dispatch_commit";
    tool_outcome_id: null | Digest;
    tool_outcome_version: null | PositiveIJsonInteger;
  }
  export interface StoreFence {
    store_uuid: Identifier;
    lease_id: Identifier;
    owner_epoch: PositiveIJsonInteger;
  }
  export interface DispatchCommit {
    committed_version: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    coordinator_lease_epoch: PositiveIJsonInteger;
    store_fence: StoreFence;
    provider_attempt: null | ProviderAttempt;
  }
  export interface ProviderAttempt {
    operation_id: Digest;
    attempt_id: Identifier;
    transport_id: Identifier;
    transport_key_epoch: PositiveIJsonInteger;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/delivery-contract.schema.json
export namespace Receipt_DeliveryContract {
  export type Digest = string;

  export interface ChioDeliveryContractReceiptMetadata {
    schema: "chio.delivery-contract.v1";
    expected_digest: Digest;
    observed_digest: Digest;
    result: "matched" | "mismatched";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/finding-delivery.schema.json
export namespace Receipt_FindingDelivery {
  export type Identifier = string;
  export type Digest = string;
  export type HierarchicalIdentifier = string;
  export type IJsonU64NonZero = number;

  export interface ChioFindingDeliveryReceiptMetadata {
    schema: "chio.finding.delivery.v1";
    finding_id: Identifier;
    listing_id: Identifier;
    transform_profile: "identity";
    digest_check: "matched" | "mismatched";
    media_type_check: "matched" | "mismatched" | "not_evaluated";
    settlement_mode: "local_reversible_hold";
    accepted_bid_envelope_sha256: Digest;
    venue_admission_envelope_sha256: Digest;
    reservation_id: Identifier;
    purchase_intent_id: Identifier;
    authoritative_payment_operation_id: Identifier;
    status_proof?: StatusProof;
  }
  export interface StatusProof {
    feed_id: HierarchicalIdentifier;
    key_domain_nonce: 3318287169837494;
    map_epoch: IJsonU64NonZero;
    status_epoch_artifact_sha256: Digest;
    proof_sha256: Digest;
    root_hash: Digest;
    non_inclusion_checked_at: IJsonU64NonZero;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json
export namespace Receipt_InclusionProof {
  /**
   * Merkle inclusion proof for a single receipt leaf in a receipt-log Merkle tree. Mirrors the serde shape of `MerkleProof` in `crates/core/chio-core-types/src/merkle.rs`. The proof allows an auditor, holding only the published Merkle root and the original leaf bytes, to verify that the leaf was included in a tree of the given size at the given position. The audit path is the ordered list of sibling hashes encountered when walking from the leaf up to the root; siblings whose subtree was carried upward without pairing (the right-edge of an unbalanced level) are omitted. Deterministic-replay consumes this schema as the contract for golden-bundle inclusion artifacts under `tests/replay/goldens/<family>/<name>/`.
   */
  export interface ChioReceiptMerkleInclusionProof {
    /**
     * Total number of leaves in the Merkle tree at the time the proof was issued.
     */
    tree_size: number;
    /**
     * Zero-based index of the leaf being proved. MUST satisfy `leaf_index < tree_size`.
     */
    leaf_index: number;
    /**
     * Ordered sibling hashes from leaf-level up to (but not including) the root. Siblings that were carried upward without pairing on the right edge of an unbalanced level are omitted, so the path length is not strictly `ceil(log2(tree_size))`. Each entry is a `chio-core-types::Hash` serialized via its transparent serde adapter (32-byte SHA-256 digest, hex-encoded with a `0x` prefix).
     */
    audit_path: string[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json
export namespace Receipt_LineageStatement {
  /**
   * Signed pairwise receipt lineage statement. Multi-parent lineage views are derived aggregates over these signed parent-child statements.
   */
  export interface ChioReceiptLineageStatement {
    schema: "chio.receipt_lineage_statement.v1";
    id: string;
    parentReceiptId: string;
    childReceiptId: string;
    parentRequestId: string;
    childRequestId: string;
    parentSessionAnchor: SessionAnchorReference;
    childSessionAnchor: SessionAnchorReference;
    relationKind: "local_child" | "continued" | "finding_memory_write_to_delivery";
    evidenceClass: "asserted" | "observed" | "verified";
    continuationTokenId?: string;
    issuedAt: number;
    kernelKey: string;
    signature: string;
  }
  export interface SessionAnchorReference {
    sessionAnchorId: string;
    sessionAnchorHash: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/record.schema.json
export namespace Receipt_Record {
  /**
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
   */
  export type ChioReceiptRecord = {
    [k: string]: unknown;
  } & {
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    action: ToolCallAction;
    decision?: Decision;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    /**
     * Kernel public key (for verification without out-of-band lookup). Supports Ed25519, uncompressed SEC1 P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes accepted by `PublicKey::from_hex`.
     */
    kernel_key: string;
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Supports Ed25519, byte-aligned DER P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes; cryptographic DER validity is checked by the verifier.
     */
    signature: string;
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        verdict: "deny";
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
      }
    | {
        verdict: "cancelled";
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
      }
    | {
        verdict: "incomplete";
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
      };

  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    schema: "chio.receipt.bbs_signature.v1";
    projection_version: "chio.bbs-projection.receipt.v1";
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    signature_hex: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/cancelled.schema.json
export namespace Result_Cancelled {
  export interface ChioToolCallResultCancelled {
    status: "cancelled";
    reason: string;
    chunks_received: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/err.schema.json
export namespace Result_Err {
  export interface ChioToolCallResultErr {
    status: "err";
    error:
      | {
          code: "capability_denied";
          detail: string;
        }
      | {
          code: "capability_expired";
        }
      | {
          code: "capability_revoked";
        }
      | {
          code: "policy_denied";
          detail: {
            guard: string;
            reason: string;
          };
        }
      | {
          code: "tool_server_error";
          detail: string;
        }
      | {
          code: "internal_error";
          detail: string;
        };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/incomplete.schema.json
export namespace Result_Incomplete {
  export interface ChioToolCallResultIncomplete {
    status: "incomplete";
    reason: string;
    chunks_received: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/ok.schema.json
export namespace Result_Ok {
  export interface ChioToolCallResultOk {
    status: "ok";
    value: unknown;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/pending_approval.schema.json
export namespace Result_PendingApproval {
  export interface ChioToolCallResultPendingApproval {
    status: "pending_approval";
    proposal: ChioThresholdApprovalProposal;
  }
  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: string;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/stream_complete.schema.json
export namespace Result_StreamComplete {
  export interface ChioToolCallResultStreamComplete {
    status: "stream_complete";
    total_chunks: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-control-receipt-body-v1.schema.json
export namespace Security_BrokerAdminControlReceiptBodyV1 {
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerAdminControlReceiptBodyV1 {
    schema: "chio.broker-admin-control-receipt.v1";
    operationId: Digest;
    requestId: Identifier;
    intentDigest: Digest;
    authorizationDigest: Digest;
    operation: "issue" | "revoke" | "status";
    tenantScope: Identifier;
    responseDigest: Digest;
    completedAtUnixSeconds: number;
    outcome: "applied";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-control-receipt-envelope-v1.schema.json
export namespace Security_BrokerAdminControlReceiptEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerAdminControlReceiptV1 {
    body: ChioBrokerAdminControlReceiptBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerAdminControlReceiptBodyV1 {
    schema: "chio.broker-admin-control-receipt.v1";
    operationId: string;
    requestId: string;
    intentDigest: string;
    authorizationDigest: string;
    operation: "issue" | "revoke" | "status";
    tenantScope: string;
    responseDigest: string;
    completedAtUnixSeconds: number;
    outcome: "applied";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-mutation-receipt-body-v1.schema.json
export namespace Security_BrokerAdminMutationReceiptBodyV1 {
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerAdminMutationReceiptBodyV1 {
    schema: "chio.broker-admin-mutation-receipt.v1";
    operationId: Digest;
    requestId: Identifier;
    intentDigest: Digest;
    authorizationDigest: Digest;
    operation: "provision" | "rotate" | "disable" | "delete";
    tenantScope: Identifier;
    credential: CredentialRef;
    completedAtUnixSeconds: number;
    outcome: "applied";
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-mutation-receipt-envelope-v1.schema.json
export namespace Security_BrokerAdminMutationReceiptEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerAdminMutationReceiptV1 {
    body: ChioBrokerAdminMutationReceiptBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerAdminMutationReceiptBodyV1 {
    schema: "chio.broker-admin-mutation-receipt.v1";
    operationId: string;
    requestId: string;
    intentDigest: string;
    authorizationDigest: string;
    operation: "provision" | "rotate" | "disable" | "delete";
    tenantScope: string;
    credential: CredentialRef;
    completedAtUnixSeconds: number;
    outcome: "applied";
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-attempt-registration-v1.schema.json
export namespace Security_BrokerAttemptRegistrationV1 {
  export type Identifier = string;
  export type Digest = string;

  export interface ChioBrokerAttemptRegistrationV1 {
    ids: AttemptIds;
    invocationId: Identifier;
    parentCapabilityId: Identifier;
    brokerCapabilityId: Identifier;
    requestDigest: Digest;
    requestCanonicalDigest: Digest;
    proofDigest: Digest;
    proofKeyId: Identifier;
    proofNonce: string;
    nonceExpiresAtUnixSeconds: number;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    authorityMetadataDigest: Digest;
    revocationAuthorityDomain: Identifier;
  }
  export interface AttemptIds {
    operationId: Identifier;
    attemptId: Identifier;
    holdId: Identifier;
    authorizeEventId: Identifier;
    reverseEventId: Identifier;
    captureEventId: Identifier;
  }
  export interface Quota {
    keyId: Identifier;
    maximumExecutions: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-comparison-body-v1.schema.json
export namespace Security_BrokerAuditComparisonBodyV1 {
  export type Digest = string;

  export interface ChioBrokerAuditComparisonBodyV1 {
    schema: "chio.broker-audit-comparison.v1";
    issuedAtUnixSeconds: number;
    capabilitySha256: Digest;
    proofSha256: Digest;
    canonicalRequestSha256: Digest;
    authorityContextSha256: Digest;
    auditIdSha256: Digest;
    governedAuditIntentSha256: Digest;
    auditAuthorizationSha256: Digest;
    runnerAuthorizationSha256: Digest;
    referenceSourceSha256: Digest;
    brokerOutboundProjectionCommitmentSha256: Digest;
    referenceOutboundProjectionCommitmentSha256: Digest;
    projectionsEqual: boolean;
    networkDispatchCount: 0;
    accountingMutationCount: 0;
    rawCredentialReturned: false;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-comparison-envelope-v1.schema.json
export namespace Security_BrokerAuditComparisonEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerAuditComparisonV1 {
    body: ChioBrokerAuditComparisonBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerAuditComparisonBodyV1 {
    schema: "chio.broker-audit-comparison.v1";
    issuedAtUnixSeconds: number;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    authorityContextSha256: string;
    auditIdSha256: string;
    governedAuditIntentSha256: string;
    auditAuthorizationSha256: string;
    runnerAuthorizationSha256: string;
    referenceSourceSha256: string;
    brokerOutboundProjectionCommitmentSha256: string;
    referenceOutboundProjectionCommitmentSha256: string;
    projectionsEqual: boolean;
    networkDispatchCount: 0;
    accountingMutationCount: 0;
    rawCredentialReturned: false;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-runner-authorization-body-v1.schema.json
export namespace Security_BrokerAuditRunnerAuthorizationBodyV1 {
  export type Identifier = string;
  export type Digest = string;

  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    schema: "chio.broker-audit-runner-authorization.v1";
    auditId: Identifier;
    deploymentId: Identifier;
    brokerInstanceId: Identifier;
    tenantScope: Identifier;
    runnerId: Identifier;
    referenceSource: Identifier;
    referenceCommitmentSha256: Digest;
    capabilitySha256: Digest;
    proofSha256: Digest;
    canonicalRequestSha256: Digest;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
    credentialProvider: Identifier;
    revocationAuthorityDomain: Identifier;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-runner-authorization-envelope-v1.schema.json
export namespace Security_BrokerAuditRunnerAuthorizationEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    schema: "chio.broker-audit-runner-authorization.v1";
    auditId: string;
    deploymentId: string;
    brokerInstanceId: string;
    tenantScope: string;
    runnerId: string;
    referenceSource: string;
    referenceCommitmentSha256: string;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    credentialProvider: string;
    revocationAuthorityDomain: string;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-request-body-v1.schema.json
export namespace Security_BrokerAuthorityRequestBodyV1 {
  export type AuthorityRpcIdentifier = string;
  export type PositiveU64 = number;
  export type PublicKey = string;
  export type Operation =
    | CapabilitiesOperation
    | PrepareExecutionOperation
    | VerifyLiveParentOperation
    | CheckBrokerRevocationOperation
    | HoldOperation
    | ControlOperation;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type HoldOperation =
    | {
        kind: "query_execution_hold";
        request: QueryHoldRequest;
      }
    | {
        kind: "authorize_execution_hold";
        request: AuthorizeHoldRequest;
      }
    | {
        kind: "reverse_execution_hold";
        request: ReverseHoldRequest;
      }
    | {
        kind: "capture_execution_hold";
        request: CaptureHoldRequest;
      };
  export type AuthorityRpcDigest = string;

  export interface ChioBrokerAuthorityRPCRequestBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: AuthorityRpcIdentifier;
    issuedAtUnixSeconds: PositiveU64;
    broker: PublicKey;
    operation: Operation;
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    schema: "chio.broker-execute.v1";
    invocationId: string;
    capability: ChioSignedBrokerCapabilityV1;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
  }
  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface Request {
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 524288
     */
    body: number[];
    approvedPreviewSha256: string | null;
    options: Options;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface Options {
    timeoutMs: number;
    streaming: boolean;
    responseLimitBytes: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    parentCapabilityId: AuthorityRpcIdentifier;
    expectedSubject: PublicKey;
    expectedAudience: AuthorityRpcIdentifier;
    nowUnixSeconds: PositiveU64;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: AuthorityRpcIdentifier;
    revocationId: AuthorityRpcIdentifier;
    nowUnixSeconds: PositiveU64;
  }
  export interface QueryHoldRequest {
    operationId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    authorizeEventId: AuthorityRpcIdentifier;
    reverseEventId: AuthorityRpcIdentifier;
    captureEventId: AuthorityRpcIdentifier;
  }
  export interface AuthorizeHoldRequest {
    operationId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    authorizeEventId: AuthorityRpcIdentifier;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    authorityMetadataDigest: AuthorityRpcDigest;
  }
  export interface Quota {
    keyId: AuthorityRpcIdentifier;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    operationId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    reverseEventId: AuthorityRpcIdentifier;
    proofDispatchDidNotBegin: true;
  }
  export interface CaptureHoldRequest {
    operationId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    captureEventId: AuthorityRpcIdentifier;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [AuthorityRpcIdentifier, ...AuthorityRpcIdentifier[]];
    revocationSetDigest: AuthorityRpcDigest;
    authorizationArtifactDigest: AuthorityRpcDigest;
    authorityMetadataDigest: AuthorityRpcDigest;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    operation: "issue" | "revoke" | "status";
    tenantScope: AuthorityRpcIdentifier;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-request-envelope-v1.schema.json
export namespace Security_BrokerAuthorityRequestEnvelopeV1 {
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedBrokerAuthorityRPCRequestV1 {
    body: ChioBrokerAuthorityRPCRequestBodyV1;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioBrokerAuthorityRPCRequestBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: string;
    issuedAtUnixSeconds: number;
    broker: string;
    operation:
      | CapabilitiesOperation
      | PrepareExecutionOperation
      | VerifyLiveParentOperation
      | CheckBrokerRevocationOperation
      | (
          | {
              kind: "query_execution_hold";
              request: QueryHoldRequest;
            }
          | {
              kind: "authorize_execution_hold";
              request: AuthorizeHoldRequest;
            }
          | {
              kind: "reverse_execution_hold";
              request: ReverseHoldRequest;
            }
          | {
              kind: "capture_execution_hold";
              request: CaptureHoldRequest;
            }
        )
      | ControlOperation;
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    schema: "chio.broker-execute.v1";
    invocationId: string;
    capability: ChioSignedBrokerCapabilityV1;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
  }
  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface Request {
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 524288
     */
    body: number[];
    approvedPreviewSha256: string | null;
    options: Options;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface Options {
    timeoutMs: number;
    streaming: boolean;
    responseLimitBytes: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    parentCapabilityId: string;
    expectedSubject: string;
    expectedAudience: string;
    nowUnixSeconds: number;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: string;
    revocationId: string;
    nowUnixSeconds: number;
  }
  export interface QueryHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    authorizeEventId: string;
    reverseEventId: string;
    captureEventId: string;
  }
  export interface AuthorizeHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    authorizeEventId: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    authorityMetadataDigest: string;
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    reverseEventId: string;
    proofDispatchDidNotBegin: true;
  }
  export interface CaptureHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    captureEventId: string;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [string, ...string[]];
    revocationSetDigest: string;
    authorizationArtifactDigest: string;
    authorityMetadataDigest: string;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    operation: "issue" | "revoke" | "status";
    tenantScope: string;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-response-body-v1.schema.json
export namespace Security_BrokerAuthorityResponseBodyV1 {
  export type AuthorityRpcResponseIdentifier = string;
  export type Digest = string;
  export type PositiveU64 = number;
  export type PublicKey = string;
  export type Result =
    | CapabilitiesResult
    | PreparedResult
    | LiveParentResult
    | RevocationResult
    | HoldResult
    | ControlResult
    | RejectedResult;
  export type U64 = number;
  export type HoldState =
    | ("unknown" | "denied" | "held" | "reversed")
    | {
        captured: CaptureCommit;
      };

  export interface ChioBrokerAuthorityRPCResponseBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: AuthorityRpcResponseIdentifier;
    requestDigest: Digest;
    issuedAtUnixSeconds: PositiveU64;
    authority: PublicKey;
    result: Result;
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    profile: "authoritative_hold_event";
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: AuthorityRpcResponseIdentifier;
    preparedDispatchId: AuthorityRpcResponseIdentifier;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ];
    authorityMetadataDigest: Digest;
    revocationAuthorityDomain: AuthorityRpcResponseIdentifier;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: AuthorityRpcResponseIdentifier[];
  }
  export interface AuthorityRpcResponseQuota {
    keyId: AuthorityRpcResponseIdentifier;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    capabilityId: AuthorityRpcResponseIdentifier;
    subject: PublicKey;
    audience: AuthorityRpcResponseIdentifier;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: AuthorityRpcResponseIdentifier[];
    expiresAtUnixSeconds: PositiveU64;
    verifiedAtUnixSeconds: PositiveU64;
    authoritySnapshotDigest: Digest;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    revoked: boolean;
    observedAtUnixSeconds: PositiveU64;
    commitIndex: U64;
    authorityDomain: AuthorityRpcResponseIdentifier;
  }
  export interface HoldResult {
    kind: "hold";
    response: HoldState;
  }
  export interface CaptureCommit {
    checkedRevocationSetDigest: Digest;
    budgetCommitIndex: U64;
    revocationCommitIndex: U64;
    authorityCommitIndex: U64;
    leaderEpoch: U64;
  }
  export interface ControlResult {
    kind: "control";
    /**
     * @maxItems 1048576
     */
    response: number[];
  }
  export interface RejectedResult {
    kind: "rejected";
    response: {
      code: AuthorityRpcResponseIdentifier;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-response-envelope-v1.schema.json
export namespace Security_BrokerAuthorityResponseEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedBrokerAuthorityRPCResponseV1 {
    body: ChioBrokerAuthorityRPCResponseBodyV1;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioBrokerAuthorityRPCResponseBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: string;
    requestDigest: string;
    issuedAtUnixSeconds: number;
    authority: string;
    result:
      | CapabilitiesResult
      | PreparedResult
      | LiveParentResult
      | RevocationResult
      | HoldResult
      | ControlResult
      | RejectedResult;
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    profile: "authoritative_hold_event";
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: string;
    preparedDispatchId: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ];
    authorityMetadataDigest: string;
    revocationAuthorityDomain: string;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: string[];
  }
  export interface AuthorityRpcResponseQuota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    capabilityId: string;
    subject: string;
    audience: string;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: string[];
    expiresAtUnixSeconds: number;
    verifiedAtUnixSeconds: number;
    authoritySnapshotDigest: string;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    revoked: boolean;
    observedAtUnixSeconds: number;
    commitIndex: number;
    authorityDomain: string;
  }
  export interface HoldResult {
    kind: "hold";
    response:
      | ("unknown" | "denied" | "held" | "reversed")
      | {
          captured: CaptureCommit;
        };
  }
  export interface CaptureCommit {
    checkedRevocationSetDigest: string;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
  }
  export interface ControlResult {
    kind: "control";
    /**
     * @maxItems 1048576
     */
    response: number[];
  }
  export interface RejectedResult {
    kind: "rejected";
    response: {
      code: string;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-capability-body-v1.schema.json
export namespace Security_BrokerCapabilityBodyV1 {
  export type PublicKey = string;
  export type Identifier = string;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Digest = string;

  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: PublicKey;
    capabilityId: Identifier;
    parentCapabilityId: Identifier;
    subject: PublicKey;
    audience: Identifier;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: Identifier;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: Identifier;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: Identifier;
    credentialId: Identifier;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: Digest;
    requiredPreviewSha256: Digest | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: PublicKey;
    nonceTtlSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-capability-envelope-v1.schema.json
export namespace Security_BrokerCapabilityEnvelopeV1 {
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Signature = string;

  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-failure-v1.schema.json
export namespace Security_BrokerExecuteFailureV1 {
  export interface ChioBrokerExecuteFailureV1 {
    diagnosticCode: string;
    receiptReference: string;
    receipt: ChioSignedBrokerExecutionFailureReceiptV1;
  }
  export interface ChioSignedBrokerExecutionFailureReceiptV1 {
    body: ChioBrokerExecutionFailureReceiptBodyV1;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    schema: "chio.broker-execution-failure-receipt.v1";
    receiptId: string;
    issuedAtUnixSeconds: number;
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
    outcome: "denied" | "reversed" | "failed" | "unknown";
    diagnosticCode: string;
    requestDigest: string;
    capabilityDigest: string | null;
    attemptId: string | null;
    invocationId: string | null;
    holdId: string | null;
    parentCapabilityId: string | null;
    brokerCapabilityId: string | null;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-request-v1.schema.json
export namespace Security_BrokerExecuteRequestV1 {
  export type Identifier = string;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type DigestOrNull = Digest | null;
  export type Digest = string;

  export interface ChioBrokerExecuteRequestV1 {
    schema: "chio.broker-execute.v1";
    invocationId: Identifier;
    capability: ChioSignedBrokerCapabilityV1;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
  }
  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface Request {
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 524288
     */
    body: number[];
    approvedPreviewSha256: DigestOrNull;
    options: Options;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface Options {
    timeoutMs: number;
    streaming: boolean;
    responseLimitBytes: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-response-v1.schema.json
export namespace Security_BrokerExecuteResponseV1 {
  export interface ChioBrokerExecuteResponseV1 {
    status: number;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 2097152
     */
    body: number[];
    evidence: ChioBrokerExecutionEvidenceV1;
    receiptReference: string;
    receipt: ChioSignedBrokerExecutionReceiptV1;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    schema: "chio.broker-execution-evidence.v1";
    attemptId: string;
    invocationId: string;
    holdId: string;
    requestDigest: string;
    capabilityDigest: string;
    revocationSetDigest: string;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
    upstreamStatus: number;
    responseBodySha256: string;
  }
  export interface ChioSignedBrokerExecutionReceiptV1 {
    body: ChioBrokerExecutionReceiptBodyV1;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerExecutionReceiptBodyV1 {
    schema: "chio.broker-execution-receipt.v1";
    receiptId: string;
    issuedAtUnixSeconds: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    operationId: string;
    authorizeEventId: string;
    captureEventId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    subject: string;
    credentialReferenceHash: string;
    credentialVersion: number;
    normalizedDestination: Destination;
    requestBodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    brokerQuotaKeyId: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    requestBodyBytes: number;
    responseBodyBytes: number;
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: string[];
    outcome: "completed";
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-evidence-v1.schema.json
export namespace Security_BrokerExecutionEvidenceV1 {
  export type Identifier = string;
  export type Digest = string;

  export interface ChioBrokerExecutionEvidenceV1 {
    schema: "chio.broker-execution-evidence.v1";
    attemptId: Identifier;
    invocationId: Identifier;
    holdId: Identifier;
    requestDigest: Digest;
    capabilityDigest: Digest;
    revocationSetDigest: Digest;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
    upstreamStatus: number;
    responseBodySha256: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-failure-receipt-body-v1.schema.json
export namespace Security_BrokerExecutionFailureReceiptBodyV1 {
  export type Identifier = string;
  export type Digest = string;
  export type DigestOrNull = Digest | null;
  export type IdentifierOrNull = Identifier | null;

  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    schema: "chio.broker-execution-failure-receipt.v1";
    receiptId: Identifier;
    issuedAtUnixSeconds: number;
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
    outcome: "denied" | "reversed" | "failed" | "unknown";
    diagnosticCode: string;
    requestDigest: Digest;
    capabilityDigest: DigestOrNull;
    attemptId: IdentifierOrNull;
    invocationId: IdentifierOrNull;
    holdId: IdentifierOrNull;
    parentCapabilityId: IdentifierOrNull;
    brokerCapabilityId: IdentifierOrNull;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-failure-receipt-envelope-v1.schema.json
export namespace Security_BrokerExecutionFailureReceiptEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerExecutionFailureReceiptV1 {
    body: ChioBrokerExecutionFailureReceiptBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    schema: "chio.broker-execution-failure-receipt.v1";
    receiptId: string;
    issuedAtUnixSeconds: number;
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
    outcome: "denied" | "reversed" | "failed" | "unknown";
    diagnosticCode: string;
    requestDigest: string;
    capabilityDigest: string | null;
    attemptId: string | null;
    invocationId: string | null;
    holdId: string | null;
    parentCapabilityId: string | null;
    brokerCapabilityId: string | null;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-receipt-body-v1.schema.json
export namespace Security_BrokerExecutionReceiptBodyV1 {
  export type Identifier = string;
  export type PublicKey = string;
  export type Digest = string;

  export interface ChioBrokerExecutionReceiptBodyV1 {
    schema: "chio.broker-execution-receipt.v1";
    receiptId: Identifier;
    issuedAtUnixSeconds: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    operationId: Identifier;
    authorizeEventId: Identifier;
    captureEventId: Identifier;
    parentCapabilityId: Identifier;
    brokerCapabilityId: Identifier;
    subject: PublicKey;
    credentialReferenceHash: Digest;
    credentialVersion: number;
    normalizedDestination: Destination;
    requestBodySha256: Digest;
    callerHeadersSha256: Digest;
    callerOptionsSha256: Digest;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    brokerQuotaKeyId: Identifier;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
    requestBodyBytes: number;
    responseBodyBytes: number;
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: Identifier[];
    outcome: "completed";
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    schema: "chio.broker-execution-evidence.v1";
    attemptId: string;
    invocationId: string;
    holdId: string;
    requestDigest: string;
    capabilityDigest: string;
    revocationSetDigest: string;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
    upstreamStatus: number;
    responseBodySha256: string;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface Quota {
    keyId: Identifier;
    maximumExecutions: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-receipt-envelope-v1.schema.json
export namespace Security_BrokerExecutionReceiptEnvelopeV1 {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedBrokerExecutionReceiptV1 {
    body: ChioBrokerExecutionReceiptBodyV1;
    signer: PublicKey;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerExecutionReceiptBodyV1 {
    schema: "chio.broker-execution-receipt.v1";
    receiptId: string;
    issuedAtUnixSeconds: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    operationId: string;
    authorizeEventId: string;
    captureEventId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    subject: string;
    credentialReferenceHash: string;
    credentialVersion: number;
    normalizedDestination: Destination;
    requestBodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    brokerQuotaKeyId: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    requestBodyBytes: number;
    responseBodyBytes: number;
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: string[];
    outcome: "completed";
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    schema: "chio.broker-execution-evidence.v1";
    attemptId: string;
    invocationId: string;
    holdId: string;
    requestDigest: string;
    capabilityDigest: string;
    revocationSetDigest: string;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
    upstreamStatus: number;
    responseBodySha256: string;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-prepare-dispatch-acknowledgement-v1.schema.json
export namespace Security_BrokerPrepareDispatchAcknowledgementV1 {
  export type Identifier = string;

  export interface ChioBrokerPrepareDispatchAcknowledgementV1 {
    schema: "chio.broker-prepare-dispatch-acknowledgement.v1";
    operationId: Identifier;
    attemptId: Identifier;
    preparedDispatchId: Identifier;
    preparedAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-challenge-v1.schema.json
export namespace Security_BrokerPrivilegedAuditChallengeV1 {
  export type Digest = string;
  export type PositiveU64 = number;
  export type PublicKey = string;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  /**
   * Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
   */
  export interface ChioSignedBrokerPrivilegedAuditChallengeV1 {
    body: ChallengeBody;
    signer: PublicKey;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChallengeBody {
    schema: "chio.broker-privileged-audit-challenge.v1";
    sessionNonce: Digest;
    sessionCommitmentSha256: Digest;
    runnerAuthorizationBody: ChioBrokerAuditRunnerAuthorizationBodyV1;
    issuedAtUnixSeconds: PositiveU64;
    expiresAtUnixSeconds: PositiveU64;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    schema: "chio.broker-audit-runner-authorization.v1";
    auditId: string;
    deploymentId: string;
    brokerInstanceId: string;
    tenantScope: string;
    runnerId: string;
    referenceSource: string;
    referenceCommitmentSha256: string;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    credentialProvider: string;
    revocationAuthorityDomain: string;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-commit-v1.schema.json
export namespace Security_BrokerPrivilegedAuditCommitV1 {
  export type Digest = string;

  /**
   * Second and final request binding runner and governed administrator authorization to a broker challenge.
   */
  export interface ChioBrokerPrivilegedAuditCommitRequestV1 {
    schema: "chio.broker-privileged-audit-commit.v1";
    sessionNonce: Digest;
    sessionCommitmentSha256: Digest;
    runnerAuthorization: ChioSignedBrokerAuditRunnerAuthorizationV1;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    governedAdminAuthorization: [number, ...number[]];
  }
  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    schema: "chio.broker-audit-runner-authorization.v1";
    auditId: string;
    deploymentId: string;
    brokerInstanceId: string;
    tenantScope: string;
    runnerId: string;
    referenceSource: string;
    referenceCommitmentSha256: string;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    credentialProvider: string;
    revocationAuthorityDomain: string;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-evidence-v1.schema.json
export namespace Security_BrokerPrivilegedAuditEvidenceV1 {
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type PublicKey = string;
  export type PositiveU64 = number;
  export type Digest = string;

  /**
   * Canonical evidence returned after one privileged broker audit comparison.
   */
  export interface ChioBrokerPrivilegedAuditEvidenceBundleV1 {
    schema: "chio.broker-privileged-audit-evidence.v1";
    challenge: ChioSignedBrokerPrivilegedAuditChallengeV1;
    runnerAuthorization: ChioSignedBrokerAuditRunnerAuthorizationV1;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    governedAdminAuthorization: [number, ...number[]];
    livenessAuthorityExchange: AuthorityExchange;
    revocationAuthorityExchange: AuthorityExchange;
    comparison: ChioSignedBrokerAuditComparisonV1;
  }
  /**
   * Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
   */
  export interface ChioSignedBrokerPrivilegedAuditChallengeV1 {
    body: ChallengeBody;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChallengeBody {
    schema: "chio.broker-privileged-audit-challenge.v1";
    sessionNonce: string;
    sessionCommitmentSha256: string;
    runnerAuthorizationBody: ChioBrokerAuditRunnerAuthorizationBodyV1;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    schema: "chio.broker-audit-runner-authorization.v1";
    auditId: string;
    deploymentId: string;
    brokerInstanceId: string;
    tenantScope: string;
    runnerId: string;
    referenceSource: string;
    referenceCommitmentSha256: string;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    credentialProvider: string;
    revocationAuthorityDomain: string;
    issuedAtUnixSeconds: number;
    expiresAtUnixSeconds: number;
  }
  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface AuthorityExchange {
    request: ChioSignedBrokerAuthorityRPCRequestV1;
    response: ChioSignedBrokerAuthorityRPCResponseV1;
    trustedAuthority: PublicKey;
    verifiedAtUnixSeconds: PositiveU64;
    maximumClockSkewSeconds: number;
    requestSha256: Digest;
    responseSha256: Digest;
  }
  export interface ChioSignedBrokerAuthorityRPCRequestV1 {
    body: ChioBrokerAuthorityRPCRequestBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerAuthorityRPCRequestBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: string;
    issuedAtUnixSeconds: number;
    broker: string;
    operation:
      | CapabilitiesOperation
      | PrepareExecutionOperation
      | VerifyLiveParentOperation
      | CheckBrokerRevocationOperation
      | (
          | {
              kind: "query_execution_hold";
              request: QueryHoldRequest;
            }
          | {
              kind: "authorize_execution_hold";
              request: AuthorizeHoldRequest;
            }
          | {
              kind: "reverse_execution_hold";
              request: ReverseHoldRequest;
            }
          | {
              kind: "capture_execution_hold";
              request: CaptureHoldRequest;
            }
        )
      | ControlOperation;
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    schema: "chio.broker-execute.v1";
    invocationId: string;
    capability: ChioSignedBrokerCapabilityV1;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
  }
  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface Request {
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 524288
     */
    body: number[];
    approvedPreviewSha256: string | null;
    options: Options;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface Options {
    timeoutMs: number;
    streaming: boolean;
    responseLimitBytes: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    parentCapabilityId: string;
    expectedSubject: string;
    expectedAudience: string;
    nowUnixSeconds: number;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: string;
    revocationId: string;
    nowUnixSeconds: number;
  }
  export interface QueryHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    authorizeEventId: string;
    reverseEventId: string;
    captureEventId: string;
  }
  export interface AuthorizeHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    authorizeEventId: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota]
      | [Quota, Quota]
      | [Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota]
      | [Quota, Quota, Quota, Quota, Quota, Quota, Quota, Quota];
    authorityMetadataDigest: string;
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    reverseEventId: string;
    proofDispatchDidNotBegin: true;
  }
  export interface CaptureHoldRequest {
    operationId: string;
    invocationId: string;
    parentCapabilityId: string;
    brokerCapabilityId: string;
    holdId: string;
    captureEventId: string;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [string, ...string[]];
    revocationSetDigest: string;
    authorizationArtifactDigest: string;
    authorityMetadataDigest: string;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    operation: "issue" | "revoke" | "status";
    tenantScope: string;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
  }
  export interface ChioSignedBrokerAuthorityRPCResponseV1 {
    body: ChioBrokerAuthorityRPCResponseBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerAuthorityRPCResponseBodyV1 {
    schema: "chio.broker-authority-rpc.v1";
    requestId: string;
    requestDigest: string;
    issuedAtUnixSeconds: number;
    authority: string;
    result:
      | CapabilitiesResult
      | PreparedResult
      | LiveParentResult
      | RevocationResult
      | HoldResult
      | ControlResult
      | RejectedResult;
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    profile: "authoritative_hold_event";
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: string;
    preparedDispatchId: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota, AuthorityRpcResponseQuota]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ]
      | [
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota,
          AuthorityRpcResponseQuota
        ];
    authorityMetadataDigest: string;
    revocationAuthorityDomain: string;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: string[];
  }
  export interface AuthorityRpcResponseQuota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    capabilityId: string;
    subject: string;
    audience: string;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: string[];
    expiresAtUnixSeconds: number;
    verifiedAtUnixSeconds: number;
    authoritySnapshotDigest: string;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    revoked: boolean;
    observedAtUnixSeconds: number;
    commitIndex: number;
    authorityDomain: string;
  }
  export interface HoldResult {
    kind: "hold";
    response:
      | ("unknown" | "denied" | "held" | "reversed")
      | {
          captured: CaptureCommit;
        };
  }
  export interface CaptureCommit {
    checkedRevocationSetDigest: string;
    budgetCommitIndex: number;
    revocationCommitIndex: number;
    authorityCommitIndex: number;
    leaderEpoch: number;
  }
  export interface ControlResult {
    kind: "control";
    /**
     * @maxItems 1048576
     */
    response: number[];
  }
  export interface RejectedResult {
    kind: "rejected";
    response: {
      code: string;
    };
  }
  export interface ChioSignedBrokerAuditComparisonV1 {
    body: ChioBrokerAuditComparisonBodyV1;
    signer: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerAuditComparisonBodyV1 {
    schema: "chio.broker-audit-comparison.v1";
    issuedAtUnixSeconds: number;
    capabilitySha256: string;
    proofSha256: string;
    canonicalRequestSha256: string;
    authorityContextSha256: string;
    auditIdSha256: string;
    governedAuditIntentSha256: string;
    auditAuthorizationSha256: string;
    runnerAuthorizationSha256: string;
    referenceSourceSha256: string;
    brokerOutboundProjectionCommitmentSha256: string;
    referenceOutboundProjectionCommitmentSha256: string;
    projectionsEqual: boolean;
    networkDispatchCount: 0;
    accountingMutationCount: 0;
    rawCredentialReturned: false;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-open-v1.schema.json
export namespace Security_BrokerPrivilegedAuditOpenV1 {
  export type AuditIdentifier = string;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type NonzeroDigest = Digest & {
    [k: string]: unknown;
  };
  export type Digest = string;
  export type Byte = number;

  /**
   * First-phase request on the isolated broker privileged audit transport.
   */
  export interface ChioBrokerPrivilegedAuditOpenRequestV1 {
    schema: "chio.broker-privileged-audit-open.v1";
    auditId: AuditIdentifier;
    referenceSource: AuditIdentifier;
    revocationAuthorityDomain: AuditIdentifier;
    request: ChioBrokerExecuteRequestV1;
    referenceCommitmentSalt: NonzeroDigest;
    referenceCommitmentSha256: Digest;
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    referenceRequestHead: [Byte, ...Byte[]];
    /**
     * @maxItems 524288
     */
    referenceRequestBody: Byte[];
  }
  export interface ChioBrokerExecuteRequestV1 {
    schema: "chio.broker-execute.v1";
    invocationId: string;
    capability: ChioSignedBrokerCapabilityV1;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
  }
  export interface ChioSignedBrokerCapabilityV1 {
    body: ChioBrokerCapabilityBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    schema: "chio.broker-capability.v1";
    issuer: string;
    capabilityId: string;
    parentCapabilityId: string;
    subject: string;
    audience: string;
    issuedAtUnixSeconds: number;
    notBeforeUnixSeconds: number;
    expiresAtUnixSeconds: number;
    credential: CredentialRef;
    providerAdapterId: string;
    providerAdapterVersion: number;
    destination: Destination;
    constraints: RequestConstraints;
    brokerQuotaKeyId: string;
    maximumExecutions: number;
    consumption: "capture_before_dispatch";
    revocationId: string;
    proof: ProofBinding;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    providerOwnedHeaders: HeaderNames;
    maximumBodyBytes: number;
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    redirectPolicy: "disabled";
    maximumResponseBytes: number;
    streamingAllowed: boolean;
    maximumTimeoutMs: number;
  }
  export interface ProofBinding {
    mode: "public_key" | "loopback_bearer";
    callerPublicKey: string;
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface Request {
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
    /**
     * @maxItems 524288
     */
    body: number[];
    approvedPreviewSha256: string | null;
    options: Options;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface Options {
    timeoutMs: number;
    streaming: boolean;
    responseLimitBytes: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-acknowledgement-v1.schema.json
export namespace Security_BrokerRegisterAttemptAcknowledgementV1 {
  export type Identifier = string;

  export interface ChioBrokerRegisterAttemptAcknowledgementV1 {
    schema: "chio.broker-register-attempt-acknowledgement.v1";
    operationId: Identifier;
    attemptId: Identifier;
    disposition: "inserted" | "exact_retry";
    registeredAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-authorization-body-v1.schema.json
export namespace Security_BrokerRegisterAttemptAuthorizationBodyV1 {
  export type Identifier = string;
  export type Digest = string;
  export type PublicKey = string;

  export interface ChioBrokerRegisterAttemptAuthorizationBodyV1 {
    schema: "chio.broker-register-attempt-authorization.v1";
    action: "register" | "prepare" | "release";
    tenantScope: Identifier;
    registrationDigest: Digest;
    issuedAtUnixSeconds: number;
    authority: PublicKey;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-authorization-envelope-v1.schema.json
export namespace Security_BrokerRegisterAttemptAuthorizationEnvelopeV1 {
  export type Signature = string;

  export interface ChioSignedBrokerRegisterAttemptAuthorizationV1 {
    body: ChioBrokerRegisterAttemptAuthorizationBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: Signature;
  }
  export interface ChioBrokerRegisterAttemptAuthorizationBodyV1 {
    schema: "chio.broker-register-attempt-authorization.v1";
    action: "register" | "prepare" | "release";
    tenantScope: string;
    registrationDigest: string;
    issuedAtUnixSeconds: number;
    authority: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-release-attempt-acknowledgement-v1.schema.json
export namespace Security_BrokerReleaseAttemptAcknowledgementV1 {
  export type Identifier = string;

  export interface ChioBrokerReleaseAttemptAcknowledgementV1 {
    schema: "chio.broker-release-attempt-acknowledgement.v1";
    operationId: Identifier;
    attemptId: Identifier;
    releasedAtUnixSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-request-proof-body-v1.schema.json
export namespace Security_BrokerRequestProofBodyV1 {
  export type Identifier = string;
  export type Digest = string;
  export type PublicKey = string;

  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: Identifier;
    parentCapabilityId: Identifier;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: Digest;
    callerHeadersSha256: Digest;
    callerOptionsSha256: Digest;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: PublicKey;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-request-proof-envelope-v1.schema.json
export namespace Security_BrokerRequestProofEnvelopeV1 {
  export interface ChioSignedBrokerRequestProofV1 {
    body: ChioBrokerRequestProofBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    schema: "chio.broker-request-proof.v1";
    brokerCapabilityId: string;
    parentCapabilityId: string;
    credential: CredentialRef;
    capabilityExpiresAtUnixSeconds: number;
    destination: Destination;
    bodySha256: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    nonce: string;
    issuedAtUnixSeconds: number;
    authorityKey: string;
  }
  export interface CredentialRef {
    provider: string;
    credentialId: string;
    version: number;
  }
  export interface Destination {
    scheme: "https" | "http";
    normalizedHost: string;
    explicitPort: number;
    exactPathAndQuery: string;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-enforcement-failure-v1.schema.json
export namespace Security_CageEnforcementFailureV1 {
  /**
   * Closed failure code and bounded stage identifier for a rejected, unsupported, or bootstrap-failed cage launch.
   */
  export interface ChioCageEnforcementFailureV1 {
    code:
      | "unsupported_kernel"
      | "helper_identity_mismatch"
      | "invalid_plan_seals"
      | "invalid_plan"
      | "descriptor_count_mismatch"
      | "descriptor_identity_mismatch"
      | "privileged_executable"
      | "non_single_threaded_helper"
      | "execution_identity_invalid"
      | "execution_identity_apply_failed"
      | "execution_identity_mismatch"
      | "trace_handshake_failed"
      | "landlock_unavailable"
      | "landlock_partial"
      | "seccomp_unavailable"
      | "seccomp_architecture_mismatch"
      | "seccomp_install_failed"
      | "prepared_record_invalid"
      | "exec_event_missing"
      | "exec_identity_mismatch"
      | "status_protocol_violation"
      | "timeout"
      | "child_exited_before_exec";
    stage: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-enforcement-prepared-v1.schema.json
export namespace Security_CageEnforcementPreparedV1 {
  export type Digest = string;
  export type RegularFileIdentity = FileIdentity & {
    kind: "regular_file";
  };

  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    schema: "chio.cage.enforcement-prepared.v1";
    process_id: number;
    manifest_digest: Digest;
    profile_digest: Digest;
    plan_digest: Digest;
    fd_table_digest: Digest;
    helper_binding_digest: Digest;
    target_binding_digest: Digest;
    target_identity: RegularFileIdentity;
    applied_execution_identity: ExecutionIdentity;
    nono_version: "0.53.0";
    nono_patch_version: "chio.2";
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    seccomp_status: "fully_enforced";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: Digest;
    trace_session_digest: Digest;
    prepared_at_unix_ms: number;
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-enforcement-record-v1.schema.json
export namespace Security_CageEnforcementRecordV1 {
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    exit: ChioCageProcessExitEvidenceV1 | null;
  } & (
    | {
        state?: "fully_enforced";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: null;
      }
    | {
        state?: "exited";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: ChioCageProcessExitEvidenceV1;
      }
    | {
        state?: "unsupported" | "rejected" | "bootstrap_failed";
        fully_enforced?: null;
        failure?: ChioCageEnforcementFailureV1;
        exit?: null;
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    process_id: number;
    exit_code: number | null;
    signal: number | null;
    exited_at_unix_ms: number;
  } & (
    | {
        exit_code?: number;
        signal?: null;
      }
    | {
        exit_code?: null;
        signal?: number;
      }
  );

  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    exec_transition: ChioCageExecTransitionObservationV1;
    status_eof_observed: true;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    schema: "chio.cage.enforcement-prepared.v1";
    process_id: number;
    manifest_digest: string;
    profile_digest: string;
    plan_digest: string;
    fd_table_digest: string;
    helper_binding_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    applied_execution_identity: ExecutionIdentity;
    nono_version: "0.53.0";
    nono_patch_version: "chio.2";
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    seccomp_status: "fully_enforced";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    trace_session_digest: string;
    prepared_at_unix_ms: number;
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    schema: "chio.cage.exec-transition-observed.v1";
    process_id: number;
    trace_session_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    observed_at_unix_ms: number;
  }
  export interface FileIdentity1 {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  /**
   * Closed failure code and bounded stage identifier for a rejected, unsupported, or bootstrap-failed cage launch.
   */
  export interface ChioCageEnforcementFailureV1 {
    code:
      | "unsupported_kernel"
      | "helper_identity_mismatch"
      | "invalid_plan_seals"
      | "invalid_plan"
      | "descriptor_count_mismatch"
      | "descriptor_identity_mismatch"
      | "privileged_executable"
      | "non_single_threaded_helper"
      | "execution_identity_invalid"
      | "execution_identity_apply_failed"
      | "execution_identity_mismatch"
      | "trace_handshake_failed"
      | "landlock_unavailable"
      | "landlock_partial"
      | "seccomp_unavailable"
      | "seccomp_architecture_mismatch"
      | "seccomp_install_failed"
      | "prepared_record_invalid"
      | "exec_event_missing"
      | "exec_identity_mismatch"
      | "status_protocol_violation"
      | "timeout"
      | "child_exited_before_exec";
    stage: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-exec-transition-observed-v1.schema.json
export namespace Security_CageExecTransitionObservedV1 {
  export type Digest = string;
  export type RegularFileIdentity = FileIdentity & {
    kind: "regular_file";
  };

  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    schema: "chio.cage.exec-transition-observed.v1";
    process_id: number;
    trace_session_digest: Digest;
    target_binding_digest: Digest;
    target_identity: RegularFileIdentity;
    observed_at_unix_ms: number;
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-fully-enforced-evidence-v1.schema.json
export namespace Security_CageFullyEnforcedEvidenceV1 {
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    exec_transition: ChioCageExecTransitionObservationV1;
    status_eof_observed: true;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    schema: "chio.cage.enforcement-prepared.v1";
    process_id: number;
    manifest_digest: string;
    profile_digest: string;
    plan_digest: string;
    fd_table_digest: string;
    helper_binding_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    applied_execution_identity: ExecutionIdentity;
    nono_version: "0.53.0";
    nono_patch_version: "chio.2";
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    seccomp_status: "fully_enforced";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    trace_session_digest: string;
    prepared_at_unix_ms: number;
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    schema: "chio.cage.exec-transition-observed.v1";
    process_id: number;
    trace_session_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    observed_at_unix_ms: number;
  }
  export interface FileIdentity1 {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-init-plan-v2.schema.json
export namespace Security_CageInitPlanV2 {
  /**
   * Canonical, unsigned, launch-bound cage-init plan body consumed from a sealed descriptor after the parent binds target stdin, stdout, and stderr. The pre-launch CompiledCage inspection view is not an instance of this wire schema. Launch-envelope transport bindings and the aggregate 65536-byte UTF-8 environment limit are enforced by the cage runtime outside this structural schema.
   */
  export type ChioCageInitPlanV2 = {
    [k: string]: unknown;
  } & {
    schema: "chio.cage.init-plan.v2";
    compiler_version: "chio-cage-compiler.v2";
    manifest_digest: Digest;
    profile_digest: Digest;
    plan_fd_slot: 3;
    status_fd_slot: 4;
    helper_fd_slot: 5;
    target_fd_slot: 255;
    working_directory_fd_slot: 6;
    target_argv: TargetArgv;
    fd_table: FdTable;
    landlock: LandlockPlan;
    seccomp: SeccompPlan;
    resource_limits: ResourceLimits;
    execution_identity: ExecutionIdentity;
    environment: Environment;
    broker_authentication_digest: Digest | null;
  };
  export type Digest = string;
  /**
   * @minItems 1
   * @maxItems 256
   */
  export type TargetArgv = [string, ...string[]];
  /**
   * @minItems 6
   * @maxItems 191
   */
  export type FdTable = unknown[] & FdTable1;
  export type FdTable1 = [FdEntry, FdEntry, FdEntry, FdEntry, FdEntry, FdEntry, ...FdEntry[]];
  export type FdEntry =
    | (ArtifactEntry & {
        slot?: 5;
        purpose?: PurposeCageInitHelper;
        identity?: RegularFileIdentity;
      })
    | (ArtifactEntry & {
        slot?: 255;
        purpose?: PurposeTargetExecutable;
        identity?: RegularFileIdentity;
      })
    | (ArtifactEntry & {
        slot?: 6;
        purpose?: PurposeWorkingDirectory;
        identity?: DirectoryIdentity;
      })
    | (StdioEntry & {
        slot?: 7;
        purpose?: PurposeTargetStdin;
      })
    | (StdioEntry & {
        slot?: 9;
        purpose?: PurposeTargetStdout;
      })
    | (StdioEntry & {
        slot?: 10;
        purpose?: PurposeTargetStderr;
      })
    | (ArtifactEntry & {
        slot?: number;
        purpose?: PurposeIndexedResource & {
          kind?: "runtime_file";
        };
        identity?: RegularFileIdentity;
      })
    | (FdEntryBase & {
        slot?: number;
        purpose?: PurposeIndexedResource & {
          kind?: "read_grant";
        };
        identity?: PathIdentity;
        path?: AbsoluteCanonicalPath;
        binding_digest?: null;
        broker_peer_identity?: null;
        close_on_exec?: true;
      })
    | (FdEntryBase & {
        slot?: number;
        purpose?: PurposeIndexedResource & {
          kind?: "write_grant";
        };
        identity?: RegularFileIdentity;
        path?: AbsoluteCanonicalPath;
        binding_digest?: null;
        broker_peer_identity?: null;
        close_on_exec?: true;
      })
    | (FdEntryBase & {
        slot?: 8;
        purpose?: PurposeBrokerIpc;
        identity?: SocketIdentity;
        path?: null;
        binding_digest?: Digest;
        broker_peer_identity?: BrokerPeerIdentity;
        close_on_exec?: false;
      });
  export type ArtifactEntry = FdEntryBase & {
    path?: AbsoluteCanonicalPath;
    binding_digest?: Digest;
    broker_peer_identity?: null;
    close_on_exec?: true;
  };
  export type AbsoluteCanonicalPath = string;
  export type RegularFileIdentity = FileIdentity & {
    kind: "regular_file";
  };
  export type DirectoryIdentity = FileIdentity & {
    kind: "directory";
  };
  export type StdioEntry = FdEntryBase & {
    identity?: SocketIdentity;
    path?: null;
    binding_digest?: null;
    broker_peer_identity?: null;
    close_on_exec?: true;
  };
  export type SocketIdentity = FileIdentity & {
    kind: "unix_socket";
  };
  export type PathIdentity = FileIdentity & {
    kind: "regular_file" | "directory";
  };

  export interface FdEntryBase {
    slot: number;
    purpose: {};
    identity: FileIdentity;
    path: AbsoluteCanonicalPath | null;
    binding_digest: Digest | null;
    broker_peer_identity: BrokerPeerIdentity | null;
    close_on_exec: boolean;
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  export interface BrokerPeerIdentity {
    pid: number;
    uid: number;
    gid: number;
  }
  export interface PurposeCageInitHelper {
    kind: "cage_init_helper";
  }
  export interface PurposeTargetExecutable {
    kind: "target_executable";
  }
  export interface PurposeWorkingDirectory {
    kind: "working_directory";
  }
  export interface PurposeTargetStdin {
    kind: "target_stdin";
  }
  export interface PurposeTargetStdout {
    kind: "target_stdout";
  }
  export interface PurposeTargetStderr {
    kind: "target_stderr";
  }
  export interface PurposeIndexedResource {
    kind: "runtime_file" | "read_grant" | "write_grant";
    index: number;
  }
  export interface PurposeBrokerIpc {
    kind: "broker_ipc";
  }
  export interface LandlockPlan {
    default_filesystem_deny: true;
    network_mode: "blocked";
    forbidden_resources: ForbiddenResource[];
    grants: FilesystemGrant[];
  }
  export interface ForbiddenResource {
    path: AbsoluteCanonicalPath;
    identity: PathIdentity;
  }
  export interface FilesystemGrant {
    fd_slot: number;
    access: "read" | "read_directory" | "write_exact_file" | "execute_read";
    identity: PathIdentity;
  }
  export interface SeccompPlan {
    architecture: "x86_64";
    profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
    default_action: "kill_process";
    /**
     * @minItems 1
     */
    allowed_syscalls: [string, ...string[]];
    argument_constraints: {
      /**
       * @minItems 1
       */
      [k: string]: [SyscallArgumentConstraint, ...SyscallArgumentConstraint[]];
    };
  }
  export interface SyscallArgumentConstraint {
    argument_index: number;
    comparison: "equal";
    value: number;
  }
  export interface ResourceLimits {
    nofile_soft: 192;
    nofile_hard: 192;
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  export interface Environment {
    [k: string]: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-process-exit-evidence-v1.schema.json
export namespace Security_CageProcessExitEvidenceV1 {
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    process_id: number;
    exit_code: number | null;
    signal: number | null;
    exited_at_unix_ms: number;
  } & (
    | {
        exit_code?: number;
        signal?: null;
      }
    | {
        exit_code?: null;
        signal?: number;
      }
  );
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-receipt-body-v1.schema.json
export namespace Security_CageReceiptBodyV1 {
  export type ChioCageReceiptBodyV1 = {
    schema: "chio.cage.receipt-body.v1";
    attempt_id: Identifier;
    stage: "rejection" | "bootstrap" | "enforcement" | "terminal_exit";
    bindings?: Bindings;
    enforcement_record: ChioCageEnforcementRecordV1;
    started_at_unix_ms: number;
    recorded_at_unix_ms: number;
  } & (
    | {
        stage?: "rejection";
        enforcement_record?: {
          state: "unsupported" | "rejected";
        };
      }
    | {
        stage?: "bootstrap";
        enforcement_record?: {
          state: "bootstrap_failed";
        };
      }
    | {
        stage?: "enforcement";
        enforcement_record?: {
          state: "fully_enforced";
        };
      }
    | {
        stage?: "terminal_exit";
        enforcement_record?: {
          state: "exited";
        };
      }
  );
  export type Identifier = string;
  export type Digest = string;
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    exit: ChioCageProcessExitEvidenceV1 | null;
  } & (
    | {
        state?: "fully_enforced";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: null;
      }
    | {
        state?: "exited";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: ChioCageProcessExitEvidenceV1;
      }
    | {
        state?: "unsupported" | "rejected" | "bootstrap_failed";
        fully_enforced?: null;
        failure?: ChioCageEnforcementFailureV1;
        exit?: null;
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    process_id: number;
    exit_code: number | null;
    signal: number | null;
    exited_at_unix_ms: number;
  } & (
    | {
        exit_code?: number;
        signal?: null;
      }
    | {
        exit_code?: null;
        signal?: number;
      }
  );

  export interface Bindings {
    manifest_digest: Digest;
    profile_digest: Digest;
    plan_digest: Digest;
    fd_table_digest: Digest;
    helper_binding_digest: Digest;
    target_binding_digest: Digest;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    exec_transition: ChioCageExecTransitionObservationV1;
    status_eof_observed: true;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    schema: "chio.cage.enforcement-prepared.v1";
    process_id: number;
    manifest_digest: string;
    profile_digest: string;
    plan_digest: string;
    fd_table_digest: string;
    helper_binding_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    applied_execution_identity: ExecutionIdentity;
    nono_version: "0.53.0";
    nono_patch_version: "chio.2";
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    seccomp_status: "fully_enforced";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    trace_session_digest: string;
    prepared_at_unix_ms: number;
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    schema: "chio.cage.exec-transition-observed.v1";
    process_id: number;
    trace_session_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    observed_at_unix_ms: number;
  }
  export interface FileIdentity1 {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  /**
   * Closed failure code and bounded stage identifier for a rejected, unsupported, or bootstrap-failed cage launch.
   */
  export interface ChioCageEnforcementFailureV1 {
    code:
      | "unsupported_kernel"
      | "helper_identity_mismatch"
      | "invalid_plan_seals"
      | "invalid_plan"
      | "descriptor_count_mismatch"
      | "descriptor_identity_mismatch"
      | "privileged_executable"
      | "non_single_threaded_helper"
      | "execution_identity_invalid"
      | "execution_identity_apply_failed"
      | "execution_identity_mismatch"
      | "trace_handshake_failed"
      | "landlock_unavailable"
      | "landlock_partial"
      | "seccomp_unavailable"
      | "seccomp_architecture_mismatch"
      | "seccomp_install_failed"
      | "prepared_record_invalid"
      | "exec_event_missing"
      | "exec_identity_mismatch"
      | "status_protocol_violation"
      | "timeout"
      | "child_exited_before_exec";
    stage: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-receipt-metadata-v1.schema.json
export namespace Security_CageReceiptMetadataV1 {
  export type ChioCageReceiptBodyV1 = {
    schema: "chio.cage.receipt-body.v1";
    attempt_id: string;
    stage: "rejection" | "bootstrap" | "enforcement" | "terminal_exit";
    bindings?: Bindings;
    enforcement_record: ChioCageEnforcementRecordV1;
    started_at_unix_ms: number;
    recorded_at_unix_ms: number;
  } & (
    | {
        stage?: "rejection";
        enforcement_record?: {
          state: "unsupported" | "rejected";
        };
      }
    | {
        stage?: "bootstrap";
        enforcement_record?: {
          state: "bootstrap_failed";
        };
      }
    | {
        stage?: "enforcement";
        enforcement_record?: {
          state: "fully_enforced";
        };
      }
    | {
        stage?: "terminal_exit";
        enforcement_record?: {
          state: "exited";
        };
      }
  );
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    exit: ChioCageProcessExitEvidenceV1 | null;
  } & (
    | {
        state?: "fully_enforced";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: null;
      }
    | {
        state?: "exited";
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        failure?: null;
        exit?: ChioCageProcessExitEvidenceV1;
      }
    | {
        state?: "unsupported" | "rejected" | "bootstrap_failed";
        fully_enforced?: null;
        failure?: ChioCageEnforcementFailureV1;
        exit?: null;
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    process_id: number;
    exit_code: number | null;
    signal: number | null;
    exited_at_unix_ms: number;
  } & (
    | {
        exit_code?: number;
        signal?: null;
      }
    | {
        exit_code?: null;
        signal?: number;
      }
  );

  export interface ChioCageReceiptMetadataV1 {
    schema: "chio.cage.receipt-metadata.v1";
    cage_receipt: ChioCageReceiptBodyV1;
  }
  export interface Bindings {
    manifest_digest: string;
    profile_digest: string;
    plan_digest: string;
    fd_table_digest: string;
    helper_binding_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
  }
  export interface FileIdentity {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    exec_transition: ChioCageExecTransitionObservationV1;
    status_eof_observed: true;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    schema: "chio.cage.enforcement-prepared.v1";
    process_id: number;
    manifest_digest: string;
    profile_digest: string;
    plan_digest: string;
    fd_table_digest: string;
    helper_binding_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    applied_execution_identity: ExecutionIdentity;
    nono_version: "0.53.0";
    nono_patch_version: "chio.2";
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    seccomp_status: "fully_enforced";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    trace_session_digest: string;
    prepared_at_unix_ms: number;
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    schema: "chio.cage.exec-transition-observed.v1";
    process_id: number;
    trace_session_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    observed_at_unix_ms: number;
  }
  export interface FileIdentity1 {
    device: number;
    inode: number;
    mount_id: number;
    mode: number;
    uid: number;
    gid: number;
    kind: "regular_file" | "directory" | "unix_socket";
  }
  /**
   * Closed failure code and bounded stage identifier for a rejected, unsupported, or bootstrap-failed cage launch.
   */
  export interface ChioCageEnforcementFailureV1 {
    code:
      | "unsupported_kernel"
      | "helper_identity_mismatch"
      | "invalid_plan_seals"
      | "invalid_plan"
      | "descriptor_count_mismatch"
      | "descriptor_identity_mismatch"
      | "privileged_executable"
      | "non_single_threaded_helper"
      | "execution_identity_invalid"
      | "execution_identity_apply_failed"
      | "execution_identity_mismatch"
      | "trace_handshake_failed"
      | "landlock_unavailable"
      | "landlock_partial"
      | "seccomp_unavailable"
      | "seccomp_architecture_mismatch"
      | "seccomp_install_failed"
      | "prepared_record_invalid"
      | "exec_event_missing"
      | "exec_identity_mismatch"
      | "status_protocol_violation"
      | "timeout"
      | "child_exited_before_exec";
    stage: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/correlated-finding-receipt-body-v1.schema.json
export namespace Security_CorrelatedFindingReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioCorrelatedFindingReceiptBodyV1 {
    header: Header;
    policy: Policy;
    finding_id: string;
    finding_hash: Digest;
    rule_id: string;
    rule_version_hash: Digest;
    group_key_hash: Digest;
    /**
     * @minItems 1
     * @maxItems 64
     */
    ordered_event_ids: [string, ...string[]];
    /**
     * @minItems 1
     * @maxItems 64
     */
    ordered_evidence_digests: [Digest, ...Digest[]];
    /**
     * @minItems 1
     * @maxItems 64
     */
    ordered_source_receipt_ids: [string, ...string[]];
    first_event_time_unix_ms: number;
    last_event_time_unix_ms: number;
    lineage_seed: string;
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/correlated-finding-v1.schema.json
export namespace Security_CorrelatedFindingV1 {
  export type Identifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  /**
   * @minItems 1
   * @maxItems 64
   */
  export type Identifiers = [Identifier, ...Identifier[]];
  export type Time = number;

  export interface ChioCorrelatedFindingV1 {
    finding_id: Identifier;
    tenant_id: Identifier;
    rule_id: Identifier;
    rule_version_hash: Digest;
    policy_version: Identifier;
    group_key_hash: Digest;
    ordered_event_ids: Identifiers;
    /**
     * @minItems 1
     * @maxItems 64
     */
    ordered_evidence_digests: [Digest, ...Digest[]];
    ordered_source_receipt_ids: Identifiers;
    first_event_time_unix_ms: Time;
    last_event_time_unix_ms: Time;
    lineage_seed: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/declassification-consumption-receipt-body-v1.schema.json
export namespace Security_DeclassificationConsumptionReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioDeclassificationConsumptionReceiptBodyV1 {
    header: Header;
    policy: Policy;
    grant_id: string;
    grant_hash: Digest;
    request_hash: Digest;
    event_id: string;
    state: "consumed_pending_dispatch";
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/declassification-grant.schema.json
export namespace Security_DeclassificationGrant {
  export type FlowIdentifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest32 = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  /**
   * Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
   */
  export type InformationLabel =
    | {
        kind: "known";
        owners: {
          /**
           * @maxItems 256
           */
          [k: string]: string[];
        };
        /**
         * @maxItems 64
         */
        compartments: string[];
      }
    | {
        kind: "top";
      };

  /**
   * One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
   */
  export interface SignedDeclassificationGrant {
    body: {
      domain_version: 1;
      grant_id: FlowIdentifier;
      capability_id: FlowIdentifier;
      tenant_id: FlowIdentifier;
      subject_id: FlowIdentifier;
      agent_id: FlowIdentifier;
      session_id: FlowIdentifier;
      source_label_hash: Digest32;
      target_label: InformationLabel & {
        kind: "known";
      };
      destination_id: FlowIdentifier;
      tool_name: FlowIdentifier;
      purpose: FlowIdentifier;
      request_hash: Digest32;
      issued_at_unix_seconds: number;
      expires_at_unix_seconds: number;
      authority_key_id: FlowIdentifier;
    };
    authority_key: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/declassification-outcome-receipt-body-v1.schema.json
export namespace Security_DeclassificationOutcomeReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioDeclassificationOutcomeReceiptBodyV1 {
    header: Header;
    policy: Policy;
    grant_id: string;
    grant_hash: Digest;
    request_hash: Digest;
    event_id: string;
    from_state: "consumed_pending_dispatch";
    to_state: "released" | "dispatch_failed" | "outcome_unknown";
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json
export namespace Security_DetectorHealthReceiptBodyV1 {
  export type ChioDetectorHealthReceiptBodyV1 = {
    [k: string]: unknown;
  } & {
    header: Header;
    policy: Policy;
    rule_id: Identifier;
    rule_version_hash: Digest;
    group_binding: GroupBinding;
    event_id: Identifier;
    health_kind:
      | "corrupt_event"
      | "corrupt_state"
      | "state_overflow"
      | "store_conflict"
      | "store_unavailable"
      | "truncated_scan";
    watermark: Watermark;
    evidence_hash: Digest;
  };
  export type Time = number;
  export type Identifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type GroupBinding =
    | {
        kind: "unresolved";
      }
    | {
        kind: "resolved";
        group_key_hash: Digest;
      };
  export type Watermark =
    | {
        kind: "unknown";
      }
    | {
        kind: "committed";
        unix_ms: Time;
      }
    | {
        kind: "contradictory";
        claimed_unix_ms: string;
      };

  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: Time;
    tenant_id: Identifier;
    transition_id: Identifier;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: Identifier[];
  }
  export interface Policy {
    policy_version: Identifier;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/effect-transition-receipt-body-v1.schema.json
export namespace Security_EffectTransitionReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type Kind =
    | "escalate_alert"
    | "throttle_session"
    | "restrict_egress"
    | "suspend_session"
    | "suspend_capability_set"
    | "freeze_issuance";
  export type Target =
    | {
        target_type: "tenant";
        tenant_id: string;
      }
    | {
        target_type: "session";
        session_id: string;
      }
    | {
        target_type: "lineage";
        lineage_id: string;
      }
    | {
        target_type: "capability_set";
        affected_set_hash: Digest;
      };
  export type JsonSafePositiveInteger = number;
  export type Outcome =
    | {
        state: "requested";
      }
    | {
        state: "applied";
        resulting_version_hash: Digest;
      }
    | {
        state: "apply_failed";
        error_code: string;
      }
    | {
        state: "rollback_requested";
      }
    | {
        state: "restored";
        resulting_version_hash: Digest;
      }
    | {
        state: "rollback_failed";
        error_code: string;
      };

  export interface ChioEffectTransitionReceiptBodyV1 {
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    effect: Effect;
    generation: JsonSafePositiveInteger;
    scheduler_lease_owner_id?: string | null;
    scheduler_fencing_token: JsonSafePositiveInteger;
    outcome: Outcome;
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: string;
    trigger_finding_id: string;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
  export interface Effect {
    effect_id: string;
    ordinal: number;
    kind: Kind;
    target: Target;
    contribution_hash: Digest;
    observed_base_version_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/flow-denial-receipt-body-v1.schema.json
export namespace Security_FlowDenialReceiptBodyV1 {
  export type Time = number;
  export type Identifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioFlowDenialReceiptBodyV1 {
    header: Header;
    policy: Policy;
    request_hash: Digest;
    source_label_hash: Digest;
    destination_label_hash: Digest;
    guard_evidence_hash: Digest;
    denial_code: Identifier;
    event_id: Identifier;
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: Time;
    tenant_id: Identifier;
    transition_id: Identifier;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: Identifier[];
  }
  export interface Policy {
    policy_version: Identifier;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/information-label.schema.json
export namespace Security_InformationLabel {
  /**
   * Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.
   */
  export type InformationLabel =
    | {
        kind: "known";
        owners: {
          /**
           * @maxItems 256
           */
          [k: string]: FlowIdentifier[];
        };
        /**
         * @maxItems 64
         */
        compartments: FlowIdentifier[];
      }
    | {
        kind: "top";
      };
  export type FlowIdentifier = string;
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-activation-commit-body-v1.schema.json
export namespace Security_KeyLogActivationCommitBodyV1 {
  export type KeyLogIdentifier = string;
  export type Hash = string;

  export interface ChioKeyLogActivationCommitBodyV1 {
    schema: "chio.key-log.activation-commit.v1";
    log_id: KeyLogIdentifier;
    event_id: KeyLogIdentifier;
    checkpoint_hash: Hash;
    checkpoint_body_hash: Hash;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: Hash;
    event_leaf_hash: Hash;
    witness_set_hash: Hash;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
    committed_at: number;
    signing_epoch: number;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-activation-commit-envelope-v1.schema.json
export namespace Security_KeyLogActivationCommitEnvelopeV1 {
  export interface ChioSignedKeyLogActivationCommitEnvelopeV1 {
    body: ChioKeyLogActivationCommitBodyV1;
    operator_key_id: string;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_signature: string;
  }
  export interface ChioKeyLogActivationCommitBodyV1 {
    schema: "chio.key-log.activation-commit.v1";
    log_id: string;
    event_id: string;
    checkpoint_hash: string;
    checkpoint_body_hash: string;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: string;
    event_leaf_hash: string;
    witness_set_hash: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
    committed_at: number;
    signing_epoch: number;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-artifact-time-anchor-body-v1.schema.json
export namespace Security_KeyLogArtifactTimeAnchorBodyV1 {
  export type Identifier = string;
  export type Hash = string;
  export type U64 = number;
  export type Anchor = CheckpointAnchor | ExternalAnchor;

  export interface ChioKeyLogArtifactTimeAnchorBodyV1 {
    schema: "chio.key-log.artifact-time-anchor.v1";
    anchor_id: Identifier;
    artifact_hash: Hash;
    anchored_at: U64;
    anchor: Anchor;
  }
  export interface CheckpointAnchor {
    type: "receipt_checkpoint" | "key_log_checkpoint";
    checkpoint_sequence: U64;
    checkpoint_hash: Hash;
  }
  export interface ExternalAnchor {
    type: "external";
    commitment: Hash;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-artifact-time-anchor-envelope-v1.schema.json
export namespace Security_KeyLogArtifactTimeAnchorEnvelopeV1 {
  export type Hash = string;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedKeyLogArtifactTimeAnchorV1 {
    body: ChioKeyLogArtifactTimeAnchorBodyV1;
    anchor_key_id: Hash;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioKeyLogArtifactTimeAnchorBodyV1 {
    schema: "chio.key-log.artifact-time-anchor.v1";
    anchor_id: string;
    artifact_hash: string;
    anchored_at: number;
    anchor: CheckpointAnchor | ExternalAnchor;
  }
  export interface CheckpointAnchor {
    type: "receipt_checkpoint" | "key_log_checkpoint";
    checkpoint_sequence: number;
    checkpoint_hash: string;
  }
  export interface ExternalAnchor {
    type: "external";
    commitment: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-audit-readiness-body-v1.schema.json
export namespace Security_KeyLogAuditReadinessBodyV1 {
  export type Identifier = string;
  export type Hash = string;
  export type Nonce = string;
  export type PositiveU64 = number;
  export type Count = number;

  export interface ChioKeyLogAuditServiceReadinessBodyV1 {
    schema: "chio.key-log.audit-readiness.v1";
    monitor_id: Identifier;
    configuration_binding: Hash;
    nonce: Nonce;
    process_id: number;
    storage_identity: Hash;
    started_at: PositiveU64;
    last_successful_poll_at: PositiveU64;
    pin?: KeyLogPin;
    operator_head: KeyLogPin;
    witness_views: {
      [k: string]: WitnessView;
    };
    witness_proofs: {
      [k: string]: ChioSignedKeyLogWitnessServiceReadinessProofV1;
    };
    conflict_count: Count;
  }
  export interface KeyLogPin {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: Hash;
    root_hash: Hash;
    signing_epoch: number;
  }
  export interface WitnessView {
    pin?: KeyLogPin;
    process_id: number;
    storage_identity: Hash;
    conflict_count: Count;
  }
  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    schema: "chio.key-log.witness-readiness.v1";
    witness_id: string;
    configuration_binding: string;
    nonce: string;
    process_id: number;
    storage_identity: string;
    started_at: number;
    pin?: KeyLogPin1;
    conflict_count: number;
    gossip_observation_count: number;
  }
  export interface KeyLogPin1 {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: string;
    root_hash: string;
    signing_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-audit-readiness-proof-v1.schema.json
export namespace Security_KeyLogAuditReadinessProofV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedKeyLogAuditServiceReadinessProofV1 {
    body: ChioKeyLogAuditServiceReadinessBodyV1;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioKeyLogAuditServiceReadinessBodyV1 {
    schema: "chio.key-log.audit-readiness.v1";
    monitor_id: string;
    configuration_binding: string;
    nonce: string;
    process_id: number;
    storage_identity: string;
    started_at: number;
    last_successful_poll_at: number;
    pin?: KeyLogPin;
    operator_head: KeyLogPin;
    witness_views: {
      [k: string]: WitnessView;
    };
    witness_proofs: {
      [k: string]: ChioSignedKeyLogWitnessServiceReadinessProofV1;
    };
    conflict_count: number;
  }
  export interface KeyLogPin {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: string;
    root_hash: string;
    signing_epoch: number;
  }
  export interface WitnessView {
    pin?: KeyLogPin;
    process_id: number;
    storage_identity: string;
    conflict_count: number;
  }
  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    schema: "chio.key-log.witness-readiness.v1";
    witness_id: string;
    configuration_binding: string;
    nonce: string;
    process_id: number;
    storage_identity: string;
    started_at: number;
    pin?: KeyLogPin1;
    conflict_count: number;
    gossip_observation_count: number;
  }
  export interface KeyLogPin1 {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: string;
    root_hash: string;
    signing_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-checkpoint-body-v1.schema.json
export namespace Security_KeyLogCheckpointBodyV1 {
  export type Hash = string;

  export interface ChioKeyLogCheckpointBodyV1 {
    schema: "chio.key-log.checkpoint.v1";
    log_id: string;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: Hash;
    previous_checkpoint_hash?: Hash;
    issued_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-checkpoint-envelope-v1.schema.json
export namespace Security_KeyLogCheckpointEnvelopeV1 {
  export type Signature = string;

  export interface ChioSignedKeyLogCheckpointEnvelopeV1 {
    body: ChioKeyLogCheckpointBodyV1;
    operator_key_id: string;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_signature: Signature;
    /**
     * @maxItems 64
     */
    witness_signatures?: ChioKeyLogWitnessSignatureV1[];
  }
  export interface ChioKeyLogCheckpointBodyV1 {
    schema: "chio.key-log.checkpoint.v1";
    log_id: string;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: string;
    previous_checkpoint_hash?: string;
    issued_at: number;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-enterprise-receipt-body-v1.schema.json
export namespace Security_KeyLogEnterpriseReceiptBodyV1 {
  export type ChioKeyLogEnterpriseReceiptBodyV1 = {
    schema: "chio.key-log.enterprise-receipt.v1";
    receipt_id: KeyLogIdentifier;
    transaction_id: KeyLogIdentifier;
    issued_at: number;
    log_id: KeyLogIdentifier;
    event_id: KeyLogIdentifier;
    event_sequence: number;
    event_envelope_hash: Hash;
    /**
     * @minItems 1
     * @maxItems 66
     */
    event_signers: [EventSigner, ...EventSigner[]];
    stage: "pending" | "active";
    tree_size: number;
    root_hash: Hash;
    checkpoint_hash: Hash;
    checkpoint_sequence: number;
    operator_key_id: Hash;
    witness_roster_id: KeyLogIdentifier;
    /**
     * @maxItems 64
     */
    witness_signatures: ChioKeyLogWitnessSignatureV1[];
    activation_commit_hash?: Hash;
    signing_epoch?: number;
    /**
     * @maxItems 64
     */
    source_receipt_ids?: KeyLogIdentifier[];
    outcome: "pending_committed" | "activated";
  } & (
    | {
        stage?: "pending";
        outcome?: "pending_committed";
        /**
         * @maxItems 0
         */
        witness_signatures?: [];
      }
    | {
        stage?: "active";
        outcome?: "activated";
        /**
         * @minItems 1
         */
        witness_signatures?: [unknown, ...unknown[]];
        /**
         * @minItems 1
         * @maxItems 1
         */
        source_receipt_ids: [unknown];
      }
  );
  export type KeyLogIdentifier = string;
  export type Hash = string;
  export type EventSigner =
    | {
        role: "bootstrap";
        key_id: Hash;
      }
    | {
        role: "old_key";
        key_id: Hash;
      }
    | {
        role: "new_key";
        key_id: Hash;
      }
    | {
        role: "recovery";
        authorizer_id: KeyLogIdentifier;
      };

  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-enterprise-receipt-envelope-v1.schema.json
export namespace Security_KeyLogEnterpriseReceiptEnvelopeV1 {
  export type ChioKeyLogEnterpriseReceiptBodyV1 = {
    schema: "chio.key-log.enterprise-receipt.v1";
    receipt_id: string;
    transaction_id: string;
    issued_at: number;
    log_id: string;
    event_id: string;
    event_sequence: number;
    event_envelope_hash: string;
    /**
     * @minItems 1
     * @maxItems 66
     */
    event_signers: [
      (
        | {
            role: "bootstrap";
            key_id: string;
          }
        | {
            role: "old_key";
            key_id: string;
          }
        | {
            role: "new_key";
            key_id: string;
          }
        | {
            role: "recovery";
            authorizer_id: string;
          }
      ),
      ...(
        | {
            role: "bootstrap";
            key_id: string;
          }
        | {
            role: "old_key";
            key_id: string;
          }
        | {
            role: "new_key";
            key_id: string;
          }
        | {
            role: "recovery";
            authorizer_id: string;
          }
      )[]
    ];
    stage: "pending" | "active";
    tree_size: number;
    root_hash: string;
    checkpoint_hash: string;
    checkpoint_sequence: number;
    operator_key_id: string;
    witness_roster_id: string;
    /**
     * @maxItems 64
     */
    witness_signatures: ChioKeyLogWitnessSignatureV1[];
    activation_commit_hash?: string;
    signing_epoch?: number;
    /**
     * @maxItems 64
     */
    source_receipt_ids?: string[];
    outcome: "pending_committed" | "activated";
  } & (
    | {
        stage?: "pending";
        outcome?: "pending_committed";
        /**
         * @maxItems 0
         */
        witness_signatures?: [];
      }
    | {
        stage?: "active";
        outcome?: "activated";
        /**
         * @minItems 1
         */
        witness_signatures?: [unknown, ...unknown[]];
        /**
         * @minItems 1
         * @maxItems 1
         */
        source_receipt_ids: [unknown];
      }
  );

  export interface ChioSignedKeyLogEnterpriseReceiptEnvelopeV1 {
    body: ChioKeyLogEnterpriseReceiptBodyV1;
    operator_key_id: string;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_signature: string;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-event-body-v1.schema.json
export namespace Security_KeyLogEventBodyV1 {
  export type KeyLogIdentifier = string;
  export type Hash = string;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type PublicKey = string;
  export type Operation =
    | {
        type: "genesis";
      }
    | {
        type: "rotate";
        previous_key_id: Hash;
        witness_roster_id: KeyLogIdentifier;
        witness_roster_binding: Hash;
      }
    | {
        type: "abort_rotation";
        previous_key_id: Hash;
        recovery_policy_id?: KeyLogIdentifier;
        recovery_policy_binding?: Hash;
      }
    | {
        type: "retire";
      }
    | {
        type: "revoke";
      }
    | {
        type: "recover";
        previous_key_id: Hash;
        witness_roster_id: KeyLogIdentifier;
        witness_roster_binding: Hash;
        recovery_policy_id: KeyLogIdentifier;
        recovery_policy_binding: Hash;
      };

  export interface ChioKeyLogEventBodyV1 {
    schema: "chio.key-log.event.v1";
    log_id: KeyLogIdentifier;
    sequence: number;
    event_id: KeyLogIdentifier;
    previous_event_hash?: Hash;
    authority_id: KeyLogIdentifier;
    key_id: Hash;
    algorithm: Algorithm;
    public_key: PublicKey;
    operation: Operation;
    effective_at: number;
    verify_until?: number;
    reason?: string;
    issued_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-event-envelope-v1.schema.json
export namespace Security_KeyLogEventEnvelopeV1 {
  export type Hash = string;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;
  export type KeyLogIdentifier = string;

  export interface ChioSignedKeyLogEventEnvelopeV1 {
    body: ChioKeyLogEventBodyV1;
    authorizations: {
      bootstrap?: KeyAuthorization;
      old_key?: KeyAuthorization;
      new_key?: KeyAuthorization;
      /**
       * @maxItems 64
       */
      recovery?: RecoveryAuthorization[];
    };
  }
  export interface ChioKeyLogEventBodyV1 {
    schema: "chio.key-log.event.v1";
    log_id: string;
    sequence: number;
    event_id: string;
    previous_event_hash?: string;
    authority_id: string;
    key_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    public_key: string;
    operation:
      | {
          type: "genesis";
        }
      | {
          type: "rotate";
          previous_key_id: string;
          witness_roster_id: string;
          witness_roster_binding: string;
        }
      | {
          type: "abort_rotation";
          previous_key_id: string;
          recovery_policy_id?: string;
          recovery_policy_binding?: string;
        }
      | {
          type: "retire";
        }
      | {
          type: "revoke";
        }
      | {
          type: "recover";
          previous_key_id: string;
          witness_roster_id: string;
          witness_roster_binding: string;
          recovery_policy_id: string;
          recovery_policy_binding: string;
        };
    effective_at: number;
    verify_until?: number;
    reason?: string;
    issued_at: number;
  }
  export interface KeyAuthorization {
    key_id: Hash;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface RecoveryAuthorization {
    authorizer_id: KeyLogIdentifier;
    algorithm: Algorithm;
    signature: Signature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-sync-response-v1.schema.json
export namespace Security_KeyLogSyncResponseV1 {
  export type Hash = string;

  export interface ChioKeyLogSynchronizationResponseV1 {
    base_checkpoint_hash?: Hash;
    /**
     * @maxItems 4096
     */
    checkpoints: ChioSignedKeyLogCheckpointEnvelopeV1[];
    /**
     * @maxItems 4096
     */
    event_envelopes: ChioSignedKeyLogEventEnvelopeV1[];
    /**
     * @minItems 1
     * @maxItems 4096
     */
    activation_commits?: [ChioSignedKeyLogActivationCommitEnvelopeV1, ...ChioSignedKeyLogActivationCommitEnvelopeV1[]];
    consistency_proof?: ConsistencyProof;
  }
  export interface ChioSignedKeyLogCheckpointEnvelopeV1 {
    body: ChioKeyLogCheckpointBodyV1;
    operator_key_id: string;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_signature: string;
    /**
     * @maxItems 64
     */
    witness_signatures?: ChioKeyLogWitnessSignatureV1[];
  }
  export interface ChioKeyLogCheckpointBodyV1 {
    schema: "chio.key-log.checkpoint.v1";
    log_id: string;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: string;
    previous_checkpoint_hash?: string;
    issued_at: number;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioSignedKeyLogEventEnvelopeV1 {
    body: ChioKeyLogEventBodyV1;
    authorizations: {
      bootstrap?: KeyAuthorization;
      old_key?: KeyAuthorization;
      new_key?: KeyAuthorization;
      /**
       * @maxItems 64
       */
      recovery?: RecoveryAuthorization[];
    };
  }
  export interface ChioKeyLogEventBodyV1 {
    schema: "chio.key-log.event.v1";
    log_id: string;
    sequence: number;
    event_id: string;
    previous_event_hash?: string;
    authority_id: string;
    key_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    public_key: string;
    operation:
      | {
          type: "genesis";
        }
      | {
          type: "rotate";
          previous_key_id: string;
          witness_roster_id: string;
          witness_roster_binding: string;
        }
      | {
          type: "abort_rotation";
          previous_key_id: string;
          recovery_policy_id?: string;
          recovery_policy_binding?: string;
        }
      | {
          type: "retire";
        }
      | {
          type: "revoke";
        }
      | {
          type: "recover";
          previous_key_id: string;
          witness_roster_id: string;
          witness_roster_binding: string;
          recovery_policy_id: string;
          recovery_policy_binding: string;
        };
    effective_at: number;
    verify_until?: number;
    reason?: string;
    issued_at: number;
  }
  export interface KeyAuthorization {
    key_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface RecoveryAuthorization {
    authorizer_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioSignedKeyLogActivationCommitEnvelopeV1 {
    body: ChioKeyLogActivationCommitBodyV1;
    operator_key_id: string;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_signature: string;
  }
  export interface ChioKeyLogActivationCommitBodyV1 {
    schema: "chio.key-log.activation-commit.v1";
    log_id: string;
    event_id: string;
    checkpoint_hash: string;
    checkpoint_body_hash: string;
    checkpoint_sequence: number;
    tree_size: number;
    root_hash: string;
    event_leaf_hash: string;
    witness_set_hash: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
    committed_at: number;
    signing_epoch: number;
  }
  export interface ConsistencyProof {
    old_size: number;
    new_size: number;
    /**
     * @maxItems 65
     */
    audit_path: Hash[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-readiness-body-v1.schema.json
export namespace Security_KeyLogWitnessReadinessBodyV1 {
  export type Identifier = string;
  export type Hash = string;
  export type Nonce = string;
  export type PositiveU64 = number;
  export type Count = number;

  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    schema: "chio.key-log.witness-readiness.v1";
    witness_id: Identifier;
    configuration_binding: Hash;
    nonce: Nonce;
    process_id: number;
    storage_identity: Hash;
    started_at: PositiveU64;
    pin?: KeyLogPin;
    conflict_count: Count;
    gossip_observation_count: Count;
  }
  export interface KeyLogPin {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: Hash;
    root_hash: Hash;
    signing_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-readiness-proof-v1.schema.json
export namespace Security_KeyLogWitnessReadinessProofV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    schema: "chio.key-log.witness-readiness.v1";
    witness_id: string;
    configuration_binding: string;
    nonce: string;
    process_id: number;
    storage_identity: string;
    started_at: number;
    pin?: KeyLogPin;
    conflict_count: number;
    gossip_observation_count: number;
  }
  export interface KeyLogPin {
    checkpoint_sequence: number;
    tree_size: number;
    checkpoint_hash: string;
    root_hash: string;
    signing_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-signature-v1.schema.json
export namespace Security_KeyLogWitnessSignatureV1 {
  export interface ChioKeyLogWitnessSignatureV1 {
    witness_id: string;
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/keyring-artifact-signature-v1.schema.json
export namespace Security_KeyringArtifactSignatureV1 {
  export type Hash = string;
  export type U64 = number;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioKeyringArtifactSignatureEvidenceV1 {
    schema: "chio.keyring.artifact-signature.v1";
    artifact_hash: Hash;
    key_id: Hash;
    signing_epoch: U64;
    algorithm: Algorithm;
    artifact_signature: Signature;
    fence_signature: Signature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/lift-rollback-completion-receipt-body-v1.schema.json
export namespace Security_LiftRollbackCompletionReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type LiftOutcome =
    | {
        state: "planned";
      }
    | {
        state: "apply_failed";
        error_code: string;
      }
    | {
        state: "restored";
        resulting_version_hash: Digest;
      }
    | {
        state: "rollback_failed";
        error_code: string;
      }
    | {
        state: "no_rollback_required";
      };

  export interface ChioLiftOrRollbackCompletionReceiptBodyV1 {
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    execution_dispatch: ExecutionDispatch | null;
    dispatch_authorization_hash: Digest | null;
    response_generation: number;
    response_body_hash: Digest;
    final_state: "lifted" | "rollback_partial";
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [
      {
        effect: Effect;
        outcome: LiftOutcome;
      },
      ...{
        effect: Effect;
        outcome: LiftOutcome;
      }[]
    ];
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: string;
    trigger_finding_id: string;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
  export interface ExecutionDispatch {
    schema_version: 1;
    tenant_id: string;
    dispatch_id: string;
    action_id: string;
    plan_hash: Digest;
    executor_authority_id: string;
    executor_authority_generation: number;
    authorization_capability_hash: Digest;
    governed_intent_hash: Digest;
    policy_decision_hash: Digest;
    approval:
      | {
          approval_mode: "automatic";
        }
      | {
          approval_mode: "governed";
          admission_operation_id: string;
          admission_operation_version: number;
          approval_set_hash: Digest;
        };
    authorized_at_unix_ms: number;
  }
  export interface Effect {
    effect_id: string;
    ordinal: number;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          target_type: "session";
          session_id: string;
        }
      | {
          target_type: "lineage";
          lineage_id: string;
        }
      | {
          target_type: "capability_set";
          affected_set_hash: Digest;
        };
    contribution_hash: Digest;
    observed_base_version_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/mcp-cage-launch-policy-v2.schema.json
export namespace Security_McpCageLaunchPolicyV2 {
  export type PublicKey = string;
  export type AbsoluteCanonicalPath = string;
  export type EnvironmentVariable = string;
  export type Digest = string;
  export type Identifier = string;
  export type EnterpriseMigration = {
    [k: string]: unknown;
  } & {
    state_database_path: AbsoluteCanonicalPath;
    deployment_id: Identifier;
    stage: "disabled" | "shadow" | "enforced" | "legacy_removed";
    /**
     * @minItems 1
     * @maxItems 16
     */
    trusted_transition_signers:
      | [PublicKey]
      | [PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey, PublicKey]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ]
      | [
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey,
          PublicKey
        ];
    minimum_head: MinimumHead;
  };
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type NonzeroDigest32 = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type BrokerBinding = {
    inherited_fd?: number;
    socket_path?: AbsoluteCanonicalPath;
    authentication_digest: Digest;
    expected_peer_identity: BrokerPeerIdentity;
  } & BrokerBinding1;
  export type BrokerBinding1 = {};
  export type Signature = string;

  /**
   * Canonical signed operator policy for a migration-enforced MCP stdio cage launch.
   */
  export interface ChioSignedMCPCageLaunchPolicyV2 {
    body: PolicyBody;
    signer_public_key: PublicKey;
    signature: Signature;
  }
  export interface PolicyBody {
    schema: "chio.mcp.cage-launch-policy.v2";
    signed_manifest: ChioSignedToolManifestV2;
    registered_public_key: PublicKey;
    operator_ceilings: OperatorCeilings;
    runtime: Runtime;
    limits: Limits;
    receipt: ReceiptRuntime;
    enterprise_migration: EnterpriseMigration;
    broker?: BrokerBinding;
  }
  /**
   * Exact SignedManifest envelope admitted by chio-cage before any manifest permission is read.
   */
  export interface ChioSignedToolManifestV2 {
    manifest: ChioToolManifestV2;
    signature: string;
    signer_key: string;
  }
  /**
   * Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
   */
  export interface ChioToolManifestV2 {
    schema: "chio.manifest.v2";
    server_id: string;
    name: string;
    description?: string;
    version: string;
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    required_permissions?: RequiredPermissions;
    public_key: string;
  }
  export interface ToolDefinition {
    name: string;
    description: string;
    input_schema: {};
    output_schema?: {};
    pricing?: ToolPricing;
    annotations: ToolAnnotations;
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    flow?: ToolFlowDeclaration;
  }
  export interface ToolPricing {
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    base_price?: MonetaryAmount;
    unit_price?: MonetaryAmount;
    billing_unit?: string;
  }
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface ToolAnnotations {
    read_only: boolean;
    destructive: boolean;
    idempotent: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    output_label?: KnownLabel;
    input_clearance?: KnownLabel;
    egress: boolean;
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
  }
  export interface KnownLabel {
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
    /**
     * @maxItems 64
     */
    compartments: string[];
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
  export interface OperatorCeilings {
    read_paths: AbsoluteCanonicalPath[];
    write_paths: AbsoluteCanonicalPath[];
    network_destinations: NetworkDestination[];
    environment_variables: EnvironmentVariable[];
    /**
     * @minItems 1
     */
    native_syscall_profiles: [
      "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1",
      ...("native_minimal_v1" | "native_standard_v1" | "brokered_native_v1")[]
    ];
    forbidden_paths: AbsoluteCanonicalPath[];
  }
  export interface Runtime {
    cage_init_path: AbsoluteCanonicalPath;
    cage_init_binding_digest: Digest;
    target_path: AbsoluteCanonicalPath;
    target_binding_digest: Digest;
    working_directory: AbsoluteCanonicalPath;
    /**
     * @maxItems 48
     */
    runtime_files: AbsoluteCanonicalPath[];
    /**
     * @minItems 1
     * @maxItems 256
     */
    target_argv: [string, ...string[]];
    execution_identity: ExecutionIdentity;
  }
  export interface ExecutionIdentity {
    uid: number;
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
  }
  export interface Limits {
    max_artifact_bytes: number;
    launch_timeout_ms: number;
    nofile_soft: 192;
    nofile_hard: 192;
  }
  export interface ReceiptRuntime {
    database_path: AbsoluteCanonicalPath;
    signer_seed_path: AbsoluteCanonicalPath;
    trusted_signer_public_key: PublicKey;
    capability_id: Identifier;
    tenant_id?: Identifier;
  }
  export interface MinimumHead {
    key: MigrationKey;
    minimum_generation: 0 | 1 | 2 | 3;
    transition_digest: NonzeroDigest32;
  }
  export interface MigrationKey {
    deployment_id: Identifier;
    scope_kind: "tool_server";
    scope_id: Identifier;
    control: "cage_enforcement";
  }
  export interface BrokerPeerIdentity {
    pid: number;
    uid: number;
    gid: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json
export namespace Security_ResponseCompletionReceiptBodyV1 {
  export type ChioResponseCompletionReceiptBodyV1 = {
    [k: string]: unknown;
  } & {
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    execution_dispatch: ExecutionDispatch | null;
    dispatch_authorization_hash: Digest | null;
    response_generation: number;
    response_body_hash: Digest;
    final_state: "active" | "apply_partial" | "failed";
    error_code: string | null;
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [
      {
        effect: Effect;
        outcome: CompletionOutcome;
      },
      ...{
        effect: Effect;
        outcome: CompletionOutcome;
      }[]
    ];
  };
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type DispatchApproval =
    | {
        approval_mode: "automatic";
      }
    | {
        approval_mode: "governed";
        admission_operation_id: string;
        admission_operation_version: number;
        approval_set_hash: Digest;
      };
  export type CompletionOutcome =
    | {
        state: "planned";
      }
    | {
        state: "applied";
        resulting_version_hash: Digest;
      }
    | {
        state: "apply_failed";
        error_code: string;
      };

  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: string;
    trigger_finding_id: string;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
  export interface ExecutionDispatch {
    schema_version: 1;
    tenant_id: string;
    dispatch_id: string;
    action_id: string;
    plan_hash: Digest;
    executor_authority_id: string;
    executor_authority_generation: number;
    authorization_capability_hash: Digest;
    governed_intent_hash: Digest;
    policy_decision_hash: Digest;
    approval: DispatchApproval;
    authorized_at_unix_ms: number;
  }
  export interface Effect {
    effect_id: string;
    ordinal: number;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          target_type: "session";
          session_id: string;
        }
      | {
          target_type: "lineage";
          lineage_id: string;
        }
      | {
          target_type: "capability_set";
          affected_set_hash: Digest;
        };
    contribution_hash: Digest;
    observed_base_version_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-effect-v1.schema.json
export namespace Security_ResponseEffectV1 {
  export type Identifier = string;
  export type Kind =
    | "escalate_alert"
    | "throttle_session"
    | "restrict_egress"
    | "suspend_session"
    | "suspend_capability_set"
    | "freeze_issuance";
  export type Target =
    | {
        target_type: "tenant";
        tenant_id: Identifier;
      }
    | {
        target_type: "session";
        session_id: Identifier;
      }
    | {
        target_type: "lineage";
        lineage_id: Identifier;
      }
    | {
        target_type: "capability_set";
        affected_set_hash: Digest;
      };
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioResponseEffectV1 {
    effect_id: Identifier;
    ordinal: number;
    kind: Kind;
    target: Target;
    /**
     * @maxItems 1048576
     */
    canonical_contribution: number[];
    contribution_hash: Digest;
    observed_base_version_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-plan-receipt-body-v1.schema.json
export namespace Security_ResponsePlanReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioResponsePlanReceiptBodyV1 {
    header: Header;
    response: Response;
    plan_created_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [Effect, ...Effect[]];
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: string;
    trigger_finding_id: string;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
  export interface Effect {
    effect_id: string;
    ordinal: number;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          target_type: "session";
          session_id: string;
        }
      | {
          target_type: "lineage";
          lineage_id: string;
        }
      | {
          target_type: "capability_set";
          affected_set_hash: Digest;
        };
    contribution_hash: Digest;
    observed_base_version_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-plan-v1.schema.json
export namespace Security_ResponsePlanV1 {
  export type Identifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest1 = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type Time = number;
  export type ApprovalRequirement =
    | {
        approval_type: "automatic";
      }
    | {
        approval_type: "governed";
        policy_id: Identifier;
      };

  export interface ChioResponsePlanV1 {
    action_id: Identifier;
    trigger_finding_id: Identifier;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: Identifier;
    tenant_id: Identifier;
    policy_version: Identifier;
    policy_hash: Digest;
    /**
     * @minItems 1
     * @maxItems 4096
     */
    affected_ids: [Identifier, ...Identifier[]];
    affected_set_hash: Digest;
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [ChioResponseEffectV1, ...ChioResponseEffectV1[]];
    ttl_ms: Time;
    created_at_unix_ms: Time;
    expires_at_unix_ms: Time;
    operator_capability: OperatorCapability;
    approval_requirement: ApprovalRequirement;
    submitter: Identifier;
    reason_hash: Digest;
    plan_hash: Digest;
  }
  export interface ChioResponseEffectV1 {
    effect_id: string;
    ordinal: number;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          target_type: "session";
          session_id: string;
        }
      | {
          target_type: "lineage";
          lineage_id: string;
        }
      | {
          target_type: "capability_set";
          affected_set_hash: Digest1;
        };
    /**
     * @maxItems 1048576
     */
    canonical_contribution: number[];
    contribution_hash: Digest1;
    observed_base_version_hash: Digest1;
  }
  export interface OperatorCapability {
    capability_id: Identifier;
    capability_digest: Digest;
    expires_at_unix_ms: Time;
    executor_subject: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-state-transition-receipt-body-v1.schema.json
export namespace Security_ResponseStateTransitionReceiptBodyV1 {
  export type Time = number;
  export type Identifier = string;
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  export type State =
    | "planned"
    | "awaiting_approval"
    | "applying"
    | "active"
    | "apply_partial"
    | "expiring"
    | "rolling_back"
    | "rollback_partial"
    | "cancelled"
    | "expired"
    | "failed"
    | "lifted";

  export interface ChioResponseStateTransitionReceiptBodyV1 {
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    generation: number;
    from_state: State;
    to_state: State;
    cause:
      | "approval_requested"
      | "approval_satisfied"
      | "apply_started"
      | "apply_completed"
      | "applying_lease_renewed"
      | "applying_lease_expired"
      | "plan_expired"
      | "operator_cancelled"
      | "rollback_completed"
      | "rollback_failed"
      | "rollback_requested"
      | "rollback_retry"
      | "validation_failed";
    applying_lease_expires_at_unix_ms: Time | null;
    scheduler_lease_owner_id?: Identifier | null;
    scheduler_fencing_token?: number | null;
    error_code: Identifier | null;
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: Time;
    tenant_id: Identifier;
    transition_id: Identifier;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [Identifier, ...Identifier[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: Identifier;
    trigger_finding_id: Identifier;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: Identifier;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: Time;
  }
  export interface Policy {
    policy_version: Identifier;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/scheduler-health-receipt-body-v1.schema.json
export namespace Security_SchedulerHealthReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioSchedulerHealthReceiptBodyV1 {
    header: Header;
    response: Response;
    event_id: string;
    first_failure_at_unix_ms: number;
    attempts: number;
    scheduler_fencing_token: number;
    error_code: string;
    evidence_hash: Digest;
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
  }
  export interface Response {
    policy: Policy;
    plan_hash: Digest;
    action_id: string;
    trigger_finding_id: string;
    trigger_finding_hash: Digest;
    trigger_finding_receipt_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/security-event-body-v1.schema.json
export namespace Security_SecurityEventBodyV1 {
  export type Identifier = string;
  export type Time = number;

  export interface ChioSecurityEventBodyV1 {
    event_id: Identifier;
    event_time_unix_ms: Time;
    ingest_time_unix_ms: Time;
    tenant_id: Identifier;
    subject: Subject;
    source_receipt_id: Identifier;
    event_kind:
      | "canary_invocation"
      | "credential_access"
      | "declassification_attempt"
      | "detector_health"
      | "egress_attempt"
      | "flow_denial"
      | "tool_invocation"
      | "tripwire_observation"
      | "watermark_observation";
    severity: "informational" | "low" | "medium" | "high" | "critical";
    /**
     * @minItems 1
     * @maxItems 64
     */
    evidence_references: [Identifier, ...Identifier[]];
    producer_id: Identifier;
    producer_key_id: Identifier;
    trust_class: "internal_detector" | "verified_receipt";
    policy_version: Identifier;
  }
  export interface Subject {
    subject_id: Identifier;
    agent_id: Identifier;
    session_id: Identifier;
    capability_id: Identifier;
    lineage_seed: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/signed-security-event-envelope-v1.schema.json
export namespace Security_SignedSecurityEventEnvelopeV1 {
  export type PublicKey = string;
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedSecurityEventProvenanceEnvelopeV1 {
    body: ChioSecurityEventBodyV1;
    producer_key: PublicKey;
    algorithm: Algorithm;
    signature: Signature;
  }
  export interface ChioSecurityEventBodyV1 {
    event_id: string;
    event_time_unix_ms: number;
    ingest_time_unix_ms: number;
    tenant_id: string;
    subject: Subject;
    source_receipt_id: string;
    event_kind:
      | "canary_invocation"
      | "credential_access"
      | "declassification_attempt"
      | "detector_health"
      | "egress_attempt"
      | "flow_denial"
      | "tool_invocation"
      | "tripwire_observation"
      | "watermark_observation";
    severity: "informational" | "low" | "medium" | "high" | "critical";
    /**
     * @minItems 1
     * @maxItems 64
     */
    evidence_references: [string, ...string[]];
    producer_id: string;
    producer_key_id: string;
    trust_class: "internal_detector" | "verified_receipt";
    policy_version: string;
  }
  export interface Subject {
    subject_id: string;
    agent_id: string;
    session_id: string;
    capability_id: string;
    lineage_seed: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/signed-tool-manifest-v2.schema.json
export namespace Security_SignedToolManifestV2 {
  /**
   * Exact SignedManifest envelope admitted by chio-cage before any manifest permission is read.
   */
  export interface ChioSignedToolManifestV2 {
    manifest: ChioToolManifestV2;
    signature: string;
    signer_key: string;
  }
  /**
   * Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
   */
  export interface ChioToolManifestV2 {
    schema: "chio.manifest.v2";
    server_id: string;
    name: string;
    description?: string;
    version: string;
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    required_permissions?: RequiredPermissions;
    public_key: string;
  }
  export interface ToolDefinition {
    name: string;
    description: string;
    input_schema: {};
    output_schema?: {};
    pricing?: ToolPricing;
    annotations: ToolAnnotations;
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    flow?: ToolFlowDeclaration;
  }
  export interface ToolPricing {
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    base_price?: MonetaryAmount;
    unit_price?: MonetaryAmount;
    billing_unit?: string;
  }
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface ToolAnnotations {
    read_only: boolean;
    destructive: boolean;
    idempotent: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    output_label?: KnownLabel;
    input_clearance?: KnownLabel;
    egress: boolean;
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
  }
  export interface KnownLabel {
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
    /**
     * @maxItems 64
     */
    compartments: string[];
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/tool-flow-declaration.schema.json
export namespace Security_ToolFlowDeclaration {
  export type FlowIdentifier = string;

  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    output_label?: KnownLabel;
    input_clearance?: KnownLabel;
    egress: boolean;
    /**
     * @minItems 1
     */
    declassification_purposes?: [FlowIdentifier, ...FlowIdentifier[]];
  }
  export interface KnownLabel {
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: FlowIdentifier[];
    };
    /**
     * @maxItems 64
     */
    compartments: FlowIdentifier[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/tool-manifest-v2.schema.json
export namespace Security_ToolManifestV2 {
  /**
   * Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
   */
  export interface ChioToolManifestV2 {
    schema: "chio.manifest.v2";
    server_id: string;
    name: string;
    description?: string;
    version: string;
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    required_permissions?: RequiredPermissions;
    public_key: string;
  }
  export interface ToolDefinition {
    name: string;
    description: string;
    input_schema: {};
    output_schema?: {};
    pricing?: ToolPricing;
    annotations: ToolAnnotations;
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    flow?: ToolFlowDeclaration;
  }
  export interface ToolPricing {
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    base_price?: MonetaryAmount;
    unit_price?: MonetaryAmount;
    billing_unit?: string;
  }
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface ToolAnnotations {
    read_only: boolean;
    destructive: boolean;
    idempotent: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    output_label?: KnownLabel;
    input_clearance?: KnownLabel;
    egress: boolean;
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
  }
  export interface KnownLabel {
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
    /**
     * @maxItems 64
     */
    compartments: string[];
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/tripwire-observation-receipt-body-v1.schema.json
export namespace Security_TripwireObservationReceiptBodyV1 {
  /**
   * @minItems 32
   * @maxItems 32
   */
  export type Digest = [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];

  export interface ChioTripwireObservationReceiptBodyV1 {
    header: Header;
    policy: Policy;
    request_id: string;
    request_hash: Digest;
    event_id: string;
    tripwire_kind:
      | "canary_capability"
      | "honey_tool"
      | "credential_artifact"
      | "file_marker"
      | "browser_cookie"
      | "internal_hostname"
      | "signed_watermark";
    artifact_id_hash: Digest;
    artifact_version_hash: Digest;
    observation_hash: Digest;
    severity: "informational" | "low" | "medium" | "high" | "critical";
  }
  export interface Header {
    schema_version: 1;
    occurred_at_unix_ms: number;
    tenant_id: string;
    transition_id: string;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
  }
  export interface Policy {
    policy_version: string;
    policy_hash: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/attestation.schema.json
export namespace TrustControl_Attestation {
  /**
   * One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/platform/chio-control-plane` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
   */
  export interface ChioTrustControlRuntimeAttestationEvidence {
    /**
     * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
     */
    schema: string;
    /**
     * Attestation verifier or relying party that accepted the evidence.
     */
    verifier: string;
    /**
     * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
     */
    tier: "none" | "basic" | "attested" | "verified";
    /**
     * Unix timestamp (seconds) when this attestation was issued.
     */
    issued_at: number;
    /**
     * Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.
     */
    expires_at: number;
    /**
     * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
     */
    evidence_sha256: string;
    /**
     * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
     */
    runtime_identity?: string;
    /**
     * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
     */
    workload_identity?: {
      /**
       * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
       */
      scheme: "spiffe";
      /**
       * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
       */
      credentialKind: "uri" | "x509_svid" | "jwt_svid";
      /**
       * Canonical workload identifier URI.
       */
      uri: string;
      /**
       * Stable trust domain resolved from the identifier.
       */
      trustDomain: string;
      /**
       * Canonical workload path within the trust domain.
       */
      path: string;
    };
    /**
     * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims.
     */
    claims?: {
      [k: string]: unknown;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/budget-snapshot-anchor-provenance.schema.json
export namespace TrustControl_BudgetSnapshotAnchorProvenance {
  export type Digest = string;

  /**
   * Leader-signed inclusion chain authenticating the exact immutable migration-anchor set carried by a trust-control cluster budget snapshot.
   */
  export interface BudgetSnapshotAnchorProvenance {
    schema: "chio.budget-snapshot-anchor-provenance.v1";
    /**
     * @minItems 1
     */
    chain: [SignedCommitment, ...SignedCommitment[]];
    clusterAuthenticator: string;
  }
  export interface SignedCommitment {
    body: Commitment;
    signature: string;
  }
  export interface Commitment {
    schema: "chio.budget-snapshot-anchor-commitment.v1";
    commitSequence: number;
    previousChainDigest: Digest;
    chainDigest: Digest;
    anchorSetDigest: Digest;
    leaderUrl: string;
    electionTerm: number;
    committedAt: number;
    signerPublicKey: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/heartbeat.schema.json
export namespace TrustControl_Heartbeat {
  /**
   * One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. The contract is anchored by `spec/PROTOCOL.md` section 9 (the `/v1/internal/cluster/status` cluster lease lifecycle). Wire field names are camelCase to match the lease projection.
   */
  export interface ChioTrustControlLeaseHeartbeat {
    /**
     * Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.
     */
    leaseEpoch: number;
    /**
     * Normalized URL of the leader claiming continued ownership of the lease.
     */
    leaderUrl: string;
    /**
     * Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.
     */
    observedAt: number;
    /**
     * Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.
     */
    proposedExpiresAt?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/lease.schema.json
export namespace TrustControl_Lease {
  /**
   * One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Wire field names are camelCase. `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix seconds (`unix_timestamp_now() + leaseTtlMs / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
   */
  export interface ChioTrustControlAuthorityLease {
    /**
     * Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.
     */
    authorityId: string;
    /**
     * Normalized URL of the cluster node that currently holds the authority lease.
     */
    leaderUrl: string;
    /**
     * Cluster election term that minted this lease. Monotonically non-decreasing.
     */
    term: number;
    /**
     * Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.
     */
    leaseEpoch: number;
    /**
     * Optional unix-second timestamp at which the current term began on this leader. Omitted when unknown (no quorum or no leader).
     */
    termStartedAt?: number;
    /**
     * Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + leaseTtlMs / 1000`. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.
     */
    leaseExpiresAt: number;
    /**
     * Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms. NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.
     */
    leaseTtlMs: number;
    /**
     * True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.
     */
    leaseValid: boolean;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/terminate.schema.json
export namespace TrustControl_Terminate {
  /**
   * One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. The contract is anchored by `spec/PROTOCOL.md` section 9, where loss of quorum or a leader change clears the lease expiry and bumps the election term. Wire field names are camelCase to match the sibling lease projection so the families stay consistent on the wire.
   */
  export interface ChioTrustControlLeaseTermination {
    /**
     * Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`.
     */
    leaseEpoch: number;
    /**
     * Normalized URL of the leader releasing the lease.
     */
    leaderUrl: string;
    /**
     * Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
     */
    reason: "leader_handoff" | "quorum_lost" | "operator_stepdown" | "term_advanced";
    /**
     * Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.
     */
    observedAt: number;
    /**
     * Optional normalized URL of the successor leader, when termination is part of a planned handoff.
     */
    successorLeaderUrl?: string;
  }
}
