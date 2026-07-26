// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.
//
// Source:     spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:       json-schema-to-typescript 15.0.4 (see xtask/codegen-tools.lock.toml)
// Pin file:   sdks/typescript/scripts/package.json
// Schema SHA: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
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
    canonical_plan_body: {};
    executor_subject: string;
    expires_at: number;
    operator_capability_expires_at: number;
    operator_capability_hash: string;
    operator_capability_id: string;
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    plan_body_hash: string;
    plan_id: string;
    plan_schema: "chio.governed-response-plan.v1";
    rollback_binding: {};
    target_binding: {};
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/governed-transaction-intent.schema.json
export namespace Agent_GovernedTransactionIntent {
  export interface ChioGovernedTransactionIntent {
    autonomy?: {};
    body?:
      | {
          kind: "tool_invocation";
        }
      | {
          kind: "active_response_plan";
          value: ChioGovernedActiveResponseIntentBody;
        };
    call_chain?: {};
    commerce?: {};
    context?: unknown;
    id: string;
    max_amount?: {
      currency: string;
      units: number;
    };
    metered_billing?: {};
    purpose: string;
    runtime_attestation?: {};
    server_id: string;
    tool_name: string;
  }
  export interface ChioGovernedActiveResponseIntentBody {
    canonical_plan_body: {};
    executor_subject: string;
    expires_at: number;
    operator_capability_expires_at: number;
    operator_capability_hash: string;
    operator_capability_id: string;
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    plan_body_hash: string;
    plan_id: string;
    plan_schema: "chio.governed-response-plan.v1";
    rollback_binding: {};
    target_binding: {};
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
  export type ChioAggregateInvocationBudget = {
    max_invocations: number;
    root_binding?: ChioSignedAggregateBudgetRootBinding;
    scope: "capability" | "delegation_family";
  } & (
    | {
        scope?: "capability";
      }
    | {
        root_binding: unknown;
        scope?: "delegation_family";
      }
  );
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
        /**
         * @maxItems 64
         */
        compartments: string[];
        kind: "known";
        owners: {
          /**
           * @maxItems 256
           */
          [k: string]: string[];
        };
      }
    | {
        kind: "top";
      };
  export type ChioGovernedTransactionIntent =
    | {
        body: ToolInvocationBody;
        kind: "tool_invocation";
        schema: "chio.governed-transaction-intent.v2";
      }
    | {
        body: ActiveResponsePlanBody;
        kind: "active_response_plan";
        schema: "chio.governed-transaction-intent.v2";
      };

  export interface ChioAgentMessageToolCallRequest {
    approval_token?: ChioSignedGovernedApprovalToken;
    /**
     * @maxItems 32
     */
    approval_tokens?: ChioSignedGovernedApprovalToken[];
    capability_token: {
      aggregate_invocation_budget?: ChioAggregateInvocationBudget;
      algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
      attenuation_proof?: {
        child_scope_hash: string;
        normalized_subset_proof: string[];
        parent_scope_hash: string;
      };
      budget_share_bps?: number;
      caveats?: {
        enforced_at?: string;
        kind: string;
        predicate: unknown;
      }[];
      delegation_chain?: {
        attenuations?: {}[];
        capability_id: string;
        delegatee: string;
        delegator: string;
        scope_hash?: string;
        signature: string;
        timestamp: number;
      }[];
      expires_at: number;
      id: string;
      issued_at: number;
      issuer: string;
      /**
       * Signed-artifact schema ID for live capability-token serialization.
       */
      schema?: "chio.capability.v1";
      scope: {
        grants?: {
          constraints?: {
            type: string;
            value?: unknown;
          }[];
          dpop_required?: boolean;
          max_cost_per_invocation?: {
            currency: string;
            units: number;
          };
          max_invocations?: number;
          max_total_cost?: {
            currency: string;
            units: number;
          };
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          server_id: string;
          tool_name: string;
        }[];
        prompt_grants?: {
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          prompt_name: string;
        }[];
        resource_grants?: {
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          uri_pattern: string;
        }[];
      };
      scope_attenuations?: {
        type: string;
        [k: string]: unknown;
      }[];
      signature: string;
      subject: string;
    };
    declassification_grant?: SignedDeclassificationGrant;
    governed_intent?: ChioGovernedTransactionIntent;
    id: string;
    params: unknown;
    server_id: string;
    supplemental_authorization?: {
      /**
       * @minItems 1
       * @maxItems 65536
       */
      artifact: [number, ...number[]];
      reference: string;
    };
    threshold_approval_proposal?: ChioSignedThresholdApprovalProposal;
    tool: string;
    type: "tool_call_request";
  }
  export interface ChioSignedGovernedApprovalToken {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    approver: string;
    decision: "approved" | "denied";
    expires_at: number;
    governed_intent_hash: string;
    id: string;
    issued_at: number;
    request_id: string;
    signature: string;
    subject: string;
    threshold_proposal_hash?: string;
  }
  export interface ChioSignedAggregateBudgetRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioAggregateBudgetRootBindingBody;
    signature: string;
  }
  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: string;
    root_capability_id: string;
    root_expires_at: number;
    root_issuer: string;
    root_scope_hash: string;
    root_subject: string;
    schema: "chio.aggregate-budget-root.v1";
  }
  /**
   * One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
   */
  export interface SignedDeclassificationGrant {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    authority_key: string;
    body: {
      agent_id: string;
      authority_key_id: string;
      capability_id: string;
      destination_id: string;
      domain_version: 1;
      expires_at_unix_seconds: number;
      grant_id: string;
      issued_at_unix_seconds: number;
      purpose: string;
      request_hash: Digest32;
      session_id: string;
      source_label_hash: Digest32;
      subject_id: string;
      target_label: InformationLabel & {
        kind: "known";
      };
      tenant_id: string;
      tool_name: string;
    };
    signature: string;
  }
  export interface ToolInvocationBody {
    autonomy?: Autonomy;
    call_chain?: CallChain;
    commerce?: Commerce;
    context?: unknown;
    id: string;
    max_amount?: MonetaryAmount;
    metered_billing?: MeteredBilling;
    purpose: string;
    runtime_attestation?: {};
    server_id: string;
    tool_name: string;
  }
  export interface Autonomy {
    delegationBondId?: string;
    tier: "direct" | "delegated" | "autonomous";
  }
  export interface CallChain {
    chainId: string;
    delegatorSubject: string;
    originSubject: string;
    parentReceiptId?: string;
    parentRequestId: string;
  }
  export interface Commerce {
    seller: string;
    shared_payment_token_id: string;
  }
  export interface MonetaryAmount {
    currency: string;
    units: number;
  }
  export interface MeteredBilling {
    maxBilledUnits?: number;
    quote: {
      billingUnit: string;
      expiresAt?: number;
      issuedAt: number;
      provider: string;
      quoteId: string;
      quotedCost: MonetaryAmount;
      quotedUnits: number;
    };
    settlementMode: "must_prepay" | "hold_capture" | "allow_then_settle";
  }
  export interface ActiveResponsePlanBody {
    canonicalPlanBody: {};
    executorSubject: string;
    expiresAt: number;
    operatorCapabilityExpiresAt: number;
    operatorCapabilityHash: string;
    operatorCapabilityId: string;
    /**
     * @minItems 1
     * @maxItems 5
     */
    orderedEffects:
      | ["throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ];
    planBodyHash: string;
    planId: string;
    planSchema: "chio.response-plan.v1";
    rollbackBinding: {};
    targetBinding: {};
  }
  export interface ChioSignedThresholdApprovalProposal {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioThresholdApprovalProposalBody;
    policyAuthority: string;
    signature: string;
  }
  export interface ChioThresholdApprovalProposalBody {
    authorizationCapabilityHash: string;
    eligibleSetDigest: string;
    governedIntentHash: string;
    policyHash: string;
    proposalCreatedAt: number;
    proposalDeadline: number;
    proposalId: string;
    requestId: string;
    required: number;
    schema: "chio.threshold-approval-proposal.v1";
    subject: string;
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
        observed_at: number;
        receipt: WitnessReceipt;
      }
    | {
        error: string;
        kind: "stale";
        last_verified: number;
      };

  /**
   * Signed additive Merkle batch over receipts or checkpoints. Local receipt signatures remain authoritative; the batch adds continuity and public-witness timestamping.
   */
  export interface ChioAnchorBatchV1 {
    body: Body;
    signature: string;
  }
  export interface Body {
    /**
     * @minItems 1
     */
    checkpointIds: [string, ...string[]];
    /**
     * @minItems 1
     */
    inclusions: [Inclusion, ...Inclusion[]];
    issuedAt: number;
    schema: "chio.anchor_batch.v1";
    signerKey: string;
    treeRoot: string;
    witness: Witness;
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
    observedAt?: number;
    root: string;
    witnessId: string;
  }
  /**
   * Verifier-bound receipt returned by a public-witness lane. OTS receipts remain advisory until the lane carries trusted Bitcoin header or calendar-backed commitment evidence.
   */
  export interface WitnessReceipt {
    bodyHash: string;
    externalUuid: string;
    inclusionProof: string;
    kind: "rekor" | "ots" | "solana_memo";
    publishedAt: number;
    witnessRoot: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root-binding-body.schema.json
export namespace Capability_AggregateBudgetRootBindingBody {
  export type Digest = string;
  export type Identifier = string;
  export type PublicKey = string;

  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: Digest;
    root_capability_id: Identifier;
    root_expires_at: number;
    root_issuer: PublicKey;
    root_scope_hash: Digest;
    root_subject: PublicKey;
    schema: "chio.aggregate-budget-root.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root-binding.schema.json
export namespace Capability_AggregateBudgetRootBinding {
  export type Signature = string;

  export interface ChioSignedAggregateBudgetRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioAggregateBudgetRootBindingBody;
    signature: Signature;
  }
  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: string;
    root_capability_id: string;
    root_expires_at: number;
    root_issuer: string;
    root_scope_hash: string;
    root_subject: string;
    schema: "chio.aggregate-budget-root.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root-commitment.schema.json
export namespace Capability_AggregateBudgetRootCommitment {
  export type Identifier = string;
  export type PublicKey = string;
  export type Digest = string;

  export interface ChioAggregateBudgetRootCommitment {
    aggregate_scope: "delegation_family";
    max_invocations: number;
    root_capability_id: Identifier;
    root_expires_at: number;
    root_issued_at: number;
    root_issuer: PublicKey;
    root_scope_hash: Digest;
    root_subject: PublicKey;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root.schema.json
export namespace Capability_AggregateBudgetRoot {
  export type AggregateRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type AggregateRootPublicKey = string;
  export type AggregateRootSignature = string;

  export interface ChioAggregateBudgetRootBinding {
    algorithm?: AggregateRootSigningAlgorithm;
    body: {
      max_invocations: number;
      root_capability_hash: string;
      root_capability_id: string;
      root_expires_at: number;
      root_issuer: AggregateRootPublicKey;
      root_scope_hash: string;
      root_subject: AggregateRootPublicKey;
      schema: "chio.aggregate-budget-root.v1";
    };
    signature: AggregateRootSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-family-preservation-evidence.schema.json
export namespace Capability_AggregateFamilyPreservationEvidence {
  export interface ChioAggregateFamilyPreservationEvidence {
    maxInvocations: number;
    rootBindingDigest: string;
    rootCapabilityId: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-invocation-budget.schema.json
export namespace Capability_AggregateInvocationBudget {
  export type ChioAggregateInvocationBudget = {
    max_invocations: number;
    root_binding?: ChioSignedAggregateBudgetRootBinding;
    scope: "capability" | "delegation_family";
  } & (
    | {
        scope?: "capability";
      }
    | {
        root_binding: unknown;
        scope?: "delegation_family";
      }
  );

  export interface ChioSignedAggregateBudgetRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioAggregateBudgetRootBindingBody;
    signature: string;
  }
  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: string;
    root_capability_id: string;
    root_expires_at: number;
    root_issuer: string;
    root_scope_hash: string;
    root_subject: string;
    schema: "chio.aggregate-budget-root.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/capabilities.schema.json
export namespace Capability_Capabilities {
  /**
   * Feature bitset exchanged during federation trust establishment, including aggregate budgets, cumulative approval, threshold approval, and governed active response. Malformed feature names and unsupported schema IDs fail closed.
   */
  export interface ChioCapabilityNegotiationV1 {
    /**
     * String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.
     */
    features?: {
      [k: string]: boolean;
    };
    schema: "chio.capabilities.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/cumulative-approval-root.schema.json
export namespace Capability_CumulativeApprovalRoot {
  export type CumulativeRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type CumulativeRootPublicKey = string;
  export type CumulativeRootSignature = string;

  export interface ChioCumulativeApprovalRootBinding {
    algorithm?: CumulativeRootSigningAlgorithm;
    body: {
      approval_budget_epoch: number;
      approval_budget_id: string;
      root_capability_hash: string;
      root_capability_id: string;
      root_expires_at: number;
      root_grant_hash: string;
      root_issuer: CumulativeRootPublicKey;
      root_scope_hash: string;
      root_subject: CumulativeRootPublicKey;
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
    };
    signature: CumulativeRootSignature;
  }
  export interface CumulativeRootMonetaryAmount {
    currency: string;
    units: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/governed-approval-token-body.schema.json
export namespace Capability_GovernedApprovalTokenBody {
  export type PublicKey = string;
  export type Digest = string;
  export type GovernanceIdentifier = string;

  export interface ChioGovernedApprovalTokenBody {
    approver: PublicKey;
    decision: "approved" | "denied";
    expires_at: number;
    governed_intent_hash: Digest;
    id: GovernanceIdentifier;
    issued_at: number;
    request_id: GovernanceIdentifier;
    subject: PublicKey;
    threshold_proposal_hash?: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/governed-approval-token.schema.json
export namespace Capability_GovernedApprovalToken {
  export type PublicKey = string;
  export type Digest = string;
  export type GovernanceIdentifier = string;
  export type Signature = string;

  export interface ChioSignedGovernedApprovalToken {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    approver: PublicKey;
    decision: "approved" | "denied";
    expires_at: number;
    governed_intent_hash: Digest;
    id: GovernanceIdentifier;
    issued_at: number;
    request_id: GovernanceIdentifier;
    signature: Signature;
    subject: PublicKey;
    threshold_proposal_hash?: Digest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/governed-transaction-intent.schema.json
export namespace Capability_GovernedTransactionIntent {
  export type ChioGovernedTransactionIntent =
    | {
        body: ToolInvocationBody;
        kind: "tool_invocation";
        schema: "chio.governed-transaction-intent.v2";
      }
    | {
        body: ActiveResponsePlanBody;
        kind: "active_response_plan";
        schema: "chio.governed-transaction-intent.v2";
      };
  export type GovernanceIdentifier = string;
  export type PublicKey = string;
  export type Digest = string;

  export interface ToolInvocationBody {
    autonomy?: Autonomy;
    call_chain?: CallChain;
    commerce?: Commerce;
    context?: unknown;
    id: GovernanceIdentifier;
    max_amount?: MonetaryAmount;
    metered_billing?: MeteredBilling;
    purpose: string;
    runtime_attestation?: {};
    server_id: string;
    tool_name: string;
  }
  export interface Autonomy {
    delegationBondId?: GovernanceIdentifier;
    tier: "direct" | "delegated" | "autonomous";
  }
  export interface CallChain {
    chainId: GovernanceIdentifier;
    delegatorSubject: string;
    originSubject: string;
    parentReceiptId?: GovernanceIdentifier;
    parentRequestId: GovernanceIdentifier;
  }
  export interface Commerce {
    seller: string;
    shared_payment_token_id: string;
  }
  export interface MonetaryAmount {
    currency: string;
    units: number;
  }
  export interface MeteredBilling {
    maxBilledUnits?: number;
    quote: {
      billingUnit: string;
      expiresAt?: number;
      issuedAt: number;
      provider: string;
      quoteId: GovernanceIdentifier;
      quotedCost: MonetaryAmount;
      quotedUnits: number;
    };
    settlementMode: "must_prepay" | "hold_capture" | "allow_then_settle";
  }
  export interface ActiveResponsePlanBody {
    canonicalPlanBody: {};
    executorSubject: PublicKey;
    expiresAt: number;
    operatorCapabilityExpiresAt: number;
    operatorCapabilityHash: Digest;
    operatorCapabilityId: GovernanceIdentifier;
    /**
     * @minItems 1
     * @maxItems 5
     */
    orderedEffects:
      | ["throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ]
      | [
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
          "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance"
        ];
    planBodyHash: Digest;
    planId: GovernanceIdentifier;
    planSchema: "chio.response-plan.v1";
    rollbackBinding: {};
    targetBinding: {};
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
    constraints?: Constraint[];
    /**
     * If true, the kernel requires a valid DPoP proof for every invocation under this grant.
     */
    dpop_required?: boolean;
    max_cost_per_invocation?: MonetaryAmount;
    max_invocations?: number;
    max_total_cost?: MonetaryAmount;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    /**
     * Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
     */
    server_id: string;
    /**
     * Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
     */
    tool_name: string;
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
    currency: string;
    units: number;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    uri_pattern: string;
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    prompt_name: string;
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
// Source: spec/schemas/chio-wire/v1/capability/threshold-approval-proposal-body.schema.json
export namespace Capability_ThresholdApprovalProposalBody {
  export type Digest = string;
  export type GovernanceIdentifier = string;
  export type PublicKey = string;

  export interface ChioThresholdApprovalProposalBody {
    authorizationCapabilityHash: Digest;
    eligibleSetDigest: Digest;
    governedIntentHash: Digest;
    policyHash: Digest;
    proposalCreatedAt: number;
    proposalDeadline: number;
    proposalId: GovernanceIdentifier;
    requestId: GovernanceIdentifier;
    required: number;
    schema: "chio.threshold-approval-proposal.v1";
    subject: PublicKey;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/threshold-approval-proposal.schema.json
export namespace Capability_ThresholdApprovalProposal {
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedThresholdApprovalProposal {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioThresholdApprovalProposalBody;
    policyAuthority: PublicKey;
    signature: Signature;
  }
  export interface ChioThresholdApprovalProposalBody {
    authorizationCapabilityHash: string;
    eligibleSetDigest: string;
    governedIntentHash: string;
    policyHash: string;
    proposalCreatedAt: number;
    proposalDeadline: number;
    proposalId: string;
    requestId: string;
    required: number;
    schema: "chio.threshold-approval-proposal.v1";
    subject: string;
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
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    caveats?: Caveat[];
    delegation_chain?: DelegationLink[];
    expires_at: number;
    id: string;
    issued_at: number;
    issuer: string;
    schema?: "chio.capability.v1";
    scope: ChioScope;
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    signature: string;
    subject: string;
  };
  export type ChioAggregateInvocationBudget = {
    max_invocations: number;
    root_binding?: ChioSignedAggregateBudgetRootBinding;
    scope: "capability" | "delegation_family";
  } & (
    | {
        scope?: "capability";
      }
    | {
        root_binding: unknown;
        scope?: "delegation_family";
      }
  );
  export type Constraint =
    | GenericConstraint
    | LegacyApprovalConstraint
    | CumulativeApprovalDirectConstraint
    | CumulativeApprovalDelegableConstraint;
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";

  export interface ChioSignedAggregateBudgetRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioAggregateBudgetRootBindingBody;
    signature: string;
  }
  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: string;
    root_capability_id: string;
    root_expires_at: number;
    root_issuer: string;
    root_scope_hash: string;
    root_subject: string;
    schema: "chio.aggregate-budget-root.v1";
  }
  export interface AttenuationProof {
    aggregateFamilyPreservation?: ChioAggregateFamilyPreservationEvidence;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
    parentScopeHash: string;
  }
  export interface ChioAggregateFamilyPreservationEvidence {
    maxInvocations: number;
    rootBindingDigest: string;
    rootCapabilityId: string;
  }
  export interface AttenuationWitness {
    normalizedChildScope: string;
    normalizedParentScope: string;
    restrictedPredicates?: string[];
    subsetRelations?: GrantSubsetRelation[];
  }
  export interface GrantSubsetRelation {
    childIndex: number;
    grantKind: "tool" | "resource" | "prompt";
    parentIndex: number;
    subset: true;
  }
  export interface Caveat {
    kind: "restrict_tool" | "bind_session" | "restrict_audience" | "restrict_geo" | "restrict_time_window";
    predicate: string;
    sig?: string;
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    aggregate_family_preservation?: ChioAggregateFamilyPreservationEvidence;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    capability_id: string;
    delegatee: string;
    delegator: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
    signature: string;
    timestamp: number;
  }
  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    prompt_grants?: PromptGrant[];
    resource_grants?: ResourceGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    constraints?: Constraint[];
    dpop_required?: boolean;
    max_cost_per_invocation?: MonetaryAmount;
    max_invocations?: number;
    max_total_cost?: MonetaryAmount;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    server_id: string;
    tool_name: string;
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
      approval_budget_epoch: number;
      approval_budget_id: string;
      cumulative_approval_root_binding?: never;
      threshold: MonetaryAmount;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    currency: string;
    units: number;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      approval_budget_epoch: number;
      approval_budget_id: string;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
      threshold: MonetaryAmount;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: {
      approval_budget_epoch: number;
      approval_budget_id: string;
      root_capability_hash: string;
      root_capability_id: string;
      root_expires_at: number;
      root_grant_hash: string;
      root_issuer: string;
      root_scope_hash: string;
      root_subject: string;
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
    };
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    currency: string;
    units: number;
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    prompt_name: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    uri_pattern: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/verified-approval-set.schema.json
export namespace Capability_VerifiedApprovalSet {
  export type Digest = string;
  export type GovernanceIdentifier = string;
  export type PublicKey = string;

  export interface ChioVerifiedThresholdApprovalSet {
    authorizationCapabilityHash: Digest;
    /**
     * @minItems 1
     * @maxItems 32
     */
    canonicalTokenDigests: [Digest, ...Digest[]];
    eligibleSetDigest: Digest;
    governedIntentHash: Digest;
    policyHash: Digest;
    proposalCreatedAt: number;
    proposalDeadline: number;
    proposalId: GovernanceIdentifier;
    requestId: GovernanceIdentifier;
    required: number;
    schema: "chio.verified-approval-set.v1";
    subject: PublicKey;
    thresholdProposalHash: Digest;
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
    payload: string;
    payloadType: "application/vnd.in-toto+json";
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
    predicate: {
      capability_lease_ref?: CapabilityLeaseRef;
      co_sign: "bilateral_required" | "bilateral_if_cross_org";
      consistency_anchor?: string;
      consistency_model: "crdt-commutative";
      cross_org_visibility: "private" | "treaty_only" | "federated" | "public";
      governance_receipt_ref?: GovernanceReceiptRef;
      invocation_id: string;
      policy_evaluation_summary?: PolicyEvaluationSummary;
      receipt_canonical_json: string;
      schema: "chio.bilateral-signature-slice.v1";
      timestamp_unix_ms: number;
      tool_name: string;
      tool_server_a: KernelIdentity;
      tool_server_b: KernelIdentity;
    };
    predicateType: "chio.bilateral-signature-slice.v1";
    /**
     * @minItems 1
     * @maxItems 1
     */
    subject: [
      {
        digest: {
          sha256: string;
        };
        name: string;
      }
    ];
  }
  export interface CapabilityLeaseRef {
    expires_at_unix_ms: number;
    issuer: string;
    lease_id: string;
    scope_digest?: HashRecord;
  }
  export interface HashRecord {
    alg: "sha256";
    value: string;
  }
  export interface GovernanceReceiptRef {
    digest: HashRecord;
    kernel_id: string;
    receipt_id: string;
  }
  export interface PolicyEvaluationSummary {
    joint_disposition?: "allow" | "deny";
    server_a_verdict: PolicyVerdict;
    server_b_verdict: PolicyVerdict;
  }
  export interface PolicyVerdict {
    policy_id: string;
    policy_version: string;
    rationale_code?: string;
    verdict: "allow" | "deny";
  }
  export interface KernelIdentity {
    alg: "ed25519";
    kernel_id: string;
    passport_key_fingerprint: string;
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
     * Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.
     */
    id: number | string | null;
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
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
     * Error payload. Present only on failure. Mutually exclusive with `result`.
     */
    error?: {
      /**
       * JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).
       */
      code: number;
      /**
       * Optional structured detail. Shape is method- or code-specific.
       */
      data?: {
        [k: string]: unknown;
      };
      /**
       * Short human-readable error description.
       */
      message: string;
    };
    /**
     * Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
     */
    id: number | string | null;
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.
     */
    result?: {
      [k: string]: unknown;
    };
  } & {
    [k: string]: unknown;
  };
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_list.schema.json
export namespace Kernel_CapabilityList {
  export type ChioAggregateInvocationBudget = {
    max_invocations: number;
    root_binding?: ChioSignedAggregateBudgetRootBinding;
    scope: "capability" | "delegation_family";
  } & (
    | {
        scope?: "capability";
      }
    | {
        root_binding: unknown;
        scope?: "delegation_family";
      }
  );

  export interface ChioKernelMessageCapabilityList {
    capabilities: {
      aggregate_invocation_budget?: ChioAggregateInvocationBudget;
      algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
      attenuation_proof?: {
        child_scope_hash: string;
        normalized_subset_proof: string[];
        parent_scope_hash: string;
      };
      budget_share_bps?: number;
      caveats?: {
        enforced_at?: string;
        kind: string;
        predicate: unknown;
      }[];
      delegation_chain?: {
        attenuations?: {}[];
        capability_id: string;
        delegatee: string;
        delegator: string;
        signature: string;
        timestamp: number;
      }[];
      expires_at: number;
      id: string;
      issued_at: number;
      issuer: string;
      /**
       * Signed-artifact schema ID for live capability-token serialization.
       */
      schema?: "chio.capability.v1";
      scope: {
        grants?: {
          constraints?: {
            type: string;
            value?: unknown;
          }[];
          dpop_required?: boolean;
          max_cost_per_invocation?: {
            currency: string;
            units: number;
          };
          max_invocations?: number;
          max_total_cost?: {
            currency: string;
            units: number;
          };
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          server_id: string;
          tool_name: string;
        }[];
        prompt_grants?: {
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          prompt_name: string;
        }[];
        resource_grants?: {
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          uri_pattern: string;
        }[];
      };
      scope_attenuations?: {
        type: string;
        [k: string]: unknown;
      }[];
      signature: string;
      subject: string;
    }[];
    type: "capability_list";
  }
  export interface ChioSignedAggregateBudgetRootBinding {
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioAggregateBudgetRootBindingBody;
    signature: string;
  }
  export interface ChioAggregateBudgetRootBindingBody {
    max_invocations: number;
    root_capability_hash: string;
    root_capability_id: string;
    root_expires_at: number;
    root_issuer: string;
    root_scope_hash: string;
    root_subject: string;
    schema: "chio.aggregate-budget-root.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_revoked.schema.json
export namespace Kernel_CapabilityRevoked {
  export interface ChioKernelMessageCapabilityRevoked {
    id: string;
    type: "capability_revoked";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/combined-capture-metadata.schema.json
export namespace Kernel_CombinedCaptureMetadata {
  export interface ChioCombinedAdmissionCaptureMetadata {
    budget_commit_index: number;
    hold_id: string;
    leader_epoch: number;
    operation_id: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quota_keys:
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ]
      | [
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          },
          {
            grant_index?: number;
            owner_id: string;
            profile: string;
          }
        ];
    revocation_commit_index: number;
    revocation_set_digest: string;
    schema: "chio.admission-capture-metadata.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/execution_nonce.schema.json
export namespace Kernel_ExecutionNonce {
  export interface ChioSignedExecutionNonce {
    nonce: {
      bound_to: {
        capability_id: string;
        parameter_hash: string;
        request_id: string;
        subject_id: string;
        tool_name: string;
        tool_server: string;
      };
      expires_at: number;
      issued_at: number;
      nonce_id: string;
      reserved_hold_id?: string;
      reserving_request_id?: string;
      schema: "chio.execution_nonce.v1";
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
    chunk_index: number;
    data: unknown;
    id: string;
    type: "tool_call_chunk";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/tool_call_response.schema.json
export namespace Kernel_ToolCallResponse {
  /**
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
   */
  export type ChioReceiptRecord = {
    [k: string]: unknown;
  } & {
    action: ToolCallAction;
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384";
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    decision?: Decision;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/core/chio-core-types/src/crypto.rs`.
     */
    kernel_key: string;
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/core/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
     */
    signature: string;
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        verdict: "deny";
      }
    | {
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
        verdict: "cancelled";
      }
    | {
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
        verdict: "incomplete";
      };

  export interface ChioKernelMessageToolCallResponse {
    execution_nonce?: ChioSignedExecutionNonce;
    id: string;
    receipt: ChioReceiptRecord;
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
          chunks_received: number;
          reason: string;
          status: "cancelled";
        }
      | {
          chunks_received: number;
          reason: string;
          status: "incomplete";
        }
      | {
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
          status: "err";
        };
    type: "tool_call_response";
  }
  export interface ChioSignedExecutionNonce {
    nonce: {
      bound_to: {
        capability_id: string;
        parameter_hash: string;
        request_id: string;
        subject_id: string;
        tool_name: string;
        tool_server: string;
      };
      expires_at: number;
      issued_at: number;
      nonce_id: string;
      reserved_hold_id?: string;
      reserving_request_id?: string;
      schema: "chio.execution_nonce.v1";
    };
    signature: string;
  }
  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    projection_version: "chio.bbs-projection.receipt.v1";
    schema: "chio.receipt.bbs_signature.v1";
    signature_hex: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
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
     * Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.
     */
    assembledAt: number;
    /**
     * Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.
     */
    chainId: string;
    /**
     * Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`, which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
     */
    evidenceClass: "asserted" | "observed" | "verified";
    /**
     * Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.
     */
    issuer?: string;
    /**
     * Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.
     *
     * @minItems 1
     */
    statements: [
      {
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
        };
      },
      ...{
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
        };
      }[]
    ];
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
     * Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.
     */
    delegatorSubject: string;
    /**
     * Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).
     */
    originSubject: string;
    /**
     * Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.
     */
    parentReceiptId?: string;
    /**
     * Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.
     */
    parentRequestId: string;
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
     * Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.
     */
    api_version: string;
    /**
     * Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.
     */
    principal: string;
    /**
     * Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`).
     */
    provider: string;
    /**
     * Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; Chio fails closed if the value is in the future relative to the kernel clock.
     */
    received_at: number;
    /**
     * Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.
     */
    request_id: string;
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
     * Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
     */
    chainId: string;
    /**
     * Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.
     */
    evidenceClass?: "asserted" | "observed" | "verified";
    /**
     * Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.
     */
    guard?: string;
    /**
     * Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.
     */
    reason?: string;
    /**
     * Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
     */
    receiptId?: string;
    /**
     * Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.
     */
    renderedAt: number;
    /**
     * Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.
     */
    requestId: string;
    /**
     * Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
     */
    verdict: "allow" | "deny" | "cancel" | "incomplete";
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
  export type PositiveIJsonInteger = number;
  export type Identifier = string;
  export type Digest = string;

  export interface ChioDurableAdmissionReceiptMetadata {
    compensation_status: "not_compensated" | "compensated_before_dispatch" | "not_accepted_after_dispatch_commit";
    coordinator_lease_epoch: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    operation_id: Digest;
    projected_dispatch_state:
      | "not_committed"
      | "capture_pending"
      | "committed"
      | "finalizing"
      | "terminal"
      | "not_applicable";
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
      | "mutation_ready"
      | "mutation_submitted"
      | "economic_mutation_applied"
      | "economic_mutation_not_applied";
    request_binding_hash: Digest;
    request_id: Identifier;
    request_namespace_digest: Digest;
    retained_dispatch_commit: null | DispatchCommit;
    schema: "chio.admission-receipt.v1";
    store_fence: StoreFence;
    tool_outcome_id: null | Digest;
    tool_outcome_version: null | PositiveIJsonInteger;
    trusted_time_unix_ms: PositiveIJsonInteger;
  }
  export interface DispatchCommit {
    committed_version: PositiveIJsonInteger;
    coordinator_lease_epoch: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    provider_attempt: null | ProviderAttempt;
    store_fence: StoreFence;
  }
  export interface ProviderAttempt {
    attempt_id: Identifier;
    operation_id: Digest;
    transport_id: Identifier;
    transport_key_epoch: PositiveIJsonInteger;
  }
  export interface StoreFence {
    lease_id: Identifier;
    owner_epoch: PositiveIJsonInteger;
    store_uuid: Identifier;
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
     * Ordered sibling hashes from leaf-level up to (but not including) the root. Siblings that were carried upward without pairing on the right edge of an unbalanced level are omitted, so the path length is not strictly `ceil(log2(tree_size))`. Each entry is a `chio-core-types::Hash` serialized via its transparent serde adapter (32-byte SHA-256 digest, hex-encoded with a `0x` prefix).
     */
    audit_path: string[];
    /**
     * Zero-based index of the leaf being proved. MUST satisfy `leaf_index < tree_size`.
     */
    leaf_index: number;
    /**
     * Total number of leaves in the Merkle tree at the time the proof was issued.
     */
    tree_size: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json
export namespace Receipt_LineageStatement {
  /**
   * Signed pairwise receipt lineage statement. Multi-parent lineage views are derived aggregates over these signed parent-child statements.
   */
  export interface ChioReceiptLineageStatement {
    childReceiptId: string;
    childRequestId: string;
    childSessionAnchor: SessionAnchorReference;
    continuationTokenId?: string;
    evidenceClass: "asserted" | "observed" | "verified";
    id: string;
    issuedAt: number;
    kernelKey: string;
    parentReceiptId: string;
    parentRequestId: string;
    parentSessionAnchor: SessionAnchorReference;
    relationKind: "local_child" | "continued";
    schema: "chio.receipt_lineage_statement.v1";
    signature: string;
  }
  export interface SessionAnchorReference {
    sessionAnchorHash: string;
    sessionAnchorId: string;
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
    action: ToolCallAction;
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384";
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    decision?: Decision;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/core/chio-core-types/src/crypto.rs`.
     */
    kernel_key: string;
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/core/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
     */
    signature: string;
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        verdict: "deny";
      }
    | {
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
        verdict: "cancelled";
      }
    | {
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
        verdict: "incomplete";
      };

  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    projection_version: "chio.bbs-projection.receipt.v1";
    schema: "chio.receipt.bbs_signature.v1";
    signature_hex: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/cancelled.schema.json
export namespace Result_Cancelled {
  export interface ChioToolCallResultCancelled {
    chunks_received: number;
    reason: string;
    status: "cancelled";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/err.schema.json
export namespace Result_Err {
  export interface ChioToolCallResultErr {
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
    status: "err";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/incomplete.schema.json
export namespace Result_Incomplete {
  export interface ChioToolCallResultIncomplete {
    chunks_received: number;
    reason: string;
    status: "incomplete";
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
    authorizationDigest: Digest;
    completedAtUnixSeconds: number;
    intentDigest: Digest;
    operation: "issue" | "revoke" | "status";
    operationId: Digest;
    outcome: "applied";
    requestId: Identifier;
    responseDigest: Digest;
    schema: "chio.broker-admin-control-receipt.v1";
    tenantScope: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-control-receipt-envelope-v1.schema.json
export namespace Security_BrokerAdminControlReceiptEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerAdminControlReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAdminControlReceiptBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerAdminControlReceiptBodyV1 {
    authorizationDigest: string;
    completedAtUnixSeconds: number;
    intentDigest: string;
    operation: "issue" | "revoke" | "status";
    operationId: string;
    outcome: "applied";
    requestId: string;
    responseDigest: string;
    schema: "chio.broker-admin-control-receipt.v1";
    tenantScope: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-mutation-receipt-body-v1.schema.json
export namespace Security_BrokerAdminMutationReceiptBodyV1 {
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerAdminMutationReceiptBodyV1 {
    authorizationDigest: Digest;
    completedAtUnixSeconds: number;
    credential: CredentialRef;
    intentDigest: Digest;
    operation: "provision" | "rotate" | "disable" | "delete";
    operationId: Digest;
    outcome: "applied";
    requestId: Identifier;
    schema: "chio.broker-admin-mutation-receipt.v1";
    tenantScope: Identifier;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-admin-mutation-receipt-envelope-v1.schema.json
export namespace Security_BrokerAdminMutationReceiptEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerAdminMutationReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAdminMutationReceiptBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerAdminMutationReceiptBodyV1 {
    authorizationDigest: string;
    completedAtUnixSeconds: number;
    credential: CredentialRef;
    intentDigest: string;
    operation: "provision" | "rotate" | "disable" | "delete";
    operationId: string;
    outcome: "applied";
    requestId: string;
    schema: "chio.broker-admin-mutation-receipt.v1";
    tenantScope: string;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-attempt-registration-v1.schema.json
export namespace Security_BrokerAttemptRegistrationV1 {
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerAttemptRegistrationV1 {
    authorityMetadataDigest: Digest;
    brokerCapabilityId: Identifier;
    ids: AttemptIds;
    invocationId: Identifier;
    nonceExpiresAtUnixSeconds: number;
    parentCapabilityId: Identifier;
    proofDigest: Digest;
    proofKeyId: Identifier;
    proofNonce: string;
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
    requestCanonicalDigest: Digest;
    requestDigest: Digest;
    revocationAuthorityDomain: Identifier;
  }
  export interface AttemptIds {
    attemptId: Identifier;
    authorizeEventId: Identifier;
    captureEventId: Identifier;
    holdId: Identifier;
    operationId: Identifier;
    reverseEventId: Identifier;
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
    accountingMutationCount: 0;
    auditAuthorizationSha256: Digest;
    auditIdSha256: Digest;
    authorityContextSha256: Digest;
    brokerOutboundProjectionCommitmentSha256: Digest;
    canonicalRequestSha256: Digest;
    capabilitySha256: Digest;
    governedAuditIntentSha256: Digest;
    issuedAtUnixSeconds: number;
    networkDispatchCount: 0;
    projectionsEqual: boolean;
    proofSha256: Digest;
    rawCredentialReturned: false;
    referenceOutboundProjectionCommitmentSha256: Digest;
    referenceSourceSha256: Digest;
    runnerAuthorizationSha256: Digest;
    schema: "chio.broker-audit-comparison.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-comparison-envelope-v1.schema.json
export namespace Security_BrokerAuditComparisonEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerAuditComparisonV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuditComparisonBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerAuditComparisonBodyV1 {
    accountingMutationCount: 0;
    auditAuthorizationSha256: string;
    auditIdSha256: string;
    authorityContextSha256: string;
    brokerOutboundProjectionCommitmentSha256: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    governedAuditIntentSha256: string;
    issuedAtUnixSeconds: number;
    networkDispatchCount: 0;
    projectionsEqual: boolean;
    proofSha256: string;
    rawCredentialReturned: false;
    referenceOutboundProjectionCommitmentSha256: string;
    referenceSourceSha256: string;
    runnerAuthorizationSha256: string;
    schema: "chio.broker-audit-comparison.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-runner-authorization-body-v1.schema.json
export namespace Security_BrokerAuditRunnerAuthorizationBodyV1 {
  export type Identifier = string;
  export type Digest = string;

  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    auditId: Identifier;
    brokerInstanceId: Identifier;
    canonicalRequestSha256: Digest;
    capabilitySha256: Digest;
    credentialProvider: Identifier;
    deploymentId: Identifier;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    proofSha256: Digest;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
    referenceCommitmentSha256: Digest;
    referenceSource: Identifier;
    revocationAuthorityDomain: Identifier;
    runnerId: Identifier;
    schema: "chio.broker-audit-runner-authorization.v1";
    tenantScope: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-audit-runner-authorization-envelope-v1.schema.json
export namespace Security_BrokerAuditRunnerAuthorizationEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    auditId: string;
    brokerInstanceId: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    credentialProvider: string;
    deploymentId: string;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    proofSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    referenceCommitmentSha256: string;
    referenceSource: string;
    revocationAuthorityDomain: string;
    runnerId: string;
    schema: "chio.broker-audit-runner-authorization.v1";
    tenantScope: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-request-body-v1.schema.json
export namespace Security_BrokerAuthorityRequestBodyV1 {
  export type PublicKey = string;
  export type PositiveU64 = number;
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
  export type AuthorityRpcIdentifier = string;
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
    broker: PublicKey;
    issuedAtUnixSeconds: PositiveU64;
    operation: Operation;
    requestId: AuthorityRpcIdentifier;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    capability: ChioSignedBrokerCapabilityV1;
    invocationId: string;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
    schema: "chio.broker-execute.v1";
  }
  export interface ChioSignedBrokerCapabilityV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface Request {
    approvedPreviewSha256: string | null;
    /**
     * @maxItems 524288
     */
    body: number[];
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
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
    responseLimitBytes: number;
    streaming: boolean;
    timeoutMs: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    expectedAudience: AuthorityRpcIdentifier;
    expectedSubject: PublicKey;
    nowUnixSeconds: PositiveU64;
    parentCapabilityId: AuthorityRpcIdentifier;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: AuthorityRpcIdentifier;
    nowUnixSeconds: PositiveU64;
    revocationId: AuthorityRpcIdentifier;
  }
  export interface QueryHoldRequest {
    authorizeEventId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    captureEventId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    operationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    reverseEventId: AuthorityRpcIdentifier;
  }
  export interface AuthorizeHoldRequest {
    authorityMetadataDigest: AuthorityRpcDigest;
    authorizeEventId: AuthorityRpcIdentifier;
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    operationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
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
  }
  export interface Quota {
    keyId: AuthorityRpcIdentifier;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    brokerCapabilityId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    operationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    proofDispatchDidNotBegin: true;
    reverseEventId: AuthorityRpcIdentifier;
  }
  export interface CaptureHoldRequest {
    authorityMetadataDigest: AuthorityRpcDigest;
    authorizationArtifactDigest: AuthorityRpcDigest;
    brokerCapabilityId: AuthorityRpcIdentifier;
    captureEventId: AuthorityRpcIdentifier;
    holdId: AuthorityRpcIdentifier;
    invocationId: AuthorityRpcIdentifier;
    operationId: AuthorityRpcIdentifier;
    parentCapabilityId: AuthorityRpcIdentifier;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [AuthorityRpcIdentifier, ...AuthorityRpcIdentifier[]];
    revocationSetDigest: AuthorityRpcDigest;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    operation: "issue" | "revoke" | "status";
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
    tenantScope: AuthorityRpcIdentifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-request-envelope-v1.schema.json
export namespace Security_BrokerAuthorityRequestEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Signature = string;

  export interface ChioSignedBrokerAuthorityRPCRequestV1 {
    algorithm: Algorithm;
    body: ChioBrokerAuthorityRPCRequestBodyV1;
    signature: Signature;
  }
  export interface ChioBrokerAuthorityRPCRequestBodyV1 {
    broker: string;
    issuedAtUnixSeconds: number;
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
    requestId: string;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    capability: ChioSignedBrokerCapabilityV1;
    invocationId: string;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
    schema: "chio.broker-execute.v1";
  }
  export interface ChioSignedBrokerCapabilityV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface Request {
    approvedPreviewSha256: string | null;
    /**
     * @maxItems 524288
     */
    body: number[];
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
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
    responseLimitBytes: number;
    streaming: boolean;
    timeoutMs: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    expectedAudience: string;
    expectedSubject: string;
    nowUnixSeconds: number;
    parentCapabilityId: string;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: string;
    nowUnixSeconds: number;
    revocationId: string;
  }
  export interface QueryHoldRequest {
    authorizeEventId: string;
    brokerCapabilityId: string;
    captureEventId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    reverseEventId: string;
  }
  export interface AuthorizeHoldRequest {
    authorityMetadataDigest: string;
    authorizeEventId: string;
    brokerCapabilityId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
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
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    brokerCapabilityId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    proofDispatchDidNotBegin: true;
    reverseEventId: string;
  }
  export interface CaptureHoldRequest {
    authorityMetadataDigest: string;
    authorizationArtifactDigest: string;
    brokerCapabilityId: string;
    captureEventId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [string, ...string[]];
    revocationSetDigest: string;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    operation: "issue" | "revoke" | "status";
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
    tenantScope: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-response-body-v1.schema.json
export namespace Security_BrokerAuthorityResponseBodyV1 {
  export type PublicKey = string;
  export type PositiveU64 = number;
  export type Digest = string;
  export type Identifier = string;
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
    authority: PublicKey;
    issuedAtUnixSeconds: PositiveU64;
    requestDigest: Digest;
    requestId: Identifier;
    result: Result;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    profile: "authoritative_hold_event";
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: Identifier;
    authorityMetadataDigest: Digest;
    preparedDispatchId: Identifier;
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
    revocationAuthorityDomain: Identifier;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: Identifier[];
  }
  export interface Quota {
    keyId: Identifier;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    audience: Identifier;
    authoritySnapshotDigest: Digest;
    capabilityId: Identifier;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: Identifier[];
    expiresAtUnixSeconds: PositiveU64;
    subject: PublicKey;
    verifiedAtUnixSeconds: PositiveU64;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    authorityDomain: Identifier;
    commitIndex: U64;
    observedAtUnixSeconds: PositiveU64;
    revoked: boolean;
  }
  export interface HoldResult {
    kind: "hold";
    response: HoldState;
  }
  export interface CaptureCommit {
    authorityCommitIndex: U64;
    budgetCommitIndex: U64;
    checkedRevocationSetDigest: Digest;
    leaderEpoch: U64;
    revocationCommitIndex: U64;
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
      code: Identifier;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-authority-response-envelope-v1.schema.json
export namespace Security_BrokerAuthorityResponseEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedBrokerAuthorityRPCResponseV1 {
    algorithm: Algorithm;
    body: ChioBrokerAuthorityRPCResponseBodyV1;
    signature: Signature;
  }
  export interface ChioBrokerAuthorityRPCResponseBodyV1 {
    authority: string;
    issuedAtUnixSeconds: number;
    requestDigest: string;
    requestId: string;
    result:
      | CapabilitiesResult
      | PreparedResult
      | LiveParentResult
      | RevocationResult
      | HoldResult
      | ControlResult
      | RejectedResult;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    profile: "authoritative_hold_event";
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: string;
    authorityMetadataDigest: string;
    preparedDispatchId: string;
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
    revocationAuthorityDomain: string;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: string[];
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    audience: string;
    authoritySnapshotDigest: string;
    capabilityId: string;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: string[];
    expiresAtUnixSeconds: number;
    subject: string;
    verifiedAtUnixSeconds: number;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    authorityDomain: string;
    commitIndex: number;
    observedAtUnixSeconds: number;
    revoked: boolean;
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
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    checkedRevocationSetDigest: string;
    leaderEpoch: number;
    revocationCommitIndex: number;
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
  export type Identifier = string;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Digest = string;
  export type PublicKey = string;

  export interface ChioBrokerCapabilityBodyV1 {
    audience: Identifier;
    brokerQuotaKeyId: Identifier;
    capabilityId: Identifier;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: PublicKey;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: Identifier;
    proof: ProofBinding;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
    revocationId: Identifier;
    schema: "chio.broker-capability.v1";
    subject: PublicKey;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: Digest;
    requiredPreviewSha256: Digest | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: Identifier;
    provider: Identifier;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: PublicKey;
    mode: "public_key" | "loopback_bearer";
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
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: Signature;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-failure-v1.schema.json
export namespace Security_BrokerExecuteFailureV1 {
  export interface ChioBrokerExecuteFailureV1 {
    diagnosticCode: string;
    receipt: ChioSignedBrokerExecutionFailureReceiptV1;
    receiptReference: string;
  }
  export interface ChioSignedBrokerExecutionFailureReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerExecutionFailureReceiptBodyV1;
    signature: string;
    signer: string;
  }
  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    attemptId: string | null;
    brokerCapabilityId: string | null;
    capabilityDigest: string | null;
    diagnosticCode: string;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
    holdId: string | null;
    invocationId: string | null;
    issuedAtUnixSeconds: number;
    outcome: "denied" | "reversed" | "failed" | "unknown";
    parentCapabilityId: string | null;
    receiptId: string;
    requestDigest: string;
    schema: "chio.broker-execution-failure-receipt.v1";
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-request-v1.schema.json
export namespace Security_BrokerExecuteRequestV1 {
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Identifier = string;
  export type DigestOrNull = Digest | null;
  export type Digest = string;

  export interface ChioBrokerExecuteRequestV1 {
    capability: ChioSignedBrokerCapabilityV1;
    invocationId: Identifier;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
    schema: "chio.broker-execute.v1";
  }
  export interface ChioSignedBrokerCapabilityV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface Request {
    approvedPreviewSha256: DigestOrNull;
    /**
     * @maxItems 524288
     */
    body: number[];
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
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
    responseLimitBytes: number;
    streaming: boolean;
    timeoutMs: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execute-response-v1.schema.json
export namespace Security_BrokerExecuteResponseV1 {
  export interface ChioBrokerExecuteResponseV1 {
    /**
     * @maxItems 2097152
     */
    body: number[];
    evidence: ChioBrokerExecutionEvidenceV1;
    /**
     * @maxItems 64
     */
    headers: Header[];
    receipt: ChioSignedBrokerExecutionReceiptV1;
    receiptReference: string;
    status: number;
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    attemptId: string;
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    capabilityDigest: string;
    holdId: string;
    invocationId: string;
    leaderEpoch: number;
    requestDigest: string;
    responseBodySha256: string;
    revocationCommitIndex: number;
    revocationSetDigest: string;
    schema: "chio.broker-execution-evidence.v1";
    upstreamStatus: number;
  }
  export interface Header {
    name: string;
    /**
     * @maxItems 8192
     */
    value: number[];
  }
  export interface ChioSignedBrokerExecutionReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerExecutionReceiptBodyV1;
    signature: string;
    signer: string;
  }
  export interface ChioBrokerExecutionReceiptBodyV1 {
    authorizeEventId: string;
    brokerCapabilityId: string;
    brokerQuotaKeyId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    captureEventId: string;
    credentialReferenceHash: string;
    credentialVersion: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    issuedAtUnixSeconds: number;
    normalizedDestination: Destination;
    operationId: string;
    outcome: "completed";
    parentCapabilityId: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
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
    receiptId: string;
    requestBodyBytes: number;
    requestBodySha256: string;
    responseBodyBytes: number;
    schema: "chio.broker-execution-receipt.v1";
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: string[];
    subject: string;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
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
    attemptId: Identifier;
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    capabilityDigest: Digest;
    holdId: Identifier;
    invocationId: Identifier;
    leaderEpoch: number;
    requestDigest: Digest;
    responseBodySha256: Digest;
    revocationCommitIndex: number;
    revocationSetDigest: Digest;
    schema: "chio.broker-execution-evidence.v1";
    upstreamStatus: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-failure-receipt-body-v1.schema.json
export namespace Security_BrokerExecutionFailureReceiptBodyV1 {
  export type IdentifierOrNull = Identifier | null;
  export type Identifier = string;
  export type DigestOrNull = Digest | null;
  export type Digest = string;

  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    attemptId: IdentifierOrNull;
    brokerCapabilityId: IdentifierOrNull;
    capabilityDigest: DigestOrNull;
    diagnosticCode: string;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
    holdId: IdentifierOrNull;
    invocationId: IdentifierOrNull;
    issuedAtUnixSeconds: number;
    outcome: "denied" | "reversed" | "failed" | "unknown";
    parentCapabilityId: IdentifierOrNull;
    receiptId: Identifier;
    requestDigest: Digest;
    schema: "chio.broker-execution-failure-receipt.v1";
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-failure-receipt-envelope-v1.schema.json
export namespace Security_BrokerExecutionFailureReceiptEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerExecutionFailureReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerExecutionFailureReceiptBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerExecutionFailureReceiptBodyV1 {
    attemptId: string | null;
    brokerCapabilityId: string | null;
    capabilityDigest: string | null;
    diagnosticCode: string;
    dispatchKnowledge: "not_started" | "not_committed" | "committed" | "unknown";
    holdId: string | null;
    invocationId: string | null;
    issuedAtUnixSeconds: number;
    outcome: "denied" | "reversed" | "failed" | "unknown";
    parentCapabilityId: string | null;
    receiptId: string;
    requestDigest: string;
    schema: "chio.broker-execution-failure-receipt.v1";
    stage: "admission" | "hold" | "capture" | "dispatch" | "response" | "receipt_persistence";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-receipt-body-v1.schema.json
export namespace Security_BrokerExecutionReceiptBodyV1 {
  export type Identifier = string;
  export type Digest = string;
  export type PublicKey = string;

  export interface ChioBrokerExecutionReceiptBodyV1 {
    authorizeEventId: Identifier;
    brokerCapabilityId: Identifier;
    brokerQuotaKeyId: Identifier;
    callerHeadersSha256: Digest;
    callerOptionsSha256: Digest;
    captureEventId: Identifier;
    credentialReferenceHash: Digest;
    credentialVersion: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    issuedAtUnixSeconds: number;
    normalizedDestination: Destination;
    operationId: Identifier;
    outcome: "completed";
    parentCapabilityId: Identifier;
    providerAdapterId: Identifier;
    providerAdapterVersion: number;
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
    receiptId: Identifier;
    requestBodyBytes: number;
    requestBodySha256: Digest;
    responseBodyBytes: number;
    schema: "chio.broker-execution-receipt.v1";
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: Identifier[];
    subject: PublicKey;
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    attemptId: string;
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    capabilityDigest: string;
    holdId: string;
    invocationId: string;
    leaderEpoch: number;
    requestDigest: string;
    responseBodySha256: string;
    revocationCommitIndex: number;
    revocationSetDigest: string;
    schema: "chio.broker-execution-evidence.v1";
    upstreamStatus: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface Quota {
    keyId: Identifier;
    maximumExecutions: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-execution-receipt-envelope-v1.schema.json
export namespace Security_BrokerExecutionReceiptEnvelopeV1 {
  export type Signature = string;
  export type PublicKey = string;

  export interface ChioSignedBrokerExecutionReceiptV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerExecutionReceiptBodyV1;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChioBrokerExecutionReceiptBodyV1 {
    authorizeEventId: string;
    brokerCapabilityId: string;
    brokerQuotaKeyId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    captureEventId: string;
    credentialReferenceHash: string;
    credentialVersion: number;
    evidence: ChioBrokerExecutionEvidenceV1;
    issuedAtUnixSeconds: number;
    normalizedDestination: Destination;
    operationId: string;
    outcome: "completed";
    parentCapabilityId: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
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
    receiptId: string;
    requestBodyBytes: number;
    requestBodySha256: string;
    responseBodyBytes: number;
    schema: "chio.broker-execution-receipt.v1";
    /**
     * @minItems 0
     * @maxItems 64
     */
    sourceReceiptIds: string[];
    subject: string;
  }
  export interface ChioBrokerExecutionEvidenceV1 {
    attemptId: string;
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    capabilityDigest: string;
    holdId: string;
    invocationId: string;
    leaderEpoch: number;
    requestDigest: string;
    responseBodySha256: string;
    revocationCommitIndex: number;
    revocationSetDigest: string;
    schema: "chio.broker-execution-evidence.v1";
    upstreamStatus: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
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
    attemptId: Identifier;
    operationId: Identifier;
    preparedAtUnixSeconds: number;
    preparedDispatchId: Identifier;
    schema: "chio.broker-prepare-dispatch-acknowledgement.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-challenge-v1.schema.json
export namespace Security_BrokerPrivilegedAuditChallengeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type PositiveU64 = number;
  export type Digest = string;
  export type Signature = string;
  export type PublicKey = string;

  /**
   * Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
   */
  export interface ChioSignedBrokerPrivilegedAuditChallengeV1 {
    algorithm: Algorithm;
    body: ChallengeBody;
    signature: Signature;
    signer: PublicKey;
  }
  export interface ChallengeBody {
    expiresAtUnixSeconds: PositiveU64;
    issuedAtUnixSeconds: PositiveU64;
    runnerAuthorizationBody: ChioBrokerAuditRunnerAuthorizationBodyV1;
    schema: "chio.broker-privileged-audit-challenge.v1";
    sessionCommitmentSha256: Digest;
    sessionNonce: Digest;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    auditId: string;
    brokerInstanceId: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    credentialProvider: string;
    deploymentId: string;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    proofSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    referenceCommitmentSha256: string;
    referenceSource: string;
    revocationAuthorityDomain: string;
    runnerId: string;
    schema: "chio.broker-audit-runner-authorization.v1";
    tenantScope: string;
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
    /**
     * @minItems 1
     * @maxItems 65536
     */
    governedAdminAuthorization: [number, ...number[]];
    runnerAuthorization: ChioSignedBrokerAuditRunnerAuthorizationV1;
    schema: "chio.broker-privileged-audit-commit.v1";
    sessionCommitmentSha256: Digest;
    sessionNonce: Digest;
  }
  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signature: string;
    signer: string;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    auditId: string;
    brokerInstanceId: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    credentialProvider: string;
    deploymentId: string;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    proofSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    referenceCommitmentSha256: string;
    referenceSource: string;
    revocationAuthorityDomain: string;
    runnerId: string;
    schema: "chio.broker-audit-runner-authorization.v1";
    tenantScope: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-evidence-v1.schema.json
export namespace Security_BrokerPrivilegedAuditEvidenceV1 {
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];
  export type Digest = string;
  export type PublicKey = string;
  export type PositiveU64 = number;

  /**
   * Canonical evidence returned after one privileged broker audit comparison.
   */
  export interface ChioBrokerPrivilegedAuditEvidenceBundleV1 {
    challenge: ChioSignedBrokerPrivilegedAuditChallengeV1;
    comparison: ChioSignedBrokerAuditComparisonV1;
    /**
     * @minItems 1
     * @maxItems 65536
     */
    governedAdminAuthorization: [number, ...number[]];
    livenessAuthorityExchange: AuthorityExchange;
    revocationAuthorityExchange: AuthorityExchange;
    runnerAuthorization: ChioSignedBrokerAuditRunnerAuthorizationV1;
    schema: "chio.broker-privileged-audit-evidence.v1";
  }
  /**
   * Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
   */
  export interface ChioSignedBrokerPrivilegedAuditChallengeV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChallengeBody;
    signature: string;
    signer: string;
  }
  export interface ChallengeBody {
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    runnerAuthorizationBody: ChioBrokerAuditRunnerAuthorizationBodyV1;
    schema: "chio.broker-privileged-audit-challenge.v1";
    sessionCommitmentSha256: string;
    sessionNonce: string;
  }
  export interface ChioBrokerAuditRunnerAuthorizationBodyV1 {
    auditId: string;
    brokerInstanceId: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    credentialProvider: string;
    deploymentId: string;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    proofSha256: string;
    providerAdapterId: string;
    providerAdapterVersion: number;
    referenceCommitmentSha256: string;
    referenceSource: string;
    revocationAuthorityDomain: string;
    runnerId: string;
    schema: "chio.broker-audit-runner-authorization.v1";
    tenantScope: string;
  }
  export interface ChioSignedBrokerAuditComparisonV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuditComparisonBodyV1;
    signature: string;
    signer: string;
  }
  export interface ChioBrokerAuditComparisonBodyV1 {
    accountingMutationCount: 0;
    auditAuthorizationSha256: string;
    auditIdSha256: string;
    authorityContextSha256: string;
    brokerOutboundProjectionCommitmentSha256: string;
    canonicalRequestSha256: string;
    capabilitySha256: string;
    governedAuditIntentSha256: string;
    issuedAtUnixSeconds: number;
    networkDispatchCount: 0;
    projectionsEqual: boolean;
    proofSha256: string;
    rawCredentialReturned: false;
    referenceOutboundProjectionCommitmentSha256: string;
    referenceSourceSha256: string;
    runnerAuthorizationSha256: string;
    schema: "chio.broker-audit-comparison.v1";
  }
  export interface AuthorityExchange {
    maximumClockSkewSeconds: number;
    request: ChioSignedBrokerAuthorityRPCRequestV1;
    requestSha256: Digest;
    response: ChioSignedBrokerAuthorityRPCResponseV1;
    responseSha256: Digest;
    trustedAuthority: PublicKey;
    verifiedAtUnixSeconds: PositiveU64;
  }
  export interface ChioSignedBrokerAuthorityRPCRequestV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuthorityRPCRequestBodyV1;
    signature: string;
  }
  export interface ChioBrokerAuthorityRPCRequestBodyV1 {
    broker: string;
    issuedAtUnixSeconds: number;
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
    requestId: string;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesOperation {
    kind: "capabilities";
  }
  export interface PrepareExecutionOperation {
    kind: "prepare_execution";
    request: ChioBrokerExecuteRequestV1;
  }
  export interface ChioBrokerExecuteRequestV1 {
    capability: ChioSignedBrokerCapabilityV1;
    invocationId: string;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
    schema: "chio.broker-execute.v1";
  }
  export interface ChioSignedBrokerCapabilityV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface Request {
    approvedPreviewSha256: string | null;
    /**
     * @maxItems 524288
     */
    body: number[];
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
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
    responseLimitBytes: number;
    streaming: boolean;
    timeoutMs: number;
  }
  export interface VerifyLiveParentOperation {
    kind: "verify_live_parent";
    request: CapabilityLivenessRequest;
  }
  export interface CapabilityLivenessRequest {
    expectedAudience: string;
    expectedSubject: string;
    nowUnixSeconds: number;
    parentCapabilityId: string;
  }
  export interface CheckBrokerRevocationOperation {
    kind: "check_broker_revocation";
    request: BrokerRevocationRequest;
  }
  export interface BrokerRevocationRequest {
    brokerCapabilityId: string;
    nowUnixSeconds: number;
    revocationId: string;
  }
  export interface QueryHoldRequest {
    authorizeEventId: string;
    brokerCapabilityId: string;
    captureEventId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    reverseEventId: string;
  }
  export interface AuthorizeHoldRequest {
    authorityMetadataDigest: string;
    authorizeEventId: string;
    brokerCapabilityId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
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
  }
  export interface Quota {
    keyId: string;
    maximumExecutions: number;
  }
  export interface ReverseHoldRequest {
    brokerCapabilityId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    proofDispatchDidNotBegin: true;
    reverseEventId: string;
  }
  export interface CaptureHoldRequest {
    authorityMetadataDigest: string;
    authorizationArtifactDigest: string;
    brokerCapabilityId: string;
    captureEventId: string;
    holdId: string;
    invocationId: string;
    operationId: string;
    parentCapabilityId: string;
    /**
     * @minItems 1
     * @maxItems 128
     */
    revocationIds: [string, ...string[]];
    revocationSetDigest: string;
  }
  export interface ControlOperation {
    kind: "control";
    request: ControlRequest;
  }
  export interface ControlRequest {
    /**
     * @minItems 1
     * @maxItems 65536
     */
    authorization: [number, ...number[]];
    operation: "issue" | "revoke" | "status";
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    payload: [number, ...number[]];
    tenantScope: string;
  }
  export interface ChioSignedBrokerAuthorityRPCResponseV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuthorityRPCResponseBodyV1;
    signature: string;
  }
  export interface ChioBrokerAuthorityRPCResponseBodyV1 {
    authority: string;
    issuedAtUnixSeconds: number;
    requestDigest: string;
    requestId: string;
    result:
      | CapabilitiesResult
      | PreparedResult
      | LiveParentResult
      | RevocationResult
      | HoldResult
      | ControlResult
      | RejectedResult;
    schema: "chio.broker-authority-rpc.v1";
  }
  export interface CapabilitiesResult {
    kind: "capabilities";
    response: Capabilities;
  }
  export interface Capabilities {
    atomicMultiKeyHolds: boolean;
    combinedCaptureAndRevocation: boolean;
    profile: "authoritative_hold_event";
    queryById: boolean;
    sharedRevocationWriteDomain: boolean;
  }
  export interface PreparedResult {
    kind: "prepared";
    response: TrustedExecutionContext;
  }
  export interface TrustedExecutionContext {
    admissionOperationId: string;
    authorityMetadataDigest: string;
    preparedDispatchId: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [Quota1]
      | [Quota1, Quota1]
      | [Quota1, Quota1, Quota1]
      | [Quota1, Quota1, Quota1, Quota1]
      | [Quota1, Quota1, Quota1, Quota1, Quota1]
      | [Quota1, Quota1, Quota1, Quota1, Quota1, Quota1]
      | [Quota1, Quota1, Quota1, Quota1, Quota1, Quota1, Quota1]
      | [Quota1, Quota1, Quota1, Quota1, Quota1, Quota1, Quota1, Quota1];
    revocationAuthorityDomain: string;
    /**
     * @maxItems 64
     */
    sourceReceiptIds: string[];
  }
  export interface Quota1 {
    keyId: string;
    maximumExecutions: number;
  }
  export interface LiveParentResult {
    kind: "live_parent";
    response: LiveParent;
  }
  export interface LiveParent {
    audience: string;
    authoritySnapshotDigest: string;
    capabilityId: string;
    /**
     * @maxItems 128
     */
    delegationAncestorIds: string[];
    expiresAtUnixSeconds: number;
    subject: string;
    verifiedAtUnixSeconds: number;
  }
  export interface RevocationResult {
    kind: "revocation";
    response: RevocationSnapshot;
  }
  export interface RevocationSnapshot {
    authorityDomain: string;
    commitIndex: number;
    observedAtUnixSeconds: number;
    revoked: boolean;
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
    authorityCommitIndex: number;
    budgetCommitIndex: number;
    checkedRevocationSetDigest: string;
    leaderEpoch: number;
    revocationCommitIndex: number;
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
  export interface ChioSignedBrokerAuditRunnerAuthorizationV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerAuditRunnerAuthorizationBodyV1;
    signature: string;
    signer: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-privileged-audit-open-v1.schema.json
export namespace Security_BrokerPrivilegedAuditOpenV1 {
  export type Identifier = string;
  export type NonzeroDigest = Digest & {
    [k: string]: unknown;
  };
  export type Digest = string;
  export type Byte = number;
  /**
   * @maxItems 64
   */
  export type HeaderNames = string[];

  /**
   * First-phase request on the isolated broker privileged audit transport.
   */
  export interface ChioBrokerPrivilegedAuditOpenRequestV1 {
    auditId: Identifier;
    referenceCommitmentSalt: NonzeroDigest;
    referenceCommitmentSha256: Digest;
    /**
     * @maxItems 524288
     */
    referenceRequestBody: Byte[];
    /**
     * @minItems 1
     * @maxItems 1048576
     */
    referenceRequestHead: [Byte, ...Byte[]];
    referenceSource: Identifier;
    request: ChioBrokerExecuteRequestV1;
    revocationAuthorityDomain: Identifier;
    schema: "chio.broker-privileged-audit-open.v1";
  }
  export interface ChioBrokerExecuteRequestV1 {
    capability: ChioSignedBrokerCapabilityV1;
    invocationId: string;
    proof: ChioSignedBrokerRequestProofV1;
    request: Request;
    schema: "chio.broker-execute.v1";
  }
  export interface ChioSignedBrokerCapabilityV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerCapabilityBodyV1;
    signature: string;
  }
  export interface ChioBrokerCapabilityBodyV1 {
    audience: string;
    brokerQuotaKeyId: string;
    capabilityId: string;
    constraints: RequestConstraints;
    consumption: "capture_before_dispatch";
    credential: CredentialRef;
    destination: Destination;
    expiresAtUnixSeconds: number;
    issuedAtUnixSeconds: number;
    issuer: string;
    maximumExecutions: number;
    notBeforeUnixSeconds: number;
    parentCapabilityId: string;
    proof: ProofBinding;
    providerAdapterId: string;
    providerAdapterVersion: number;
    revocationId: string;
    schema: "chio.broker-capability.v1";
    subject: string;
  }
  export interface RequestConstraints {
    allowedCallerHeaders: HeaderNames;
    maximumBodyBytes: number;
    maximumResponseBytes: number;
    maximumTimeoutMs: number;
    providerOwnedHeaders: HeaderNames;
    redirectPolicy: "disabled";
    requiredBodySha256: string;
    requiredPreviewSha256: string | null;
    streamingAllowed: boolean;
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
  export interface ProofBinding {
    callerPublicKey: string;
    mode: "public_key" | "loopback_bearer";
    nonceTtlSeconds: number;
  }
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface Request {
    approvedPreviewSha256: string | null;
    /**
     * @maxItems 524288
     */
    body: number[];
    destination: Destination;
    /**
     * @maxItems 64
     */
    headers: Header[];
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
    responseLimitBytes: number;
    streaming: boolean;
    timeoutMs: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-acknowledgement-v1.schema.json
export namespace Security_BrokerRegisterAttemptAcknowledgementV1 {
  export type Identifier = string;

  export interface ChioBrokerRegisterAttemptAcknowledgementV1 {
    attemptId: Identifier;
    disposition: "inserted" | "exact_retry";
    operationId: Identifier;
    registeredAtUnixSeconds: number;
    schema: "chio.broker-register-attempt-acknowledgement.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-authorization-body-v1.schema.json
export namespace Security_BrokerRegisterAttemptAuthorizationBodyV1 {
  export type PublicKey = string;
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerRegisterAttemptAuthorizationBodyV1 {
    action: "register" | "prepare" | "release";
    authority: PublicKey;
    issuedAtUnixSeconds: number;
    registrationDigest: Digest;
    schema: "chio.broker-register-attempt-authorization.v1";
    tenantScope: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-register-attempt-authorization-envelope-v1.schema.json
export namespace Security_BrokerRegisterAttemptAuthorizationEnvelopeV1 {
  export type Signature = string;

  export interface ChioSignedBrokerRegisterAttemptAuthorizationV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRegisterAttemptAuthorizationBodyV1;
    signature: Signature;
  }
  export interface ChioBrokerRegisterAttemptAuthorizationBodyV1 {
    action: "register" | "prepare" | "release";
    authority: string;
    issuedAtUnixSeconds: number;
    registrationDigest: string;
    schema: "chio.broker-register-attempt-authorization.v1";
    tenantScope: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-release-attempt-acknowledgement-v1.schema.json
export namespace Security_BrokerReleaseAttemptAcknowledgementV1 {
  export type Identifier = string;

  export interface ChioBrokerReleaseAttemptAcknowledgementV1 {
    attemptId: Identifier;
    operationId: Identifier;
    releasedAtUnixSeconds: number;
    schema: "chio.broker-release-attempt-acknowledgement.v1";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-request-proof-body-v1.schema.json
export namespace Security_BrokerRequestProofBodyV1 {
  export type PublicKey = string;
  export type Digest = string;
  export type Identifier = string;

  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: PublicKey;
    bodySha256: Digest;
    brokerCapabilityId: Identifier;
    callerHeadersSha256: Digest;
    callerOptionsSha256: Digest;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: Identifier;
    schema: "chio.broker-request-proof.v1";
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/broker-request-proof-envelope-v1.schema.json
export namespace Security_BrokerRequestProofEnvelopeV1 {
  export interface ChioSignedBrokerRequestProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioBrokerRequestProofBodyV1;
    signature: string;
  }
  export interface ChioBrokerRequestProofBodyV1 {
    authorityKey: string;
    bodySha256: string;
    brokerCapabilityId: string;
    callerHeadersSha256: string;
    callerOptionsSha256: string;
    capabilityExpiresAtUnixSeconds: number;
    credential: CredentialRef;
    destination: Destination;
    issuedAtUnixSeconds: number;
    nonce: string;
    parentCapabilityId: string;
    schema: "chio.broker-request-proof.v1";
  }
  export interface CredentialRef {
    credentialId: string;
    provider: string;
    version: number;
  }
  export interface Destination {
    exactPathAndQuery: string;
    explicitPort: number;
    method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
    normalizedHost: string;
    scheme: "https" | "http";
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
    applied_execution_identity: ExecutionIdentity;
    fd_table_digest: Digest;
    helper_binding_digest: Digest;
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    manifest_digest: Digest;
    nono_patch_version: "chio.2";
    nono_version: "0.53.0";
    plan_digest: Digest;
    prepared_at_unix_ms: number;
    process_id: number;
    profile_digest: Digest;
    schema: "chio.cage.enforcement-prepared.v1";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: Digest;
    seccomp_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    target_binding_digest: Digest;
    target_identity: RegularFileIdentity;
    trace_session_digest: Digest;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-enforcement-record-v1.schema.json
export namespace Security_CageEnforcementRecordV1 {
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    exit: ChioCageProcessExitEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
  } & (
    | {
        exit?: null;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "fully_enforced";
      }
    | {
        exit?: ChioCageProcessExitEvidenceV1;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "exited";
      }
    | {
        exit?: null;
        failure?: ChioCageEnforcementFailureV1;
        fully_enforced?: null;
        state?: "unsupported" | "rejected" | "bootstrap_failed";
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    exit_code: number | null;
    exited_at_unix_ms: number;
    process_id: number;
    signal: number | null;
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
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    exec_transition: ChioCageExecTransitionObservationV1;
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    status_eof_observed: true;
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    observed_at_unix_ms: number;
    process_id: number;
    schema: "chio.cage.exec-transition-observed.v1";
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    applied_execution_identity: ExecutionIdentity;
    fd_table_digest: string;
    helper_binding_digest: string;
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    manifest_digest: string;
    nono_patch_version: "chio.2";
    nono_version: "0.53.0";
    plan_digest: string;
    prepared_at_unix_ms: number;
    process_id: number;
    profile_digest: string;
    schema: "chio.cage.enforcement-prepared.v1";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    seccomp_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
  }
  export interface FileIdentity1 {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
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
    observed_at_unix_ms: number;
    process_id: number;
    schema: "chio.cage.exec-transition-observed.v1";
    target_binding_digest: Digest;
    target_identity: RegularFileIdentity;
    trace_session_digest: Digest;
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-fully-enforced-evidence-v1.schema.json
export namespace Security_CageFullyEnforcedEvidenceV1 {
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    exec_transition: ChioCageExecTransitionObservationV1;
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    status_eof_observed: true;
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    observed_at_unix_ms: number;
    process_id: number;
    schema: "chio.cage.exec-transition-observed.v1";
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    applied_execution_identity: ExecutionIdentity;
    fd_table_digest: string;
    helper_binding_digest: string;
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    manifest_digest: string;
    nono_patch_version: "chio.2";
    nono_version: "0.53.0";
    plan_digest: string;
    prepared_at_unix_ms: number;
    process_id: number;
    profile_digest: string;
    schema: "chio.cage.enforcement-prepared.v1";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    seccomp_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
  }
  export interface FileIdentity1 {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
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
    broker_authentication_digest: Digest | null;
    compiler_version: "chio-cage-compiler.v2";
    environment: Environment;
    execution_identity: ExecutionIdentity;
    fd_table: FdTable;
    helper_fd_slot: 5;
    landlock: LandlockPlan;
    manifest_digest: Digest;
    plan_fd_slot: 3;
    profile_digest: Digest;
    resource_limits: ResourceLimits;
    schema: "chio.cage.init-plan.v2";
    seccomp: SeccompPlan;
    status_fd_slot: 4;
    target_argv: TargetArgv;
    target_fd_slot: 255;
    working_directory_fd_slot: 6;
  };
  export type Digest = string;
  /**
   * @minItems 6
   * @maxItems 191
   */
  export type FdTable = unknown[] & FdTable1;
  export type FdTable1 = [FdEntry, FdEntry, FdEntry, FdEntry, FdEntry, FdEntry, ...FdEntry[]];
  export type FdEntry =
    | (ArtifactEntry & {
        identity?: RegularFileIdentity;
        purpose?: PurposeCageInitHelper;
        slot?: 5;
      })
    | (ArtifactEntry & {
        identity?: RegularFileIdentity;
        purpose?: PurposeTargetExecutable;
        slot?: 255;
      })
    | (ArtifactEntry & {
        identity?: DirectoryIdentity;
        purpose?: PurposeWorkingDirectory;
        slot?: 6;
      })
    | (StdioEntry & {
        purpose?: PurposeTargetStdin;
        slot?: 7;
      })
    | (StdioEntry & {
        purpose?: PurposeTargetStdout;
        slot?: 9;
      })
    | (StdioEntry & {
        purpose?: PurposeTargetStderr;
        slot?: 10;
      })
    | (ArtifactEntry & {
        identity?: RegularFileIdentity;
        purpose?: PurposeIndexedResource & {
          kind?: "runtime_file";
        };
        slot?: number;
      })
    | (FdEntryBase & {
        binding_digest?: null;
        broker_peer_identity?: null;
        close_on_exec?: true;
        identity?: PathIdentity;
        path?: AbsoluteCanonicalPath;
        purpose?: PurposeIndexedResource & {
          kind?: "read_grant";
        };
        slot?: number;
      })
    | (FdEntryBase & {
        binding_digest?: null;
        broker_peer_identity?: null;
        close_on_exec?: true;
        identity?: RegularFileIdentity;
        path?: AbsoluteCanonicalPath;
        purpose?: PurposeIndexedResource & {
          kind?: "write_grant";
        };
        slot?: number;
      })
    | (FdEntryBase & {
        binding_digest?: Digest;
        broker_peer_identity?: BrokerPeerIdentity;
        close_on_exec?: false;
        identity?: SocketIdentity;
        path?: null;
        purpose?: PurposeBrokerIpc;
        slot?: 8;
      });
  export type ArtifactEntry = FdEntryBase & {
    binding_digest?: Digest;
    broker_peer_identity?: null;
    close_on_exec?: true;
    path?: AbsoluteCanonicalPath;
  };
  export type AbsoluteCanonicalPath = string;
  export type RegularFileIdentity = FileIdentity & {
    kind: "regular_file";
  };
  export type DirectoryIdentity = FileIdentity & {
    kind: "directory";
  };
  export type StdioEntry = FdEntryBase & {
    binding_digest?: null;
    broker_peer_identity?: null;
    close_on_exec?: true;
    identity?: SocketIdentity;
    path?: null;
  };
  export type SocketIdentity = FileIdentity & {
    kind: "unix_socket";
  };
  export type PathIdentity = FileIdentity & {
    kind: "regular_file" | "directory";
  };
  /**
   * @minItems 1
   * @maxItems 256
   */
  export type TargetArgv = [string, ...string[]];

  export interface Environment {
    [k: string]: string;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
  }
  export interface FdEntryBase {
    binding_digest: Digest | null;
    broker_peer_identity: BrokerPeerIdentity | null;
    close_on_exec: boolean;
    identity: FileIdentity;
    path: AbsoluteCanonicalPath | null;
    purpose: {};
    slot: number;
  }
  export interface BrokerPeerIdentity {
    gid: number;
    pid: number;
    uid: number;
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
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
    index: number;
    kind: "runtime_file" | "read_grant" | "write_grant";
  }
  export interface PurposeBrokerIpc {
    kind: "broker_ipc";
  }
  export interface LandlockPlan {
    default_filesystem_deny: true;
    forbidden_resources: ForbiddenResource[];
    grants: FilesystemGrant[];
    network_mode: "blocked";
  }
  export interface ForbiddenResource {
    identity: PathIdentity;
    path: AbsoluteCanonicalPath;
  }
  export interface FilesystemGrant {
    access: "read" | "read_directory" | "write_exact_file" | "execute_read";
    fd_slot: number;
    identity: PathIdentity;
  }
  export interface ResourceLimits {
    nofile_hard: 192;
    nofile_soft: 192;
  }
  export interface SeccompPlan {
    /**
     * @minItems 1
     */
    allowed_syscalls: [string, ...string[]];
    architecture: "x86_64";
    argument_constraints: {
      /**
       * @minItems 1
       */
      [k: string]: [SyscallArgumentConstraint, ...SyscallArgumentConstraint[]];
    };
    default_action: "kill_process";
    profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
  }
  export interface SyscallArgumentConstraint {
    argument_index: number;
    comparison: "equal";
    value: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-process-exit-evidence-v1.schema.json
export namespace Security_CageProcessExitEvidenceV1 {
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    exit_code: number | null;
    exited_at_unix_ms: number;
    process_id: number;
    signal: number | null;
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
    attempt_id: Identifier;
    bindings?: Bindings;
    enforcement_record: ChioCageEnforcementRecordV1;
    recorded_at_unix_ms: number;
    schema: "chio.cage.receipt-body.v1";
    stage: "rejection" | "bootstrap" | "enforcement" | "terminal_exit";
    started_at_unix_ms: number;
  } & (
    | {
        enforcement_record?: {
          state: "unsupported" | "rejected";
        };
        stage?: "rejection";
      }
    | {
        enforcement_record?: {
          state: "bootstrap_failed";
        };
        stage?: "bootstrap";
      }
    | {
        enforcement_record?: {
          state: "fully_enforced";
        };
        stage?: "enforcement";
      }
    | {
        enforcement_record?: {
          state: "exited";
        };
        stage?: "terminal_exit";
      }
  );
  export type Identifier = string;
  export type Digest = string;
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    exit: ChioCageProcessExitEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
  } & (
    | {
        exit?: null;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "fully_enforced";
      }
    | {
        exit?: ChioCageProcessExitEvidenceV1;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "exited";
      }
    | {
        exit?: null;
        failure?: ChioCageEnforcementFailureV1;
        fully_enforced?: null;
        state?: "unsupported" | "rejected" | "bootstrap_failed";
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    exit_code: number | null;
    exited_at_unix_ms: number;
    process_id: number;
    signal: number | null;
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
    fd_table_digest: Digest;
    helper_binding_digest: Digest;
    manifest_digest: Digest;
    plan_digest: Digest;
    profile_digest: Digest;
    target_binding_digest: Digest;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
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
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    exec_transition: ChioCageExecTransitionObservationV1;
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    status_eof_observed: true;
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    observed_at_unix_ms: number;
    process_id: number;
    schema: "chio.cage.exec-transition-observed.v1";
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface FileIdentity1 {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    applied_execution_identity: ExecutionIdentity;
    fd_table_digest: string;
    helper_binding_digest: string;
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    manifest_digest: string;
    nono_patch_version: "chio.2";
    nono_version: "0.53.0";
    plan_digest: string;
    prepared_at_unix_ms: number;
    process_id: number;
    profile_digest: string;
    schema: "chio.cage.enforcement-prepared.v1";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    seccomp_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/cage-receipt-metadata-v1.schema.json
export namespace Security_CageReceiptMetadataV1 {
  export type ChioCageReceiptBodyV1 = {
    attempt_id: string;
    bindings?: Bindings;
    enforcement_record: ChioCageEnforcementRecordV1;
    recorded_at_unix_ms: number;
    schema: "chio.cage.receipt-body.v1";
    stage: "rejection" | "bootstrap" | "enforcement" | "terminal_exit";
    started_at_unix_ms: number;
  } & (
    | {
        enforcement_record?: {
          state: "unsupported" | "rejected";
        };
        stage?: "rejection";
      }
    | {
        enforcement_record?: {
          state: "bootstrap_failed";
        };
        stage?: "bootstrap";
      }
    | {
        enforcement_record?: {
          state: "fully_enforced";
        };
        stage?: "enforcement";
      }
    | {
        enforcement_record?: {
          state: "exited";
        };
        stage?: "terminal_exit";
      }
  );
  /**
   * Closed state record that cannot claim fully-enforced or exited without complete enforcement evidence.
   */
  export type ChioCageEnforcementRecordV1 = {
    exit: ChioCageProcessExitEvidenceV1 | null;
    failure: ChioCageEnforcementFailureV1 | null;
    fully_enforced: ChioCageFullyEnforcedEvidenceV1 | null;
    schema: "chio.cage.enforcement-record.v1";
    state: "unsupported" | "rejected" | "bootstrap_failed" | "fully_enforced" | "exited";
  } & (
    | {
        exit?: null;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "fully_enforced";
      }
    | {
        exit?: ChioCageProcessExitEvidenceV1;
        failure?: null;
        fully_enforced?: ChioCageFullyEnforcedEvidenceV1;
        state?: "exited";
      }
    | {
        exit?: null;
        failure?: ChioCageEnforcementFailureV1;
        fully_enforced?: null;
        state?: "unsupported" | "rejected" | "bootstrap_failed";
      }
  );
  /**
   * Terminal process observation carrying exactly one normal exit code or terminating signal.
   */
  export type ChioCageProcessExitEvidenceV1 = {
    exit_code: number | null;
    exited_at_unix_ms: number;
    process_id: number;
    signal: number | null;
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
    cage_receipt: ChioCageReceiptBodyV1;
    schema: "chio.cage.receipt-metadata.v1";
  }
  export interface Bindings {
    fd_table_digest: string;
    helper_binding_digest: string;
    manifest_digest: string;
    plan_digest: string;
    profile_digest: string;
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
  }
  export interface FileIdentity {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
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
  /**
   * Composite evidence requiring a prepared confinement record, the matching observed target exec transition, and EOF on the private helper status channel.
   */
  export interface ChioCageFullyEnforcedEvidenceV1 {
    exec_transition: ChioCageExecTransitionObservationV1;
    prepared: ChioCageEnforcementPreparedEvidenceV1;
    status_eof_observed: true;
  }
  /**
   * Parent-observed ptrace exec transition bound to one process, trace session, target digest, and target kernel identity.
   */
  export interface ChioCageExecTransitionObservationV1 {
    observed_at_unix_ms: number;
    process_id: number;
    schema: "chio.cage.exec-transition-observed.v1";
    target_binding_digest: string;
    target_identity: FileIdentity1 & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface FileIdentity1 {
    device: number;
    gid: number;
    inode: number;
    kind: "regular_file" | "directory" | "unix_socket";
    mode: number;
    mount_id: number;
    uid: number;
  }
  /**
   * Evidence emitted after resource limits, full Landlock, and default-deny seccomp are prepared but before the target exec transition is accepted.
   */
  export interface ChioCageEnforcementPreparedEvidenceV1 {
    applied_execution_identity: ExecutionIdentity;
    fd_table_digest: string;
    helper_binding_digest: string;
    landlock_abi: number;
    landlock_filesystem_status: "fully_enforced";
    landlock_network_status: "fully_enforced";
    manifest_digest: string;
    nono_patch_version: "chio.2";
    nono_version: "0.53.0";
    plan_digest: string;
    prepared_at_unix_ms: number;
    process_id: number;
    profile_digest: string;
    schema: "chio.cage.enforcement-prepared.v1";
    seccomp_architecture: "x86_64";
    seccomp_filter_digest: string;
    seccomp_status: "fully_enforced";
    seccompiler_version: "0.5.0";
    target_binding_digest: string;
    target_identity: FileIdentity & {
      kind: "regular_file";
    };
    trace_session_digest: string;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
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
    finding_hash: Digest;
    finding_id: string;
    first_event_time_unix_ms: number;
    group_key_hash: Digest;
    header: Header;
    last_event_time_unix_ms: number;
    lineage_seed: string;
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
    policy: Policy;
    rule_id: string;
    rule_version_hash: Digest;
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/correlated-finding-v1.schema.json
export namespace Security_CorrelatedFindingV1 {
  export type Identifier = string;
  export type Time = number;
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

  export interface ChioCorrelatedFindingV1 {
    finding_id: Identifier;
    first_event_time_unix_ms: Time;
    group_key_hash: Digest;
    last_event_time_unix_ms: Time;
    lineage_seed: Identifier;
    ordered_event_ids: Identifiers;
    /**
     * @minItems 1
     * @maxItems 64
     */
    ordered_evidence_digests: [Digest, ...Digest[]];
    ordered_source_receipt_ids: Identifiers;
    policy_version: Identifier;
    rule_id: Identifier;
    rule_version_hash: Digest;
    tenant_id: Identifier;
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
    event_id: string;
    grant_hash: Digest;
    grant_id: string;
    header: Header;
    policy: Policy;
    request_hash: Digest;
    state: "consumed_pending_dispatch";
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
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
        /**
         * @maxItems 64
         */
        compartments: string[];
        kind: "known";
        owners: {
          /**
           * @maxItems 256
           */
          [k: string]: string[];
        };
      }
    | {
        kind: "top";
      };

  /**
   * One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
   */
  export interface SignedDeclassificationGrant {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    authority_key: string;
    body: {
      agent_id: FlowIdentifier;
      authority_key_id: FlowIdentifier;
      capability_id: FlowIdentifier;
      destination_id: FlowIdentifier;
      domain_version: 1;
      expires_at_unix_seconds: number;
      grant_id: FlowIdentifier;
      issued_at_unix_seconds: number;
      purpose: FlowIdentifier;
      request_hash: Digest32;
      session_id: FlowIdentifier;
      source_label_hash: Digest32;
      subject_id: FlowIdentifier;
      target_label: InformationLabel & {
        kind: "known";
      };
      tenant_id: FlowIdentifier;
      tool_name: FlowIdentifier;
    };
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
    event_id: string;
    from_state: "consumed_pending_dispatch";
    grant_hash: Digest;
    grant_id: string;
    header: Header;
    policy: Policy;
    request_hash: Digest;
    to_state: "released" | "dispatch_failed" | "outcome_unknown";
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json
export namespace Security_DetectorHealthReceiptBodyV1 {
  export type HealthKind =
    | "corrupt_event"
    | "corrupt_state"
    | "state_overflow"
    | "store_conflict"
    | "store_unavailable"
    | "truncated_scan";
  export interface DetectorHealthReceiptBase {
    event_id: Identifier;
    evidence_hash: Digest;
    header: Header;
    policy: Policy;
    rule_id: Identifier;
    rule_version_hash: Digest;
  }
  export type ChioDetectorHealthReceiptBodyV1 = DetectorHealthReceiptBase &
    (
      | {
          group_binding: Extract<GroupBinding, { kind: "unresolved" }>;
          health_kind: HealthKind;
          watermark: Extract<Watermark, { kind: "unknown" }>;
        }
      | {
          group_binding: Extract<GroupBinding, { kind: "resolved" }>;
          health_kind: HealthKind;
          watermark: Exclude<Watermark, { kind: "contradictory" }>;
        }
      | {
          group_binding: Extract<GroupBinding, { kind: "resolved" }>;
          health_kind: "corrupt_state";
          watermark: Extract<Watermark, { kind: "contradictory" }>;
        }
    );
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
        group_key_hash: Digest;
        kind: "resolved";
      };
  export type Time = number;
  export type Watermark =
    | {
        kind: "unknown";
      }
    | {
        kind: "committed";
        unix_ms: Time;
      }
    | {
        claimed_unix_ms: string;
        kind: "contradictory";
      };

  export interface Header {
    occurred_at_unix_ms: Time;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: Identifier[];
    schema_version: 1;
    tenant_id: Identifier;
    transition_id: Identifier;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: Identifier;
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
        session_id: string;
        target_type: "session";
      }
    | {
        lineage_id: string;
        target_type: "lineage";
      }
    | {
        affected_set_hash: Digest;
        target_type: "capability_set";
      };
  export type Outcome =
    | {
        state: "requested";
      }
    | {
        resulting_version_hash: Digest;
        state: "applied";
      }
    | {
        error_code: string;
        state: "apply_failed";
      }
    | {
        state: "rollback_requested";
      }
    | {
        resulting_version_hash: Digest;
        state: "restored";
      }
    | {
        error_code: string;
        state: "rollback_failed";
      };

  export interface ChioEffectTransitionReceiptBodyV1 {
    effect: Effect;
    generation: number;
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    outcome: Outcome;
    response: Response;
    scheduler_fencing_token: number;
    scheduler_lease_owner_id?: string | null;
  }
  export interface Effect {
    contribution_hash: Digest;
    effect_id: string;
    kind: Kind;
    observed_base_version_hash: Digest;
    ordinal: number;
    target: Target;
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Response {
    action_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: string;
    trigger_finding_receipt_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/flow-denial-receipt-body-v1.schema.json
export namespace Security_FlowDenialReceiptBodyV1 {
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
  export type Time = number;

  export interface ChioFlowDenialReceiptBodyV1 {
    denial_code: Identifier;
    destination_label_hash: Digest;
    event_id: Identifier;
    guard_evidence_hash: Digest;
    header: Header;
    policy: Policy;
    request_hash: Digest;
    source_label_hash: Digest;
  }
  export interface Header {
    occurred_at_unix_ms: Time;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: Identifier[];
    schema_version: 1;
    tenant_id: Identifier;
    transition_id: Identifier;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: Identifier;
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
        /**
         * @maxItems 64
         */
        compartments: FlowIdentifier[];
        kind: "known";
        owners: {
          /**
           * @maxItems 256
           */
          [k: string]: FlowIdentifier[];
        };
      }
    | {
        kind: "top";
      };
  export type FlowIdentifier = string;
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-activation-commit-body-v1.schema.json
export namespace Security_KeyLogActivationCommitBodyV1 {
  export type Hash = string;
  export type KeyLogIdentifier = string;

  export interface ChioKeyLogActivationCommitBodyV1 {
    checkpoint_body_hash: Hash;
    checkpoint_hash: Hash;
    checkpoint_sequence: number;
    committed_at: number;
    event_id: KeyLogIdentifier;
    event_leaf_hash: Hash;
    log_id: KeyLogIdentifier;
    root_hash: Hash;
    schema: "chio.key-log.activation-commit.v1";
    signing_epoch: number;
    tree_size: number;
    witness_set_hash: Hash;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-activation-commit-envelope-v1.schema.json
export namespace Security_KeyLogActivationCommitEnvelopeV1 {
  export interface ChioSignedKeyLogActivationCommitEnvelopeV1 {
    body: ChioKeyLogActivationCommitBodyV1;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_key_id: string;
    operator_signature: string;
  }
  export interface ChioKeyLogActivationCommitBodyV1 {
    checkpoint_body_hash: string;
    checkpoint_hash: string;
    checkpoint_sequence: number;
    committed_at: number;
    event_id: string;
    event_leaf_hash: string;
    log_id: string;
    root_hash: string;
    schema: "chio.key-log.activation-commit.v1";
    signing_epoch: number;
    tree_size: number;
    witness_set_hash: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-artifact-time-anchor-body-v1.schema.json
export namespace Security_KeyLogArtifactTimeAnchorBodyV1 {
  export type Anchor = CheckpointAnchor | ExternalAnchor;
  export type Hash = string;
  export type U64 = number;
  export type Identifier = string;

  export interface ChioKeyLogArtifactTimeAnchorBodyV1 {
    anchor: Anchor;
    anchor_id: Identifier;
    anchored_at: U64;
    artifact_hash: Hash;
    schema: "chio.key-log.artifact-time-anchor.v1";
  }
  export interface CheckpointAnchor {
    checkpoint_hash: Hash;
    checkpoint_sequence: U64;
    type: "receipt_checkpoint" | "key_log_checkpoint";
  }
  export interface ExternalAnchor {
    commitment: Hash;
    type: "external";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-artifact-time-anchor-envelope-v1.schema.json
export namespace Security_KeyLogArtifactTimeAnchorEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Hash = string;
  export type Signature = string;

  export interface ChioSignedKeyLogArtifactTimeAnchorV1 {
    algorithm: Algorithm;
    anchor_key_id: Hash;
    body: ChioKeyLogArtifactTimeAnchorBodyV1;
    signature: Signature;
  }
  export interface ChioKeyLogArtifactTimeAnchorBodyV1 {
    anchor: CheckpointAnchor | ExternalAnchor;
    anchor_id: string;
    anchored_at: number;
    artifact_hash: string;
    schema: "chio.key-log.artifact-time-anchor.v1";
  }
  export interface CheckpointAnchor {
    checkpoint_hash: string;
    checkpoint_sequence: number;
    type: "receipt_checkpoint" | "key_log_checkpoint";
  }
  export interface ExternalAnchor {
    commitment: string;
    type: "external";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-audit-readiness-body-v1.schema.json
export namespace Security_KeyLogAuditReadinessBodyV1 {
  export type Hash = string;
  export type Count = number;
  export type PositiveU64 = number;
  export type Identifier = string;
  export type Nonce = string;

  export interface ChioKeyLogAuditServiceReadinessBodyV1 {
    configuration_binding: Hash;
    conflict_count: Count;
    last_successful_poll_at: PositiveU64;
    monitor_id: Identifier;
    nonce: Nonce;
    operator_head: KeyLogPin;
    pin?: KeyLogPin;
    process_id: number;
    schema: "chio.key-log.audit-readiness.v1";
    started_at: PositiveU64;
    storage_identity: Hash;
    witness_proofs: {
      [k: string]: ChioSignedKeyLogWitnessServiceReadinessProofV1;
    };
    witness_views: {
      [k: string]: WitnessView;
    };
  }
  export interface KeyLogPin {
    checkpoint_hash: Hash;
    checkpoint_sequence: number;
    root_hash: Hash;
    signing_epoch: number;
    tree_size: number;
  }
  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    signature: string;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    configuration_binding: string;
    conflict_count: number;
    gossip_observation_count: number;
    nonce: string;
    pin?: KeyLogPin1;
    process_id: number;
    schema: "chio.key-log.witness-readiness.v1";
    started_at: number;
    storage_identity: string;
    witness_id: string;
  }
  export interface KeyLogPin1 {
    checkpoint_hash: string;
    checkpoint_sequence: number;
    root_hash: string;
    signing_epoch: number;
    tree_size: number;
  }
  export interface WitnessView {
    conflict_count: Count;
    pin?: KeyLogPin;
    process_id: number;
    storage_identity: Hash;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-audit-readiness-proof-v1.schema.json
export namespace Security_KeyLogAuditReadinessProofV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedKeyLogAuditServiceReadinessProofV1 {
    algorithm: Algorithm;
    body: ChioKeyLogAuditServiceReadinessBodyV1;
    signature: Signature;
  }
  export interface ChioKeyLogAuditServiceReadinessBodyV1 {
    configuration_binding: string;
    conflict_count: number;
    last_successful_poll_at: number;
    monitor_id: string;
    nonce: string;
    operator_head: KeyLogPin;
    pin?: KeyLogPin;
    process_id: number;
    schema: "chio.key-log.audit-readiness.v1";
    started_at: number;
    storage_identity: string;
    witness_proofs: {
      [k: string]: ChioSignedKeyLogWitnessServiceReadinessProofV1;
    };
    witness_views: {
      [k: string]: WitnessView;
    };
  }
  export interface KeyLogPin {
    checkpoint_hash: string;
    checkpoint_sequence: number;
    root_hash: string;
    signing_epoch: number;
    tree_size: number;
  }
  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    signature: string;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    configuration_binding: string;
    conflict_count: number;
    gossip_observation_count: number;
    nonce: string;
    pin?: KeyLogPin1;
    process_id: number;
    schema: "chio.key-log.witness-readiness.v1";
    started_at: number;
    storage_identity: string;
    witness_id: string;
  }
  export interface KeyLogPin1 {
    checkpoint_hash: string;
    checkpoint_sequence: number;
    root_hash: string;
    signing_epoch: number;
    tree_size: number;
  }
  export interface WitnessView {
    conflict_count: number;
    pin?: KeyLogPin;
    process_id: number;
    storage_identity: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-checkpoint-body-v1.schema.json
export namespace Security_KeyLogCheckpointBodyV1 {
  export type Hash = string;

  export interface ChioKeyLogCheckpointBodyV1 {
    checkpoint_sequence: number;
    issued_at: number;
    log_id: string;
    previous_checkpoint_hash?: Hash;
    root_hash: Hash;
    schema: "chio.key-log.checkpoint.v1";
    tree_size: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-checkpoint-envelope-v1.schema.json
export namespace Security_KeyLogCheckpointEnvelopeV1 {
  export type Signature = string;

  export interface ChioSignedKeyLogCheckpointEnvelopeV1 {
    body: ChioKeyLogCheckpointBodyV1;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_key_id: string;
    operator_signature: Signature;
    /**
     * @maxItems 64
     */
    witness_signatures?: ChioKeyLogWitnessSignatureV1[];
  }
  export interface ChioKeyLogCheckpointBodyV1 {
    checkpoint_sequence: number;
    issued_at: number;
    log_id: string;
    previous_checkpoint_hash?: string;
    root_hash: string;
    schema: "chio.key-log.checkpoint.v1";
    tree_size: number;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-enterprise-receipt-body-v1.schema.json
export namespace Security_KeyLogEnterpriseReceiptBodyV1 {
  export type ChioKeyLogEnterpriseReceiptBodyV1 = {
    activation_commit_hash?: Hash;
    checkpoint_hash: Hash;
    checkpoint_sequence: number;
    event_envelope_hash: Hash;
    event_id: KeyLogIdentifier;
    event_sequence: number;
    /**
     * @minItems 1
     * @maxItems 66
     */
    event_signers: [EventSigner, ...EventSigner[]];
    issued_at: number;
    log_id: KeyLogIdentifier;
    operator_key_id: Hash;
    outcome: "pending_committed" | "activated";
    receipt_id: KeyLogIdentifier;
    root_hash: Hash;
    schema: "chio.key-log.enterprise-receipt.v1";
    signing_epoch?: number;
    /**
     * @maxItems 64
     */
    source_receipt_ids?: KeyLogIdentifier[];
    stage: "pending" | "active";
    transaction_id: KeyLogIdentifier;
    tree_size: number;
    witness_roster_id: KeyLogIdentifier;
    /**
     * @maxItems 64
     */
    witness_signatures: ChioKeyLogWitnessSignatureV1[];
  } & (
    | {
        outcome?: "pending_committed";
        stage?: "pending";
        /**
         * @maxItems 0
         */
        witness_signatures?: [];
      }
    | {
        outcome?: "activated";
        /**
         * @minItems 1
         * @maxItems 1
         */
        source_receipt_ids: [unknown];
        stage?: "active";
        /**
         * @minItems 1
         */
        witness_signatures?: [unknown, ...unknown[]];
      }
  );
  export type Hash = string;
  export type KeyLogIdentifier = string;
  export type EventSigner =
    | {
        key_id: Hash;
        role: "bootstrap";
      }
    | {
        key_id: Hash;
        role: "old_key";
      }
    | {
        key_id: Hash;
        role: "new_key";
      }
    | {
        authorizer_id: KeyLogIdentifier;
        role: "recovery";
      };

  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-enterprise-receipt-envelope-v1.schema.json
export namespace Security_KeyLogEnterpriseReceiptEnvelopeV1 {
  export type ChioKeyLogEnterpriseReceiptBodyV1 = {
    activation_commit_hash?: string;
    checkpoint_hash: string;
    checkpoint_sequence: number;
    event_envelope_hash: string;
    event_id: string;
    event_sequence: number;
    /**
     * @minItems 1
     * @maxItems 66
     */
    event_signers: [
      (
        | {
            key_id: string;
            role: "bootstrap";
          }
        | {
            key_id: string;
            role: "old_key";
          }
        | {
            key_id: string;
            role: "new_key";
          }
        | {
            authorizer_id: string;
            role: "recovery";
          }
      ),
      ...(
        | {
            key_id: string;
            role: "bootstrap";
          }
        | {
            key_id: string;
            role: "old_key";
          }
        | {
            key_id: string;
            role: "new_key";
          }
        | {
            authorizer_id: string;
            role: "recovery";
          }
      )[]
    ];
    issued_at: number;
    log_id: string;
    operator_key_id: string;
    outcome: "pending_committed" | "activated";
    receipt_id: string;
    root_hash: string;
    schema: "chio.key-log.enterprise-receipt.v1";
    signing_epoch?: number;
    /**
     * @maxItems 64
     */
    source_receipt_ids?: string[];
    stage: "pending" | "active";
    transaction_id: string;
    tree_size: number;
    witness_roster_id: string;
    /**
     * @maxItems 64
     */
    witness_signatures: ChioKeyLogWitnessSignatureV1[];
  } & (
    | {
        outcome?: "pending_committed";
        stage?: "pending";
        /**
         * @maxItems 0
         */
        witness_signatures?: [];
      }
    | {
        outcome?: "activated";
        /**
         * @minItems 1
         * @maxItems 1
         */
        source_receipt_ids: [unknown];
        stage?: "active";
        /**
         * @minItems 1
         */
        witness_signatures?: [unknown, ...unknown[]];
      }
  );

  export interface ChioSignedKeyLogEnterpriseReceiptEnvelopeV1 {
    body: ChioKeyLogEnterpriseReceiptBodyV1;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_key_id: string;
    operator_signature: string;
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-event-body-v1.schema.json
export namespace Security_KeyLogEventBodyV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type KeyLogIdentifier = string;
  export type Hash = string;
  export type Operation =
    | {
        type: "genesis";
      }
    | {
        previous_key_id: Hash;
        type: "rotate";
        witness_roster_binding: Hash;
        witness_roster_id: KeyLogIdentifier;
      }
    | {
        previous_key_id: Hash;
        recovery_policy_binding?: Hash;
        recovery_policy_id?: KeyLogIdentifier;
        type: "abort_rotation";
      }
    | {
        type: "retire";
      }
    | {
        type: "revoke";
      }
    | {
        previous_key_id: Hash;
        recovery_policy_binding: Hash;
        recovery_policy_id: KeyLogIdentifier;
        type: "recover";
        witness_roster_binding: Hash;
        witness_roster_id: KeyLogIdentifier;
      };
  export type PublicKey = string;

  export interface ChioKeyLogEventBodyV1 {
    algorithm: Algorithm;
    authority_id: KeyLogIdentifier;
    effective_at: number;
    event_id: KeyLogIdentifier;
    issued_at: number;
    key_id: Hash;
    log_id: KeyLogIdentifier;
    operation: Operation;
    previous_event_hash?: Hash;
    public_key: PublicKey;
    reason?: string;
    schema: "chio.key-log.event.v1";
    sequence: number;
    verify_until?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-event-envelope-v1.schema.json
export namespace Security_KeyLogEventEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Hash = string;
  export type Signature = string;
  export type KeyLogIdentifier = string;

  export interface ChioSignedKeyLogEventEnvelopeV1 {
    authorizations: {
      bootstrap?: KeyAuthorization;
      new_key?: KeyAuthorization;
      old_key?: KeyAuthorization;
      /**
       * @maxItems 64
       */
      recovery?: RecoveryAuthorization[];
    };
    body: ChioKeyLogEventBodyV1;
  }
  export interface KeyAuthorization {
    algorithm: Algorithm;
    key_id: Hash;
    signature: Signature;
  }
  export interface RecoveryAuthorization {
    algorithm: Algorithm;
    authorizer_id: KeyLogIdentifier;
    signature: Signature;
  }
  export interface ChioKeyLogEventBodyV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    authority_id: string;
    effective_at: number;
    event_id: string;
    issued_at: number;
    key_id: string;
    log_id: string;
    operation:
      | {
          type: "genesis";
        }
      | {
          previous_key_id: string;
          type: "rotate";
          witness_roster_binding: string;
          witness_roster_id: string;
        }
      | {
          previous_key_id: string;
          recovery_policy_binding?: string;
          recovery_policy_id?: string;
          type: "abort_rotation";
        }
      | {
          type: "retire";
        }
      | {
          type: "revoke";
        }
      | {
          previous_key_id: string;
          recovery_policy_binding: string;
          recovery_policy_id: string;
          type: "recover";
          witness_roster_binding: string;
          witness_roster_id: string;
        };
    previous_event_hash?: string;
    public_key: string;
    reason?: string;
    schema: "chio.key-log.event.v1";
    sequence: number;
    verify_until?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-sync-response-v1.schema.json
export namespace Security_KeyLogSyncResponseV1 {
  export type Hash = string;

  export interface ChioKeyLogSynchronizationResponseV1 {
    /**
     * @minItems 1
     * @maxItems 4096
     */
    activation_commits?: [ChioSignedKeyLogActivationCommitEnvelopeV1, ...ChioSignedKeyLogActivationCommitEnvelopeV1[]];
    base_checkpoint_hash?: Hash;
    /**
     * @maxItems 4096
     */
    checkpoints: ChioSignedKeyLogCheckpointEnvelopeV1[];
    consistency_proof?: ConsistencyProof;
    /**
     * @maxItems 4096
     */
    event_envelopes: ChioSignedKeyLogEventEnvelopeV1[];
  }
  export interface ChioSignedKeyLogActivationCommitEnvelopeV1 {
    body: ChioKeyLogActivationCommitBodyV1;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_key_id: string;
    operator_signature: string;
  }
  export interface ChioKeyLogActivationCommitBodyV1 {
    checkpoint_body_hash: string;
    checkpoint_hash: string;
    checkpoint_sequence: number;
    committed_at: number;
    event_id: string;
    event_leaf_hash: string;
    log_id: string;
    root_hash: string;
    schema: "chio.key-log.activation-commit.v1";
    signing_epoch: number;
    tree_size: number;
    witness_set_hash: string;
    /**
     * @minItems 1
     * @maxItems 64
     */
    witness_signatures: [ChioKeyLogWitnessSignatureV1, ...ChioKeyLogWitnessSignatureV1[]];
  }
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
  export interface ChioSignedKeyLogCheckpointEnvelopeV1 {
    body: ChioKeyLogCheckpointBodyV1;
    operator_algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    operator_key_id: string;
    operator_signature: string;
    /**
     * @maxItems 64
     */
    witness_signatures?: ChioKeyLogWitnessSignatureV1[];
  }
  export interface ChioKeyLogCheckpointBodyV1 {
    checkpoint_sequence: number;
    issued_at: number;
    log_id: string;
    previous_checkpoint_hash?: string;
    root_hash: string;
    schema: "chio.key-log.checkpoint.v1";
    tree_size: number;
  }
  export interface ConsistencyProof {
    /**
     * @maxItems 65
     */
    audit_path: Hash[];
    new_size: number;
    old_size: number;
  }
  export interface ChioSignedKeyLogEventEnvelopeV1 {
    authorizations: {
      bootstrap?: KeyAuthorization;
      new_key?: KeyAuthorization;
      old_key?: KeyAuthorization;
      /**
       * @maxItems 64
       */
      recovery?: RecoveryAuthorization[];
    };
    body: ChioKeyLogEventBodyV1;
  }
  export interface KeyAuthorization {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    key_id: string;
    signature: string;
  }
  export interface RecoveryAuthorization {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    authorizer_id: string;
    signature: string;
  }
  export interface ChioKeyLogEventBodyV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    authority_id: string;
    effective_at: number;
    event_id: string;
    issued_at: number;
    key_id: string;
    log_id: string;
    operation:
      | {
          type: "genesis";
        }
      | {
          previous_key_id: string;
          type: "rotate";
          witness_roster_binding: string;
          witness_roster_id: string;
        }
      | {
          previous_key_id: string;
          recovery_policy_binding?: string;
          recovery_policy_id?: string;
          type: "abort_rotation";
        }
      | {
          type: "retire";
        }
      | {
          type: "revoke";
        }
      | {
          previous_key_id: string;
          recovery_policy_binding: string;
          recovery_policy_id: string;
          type: "recover";
          witness_roster_binding: string;
          witness_roster_id: string;
        };
    previous_event_hash?: string;
    public_key: string;
    reason?: string;
    schema: "chio.key-log.event.v1";
    sequence: number;
    verify_until?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-readiness-body-v1.schema.json
export namespace Security_KeyLogWitnessReadinessBodyV1 {
  export type Hash = string;
  export type Count = number;
  export type Nonce = string;
  export type PositiveU64 = number;
  export type Identifier = string;

  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    configuration_binding: Hash;
    conflict_count: Count;
    gossip_observation_count: Count;
    nonce: Nonce;
    pin?: KeyLogPin;
    process_id: number;
    schema: "chio.key-log.witness-readiness.v1";
    started_at: PositiveU64;
    storage_identity: Hash;
    witness_id: Identifier;
  }
  export interface KeyLogPin {
    checkpoint_hash: Hash;
    checkpoint_sequence: number;
    root_hash: Hash;
    signing_epoch: number;
    tree_size: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-readiness-proof-v1.schema.json
export namespace Security_KeyLogWitnessReadinessProofV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Signature = string;

  export interface ChioSignedKeyLogWitnessServiceReadinessProofV1 {
    algorithm: Algorithm;
    body: ChioKeyLogWitnessServiceReadinessBodyV1;
    signature: Signature;
  }
  export interface ChioKeyLogWitnessServiceReadinessBodyV1 {
    configuration_binding: string;
    conflict_count: number;
    gossip_observation_count: number;
    nonce: string;
    pin?: KeyLogPin;
    process_id: number;
    schema: "chio.key-log.witness-readiness.v1";
    started_at: number;
    storage_identity: string;
    witness_id: string;
  }
  export interface KeyLogPin {
    checkpoint_hash: string;
    checkpoint_sequence: number;
    root_hash: string;
    signing_epoch: number;
    tree_size: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/key-log-witness-signature-v1.schema.json
export namespace Security_KeyLogWitnessSignatureV1 {
  export interface ChioKeyLogWitnessSignatureV1 {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
    witness_id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/keyring-artifact-signature-v1.schema.json
export namespace Security_KeyringArtifactSignatureV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type Hash = string;
  export type Signature = string;
  export type U64 = number;

  export interface ChioKeyringArtifactSignatureEvidenceV1 {
    algorithm: Algorithm;
    artifact_hash: Hash;
    artifact_signature: Signature;
    fence_signature: Signature;
    key_id: Hash;
    schema: "chio.keyring.artifact-signature.v1";
    signing_epoch: U64;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/lift-rollback-completion-receipt-body-v1.schema.json
export namespace Security_LiftRollbackCompletionReceiptBodyV1 {
  export type ChioLiftOrRollbackCompletionReceiptBodyV1 = {
    dispatch_authorization_hash: Digest | null;
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
    execution_dispatch: ExecutionDispatch | null;
    final_state: "lifted" | "rollback_partial";
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    response_body_hash: Digest;
    response_generation: number;
  } & (
    | {
        dispatch_authorization_hash?: null;
        execution_dispatch?: null;
      }
    | {
        dispatch_authorization_hash?: Digest;
        execution_dispatch?: ExecutionDispatch;
      }
  );
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
        error_code: string;
        state: "apply_failed";
      }
    | {
        resulting_version_hash: Digest;
        state: "restored";
      }
    | {
        error_code: string;
        state: "rollback_failed";
      }
    | {
        state: "no_rollback_required";
      };

  export interface Effect {
    contribution_hash: Digest;
    effect_id: string;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    observed_base_version_hash: Digest;
    ordinal: number;
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          session_id: string;
          target_type: "session";
        }
      | {
          lineage_id: string;
          target_type: "lineage";
        }
      | {
          affected_set_hash: Digest;
          target_type: "capability_set";
        };
  }
  export interface ExecutionDispatch {
    action_id: string;
    approval:
      | {
          approval_mode: "automatic";
        }
      | {
          admission_operation_id: string;
          admission_operation_version: number;
          approval_mode: "governed";
          approval_set_hash: Digest;
        };
    authorization_capability_hash: Digest;
    authorized_at_unix_ms: number;
    dispatch_id: string;
    executor_authority_generation: number;
    executor_authority_id: string;
    governed_intent_hash: Digest;
    plan_hash: Digest;
    policy_decision_hash: Digest;
    schema_version: 1;
    tenant_id: string;
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Response {
    action_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: string;
    trigger_finding_receipt_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/mcp-cage-launch-policy-v2.schema.json
export namespace Security_McpCageLaunchPolicyV2 {
  export type BrokerBinding = {
    authentication_digest: Digest;
    expected_peer_identity: BrokerPeerIdentity;
    inherited_fd?: number;
    socket_path?: AbsoluteCanonicalPath;
  } & BrokerBinding1;
  export type Digest = string;
  export type AbsoluteCanonicalPath = string;
  export type BrokerBinding1 = {};
  export type EnterpriseMigration = {
    [k: string]: unknown;
  } & {
    deployment_id: Identifier;
    minimum_head: MinimumHead;
    stage: "disabled" | "shadow" | "enforced" | "legacy_removed";
    state_database_path: AbsoluteCanonicalPath;
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
  };
  export type Identifier = string;
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
  export type PublicKey = string;
  export type EnvironmentVariable = string;
  export type Signature = string;

  /**
   * Canonical signed operator policy for a migration-enforced MCP stdio cage launch.
   */
  export interface ChioSignedMCPCageLaunchPolicyV2 {
    body: PolicyBody;
    signature: Signature;
    signer_public_key: PublicKey;
  }
  export interface PolicyBody {
    broker?: BrokerBinding;
    enterprise_migration: EnterpriseMigration;
    limits: Limits;
    operator_ceilings: OperatorCeilings;
    receipt: ReceiptRuntime;
    registered_public_key: PublicKey;
    runtime: Runtime;
    schema: "chio.mcp.cage-launch-policy.v2";
    signed_manifest: ChioSignedToolManifestV2;
  }
  export interface BrokerPeerIdentity {
    gid: number;
    pid: number;
    uid: number;
  }
  export interface MinimumHead {
    key: MigrationKey;
    minimum_generation: 0 | 1 | 2 | 3;
    transition_digest: NonzeroDigest32;
  }
  export interface MigrationKey {
    control: "cage_enforcement";
    deployment_id: Identifier;
    scope_id: Identifier;
    scope_kind: "tool_server";
  }
  export interface Limits {
    launch_timeout_ms: number;
    max_artifact_bytes: number;
    nofile_hard: 192;
    nofile_soft: 192;
  }
  export interface OperatorCeilings {
    environment_variables: EnvironmentVariable[];
    forbidden_paths: AbsoluteCanonicalPath[];
    /**
     * @minItems 1
     */
    native_syscall_profiles: [
      "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1",
      ...("native_minimal_v1" | "native_standard_v1" | "brokered_native_v1")[]
    ];
    network_destinations: NetworkDestination[];
    read_paths: AbsoluteCanonicalPath[];
    write_paths: AbsoluteCanonicalPath[];
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
  export interface ReceiptRuntime {
    capability_id: Identifier;
    database_path: AbsoluteCanonicalPath;
    signer_seed_path: AbsoluteCanonicalPath;
    tenant_id?: Identifier;
    trusted_signer_public_key: PublicKey;
  }
  export interface Runtime {
    cage_init_binding_digest: Digest;
    cage_init_path: AbsoluteCanonicalPath;
    execution_identity: ExecutionIdentity;
    /**
     * @maxItems 48
     */
    runtime_files: AbsoluteCanonicalPath[];
    /**
     * @minItems 1
     * @maxItems 256
     */
    target_argv: [string, ...string[]];
    target_binding_digest: Digest;
    target_path: AbsoluteCanonicalPath;
    working_directory: AbsoluteCanonicalPath;
  }
  export interface ExecutionIdentity {
    gid: number;
    /**
     * @maxItems 64
     */
    supplementary_gids: number[];
    uid: number;
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
    description?: string;
    name: string;
    public_key: string;
    required_permissions?: RequiredPermissions;
    schema: "chio.manifest.v2";
    server_id: string;
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    version: string;
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
  }
  export interface ToolDefinition {
    annotations: ToolAnnotations;
    description: string;
    flow?: ToolFlowDeclaration;
    input_schema: {};
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    name: string;
    output_schema?: {};
    pricing?: ToolPricing;
  }
  export interface ToolAnnotations {
    destructive: boolean;
    idempotent: boolean;
    read_only: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
    egress: boolean;
    input_clearance?: KnownLabel;
    output_label?: KnownLabel;
  }
  export interface KnownLabel {
    /**
     * @maxItems 64
     */
    compartments: string[];
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
  }
  export interface ToolPricing {
    base_price?: MonetaryAmount;
    billing_unit?: string;
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    unit_price?: MonetaryAmount;
  }
  export interface MonetaryAmount {
    currency: string;
    units: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json
export namespace Security_ResponseCompletionReceiptBodyV1 {
  export type ChioResponseCompletionReceiptBodyV1 = {
    [k: string]: unknown;
  } & {
    dispatch_authorization_hash: Digest | null;
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
    error_code: string | null;
    execution_dispatch: ExecutionDispatch | null;
    final_state: "active" | "apply_partial" | "failed";
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    response_body_hash: Digest;
    response_generation: number;
  } & (
      | {
          dispatch_authorization_hash?: null;
          execution_dispatch?: null;
        }
      | {
          dispatch_authorization_hash?: Digest;
          execution_dispatch?: ExecutionDispatch;
        }
    );
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
  export type CompletionOutcome =
    | {
        state: "planned";
      }
    | {
        resulting_version_hash: Digest;
        state: "applied";
      }
    | {
        error_code: string;
        state: "apply_failed";
      };
  export type DispatchApproval =
    | {
        approval_mode: "automatic";
      }
    | {
        admission_operation_id: string;
        admission_operation_version: number;
        approval_mode: "governed";
        approval_set_hash: Digest;
      };

  export interface Effect {
    contribution_hash: Digest;
    effect_id: string;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    observed_base_version_hash: Digest;
    ordinal: number;
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          session_id: string;
          target_type: "session";
        }
      | {
          lineage_id: string;
          target_type: "lineage";
        }
      | {
          affected_set_hash: Digest;
          target_type: "capability_set";
        };
  }
  export interface ExecutionDispatch {
    action_id: string;
    approval: DispatchApproval;
    authorization_capability_hash: Digest;
    authorized_at_unix_ms: number;
    dispatch_id: string;
    executor_authority_generation: number;
    executor_authority_id: string;
    governed_intent_hash: Digest;
    plan_hash: Digest;
    policy_decision_hash: Digest;
    schema_version: 1;
    tenant_id: string;
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Response {
    action_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: string;
    trigger_finding_receipt_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-effect-v1.schema.json
export namespace Security_ResponseEffectV1 {
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
        session_id: Identifier;
        target_type: "session";
      }
    | {
        lineage_id: Identifier;
        target_type: "lineage";
      }
    | {
        affected_set_hash: Digest;
        target_type: "capability_set";
      };

  export interface ChioResponseEffectV1 {
    /**
     * @maxItems 1048576
     */
    canonical_contribution: number[];
    contribution_hash: Digest;
    effect_id: Identifier;
    kind: Kind;
    observed_base_version_hash: Digest;
    ordinal: number;
    target: Target;
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
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [Effect, ...Effect[]];
    header: Header;
    plan_created_at_unix_ms: number;
    response: Response;
  }
  export interface Effect {
    contribution_hash: Digest;
    effect_id: string;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    observed_base_version_hash: Digest;
    ordinal: number;
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          session_id: string;
          target_type: "session";
        }
      | {
          lineage_id: string;
          target_type: "lineage";
        }
      | {
          affected_set_hash: Digest;
          target_type: "capability_set";
        };
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Response {
    action_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: string;
    trigger_finding_receipt_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
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
  export type ApprovalRequirement =
    | {
        approval_type: "automatic";
      }
    | {
        approval_type: "governed";
        policy_id: Identifier;
      };
  export type Time = number;
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

  export interface ChioResponsePlanV1 {
    action_id: Identifier;
    /**
     * @minItems 1
     * @maxItems 4096
     */
    affected_ids: [Identifier, ...Identifier[]];
    affected_set_hash: Digest;
    approval_requirement: ApprovalRequirement;
    created_at_unix_ms: Time;
    /**
     * @minItems 1
     * @maxItems 64
     */
    effects: [ChioResponseEffectV1, ...ChioResponseEffectV1[]];
    expires_at_unix_ms: Time;
    operator_capability: OperatorCapability;
    plan_hash: Digest;
    policy_hash: Digest;
    policy_version: Identifier;
    reason_hash: Digest;
    submitter: Identifier;
    tenant_id: Identifier;
    trigger_finding_hash: Digest;
    trigger_finding_id: Identifier;
    trigger_finding_receipt_id: Identifier;
    ttl_ms: Time;
  }
  export interface ChioResponseEffectV1 {
    /**
     * @maxItems 1048576
     */
    canonical_contribution: number[];
    contribution_hash: Digest1;
    effect_id: string;
    kind:
      | "escalate_alert"
      | "throttle_session"
      | "restrict_egress"
      | "suspend_session"
      | "suspend_capability_set"
      | "freeze_issuance";
    observed_base_version_hash: Digest1;
    ordinal: number;
    target:
      | {
          target_type: "tenant";
          tenant_id: string;
        }
      | {
          session_id: string;
          target_type: "session";
        }
      | {
          lineage_id: string;
          target_type: "lineage";
        }
      | {
          affected_set_hash: Digest1;
          target_type: "capability_set";
        };
  }
  export interface OperatorCapability {
    capability_digest: Digest;
    capability_id: Identifier;
    executor_subject: Identifier;
    expires_at_unix_ms: Time;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/response-state-transition-receipt-body-v1.schema.json
export namespace Security_ResponseStateTransitionReceiptBodyV1 {
  export type Time = number;
  export type Identifier = string;
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

  export interface ChioResponseStateTransitionReceiptBodyV1 {
    applying_lease_expires_at_unix_ms: Time | null;
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
    error_code: Identifier | null;
    from_state: State;
    generation: number;
    header: Header & {
      /**
       * @maxItems 1
       */
      prior_receipt_ids?: [] | [unknown];
    };
    response: Response;
    scheduler_fencing_token?: number | null;
    scheduler_lease_owner_id?: Identifier | null;
    to_state: State;
  }
  export interface Header {
    occurred_at_unix_ms: Time;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [Identifier, ...Identifier[]];
    schema_version: 1;
    tenant_id: Identifier;
    transition_id: Identifier;
  }
  export interface Response {
    action_id: Identifier;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: Time;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: Identifier;
    trigger_finding_receipt_id: Identifier;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: Identifier;
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
    attempts: number;
    error_code: string;
    event_id: string;
    evidence_hash: Digest;
    first_failure_at_unix_ms: number;
    header: Header;
    response: Response;
    scheduler_fencing_token: number;
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    prior_receipt_ids: [string, ...string[]];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Response {
    action_id: string;
    affected_set_hash: Digest;
    plan_expires_at_unix_ms: number;
    plan_hash: Digest;
    policy: Policy;
    trigger_finding_hash: Digest;
    trigger_finding_id: string;
    trigger_finding_receipt_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/security-event-body-v1.schema.json
export namespace Security_SecurityEventBodyV1 {
  export type Identifier = string;
  export type Time = number;

  export interface ChioSecurityEventBodyV1 {
    event_id: Identifier;
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
    event_time_unix_ms: Time;
    /**
     * @minItems 1
     * @maxItems 64
     */
    evidence_references: [Identifier, ...Identifier[]];
    ingest_time_unix_ms: Time;
    policy_version: Identifier;
    producer_id: Identifier;
    producer_key_id: Identifier;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    source_receipt_id: Identifier;
    subject: Subject;
    tenant_id: Identifier;
    trust_class: "internal_detector" | "verified_receipt";
  }
  export interface Subject {
    agent_id: Identifier;
    capability_id: Identifier;
    lineage_seed: Identifier;
    session_id: Identifier;
    subject_id: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/signed-security-event-envelope-v1.schema.json
export namespace Security_SignedSecurityEventEnvelopeV1 {
  export type Algorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type PublicKey = string;
  export type Signature = string;

  export interface ChioSignedSecurityEventProvenanceEnvelopeV1 {
    algorithm: Algorithm;
    body: ChioSecurityEventBodyV1;
    producer_key: PublicKey;
    signature: Signature;
  }
  export interface ChioSecurityEventBodyV1 {
    event_id: string;
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
    event_time_unix_ms: number;
    /**
     * @minItems 1
     * @maxItems 64
     */
    evidence_references: [string, ...string[]];
    ingest_time_unix_ms: number;
    policy_version: string;
    producer_id: string;
    producer_key_id: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    source_receipt_id: string;
    subject: Subject;
    tenant_id: string;
    trust_class: "internal_detector" | "verified_receipt";
  }
  export interface Subject {
    agent_id: string;
    capability_id: string;
    lineage_seed: string;
    session_id: string;
    subject_id: string;
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
    description?: string;
    name: string;
    public_key: string;
    required_permissions?: RequiredPermissions;
    schema: "chio.manifest.v2";
    server_id: string;
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    version: string;
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
  export interface ToolDefinition {
    annotations: ToolAnnotations;
    description: string;
    flow?: ToolFlowDeclaration;
    input_schema: {};
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    name: string;
    output_schema?: {};
    pricing?: ToolPricing;
  }
  export interface ToolAnnotations {
    destructive: boolean;
    idempotent: boolean;
    read_only: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
    egress: boolean;
    input_clearance?: KnownLabel;
    output_label?: KnownLabel;
  }
  export interface KnownLabel {
    /**
     * @maxItems 64
     */
    compartments: string[];
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
  }
  export interface ToolPricing {
    base_price?: MonetaryAmount;
    billing_unit?: string;
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    unit_price?: MonetaryAmount;
  }
  export interface MonetaryAmount {
    currency: string;
    units: number;
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
    /**
     * @minItems 1
     */
    declassification_purposes?: [FlowIdentifier, ...FlowIdentifier[]];
    egress: boolean;
    input_clearance?: KnownLabel;
    output_label?: KnownLabel;
  }
  export interface KnownLabel {
    /**
     * @maxItems 64
     */
    compartments: FlowIdentifier[];
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: FlowIdentifier[];
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/security/tool-manifest-v2.schema.json
export namespace Security_ToolManifestV2 {
  /**
   * Strict signed platform manifest body combining normative tool flow metadata and typed native cage permissions.
   */
  export interface ChioToolManifestV2 {
    description?: string;
    name: string;
    public_key: string;
    required_permissions?: RequiredPermissions;
    schema: "chio.manifest.v2";
    server_id: string;
    /**
     * @minItems 1
     */
    server_tools?: ["computer_use" | "bash" | "text_editor", ...("computer_use" | "bash" | "text_editor")[]];
    /**
     * @minItems 1
     */
    tools: [ToolDefinition, ...ToolDefinition[]];
    version: string;
  }
  export interface RequiredPermissions {
    /**
     * @minItems 1
     */
    environment_variables?: [string, ...string[]];
    native_syscall_profile: "native_minimal_v1" | "native_standard_v1" | "brokered_native_v1";
    /**
     * @minItems 1
     */
    network_destinations?: [NetworkDestination, ...NetworkDestination[]];
    /**
     * @minItems 1
     */
    read_paths?: [string, ...string[]];
    /**
     * @minItems 1
     */
    write_paths?: [string, ...string[]];
  }
  export interface NetworkDestination {
    host: string;
    port: number;
  }
  export interface ToolDefinition {
    annotations: ToolAnnotations;
    description: string;
    flow?: ToolFlowDeclaration;
    input_schema: {};
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
    name: string;
    output_schema?: {};
    pricing?: ToolPricing;
  }
  export interface ToolAnnotations {
    destructive: boolean;
    idempotent: boolean;
    read_only: boolean;
    requires_approval: boolean;
  }
  /**
   * Publisher-authenticated information-flow constraints retained across protocol bridges.
   */
  export interface ToolFlowDeclaration {
    /**
     * @minItems 1
     */
    declassification_purposes?: [string, ...string[]];
    egress: boolean;
    input_clearance?: KnownLabel;
    output_label?: KnownLabel;
  }
  export interface KnownLabel {
    /**
     * @maxItems 64
     */
    compartments: string[];
    kind: "known";
    owners: {
      /**
       * @maxItems 256
       */
      [k: string]: string[];
    };
  }
  export interface ToolPricing {
    base_price?: MonetaryAmount;
    billing_unit?: string;
    pricing_model: "flat" | "per_invocation" | "per_unit" | "hybrid";
    unit_price?: MonetaryAmount;
  }
  export interface MonetaryAmount {
    currency: string;
    units: number;
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
    artifact_id_hash: Digest;
    artifact_version_hash: Digest;
    event_id: string;
    header: Header;
    observation_hash: Digest;
    policy: Policy;
    request_hash: Digest;
    request_id: string;
    severity: "informational" | "low" | "medium" | "high" | "critical";
    tripwire_kind:
      | "canary_capability"
      | "honey_tool"
      | "credential_artifact"
      | "file_marker"
      | "browser_cookie"
      | "internal_hostname"
      | "signed_watermark";
  }
  export interface Header {
    occurred_at_unix_ms: number;
    /**
     * @maxItems 64
     */
    prior_receipt_ids: string[];
    schema_version: 1;
    tenant_id: string;
    transition_id: string;
  }
  export interface Policy {
    policy_hash: Digest;
    policy_version: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/admission-capture-metadata.schema.json
export namespace TrustControl_AdmissionCaptureMetadata {
  type AdmissionCaptureMetadataBase = {
    [k: string]: unknown;
  } & {
    aggregateRootBindingDigest?: Digest;
    aggregateRootCapabilityId?: Identifier;
    authority: Authority;
    authorityCommitIndex: number;
    /**
     * @minItems 1
     * @maxItems 8
     */
    authorizationArtifactDigests:
      | [Digest]
      | [Digest, Digest]
      | [Digest, Digest, Digest]
      | [Digest, Digest, Digest, Digest]
      | [Digest, Digest, Digest, Digest, Digest]
      | [Digest, Digest, Digest, Digest, Digest, Digest]
      | [Digest, Digest, Digest, Digest, Digest, Digest, Digest]
      | [Digest, Digest, Digest, Digest, Digest, Digest, Digest, Digest];
    budgetCommitIndex: number;
    checkedRevocationSetDigest: Digest;
    eventId: Identifier;
    holdId: Identifier;
    /**
     * @minItems 1
     * @maxItems 8
     */
    invocationQuotas:
      | [InvocationQuotaTransition]
      | [InvocationQuotaTransition, InvocationQuotaTransition]
      | [InvocationQuotaTransition, InvocationQuotaTransition, InvocationQuotaTransition]
      | [InvocationQuotaTransition, InvocationQuotaTransition, InvocationQuotaTransition, InvocationQuotaTransition]
      | [
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition
        ]
      | [
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition
        ]
      | [
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition
        ]
      | [
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition,
          InvocationQuotaTransition
        ];
    invocationState: "captured";
    monetaryState: "none" | "exposed" | "released" | "reconciled" | "captured" | "reversed";
    operationId: Identifier;
    revocationCommitIndex: number;
  };
  export type ChioAuthoritativeAdmissionCaptureReceiptProjection =
    AdmissionCaptureMetadataBase &
    (
      | {
          guaranteeLevel: "single_node_atomic";
          leaderEpoch?: never;
          partitionEscrowEvidence?: never;
        }
      | {
          guaranteeLevel: "partition_escrowed";
          leaderEpoch?: never;
          partitionEscrowEvidence: PartitionEscrowEvidence;
        }
      | {
          guaranteeLevel: "ha_linearizable";
          leaderEpoch: number;
          partitionEscrowEvidence?: never;
        }
    );
  export type Digest = string;
  export type Identifier = string;
  export type QuotaKey = {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    grantIndex?: number;
    ownerId: string;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  };

  export interface Authority {
    authorityId: Identifier;
    leaseEpoch: number;
    leaseId: Identifier;
  }
  export interface InvocationQuotaTransition {
    capturedInvocationsAfter: number;
    capturedInvocationsBefore: number;
    key: QuotaKey;
    maxInvocations: number;
    reservedInvocationsAfter: number;
    reservedInvocationsBefore: number;
  }
  export interface PartitionEscrowEvidence {
    canonicalJson: string;
    digest: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/admission-request-binding.schema.json
export namespace TrustControl_AdmissionRequestBinding {
  export type ChioAdmissionOperationRequestBindingProjection = {
    actionHash: Digest;
    /**
     * @maxItems 32
     */
    approvalTokenDigests: Digest[];
    budgetHoldReference: OptionalIdentifier;
    executionNonceReference: OptionalIdentifier;
    governedIntentHash: OptionalDigest;
    policyHash: Digest;
    supplementalAuthorizationDigest: OptionalDigest;
    supplementalAuthorizationReference: OptionalIdentifier;
    thresholdProposalHash: OptionalDigest;
    verifiedApprovalSetHash: OptionalDigest;
  } & (
    | {
        supplementalAuthorizationDigest?: null;
        supplementalAuthorizationReference?: null;
      }
    | {
        supplementalAuthorizationDigest?: Digest;
        supplementalAuthorizationReference?: Identifier;
      }
  );
  export type Digest = string;
  export type OptionalIdentifier = Identifier | null;
  export type Identifier = string;
  export type OptionalDigest = Digest | null;
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/attestation.schema.json
export namespace TrustControl_Attestation {
  /**
   * One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/platform/chio-control-plane` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
   */
  export interface ChioTrustControlRuntimeAttestationEvidence {
    /**
     * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims.
     */
    claims?: {
      [k: string]: unknown;
    };
    /**
     * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
     */
    evidence_sha256: string;
    /**
     * Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.
     */
    expires_at: number;
    /**
     * Unix timestamp (seconds) when this attestation was issued.
     */
    issued_at: number;
    /**
     * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
     */
    runtime_identity?: string;
    /**
     * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
     */
    schema: string;
    /**
     * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
     */
    tier: "none" | "basic" | "attested" | "verified";
    /**
     * Attestation verifier or relying party that accepted the evidence.
     */
    verifier: string;
    /**
     * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
     */
    workload_identity?: {
      /**
       * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
       */
      credentialKind: "uri" | "x509_svid" | "jwt_svid";
      /**
       * Canonical workload path within the trust domain.
       */
      path: string;
      /**
       * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
       */
      scheme: "spiffe";
      /**
       * Stable trust domain resolved from the identifier.
       */
      trustDomain: string;
      /**
       * Canonical workload identifier URI.
       */
      uri: string;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/budget-invocation-admission-evidence.schema.json
export namespace TrustControl_BudgetInvocationAdmissionEvidence {
  export type ChioBudgetInvocationAdmissionEvidence = {
    [k: string]: unknown;
  } & {
    aggregateBindingDigest?: Digest;
    aggregateRootCapabilityId?: Identifier;
    /**
     * @minItems 1
     * @maxItems 8
     */
    invocationQuotas:
      | [InvocationQuota]
      | [InvocationQuota, InvocationQuota]
      | [InvocationQuota, InvocationQuota, InvocationQuota]
      | [InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota]
      | [InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota]
      | [InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota, InvocationQuota]
      | [
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota
        ]
      | [
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota,
          InvocationQuota
        ];
    partitionEscrowEvidence?: PartitionEscrowEvidence;
    revocationSet: RevocationSet;
    supplementalBinding?: SupplementalBinding;
  };
  export type Digest = string;
  export type Identifier = string;
  export type QuotaKey = {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    grantIndex?: number;
    ownerId: Identifier;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  };
  export type SafeInteger = number;
  export type PublicKey = string;

  export interface InvocationQuota {
    key: QuotaKey;
    maxInvocations: number;
  }
  export interface PartitionEscrowEvidence {
    canonicalJson: string;
    digest: Digest;
  }
  export interface RevocationSet {
    digest: Digest;
    /**
     * @minItems 1
     * @maxItems 128
     */
    ids: [Identifier, ...Identifier[]];
  }
  export interface SupplementalBinding {
    artifactDigest: Digest;
    brokerCapabilityId: Identifier;
    claimBindingDigest: Digest;
    expiresAt: SafeInteger;
    issuer: PublicKey;
    negotiatedFeaturesDigest: Digest;
    notBefore: SafeInteger;
    requestBindingHash: Digest;
    requestConstraintDigest: Digest;
    verifiedAt: SafeInteger;
    verifierId: Identifier;
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
    /**
     * @minItems 1
     */
    chain: [SignedCommitment, ...SignedCommitment[]];
    clusterAuthenticator: string;
    schema: "chio.budget-snapshot-anchor-provenance.v1";
  }
  export interface SignedCommitment {
    body: Commitment;
    signature: string;
  }
  export interface Commitment {
    anchorSetDigest: Digest;
    chainDigest: Digest;
    commitSequence: number;
    committedAt: number;
    electionTerm: number;
    leaderUrl: string;
    previousChainDigest: Digest;
    schema: "chio.budget-snapshot-anchor-commitment.v1";
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
     * Normalized URL of the leader claiming continued ownership of the lease.
     */
    leaderUrl: string;
    /**
     * Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.
     */
    leaseEpoch: number;
    /**
     * Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
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
     * Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.
     */
    leaseEpoch: number;
    /**
     * Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + leaseTtlMs / 1000`. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.
     */
    leaseExpiresAt: number;
    /**
     * Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.
     */
    leaseId: string;
    /**
     * Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms. NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.
     */
    leaseTtlMs: number;
    /**
     * True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.
     */
    leaseValid: boolean;
    /**
     * Cluster election term that minted this lease. Monotonically non-decreasing.
     */
    term: number;
    /**
     * Optional unix-second timestamp at which the current term began on this leader. Omitted when unknown (no quorum or no leader).
     */
    termStartedAt?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/partition-escrow-admission-evidence.schema.json
export namespace TrustControl_PartitionEscrowAdmissionEvidence {
  /**
   * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
   */
  export type Identifier = string;
  export type Digest = string;
  export type PositiveSafeInteger = number;
  /**
   * An allocator-signed, complete partition allocation plan derived from one source-signed quota commitment.
   */
  export type ChioSignedPartitionEscrowAllocationSet = {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    allocatorKey: string;
    body: Body;
    signature: string;
  };
  export type PartitionEscrowQuota = {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    grantIndex?: number;
    maxInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    ownerId: string;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  } & {
    grantIndex?: number;
    maxInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    ownerId: string;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  } & {
    grantIndex?: number;
    maxInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    ownerId: string;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  };
  export type Uint32 = number;
  /**
   * A source-key-signed commitment binding one global invocation quota to an exact source artifact and complete partition allocation plan.
   */
  export type ChioSignedPartitionEscrowQuotaCommitment = {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    [k: string]: unknown;
  } & {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    body: QuotaCommitmentBody;
    signature: string;
    signerKey: string;
  };
  export type SafeInteger = number;
  export type PublicKey = string;
  /**
   * The kind discriminator is camelCase. Variant payload fields remain snake_case because that is the exact serde representation.
   */
  export type SourceTrust =
    | GrantCapabilityTrust
    | AggregateCapabilityTrust
    | AggregateFamilyTrust
    | BrokerCapabilityTrust;
  export type PositiveUint32 = number;

  /**
   * Canonical historical proof that a durable partition authority verified and admitted one or more source-backed invocation quotas.
   */
  export interface ChioPartitionEscrowAdmissionEvidence {
    authorityDomain: Identifier;
    authorityId: Identifier;
    durableStore: DurableStore;
    partitionId: Identifier;
    /**
     * Quota keys and certificate bindings must be unique under runtime validation.
     *
     * @minItems 1
     * @maxItems 8
     */
    quotas:
      | [QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence, QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence]
      | [QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence, QuotaEvidence]
      | [
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence,
          QuotaEvidence
        ];
    resolver: Resolver;
    schema: "chio.partition-escrow-admission-evidence.v1";
    verifiedAt: SafeInteger;
  }
  export interface DurableStore {
    counterNamespaceDigest: Digest;
    fencingToken: PositiveSafeInteger;
    storeIdentityDigest: Digest;
  }
  export interface QuotaEvidence {
    allocationEpoch: PositiveSafeInteger;
    allocationPlanDigest: Digest;
    allocationRootId: Identifier;
    allocationSet: ChioSignedPartitionEscrowAllocationSet;
    allocationSetDigest: Digest;
    globalQuota: PartitionEscrowQuota;
    localAllocatedInvocations: Uint32;
    quotaCertificateBindingDigest: Digest;
    quotaCommitment: ChioSignedPartitionEscrowQuotaCommitment;
    quotaCommitmentDigest: Digest;
    quotaDescriptorDigest: Digest;
    quotaKeyDigest: Digest;
    /**
     * Exclusive source authority expiry. Runtime validation also requires this value to be greater than sourceNotBefore.
     */
    sourceExpiresAt: PositiveSafeInteger;
    sourceNotBefore: SafeInteger;
    sourceSigner: PublicKey;
    sourceTrust: SourceTrust;
    sourceTrustBindingDigest: Digest;
    totalAllocatedInvocations: Uint32;
    underlyingSourceArtifactDigest: Digest;
  }
  export interface Body {
    allocationEpoch: number;
    allocationPlanDigest: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    allocationRootId: string;
    /**
     * The complete allocation set. Runtime validation additionally requires bytewise ordering, unique partition and authority identifiers, and a sum no greater than quota.maxInvocations.
     *
     * @minItems 1
     * @maxItems 64
     */
    allocations: [Allocation, ...Allocation[]];
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    authorityDomain: string;
    /**
     * Exclusive allocation expiry. Runtime validation also requires notBefore < expiresAt <= quotaCommitmentExpiresAt.
     */
    expiresAt: number;
    notBefore: number;
    quota: PartitionEscrowQuota;
    quotaCommitmentDigest: string;
    quotaCommitmentExpiresAt: number;
    schema: "chio.partition-escrow-allocation-set.v1";
  }
  export interface Allocation {
    allocatedInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    authorityId: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    partitionId: string;
  }
  export interface QuotaCommitmentBody {
    allocationEpoch: number;
    allocationPlanDigest: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    allocationRootId: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    authorityDomain: string;
    quota: PartitionEscrowQuota;
    quotaKeyDigest: string;
    schema: "chio.partition-escrow-quota-commitment.v1";
    /**
     * Exclusive source authority expiry. Runtime validation also requires this value to be greater than sourceNotBefore.
     */
    sourceExpiresAt: number;
    sourceNotBefore: number;
    sourceTrustBindingDigest: string;
    underlyingSourceArtifactDigest: string;
  }
  export interface GrantCapabilityTrust {
    capability_id: Identifier;
    grant_index: Uint32;
    kind: "grantCapability";
    revocation_set_digest: Digest;
  }
  export interface AggregateCapabilityTrust {
    capability_id: Identifier;
    kind: "aggregateCapability";
    revocation_set_digest: Digest;
  }
  export interface AggregateFamilyTrust {
    family_owner: Digest;
    kind: "aggregateFamily";
    revocation_set_digest: Digest;
    root_binding_digest: Digest;
    root_capability_id: Identifier;
  }
  export interface BrokerCapabilityTrust {
    broker_capability_id: Identifier;
    claim_binding_digest: Digest;
    kind: "brokerCapability";
    negotiated_features_digest: Digest;
    quota_owner_id: Digest;
    request_binding_hash: Digest;
    request_constraint_digest: Digest;
    revocation_set_digest: Digest;
    verifier_id: Identifier;
  }
  export interface Resolver {
    configurationDigest: Digest;
    implementationId: Identifier;
    implementationVersion: PositiveUint32;
    resolverId: Identifier;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/partition-escrow-allocation-set.schema.json
export namespace TrustControl_PartitionEscrowAllocationSet {
  /**
   * An allocator-signed, complete partition allocation plan derived from one source-signed quota commitment.
   */
  export type ChioSignedPartitionEscrowAllocationSet = {
    [k: string]: unknown;
  } & {
    algorithm: "ed25519" | "p256" | "p384" | "hybrid";
    allocatorKey: string;
    body: Body;
    signature: string;
  };
  export type PartitionEscrowQuota = {
    [k: string]: unknown;
  } & {
    grantIndex?: number;
    maxInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    ownerId: string;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  };

  export interface Body {
    allocationEpoch: number;
    allocationPlanDigest: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    allocationRootId: string;
    /**
     * The complete allocation set. Runtime validation additionally requires bytewise ordering, unique partition and authority identifiers, and a sum no greater than quota.maxInvocations.
     *
     * @minItems 1
     * @maxItems 64
     */
    allocations: [Allocation, ...Allocation[]];
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    authorityDomain: string;
    /**
     * Exclusive allocation expiry. Runtime validation also requires notBefore < expiresAt <= quotaCommitmentExpiresAt.
     */
    expiresAt: number;
    notBefore: number;
    quota: PartitionEscrowQuota;
    quotaCommitmentDigest: string;
    quotaCommitmentExpiresAt: number;
    schema: "chio.partition-escrow-allocation-set.v1";
  }
  export interface Allocation {
    allocatedInvocations: number;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    authorityId: string;
    /**
     * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
     */
    partitionId: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/partition-escrow-quota-commitment.schema.json
export namespace TrustControl_PartitionEscrowQuotaCommitment {
  /**
   * A source-key-signed commitment binding one global invocation quota to an exact source artifact and complete partition allocation plan.
   */
  export type ChioSignedPartitionEscrowQuotaCommitment = {
    [k: string]: unknown;
  } & {
    algorithm: PartitionEscrowSignatureAlgorithm;
    body: QuotaCommitmentBody;
    signature: PartitionEscrowSignature;
    signerKey: PartitionEscrowPublicKey;
  };
  export type PartitionEscrowSignatureAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type PartitionEscrowPositiveSafeInteger = number;
  export type PartitionEscrowDigest = string;
  /**
   * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
   */
  export type PartitionEscrowIdentifier = string;
  export type PartitionEscrowQuota = {
    [k: string]: unknown;
  } & {
    grantIndex?: PartitionEscrowUint32;
    maxInvocations: PartitionEscrowUint32;
    ownerId: PartitionEscrowIdentifier;
    profile:
      | "chio.grant-invocation.v1"
      | "chio.aggregate-capability-invocation.v1"
      | "chio.aggregate-family-invocation.v1"
      | "chio.broker-capability-execution.v1";
  };
  export type PartitionEscrowUint32 = number;
  export type PartitionEscrowSafeInteger = number;
  export type PartitionEscrowSignature = string;
  export type PartitionEscrowPublicKey = string;

  export interface QuotaCommitmentBody {
    allocationEpoch: PartitionEscrowPositiveSafeInteger;
    allocationPlanDigest: PartitionEscrowDigest;
    allocationRootId: PartitionEscrowIdentifier;
    authorityDomain: PartitionEscrowIdentifier;
    quota: PartitionEscrowQuota;
    quotaKeyDigest: PartitionEscrowDigest;
    schema: "chio.partition-escrow-quota-commitment.v1";
    /**
     * Exclusive source authority expiry. Runtime validation also requires this value to be greater than sourceNotBefore.
     */
    sourceExpiresAt: PartitionEscrowPositiveSafeInteger;
    sourceNotBefore: PartitionEscrowSafeInteger;
    sourceTrustBindingDigest: PartitionEscrowDigest;
    underlyingSourceArtifactDigest: PartitionEscrowDigest;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/partition-escrow-receipt-metadata.schema.json
export namespace TrustControl_PartitionEscrowReceiptMetadata {
  export type Digest = string;
  /**
   * A non-empty identifier whose UTF-8 representation is limited to 512 bytes by runtime validation.
   */
  export type Identifier = string;
  export type PositiveSafeInteger = number;
  export type PositiveUint32 = number;

  /**
   * Receipt-side partition authority proof carrying the exact canonical admission-evidence JSON, its domain-separated digest, and an indexable authority summary.
   */
  export interface ChioPartitionEscrowFinancialReceiptMetadata {
    /**
     * The exact RFC 8785 canonical JSON serialization of a partition-escrow admission evidence object. Runtime validation applies the one MiB bound to UTF-8 bytes.
     */
    canonical_json: string;
    evidence_digest: Digest;
    summary: Summary;
  }
  export interface Summary {
    authority_id: Identifier;
    counter_namespace_digest: Digest;
    fencing_token: PositiveSafeInteger;
    partition_id: Identifier;
    resolver_configuration_digest: Digest;
    resolver_id: Identifier;
    resolver_implementation_id: Identifier;
    resolver_implementation_version: PositiveUint32;
    store_identity_digest: Digest;
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
     * Normalized URL of the leader releasing the lease.
     */
    leaderUrl: string;
    /**
     * Lease epoch carried alongside `leaseId`.
     */
    leaseEpoch: number;
    /**
     * Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
    /**
     * Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.
     */
    observedAt: number;
    /**
     * Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
     */
    reason: "leader_handoff" | "quorum_lost" | "operator_stepdown" | "term_advanced";
    /**
     * Optional normalized URL of the successor leader, when termination is part of a planned handoff.
     */
    successorLeaderUrl?: string;
  }
}
