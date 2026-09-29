#![allow(deprecated)]

use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::thread;
use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    governance::{
        CallChainContinuationAudience, CallChainContinuationToken, CallChainContinuationTokenBody,
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedAutonomyContext, GovernedAutonomyTier, GovernedCallChainContext,
        GovernedTransactionIntent, GovernedUpstreamCallChainProof,
        GovernedUpstreamCallChainProofBody, GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY,
        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY,
    },
    scope::{
        ChioScope, Constraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant,
    },
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::credit::{
    CreditBondArtifact, CreditBondDisposition, CreditBondLifecycleState, CreditBondPrerequisites,
    CreditBondReport, CreditBondSupportBoundary, CreditScorecardBand, CreditScorecardConfidence,
    CreditScorecardSummary, ExposureLedgerQuery, ExposureLedgerSummary, SignedCreditBond,
    CREDIT_BOND_ARTIFACT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::GuardEvidence,
};
use chio_core::session::{
    CompleteOperation, CompletionArgument, CompletionReference, CreateMessageOperation,
    GetPromptOperation, OperationContext, RequestId, SamplingMessage, SamplingTool,
    SamplingToolChoice, SessionAnchorReference, SessionAuthContext, SessionId, SessionOperation,
    ToolCallOperation,
};
use chio_core::{
    PromptArgument, PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation,
    ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
};
use chio_link::{ExchangeRate, PriceOracle, PriceOracleError};
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;
use chio_core_types::capability::scope::ModelSafetyTier;
use chio_core_types::{
    PlanEvaluationRequest, PlanVerdict, PlannedToolCall, StepVerdictKind,
};
use std::sync::Arc as StdArc;
use crate::approval::{
    compute_parameter_hash, resume_with_decision, ApprovalContext, ApprovalDecision, ApprovalGuard,
    ApprovalOutcome, ApprovalRequest, ApprovalStore, ApprovalToken, HitlVerdict,
    InMemoryApprovalStore,
};
use crate::approval_channels::RecordingChannel;
use crate::governed_active_response::{
    GovernedActiveResponseDispatchCommit, GovernedActiveResponseRequest,
};
use crate::threshold_approval::ThresholdApprovalRequirementResolver;
use chio_core::capability::governance::{
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntentBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ACTIVE_RESPONSE_PLAN_TOOL_NAME,
    ACTIVE_RESPONSE_SERVER_ID, GOVERNED_RESPONSE_PLAN_SCHEMA, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequirement, ThresholdApproverIdentity,
};
use chio_log_redact::redacted;
use crate::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    InMemoryExecutionNonceStore, NonceBinding,
};
use crate::compliance_score::{
    compliance_score, ComplianceScoreConfig, ComplianceScoreInputs,
};
use crate::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};
use crate::operator_report::ComplianceReport;
use chio_core_types::session::{
    EnterpriseFederationMethod, EnterpriseIdentityContext, OAuthBearerFederatedClaims,
    OAuthBearerSessionAuthInput,
};
use std::collections::BTreeMap;
use chio_core::capability::features::CapabilityNegotiation;
use chio_federation::{
    bilateral::BilateralCoSigningError, bilateral::BilateralCoSigningProtocol,
    bilateral::CoSigningRequest, bilateral::CoSigningResponse, bilateral::InProcessCoSigner,
    trust_establishment::FederationPeer, trust_establishment::KernelTrustExchange,
    trust_establishment::PeerHandshakeEnvelope,
};
use crate::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult,
    AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationStoreError,
    AdmissionOperationV1, AdmissionProjectionCapabilities, AdmissionReplayClassification,
    AdmissionReplayKey, AdmissionTerminal, AdmissionTerminalProjection, AdmissionTerminalReplay,
    QualifiedAdmissionOperationStore, StoreMutationFence, UntrustedAdmissionRecoveryClaim,
};
use crate::receipt_store::{QualifiedAdmissionProjectionStore, ReceiptStore, ReceiptStoreError};
use crate::tool_outcome::{
    validate_evaluation_store_successor, validate_terminal_store_pair, CanonicalInvocationBlobV1,
    CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1, QualifiedToolOutcomeStore,
    RawInvocationOutcomeV1, ToolOutcomeInsertResultV1, ToolOutcomeRecordV1, ToolOutcomeStore,
    ToolOutcomeStoreError,
};

use proptest::prelude::*;

use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetInvocationCaptureDecision,
    BudgetMutationKind, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
};

#[path = "tests/support.rs"]
mod support;
use support::{make_config, make_kernel, DeadWriterReceiptStore, RejectingDeadWriterReceiptStore, SnapshotTrackingDeadWriterStore, SqliteReceiptStore, SqliteRevocationStore, make_keypair, make_signed_receipt, unique_receipt_db_path, make_elicited_content, make_grant, make_scope, make_capability, make_direct_attenuated_capability, make_request, make_request_with_arguments, make_operation_context, session_tool_call, session_capability_list, session_root_list, session_resource_list, session_resource_read, session_prompt_list, session_prompt_get, session_completion, tool_call_value_output, tool_call_stream_output, assert_content_addressed_receipt_id, make_chain_bound_delegation_link, make_chain_bound_capability, set_capability_trust_root_for_scope, V2DelegatedChildInput, make_v2_delegated_child, EchoServer, SideEffectServer, IncompleteServer, StreamingServer, EventDrainServer, FailingEventDrainServer, NestedFlowServer, MockNestedFlowClient, DocsResourceProvider, StubPaymentAdapter, DecliningPaymentAdapter, PrepaidSettledPaymentAdapter, AppendOnlyReceiptStore, RetentionCapableReceiptStore, PointLookupReceiptStore, ErroringReceiptStore, FailingCheckpointHydrationReceiptStore, FailingSessionAnchorReceiptStore, RecordingSessionAnchorReceiptStore, FailingRequestLineageReceiptStore};
#[path = "tests/support_providers.rs"]
mod support_providers;
use support_providers::{FilesystemResourceProvider, ExamplePromptProvider};

#[path = "tests/support_delegation_plain.rs"]
mod support_delegation_plain;
use support_delegation_plain::{make_chain_bound_plain_capability};

#[path = "tests/support_monetary.rs"]
mod support_monetary;
use support::budget_store_impls::{delegate_authority_fenced_budget_methods, reject_authority_fenced_budget_methods};
use support_monetary::{MonetaryCostServer, FailingMonetaryServer, UnmeasuredCostServer, CountingMonetaryServer, PendingMonetaryServer, StaticPriceOracle, make_monetary_grant, make_monetary_config, SiblingSumMonetaryFixture, make_sibling_sum_monetary_fixture, SiblingSumInvocationFixture, make_invocation_limited_grant, make_sibling_sum_invocation_fixture, spawn_payment_test_server, spawn_bound_acp_test_server, make_governed_monetary_grant, with_minimum_runtime_assurance, with_minimum_autonomy_tier, make_governed_acp_monetary_grant, make_governed_intent, GovernedAcpIntentFixture, make_governed_acp_intent, make_runtime_attestation, make_trusted_azure_runtime_attestation, make_trusted_google_runtime_attestation, make_trusted_nitro_runtime_attestation, make_attestation_trust_policy, make_attested_attestation_trust_policy, make_metered_billing_context, make_governed_call_chain_context, make_governed_upstream_call_chain_proof, attach_governed_upstream_call_chain_proof, GovernedCallChainContinuationTokenFixture, make_governed_call_chain_continuation_token, attach_governed_call_chain_continuation_token, make_governed_autonomy_context, CreditBondFixture, make_credit_bond, make_governed_approval_token, TrackingPaymentAdapter, make_dpop_kernel_and_cap, make_dpop_proof, ReverseFailingBudgetStore};
#[path = "tests/settlement_routing.rs"]
mod settlement_routing;
#[path = "tests/capability_validation.rs"]
mod capability_validation;
#[path = "tests/capability_liveness.rs"]
mod capability_liveness;
#[path = "tests/guard_pipeline.rs"]
mod guard_pipeline;
#[path = "tests/hot_path_deadlines.rs"]
mod hot_path_deadlines;
use hot_path_deadlines::{HangingToolServer};
#[path = "tests/receipts.rs"]
mod receipts;
#[path = "tests/session.rs"]
mod session;
#[path = "tests/session_security_context.rs"]
mod session_security_context;
#[path = "tests/security_dispatch.rs"]
mod security_dispatch;
#[path = "tests/session_sampling_elicitation.rs"]
mod session_sampling_elicitation;
#[path = "tests/budget.rs"]
mod budget;
#[path = "tests/budget_cross_currency.rs"]
mod budget_cross_currency;
#[path = "tests/budget_governed_fallback.rs"]
mod budget_governed_fallback;
#[path = "tests/budget_governed_call_chain.rs"]
mod budget_governed_call_chain;
#[path = "tests/budget_governed_assurance.rs"]
mod budget_governed_assurance;
#[path = "tests/emergency.rs"]
mod emergency;
#[path = "tests/constraint_variants.rs"]
mod constraint_variants;
#[path = "tests/plan_evaluation.rs"]
mod plan_evaluation;
#[path = "tests/approval_flow.rs"]
mod approval_flow;
use approval_flow::{FixedThresholdRequirement, CoreKeypair, hitl_make_request, hitl_sign_token};
#[path = "tests/approval_deadlines.rs"]
mod approval_deadlines;
#[path = "tests/boot_receipts.rs"]
mod boot_receipts;
#[path = "tests/session_reports.rs"]
mod session_reports;
#[path = "tests/threshold_crypto_floor.rs"]
mod threshold_crypto_floor;
#[path = "tests/threshold_issuance.rs"]
mod threshold_issuance;
#[path = "tests/execution_nonce_support.rs"]
mod execution_nonce_support;
use execution_nonce_support::{kernel_with_nonce, binding_for_request, mint_nonce_for_request};
#[path = "tests/execution_nonce.rs"]
mod execution_nonce;
use execution_nonce::{reserve_request, install_strict_nonce_store, StampFailingBudgetStore};
#[path = "tests/execution_nonce_transient_settle.rs"]
mod execution_nonce_transient_settle;
#[path = "tests/nonce_admission.rs"]
mod nonce_admission;
#[path = "tests/dispatch_credentials.rs"]
mod dispatch_credentials;
use dispatch_credentials::{PostDispatchApprovalCommitFailure, CountingDispatchServer, post_dispatch_approval_commit_fixture, request_with_replayed_approval, request_with_recording_execution_nonce_store};
#[path = "tests/prepared_dispatch_credentials.rs"]
mod prepared_dispatch_credentials;
#[path = "tests/immediate_dispatch_revalidation.rs"]
mod immediate_dispatch_revalidation;
#[path = "tests/post_payment_revalidation.rs"]
mod post_payment_revalidation;
#[path = "tests/payment_ambiguity.rs"]
mod payment_ambiguity;
#[path = "tests/nested_url_side_effects.rs"]
mod nested_url_side_effects;
#[path = "tests/session_nonce_binding.rs"]
mod session_nonce_binding;
#[path = "tests/compliance_score.rs"]
mod compliance_score;
#[path = "tests/multi_tenant_receipt.rs"]
mod multi_tenant_receipt;
use multi_tenant_receipt::{oauth_auth_with_enterprise_tenant};
#[path = "tests/receipt_scope_isolation.rs"]
mod receipt_scope_isolation;
#[path = "tests/memory_provenance.rs"]
mod memory_provenance;
#[path = "tests/federation_cosign.rs"]
mod federation_cosign;
use federation_cosign::{CountingRejectingCosigner, FailingAppendReceiptStore, handshake_and_pin};
#[path = "tests/revocation_durability.rs"]
mod revocation_durability;
#[path = "tests/durable_admission.rs"]
mod durable_admission;
use durable_admission::{TestAdmissionOperationStore, admission_test_fence, durable_admission_fixture};
#[path = "tests/durable_admission_url_elicitation_support.rs"]
mod durable_admission_url_elicitation_support;
use durable_admission_url_elicitation_support::{DurableUrlElicitationServer};
#[path = "tests/chio_runtime.rs"]
mod chio_runtime;
use chio_runtime::{AllowingRuntimeAdmissionHook, FailingReleaseRuntimeAdmissionHook, FailingAfterSideEffectServer, UrlElicitationBeforeSideEffectServer, CancellationAfterSideEffectServer, IncompleteAfterSideEffectServer, ToolNotRegisteredDispatchServer, NoopNestedFlowClient, make_fabricated_drop_charge, authorize_fabricated_drop_hold};
#[path = "tests/swarm_required.rs"]
mod swarm_required;
#[path = "tests/invocation_context.rs"]
mod invocation_context;
use invocation_context::{CallerContextProbe};
#[path = "tests/invocation_dispatch.rs"]
mod invocation_dispatch;
#[path = "tests/chio_runtime_url_elicitation.rs"]
mod chio_runtime_url_elicitation;
#[path = "tests/drop_guard_proptest.rs"]
mod drop_guard_proptest;
#[path = "tests/formal_closure.rs"]
mod formal_closure;

#[path = "tests/automatic_active_response_fence.rs"]
mod automatic_active_response_fence;
#[path = "tests/sim_payment.rs"]
mod sim_payment;
use sim_payment::{make_mustprepay_intent, make_no_ceiling_mustprepay_grant};

#[path = "tests/financial_accounting.rs"]
mod financial_accounting;

#[path = "../../tests/support/treaty_dsse.rs"]
mod treaty_dsse;
use treaty_dsse::TreatyDsseAdmissionHook;
