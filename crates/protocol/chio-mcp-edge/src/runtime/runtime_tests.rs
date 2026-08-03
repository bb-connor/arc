#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use chio_core::capability::{
    aggregate_budget::issue_aggregate_family_root,
    features::{
        CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, GOVERNED_ACTIVE_RESPONSE_PLAN,
        SUPPLEMENTAL_BROKER_EXECUTION_QUOTA, THRESHOLD_GOVERNED_APPROVALS,
    },
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        ProvenanceEvidenceClass, CHIO_RESPONSE_PLAN_SCHEMA,
    },
    scope::{
        ChioScope, Constraint, ModelMetadata, ModelSafetyTier, Operation, PromptGrant,
        ResourceGrant, ToolGrant,
    },
    threshold_approval::{ThresholdApprovalProposal, ThresholdApprovalProposalBody},
    token::CapabilityTokenBody,
};
use chio_core::crypto::Keypair;
use chio_core::message::OpaqueSupplementalAuthorization;
use chio_core::{
    CompletionResult, PromptArgument, PromptDefinition, PromptMessage, PromptResult,
    ResourceContent, ResourceDefinition, ResourceTemplateDefinition, SamplingMessage, SamplingTool,
    SamplingToolChoice,
};
use chio_kernel::{
    KernelConfig, KernelError, PromptProvider, ResourceProvider, RuntimeAdmissionContext,
    RuntimeAdmissionDecision, RuntimeAdmissionHook, SecurityDispatchOutcomeHandle,
    SecurityInvocationContext, SecurityInvocationContextV1, SecurityPreDispatchContext,
    SecurityPreDispatchHook, SecurityPreDispatchPolicy, ToolCallChunk, ToolCallStream,
    ToolServerConnection, ToolServerEvent, ToolServerStreamResult,
};
use std::io::Cursor;
use std::sync::{Arc, Mutex};

static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

include!("runtime_tests_parts/fixtures_and_admission.inc");
include!("runtime_tests_parts/authorization_and_protocol.inc");
include!("runtime_tests_parts/streaming_tasks_and_resources.inc");

include!("runtime_tests/completion_and_session.rs");
