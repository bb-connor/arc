# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .broker_admin_control_receipt_body_v1_schema import ChioBrokerAdminControlReceiptBodyV1, Digest, Identifier, Operation
from .broker_admin_control_receipt_envelope_v1_schema import Algorithm, ChioSignedBrokerAdminControlReceiptV1, PublicKey, Signature
from .broker_admin_mutation_receipt_body_v1_schema import ChioBrokerAdminMutationReceiptBodyV1, Digest, Identifier, Operation
from .broker_admin_mutation_receipt_envelope_v1_schema import Algorithm, ChioSignedBrokerAdminMutationReceiptV1, PublicKey, Signature
from .broker_attempt_registration_v1_schema import AttemptIds, ChioBrokerAttemptRegistrationV1, Digest, Identifier, Quota
from .broker_audit_comparison_body_v1_schema import ChioBrokerAuditComparisonBodyV1, Digest
from .broker_audit_comparison_envelope_v1_schema import Algorithm, ChioSignedBrokerAuditComparisonV1, PublicKey, Signature
from .broker_audit_runner_authorization_body_v1_schema import ChioBrokerAuditRunnerAuthorizationBodyV1, Digest, Identifier
from .broker_audit_runner_authorization_envelope_v1_schema import Algorithm, ChioSignedBrokerAuditRunnerAuthorizationV1, PublicKey, Signature
from .broker_authority_request_body_v1_schema import AuthorityRpcDigest, AuthorityRpcIdentifier, AuthorizationItem, AuthorizeHoldRequest, BrokerRevocationRequest, ByteArray, ByteArrayItem, CapabilitiesOperation, CapabilityLivenessRequest, CaptureHoldRequest, CheckBrokerRevocationOperation, ChioBrokerAuthorityRpcRequestBodyV1, ControlOperation, ControlRequest, HoldOperation, HoldOperation1, HoldOperation2, HoldOperation3, HoldOperation4, Operation, Operation2, PayloadItem, PositiveU64, PrepareExecutionOperation, PublicKey, QueryHoldRequest, Quota, ReverseHoldRequest, U32, VerifyLiveParentOperation
from .broker_authority_request_envelope_v1_schema import Algorithm, ChioSignedBrokerAuthorityRpcRequestV1, Signature
from .broker_authority_response_body_v1_schema import Capabilities, CapabilitiesResult, CaptureCommit, ChioBrokerAuthorityRpcResponseBodyV1, ControlResult, Digest, HoldResult, HoldState, HoldState1, HoldState2, Identifier, LiveParent, LiveParentResult, PositiveU64, PreparedResult, PublicKey, Quota, RejectedResult, Response, ResponseItem, Result, RevocationResult, RevocationSnapshot, TrustedExecutionContext, U64
from .broker_authority_response_envelope_v1_schema import Algorithm, ChioSignedBrokerAuthorityRpcResponseV1, Signature
from .broker_capability_body_v1_schema import ChioBrokerCapabilityBodyV1, CredentialRef, Destination, Digest, HeaderName, HeaderNames, Identifier, Method, Mode, ProofBinding, PublicKey, RequestConstraints, Scheme
from .broker_capability_envelope_v1_schema import Algorithm, ChioSignedBrokerCapabilityV1, Signature
from .broker_execute_failure_v1_schema import ChioBrokerExecuteFailureV1
from .broker_execute_request_v1_schema import BodyItem, ChioBrokerExecuteRequestV1, Digest, DigestOrNull, Header, Identifier, Options, Request, ValueItem
from .broker_execute_response_v1_schema import BodyItem, ChioBrokerExecuteResponseV1
from .broker_execution_evidence_v1_schema import ChioBrokerExecutionEvidenceV1, Digest, Identifier
from .broker_execution_failure_receipt_body_v1_schema import ChioBrokerExecutionFailureReceiptBodyV1, Digest, DigestOrNull, DispatchKnowledge, Identifier, IdentifierOrNull, Outcome, Stage
from .broker_execution_failure_receipt_envelope_v1_schema import Algorithm, ChioSignedBrokerExecutionFailureReceiptV1, PublicKey, Signature
from .broker_execution_receipt_body_v1_schema import ChioBrokerExecutionReceiptBodyV1, Digest, Identifier, PublicKey, Quota
from .broker_execution_receipt_envelope_v1_schema import Algorithm, ChioSignedBrokerExecutionReceiptV1, PublicKey, Signature
from .broker_prepare_dispatch_acknowledgement_v1_schema import ChioBrokerPrepareDispatchAcknowledgementV1, Identifier
from .broker_privileged_audit_challenge_v1_schema import Algorithm, ChallengeBody, ChioSignedBrokerPrivilegedAuditChallengeV1, Digest, PositiveU64, PublicKey, Signature
from .broker_privileged_audit_commit_v1_schema import ChioBrokerPrivilegedAuditCommitRequestV1, Digest, GovernedAdminAuthorizationItem
from .broker_privileged_audit_evidence_v1_schema import AuthorityExchange, ChioBrokerPrivilegedAuditEvidenceBundleV1, Digest, GovernedAdminAuthorizationItem, PositiveU64, PublicKey
from .broker_privileged_audit_open_v1_schema import Byte, ChioBrokerPrivilegedAuditOpenRequestV1, Digest, Identifier, NonzeroDigest
from .broker_register_attempt_acknowledgement_v1_schema import ChioBrokerRegisterAttemptAcknowledgementV1, Disposition, Identifier
from .broker_register_attempt_authorization_body_v1_schema import Action, ChioBrokerRegisterAttemptAuthorizationBodyV1, Digest, Identifier, PublicKey
from .broker_register_attempt_authorization_envelope_v1_schema import Algorithm, ChioSignedBrokerRegisterAttemptAuthorizationV1, Signature
from .broker_release_attempt_acknowledgement_v1_schema import ChioBrokerReleaseAttemptAcknowledgementV1, Identifier
from .broker_request_proof_body_v1_schema import ChioBrokerRequestProofBodyV1, Digest, Identifier, PublicKey
from .broker_request_proof_envelope_v1_schema import Algorithm, ChioSignedBrokerRequestProofV1
from .cage_enforcement_failure_v1_schema import ChioCageEnforcementFailureV1, Code
from .cage_enforcement_prepared_v1_schema import ChioCageEnforcementPreparedEvidenceV1, Digest, FileIdentity, Kind, RegularFileIdentity
from .cage_enforcement_record_v1_schema import ChioCageEnforcementRecordV1, ChioCageEnforcementRecordV11, ChioCageEnforcementRecordV12, ChioCageEnforcementRecordV13, State, State2
from .cage_exec_transition_observed_v1_schema import ChioCageExecTransitionObservationV1, Digest, FileIdentity, Kind, RegularFileIdentity
from .cage_fully_enforced_evidence_v1_schema import ChioCageFullyEnforcedEvidenceV1
from .cage_init_plan_v2_schema import AbsoluteCanonicalPath, Access, AllowedSyscall, ArtifactEntry, BrokerPeerIdentity, ChioCageInitPlanV2, Digest, DirectoryIdentity, Environment, ExecutionIdentity, FdEntry, FdEntry1, FdEntry10, FdEntry2, FdEntry3, FdEntry4, FdEntry5, FdEntry6, FdEntry7, FdEntry8, FdEntry9, FdEntryBase, FdTable, FdTable1, FileIdentity, FilesystemGrant, ForbiddenResource, Kind, Kind5, Kind6, LandlockPlan, PathIdentity, Profile, Purpose, Purpose1, Purpose2, PurposeBrokerIpc, PurposeCageInitHelper, PurposeIndexedResource, PurposeTargetExecutable, PurposeTargetStderr, PurposeTargetStdin, PurposeTargetStdout, PurposeWorkingDirectory, RegularFileIdentity, ResourceLimits, SeccompPlan, SocketIdentity, StdioEntry, SupplementaryGid, SyscallArgumentConstraint, TargetArgv, TargetArgvItem
from .cage_process_exit_evidence_v1_schema import ChioCageProcessExitEvidenceV1, ChioCageProcessExitEvidenceV11, ChioCageProcessExitEvidenceV12, ExitCode, ExitCode1, ExitCode2, Signal, Signal2
from .cage_receipt_body_v1_schema import Bindings, ChioCageReceiptBodyV1, ChioCageReceiptBodyV11, ChioCageReceiptBodyV12, ChioCageReceiptBodyV13, ChioCageReceiptBodyV14, Digest, Identifier, Stage
from .cage_receipt_metadata_v1_schema import ChioCageReceiptMetadataV1
from .correlated_finding_receipt_body_v1_schema import ChioCorrelatedFindingReceiptBodyV1
from .correlated_finding_v1_schema import ChioCorrelatedFindingV1, Digest, DigestItem, Identifier, Identifiers, Time
from .declassification_consumption_receipt_body_v1_schema import ChioDeclassificationConsumptionReceiptBodyV1
from .declassification_grant_schema import Algorithm, Body, Digest32, Digest32Item, FlowIdentifier, SignedDeclassificationGrant, TargetLabel
from .declassification_outcome_receipt_body_v1_schema import ChioDeclassificationOutcomeReceiptBodyV1, ToState
from .detector_health_receipt_body_v1_schema import ChioDetectorHealthReceiptBodyV1, Digest, DigestItem, GroupBinding, GroupBinding1, GroupBinding2, Header, HealthKind, Identifier, Policy, Time, Watermark, Watermark1, Watermark2, Watermark3
from .effect_transition_receipt_body_v1_schema import ChioEffectTransitionReceiptBodyV1, Effect, Header, Kind, Outcome, Outcome1, Outcome2, Outcome3, Outcome4, Outcome5, Outcome6, Target, Target1, Target2, Target3, Target4
from .flow_denial_receipt_body_v1_schema import ChioFlowDenialReceiptBodyV1, Digest, DigestItem, Header, Identifier, Policy, Time
from .information_label_schema import FlowIdentifier, InformationLabel, InformationLabel1, InformationLabel2
from .key_log_activation_commit_body_v1_schema import ChioKeyLogActivationCommitBodyV1, Hash, KeyLogIdentifier
from .key_log_activation_commit_envelope_v1_schema import ChioSignedKeyLogActivationCommitEnvelopeV1, OperatorAlgorithm
from .key_log_artifact_time_anchor_body_v1_schema import Anchor, CheckpointAnchor, ChioKeyLogArtifactTimeAnchorBodyV1, ExternalAnchor, Hash, Identifier, Type, U64
from .key_log_artifact_time_anchor_envelope_v1_schema import Algorithm, ChioSignedKeyLogArtifactTimeAnchorV1, Hash, Signature
from .key_log_audit_readiness_body_v1_schema import ChioKeyLogAuditServiceReadinessBodyV1, Count, Hash, Identifier, KeyLogPin, Nonce, PositiveU64, WitnessView
from .key_log_audit_readiness_proof_v1_schema import Algorithm, ChioSignedKeyLogAuditServiceReadinessProofV1, Signature
from .key_log_checkpoint_body_v1_schema import ChioKeyLogCheckpointBodyV1, Hash
from .key_log_checkpoint_envelope_v1_schema import ChioSignedKeyLogCheckpointEnvelopeV1, OperatorAlgorithm, Signature
from .key_log_enterprise_receipt_body_v1_schema import ChioKeyLogEnterpriseReceiptBodyV1, ChioKeyLogEnterpriseReceiptBodyV11, ChioKeyLogEnterpriseReceiptBodyV12, EventSigner, EventSigner1, EventSigner2, EventSigner3, EventSigner4, Hash, KeyLogIdentifier, Outcome, Stage
from .key_log_enterprise_receipt_envelope_v1_schema import ChioSignedKeyLogEnterpriseReceiptEnvelopeV1, OperatorAlgorithm
from .key_log_event_body_v1_schema import Algorithm, ChioKeyLogEventBodyV1, Hash, KeyLogIdentifier, Operation, Operation10, Operation11, Operation12, Operation7, Operation8, Operation9, PublicKey
from .key_log_event_envelope_v1_schema import Algorithm, Authorizations, ChioSignedKeyLogEventEnvelopeV1, Hash, KeyAuthorization, KeyLogIdentifier, RecoveryAuthorization, Signature
from .key_log_sync_response_v1_schema import ChioKeyLogSynchronizationResponseV1, ConsistencyProof, Hash
from .key_log_witness_readiness_body_v1_schema import ChioKeyLogWitnessServiceReadinessBodyV1, Count, Hash, Identifier, KeyLogPin, Nonce, PositiveU64
from .key_log_witness_readiness_proof_v1_schema import Algorithm, ChioSignedKeyLogWitnessServiceReadinessProofV1, Signature
from .key_log_witness_signature_v1_schema import Algorithm, ChioKeyLogWitnessSignatureV1
from .keyring_artifact_signature_v1_schema import Algorithm, ChioKeyringArtifactSignatureEvidenceV1, Hash, Signature, U64
from .lift_rollback_completion_receipt_body_v1_schema import ChioLiftOrRollbackCompletionReceiptBodyV1, ChioLiftOrRollbackCompletionReceiptBodyV11, ChioLiftOrRollbackCompletionReceiptBodyV12, Effect, FinalState, Header, LiftOutcome, LiftOutcome1, LiftOutcome2, LiftOutcome3, LiftOutcome4, LiftOutcome5
from .mcp_cage_launch_policy_v2_schema import AbsoluteCanonicalPath, BrokerBinding, BrokerBinding1, BrokerBinding2, BrokerPeerIdentity, ChioSignedMcpCageLaunchPolicyV2, Digest, EnterpriseMigration, EnvironmentVariable, Identifier, Limits, MigrationKey, MinimumGeneration, MinimumHead, NativeSyscallProfile, NonzeroDigest32, NonzeroDigest32Item, OperatorCeilings, PolicyBody, PublicKey, ReceiptRuntime, Runtime, Signature, Stage, TargetArgvItem
from .response_completion_receipt_body_v1_schema import ChioResponseCompletionReceiptBodyV1, CompletionOutcome, CompletionOutcome1, CompletionOutcome2, CompletionOutcome3, DispatchApproval, DispatchApproval1, DispatchApproval2, Effect, ExecutionDispatch, FinalState, Header
from .response_effect_v1_schema import CanonicalContributionItem, ChioResponseEffectV1, Digest, DigestItem, Identifier, Kind, Target, Target5, Target6, Target7, Target8
from .response_plan_receipt_body_v1_schema import ChioResponsePlanReceiptBodyV1
from .response_plan_v1_schema import ApprovalRequirement, ApprovalRequirement1, ApprovalRequirement2, ChioResponsePlanV1, Digest, DigestItem, Identifier, OperatorCapability, Time
from .response_state_transition_receipt_body_v1_schema import Cause, ChioResponseStateTransitionReceiptBodyV1, Digest, DigestItem, Header, Header5, Identifier, Policy, Response, SchedulerFencingToken, State, Time
from .scheduler_health_receipt_body_v1_schema import ChioSchedulerHealthReceiptBodyV1
from .security_event_body_v1_schema import ChioSecurityEventBodyV1, EventKind, Identifier, Severity, Subject, Time, TrustClass
from .signed_security_event_envelope_v1_schema import Algorithm, ChioSignedSecurityEventProvenanceEnvelopeV1, PublicKey, Signature
from .signed_tool_manifest_v2_schema import ChioSignedToolManifestV2
from .tool_flow_declaration_schema import FlowIdentifier, KnownLabel, ToolFlowDeclaration
from .tool_manifest_v2_schema import ChioToolManifestV2, EnvironmentVariable, LatencyHint, MonetaryAmount, NativeSyscallProfile, NetworkDestination, PricingModel, ReadPath, RequiredPermissions, ServerTool, ToolAnnotations, ToolDefinition, ToolPricing, WritePath
from .tripwire_observation_receipt_body_v1_schema import ChioTripwireObservationReceiptBodyV1, Severity, TripwireKind

__all__ = [
    "AbsoluteCanonicalPath",
    "Access",
    "Action",
    "Algorithm",
    "AllowedSyscall",
    "Anchor",
    "ApprovalRequirement",
    "ApprovalRequirement1",
    "ApprovalRequirement2",
    "ArtifactEntry",
    "AttemptIds",
    "AuthorityExchange",
    "AuthorityRpcDigest",
    "AuthorityRpcIdentifier",
    "AuthorizationItem",
    "Authorizations",
    "AuthorizeHoldRequest",
    "Bindings",
    "Body",
    "BodyItem",
    "BrokerBinding",
    "BrokerBinding1",
    "BrokerBinding2",
    "BrokerPeerIdentity",
    "BrokerRevocationRequest",
    "Byte",
    "ByteArray",
    "ByteArrayItem",
    "CanonicalContributionItem",
    "Capabilities",
    "CapabilitiesOperation",
    "CapabilitiesResult",
    "CapabilityLivenessRequest",
    "CaptureCommit",
    "CaptureHoldRequest",
    "Cause",
    "ChallengeBody",
    "CheckBrokerRevocationOperation",
    "CheckpointAnchor",
    "ChioBrokerAdminControlReceiptBodyV1",
    "ChioBrokerAdminMutationReceiptBodyV1",
    "ChioBrokerAttemptRegistrationV1",
    "ChioBrokerAuditComparisonBodyV1",
    "ChioBrokerAuditRunnerAuthorizationBodyV1",
    "ChioBrokerAuthorityRpcRequestBodyV1",
    "ChioBrokerAuthorityRpcResponseBodyV1",
    "ChioBrokerCapabilityBodyV1",
    "ChioBrokerExecuteFailureV1",
    "ChioBrokerExecuteRequestV1",
    "ChioBrokerExecuteResponseV1",
    "ChioBrokerExecutionEvidenceV1",
    "ChioBrokerExecutionFailureReceiptBodyV1",
    "ChioBrokerExecutionReceiptBodyV1",
    "ChioBrokerPrepareDispatchAcknowledgementV1",
    "ChioBrokerPrivilegedAuditCommitRequestV1",
    "ChioBrokerPrivilegedAuditEvidenceBundleV1",
    "ChioBrokerPrivilegedAuditOpenRequestV1",
    "ChioBrokerRegisterAttemptAcknowledgementV1",
    "ChioBrokerRegisterAttemptAuthorizationBodyV1",
    "ChioBrokerReleaseAttemptAcknowledgementV1",
    "ChioBrokerRequestProofBodyV1",
    "ChioCageEnforcementFailureV1",
    "ChioCageEnforcementPreparedEvidenceV1",
    "ChioCageEnforcementRecordV1",
    "ChioCageEnforcementRecordV11",
    "ChioCageEnforcementRecordV12",
    "ChioCageEnforcementRecordV13",
    "ChioCageExecTransitionObservationV1",
    "ChioCageFullyEnforcedEvidenceV1",
    "ChioCageInitPlanV2",
    "ChioCageProcessExitEvidenceV1",
    "ChioCageProcessExitEvidenceV11",
    "ChioCageProcessExitEvidenceV12",
    "ChioCageReceiptBodyV1",
    "ChioCageReceiptBodyV11",
    "ChioCageReceiptBodyV12",
    "ChioCageReceiptBodyV13",
    "ChioCageReceiptBodyV14",
    "ChioCageReceiptMetadataV1",
    "ChioCorrelatedFindingReceiptBodyV1",
    "ChioCorrelatedFindingV1",
    "ChioDeclassificationConsumptionReceiptBodyV1",
    "ChioDeclassificationOutcomeReceiptBodyV1",
    "ChioDetectorHealthReceiptBodyV1",
    "ChioEffectTransitionReceiptBodyV1",
    "ChioFlowDenialReceiptBodyV1",
    "ChioKeyLogActivationCommitBodyV1",
    "ChioKeyLogArtifactTimeAnchorBodyV1",
    "ChioKeyLogAuditServiceReadinessBodyV1",
    "ChioKeyLogCheckpointBodyV1",
    "ChioKeyLogEnterpriseReceiptBodyV1",
    "ChioKeyLogEnterpriseReceiptBodyV11",
    "ChioKeyLogEnterpriseReceiptBodyV12",
    "ChioKeyLogEventBodyV1",
    "ChioKeyLogSynchronizationResponseV1",
    "ChioKeyLogWitnessServiceReadinessBodyV1",
    "ChioKeyLogWitnessSignatureV1",
    "ChioKeyringArtifactSignatureEvidenceV1",
    "ChioLiftOrRollbackCompletionReceiptBodyV1",
    "ChioLiftOrRollbackCompletionReceiptBodyV11",
    "ChioLiftOrRollbackCompletionReceiptBodyV12",
    "ChioResponseCompletionReceiptBodyV1",
    "ChioResponseEffectV1",
    "ChioResponsePlanReceiptBodyV1",
    "ChioResponsePlanV1",
    "ChioResponseStateTransitionReceiptBodyV1",
    "ChioSchedulerHealthReceiptBodyV1",
    "ChioSecurityEventBodyV1",
    "ChioSignedBrokerAdminControlReceiptV1",
    "ChioSignedBrokerAdminMutationReceiptV1",
    "ChioSignedBrokerAuditComparisonV1",
    "ChioSignedBrokerAuditRunnerAuthorizationV1",
    "ChioSignedBrokerAuthorityRpcRequestV1",
    "ChioSignedBrokerAuthorityRpcResponseV1",
    "ChioSignedBrokerCapabilityV1",
    "ChioSignedBrokerExecutionFailureReceiptV1",
    "ChioSignedBrokerExecutionReceiptV1",
    "ChioSignedBrokerPrivilegedAuditChallengeV1",
    "ChioSignedBrokerRegisterAttemptAuthorizationV1",
    "ChioSignedBrokerRequestProofV1",
    "ChioSignedKeyLogActivationCommitEnvelopeV1",
    "ChioSignedKeyLogArtifactTimeAnchorV1",
    "ChioSignedKeyLogAuditServiceReadinessProofV1",
    "ChioSignedKeyLogCheckpointEnvelopeV1",
    "ChioSignedKeyLogEnterpriseReceiptEnvelopeV1",
    "ChioSignedKeyLogEventEnvelopeV1",
    "ChioSignedKeyLogWitnessServiceReadinessProofV1",
    "ChioSignedMcpCageLaunchPolicyV2",
    "ChioSignedSecurityEventProvenanceEnvelopeV1",
    "ChioSignedToolManifestV2",
    "ChioToolManifestV2",
    "ChioTripwireObservationReceiptBodyV1",
    "Code",
    "CompletionOutcome",
    "CompletionOutcome1",
    "CompletionOutcome2",
    "CompletionOutcome3",
    "ConsistencyProof",
    "ControlOperation",
    "ControlRequest",
    "ControlResult",
    "Count",
    "CredentialRef",
    "Destination",
    "Digest",
    "Digest32",
    "Digest32Item",
    "DigestItem",
    "DigestOrNull",
    "DirectoryIdentity",
    "DispatchApproval",
    "DispatchApproval1",
    "DispatchApproval2",
    "DispatchKnowledge",
    "Disposition",
    "Effect",
    "EnterpriseMigration",
    "Environment",
    "EnvironmentVariable",
    "EventKind",
    "EventSigner",
    "EventSigner1",
    "EventSigner2",
    "EventSigner3",
    "EventSigner4",
    "ExecutionDispatch",
    "ExecutionIdentity",
    "ExitCode",
    "ExitCode1",
    "ExitCode2",
    "ExternalAnchor",
    "FdEntry",
    "FdEntry1",
    "FdEntry10",
    "FdEntry2",
    "FdEntry3",
    "FdEntry4",
    "FdEntry5",
    "FdEntry6",
    "FdEntry7",
    "FdEntry8",
    "FdEntry9",
    "FdEntryBase",
    "FdTable",
    "FdTable1",
    "FileIdentity",
    "FilesystemGrant",
    "FinalState",
    "FlowIdentifier",
    "ForbiddenResource",
    "GovernedAdminAuthorizationItem",
    "GroupBinding",
    "GroupBinding1",
    "GroupBinding2",
    "Hash",
    "Header",
    "Header5",
    "HeaderName",
    "HeaderNames",
    "HealthKind",
    "HoldOperation",
    "HoldOperation1",
    "HoldOperation2",
    "HoldOperation3",
    "HoldOperation4",
    "HoldResult",
    "HoldState",
    "HoldState1",
    "HoldState2",
    "Identifier",
    "IdentifierOrNull",
    "Identifiers",
    "InformationLabel",
    "InformationLabel1",
    "InformationLabel2",
    "KeyAuthorization",
    "KeyLogIdentifier",
    "KeyLogPin",
    "Kind",
    "Kind5",
    "Kind6",
    "KnownLabel",
    "LandlockPlan",
    "LatencyHint",
    "LiftOutcome",
    "LiftOutcome1",
    "LiftOutcome2",
    "LiftOutcome3",
    "LiftOutcome4",
    "LiftOutcome5",
    "Limits",
    "LiveParent",
    "LiveParentResult",
    "Method",
    "MigrationKey",
    "MinimumGeneration",
    "MinimumHead",
    "Mode",
    "MonetaryAmount",
    "NativeSyscallProfile",
    "NetworkDestination",
    "Nonce",
    "NonzeroDigest",
    "NonzeroDigest32",
    "NonzeroDigest32Item",
    "Operation",
    "Operation10",
    "Operation11",
    "Operation12",
    "Operation2",
    "Operation7",
    "Operation8",
    "Operation9",
    "OperatorAlgorithm",
    "OperatorCapability",
    "OperatorCeilings",
    "Options",
    "Outcome",
    "Outcome1",
    "Outcome2",
    "Outcome3",
    "Outcome4",
    "Outcome5",
    "Outcome6",
    "PathIdentity",
    "PayloadItem",
    "Policy",
    "PolicyBody",
    "PositiveU64",
    "PrepareExecutionOperation",
    "PreparedResult",
    "PricingModel",
    "Profile",
    "ProofBinding",
    "PublicKey",
    "Purpose",
    "Purpose1",
    "Purpose2",
    "PurposeBrokerIpc",
    "PurposeCageInitHelper",
    "PurposeIndexedResource",
    "PurposeTargetExecutable",
    "PurposeTargetStderr",
    "PurposeTargetStdin",
    "PurposeTargetStdout",
    "PurposeWorkingDirectory",
    "QueryHoldRequest",
    "Quota",
    "ReadPath",
    "ReceiptRuntime",
    "RecoveryAuthorization",
    "RegularFileIdentity",
    "RejectedResult",
    "Request",
    "RequestConstraints",
    "RequiredPermissions",
    "ResourceLimits",
    "Response",
    "ResponseItem",
    "Result",
    "ReverseHoldRequest",
    "RevocationResult",
    "RevocationSnapshot",
    "Runtime",
    "SchedulerFencingToken",
    "Scheme",
    "SeccompPlan",
    "ServerTool",
    "Severity",
    "Signal",
    "Signal2",
    "Signature",
    "SignedDeclassificationGrant",
    "SocketIdentity",
    "Stage",
    "State",
    "State2",
    "StdioEntry",
    "Subject",
    "SupplementaryGid",
    "SyscallArgumentConstraint",
    "Target",
    "Target1",
    "Target2",
    "Target3",
    "Target4",
    "Target5",
    "Target6",
    "Target7",
    "Target8",
    "TargetArgv",
    "TargetArgvItem",
    "TargetLabel",
    "Time",
    "ToState",
    "ToolAnnotations",
    "ToolDefinition",
    "ToolFlowDeclaration",
    "ToolPricing",
    "TripwireKind",
    "TrustClass",
    "TrustedExecutionContext",
    "Type",
    "U32",
    "U64",
    "ValueItem",
    "VerifyLiveParentOperation",
    "Watermark",
    "Watermark1",
    "Watermark2",
    "Watermark3",
    "WitnessView",
    "WritePath",
]
