# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .action_intent_schema import OpaqueId, Origin, RecoveryDigest32, RecoveryDigest32Item, RecoveryExactActionIntentV1, SafeInteger, Scope
from .approval_intent_schema import Obligations, Obligations1, Obligations2, Obligations3, OpaqueId, RecoveryApprovalIntentV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .approval_submission_schema import OpaqueId, RecoveryApprovalSubmissionV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .artifact_archive_manifest_schema import ArtifactArchiveManifestV1, ArtifactReference, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Scope
from .artifact_certificate_schema import ArtifactCertificateV1, ArtifactInfluence, ArtifactProducer, ArtifactProducer1, ArtifactProducer2, ArtifactProducer3, ArtifactProducer4, ArtifactProducer5, ArtifactReference, Kind, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .artifact_handle_schema import ArtifactHandleV1, OpaqueId
from .artifact_influence_schema import ArtifactInfluenceV1, RecoveryDigest32, RecoveryDigest32Item
from .artifact_producer_schema import ArtifactProducerV1, ArtifactProducerV11, ArtifactProducerV12, ArtifactProducerV13, ArtifactProducerV14, ArtifactProducerV15, ArtifactReference, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Scope
from .artifact_recipient_schema import ArtifactRecipientV1, ArtifactReference, ArtifactSink, ArtifactSink1, ArtifactSink2, ArtifactSink3, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .artifact_reference_schema import ArtifactReferenceV1, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Scope
from .artifact_release_intent_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactReleaseIntentV1, ArtifactSink, ArtifactSink4, ArtifactSink5, ArtifactSink6, Kind, Kind2, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, State
from .artifact_version_schema import ArtifactInfluence, ArtifactProducer, ArtifactProducer10, ArtifactProducer6, ArtifactProducer7, ArtifactProducer8, ArtifactProducer9, ArtifactReference, ArtifactVersionV1, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Retention, Scope
from .authority_coverage_schema import Obligations, Obligations5, Obligations6, Obligations7, OpaqueId, RecoveryAuthorityCoverageBodyV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .authorization_requirements_schema import AttachmentProfile, Obligations, Obligations10, Obligations11, Obligations9, OpaqueId, RecoveryAuthorizationRequirementsV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .command_response_schema import Control, OpaqueId, Operation, RecoveryCommandResponseV1, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RefusalCode, Release, Release1, Release2, Release3, Release4, SafeInteger, Scope
from .command_result_schema import OpaqueId, Operation, OriginalResponse, RecoveryCommandResultV1, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RefusalCode, SafeInteger, Scope
from .command_schema import Command, Command1, Command2, Command3, Command4, Command5, Command6, Decision, OpaqueId, RecoveryCommandV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, Template
from .confined_execution_profile_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink7, ArtifactSink8, ArtifactSink9, ConfinedExecutionProfileV1, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .confined_limits_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink10, ArtifactSink11, ArtifactSink12, ConfinedLimitsV1, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .confined_return_evidence_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink13, ArtifactSink14, ArtifactSink15, ConfinedReturnEvidenceV1, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .decision_report_schema import Decision, DecisionReportV1, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .decision_report_view_schema import DecisionReportViewV1, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .dependency_graph_schema import Node, RecoveryDependencyGraphV1
from .disclosure_grant_schema import DisclosureGrant, DisclosureGrant1
from .effect_contract_schema import LookupFinality, SemanticEffectContractV1
from .explanation_evaluation_schema import Assessment, Candidate, DestinationId, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryExplanationEvaluationV1, RefusalCode, SafeInteger, Scope
from .explanation_report_schema import DestinationId, Limits, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryExplanationReportV1, RefusalCode, SafeInteger, Scope
from .explanation_request_schema import DestinationId, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryExplanationRequestV1, RefusalCode, SafeInteger, Scope
from .explanation_snapshot_schema import DestinationId, Fact, Influence, Influence1, Integrity, Observation, OpaqueId, Operation, Reason, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryExplanationSnapshotV1, RefusalCode, SafeInteger, Scope, Source, State, State6, State8, Target, Target11, Target12, Target13
from .explanation_view_schema import Assessment, Candidate, DestinationId, OpaqueId, Operation, Projection, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryExplanationViewV1, RefusalCode, SafeInteger, Scope, Summary
from .grant_binding_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, RecoveryMandatoryGrantBindingV1, SafeInteger, Scope
from .isolation_boundary_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink16, ArtifactSink17, ArtifactSink18, IsolationBoundaryV1, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .labeled_checkpoint_schema import ArtifactInfluence, ArtifactReference, LabeledCheckpointV1, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Scope
from .model_context_schema import ArtifactReference, ModelContextV1, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, Scope
from .observation_schema import Control, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryObservationV1, RefusalCode, Release, Release6, Release7, Release8, Release9, SafeInteger, Scope
from .policy_deployment_change_schema import OpaqueId, PolicyDeploymentChangeV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .policy_maintenance_proposal_schema import OpaqueId, PolicyMaintenanceProposalV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .policy_maintenance_view_schema import OpaqueId, PolicyMaintenanceViewV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .policy_trajectory_ref_schema import OpaqueId, PolicyTrajectoryRefV1, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope
from .profile_requirements_schema import AttachmentProfile, RecoveryProfileRequirementsV1, RequiredFeature
from .provider_finality_schema import Disposition, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, RecoveryProviderPositiveFinalityV1, SafeInteger, Scope
from .recovery_grant_body_schema import ChioRecoveryGrantV1SignedBody, Claims, Owners, Recovery, TargetLabel
from .recovery_setup_probe_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, RecoverySetupProbeV1, SafeInteger, Scope
from .recovery_setup_report_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, RecoverySetupReportV1, SafeInteger, Scope
from .recovery_signed_confined_disclosure_body_schema import Artifact, ChioRecoverySignedConfinedDisclosureV1SignedBody, Clearance, Compartment, Influence, Observation, Parent, Scope, Sink, Source, Target
from .recovery_signed_confined_endorsement_body_schema import Artifact, ChioRecoverySignedConfinedEndorsementV1SignedBody, Clearance, Compartment, Influence, Observation, Parent, Scope, Sink, Source, Target
from .recovery_signed_policy_deployment_change_body_schema import ChioRecoverySignedPolicyDeploymentChangeV1SignedBody, Scope
from .remedy_registry_schema import Cost, DestinationId, Kind, Latency, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryRemedyRegistryV1, RefusalCode, SafeInteger, Scope, Template
from .return_admission_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink19, ArtifactSink20, ArtifactSink21, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, ReturnAdmissionV1, SafeInteger, Scope
from .return_contract_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink22, ArtifactSink23, ArtifactSink24, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, ReturnContractV1, SafeInteger, Scope
from .review_document_schema import OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryReviewDocumentV1, RefusalCode, SafeInteger, Scope
from .review_request_schema import OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryReviewRequestV1, RefusalCode, SafeInteger, Scope
from .scoped_endorsement_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, ScopedEndorsementV1, Target, Target28
from .semantic_action_schema import OpaqueId, Output, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticActionV1, SemanticInputVersion, SemanticNativeSource
from .semantic_annotation_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticAnnotationV1, SemanticInputVersion
from .semantic_audience_schema import Completeness, Cursor, OpaqueId, Pagination, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticAudienceV1
from .semantic_deployment_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticAnnotator, SemanticDeploymentV1, SemanticDestination, SemanticOverride, SemanticRoute, SemanticSelector, SemanticSelector1, SemanticSelector2, SemanticSelector3, SemanticValue, SemanticValue1, SemanticValue2, SemanticValue3
from .semantic_invocation_schema import SemanticInvocationV1
from .semantic_package_schema import Channel, Kind, Kind14, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, SemanticChannel, SemanticOperation, SemanticPackageV1, SemanticPrerequisiteRequirement, SemanticSelector, SemanticSelector4, SemanticSelector5, SemanticSelector6, SemanticValue, SemanticValue4, SemanticValue5, SemanticValue6, SemanticWithheldStatus
from .semantic_payload_schema import OpaqueId, SafeInteger, SemanticField, SemanticPayloadV1, SemanticValue, SemanticValue7, SemanticValue8, SemanticValue9
from .semantic_plan_schema import OpaqueId, Output, RecoveryDigest32, RecoveryDigest32Item, Scope, SemanticPlanInput, SemanticPlanInput1, SemanticPlanInput2, SemanticPlanStep, SemanticPlanV1
from .semantic_prerequisite_schema import Kind, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticPrerequisiteV1
from .semantic_provider_request_schema import Kind, OpaqueId, SemanticProviderRequestV1
from .semantic_provider_response_schema import OpaqueId, SemanticProviderResponseV1
from .semantic_transformation_schema import Disposition, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SemanticInputVersion, SemanticTransformationV1
from .signed_artifact_archive_manifest_schema import SignedArtifactArchiveManifestV1
from .signed_artifact_certificate_schema import SignedArtifactCertificateV1
from .signed_authority_coverage_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedRecoveryAuthorityCoverageV1
from .signed_confined_disclosure_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink25, ArtifactSink26, ArtifactSink27, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedConfinedDisclosureV1
from .signed_confined_endorsement_schema import ArtifactInfluence, ArtifactRecipient, ArtifactReference, ArtifactSink, ArtifactSink28, ArtifactSink29, ArtifactSink30, ModelContext, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedConfinedEndorsementV1
from .signed_explanation_report_schema import DestinationId, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoverySignedExplanationReportV1, RefusalCode, SafeInteger, Scope
from .signed_explanation_view_schema import DestinationId, OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoverySignedExplanationViewV1, RefusalCode, SafeInteger, Scope
from .signed_policy_deployment_change_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedPolicyDeploymentChangeV1
from .signed_provider_finality_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedRecoveryProviderFinalityV1
from .signed_recovery_grant_schema import Body, OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedRecoveryGrant
from .signed_recovery_setup_probe_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedRecoverySetupProbeV1
from .signed_recovery_setup_report_schema import OpaqueId, RecoveryDigest32, RecoveryDigest32Item, SafeInteger, Scope, SignedRecoverySetupReportV1
from .signed_scoped_endorsement_schema import SignedScopedEndorsementV1
from .signed_semantic_annotation_schema import SignedSemanticAnnotationV1
from .signed_semantic_audience_schema import SignedSemanticAudienceV1
from .signed_semantic_deployment_schema import SignedSemanticDeploymentV1
from .signed_semantic_package_schema import SignedSemanticPackageV1
from .signed_semantic_prerequisite_schema import SignedSemanticPrerequisiteV1
from .signed_semantic_transformation_schema import SignedSemanticTransformationV1
from .support_issue_effect_schema import OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoverySupportIssueEffectContractV1, RefusalCode, SafeInteger, Scope
from .support_issue_input_schema import OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoverySupportIssueInputV1, RefusalCode, SafeInteger, Scope
from .trajectory_schema import Expected, Frame, RecoveryTrajectoryV1
from .transport_request_schema import OpaqueId, Operation, RecoveryDigest32, RecoveryDigest32Item, RecoveryEffectAdmissionUnresolvedV1, RecoveryEffectAwaitingApprovalV1, RecoveryEffectAwaitingCallerReportV1, RecoveryEffectClosedBeforeEffectV1, RecoveryEffectCompleteV1, RecoveryEffectFailedAfterEffectV1, RecoveryEffectInFlightV1, RecoveryEffectNeverAdmittedV1, RecoveryEffectPartialV1, RecoveryEffectUnknownV1, RecoveryTransportRequestV1, RefusalCode, SafeInteger, Scope

__all__ = [
    "Artifact",
    "ArtifactArchiveManifestV1",
    "ArtifactCertificateV1",
    "ArtifactHandleV1",
    "ArtifactInfluence",
    "ArtifactInfluenceV1",
    "ArtifactProducer",
    "ArtifactProducer1",
    "ArtifactProducer10",
    "ArtifactProducer2",
    "ArtifactProducer3",
    "ArtifactProducer4",
    "ArtifactProducer5",
    "ArtifactProducer6",
    "ArtifactProducer7",
    "ArtifactProducer8",
    "ArtifactProducer9",
    "ArtifactProducerV1",
    "ArtifactProducerV11",
    "ArtifactProducerV12",
    "ArtifactProducerV13",
    "ArtifactProducerV14",
    "ArtifactProducerV15",
    "ArtifactRecipient",
    "ArtifactRecipientV1",
    "ArtifactReference",
    "ArtifactReferenceV1",
    "ArtifactReleaseIntentV1",
    "ArtifactSink",
    "ArtifactSink1",
    "ArtifactSink10",
    "ArtifactSink11",
    "ArtifactSink12",
    "ArtifactSink13",
    "ArtifactSink14",
    "ArtifactSink15",
    "ArtifactSink16",
    "ArtifactSink17",
    "ArtifactSink18",
    "ArtifactSink19",
    "ArtifactSink2",
    "ArtifactSink20",
    "ArtifactSink21",
    "ArtifactSink22",
    "ArtifactSink23",
    "ArtifactSink24",
    "ArtifactSink25",
    "ArtifactSink26",
    "ArtifactSink27",
    "ArtifactSink28",
    "ArtifactSink29",
    "ArtifactSink3",
    "ArtifactSink30",
    "ArtifactSink4",
    "ArtifactSink5",
    "ArtifactSink6",
    "ArtifactSink7",
    "ArtifactSink8",
    "ArtifactSink9",
    "ArtifactVersionV1",
    "Assessment",
    "AttachmentProfile",
    "Body",
    "Candidate",
    "Channel",
    "ChioRecoveryGrantV1SignedBody",
    "ChioRecoverySignedConfinedDisclosureV1SignedBody",
    "ChioRecoverySignedConfinedEndorsementV1SignedBody",
    "ChioRecoverySignedPolicyDeploymentChangeV1SignedBody",
    "Claims",
    "Clearance",
    "Command",
    "Command1",
    "Command2",
    "Command3",
    "Command4",
    "Command5",
    "Command6",
    "Compartment",
    "Completeness",
    "ConfinedExecutionProfileV1",
    "ConfinedLimitsV1",
    "ConfinedReturnEvidenceV1",
    "Control",
    "Cost",
    "Cursor",
    "Decision",
    "DecisionReportV1",
    "DecisionReportViewV1",
    "DestinationId",
    "DisclosureGrant",
    "DisclosureGrant1",
    "Disposition",
    "Expected",
    "Fact",
    "Frame",
    "Influence",
    "Influence1",
    "Integrity",
    "IsolationBoundaryV1",
    "Kind",
    "Kind14",
    "Kind2",
    "LabeledCheckpointV1",
    "Latency",
    "Limits",
    "LookupFinality",
    "ModelContext",
    "ModelContextV1",
    "Node",
    "Obligations",
    "Obligations1",
    "Obligations10",
    "Obligations11",
    "Obligations2",
    "Obligations3",
    "Obligations5",
    "Obligations6",
    "Obligations7",
    "Obligations9",
    "Observation",
    "OpaqueId",
    "Operation",
    "Origin",
    "OriginalResponse",
    "Output",
    "Owners",
    "Pagination",
    "Parent",
    "PolicyDeploymentChangeV1",
    "PolicyMaintenanceProposalV1",
    "PolicyMaintenanceViewV1",
    "PolicyTrajectoryRefV1",
    "Projection",
    "Reason",
    "Recovery",
    "RecoveryApprovalIntentV1",
    "RecoveryApprovalSubmissionV1",
    "RecoveryAuthorityCoverageBodyV1",
    "RecoveryAuthorizationRequirementsV1",
    "RecoveryCommandResponseV1",
    "RecoveryCommandResultV1",
    "RecoveryCommandV1",
    "RecoveryDependencyGraphV1",
    "RecoveryDigest32",
    "RecoveryDigest32Item",
    "RecoveryEffectAdmissionUnresolvedV1",
    "RecoveryEffectAwaitingApprovalV1",
    "RecoveryEffectAwaitingCallerReportV1",
    "RecoveryEffectClosedBeforeEffectV1",
    "RecoveryEffectCompleteV1",
    "RecoveryEffectFailedAfterEffectV1",
    "RecoveryEffectInFlightV1",
    "RecoveryEffectNeverAdmittedV1",
    "RecoveryEffectPartialV1",
    "RecoveryEffectUnknownV1",
    "RecoveryExactActionIntentV1",
    "RecoveryExplanationEvaluationV1",
    "RecoveryExplanationReportV1",
    "RecoveryExplanationRequestV1",
    "RecoveryExplanationSnapshotV1",
    "RecoveryExplanationViewV1",
    "RecoveryMandatoryGrantBindingV1",
    "RecoveryObservationV1",
    "RecoveryProfileRequirementsV1",
    "RecoveryProviderPositiveFinalityV1",
    "RecoveryRemedyRegistryV1",
    "RecoveryReviewDocumentV1",
    "RecoveryReviewRequestV1",
    "RecoverySetupProbeV1",
    "RecoverySetupReportV1",
    "RecoverySignedExplanationReportV1",
    "RecoverySignedExplanationViewV1",
    "RecoverySupportIssueEffectContractV1",
    "RecoverySupportIssueInputV1",
    "RecoveryTrajectoryV1",
    "RecoveryTransportRequestV1",
    "RefusalCode",
    "Release",
    "Release1",
    "Release2",
    "Release3",
    "Release4",
    "Release6",
    "Release7",
    "Release8",
    "Release9",
    "RequiredFeature",
    "Retention",
    "ReturnAdmissionV1",
    "ReturnContractV1",
    "SafeInteger",
    "Scope",
    "ScopedEndorsementV1",
    "SemanticActionV1",
    "SemanticAnnotationV1",
    "SemanticAnnotator",
    "SemanticAudienceV1",
    "SemanticChannel",
    "SemanticDeploymentV1",
    "SemanticDestination",
    "SemanticEffectContractV1",
    "SemanticField",
    "SemanticInputVersion",
    "SemanticInvocationV1",
    "SemanticNativeSource",
    "SemanticOperation",
    "SemanticOverride",
    "SemanticPackageV1",
    "SemanticPayloadV1",
    "SemanticPlanInput",
    "SemanticPlanInput1",
    "SemanticPlanInput2",
    "SemanticPlanStep",
    "SemanticPlanV1",
    "SemanticPrerequisiteRequirement",
    "SemanticPrerequisiteV1",
    "SemanticProviderRequestV1",
    "SemanticProviderResponseV1",
    "SemanticRoute",
    "SemanticSelector",
    "SemanticSelector1",
    "SemanticSelector2",
    "SemanticSelector3",
    "SemanticSelector4",
    "SemanticSelector5",
    "SemanticSelector6",
    "SemanticTransformationV1",
    "SemanticValue",
    "SemanticValue1",
    "SemanticValue2",
    "SemanticValue3",
    "SemanticValue4",
    "SemanticValue5",
    "SemanticValue6",
    "SemanticValue7",
    "SemanticValue8",
    "SemanticValue9",
    "SemanticWithheldStatus",
    "SignedArtifactArchiveManifestV1",
    "SignedArtifactCertificateV1",
    "SignedConfinedDisclosureV1",
    "SignedConfinedEndorsementV1",
    "SignedPolicyDeploymentChangeV1",
    "SignedRecoveryAuthorityCoverageV1",
    "SignedRecoveryGrant",
    "SignedRecoveryProviderFinalityV1",
    "SignedRecoverySetupProbeV1",
    "SignedRecoverySetupReportV1",
    "SignedScopedEndorsementV1",
    "SignedSemanticAnnotationV1",
    "SignedSemanticAudienceV1",
    "SignedSemanticDeploymentV1",
    "SignedSemanticPackageV1",
    "SignedSemanticPrerequisiteV1",
    "SignedSemanticTransformationV1",
    "Sink",
    "Source",
    "State",
    "State6",
    "State8",
    "Summary",
    "Target",
    "Target11",
    "Target12",
    "Target13",
    "Target28",
    "TargetLabel",
    "Template",
]
