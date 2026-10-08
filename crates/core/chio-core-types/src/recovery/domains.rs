//! Closed canonical digest meanings. Every retained preimage stays exact.
use crate::canonical::CanonicalBytes;
use chio_security_types::ports::Digest32;
use sha2::{Digest, Sha256};

// Named string declarations remain visible to the wire identifier inventory.
const ACTION_INTENT_DOMAIN: &str = "chio.recovery.action-intent.v1";
const OFFER_DOMAIN: &str = "chio.recovery.offer.v1";
const PLAN_DOMAIN: &str = "chio.recovery.plan.v1";
const BASIS_DOMAIN: &str = "chio.recovery.basis.v1";
const EXPLANATION_DOMAIN: &str = "chio.recovery.explanation.v1";
const AUTHORIZATION_REQUIREMENTS_DOMAIN: &str = "chio.recovery.authorization-requirements.v1";
const SEMANTIC_DEPLOYMENT_DOMAIN: &str = "chio.semantic.deployment.v1";
const ARTIFACT_PROVENANCE_DOMAIN: &str = "chio.artifact.provenance.v1";
const RETURN_CONTRACT_DOMAIN: &str = "chio.isolation.return-contract.v1";
const EXPLANATION_SNAPSHOT_DOMAIN: &str = "chio.recovery.explanation-snapshot.v1";
const REMEDY_REGISTRY_DOMAIN: &str = "chio.recovery.remedy-registry.v1";
const EXPLANATION_EVALUATION_DOMAIN: &str = "chio.recovery.explanation-evaluation.v1";
const EXPLANATION_PROJECTION_DOMAIN: &str = "chio.recovery.explanation-projection.v1";
const CAPABILITY_BODY_DOMAIN: &str = "chio.recovery.capability-body.v1";
const OUTPUT_DISPOSITION_DOMAIN: &str = "chio.recovery.output-disposition.v1";
const DEPLOYMENT_DOMAIN: &str = "chio.recovery.deployment.v1";
const COMMAND_DOMAIN: &str = "chio.recovery.command.v1";
const SOURCE_DOMAIN: &str = "chio.recovery.source.v1";
const INFLUENCE_DOMAIN: &str = "chio.recovery.influence.v1";
const SERVING_FENCE_DOMAIN: &str = "chio.recovery.serving-fence.v1";
const PROVIDER_RESOURCE_DOMAIN: &str = "chio.recovery.provider-resource.v1";
const STORE_EVENT_DOMAIN: &str = "chio.recovery.store-event.v1";
const PROTECTED_RECORD_DOMAIN: &str = "chio.recovery.protected-record.v1";
const SEMANTIC_POLICY_DOMAIN: &str = "chio.recovery.semantic-policy.v1";
const AUTHORITY_SCOPE_DOMAIN: &str = "chio.recovery.authority-scope.v1";
const AUTHORITY_COVERAGE_DOMAIN: &str = "chio.recovery.authority-coverage.v1";
const ORIGIN_CLAIM_DOMAIN: &str = "chio.recovery.origin-claim.v1";
const PLANNING_OWNER_DOMAIN: &str = "chio.recovery.planning-owner.v1";
const ACTIVE_WORKFLOW_OWNER_DOMAIN: &str = "chio.recovery.active-owner.v1";
const PLANNING_RESERVATION_DOMAIN: &str = "chio.recovery.planning-reservation.v1";
const WORKFLOW_RESERVATION_DOMAIN: &str = "chio.recovery.workflow-reservation.v1";
const EFFECT_CONTRACT_DOMAIN: &str = "chio.recovery.effect-contract.v1";
const PREVIEW_DOMAIN: &str = "chio.recovery.preview.v1";
const SETUP_CREATION_LEGACY_DOMAIN: &str = "chio.recovery.setup.creation.v1";
const SETUP_CREATION_DOMAIN: &str = "chio.recovery.setup.creation.v2";
const SETUP_SOURCE_PROFILE_DOMAIN: &str = "chio.recovery.setup.source-profile.v2";
const SETUP_SOURCE_PROFILE_LEGACY_DOMAIN: &str = "chio.recovery.setup.source-profile.v1";
const SETUP_RETIREMENT_DOMAIN: &str = "chio.recovery.setup.retirement.v1";
const SETUP_BENIGN_RECEIPT_DOMAIN: &str = "chio.recovery.setup.benign-receipt.v1";
const SETUP_DENIED_COMMAND_DOMAIN: &str = "chio.recovery.setup.denied-command.v1";
const SETUP_NATIVE_AUTHORITY_DOMAIN: &str = "chio.recovery.setup.native-authority.v1";
const SETUP_REQUIRED_COVERAGE_DOMAIN: &str = "chio.recovery.setup.required-coverage.v1";
const DECISION_REPORT_DOMAIN: &str = "chio.recovery.decision-report.v1";
const POLICY_MAINTENANCE_PROPOSAL_DOMAIN: &str = "chio.recovery.policy-maintenance-proposal.v1";
const SEMANTIC_PACKAGE_DOMAIN: &str = "chio.semantic.package.v1";
const SEMANTIC_REGISTRY_DOMAIN: &str = "chio.semantic.registry.v1";
const SEMANTIC_ACTION_DOMAIN: &str = "chio.semantic.action.v1";
const SEMANTIC_PLAN_DOMAIN: &str = "chio.semantic.plan.v1";
const SEMANTIC_CONTENT_DOMAIN: &str = "chio.semantic.content.v1";
const SEMANTIC_ROLE_KEY_DOMAIN: &str = "chio.semantic.role-key.v1";
const SEMANTIC_NATIVE_REQUEST_SEMANTICS_DOMAIN: &str = "chio.semantic.native-request-semantics.v1";
const SEMANTIC_NATIVE_OUTPUT_ORIGIN_DOMAIN: &str = "chio.semantic.native-output-origin.v1";
const CONFINED_CAPABILITY_DOMAIN: &str = "chio.confined.capability.v1";
const ISOLATION_BOUNDARY_DOMAIN: &str = "chio.isolation.boundary.v1";
const CONFINED_EVIDENCE_BINDING_DOMAIN: &str = "chio.confined.evidence-binding.v1";
const CONFINED_PARENT_CONTROL_DOMAIN: &str = "chio.confined.parent-control.v1";
const CONFINED_LAUNCH_DOMAIN: &str = "chio.confined.launch.v1";
const KNOWLEDGE_OBSERVED_INFLUENCE_DOMAIN: &str = "chio.knowledge.observed-influence.v1";
const KNOWLEDGE_INFLUENCE_DOMAIN: &str = "chio.knowledge.influence.v1";
const KNOWLEDGE_IMPORT_INFLUENCE_DOMAIN: &str = "chio.knowledge.import-influence.v1";
const KNOWLEDGE_READ_AUTHORITY_DOMAIN: &str = "chio.knowledge.read-authority.v1";
const KNOWLEDGE_SEMANTIC_INFLUENCE_DOMAIN: &str = "chio.knowledge.semantic-influence.v1";
const KNOWLEDGE_INFLUENCE_SCOPE_DOMAIN: &str = "chio.knowledge.influence-scope.v1";
const KNOWLEDGE_INFLUENCE_FOLD_DOMAIN: &str = "chio.knowledge.influence-fold.v1";
const KNOWLEDGE_HANDLE_IDENTITY_DOMAIN: &str = "chio.knowledge.handle-identity.v1";
const KNOWLEDGE_ACTOR_IDENTITY_DOMAIN: &str = "chio.knowledge.actor-identity.v1";
const KNOWLEDGE_REFERENCE_IDENTITY_DOMAIN: &str = "chio.knowledge.reference-identity.v1";
const KNOWLEDGE_REFERENCE_OWNER_DOMAIN: &str = "chio.knowledge.reference-owner.v1";
const KNOWLEDGE_OBJECT_CUSTODY_DOMAIN: &str = "chio.knowledge.object-custody.v1";
const ARTIFACT_ARCHIVE_DOMAIN: &str = "chio.artifact.archive.v1";
const PARTICIPANT_OWNER_DOMAIN: &str = "chio.participant.owner.v1";
const SEMANTIC_NATIVE_STATUS_ORIGIN_DOMAIN: &str = "chio.semantic.native-status-origin.v1";
const SEMANTIC_NATIVE_INPUT_ORIGIN_DOMAIN: &str = "chio.semantic.native-input-origin.v1";

// Framing and identity are declared together; tests check their byte equality.
macro_rules! registered_domains {
    ($($variant:ident = $name:ident => $literal:literal),+ $(,)?) => {
        /// Canonical content identity never establishes execution authority.
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum RecoveryDigestDomain { $($variant),+ }

        pub const RECOVERY_DIGEST_DOMAINS: [RecoveryDigestDomain;
            [$(stringify!($variant)),+].len()] = [$(RecoveryDigestDomain::$variant),+];

        impl RecoveryDigestDomain {
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
            pub const fn prefix(self) -> &'static [u8] {
                match self { $(Self::$variant => concat!($literal, "\0").as_bytes()),+ }
            }
        }
    };
}

registered_domains! {
    ActionIntent = ACTION_INTENT_DOMAIN => "chio.recovery.action-intent.v1",
    Offer = OFFER_DOMAIN => "chio.recovery.offer.v1",
    Plan = PLAN_DOMAIN => "chio.recovery.plan.v1",
    Basis = BASIS_DOMAIN => "chio.recovery.basis.v1",
    Explanation = EXPLANATION_DOMAIN => "chio.recovery.explanation.v1",
    AuthorizationRequirements = AUTHORIZATION_REQUIREMENTS_DOMAIN => "chio.recovery.authorization-requirements.v1",
    SemanticDeployment = SEMANTIC_DEPLOYMENT_DOMAIN => "chio.semantic.deployment.v1",
    ArtifactProvenance = ARTIFACT_PROVENANCE_DOMAIN => "chio.artifact.provenance.v1",
    ReturnContract = RETURN_CONTRACT_DOMAIN => "chio.isolation.return-contract.v1",
    ExplanationSnapshot = EXPLANATION_SNAPSHOT_DOMAIN => "chio.recovery.explanation-snapshot.v1",
    RemedyRegistry = REMEDY_REGISTRY_DOMAIN => "chio.recovery.remedy-registry.v1",
    ExplanationEvaluation = EXPLANATION_EVALUATION_DOMAIN => "chio.recovery.explanation-evaluation.v1",
    ExplanationProjection = EXPLANATION_PROJECTION_DOMAIN => "chio.recovery.explanation-projection.v1",
    CapabilityBody = CAPABILITY_BODY_DOMAIN => "chio.recovery.capability-body.v1",
    OutputDisposition = OUTPUT_DISPOSITION_DOMAIN => "chio.recovery.output-disposition.v1",
    Deployment = DEPLOYMENT_DOMAIN => "chio.recovery.deployment.v1",
    Command = COMMAND_DOMAIN => "chio.recovery.command.v1",
    Source = SOURCE_DOMAIN => "chio.recovery.source.v1",
    Influence = INFLUENCE_DOMAIN => "chio.recovery.influence.v1",
    ServingFence = SERVING_FENCE_DOMAIN => "chio.recovery.serving-fence.v1",
    ProviderResource = PROVIDER_RESOURCE_DOMAIN => "chio.recovery.provider-resource.v1",
    StoreEvent = STORE_EVENT_DOMAIN => "chio.recovery.store-event.v1",
    ProtectedRecord = PROTECTED_RECORD_DOMAIN => "chio.recovery.protected-record.v1",
    SemanticPolicy = SEMANTIC_POLICY_DOMAIN => "chio.recovery.semantic-policy.v1",
    AuthorityScope = AUTHORITY_SCOPE_DOMAIN => "chio.recovery.authority-scope.v1",
    AuthorityCoverage = AUTHORITY_COVERAGE_DOMAIN => "chio.recovery.authority-coverage.v1",
    OriginClaim = ORIGIN_CLAIM_DOMAIN => "chio.recovery.origin-claim.v1",
    PlanningOwner = PLANNING_OWNER_DOMAIN => "chio.recovery.planning-owner.v1",
    ActiveWorkflowOwner = ACTIVE_WORKFLOW_OWNER_DOMAIN => "chio.recovery.active-owner.v1",
    PlanningReservation = PLANNING_RESERVATION_DOMAIN => "chio.recovery.planning-reservation.v1",
    WorkflowReservation = WORKFLOW_RESERVATION_DOMAIN => "chio.recovery.workflow-reservation.v1",
    EffectContract = EFFECT_CONTRACT_DOMAIN => "chio.recovery.effect-contract.v1",
    Preview = PREVIEW_DOMAIN => "chio.recovery.preview.v1",
    SetupCreationLegacy = SETUP_CREATION_LEGACY_DOMAIN => "chio.recovery.setup.creation.v1",
    SetupCreation = SETUP_CREATION_DOMAIN => "chio.recovery.setup.creation.v2",
    SetupSourceProfile = SETUP_SOURCE_PROFILE_DOMAIN => "chio.recovery.setup.source-profile.v2",
    SetupSourceProfileLegacy = SETUP_SOURCE_PROFILE_LEGACY_DOMAIN => "chio.recovery.setup.source-profile.v1",
    SetupRetirement = SETUP_RETIREMENT_DOMAIN => "chio.recovery.setup.retirement.v1",
    SetupBenignReceipt = SETUP_BENIGN_RECEIPT_DOMAIN => "chio.recovery.setup.benign-receipt.v1",
    SetupDeniedCommand = SETUP_DENIED_COMMAND_DOMAIN => "chio.recovery.setup.denied-command.v1",
    SetupNativeAuthority = SETUP_NATIVE_AUTHORITY_DOMAIN => "chio.recovery.setup.native-authority.v1",
    SetupRequiredCoverage = SETUP_REQUIRED_COVERAGE_DOMAIN => "chio.recovery.setup.required-coverage.v1",
    DecisionReport = DECISION_REPORT_DOMAIN => "chio.recovery.decision-report.v1",
    PolicyMaintenanceProposal = POLICY_MAINTENANCE_PROPOSAL_DOMAIN => "chio.recovery.policy-maintenance-proposal.v1",
    SemanticPackage = SEMANTIC_PACKAGE_DOMAIN => "chio.semantic.package.v1",
    SemanticRegistry = SEMANTIC_REGISTRY_DOMAIN => "chio.semantic.registry.v1",
    SemanticAction = SEMANTIC_ACTION_DOMAIN => "chio.semantic.action.v1",
    SemanticPlan = SEMANTIC_PLAN_DOMAIN => "chio.semantic.plan.v1",
    SemanticContent = SEMANTIC_CONTENT_DOMAIN => "chio.semantic.content.v1",
    SemanticRoleKey = SEMANTIC_ROLE_KEY_DOMAIN => "chio.semantic.role-key.v1",
    SemanticNativeRequestSemantics = SEMANTIC_NATIVE_REQUEST_SEMANTICS_DOMAIN => "chio.semantic.native-request-semantics.v1",
    SemanticNativeOutputOrigin = SEMANTIC_NATIVE_OUTPUT_ORIGIN_DOMAIN => "chio.semantic.native-output-origin.v1",
    ConfinedCapability = CONFINED_CAPABILITY_DOMAIN => "chio.confined.capability.v1",
    IsolationBoundary = ISOLATION_BOUNDARY_DOMAIN => "chio.isolation.boundary.v1",
    ConfinedEvidenceBinding = CONFINED_EVIDENCE_BINDING_DOMAIN => "chio.confined.evidence-binding.v1",
    ConfinedParentControl = CONFINED_PARENT_CONTROL_DOMAIN => "chio.confined.parent-control.v1",
    ConfinedLaunch = CONFINED_LAUNCH_DOMAIN => "chio.confined.launch.v1",
    KnowledgeObservedInfluence = KNOWLEDGE_OBSERVED_INFLUENCE_DOMAIN => "chio.knowledge.observed-influence.v1",
    KnowledgeInfluence = KNOWLEDGE_INFLUENCE_DOMAIN => "chio.knowledge.influence.v1",
    KnowledgeImportInfluence = KNOWLEDGE_IMPORT_INFLUENCE_DOMAIN => "chio.knowledge.import-influence.v1",
    KnowledgeReadAuthority = KNOWLEDGE_READ_AUTHORITY_DOMAIN => "chio.knowledge.read-authority.v1",
    KnowledgeSemanticInfluence = KNOWLEDGE_SEMANTIC_INFLUENCE_DOMAIN => "chio.knowledge.semantic-influence.v1",
    KnowledgeInfluenceScope = KNOWLEDGE_INFLUENCE_SCOPE_DOMAIN => "chio.knowledge.influence-scope.v1",
    KnowledgeInfluenceFold = KNOWLEDGE_INFLUENCE_FOLD_DOMAIN => "chio.knowledge.influence-fold.v1",
    KnowledgeHandleIdentity = KNOWLEDGE_HANDLE_IDENTITY_DOMAIN => "chio.knowledge.handle-identity.v1",
    KnowledgeActorIdentity = KNOWLEDGE_ACTOR_IDENTITY_DOMAIN => "chio.knowledge.actor-identity.v1",
    KnowledgeReferenceIdentity = KNOWLEDGE_REFERENCE_IDENTITY_DOMAIN => "chio.knowledge.reference-identity.v1",
    KnowledgeReferenceOwner = KNOWLEDGE_REFERENCE_OWNER_DOMAIN => "chio.knowledge.reference-owner.v1",
    KnowledgeObjectCustody = KNOWLEDGE_OBJECT_CUSTODY_DOMAIN => "chio.knowledge.object-custody.v1",
    ArtifactArchive = ARTIFACT_ARCHIVE_DOMAIN => "chio.artifact.archive.v1",
    ParticipantOwner = PARTICIPANT_OWNER_DOMAIN => "chio.participant.owner.v1",
    SemanticNativeStatusOrigin = SEMANTIC_NATIVE_STATUS_ORIGIN_DOMAIN => "chio.semantic.native-status-origin.v1",
    SemanticNativeInputOrigin = SEMANTIC_NATIVE_INPUT_ORIGIN_DOMAIN => "chio.semantic.native-input-origin.v1",
}

impl RecoveryDigestDomain {
    /// SHA-256(domain UTF-8 bytes || NUL || RFC 8785 canonical body).
    pub fn digest(self, body: &CanonicalBytes) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(self.prefix());
        hash.update(body.as_bytes());
        Digest32::new(hash.finalize().into())
    }
}
