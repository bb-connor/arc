use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub use manifest::{Manifest, ManifestEntry, MANIFEST_PRODUCER, MANIFEST_SCHEMA_VERSION};

/// Schema version accepted by this crate.
pub const CASE_SCHEMA_VERSION: u32 = 1;

/// Schema for behavioral controls and cargo-mutants outcomes.
pub const MUTATION_EVIDENCE_SCHEMA: &str = "chio.adversarial-mutation-evidence.v1";

/// Embedded JSON schema for on-disk adversarial case files.
pub const CASE_SCHEMA_JSON: &str = include_str!("../schema/case.schema.json");

/// Supported adversarial classes.
pub const ATTACK_CLASSES: &[AttackClass] = &[
    AttackClass::ClockRewound,
    AttackClass::FutureDated,
    AttackClass::ReplayedNonce,
    AttackClass::PartialSignature,
    AttackClass::ScopeSuperset,
    AttackClass::RevocationRollback,
    AttackClass::AnchorGrafted,
    AttackClass::SigstoreBundlePayloadMismatch,
    AttackClass::LabelDowngrade,
    AttackClass::CanaryEvasion,
    AttackClass::TemporalEvasion,
    AttackClass::ContainmentRollback,
    AttackClass::KeyLogOmission,
    AttackClass::KeyLogNoncontiguousSync,
    AttackClass::KeyLogInconsistentGrowth,
    AttackClass::KeyLogSplitView,
    AttackClass::RotationPartialCommit,
    AttackClass::RotationUnwitnessedSigning,
    AttackClass::OldKeyBackdating,
    AttackClass::AuthorityBindingMutation,
    AttackClass::BrokerSecretBoundaryCrossing,
    AttackClass::BrokerExecutionOverspend,
    AttackClass::BrokerParentDoubleCharge,
    AttackClass::BrokerOrphanHold,
    AttackClass::BrokerProofReplay,
    AttackClass::BrokerUnboundHeaders,
    AttackClass::BrokerDestinationRebinding,
    AttackClass::BrokerRevocationRace,
    AttackClass::BrokerPlaintextCustody,
    AttackClass::SandboxUnsignedManifest,
    AttackClass::SandboxPartialEnforcement,
    AttackClass::SandboxSymlinkEscape,
    AttackClass::SandboxPathSwap,
    AttackClass::SandboxHelperSubstitution,
    AttackClass::SandboxFalseExecSuccess,
    AttackClass::SandboxSyscallEscape,
    AttackClass::SandboxFdOrEnvLeak,
];

/// One statically bundled adversarial case file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundledCase {
    /// Repository-relative path to the case JSON.
    pub path: &'static str,
    /// Embedded JSON payload.
    pub contents: &'static str,
}

/// Case files embedded into the crate for downstream test harnesses.
pub const BUNDLED_CASES: &[BundledCase] = &[
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-001.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-001.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-002.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-002.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-003.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-003.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-004.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-004.json"),
    },
    BundledCase {
        path: "cases/clock_rewound/clock-rewound-005.json",
        contents: include_str!("../cases/clock_rewound/clock-rewound-005.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-001.json",
        contents: include_str!("../cases/future_dated/future-dated-001.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-002.json",
        contents: include_str!("../cases/future_dated/future-dated-002.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-003.json",
        contents: include_str!("../cases/future_dated/future-dated-003.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-004.json",
        contents: include_str!("../cases/future_dated/future-dated-004.json"),
    },
    BundledCase {
        path: "cases/future_dated/future-dated-005.json",
        contents: include_str!("../cases/future_dated/future-dated-005.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-001.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-001.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-002.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-002.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-003.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-003.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-004.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-004.json"),
    },
    BundledCase {
        path: "cases/replayed_nonce/replayed-nonce-005.json",
        contents: include_str!("../cases/replayed_nonce/replayed-nonce-005.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-001.json",
        contents: include_str!("../cases/partial_signature/partial-signature-001.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-002.json",
        contents: include_str!("../cases/partial_signature/partial-signature-002.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-003.json",
        contents: include_str!("../cases/partial_signature/partial-signature-003.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-004.json",
        contents: include_str!("../cases/partial_signature/partial-signature-004.json"),
    },
    BundledCase {
        path: "cases/partial_signature/partial-signature-005.json",
        contents: include_str!("../cases/partial_signature/partial-signature-005.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-001.json",
        contents: include_str!("../cases/scope_superset/scope-superset-001.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-002.json",
        contents: include_str!("../cases/scope_superset/scope-superset-002.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-003.json",
        contents: include_str!("../cases/scope_superset/scope-superset-003.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-004.json",
        contents: include_str!("../cases/scope_superset/scope-superset-004.json"),
    },
    BundledCase {
        path: "cases/scope_superset/scope-superset-005.json",
        contents: include_str!("../cases/scope_superset/scope-superset-005.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-001.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-001.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-002.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-002.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-003.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-003.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-004.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-004.json"),
    },
    BundledCase {
        path: "cases/revocation_rollback/revocation-rollback-005.json",
        contents: include_str!("../cases/revocation_rollback/revocation-rollback-005.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-001.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-001.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-002.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-002.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-003.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-003.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-004.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-004.json"),
    },
    BundledCase {
        path: "cases/anchor_grafted/anchor-grafted-005.json",
        contents: include_str!("../cases/anchor_grafted/anchor-grafted-005.json"),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json"
        ),
    },
    BundledCase {
        path: "cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json",
        contents: include_str!(
            "../cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json"
        ),
    },
    BundledCase {
        path: "cases/label_downgrade/label-downgrade-001.json",
        contents: include_str!("../cases/label_downgrade/label-downgrade-001.json"),
    },
    BundledCase {
        path: "cases/canary_evasion/canary-evasion-001.json",
        contents: include_str!("../cases/canary_evasion/canary-evasion-001.json"),
    },
    BundledCase {
        path: "cases/temporal_evasion/temporal-evasion-001.json",
        contents: include_str!("../cases/temporal_evasion/temporal-evasion-001.json"),
    },
    BundledCase {
        path: "cases/containment_rollback/containment-rollback-001.json",
        contents: include_str!("../cases/containment_rollback/containment-rollback-001.json"),
    },
    BundledCase {
        path: "cases/key_log_omission/key-log-omission-001.json",
        contents: include_str!("../cases/key_log_omission/key-log-omission-001.json"),
    },
    BundledCase {
        path: "cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json",
        contents: include_str!(
            "../cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json"
        ),
    },
    BundledCase {
        path: "cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json",
        contents: include_str!(
            "../cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json"
        ),
    },
    BundledCase {
        path: "cases/key_log_split_view/key-log-split-view-001.json",
        contents: include_str!("../cases/key_log_split_view/key-log-split-view-001.json"),
    },
    BundledCase {
        path: "cases/rotation_partial_commit/rotation-partial-commit-001.json",
        contents: include_str!("../cases/rotation_partial_commit/rotation-partial-commit-001.json"),
    },
    BundledCase {
        path: "cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json",
        contents: include_str!(
            "../cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json"
        ),
    },
    BundledCase {
        path: "cases/old_key_backdating/old-key-backdating-001.json",
        contents: include_str!("../cases/old_key_backdating/old-key-backdating-001.json"),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json"
        ),
    },
    BundledCase {
        path: "cases/authority_binding_mutation/threshold-proposal-mutations-001.json",
        contents: include_str!(
            "../cases/authority_binding_mutation/threshold-proposal-mutations-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json",
        contents: include_str!(
            "../cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_execution_overspend/broker-execution-overspend-001.json",
        contents: include_str!(
            "../cases/broker_execution_overspend/broker-execution-overspend-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_parent_double_charge/broker-parent-double-charge-001.json",
        contents: include_str!(
            "../cases/broker_parent_double_charge/broker-parent-double-charge-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_orphan_hold/broker-orphan-hold-001.json",
        contents: include_str!("../cases/broker_orphan_hold/broker-orphan-hold-001.json"),
    },
    BundledCase {
        path: "cases/broker_proof_replay/broker-proof-replay-001.json",
        contents: include_str!("../cases/broker_proof_replay/broker-proof-replay-001.json"),
    },
    BundledCase {
        path: "cases/broker_unbound_headers/broker-unbound-headers-001.json",
        contents: include_str!("../cases/broker_unbound_headers/broker-unbound-headers-001.json"),
    },
    BundledCase {
        path: "cases/broker_destination_rebinding/broker-destination-rebinding-001.json",
        contents: include_str!(
            "../cases/broker_destination_rebinding/broker-destination-rebinding-001.json"
        ),
    },
    BundledCase {
        path: "cases/broker_revocation_race/broker-revocation-race-001.json",
        contents: include_str!("../cases/broker_revocation_race/broker-revocation-race-001.json"),
    },
    BundledCase {
        path: "cases/broker_plaintext_custody/broker-plaintext-custody-001.json",
        contents: include_str!(
            "../cases/broker_plaintext_custody/broker-plaintext-custody-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json",
        contents: include_str!(
            "../cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json",
        contents: include_str!(
            "../cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json",
        contents: include_str!("../cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_path_swap/sandbox-path-swap-001.json",
        contents: include_str!("../cases/sandbox_path_swap/sandbox-path-swap-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json",
        contents: include_str!(
            "../cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json",
        contents: include_str!(
            "../cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json"
        ),
    },
    BundledCase {
        path: "cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json",
        contents: include_str!("../cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json"),
    },
    BundledCase {
        path: "cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json",
        contents: include_str!("../cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json"),
    },
];

/// One malicious-but-well-formed case consumed by test harnesses.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct AdversarialCase {
    /// Version of the case envelope, currently `1`.
    pub schema_version: u32,
    /// Stable case identifier, usually the file stem or content hash.
    pub id: String,
    /// Attack class this case exercises.
    pub class: AttackClass,
    /// Expected verdict. Adversarial cases are deny-asserted.
    pub expected_verdict: ExpectedVerdict,
    /// Stable deny reason asserted by downstream harnesses.
    pub expected_reason: String,
    /// Threat-model ID this case is intended to cover.
    pub threat_id: String,
    /// Auto-promoted cases start pending and do not count as coverage.
    pub pending: bool,
    /// Case-specific payload. Vector files define per-class shapes.
    pub artifact: serde_json::Value,
    /// Optional operator notes for triage and provenance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl AdversarialCase {
    /// Load and validate a case from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CaseError> {
        let case: Self = serde_json::from_slice(bytes)?;
        case.validate()?;
        Ok(case)
    }

    /// Load and validate a case from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CaseError> {
        Self::from_slice(&fs::read(path)?)
    }

    /// Validate semantic constraints that JSON Schema cannot enforce alone.
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.schema_version != CASE_SCHEMA_VERSION {
            return Err(CaseError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.id.trim().is_empty() {
            return Err(CaseError::EmptyField("id"));
        }
        if !is_valid_case_id(&self.id) {
            return Err(CaseError::InvalidCaseId(self.id.clone()));
        }
        if self.expected_reason.trim().is_empty() {
            return Err(CaseError::EmptyField("expected_reason"));
        }
        if !is_valid_expected_reason(&self.expected_reason) {
            return Err(CaseError::InvalidExpectedReason(
                self.expected_reason.clone(),
            ));
        }
        if self.threat_id.trim().is_empty() {
            return Err(CaseError::EmptyField("threat_id"));
        }
        if !is_valid_threat_id(&self.threat_id) {
            return Err(CaseError::InvalidThreatId(self.threat_id.clone()));
        }
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(CaseError::EmptyField("notes"));
        }
        match self.artifact.as_object() {
            Some(object) if !object.is_empty() => {
                if self.class.requires_mutation_evidence() {
                    self.mutation_evidence()?;
                }
            }
            _ => return Err(CaseError::InvalidArtifact),
        }
        Ok(())
    }

    /// Decode the closed evidence contract for security release cases.
    pub fn mutation_evidence(&self) -> Result<Option<MutationEvidence>, CaseError> {
        if !self.class.requires_mutation_evidence() {
            return Ok(None);
        }
        let evidence: MutationEvidence = serde_json::from_value(self.artifact.clone())
            .map_err(|_| CaseError::InvalidMutationEvidence)?;
        evidence.validate(self.class, self.pending)?;
        Ok(Some(evidence))
    }

    /// Convert a validated case into a coverage-eligible case.
    ///
    /// Pending cases are accepted by the raw loader for triage, but this
    /// method gives coverage gates a fail-closed API that rejects them.
    pub fn into_coverage_case(self) -> Result<CoverageCase, CaseError> {
        self.validate()?;
        if self.pending {
            return Err(CaseError::PendingCase(self.id));
        }
        Ok(CoverageCase(self))
    }
}

/// A validated non-pending adversarial case that may count as threat coverage.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageCase(AdversarialCase);

impl CoverageCase {
    /// Borrow the underlying case.
    pub const fn as_case(&self) -> &AdversarialCase {
        &self.0
    }

    /// Return the underlying case.
    pub fn into_inner(self) -> AdversarialCase {
        self.0
    }
}

/// Load all statically bundled cases.
pub fn bundled_cases() -> Result<Vec<AdversarialCase>, CaseError> {
    BUNDLED_CASES
        .iter()
        .map(|case| AdversarialCase::from_slice(case.contents.as_bytes()))
        .collect()
}

/// Load all statically bundled non-pending cases.
pub fn bundled_coverage_cases() -> Result<Vec<CoverageCase>, CaseError> {
    bundled_cases()?
        .into_iter()
        .filter(|case| !case.pending)
        .map(AdversarialCase::into_coverage_case)
        .collect()
}

/// Load statically bundled cases for one attack class.
pub fn bundled_cases_by_class(class: AttackClass) -> Result<Vec<AdversarialCase>, CaseError> {
    Ok(bundled_cases()?
        .into_iter()
        .filter(|case| case.class == class)
        .collect())
}

/// Adversarial attack classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackClass {
    ClockRewound,
    FutureDated,
    ReplayedNonce,
    PartialSignature,
    ScopeSuperset,
    RevocationRollback,
    AnchorGrafted,
    SigstoreBundlePayloadMismatch,
    LabelDowngrade,
    CanaryEvasion,
    TemporalEvasion,
    ContainmentRollback,
    KeyLogOmission,
    KeyLogNoncontiguousSync,
    KeyLogInconsistentGrowth,
    KeyLogSplitView,
    RotationPartialCommit,
    RotationUnwitnessedSigning,
    OldKeyBackdating,
    AuthorityBindingMutation,
    BrokerSecretBoundaryCrossing,
    BrokerExecutionOverspend,
    BrokerParentDoubleCharge,
    BrokerOrphanHold,
    BrokerProofReplay,
    BrokerUnboundHeaders,
    BrokerDestinationRebinding,
    BrokerRevocationRace,
    BrokerPlaintextCustody,
    SandboxUnsignedManifest,
    SandboxPartialEnforcement,
    SandboxSymlinkEscape,
    SandboxPathSwap,
    SandboxHelperSubstitution,
    SandboxFalseExecSuccess,
    SandboxSyscallEscape,
    SandboxFdOrEnvLeak,
}

impl AttackClass {
    /// Stable snake_case class identifier used in paths and JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockRewound => "clock_rewound",
            Self::FutureDated => "future_dated",
            Self::ReplayedNonce => "replayed_nonce",
            Self::PartialSignature => "partial_signature",
            Self::ScopeSuperset => "scope_superset",
            Self::RevocationRollback => "revocation_rollback",
            Self::AnchorGrafted => "anchor_grafted",
            Self::SigstoreBundlePayloadMismatch => "sigstore_bundle_payload_mismatch",
            Self::LabelDowngrade => "label_downgrade",
            Self::CanaryEvasion => "canary_evasion",
            Self::TemporalEvasion => "temporal_evasion",
            Self::ContainmentRollback => "containment_rollback",
            Self::KeyLogOmission => "key_log_omission",
            Self::KeyLogNoncontiguousSync => "key_log_noncontiguous_sync",
            Self::KeyLogInconsistentGrowth => "key_log_inconsistent_growth",
            Self::KeyLogSplitView => "key_log_split_view",
            Self::RotationPartialCommit => "rotation_partial_commit",
            Self::RotationUnwitnessedSigning => "rotation_unwitnessed_signing",
            Self::OldKeyBackdating => "old_key_backdating",
            Self::AuthorityBindingMutation => "authority_binding_mutation",
            Self::BrokerSecretBoundaryCrossing => "broker_secret_boundary_crossing",
            Self::BrokerExecutionOverspend => "broker_execution_overspend",
            Self::BrokerParentDoubleCharge => "broker_parent_double_charge",
            Self::BrokerOrphanHold => "broker_orphan_hold",
            Self::BrokerProofReplay => "broker_proof_replay",
            Self::BrokerUnboundHeaders => "broker_unbound_headers",
            Self::BrokerDestinationRebinding => "broker_destination_rebinding",
            Self::BrokerRevocationRace => "broker_revocation_race",
            Self::BrokerPlaintextCustody => "broker_plaintext_custody",
            Self::SandboxUnsignedManifest => "sandbox_unsigned_manifest",
            Self::SandboxPartialEnforcement => "sandbox_partial_enforcement",
            Self::SandboxSymlinkEscape => "sandbox_symlink_escape",
            Self::SandboxPathSwap => "sandbox_path_swap",
            Self::SandboxHelperSubstitution => "sandbox_helper_substitution",
            Self::SandboxFalseExecSuccess => "sandbox_false_exec_success",
            Self::SandboxSyscallEscape => "sandbox_syscall_escape",
            Self::SandboxFdOrEnvLeak => "sandbox_fd_or_env_leak",
        }
    }

    /// Whether this release class must carry behavioral mutation evidence.
    #[must_use]
    pub const fn requires_mutation_evidence(self) -> bool {
        !matches!(
            self,
            Self::ClockRewound
                | Self::FutureDated
                | Self::ReplayedNonce
                | Self::PartialSignature
                | Self::ScopeSuperset
                | Self::RevocationRollback
                | Self::AnchorGrafted
                | Self::SigstoreBundlePayloadMismatch
                | Self::AuthorityBindingMutation
        )
    }

    /// Exact mutation checks required for this attack class.
    #[must_use]
    pub const fn required_mutations(self) -> &'static [&'static str] {
        match self {
            Self::LabelDowngrade => &[
                "reader_subset_direction",
                "missing_clearance_allow",
                "ignored_store_error",
                "grant_replay",
            ],
            Self::CanaryEvasion => &["tripwire_after_dispatch"],
            Self::TemporalEvasion => &["ingest_time_substitution"],
            Self::ContainmentRollback => &[
                "truncation_ignored",
                "approval_plan_field_omission",
                "root_only_lift",
                "false_lifted_status",
            ],
            Self::KeyLogOmission => &["key_log_omission"],
            Self::KeyLogNoncontiguousSync => &["key_log_noncontiguous_sync"],
            Self::KeyLogInconsistentGrowth => &["key_log_inconsistent_growth"],
            Self::KeyLogSplitView => &["key_log_split_view"],
            Self::RotationPartialCommit => &["rotation_partial_commit"],
            Self::RotationUnwitnessedSigning => &["rotation_unwitnessed_signing"],
            Self::OldKeyBackdating => &["old_key_backdating"],
            Self::BrokerSecretBoundaryCrossing => &["broker_secret_boundary_crossing"],
            Self::BrokerExecutionOverspend => &["broker_execution_overspend"],
            Self::BrokerParentDoubleCharge => &["broker_parent_double_charge"],
            Self::BrokerOrphanHold => &["broker_orphan_hold"],
            Self::BrokerProofReplay => &["broker_proof_replay"],
            Self::BrokerUnboundHeaders => &["broker_unbound_headers"],
            Self::BrokerDestinationRebinding => &["broker_destination_rebinding"],
            Self::BrokerRevocationRace => &["broker_revocation_race"],
            Self::BrokerPlaintextCustody => &["broker_plaintext_custody"],
            Self::SandboxUnsignedManifest => &["sandbox_unsigned_manifest"],
            Self::SandboxPartialEnforcement => &["sandbox_partial_enforcement"],
            Self::SandboxSymlinkEscape => &["sandbox_symlink_escape"],
            Self::SandboxPathSwap => &["sandbox_path_swap"],
            Self::SandboxHelperSubstitution => &["sandbox_helper_substitution"],
            Self::SandboxFalseExecSuccess => &["sandbox_false_exec_success"],
            Self::SandboxSyscallEscape => &["sandbox_syscall_escape"],
            Self::SandboxFdOrEnvLeak => &["sandbox_fd_leak", "sandbox_env_leak"],
            Self::ClockRewound
            | Self::FutureDated
            | Self::ReplayedNonce
            | Self::PartialSignature
            | Self::ScopeSuperset
            | Self::RevocationRollback
            | Self::AnchorGrafted
            | Self::SigstoreBundlePayloadMismatch
            | Self::AuthorityBindingMutation => &[],
        }
    }
}

/// One exact behavioral test used as a mutation oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationControl {
    /// Stable local identifier.
    pub id: String,
    /// Cargo package containing the behavioral test.
    pub package: String,
    /// Repository-relative Rust file containing the test.
    pub test_source: String,
    /// Cargo target kind.
    pub target_kind: MutationTestTargetKind,
    /// Integration-test target name. Omitted for library tests.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub target: Option<String>,
    /// Cargo features needed to compile the behavioral test.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Operating system required by the behavioral test.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub required_target_os: Option<MutationTargetOs>,
    /// Exact Rust test name passed after `--exact`.
    pub test_name: String,
}

/// Cargo target containing an exact behavioral control.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationTestTargetKind {
    /// Package library target.
    Lib,
    /// Named integration-test target.
    Test,
}

/// Operating-system constraint for a behavioral control.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationTargetOs {
    /// Linux kernel enforcement is required.
    Linux,
}

/// Location and digest of native cargo-mutants outcomes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationOutcomes {
    /// Repository-relative cargo-mutants outcomes path.
    pub path: String,
    /// SHA-256 of the exact outcomes JSON. Absent while evidence is pending.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub sha256: Option<String>,
    /// SHA-256 of the mutation source, control source, manifests, and execution contract.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub inputs_sha256: Option<String>,
}

/// Native cargo-mutants mutation genre admitted by the evidence runner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MutationGenre {
    /// Replace an entire function body with a value.
    FnValue,
    /// Replace one binary operator.
    BinaryOperator,
    /// Delete one unary operator.
    UnaryOperator,
}

/// Stable semantic identity for exactly one native cargo-mutants mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationSelector {
    /// Native cargo-mutants genre.
    pub genre: MutationGenre,
    /// Exact source text at the native mutation span for operator mutations.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub original: Option<String>,
    /// Exact replacement emitted into the native mutant record.
    pub replacement: String,
    /// One-based ordinal for repeated identical operators, ordered by source span.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub occurrence: Option<u32>,
    /// Optional expression passed to cargo-mutants `--error` for an Err mutation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub error: Option<String>,
}

/// One focused cargo-mutants invocation bound to a behavioral control.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationCampaign {
    /// Stable mutation identifier required by the attack class.
    pub id: String,
    /// Identifier of the exact behavioral control.
    pub control_id: String,
    /// Cargo package mutated by cargo-mutants.
    pub package: String,
    /// Repository-relative Rust source file.
    ///
    /// The evidence checker requires exact cargo-mutants source-inventory
    /// membership before a campaign can run.
    pub source: String,
    /// Exact native cargo-mutants function name.
    pub function: String,
    /// Minimum number of caught mutants required for this selection.
    pub minimum_caught: u32,
    /// Semantic selector for one native mutation. Required for pending evidence.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_option"
    )]
    pub mutant: Option<MutationSelector>,
    /// Native cargo-mutants outcomes binding.
    pub outcomes: MutationOutcomes,
}

/// Closed behavioral and mutation-evidence contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationEvidence {
    /// Contract schema.
    pub schema: String,
    /// Exact behavioral controls.
    pub controls: Vec<MutationControl>,
    /// Focused cargo-mutants selections.
    pub campaigns: Vec<MutationCampaign>,
}

impl MutationEvidence {
    fn validate(&self, class: AttackClass, pending: bool) -> Result<(), CaseError> {
        if self.schema != MUTATION_EVIDENCE_SCHEMA
            || self.controls.is_empty()
            || self.campaigns.is_empty()
            || self.controls.len() > 16
            || self.campaigns.len() > 16
        {
            return Err(CaseError::InvalidMutationEvidence);
        }

        let mut control_ids = BTreeSet::new();
        for control in &self.controls {
            let features = control.features.iter().collect::<BTreeSet<_>>();
            if !valid_snake_identifier(&control.id)
                || !valid_package_name(&control.package)
                || !valid_rust_path(&control.test_source)
                || !valid_test_name(&control.test_name)
                || control.features.len() > 8
                || features.len() != control.features.len()
                || control
                    .features
                    .iter()
                    .any(|feature| !valid_package_name(feature))
                || !control_ids.insert(control.id.as_str())
            {
                return Err(CaseError::InvalidMutationEvidence);
            }
            match control.target_kind {
                MutationTestTargetKind::Lib if control.target.is_some() => {
                    return Err(CaseError::InvalidMutationEvidence);
                }
                MutationTestTargetKind::Test => match control.target.as_deref() {
                    Some(target) if valid_target_name(target) => {}
                    _ => return Err(CaseError::InvalidMutationEvidence),
                },
                MutationTestTargetKind::Lib => {}
            }
        }

        let mut campaign_ids = BTreeSet::new();
        let mut referenced_controls = BTreeSet::new();
        let mut outcome_paths = BTreeSet::new();
        for campaign in &self.campaigns {
            let expected_path = format!(
                "audits/evidence/mutants/security/{}/mutants.out/outcomes.json",
                campaign.id
            );
            if !valid_snake_identifier(&campaign.id)
                || !campaign_ids.insert(campaign.id.as_str())
                || !control_ids.contains(campaign.control_id.as_str())
                || !valid_package_name(&campaign.package)
                || !valid_rust_path(&campaign.source)
                || !valid_function_selector(&campaign.function)
                || campaign.minimum_caught == 0
                || campaign.minimum_caught > 64
                || campaign.mutant.as_ref().is_some_and(|selector| {
                    campaign.minimum_caught != 1 || !valid_mutation_selector(selector)
                })
                || (campaign.outcomes.sha256.is_none() && campaign.mutant.is_none())
                || campaign.outcomes.sha256.is_some() != campaign.outcomes.inputs_sha256.is_some()
                || campaign.outcomes.path != expected_path
                || !outcome_paths.insert(campaign.outcomes.path.as_str())
                || campaign
                    .outcomes
                    .sha256
                    .as_deref()
                    .is_some_and(|digest| !valid_sha256(digest))
                || campaign
                    .outcomes
                    .inputs_sha256
                    .as_deref()
                    .is_some_and(|digest| !valid_sha256(digest))
            {
                return Err(CaseError::InvalidMutationEvidence);
            }
            referenced_controls.insert(campaign.control_id.as_str());
        }

        if referenced_controls != control_ids {
            return Err(CaseError::InvalidMutationEvidence);
        }
        let required = class
            .required_mutations()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if campaign_ids != required {
            return Err(CaseError::InvalidMutationEvidence);
        }
        if !pending
            && self
                .campaigns
                .iter()
                .any(|campaign| campaign.outcomes.sha256.is_none())
        {
            return Err(CaseError::InvalidMutationEvidence);
        }
        Ok(())
    }
}

/// Verdict expected from a trust-boundary harness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ExpectedVerdict {
    #[serde(rename = "DENY")]
    Deny,
}

/// Case load or validation failure.
#[derive(Debug, Error)]
pub enum CaseError {
    #[error("failed to read adversarial case")]
    Io(#[from] std::io::Error),
    #[error("failed to parse adversarial case JSON")]
    Json(#[from] serde_json::Error),
    #[error("unsupported adversarial case schema version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("adversarial case field {0} must not be empty")]
    EmptyField(&'static str),
    #[error("adversarial case id {0} is not schema-compliant")]
    InvalidCaseId(String),
    #[error("adversarial case expected_reason {0} is not schema-compliant")]
    InvalidExpectedReason(String),
    #[error("adversarial case threat_id {0} is not schema-compliant")]
    InvalidThreatId(String),
    #[error("adversarial case artifact must be a non-empty object")]
    InvalidArtifact,
    #[error("security adversarial case has an invalid mutation-evidence contract")]
    InvalidMutationEvidence,
    #[error("pending adversarial case {0} is not coverage-eligible")]
    PendingCase(String),
    #[error("manifest drift: case id '{case_id}' does not match bundled path '{path}'")]
    ManifestDrift { case_id: String, path: String },
}

fn is_valid_case_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
}

fn is_valid_expected_reason(reason: &str) -> bool {
    let mut chars = reason.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_valid_threat_id(threat_id: &str) -> bool {
    let mut chars = threat_id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

fn valid_snake_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn valid_package_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    value.len() <= 96
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && !value.ends_with('-')
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn valid_target_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    value.len() <= 96
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn valid_test_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
}

fn valid_function_selector(value: &str) -> bool {
    value.len() >= 4
        && value.len() <= 192
        && value.trim() == value
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | ':' | '<' | '>' | ',' | ' ')
        })
}

fn valid_mutant_text(value: &str, allow_empty: bool) -> bool {
    value.len() <= 192
        && (allow_empty || !value.is_empty())
        && value
            .chars()
            .all(|character| character.is_ascii_graphic() || character == ' ')
}

fn valid_binary_replacement(original: &str, replacement: &str) -> bool {
    matches!(
        (original, replacement),
        ("==", "!=")
            | ("!=", "==")
            | ("&&", "||")
            | ("||", "&&")
            | (">", "<")
            | (">=", "<")
            | ("<", ">")
            | ("<=", ">")
    )
}

fn valid_mutation_selector(selector: &MutationSelector) -> bool {
    if !valid_mutant_text(&selector.replacement, true)
        || selector
            .occurrence
            .is_some_and(|occurrence| !(1..=64).contains(&occurrence))
    {
        return false;
    }
    match selector.genre {
        MutationGenre::FnValue => {
            if selector.original.is_some() {
                return false;
            }
            match selector.error.as_deref() {
                Some(error) => {
                    valid_mutant_text(error, false)
                        && selector.replacement == format!("Err({error})")
                }
                None => true,
            }
        }
        MutationGenre::BinaryOperator => {
            selector.error.is_none()
                && selector.original.as_deref().is_some_and(|original| {
                    valid_mutant_text(original, false)
                        && valid_binary_replacement(original, &selector.replacement)
                })
        }
        MutationGenre::UnaryOperator => {
            selector.error.is_none()
                && selector.replacement.is_empty()
                && selector
                    .original
                    .as_deref()
                    .is_some_and(|original| valid_mutant_text(original, false))
        }
    }
}

fn valid_rust_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && value.starts_with("crates/")
        && (value.ends_with(".rs") || value.ends_with(".inc"))
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn attack_class_names_are_stable() {
        let names = ATTACK_CLASSES
            .iter()
            .map(|class| class.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "clock_rewound",
                "future_dated",
                "replayed_nonce",
                "partial_signature",
                "scope_superset",
                "revocation_rollback",
                "anchor_grafted",
                "sigstore_bundle_payload_mismatch",
                "label_downgrade",
                "canary_evasion",
                "temporal_evasion",
                "containment_rollback",
                "key_log_omission",
                "key_log_noncontiguous_sync",
                "key_log_inconsistent_growth",
                "key_log_split_view",
                "rotation_partial_commit",
                "rotation_unwitnessed_signing",
                "old_key_backdating",
                "broker_secret_boundary_crossing",
                "broker_execution_overspend",
                "broker_parent_double_charge",
                "broker_orphan_hold",
                "broker_proof_replay",
                "broker_unbound_headers",
                "broker_destination_rebinding",
                "broker_revocation_race",
                "broker_plaintext_custody",
                "sandbox_unsigned_manifest",
                "sandbox_partial_enforcement",
                "sandbox_symlink_escape",
                "sandbox_path_swap",
                "sandbox_helper_substitution",
                "sandbox_false_exec_success",
                "sandbox_syscall_escape",
                "sandbox_fd_or_env_leak"
            ]
        );
    }

    #[test]
    fn required_security_attack_classes_are_registered() {
        let observed = ATTACK_CLASSES
            .iter()
            .map(|class| class.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let required = [
            "label_downgrade",
            "canary_evasion",
            "temporal_evasion",
            "containment_rollback",
            "key_log_omission",
            "key_log_noncontiguous_sync",
            "key_log_inconsistent_growth",
            "key_log_split_view",
            "rotation_partial_commit",
            "rotation_unwitnessed_signing",
            "old_key_backdating",
            "broker_secret_boundary_crossing",
            "broker_execution_overspend",
            "broker_parent_double_charge",
            "broker_orphan_hold",
            "broker_proof_replay",
            "broker_unbound_headers",
            "broker_destination_rebinding",
            "broker_revocation_race",
            "broker_plaintext_custody",
            "sandbox_unsigned_manifest",
            "sandbox_partial_enforcement",
            "sandbox_symlink_escape",
            "sandbox_path_swap",
            "sandbox_helper_substitution",
            "sandbox_false_exec_success",
            "sandbox_syscall_escape",
            "sandbox_fd_or_env_leak",
        ];
        for class in required {
            assert!(observed.contains(class), "missing attack class {class}");
        }
    }

    #[test]
    fn security_cases_bind_exact_controls_and_mutation_campaigns() -> Result<(), CaseError> {
        for case in bundled_cases()? {
            if !case.class.requires_mutation_evidence() {
                continue;
            }
            let evidence = case
                .mutation_evidence()?
                .ok_or(CaseError::InvalidMutationEvidence)?;
            let observed = evidence
                .campaigns
                .iter()
                .map(|campaign| campaign.id.as_str())
                .collect::<BTreeSet<_>>();
            let required = case
                .class
                .required_mutations()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            assert_eq!(observed, required, "{}", case.id);
            if !case.pending {
                assert!(
                    evidence.campaigns.iter().all(|campaign| {
                        campaign.outcomes.sha256.is_some()
                            && campaign.outcomes.inputs_sha256.is_some()
                    }),
                    "{}",
                    case.id
                );
            }
        }
        Ok(())
    }

    #[test]
    fn pending_security_evidence_is_not_coverage_eligible() -> Result<(), CaseError> {
        let expected = bundled_cases()?
            .into_iter()
            .filter(|case| !case.pending)
            .count();
        let coverage = bundled_coverage_cases()?;
        assert_eq!(coverage.len(), expected);
        assert!(coverage.iter().all(|case| !case.as_case().pending));
        Ok(())
    }

    #[test]
    fn security_case_rejects_legacy_shape_only_metadata() {
        let error = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "label-downgrade-invalid",
              "class": "label_downgrade",
              "expected_verdict": "DENY",
              "expected_reason": "label_downgrade_detected",
              "threat_id": "pii_phi_exposure",
              "pending": true,
              "artifact": {
                "required_check": "label_downgrade",
                "control": {"check_present": true, "expected_verdict": "DENY"},
                "mutant": {"check_present": false, "expected_verdict": "DENY"}
              }
            }"#,
        )
        .err();
        assert!(matches!(error, Some(CaseError::InvalidMutationEvidence)));
    }

    #[test]
    fn completed_security_case_requires_a_caught_outcomes_digest() {
        let error = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "temporal-evasion-invalid",
              "class": "temporal_evasion",
              "expected_verdict": "DENY",
              "expected_reason": "temporal_evasion_detected",
              "threat_id": "behavioral_sequence_attack",
              "pending": false,
              "artifact": {
                "schema": "chio.adversarial-mutation-evidence.v1",
                "controls": [{
                  "id": "event_time_control",
                  "package": "chio-quarantine",
                  "test_source": "crates/security/chio-quarantine/src/correlation.rs",
                  "target_kind": "lib",
                  "test_name": "correlation::tests::event_time_window_rejects_reverse_and_expired_sequences"
                }],
                "campaigns": [{
                  "id": "ingest_time_substitution",
                  "control_id": "event_time_control",
                  "package": "chio-quarantine",
                  "source": "crates/security/chio-quarantine/src/correlation.rs",
                  "function": "event_time_is_ordered_and_within",
                  "minimum_caught": 1,
                  "outcomes": {
                    "path": "audits/evidence/mutants/security/ingest_time_substitution/mutants.out/outcomes.json"
                  }
                }]
              }
            }"#,
        )
        .err();
        assert!(matches!(error, Some(CaseError::InvalidMutationEvidence)));
    }

    #[test]
    fn rust_source_paths_admit_modules_and_includes_only() {
        assert!(valid_rust_path("crates/core/example/src/lib.rs"));
        assert!(valid_rust_path(
            "crates/core/example/src/lib_parts/part_01.inc"
        ));
        for invalid in [
            "/crates/core/example/src/lib.rs",
            "crates/core/example/../src/lib.rs",
            "crates/core/example/src/lib.json",
            "src/lib.rs",
        ] {
            assert!(!valid_rust_path(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn function_selectors_admit_qualified_generic_names() {
        assert!(valid_function_selector(
            "ResponseExecutor<S, E, R, A>::drive_rollback"
        ));
        assert!(!valid_function_selector(
            "ResponseExecutor<S; E>::drive_rollback"
        ));
        assert!(!valid_function_selector(
            " ResponseExecutor<S, E>::drive_rollback"
        ));
        assert!(!valid_function_selector(
            "ResponseExecutor<S, E>::drive_rollback "
        ));
    }

    #[test]
    fn test_names_require_double_colon_separated_identifiers() {
        for valid in ["control", "module::control", "module_1::_control"] {
            assert!(valid_test_name(valid), "rejected {valid}");
        }
        for invalid in [
            ":control",
            "control:",
            "module:control",
            "module:::control",
            "::control",
            "control::",
        ] {
            assert!(!valid_test_name(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn mutation_contract_optional_fields_reject_explicit_null() {
        let control = serde_json::json!({
            "id": "control",
            "package": "chio-core",
            "test_source": "crates/core/chio-core/src/lib.rs",
            "target_kind": "lib",
            "test_name": "tests::control"
        });
        assert!(serde_json::from_value::<MutationControl>(control.clone()).is_ok());
        for field in ["target", "required_target_os"] {
            let mut candidate = control.clone();
            candidate[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<MutationControl>(candidate).is_err(),
                "accepted null {field}"
            );
        }

        let outcomes = serde_json::json!({
            "path": "audits/evidence/mutants/security/control/mutants.out/outcomes.json"
        });
        assert!(serde_json::from_value::<MutationOutcomes>(outcomes.clone()).is_ok());
        for field in ["sha256", "inputs_sha256"] {
            let mut candidate = outcomes.clone();
            candidate[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<MutationOutcomes>(candidate).is_err(),
                "accepted null {field}"
            );
        }

        let selector = serde_json::json!({
            "genre": "FnValue",
            "replacement": "true"
        });
        assert!(serde_json::from_value::<MutationSelector>(selector.clone()).is_ok());
        for field in ["original", "occurrence", "error"] {
            let mut candidate = selector.clone();
            candidate[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<MutationSelector>(candidate).is_err(),
                "accepted null {field}"
            );
        }

        let campaign = serde_json::json!({
            "id": "control",
            "control_id": "control",
            "package": "chio-core",
            "source": "crates/core/chio-core/src/lib.rs",
            "function": "control",
            "minimum_caught": 1,
            "outcomes": outcomes
        });
        assert!(serde_json::from_value::<MutationCampaign>(campaign.clone()).is_ok());
        let mut candidate = campaign;
        candidate["mutant"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MutationCampaign>(candidate).is_err());
    }

    #[test]
    fn parses_and_validates_case_envelope() -> Result<(), CaseError> {
        let case = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "clock-rewound-smoke",
              "class": "clock_rewound",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": { "receipt": { "issued_at": "1970-01-01T00:00:00Z" } }
            }"#,
        )?;

        assert_eq!(case.class, AttackClass::ClockRewound);
        assert_eq!(case.expected_verdict, ExpectedVerdict::Deny);
        assert!(!case.pending);
        assert!(case.into_coverage_case().is_ok());
        Ok(())
    }

    #[test]
    fn rejects_empty_object_artifact() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "empty-artifact",
              "class": "future_dated",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": {}
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidArtifact)));
    }

    #[test]
    fn rejects_non_object_artifact() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "scalar-artifact",
              "class": "future_dated",
              "expected_verdict": "DENY",
              "expected_reason": "capability_not_yet_valid",
              "threat_id": "capability_token_theft",
              "pending": false,
              "artifact": "not-an-object"
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidArtifact)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "extra-field",
              "class": "replayed_nonce",
              "expected_verdict": "DENY",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" },
              "unexpected": true
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::Json(_))));
    }

    #[test]
    fn rejects_unsupported_schema_versions() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 2,
              "id": "future-version",
              "class": "replayed_nonce",
              "expected_verdict": "DENY",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::UnsupportedSchemaVersion(2))));
    }

    #[test]
    fn rejects_non_deny_verdicts() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "allow-verdict",
              "class": "replayed_nonce",
              "expected_verdict": "ALLOW",
              "expected_reason": "nonce_replayed",
              "threat_id": "native_channel_replay",
              "pending": false,
              "artifact": { "nonce": "n-1" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::Json(_))));
    }

    #[test]
    fn rejects_malformed_ids() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "Bad ID",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidCaseId(_))));
    }

    #[test]
    fn rejects_malformed_threat_ids() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-threat-id",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "Bad Threat",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidThreatId(_))));
    }

    #[test]
    fn rejects_padded_expected_reason() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-reason",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": " scope_superset ",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidExpectedReason(_))));
    }

    #[test]
    fn rejects_control_character_expected_reason() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "bad-reason-control",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset\nadmin",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" }
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::InvalidExpectedReason(_))));
    }

    #[test]
    fn rejects_empty_notes() {
        let err = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "empty-note",
              "class": "scope_superset",
              "expected_verdict": "DENY",
              "expected_reason": "scope_superset",
              "threat_id": "delegation_chain_abuse",
              "pending": false,
              "artifact": { "scope": "*" },
              "notes": [""]
            }"#,
        )
        .err();

        assert!(matches!(err, Some(CaseError::EmptyField("notes"))));
    }

    #[test]
    fn pending_cases_are_not_coverage_eligible() -> Result<(), CaseError> {
        let case = AdversarialCase::from_slice(
            br#"{
              "schema_version": 1,
              "id": "pending-crash",
              "class": "anchor_grafted",
              "expected_verdict": "DENY",
              "expected_reason": "anchor_grafted",
              "threat_id": "delegation_chain_abuse",
              "pending": true,
              "artifact": { "anchor": "pending" }
            }"#,
        )?;

        assert!(matches!(
            case.into_coverage_case(),
            Err(CaseError::PendingCase(id)) if id == "pending-crash"
        ));
        Ok(())
    }

    #[test]
    fn bundled_cases_are_valid_and_closed_cases_are_coverage_eligible() -> Result<(), CaseError> {
        let cases = bundled_cases()?;
        assert_eq!(cases.len(), BUNDLED_CASES.len());
        for case in cases {
            assert_eq!(case.expected_verdict, ExpectedVerdict::Deny);
            assert!(!case.expected_reason.trim().is_empty());
            assert!(!case.threat_id.trim().is_empty());
            assert!(case
                .artifact
                .as_object()
                .is_some_and(|object| !object.is_empty()));
            if case.pending {
                continue;
            }
            case.into_coverage_case()?;
        }
        Ok(())
    }

    /// Every non-pending bundled case must cite a
    /// `threat_id` that exists in
    /// `spec/security/chio-threat-model.v1.json`. Vectors with
    /// `pending: true` are auto-promoted from libFuzzer crashes
    /// and are excepted from the citation gate until a human
    /// triages them and strips the flag.
    #[test]
    fn every_non_pending_case_cites_a_known_threat_id() -> Result<(), CaseError> {
        const THREAT_MODEL_JSON: &str =
            include_str!("../../../../spec/security/chio-threat-model.v1.json");
        let doc: serde_json::Value =
            serde_json::from_str(THREAT_MODEL_JSON).expect("threat-model JSON parses");
        let known: std::collections::BTreeSet<String> = doc
            .get("threats")
            .and_then(serde_json::Value::as_array)
            .map(|threats| {
                threats
                    .iter()
                    .filter_map(|t| t.get("id").and_then(serde_json::Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            !known.is_empty(),
            "threat-model JSON must enumerate at least one threat ID"
        );

        for case in bundled_cases()? {
            if case.pending {
                continue;
            }
            assert!(
                known.contains(&case.threat_id),
                "case {:?} cites threat_id {:?} which is not in chio-threat-model.v1.json",
                case.id,
                case.threat_id
            );
        }
        Ok(())
    }
}
