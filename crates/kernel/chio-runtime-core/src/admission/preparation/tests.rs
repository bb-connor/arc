use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core_types::{crypto::Keypair, receipt::lineage::SignedExportEnvelope};

use super::*;
use crate::admission::commit_prepared_runtime_admission;
use crate::schema::*;
use crate::store::RuntimeAdmissionStore;
use crate::InMemoryRuntimeAdmissionStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type SignedPreparationPolicy = (
    SignedRuntimePheromonePolicy,
    SignedRuntimePeerWeights,
    SignedRuntimePheromoneQueryReport,
);

fn signed_preparation_policy(
    signer: &Keypair,
    trust: &RuntimeVerifierTrustBundleV4,
) -> TestResult<SignedPreparationPolicy> {
    let weights = RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_owned(),
        verifier_id: trust.verifier_id.clone(),
        key_id: trust.key_id.clone(),
        reputation_epoch: 7,
        issued_at_unix_ms: trust.issued_at_unix_ms,
        expires_at_unix_ms: trust.expires_at_unix_ms,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: "kernel-local".to_owned(),
            weight: 1.0,
        }],
    };
    let policy = RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_owned(),
        policy_id: "policy-preparation".to_owned(),
        verifier_id: trust.verifier_id.clone(),
        key_id: trust.key_id.clone(),
        policy_version: 1,
        mode: "enforce".to_owned(),
        issued_at_unix_ms: trust.issued_at_unix_ms,
        expires_at_unix_ms: trust.expires_at_unix_ms,
        allowed_reputation_epochs: vec![7],
        max_query_report_age_ms: 1_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: trust.trust_bundle_sha256.clone(),
        peer_weights_sha256: crate::runtime_peer_weights_sha256(&weights)?,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-destructive-risk".to_owned(),
            subject_class: "workflow.destructive_step".to_owned(),
            subject_class_namespace: "chio.runtime".to_owned(),
            action_class_id: "*".to_owned(),
            direction: "deny_if_at_or_above".to_owned(),
            threshold_total_strength: 0.75,
            effect: "deny".to_owned(),
        }],
    };
    let query_report = serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": true,
        "concentration": {
            "subjectClass": "workflow.destructive_step",
            "subjectClassNamespace": "chio.runtime",
            "totalStrength": 0.10,
            "distinctOriginPairs": 1,
            "reputationEpoch": 7,
            "evaluatedAtUnixMs": 2_000
        }
    });
    Ok((
        SignedExportEnvelope::sign(policy, signer)?,
        SignedExportEnvelope::sign(weights, signer)?,
        SignedExportEnvelope::sign(query_report, signer)?,
    ))
}

#[derive(Default)]
struct CallbackCountingStore {
    inner: InMemoryRuntimeAdmissionStore,
    calls: AtomicUsize,
}

impl RuntimeAdmissionStore for CallbackCountingStore {
    fn bundle(&self, id: &str) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.bundle(id)
    }

    fn consume_destructive_lease(&self, id: &str, admission: &str) -> Result<(), ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.consume_destructive_lease(id, admission)
    }

    fn release_destructive_lease(&self, id: &str, admission: &str) -> Result<(), ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.release_destructive_lease(id, admission)
    }

    fn runtime_trust_floor(
        &self,
        verifier: &str,
        key: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.runtime_trust_floor(verifier, key)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
            &self.inner,
            entry,
            previous_hash_sha256,
        )
    }
}

fn prepare_owned(store: &dyn RuntimeAdmissionStore) -> TestResult<PreparedRuntimeAdmission> {
    prepare_owned_with_destructive(store, false)
}

fn prepare_owned_with_destructive(
    store: &dyn RuntimeAdmissionStore,
    destructive: bool,
) -> TestResult<PreparedRuntimeAdmission> {
    let signer = Keypair::generate();
    let profile = RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-preparation".to_string(),
        local_kernel_id: "kernel-local".to_string(),
        verifier_id: "verifier-preparation".to_string(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 3_000,
    };
    let binding = RuntimeRequestBinding {
        request_id: "request-preparation".to_string(),
        capability_id: "capability-preparation".to_string(),
        server_id: "server-preparation".to_string(),
        tool_name: if destructive { "mutate" } else { "read" }.to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: None,
        host_kernel_id: profile.local_kernel_id.clone(),
    };
    let bundle = RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "admission-preparation".to_string(),
        binding: binding.clone(),
        workflow_id: "workflow-preparation".to_string(),
        workflow_grant_id: "grant-preparation".to_string(),
        step_index: 0,
        destructive,
        lease_id: destructive.then(|| "lease-preparation".to_string()),
        governance_receipt_id: destructive.then(|| "governance-preparation".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    };
    let trust = SignedExportEnvelope::sign(
        RuntimeVerifierTrustBundleV4 {
            schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
            verifier_id: profile.verifier_id.clone(),
            key_id: "key-preparation".to_string(),
            version: 1,
            previous_hash_sha256: None,
            trust_bundle_sha256: bundle.trust_bundle_sha256.clone(),
            verification_context_sha256: bundle.verification_context_sha256.clone(),
            revocation_checkpoint_sha256: "d".repeat(64),
            revocation_authority_roots: vec!["revocation-authority".to_string()],
            issued_at_unix_ms: profile.issued_at_unix_ms,
            expires_at_unix_ms: profile.expires_at_unix_ms,
        },
        &signer,
    )?;
    let keys = [RuntimeTrustedVerifierKey {
        verifier_id: profile.verifier_id.clone(),
        key_id: trust.body.key_id.clone(),
        public_key: signer.public_key(),
        valid_from_unix_ms: profile.issued_at_unix_ms,
        valid_until_unix_ms: profile.expires_at_unix_ms,
        status: "active".to_string(),
    }];
    let policy = destructive
        .then(|| signed_preparation_policy(&signer, &trust.body))
        .transpose()?;
    match prepare_runtime_admission_from_bundle(
        RuntimeAdmissionInput {
            profile: &profile,
            store,
            admission_id: "admission-preparation",
            request: &binding,
            action_class_id: None,
            runtime_trust_input: Some(&trust),
            trusted_verifier_keys: &keys,
            pheromone_query_report: policy.as_ref().map(|inputs| &inputs.2),
            runtime_pheromone_policy: policy.as_ref().map(|inputs| &inputs.0),
            runtime_peer_weights: policy.as_ref().map(|inputs| &inputs.1),
            now_unix_ms: 2_000,
        },
        Some(bundle),
    )? {
        RuntimeAdmissionPreparation::Prepared(prepared) => Ok(prepared),
        RuntimeAdmissionPreparation::Rejected(report) => {
            Err(std::io::Error::other(format!("preparation rejected: {report:?}")).into())
        }
    }
}

#[test]
fn supplied_bundle_preparation_and_drop_do_not_call_store() -> TestResult {
    let store = CallbackCountingStore::default();
    let prepared = prepare_owned(&store)?;
    assert!(prepared.trust_floor_update.is_some());
    assert!(prepared.checks.iter().all(|check| {
        check.code != "destructive.lease_reserved" && check.code != "runtime_trust.floor"
    }));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    drop(prepared);
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    assert!(store
        .inner
        .runtime_trust_floor("verifier-preparation", "key-preparation")?
        .is_none());
    Ok(())
}

#[test]
fn destructive_preparation_and_drop_never_reserve_or_claim_the_lease() -> TestResult {
    let store = CallbackCountingStore::default();
    let prepared = prepare_owned_with_destructive(&store, true)?;
    assert!(prepared.bundle.destructive);
    assert!(prepared
        .policy_decision
        .as_ref()
        .is_some_and(|decision| decision.enforced && decision.decision == "allow"));
    for code in [
        "runtime_policy.signature",
        "runtime_pheromone_query_report.signature",
        "runtime_peer_weights.signature",
        "runtime_policy.bindings",
    ] {
        assert!(prepared.checks.iter().any(|check| check.code == code));
    }
    assert_eq!(
        prepared.bundle.lease_id.as_deref(),
        Some("lease-preparation")
    );
    assert!(prepared.trust_floor_update.is_some());
    assert!(prepared.checks.iter().all(|check| {
        check.code != "destructive.lease_reserved" && check.code != "runtime_trust.floor"
    }));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    drop(prepared);
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    assert!(store
        .inner
        .runtime_trust_floor("verifier-preparation", "key-preparation")?
        .is_none());
    store
        .inner
        .consume_destructive_lease("lease-preparation", "admission-preparation")?;
    store
        .inner
        .release_destructive_lease("lease-preparation", "admission-preparation")?;
    Ok(())
}

#[test]
fn commit_uses_owned_inputs_after_preparation_locals_are_dropped() -> TestResult {
    let store = CallbackCountingStore::default();
    let prepared = prepare_owned(&store)?;
    let report = commit_prepared_runtime_admission(prepared, &store, None)?;
    assert!(report.accepted);
    assert_eq!(report.admission_id, "admission-preparation");
    assert_eq!(report.receipt_metadata["chio_runtime"]["accepted"], true);
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    let floor = store
        .inner
        .runtime_trust_floor("verifier-preparation", "key-preparation")?
        .ok_or_else(|| std::io::Error::other("committed trust floor missing"))?;
    assert_eq!(floor.highest_version, 1);
    Ok(())
}

#[test]
fn commit_rechecks_trust_floor_advanced_after_preparation() -> TestResult {
    let store = CallbackCountingStore::default();
    let prepared = prepare_owned(&store)?;
    let mut advanced = prepared
        .trust_floor_update
        .as_ref()
        .ok_or_else(|| std::io::Error::other("prepared trust floor missing"))?
        .0
        .clone();
    advanced.highest_version = 2;
    advanced.latest_bundle_sha256 = "e".repeat(64);
    store.inner.record_runtime_trust_floor(advanced.clone())?;

    let report = commit_prepared_runtime_admission(prepared, &store, None)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_trust_rollback")
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .inner
            .runtime_trust_floor("verifier-preparation", "key-preparation")?,
        Some(advanced)
    );
    Ok(())
}

#[test]
fn destructive_commit_releases_lease_when_trust_floor_advanced_after_preparation() -> TestResult {
    let store = CallbackCountingStore::default();
    let prepared = prepare_owned_with_destructive(&store, true)?;
    let mut advanced = prepared
        .trust_floor_update
        .as_ref()
        .ok_or_else(|| std::io::Error::other("prepared trust floor missing"))?
        .0
        .clone();
    advanced.highest_version = 2;
    advanced.latest_bundle_sha256 = "e".repeat(64);
    store.inner.record_runtime_trust_floor(advanced.clone())?;
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);

    let report = commit_prepared_runtime_admission(prepared, &store, None)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_trust_rollback")
    );
    assert!(report.receipt_metadata["chio_runtime"]
        .get("reserved_destructive_lease_id")
        .is_none());
    assert!(report.receipt_metadata["chio_runtime"]
        .get("reservation_release_failed")
        .is_none());
    // The destructive consume was acknowledged, the atomic floor transition
    // rejected stale input, and the owned lease was released exactly once.
    assert_eq!(store.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        store
            .inner
            .runtime_trust_floor("verifier-preparation", "key-preparation")?,
        Some(advanced)
    );
    store
        .inner
        .consume_destructive_lease("lease-preparation", "admission-preparation")?;
    store
        .inner
        .release_destructive_lease("lease-preparation", "admission-preparation")?;
    Ok(())
}
