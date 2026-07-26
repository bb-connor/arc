use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::partition_escrow::{
    PartitionEscrowAllocation, PartitionEscrowAllocationPlan, PartitionEscrowAllocationPlanBinding,
    PartitionEscrowAllocationSetBody, PartitionEscrowQuota, PartitionEscrowQuotaCommitmentBody,
    PartitionEscrowQuotaSourceBinding, SignedPartitionEscrowAllocationSet,
    SignedPartitionEscrowQuotaCommitment,
};
use chio_core_types::Keypair;
use chio_test_support::prelude::*;

use super::source::{
    source_trust_matches_quota, test_source_trust_binding_digest,
    PartitionEscrowSourceTrustEvidence,
};
use super::*;
use crate::budget_store::{BudgetQuotaProfile, VerifiedInvocationAdmission};
use crate::threshold_approval::authorization_capability_hash;

struct GrantFixture {
    key: Keypair,
    capability: CapabilityToken,
    admission: VerifiedInvocationAdmission,
    commitment: SignedPartitionEscrowQuotaCommitment,
    allocation_set: SignedPartitionEscrowAllocationSet,
}

fn local_authority_id() -> String {
    "71".repeat(32)
}

fn allocations(local: u32, remote: u32) -> Vec<PartitionEscrowAllocation> {
    let authority_id = local_authority_id();
    vec![
        PartitionEscrowAllocation::new("partition-a", &authority_id, local)
            .test_expect("local allocation"),
        PartitionEscrowAllocation::new("partition-b", "authority-b", remote)
            .test_expect("remote allocation"),
    ]
}

fn grant_fixture(seed: u8, capability_id: &str, maximum: u32, local: u32) -> GrantFixture {
    let key = Keypair::from_seed(&[seed; 32]);
    let subject = Keypair::from_seed(&[seed.saturating_add(1); 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: key.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 90,
            expires_at: 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &key,
    )
    .test_expect("signed capability");
    let admission = VerifiedInvocationAdmission::grant_only(capability_id, 0, Some(maximum))
        .test_expect("verified grant admission");
    let quota =
        PartitionEscrowQuota::new("chio.grant-invocation.v1", capability_id, Some(0), maximum)
            .test_expect("partition escrow grant quota");
    let remote = maximum.saturating_sub(local);
    let plan = PartitionEscrowAllocationPlan::new(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            format!("root-{capability_id}"),
            1,
            quota.clone(),
            capability.expires_at,
            100,
            250,
        )
        .test_expect("allocation plan binding"),
        allocations(local, remote),
    )
    .test_expect("allocation plan");
    let artifact_digest =
        authorization_capability_hash(&capability).test_expect("capability artifact digest");
    let trust_evidence = PartitionEscrowSourceTrustEvidence::GrantCapability {
        capability_id: capability_id.to_string(),
        grant_index: 0,
        revocation_set_digest: admission.revocation_set().digest().to_string(),
    };
    let trust_digest = test_source_trust_binding_digest(
        &quota,
        &artifact_digest,
        &capability.issuer,
        capability.issued_at,
        capability.expires_at,
        &trust_evidence,
    )
    .test_expect("source trust digest");
    let commitment = SignedPartitionEscrowQuotaCommitment::sign(
        PartitionEscrowQuotaCommitmentBody::new(
            &plan,
            PartitionEscrowQuotaSourceBinding::new(
                artifact_digest,
                trust_digest,
                capability.issued_at,
                capability.expires_at,
            )
            .test_expect("source binding"),
        )
        .test_expect("commitment body"),
        &key,
    )
    .test_expect("quota commitment");
    let source = verify_grant_partition_escrow_source(&commitment, &capability, &admission, 0, 100)
        .test_expect("grant partition escrow source");
    let allocation_set = SignedPartitionEscrowAllocationSet::sign(
        PartitionEscrowAllocationSetBody::new(
            source.certificate(),
            100,
            250,
            allocations(local, remote),
        )
        .test_expect("allocation set body"),
        &key,
    )
    .test_expect("signed allocation set");
    GrantFixture {
        key,
        capability,
        admission,
        commitment,
        allocation_set,
    }
}

fn entry(fixture: &GrantFixture) -> PartitionEscrowRegistryEntryInput {
    PartitionEscrowRegistryEntryInput {
        quota_commitment: fixture.commitment.clone(),
        allocation_set: fixture.allocation_set.clone(),
    }
}

fn registry_input(entries: Vec<PartitionEscrowRegistryEntryInput>) -> PartitionEscrowRegistryInput {
    let authority_id = local_authority_id();
    let counter_namespace_digest =
        partition_escrow_counter_namespace_digest("partition-a", &authority_id)
            .test_expect("counter namespace digest");
    PartitionEscrowRegistryInput {
        authority_domain: "production".to_string(),
        partition_id: "partition-a".to_string(),
        authority_id: authority_id.clone(),
        resolver_id: "static-partition-escrow-registry".to_string(),
        resolver_implementation_id: "chio-kernel-static-partition-escrow".to_string(),
        resolver_implementation_version: 1,
        store_identity_digest: authority_id,
        counter_namespace_digest,
        fencing_token: 1,
        entries,
    }
}

fn registry(entries: Vec<PartitionEscrowRegistryEntryInput>) -> PartitionEscrowRegistry {
    PartitionEscrowRegistry::new(registry_input(entries)).test_expect("partition escrow registry")
}

fn source(
    fixture: &GrantFixture,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaSource, PartitionEscrowRegistryError> {
    verify_grant_partition_escrow_source(
        &fixture.commitment,
        &fixture.capability,
        &fixture.admission,
        0,
        now,
    )
}

#[test]
fn registry_yields_only_signed_local_maximum_and_complete_evidence() {
    let fixture = grant_fixture(51, "capability-a", 5, 2);
    let registry = registry(vec![entry(&fixture)]);
    let verified_source = source(&fixture, 150).test_expect("fresh source");
    let admission = registry
        .resolve(&[verified_source], 150)
        .test_expect("partition escrow admission");

    assert_eq!(admission.quotas().len(), 1);
    assert_eq!(admission.quotas()[0].global_quota().max_invocations(), 5);
    assert_eq!(admission.quotas()[0].local_quota().max_invocations(), 2);
    assert_eq!(
        admission.quotas()[0]
            .evidence()
            .local_allocated_invocations(),
        2
    );
    assert_eq!(admission.evidence().durable_store().fencing_token(), 1);
    assert_eq!(
        admission.evidence().digest().test_expect("evidence digest"),
        admission.evidence_digest()
    );
    registry
        .verify_persisted_admission(admission.evidence())
        .test_expect("persisted evidence");

    let canonical = admission
        .evidence()
        .canonical_bytes()
        .test_expect("canonical evidence");
    let decoded = PartitionEscrowAdmissionEvidence::from_canonical_json_bytes(&canonical)
        .test_expect("decoded evidence");
    assert_eq!(&decoded, admission.evidence());
}

#[test]
fn detached_certificate_with_wrong_underlying_source_cannot_activate() {
    let fixture = grant_fixture(52, "capability-b", 5, 2);
    let mut value = serde_json::to_value(&fixture.commitment).test_expect("commitment value");
    value["body"]["underlyingSourceArtifactDigest"] = serde_json::Value::String("ff".repeat(32));
    let body: PartitionEscrowQuotaCommitmentBody =
        serde_json::from_value(value["body"].clone()).test_expect("changed commitment body");
    let wrong = SignedPartitionEscrowQuotaCommitment::sign(body, &fixture.key)
        .test_expect("wrong-source commitment");

    assert!(matches!(
        verify_grant_partition_escrow_source(
            &wrong,
            &fixture.capability,
            &fixture.admission,
            0,
            150,
        ),
        Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "underlying source artifact digest"
        ))
    ));
}

#[test]
fn source_trust_digest_cannot_be_supplied_by_the_commitment() {
    let fixture = grant_fixture(53, "capability-c", 5, 2);
    let mut value = serde_json::to_value(&fixture.commitment).test_expect("commitment value");
    value["body"]["sourceTrustBindingDigest"] = serde_json::Value::String("ee".repeat(32));
    let body: PartitionEscrowQuotaCommitmentBody =
        serde_json::from_value(value["body"].clone()).test_expect("changed commitment body");
    let wrong = SignedPartitionEscrowQuotaCommitment::sign(body, &fixture.key)
        .test_expect("wrong-trust commitment");

    assert!(matches!(
        verify_grant_partition_escrow_source(
            &wrong,
            &fixture.capability,
            &fixture.admission,
            0,
            150,
        ),
        Err(PartitionEscrowRegistryError::SourceBindingMismatch(
            "kernel-derived source trust binding"
        ))
    ));
}

#[test]
fn source_trust_owner_and_profile_must_match_the_quota() {
    let owner = "42".repeat(32);
    let revocations = "43".repeat(32);
    let family = PartitionEscrowSourceTrustEvidence::AggregateFamily {
        root_capability_id: "family-root".to_string(),
        root_binding_digest: "44".repeat(32),
        family_owner: owner.clone(),
        revocation_set_digest: revocations.clone(),
    };
    let family_quota = PartitionEscrowQuota::new(
        BudgetQuotaProfile::AggregateFamilyInvocation.as_str(),
        &owner,
        None,
        5,
    )
    .test_expect("family quota");
    assert!(source_trust_matches_quota(&family_quota, &family));

    let different_owner = PartitionEscrowQuota::new(
        BudgetQuotaProfile::AggregateFamilyInvocation.as_str(),
        "45".repeat(32),
        None,
        5,
    )
    .test_expect("different family owner quota");
    assert!(!source_trust_matches_quota(&different_owner, &family));

    let broker = PartitionEscrowSourceTrustEvidence::BrokerCapability {
        verifier_id: "broker-verifier".to_string(),
        broker_capability_id: "broker-capability".to_string(),
        quota_owner_id: owner.clone(),
        request_constraint_digest: "46".repeat(32),
        request_binding_hash: "47".repeat(32),
        negotiated_features_digest: "48".repeat(32),
        claim_binding_digest: "49".repeat(32),
        revocation_set_digest: revocations,
    };
    let broker_quota = PartitionEscrowQuota::new(
        BudgetQuotaProfile::SupplementalBrokerExecution.as_str(),
        &owner,
        None,
        5,
    )
    .test_expect("broker quota");
    assert!(source_trust_matches_quota(&broker_quota, &broker));
    assert!(!source_trust_matches_quota(&family_quota, &broker));
}

#[test]
fn one_logical_quota_cannot_install_multiple_epochs_or_maxima() {
    let first = grant_fixture(54, "capability-d", 5, 2);
    let changed_maximum = grant_fixture(54, "capability-d", 6, 2);

    assert!(matches!(
        PartitionEscrowRegistry::new(registry_input(
            vec![entry(&first), entry(&changed_maximum),]
        )),
        Err(PartitionEscrowRegistryError::EquivocatingAllocationSet)
    ));
}

#[test]
fn source_and_allocation_are_rechecked_at_every_admission() {
    let fixture = grant_fixture(55, "capability-e", 5, 2);
    let registry = registry(vec![entry(&fixture)]);

    assert!(matches!(
        source(&fixture, 300),
        Err(PartitionEscrowRegistryError::SourceVerification(_))
    ));

    let source_at_150 = source(&fixture, 150).test_expect("source at 150");
    assert!(matches!(
        registry.resolve(&[source_at_150], 151),
        Err(PartitionEscrowRegistryError::SourceNotFresh)
    ));
}

#[test]
fn durable_store_identity_and_fence_must_match_signed_allocations() {
    let fixture = grant_fixture(56, "capability-f", 5, 2);
    let base = registry(vec![entry(&fixture)]);
    let mut changed_input = registry_input(vec![entry(&fixture)]);
    changed_input.fencing_token = 12;
    assert!(matches!(
        PartitionEscrowRegistry::new(changed_input),
        Err(PartitionEscrowRegistryError::DurableStoreBindingMismatch)
    ));
    assert!(!base.runtime_evidence().configuration_digest().is_empty());
}

#[test]
fn persisted_evidence_rejects_local_or_global_maximum_rebinding() {
    let fixture = grant_fixture(57, "capability-g", 5, 2);
    let registry = registry(vec![entry(&fixture)]);
    let verified_source = source(&fixture, 150).test_expect("fresh source");
    let admission = registry
        .resolve(&[verified_source], 150)
        .test_expect("partition escrow admission");

    let mut local = admission.evidence().clone();
    local.quotas[0].local_allocated_invocations = 5;
    assert!(matches!(
        registry.verify_persisted_admission(&local),
        Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch)
    ));

    let mut global = admission.evidence().clone();
    global.quotas[0].global_quota =
        PartitionEscrowQuota::new("chio.grant-invocation.v1", "capability-g", Some(0), 2)
            .test_expect("changed global quota");
    assert!(matches!(
        registry.verify_persisted_admission(&global),
        Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch)
    ));

    let mut source_owner = admission.evidence().clone();
    source_owner.quotas[0].source_trust = PartitionEscrowSourceTrustEvidence::AggregateCapability {
        capability_id: "capability-g".to_string(),
        revocation_set_digest: fixture.admission.revocation_set().digest().to_string(),
    };
    assert!(matches!(
        registry.verify_persisted_admission(&source_owner),
        Err(PartitionEscrowRegistryError::AdmissionEvidenceMismatch)
    ));
}
