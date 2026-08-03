use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::{canonical_json_bytes, Keypair};
use chio_test_support::prelude::*;

const PROFILE: &str = "chio.aggregate-family-invocation.v1";

fn quota(maximum: u32) -> PartitionEscrowQuota {
    PartitionEscrowQuota::new(PROFILE, "11".repeat(32), None, maximum).test_expect("valid quota")
}

fn allocations(left: u32, right: u32) -> Vec<PartitionEscrowAllocation> {
    vec![
        PartitionEscrowAllocation::new("partition-a", "authority-a", left)
            .test_expect("left allocation"),
        PartitionEscrowAllocation::new("partition-b", "authority-b", right)
            .test_expect("right allocation"),
    ]
}

fn plan(
    quota: PartitionEscrowQuota,
    source_expires_at: u64,
    allocations: Vec<PartitionEscrowAllocation>,
) -> PartitionEscrowAllocationPlan {
    PartitionEscrowAllocationPlan::new(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            "allocation-root-1",
            7,
            quota,
            source_expires_at,
            100,
            200,
        )
        .test_expect("valid plan binding"),
        allocations,
    )
    .test_expect("valid allocation plan")
}

fn source_binding(
    artifact_digest_byte: &str,
    trust_digest_byte: &str,
    expires_at: u64,
) -> PartitionEscrowQuotaSourceBinding {
    PartitionEscrowQuotaSourceBinding::new(
        artifact_digest_byte.repeat(32),
        trust_digest_byte.repeat(32),
        90,
        expires_at,
    )
    .test_expect("valid source binding")
}

fn commitment_for_plan(
    key: &Keypair,
    plan: &PartitionEscrowAllocationPlan,
    source: PartitionEscrowQuotaSourceBinding,
) -> SignedPartitionEscrowQuotaCommitment {
    SignedPartitionEscrowQuotaCommitment::sign(
        PartitionEscrowQuotaCommitmentBody::new(plan, source).test_expect("valid commitment body"),
        key,
    )
    .test_expect("signed commitment")
}

fn commitment(
    key: &Keypair,
    quota: PartitionEscrowQuota,
    artifact_digest_byte: &str,
    trust_digest_byte: &str,
) -> SignedPartitionEscrowQuotaCommitment {
    let plan = plan(quota, 250, allocations(4, 6));
    commitment_for_plan(
        key,
        &plan,
        source_binding(artifact_digest_byte, trust_digest_byte, 250),
    )
}

fn certificate(
    key: &Keypair,
    quota: PartitionEscrowQuota,
) -> VerifiedPartitionEscrowQuotaCertificate {
    verify_partition_escrow_quota_commitment(&commitment(key, quota, "aa", "bb"), 100)
        .test_expect("verified certificate")
}

fn context(
    quota_certificate: &VerifiedPartitionEscrowQuotaCertificate,
) -> PartitionEscrowAllocationVerificationContext {
    PartitionEscrowAllocationVerificationContext::new(
        "partition-a",
        "authority-a",
        quota_certificate,
    )
    .test_expect("valid allocation verification context")
}

fn signed_set(
    key: &Keypair,
    quota_certificate: &VerifiedPartitionEscrowQuotaCertificate,
) -> SignedPartitionEscrowAllocationSet {
    SignedPartitionEscrowAllocationSet::sign(
        PartitionEscrowAllocationSetBody::new(quota_certificate, 100, 200, allocations(4, 6))
            .test_expect("valid allocation body"),
        key,
    )
    .test_expect("signed allocation set")
}

#[test]
fn signed_allocation_set_round_trips_and_binds_local_cap() {
    let key = Keypair::from_seed(&[41; 32]);
    let quota_certificate = certificate(&key, quota(10));
    let signed = signed_set(&key, &quota_certificate);
    let canonical = signed.canonical_bytes().test_expect("canonical allocation");
    let decoded = SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(&canonical)
        .test_expect("decoded allocation");
    let verified: VerifiedPartitionEscrowAllocation = verify_partition_escrow_allocation_set(
        &decoded,
        &context(&quota_certificate),
        150,
        Some(&signed.digest().test_expect("allocation digest")),
    )
    .test_expect("verified allocation");

    assert_eq!(verified.local_allocated_invocations(), 4);
    assert_eq!(verified.total_allocated_invocations(), 10);
    assert_eq!(
        verified.quota_certificate_binding_digest(),
        quota_certificate
            .binding_digest()
            .test_expect("certificate binding")
    );
    assert_eq!(
        verified.quota_commitment_digest(),
        quota_certificate.commitment_digest()
    );
    assert_eq!(
        verified.underlying_source_artifact_digest(),
        quota_certificate.underlying_source_artifact_digest()
    );
    assert_eq!(
        verified.source_trust_binding_digest(),
        quota_certificate.source_trust_binding_digest()
    );
    assert_eq!(
        verified.allocation_plan_digest(),
        quota_certificate.allocation_plan_digest()
    );
    assert_eq!(
        decoded.signing_bytes().test_expect("decoded signing bytes"),
        signed.signing_bytes().test_expect("signed signing bytes")
    );
}

#[test]
fn core_certificate_is_cryptographic_evidence_not_source_authority() {
    let attacker = Keypair::from_seed(&[38; 32]);
    let signed = commitment(&attacker, quota(10), "aa", "bb");
    let certificate = verify_partition_escrow_quota_commitment(&signed, 100)
        .test_expect("cryptographic certificate");

    assert_eq!(certificate.certificate_signer(), &attacker.public_key());
    assert_eq!(
        certificate.underlying_source_artifact_digest(),
        "aa".repeat(32)
    );
    assert_eq!(certificate.source_trust_binding_digest(), "bb".repeat(32));
}

#[test]
fn source_digest_and_trust_binding_are_not_substitutable() {
    let key = Keypair::from_seed(&[37; 32]);
    let expected = commitment(&key, quota(10), "aa", "bb");
    let certificate = verify_partition_escrow_quota_commitment(&expected, 100)
        .test_expect("expected certificate");
    let wrong_source = commitment(&key, quota(10), "cc", "bb");
    let wrong_trust = commitment(&key, quota(10), "aa", "dd");

    assert_eq!(
        certificate
            .verify_commitment(&wrong_source)
            .test_expect_err("wrong source digest"),
        PartitionEscrowValidationError::UnderlyingSourceDigestMismatch
    );
    assert_eq!(
        certificate
            .verify_commitment(&wrong_trust)
            .test_expect_err("wrong trust binding"),
        PartitionEscrowValidationError::SourceTrustBindingMismatch
    );
    assert_ne!(
        expected.digest().test_expect("expected digest"),
        wrong_source.digest().test_expect("wrong source digest")
    );
    assert_ne!(
        expected.digest().test_expect("expected digest"),
        wrong_trust.digest().test_expect("wrong trust digest")
    );
}

#[test]
fn structural_load_and_fresh_admission_use_distinct_result_types() {
    let key = Keypair::from_seed(&[40; 32]);
    let quota_certificate = certificate(&key, quota(10));
    let signed = signed_set(&key, &quota_certificate);

    let structural: StructurallyVerifiedPartitionEscrowAllocation =
        verify_partition_escrow_allocation_set_structure(
            &signed,
            &context(&quota_certificate),
            Some(&signed.digest().test_expect("allocation digest")),
        )
        .test_expect("structural allocation");
    assert_eq!(
        structural.allocation_plan_digest(),
        quota_certificate.allocation_plan_digest()
    );
    assert_eq!(
        verify_partition_escrow_allocation_set(&signed, &context(&quota_certificate), 200, None,)
            .test_expect_err("expired allocation"),
        PartitionEscrowValidationError::Expired
    );
}

#[test]
fn allocation_plan_commits_complete_cross_partition_state() {
    let key = Keypair::from_seed(&[39; 32]);
    let quota_certificate = certificate(&key, quota(10));

    assert_eq!(
        PartitionEscrowAllocationSetBody::new(&quota_certificate, 100, 200, allocations(3, 7),)
            .test_expect_err("changed complete allocation plan"),
        PartitionEscrowValidationError::AllocationPlanDigestMismatch
    );
}

#[test]
fn allocation_sum_uses_wide_checked_arithmetic() {
    let error = PartitionEscrowAllocationPlan::new(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            "allocation-root-1",
            7,
            quota(u32::MAX),
            250,
            100,
            200,
        )
        .test_expect("wide-sum plan binding"),
        allocations(u32::MAX, 1),
    )
    .test_expect_err("allocation sum above u32 maximum");
    assert_eq!(
        error,
        PartitionEscrowValidationError::AllocationSumExceeded {
            allocated: u64::from(u32::MAX) + 1,
            maximum: u32::MAX,
        }
    );
}

#[test]
fn logical_quota_key_excludes_maximum_while_descriptor_binds_it() {
    let lower = quota(10);
    let higher = quota(11);

    assert_eq!(
        lower.key_digest().test_expect("lower key"),
        higher.key_digest().test_expect("higher key")
    );
    assert_ne!(
        lower.descriptor_digest().test_expect("lower descriptor"),
        higher.descriptor_digest().test_expect("higher descriptor")
    );
}

#[test]
fn derived_quota_owner_shapes_match_authoritative_budget_keys() {
    assert_eq!(
        PartitionEscrowQuota::new(PROFILE, "family-root", None, 10)
            .test_expect_err("invalid family owner"),
        PartitionEscrowValidationError::InvalidDigest("derived quota owner id")
    );
    assert_eq!(
        PartitionEscrowQuota::new(
            "chio.broker-capability-execution.v1",
            "broker-root",
            None,
            10,
        )
        .test_expect_err("invalid broker owner"),
        PartitionEscrowValidationError::InvalidDigest("derived quota owner id")
    );
    PartitionEscrowQuota::new(
        "chio.aggregate-capability-invocation.v1",
        "capability-id",
        None,
        10,
    )
    .test_expect("valid capability aggregate owner");
}

#[test]
fn partition_and_authority_ids_are_globally_unique() {
    let duplicate_partition = vec![
        PartitionEscrowAllocation::new("partition-a", "authority-a", 1)
            .test_expect("first duplicate-partition allocation"),
        PartitionEscrowAllocation::new("partition-a", "authority-b", 1)
            .test_expect("second duplicate-partition allocation"),
    ];
    assert_eq!(
        PartitionEscrowAllocationPlan::new(
            PartitionEscrowAllocationPlanBinding::new(
                "production",
                "allocation-root-1",
                7,
                quota(2),
                250,
                100,
                200,
            )
            .test_expect("duplicate-partition plan binding"),
            duplicate_partition,
        )
        .test_expect_err("duplicate partition"),
        PartitionEscrowValidationError::DuplicatePartitionId
    );

    let duplicate_authority = vec![
        PartitionEscrowAllocation::new("partition-a", "authority-a", 1)
            .test_expect("first duplicate-authority allocation"),
        PartitionEscrowAllocation::new("partition-b", "authority-a", 1)
            .test_expect("second duplicate-authority allocation"),
    ];
    assert_eq!(
        PartitionEscrowAllocationPlan::new(
            PartitionEscrowAllocationPlanBinding::new(
                "production",
                "allocation-root-1",
                7,
                quota(2),
                250,
                100,
                200,
            )
            .test_expect("duplicate-authority plan binding"),
            duplicate_authority,
        )
        .test_expect_err("duplicate authority"),
        PartitionEscrowValidationError::DuplicateAuthorityId
    );
}

#[test]
fn certificate_and_allocation_pins_fail_closed() {
    let key = Keypair::from_seed(&[42; 32]);
    let other = Keypair::from_seed(&[43; 32]);
    let quota_certificate = certificate(&key, quota(10));
    let signed = signed_set(&key, &quota_certificate);
    let body =
        PartitionEscrowAllocationSetBody::new(&quota_certificate, 100, 200, allocations(4, 6))
            .test_expect("valid allocation body");
    let wrong_signer = SignedPartitionEscrowAllocationSet::sign(body, &other)
        .test_expect("wrong-signer allocation");

    assert_eq!(
        verify_partition_escrow_allocation_set(
            &wrong_signer,
            &context(&quota_certificate),
            150,
            None,
        )
        .test_expect_err("wrong allocation signer"),
        PartitionEscrowValidationError::SignerMismatch
    );
    assert_eq!(
        verify_partition_escrow_allocation_set(
            &signed,
            &context(&quota_certificate),
            150,
            Some(&"00".repeat(32)),
        )
        .test_expect_err("wrong allocation pin"),
        PartitionEscrowValidationError::AllocationSetDigestMismatch
    );
}

#[test]
fn certificate_freshness_is_not_reusable_after_expiry() {
    let key = Keypair::from_seed(&[44; 32]);
    let signed = commitment(&key, quota(10), "aa", "bb");
    assert_eq!(
        verify_partition_escrow_quota_commitment(&signed, 250)
            .test_expect_err("expired certificate"),
        PartitionEscrowValidationError::Expired
    );
}

#[test]
fn allocation_cannot_outlive_certificate_source_window() {
    assert_eq!(
        PartitionEscrowAllocationPlanBinding::new(
            "production",
            "allocation-root-1",
            7,
            quota(10),
            175,
            100,
            200,
        )
        .test_expect_err("plan binding outlives source"),
        PartitionEscrowValidationError::AllocationOutlivesQuotaAuthority
    );
}

#[test]
fn canonical_decoders_compare_typed_reserialization() {
    let key = Keypair::from_seed(&[45; 32]);
    let signed_commitment = commitment(&key, quota(10), "aa", "bb");
    let commitment_pretty =
        serde_json::to_vec_pretty(&signed_commitment).test_expect("pretty commitment");
    assert_eq!(
        SignedPartitionEscrowQuotaCommitment::from_canonical_json_bytes(&commitment_pretty)
            .test_expect_err("non-canonical commitment"),
        PartitionEscrowValidationError::NonCanonicalEnvelope
    );

    let quota_certificate = verify_partition_escrow_quota_commitment(&signed_commitment, 100)
        .test_expect("verified commitment");
    let signed_set = signed_set(&key, &quota_certificate);
    let pretty = serde_json::to_vec_pretty(&signed_set).test_expect("pretty allocation");
    assert_eq!(
        SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(&pretty)
            .test_expect_err("non-canonical allocation"),
        PartitionEscrowValidationError::NonCanonicalEnvelope
    );

    let mut alternate = serde_json::to_value(&signed_set).test_expect("allocation value");
    alternate["body"]["quota"]["grantIndex"] = serde_json::Value::Null;
    let canonical_alternate = canonical_json_bytes(&alternate).test_expect("canonical alternate");
    assert_eq!(
        SignedPartitionEscrowAllocationSet::from_canonical_json_bytes(&canonical_alternate)
            .test_expect_err("typed canonical mismatch"),
        PartitionEscrowValidationError::NonCanonicalEnvelope
    );
}
