use super::*;
use chio_test_support::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    aggregate_budget::{
        issue_aggregate_family_root, AggregateFamilyRootResolution,
        AggregateFamilyRootResolutionError, AggregateFamilyRootResolver, AggregateInvocationBudget,
        AggregateInvocationScope,
    },
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::ReceiptAttributionMetadata,
};
use chio_core::SigningAlgorithm;
use chio_kernel::{CapabilityAuthority, KernelError, ReceiptStore};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::{
    ReputationIssuancePolicy, ReputationTierPolicy, RuntimeAssuranceIssuancePolicy,
    RuntimeAssuranceTierPolicy, TierScopeCeiling,
};

fn unique_path(prefix: &str, extension: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{extension}"))
}

struct FixedCapabilityAuthority {
    capability: CapabilityToken,
    authority_public_key: chio_core::PublicKey,
    trusted_public_keys: Vec<chio_core::PublicKey>,
}

struct TrustMutatingAuthority {
    capability: CapabilityToken,
    initial_authority: chio_core::PublicKey,
    substituted_authority: chio_core::PublicKey,
    issued: AtomicBool,
}

impl CapabilityAuthority for TrustMutatingAuthority {
    fn authority_public_key(&self) -> chio_core::PublicKey {
        if self.issued.load(Ordering::SeqCst) {
            self.substituted_authority.clone()
        } else {
            self.initial_authority.clone()
        }
    }

    fn trusted_public_keys(&self) -> Vec<chio_core::PublicKey> {
        if self.issued.load(Ordering::SeqCst) {
            vec![self.substituted_authority.clone()]
        } else {
            Vec::new()
        }
    }

    fn issue_capability(
        &self,
        _subject: &chio_core::PublicKey,
        _scope: ChioScope,
        _ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        self.issued.store(true, Ordering::SeqCst);
        Ok(self.capability.clone())
    }
}

impl CapabilityAuthority for FixedCapabilityAuthority {
    fn authority_public_key(&self) -> chio_core::PublicKey {
        self.authority_public_key.clone()
    }

    fn trusted_public_keys(&self) -> Vec<chio_core::PublicKey> {
        self.trusted_public_keys.clone()
    }

    fn issue_capability(
        &self,
        _subject: &chio_core::PublicKey,
        _scope: ChioScope,
        _ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        Ok(self.capability.clone())
    }
}

fn delegable_root_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "root-server".to_string(),
            tool_name: "root-tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

#[test]
fn aggregate_family_root_issuance_persists_explicit_legacy_before_return() {
    let receipt_db_path = unique_path("issuance-legacy-root", ".sqlite3");
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(issuer)),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let capability = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect("delegable capability issuance");
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert!(matches!(
        store.resolve_aggregate_family_root(&capability.id),
        Ok(AggregateFamilyRootResolution::LegacyUnbound(_))
    ));

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn issuance_persists_aggregate_family_root_before_return() {
    let receipt_db_path = unique_path("issuance-family-root", ".sqlite3");
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let issued_at = unix_now();
    let capability = issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "issued-family-root".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: delegable_root_scope(),
            issued_at,
            expires_at: issued_at.checked_add(300).test_expect("family root expiry"),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        9,
        &issuer,
    )
    .test_expect("family root");
    let authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: capability.clone(),
            authority_public_key: issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let returned = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect("family-root issuance");
    assert_eq!(returned.id, capability.id);
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert!(matches!(
        store.resolve_aggregate_family_root(&returned.id),
        Ok(AggregateFamilyRootResolution::FamilyBound(root))
            if root.max_invocations() == 9
    ));

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn aggregate_family_root_nondelegable_and_generic_lineage_remain_missing() {
    let receipt_db_path = unique_path("issuance-nonroot", ".sqlite3");
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(issuer)),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "nonroot-server".to_string(),
            tool_name: "nonroot-tool".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let capability = authority
        .issue_capability(&subject.public_key(), scope, 300)
        .test_expect("nondelegable issuance");
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert_eq!(
        store.resolve_aggregate_family_root(&capability.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );

    let family_issuer = Keypair::generate();
    let family_subject = Keypair::generate();
    let family_issued_at = unix_now();
    let nondelegable_family = issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "nondelegable-family-root".to_string(),
            issuer: family_issuer.public_key(),
            subject: family_subject.public_key(),
            scope: ChioScope::default(),
            issued_at: family_issued_at,
            expires_at: family_issued_at
                .checked_add(300)
                .test_expect("nondelegable family expiry"),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        7,
        &family_issuer,
    )
    .test_expect("nondelegable family token");
    let family_authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: nondelegable_family.clone(),
            authority_public_key: family_issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );
    family_authority
        .issue_capability(&family_subject.public_key(), ChioScope::default(), 300)
        .test_expect("nondelegable family issuance");
    assert_eq!(
        store.resolve_aggregate_family_root(&nondelegable_family.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );

    let aggregate_issuer = Keypair::generate();
    let aggregate_subject = Keypair::generate();
    let aggregate_issued_at = unix_now();
    let capability_aggregate = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-aggregate-not-root".to_string(),
            issuer: aggregate_issuer.public_key(),
            subject: aggregate_subject.public_key(),
            scope: ChioScope::default(),
            issued_at: aggregate_issued_at,
            expires_at: aggregate_issued_at
                .checked_add(300)
                .test_expect("capability aggregate expiry"),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: Some(AggregateInvocationBudget {
                scope: AggregateInvocationScope::Capability,
                max_invocations: 7,
                root_binding: None,
            }),
        },
        &aggregate_issuer,
    )
    .test_expect("capability aggregate token");
    let aggregate_authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: capability_aggregate.clone(),
            authority_public_key: aggregate_issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );
    aggregate_authority
        .issue_capability(&aggregate_subject.public_key(), ChioScope::default(), 300)
        .test_expect("capability aggregate issuance");
    assert_eq!(
        store.resolve_aggregate_family_root(&capability_aggregate.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );

    let raw_issuer = Keypair::generate();
    let raw_subject = Keypair::generate();
    let raw_root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "generic-lineage-root".to_string(),
            issuer: raw_issuer.public_key(),
            subject: raw_subject.public_key(),
            scope: delegable_root_scope(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &raw_issuer,
    )
    .test_expect("generic root");
    store
        .record_capability_snapshot(&raw_root, None)
        .test_expect("generic lineage snapshot");
    assert_eq!(
        store.resolve_aggregate_family_root(&raw_root.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn aggregate_family_root_untrusted_issuance_rejects_before_lineage() {
    let receipt_db_path = unique_path("issuance-untrusted-root", ".sqlite3");
    let issuer = Keypair::generate();
    let advertised_authority = Keypair::generate();
    let subject = Keypair::generate();
    let capability = issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "untrusted-issued-family-root".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: delegable_root_scope(),
            issued_at: 1_000,
            expires_at: 1_300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        9,
        &issuer,
    )
    .test_expect("family root");
    let authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: capability.clone(),
            authority_public_key: advertised_authority.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let error = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect_err("untrusted family-root issuance must fail");
    assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert_eq!(
        store.resolve_aggregate_family_root(&capability.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );
    assert!(store
        .get_lineage(&capability.id)
        .test_expect("lineage query")
        .is_none());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn aggregate_family_root_issuance_binds_returned_token_to_request() {
    let receipt_db_path = unique_path("issuance-request-binding", ".sqlite3");
    let issuer = Keypair::generate();
    let token_subject = Keypair::generate();
    let requested_subject = Keypair::generate();
    let capability = issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "request-mismatched-family-root".to_string(),
            issuer: issuer.public_key(),
            subject: token_subject.public_key(),
            scope: delegable_root_scope(),
            issued_at: 1_000,
            expires_at: 1_300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        9,
        &issuer,
    )
    .test_expect("family root");
    let authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: capability.clone(),
            authority_public_key: issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let error = authority
        .issue_capability(&requested_subject.public_key(), delegable_root_scope(), 300)
        .test_expect_err("request-mismatched root must fail");
    assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
    assert!(error.to_string().contains("subject"));
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert_eq!(
        store.resolve_aggregate_family_root(&capability.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );
    assert!(store
        .get_lineage(&capability.id)
        .test_expect("lineage query")
        .is_none());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn capability_issuance_rejects_returned_scope_substitution_without_persistence() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "scope-substituted-capability".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 1_300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .test_expect("scope-substituted capability");
    let authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability,
            authority_public_key: issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        None,
        None,
    );

    let error = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect_err("scope substitution must fail without persistence");
    assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
    assert!(error.to_string().contains("scope"));
}

#[test]
fn capability_issuance_rejects_invalid_lifetime_envelopes() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    for (id, issued_at, expires_at) in [
        ("overlong-capability", 1_000, 1_301),
        ("zero-lifetime-capability", 1_000, 1_000),
        ("reversed-lifetime-capability", u64::MAX - 5, 4),
    ] {
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at,
                expires_at,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .test_expect("invalid-lifetime capability");
        let authority = wrap_capability_authority(
            Box::new(FixedCapabilityAuthority {
                capability,
                authority_public_key: issuer.public_key(),
                trusted_public_keys: Vec::new(),
            }),
            None,
            None,
            None,
            None,
        );

        let error = authority
            .issue_capability(&subject.public_key(), ChioScope::default(), 300)
            .test_expect_err("invalid lifetime must fail");
        assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
        assert!(error.to_string().contains("lifetime"));
    }
}

#[test]
fn capability_issuance_rejects_algorithm_and_signature_substitution() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let body = CapabilityTokenBody {
        id: "crypto-substituted-capability".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope::default(),
        issued_at: 1_000,
        expires_at: 1_300,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    let mut algorithm_substitution =
        CapabilityToken::sign(body.clone(), &issuer).test_expect("signed capability");
    algorithm_substitution.algorithm = Some(SigningAlgorithm::P256);
    let mut signature_substitution =
        CapabilityToken::sign(body, &issuer).test_expect("signed capability");
    signature_substitution.id = "signature-substituted-capability".to_string();

    for (capability, expected_reason) in [
        (algorithm_substitution, "algorithm"),
        (signature_substitution, "signature"),
    ] {
        let authority = wrap_capability_authority(
            Box::new(FixedCapabilityAuthority {
                capability,
                authority_public_key: issuer.public_key(),
                trusted_public_keys: Vec::new(),
            }),
            None,
            None,
            None,
            None,
        );
        let error = authority
            .issue_capability(&subject.public_key(), ChioScope::default(), 300)
            .test_expect_err("crypto substitution must fail");
        assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
        assert!(error.to_string().contains(expected_reason));
    }
}

#[test]
fn capability_issuance_uses_preissuance_trust_snapshot() {
    let initial_authority = Keypair::generate();
    let substituted_authority = Keypair::generate();
    let subject = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "trust-substituted-capability".to_string(),
            issuer: substituted_authority.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 1_300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &substituted_authority,
    )
    .test_expect("trust-substituted capability");
    let authority = wrap_capability_authority(
        Box::new(TrustMutatingAuthority {
            capability,
            initial_authority: initial_authority.public_key(),
            substituted_authority: substituted_authority.public_key(),
            issued: AtomicBool::new(false),
        }),
        None,
        None,
        None,
        None,
    );

    let error = authority
        .issue_capability(&subject.public_key(), ChioScope::default(), 300)
        .test_expect_err("post-issuance trust mutation must fail");
    assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
    assert!(error.to_string().contains("trusted authority snapshot"));
}

#[test]
fn aggregate_family_root_issuance_rejects_future_activation() {
    let receipt_db_path = unique_path("issuance-future-root", ".sqlite3");
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let issued_at = unix_now()
        .checked_add(86_400)
        .test_expect("future issuance time");
    let capability = issue_aggregate_family_root(
        CapabilityTokenBody {
            id: "future-issued-family-root".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: delegable_root_scope(),
            issued_at,
            expires_at: issued_at.checked_add(300).test_expect("future expiry time"),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        9,
        &issuer,
    )
    .test_expect("future family root");
    let authority = wrap_capability_authority(
        Box::new(FixedCapabilityAuthority {
            capability: capability.clone(),
            authority_public_key: issuer.public_key(),
            trusted_public_keys: Vec::new(),
        }),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let error = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect_err("future root must fail issuance");
    assert!(matches!(&error, KernelError::CapabilityIssuanceFailed(_)));
    assert!(error.to_string().contains("validity"));
    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    assert_eq!(
        store.resolve_aggregate_family_root(&capability.id),
        Err(AggregateFamilyRootResolutionError::Missing)
    );
    assert!(store
        .get_lineage(&capability.id)
        .test_expect("lineage query")
        .is_none());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn aggregate_family_root_issuance_capture_is_atomic_with_lineage() {
    let receipt_db_path = unique_path("issuance-atomic-root", ".sqlite3");
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
        let connection = rusqlite::Connection::open(&receipt_db_path).test_expect("connection");
        connection
            .execute_batch(
                "CREATE TRIGGER reject_issued_capability_lineage
                 BEFORE INSERT ON capability_lineage
                 BEGIN
                     SELECT RAISE(ABORT, 'lineage rejected');
                 END;",
            )
            .test_expect("lineage rejection trigger");
        drop(store);
    }
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(issuer)),
        None,
        None,
        Some(&receipt_db_path),
        None,
    );

    let error = authority
        .issue_capability(&subject.public_key(), delegable_root_scope(), 300)
        .test_expect_err("lineage failure must fail issuance atomically");
    assert!(matches!(error, KernelError::CapabilityIssuanceFailed(_)));
    let connection = rusqlite::Connection::open(&receipt_db_path).test_expect("connection");
    let root_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM chio_aggregate_family_roots",
            [],
            |row| row.get(0),
        )
        .test_expect("root count");
    let lineage_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM capability_lineage", [], |row| {
            row.get(0)
        })
        .test_expect("lineage count");
    assert_eq!(root_count, 0);
    assert_eq!(lineage_count, 0);

    let _ = fs::remove_file(receipt_db_path);
}

fn test_policy() -> ReputationIssuancePolicy {
    ReputationIssuancePolicy {
        scoring: chio_reputation::ReputationConfig {
            history_receipt_target: 10,
            history_day_target: 10,
            ..Default::default()
        },
        probationary_receipt_count: 10,
        probationary_min_days: 10,
        probationary_score_ceiling: 0.60,
        tiers: vec![
            ReputationTierPolicy {
                name: "probationary".to_string(),
                score_range: [0.0, 0.50],
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Read, Operation::Get],
                    max_invocations: Some(50),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 60,
                    constraints_required: true,
                },
            },
            ReputationTierPolicy {
                name: "trusted".to_string(),
                score_range: [0.50, 1.0],
                max_scope: TierScopeCeiling {
                    operations: vec![
                        Operation::Read,
                        Operation::Get,
                        Operation::Invoke,
                        Operation::ReadResult,
                        Operation::Delegate,
                    ],
                    max_invocations: Some(500),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 10_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(3),
                    ttl_seconds: 300,
                    constraints_required: false,
                },
            },
        ],
    }
}

fn test_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
    RuntimeAssuranceIssuancePolicy {
        tiers: vec![
            RuntimeAssuranceTierPolicy {
                name: "baseline".to_string(),
                minimum_attestation_tier: RuntimeAssuranceTier::None,
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Invoke],
                    max_invocations: Some(5),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 30,
                    constraints_required: false,
                },
            },
            RuntimeAssuranceTierPolicy {
                name: "attested".to_string(),
                minimum_attestation_tier: RuntimeAssuranceTier::Attested,
                max_scope: TierScopeCeiling {
                    operations: vec![Operation::Invoke],
                    max_invocations: Some(20),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1_000,
                        currency: "USD".to_string(),
                    }),
                    max_delegation_depth: Some(0),
                    ttl_seconds: 300,
                    constraints_required: false,
                },
            },
        ],
        attestation_trust_policy: None,
    }
}

fn test_trusted_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
    let mut policy = test_runtime_assurance_policy();
    policy.attestation_trust_policy = Some(
        chio_core::capability::trust_policy::AttestationTrustPolicy {
            rules: vec![
                chio_core::capability::trust_policy::AttestationTrustRule {
                    name: "azure-contoso".to_string(),
                    schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                    verifier: "https://maa.contoso.test".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["sgx".to_string()],
                    required_assertions: std::collections::BTreeMap::new(),
                },
                chio_core::capability::trust_policy::AttestationTrustRule {
                    name: "google-confidential".to_string(),
                    schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                    verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["confidential_vm".to_string()],
                    required_assertions: std::collections::BTreeMap::from([
                        ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                        ("secureBoot".to_string(), "enabled".to_string()),
                    ]),
                },
            ],
        },
    );
    policy.tiers.push(RuntimeAssuranceTierPolicy {
        name: "verified".to_string(),
        minimum_attestation_tier: RuntimeAssuranceTier::Verified,
        max_scope: TierScopeCeiling {
            operations: vec![Operation::Invoke],
            max_invocations: Some(50),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            max_delegation_depth: Some(0),
            ttl_seconds: 600,
            constraints_required: false,
        },
    });
    policy
}

fn test_azure_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now();
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest-azure".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn test_google_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now();
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest-google".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
    kernel_kp: &Keypair,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .test_expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_kp.public_key(),
            bbs_projection_version: None,
        },
        kernel_kp,
    )
    .test_expect("sign receipt")
}

fn make_subject_capability(
    capability_id: &str,
    subject_kp: &Keypair,
    issuer_kp: &Keypair,
    issued_at: u64,
    max_invocations: Option<u32>,
) -> CapabilityToken {
    let body = chio_core::capability::token::CapabilityTokenBody {
        id: capability_id.to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                max_invocations,
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 2_500,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at,
        expires_at: issued_at + 3_600,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer_kp).test_expect("sign capability")
}

#[test]
fn probationary_subject_requires_constrained_read_scope_and_persists_snapshot() {
    let receipt_db_path = unique_path("issuance-policy-receipts", ".sqlite3");
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let subject_kp = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability(&subject_kp.public_key(), scope, 30)
        .test_expect("probationary read capability should issue");

    let store = SqliteReceiptStore::open(&receipt_db_path).test_expect("open receipt store");
    let stored = store
        .get_lineage(&capability.id)
        .test_expect("lineage query")
        .test_expect("snapshot present");
    assert_eq!(stored.subject_key, subject_kp.public_key().to_hex());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn probationary_subject_denied_broad_issue_request() {
    let receipt_db_path = unique_path("issuance-policy-deny", ".sqlite3");
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let subject_kp = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability(&subject_kp.public_key(), scope, 300)
        .test_expect_err("broad probationary issuance should be denied");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected denial, got {error:?}"
    );

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn strong_local_history_allows_trusted_invoke_scope() {
    let receipt_db_path = unique_path("issuance-policy-history", ".sqlite3");
    let receipt_store = SqliteReceiptStore::open(&receipt_db_path).test_expect("receipt store");
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    // The history receipts must be signed by a kernel key the issuing
    // authority trusts; otherwise reputation scoring fails them closed as
    // unsigned (see chio-reputation::receipt_integrity_valid) and the
    // subject never accumulates history. Sign every receipt with the same
    // keypair that backs the local authority below so its public key is in
    // the trusted set.
    let kernel_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();
    let now = unix_now();
    let subject_capability = make_subject_capability(
        "cap-history-001",
        &subject_kp,
        &issuer_kp,
        now - 20 * 86_400,
        Some(200),
    );
    receipt_store
        .record_capability_snapshot(&subject_capability, None)
        .test_expect("record subject capability");
    for day in 0..12 {
        let receipt = make_receipt(
            &format!("rcpt-{day}"),
            &subject_capability.id,
            &subject_hex,
            &issuer_hex,
            now - (11 - day) * 86_400,
            &kernel_kp,
        );
        receipt_store
            .append_chio_receipt(&receipt)
            .test_expect("append receipt");
    }
    drop(receipt_store);

    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(kernel_kp)),
        Some(test_policy()),
        None,
        Some(&receipt_db_path),
        None,
    );
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: Some(250),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability(&subject_kp.public_key(), requested_scope, 300)
        .test_expect("trusted issuance should succeed");
    assert_eq!(capability.subject, subject_kp.public_key());

    let _ = fs::remove_file(receipt_db_path);
}

#[test]
fn runtime_assurance_policy_denies_high_budget_without_attestation() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability(&subject_kp.public_key(), requested_scope, 120)
        .test_expect_err("baseline runtime tier should not allow the higher monetary ceiling");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected runtime-assurance issuance denial, got {error:?}"
    );
}

#[test]
fn runtime_assurance_policy_denies_raw_attestation_without_local_trust_boundary() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_azure_runtime_attestation()),
        )
        .test_expect_err("raw attestation must not unlock attested scope without local trust");

    assert!(
        error
            .to_string()
            .contains("policy tier 'baseline'"),
        "expected local verification boundary to keep raw attestation on the baseline tier, got {error}"
    );
}

#[test]
fn issuance_verification_returns_canonical_subject_and_provenance() {
    let policy = test_trusted_runtime_assurance_policy();
    let verified = verify_runtime_attestation_for_issuance(
        Some(&test_azure_runtime_attestation()),
        Some(&policy),
        unix_now(),
    )
    .test_expect("trusted attestation should verify")
    .test_expect("verified record should be returned when runtime policy is present");

    assert!(verified.is_locally_accepted());
    assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
    assert_eq!(
        verified.provenance.canonical_verifier,
        "https://maa.contoso.test"
    );
    assert_eq!(verified.matched_trust_rule(), Some("azure-contoso"));
    assert_eq!(
        verified
            .workload_identity()
            .test_expect("trusted attestation should bind a workload identity")
            .trust_domain,
        "chio"
    );
}

#[test]
fn issuance_verification_returns_verified_record_without_runtime_policy() {
    let evidence = test_azure_runtime_attestation();
    let verified = verify_runtime_attestation_for_issuance(Some(&evidence), None, unix_now())
        .test_expect("attestation should pass local binding validation")
        .test_expect("verified record should still be returned without runtime policy");

    assert!(!verified.policy_outcome.trust_policy_configured);
    assert!(!verified.is_locally_accepted());
    assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::None);
    assert_eq!(
        verified.evidence_schema(),
        "chio.runtime-attestation.azure-maa.jwt.v1"
    );
    assert_eq!(verified.evidence_sha256(), "attestation-digest-azure");
    assert_eq!(verified.canonical_verifier(), "https://maa.contoso.test");
    assert_eq!(
        verified.verifier_family(),
        chio_core::appraisal::AttestationVerifierFamily::AzureMaa
    );
    assert!(verified.matches_evidence(&evidence));
}

#[test]
fn workload_identity_validation_denies_conflicting_attestation_without_policy() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        None,
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let now = unix_now();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let runtime_attestation = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest".to_string(),
        runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
        workload_identity: Some(chio_core::capability::workload_identity::WorkloadIdentity {
            scheme: chio_core::capability::workload_identity::WorkloadIdentityScheme::Spiffe,
            credential_kind:
                chio_core::capability::workload_identity::WorkloadCredentialKind::X509Svid,
            uri: "spiffe://dev.chio/payments/worker".to_string(),
            trust_domain: "dev.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    };

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(runtime_attestation),
        )
        .test_expect_err("conflicting workload identity should fail closed");
    assert!(
        matches!(error, KernelError::CapabilityIssuanceDenied(_)),
        "expected issuance denial, got {error:?}"
    );
    assert!(
        error.to_string().contains("workload identity"),
        "expected workload-identity denial, got {error}"
    );
}

#[test]
fn runtime_assurance_policy_rebinds_trusted_attestation_to_verified_tier() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_azure_runtime_attestation()),
        )
        .test_expect("trusted attestation should unlock verified tier");

    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                RuntimeAssuranceTier::Verified
            )),
        "issued capability should bind the verified runtime assurance tier"
    );
}

#[test]
fn runtime_assurance_policy_denies_untrusted_attestation_when_verifier_rules_exist() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let mut untrusted = test_azure_runtime_attestation();
    untrusted.verifier = "https://maa.untrusted.test".to_string();

    let error = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(untrusted),
        )
        .test_expect_err("untrusted verifier should fail closed");
    assert!(
        error.to_string().contains("trust policy"),
        "expected trust policy denial, got {error}"
    );
}

#[test]
fn runtime_assurance_policy_rebinds_google_attestation_to_verified_tier() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(
            Keypair::generate(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject_kp = Keypair::generate();
    let requested_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let capability = authority
        .issue_capability_with_attestation(
            &subject_kp.public_key(),
            requested_scope,
            120,
            Some(test_google_runtime_attestation()),
        )
        .test_expect("trusted google appraisal should unlock verified tier");

    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                RuntimeAssuranceTier::Verified
            )),
        "issued capability should bind the verified runtime assurance tier"
    );
}
