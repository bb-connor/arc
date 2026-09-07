use std::sync::Arc;
#[cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt};

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core_types::{Ed25519Backend, Keypair, PublicKey};
use chio_secret_broker::budget::ExecutionQuota;
use chio_secret_broker::daemon::daemon_admin_intent_digest;
use chio_secret_broker::protocol::{
    BrokerDestination, BrokerExecuteResponse, BrokerExecutionEvidence, CredentialRef,
    BROKER_EVIDENCE_SCHEMA,
};
use chio_secret_broker::provision::{
    admin_mutation_receipt_digest, governed_admin_intent_digest, sign_admin_control_receipt,
    sign_admin_mutation_receipt, AdminAuthorization, AdminAuthorizer, AdminClock,
    AdminControlReceiptBody, AdminMutationOutcome, AdminMutationReceiptBody, AdminOperation,
    GovernedAdminAuthorizationEnvelope, GovernedAdminAuthorizer, GovernedAdminPolicy,
    ADMIN_CONTROL_RECEIPT_SCHEMA, ADMIN_MUTATION_RECEIPT_SCHEMA,
};
use chio_secret_broker::receipt::{
    credential_reference_hash, receipt_digest, sign_execution_receipt, sign_failure_receipt,
    verify_execution_receipt, verify_failure_receipt, BrokerDispatchKnowledge,
    BrokerExecutionOutcome, BrokerFailureOutcome, BrokerFailureReceiptBody, BrokerFailureStage,
    BrokerReceiptBody, BrokerReceiptSink, SqliteBrokerReceiptSink, BROKER_FAILURE_RECEIPT_SCHEMA,
    BROKER_RECEIPT_SCHEMA,
};
use chio_secret_broker::service::IpcOperation;
use chio_test_support::prelude::*;
use sha2::Digest;

struct FixedClock(u64);

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().test_expect("tempdir");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .test_expect("harden database directory");
    directory
}

impl AdminClock for FixedClock {
    fn now_unix_seconds(&self) -> chio_secret_broker::Result<u64> {
        Ok(self.0)
    }
}

fn governed_admin_test_policy() -> (GovernedAdminPolicy, PublicKey) {
    let approver = Keypair::from_seed(&[91; 32]);
    let subject = Keypair::from_seed(&[92; 32]).public_key();
    (
        GovernedAdminPolicy {
            trusted_approvers: vec![approver.public_key()],
            subject,
            threshold: 1,
            maximum_token_lifetime_seconds: 60,
        },
        Keypair::from_seed(&[93; 32]).public_key(),
    )
}

#[test]
fn governed_admin_replay_rejects_volatile_and_relative_database_names() {
    for path in [
        std::path::PathBuf::from(":memory:"),
        std::path::PathBuf::from("FiLe:admin-replay?mode=memory&cache=shared"),
        std::path::PathBuf::from("relative-admin-replay.sqlite3"),
    ] {
        let (policy, receipt_signer) = governed_admin_test_policy();
        assert!(GovernedAdminAuthorizer::open(
            path,
            policy,
            receipt_signer,
            Arc::new(FixedClock(100)),
        )
        .is_err());
    }
}

#[cfg(unix)]
#[test]
fn governed_admin_replay_detects_hardlinks_and_path_rebinding() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let database = trusted_directory.join("admin-identity.sqlite3");
    let hardlink = trusted_directory.join("admin-identity-hardlink.sqlite3");
    let displaced = trusted_directory.join("admin-identity-displaced.sqlite3");
    let (policy, receipt_signer) = governed_admin_test_policy();
    let authorizer = GovernedAdminAuthorizer::open(
        &database,
        policy.clone(),
        receipt_signer.clone(),
        Arc::new(FixedClock(100)),
    )
    .test_expect("authorizer");

    std::fs::hard_link(&database, &hardlink).test_expect("hardlink database");
    assert!(authorizer.query_operation(&"00".repeat(32)).is_err());
    assert!(GovernedAdminAuthorizer::open(
        &database,
        policy,
        receipt_signer,
        Arc::new(FixedClock(100)),
    )
    .is_err());
    std::fs::remove_file(&hardlink).test_expect("remove hardlink");

    std::fs::rename(&database, &displaced).test_expect("displace database name");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&database)
        .test_expect("create same-name replacement");
    assert!(authorizer.query_operation(&"00".repeat(32)).is_err());
}

fn credential() -> CredentialRef {
    CredentialRef {
        provider: "generic-https".to_string(),
        credential_id: "credential-production".to_string(),
        version: 1,
    }
}

fn approval(
    signer: &Keypair,
    subject: &PublicKey,
    id: &str,
    request_id: &str,
    intent_digest: &str,
) -> GovernedApprovalToken {
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: id.to_string(),
            approver: signer.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent_digest.to_string(),
            threshold_proposal_hash: Some("7a".repeat(32)),
            request_id: request_id.to_string(),
            issued_at: 90,
            expires_at: 110,
            decision: GovernedApprovalDecision::Approved,
        },
        signer,
    )
    .test_expect("signed approval")
}

#[test]
fn governed_admin_authorization_is_threshold_bound_and_durably_single_use() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let first = Keypair::from_seed(&[31; 32]);
    let second = Keypair::from_seed(&[32; 32]);
    let subject = Keypair::from_seed(&[33; 32]).public_key();
    let trusted_receipt_signer = Keypair::from_seed(&[30; 32]).public_key();
    let credential = credential();
    let intent_digest =
        governed_admin_intent_digest(AdminOperation::Rotate, "tenant-production", &credential)
            .test_expect("intent digest");
    let envelope = GovernedAdminAuthorizationEnvelope::new(vec![
        approval(
            &first,
            &subject,
            "approval-production-1",
            "request-production-1",
            &intent_digest,
        ),
        approval(
            &second,
            &subject,
            "approval-production-2",
            "request-production-1",
            &intent_digest,
        ),
    ])
    .test_expect("envelope");
    let authorization =
        AdminAuthorization::new(envelope.canonical_bytes().test_expect("canonical envelope"))
            .test_expect("authorization");
    let authorizer = GovernedAdminAuthorizer::open(
        trusted_directory.join("admin-replay.sqlite3"),
        GovernedAdminPolicy {
            trusted_approvers: vec![first.public_key(), second.public_key()],
            subject,
            threshold: 2,
            maximum_token_lifetime_seconds: 60,
        },
        trusted_receipt_signer.clone(),
        Arc::new(FixedClock(100)),
    )
    .test_expect("authorizer");

    let digest = authorizer
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .test_expect("authorized once");
    assert_eq!(digest.len(), 64);
    assert!(authorizer
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .is_err());

    let reopened = GovernedAdminAuthorizer::open(
        trusted_directory.join("admin-replay.sqlite3"),
        GovernedAdminPolicy {
            trusted_approvers: vec![first.public_key(), second.public_key()],
            subject: Keypair::from_seed(&[33; 32]).public_key(),
            threshold: 2,
            maximum_token_lifetime_seconds: 60,
        },
        trusted_receipt_signer,
        Arc::new(FixedClock(100)),
    )
    .test_expect("reopened authorizer");
    assert!(reopened
        .authorize(
            &authorization,
            AdminOperation::Rotate,
            "tenant-production",
            &credential,
        )
        .is_err());
}

#[test]
fn governed_admin_operation_recovers_after_expiry_and_persists_signed_completion() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let database = trusted_directory.join("admin-recovery.sqlite3");
    let approver = Keypair::from_seed(&[34; 32]);
    let subject = Keypair::from_seed(&[35; 32]).public_key();
    let receipt_signer = Keypair::from_seed(&[36; 32]);
    let credential = credential();
    let intent_digest =
        governed_admin_intent_digest(AdminOperation::Rotate, "tenant-production", &credential)
            .test_expect("intent digest");
    let envelope = GovernedAdminAuthorizationEnvelope::new(vec![approval(
        &approver,
        &subject,
        "approval-recovery-1",
        "request-recovery-1",
        &intent_digest,
    )])
    .test_expect("envelope");
    let authorization =
        AdminAuthorization::new(envelope.canonical_bytes().test_expect("canonical envelope"))
            .test_expect("authorization");
    let policy = GovernedAdminPolicy {
        trusted_approvers: vec![approver.public_key()],
        subject: subject.clone(),
        threshold: 1,
        maximum_token_lifetime_seconds: 60,
    };
    let authorizer = GovernedAdminAuthorizer::open(
        &database,
        policy.clone(),
        receipt_signer.public_key(),
        Arc::new(FixedClock(100)),
    )
    .test_expect("authorizer");
    let pending = authorizer
        .begin_intent_digest(&authorization, &intent_digest)
        .test_expect("begin operation");
    let operation_id = pending.operation_id().to_string();
    assert!(pending.completed_receipt().is_none());
    drop(authorizer);

    let reopened = GovernedAdminAuthorizer::open(
        &database,
        policy.clone(),
        receipt_signer.public_key(),
        Arc::new(FixedClock(1_000)),
    )
    .test_expect("reopened authorizer");
    let recovered = reopened
        .begin_intent_digest(&authorization, &intent_digest)
        .test_expect("expired exact retry recovers");
    assert_eq!(recovered.operation_id(), operation_id);
    let receipt = sign_admin_mutation_receipt(
        AdminMutationReceiptBody {
            schema: ADMIN_MUTATION_RECEIPT_SCHEMA.to_string(),
            operation_id: recovered.operation_id().to_string(),
            request_id: recovered.request_id().to_string(),
            intent_digest: recovered.intent_digest().to_string(),
            authorization_digest: recovered.authorization_digest().to_string(),
            operation: AdminOperation::Rotate,
            tenant_scope: "tenant-production".to_string(),
            credential: credential.clone(),
            completed_at_unix_seconds: 1_000,
            outcome: AdminMutationOutcome::Applied,
        },
        &Ed25519Backend::new(receipt_signer.clone()),
    )
    .test_expect("signed receipt");
    let completed = reopened
        .complete_operation(&recovered, &receipt)
        .test_expect("complete operation");
    assert_eq!(completed, receipt);
    drop(reopened);

    let final_reader = GovernedAdminAuthorizer::open(
        &database,
        policy,
        receipt_signer.public_key(),
        Arc::new(FixedClock(2_000)),
    )
    .test_expect("final reader");
    let durable = final_reader
        .query_operation(&operation_id)
        .test_expect("query operation")
        .test_expect("durable operation");
    assert_eq!(durable.completed_receipt(), Some(&receipt));
    assert_eq!(
        final_reader
            .begin_intent_digest(&authorization, &intent_digest)
            .test_expect("completed exact retry")
            .completed_receipt(),
        Some(&receipt)
    );
}

#[test]
fn governed_admin_journal_rejects_self_signed_completion_substitution() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let database = trusted_directory.join("admin-journal-tamper.sqlite3");
    let approver = Keypair::from_seed(&[43; 32]);
    let subject = Keypair::from_seed(&[44; 32]).public_key();
    let trusted_receipt_signer = Keypair::from_seed(&[45; 32]);
    let attacker_receipt_signer = Keypair::from_seed(&[46; 32]);
    let credential = credential();
    let intent_digest =
        governed_admin_intent_digest(AdminOperation::Rotate, "tenant-production", &credential)
            .test_expect("intent digest");
    let envelope = GovernedAdminAuthorizationEnvelope::new(vec![approval(
        &approver,
        &subject,
        "approval-journal-tamper-1",
        "request-journal-tamper-1",
        &intent_digest,
    )])
    .test_expect("envelope");
    let authorization =
        AdminAuthorization::new(envelope.canonical_bytes().test_expect("canonical envelope"))
            .test_expect("authorization");
    let policy = GovernedAdminPolicy {
        trusted_approvers: vec![approver.public_key()],
        subject,
        threshold: 1,
        maximum_token_lifetime_seconds: 60,
    };
    let authorizer = GovernedAdminAuthorizer::open(
        &database,
        policy.clone(),
        trusted_receipt_signer.public_key(),
        Arc::new(FixedClock(100)),
    )
    .test_expect("authorizer");
    let operation = authorizer
        .begin_intent_digest(&authorization, &intent_digest)
        .test_expect("begin operation");
    let trusted_receipt = sign_admin_mutation_receipt(
        AdminMutationReceiptBody {
            schema: ADMIN_MUTATION_RECEIPT_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_id: operation.request_id().to_string(),
            intent_digest: operation.intent_digest().to_string(),
            authorization_digest: operation.authorization_digest().to_string(),
            operation: AdminOperation::Rotate,
            tenant_scope: "tenant-production".to_string(),
            credential,
            completed_at_unix_seconds: 100,
            outcome: AdminMutationOutcome::Applied,
        },
        &Ed25519Backend::new(trusted_receipt_signer.clone()),
    )
    .test_expect("trusted receipt");
    let untrusted_completion = sign_admin_mutation_receipt(
        trusted_receipt.body.clone(),
        &Ed25519Backend::new(attacker_receipt_signer.clone()),
    )
    .test_expect("untrusted completion receipt");
    assert!(authorizer
        .complete_operation(&operation, &untrusted_completion)
        .is_err());
    authorizer
        .complete_operation(&operation, &trusted_receipt)
        .test_expect("complete operation");
    drop(authorizer);

    let attacker_receipt = sign_admin_mutation_receipt(
        trusted_receipt.body.clone(),
        &Ed25519Backend::new(attacker_receipt_signer),
    )
    .test_expect("attacker self-signed receipt");
    let attacker_canonical =
        chio_core_types::canonical_json_bytes(&attacker_receipt).test_expect("attacker canonical");
    let attacker_digest =
        admin_mutation_receipt_digest(&attacker_receipt).test_expect("attacker receipt digest");
    let connection = rusqlite::Connection::open(&database).test_expect("open journal for tamper");
    connection
        .execute_batch("DROP TRIGGER governed_admin_completions_no_update;")
        .test_expect("disable append-only trigger to model offline tamper");
    connection
        .execute(
            r#"
            UPDATE governed_admin_operation_completions
            SET receipt_digest = ?1, canonical_receipt = ?2
            WHERE operation_id = ?3
            "#,
            rusqlite::params![
                attacker_digest,
                attacker_canonical,
                operation.operation_id()
            ],
        )
        .test_expect("substitute self-signed receipt");
    drop(connection);

    let reopened = GovernedAdminAuthorizer::open(
        &database,
        policy,
        trusted_receipt_signer.public_key(),
        Arc::new(FixedClock(1_000)),
    )
    .test_expect("reopened authorizer");
    assert!(reopened.query_operation(operation.operation_id()).is_err());
    assert!(reopened
        .begin_intent_digest(&authorization, &intent_digest)
        .is_err());
}

#[test]
fn governed_admin_control_replays_the_exact_signed_response_after_restart() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let database = trusted_directory.join("admin-control-recovery.sqlite3");
    let approver = Keypair::from_seed(&[37; 32]);
    let subject = Keypair::from_seed(&[38; 32]).public_key();
    let receipt_signer = Keypair::from_seed(&[39; 32]);
    let trusted_mutation_receipt_signer = receipt_signer.public_key();
    let payload = chio_core_types::canonical_json_bytes(&serde_json::json!({
        "capabilityId": "broker-capability-production-1",
        "credential": {
            "credentialId": "credential-production",
            "provider": "generic-https",
            "version": 1
        },
        "revocationId": "broker-revocation-production-1",
        "schema": "chio.broker-capability-control.v1"
    }))
    .test_expect("control payload");
    let intent_digest =
        daemon_admin_intent_digest(IpcOperation::Status, "tenant-production", &payload)
            .test_expect("control intent");
    let envelope = GovernedAdminAuthorizationEnvelope::new(vec![approval(
        &approver,
        &subject,
        "approval-control-recovery-1",
        "request-control-recovery-1",
        &intent_digest,
    )])
    .test_expect("envelope");
    let authorization =
        AdminAuthorization::new(envelope.canonical_bytes().test_expect("canonical envelope"))
            .test_expect("authorization");
    let policy = GovernedAdminPolicy {
        trusted_approvers: vec![approver.public_key()],
        subject,
        threshold: 1,
        maximum_token_lifetime_seconds: 60,
    };
    let authorizer = GovernedAdminAuthorizer::open(
        &database,
        policy.clone(),
        trusted_mutation_receipt_signer.clone(),
        Arc::new(FixedClock(100)),
    )
    .test_expect("authorizer");
    let operation = authorizer
        .begin_intent_digest(&authorization, &intent_digest)
        .test_expect("begin control operation");
    let response = chio_core_types::canonical_json_bytes(&serde_json::json!({
        "authorityCommitIndex": 12,
        "capabilityId": "broker-capability-production-1",
        "observedAtUnixSeconds": 100,
        "revocationId": "broker-revocation-production-1",
        "revoked": false,
        "schema": "chio.broker-capability-status.v1"
    }))
    .test_expect("control response");
    let receipt = sign_admin_control_receipt(
        AdminControlReceiptBody {
            schema: ADMIN_CONTROL_RECEIPT_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_id: operation.request_id().to_string(),
            intent_digest: operation.intent_digest().to_string(),
            authorization_digest: operation.authorization_digest().to_string(),
            operation: "status".to_string(),
            tenant_scope: "tenant-production".to_string(),
            response_digest: hex::encode(sha2::Sha256::digest(&response)),
            completed_at_unix_seconds: 100,
            outcome: AdminMutationOutcome::Applied,
        },
        &Ed25519Backend::new(receipt_signer),
    )
    .test_expect("signed control receipt");
    let completed = authorizer
        .complete_control_operation(&operation, &receipt, &response)
        .test_expect("complete control operation");
    assert_eq!(completed.receipt(), &receipt);
    assert_eq!(completed.response(), response);
    drop(authorizer);

    let reopened = GovernedAdminAuthorizer::open(
        &database,
        policy,
        trusted_mutation_receipt_signer,
        Arc::new(FixedClock(1_000)),
    )
    .test_expect("reopened authorizer");
    let recovered = reopened
        .begin_intent_digest(&authorization, &intent_digest)
        .test_expect("expired exact retry recovers");
    assert_eq!(recovered.operation_id(), operation.operation_id());
    let durable = reopened
        .query_control_completion(recovered.operation_id())
        .test_expect("query control completion")
        .test_expect("durable control completion");
    assert_eq!(durable.receipt(), &receipt);
    assert_eq!(durable.response(), response);
}

fn signed_receipt(signer: &Keypair) -> chio_secret_broker::receipt::SignedBrokerReceipt {
    let credential = credential();
    let signer_backend = Ed25519Backend::new(signer.clone());
    sign_execution_receipt(
        BrokerReceiptBody {
            schema: BROKER_RECEIPT_SCHEMA.to_string(),
            receipt_id: "broker-receipt-production-1".to_string(),
            issued_at_unix_seconds: 100,
            evidence: BrokerExecutionEvidence {
                schema: BROKER_EVIDENCE_SCHEMA.to_string(),
                attempt_id: "attempt-production-1".to_string(),
                invocation_id: "invocation-production-1".to_string(),
                hold_id: "hold-production-1".to_string(),
                request_digest: "11".repeat(32),
                capability_digest: "22".repeat(32),
                revocation_set_digest: "33".repeat(32),
                budget_commit_index: 10,
                revocation_commit_index: 11,
                authority_commit_index: 12,
                leader_epoch: 13,
                upstream_status: 200,
                response_body_sha256: "44".repeat(32),
            },
            operation_id: "operation-production-1".to_string(),
            authorize_event_id: "authorize-event-production-1".to_string(),
            capture_event_id: "capture-event-production-1".to_string(),
            parent_capability_id: "parent-capability-production-1".to_string(),
            broker_capability_id: "broker-capability-production-1".to_string(),
            subject: Keypair::from_seed(&[42; 32]).public_key(),
            credential_reference_hash: credential_reference_hash(&credential)
                .test_expect("credential reference hash"),
            credential_version: credential.version,
            normalized_destination: BrokerDestination::parse(
                "https://example.com/v1/resource",
                "POST",
                false,
            )
            .test_expect("destination"),
            request_body_sha256: "55".repeat(32),
            caller_headers_sha256: "66".repeat(32),
            caller_options_sha256: "77".repeat(32),
            quotas: vec![
                ExecutionQuota {
                    key_id: "broker-quota-production".to_string(),
                    maximum_executions: 2,
                },
                ExecutionQuota {
                    key_id: "parent-quota-production".to_string(),
                    maximum_executions: 10,
                },
            ],
            broker_quota_key_id: "broker-quota-production".to_string(),
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            request_body_bytes: 128,
            response_body_bytes: 256,
            source_receipt_ids: vec!["source-receipt-production-1".to_string()],
            outcome: BrokerExecutionOutcome::Completed,
        },
        &signer_backend,
    )
    .test_expect("signed receipt")
}

fn completed_response(signer: &Keypair) -> BrokerExecuteResponse {
    let body = b"sanitized-completed-response".to_vec();
    let mut receipt_body = signed_receipt(signer).body;
    receipt_body.evidence.response_body_sha256 = hex::encode(sha2::Sha256::digest(&body));
    receipt_body.response_body_bytes = u64::try_from(body.len()).test_expect("response length");
    let receipt = sign_execution_receipt(receipt_body, &Ed25519Backend::new(signer.clone()))
        .test_expect("completed receipt");
    BrokerExecuteResponse {
        status: receipt.body.evidence.upstream_status,
        headers: Vec::new(),
        body,
        evidence: receipt.body.evidence.clone(),
        receipt_reference: format!(
            "broker-receipt-sha256-{}",
            receipt_digest(&receipt).test_expect("receipt digest")
        ),
        receipt,
    }
}

fn signed_failure_for_attempt(
    signer: &Keypair,
    receipt_id: &str,
) -> chio_secret_broker::receipt::SignedBrokerFailureReceipt {
    sign_failure_receipt(
        BrokerFailureReceiptBody {
            schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id.to_string(),
            issued_at_unix_seconds: 101,
            stage: BrokerFailureStage::Dispatch,
            outcome: BrokerFailureOutcome::Failed,
            diagnostic_code: "chio.broker.conflict".to_string(),
            request_digest: "11".repeat(32),
            capability_digest: Some("22".repeat(32)),
            attempt_id: Some("attempt-production-1".to_string()),
            invocation_id: Some("invocation-production-1".to_string()),
            hold_id: Some("hold-production-1".to_string()),
            parent_capability_id: Some("parent-capability-production-1".to_string()),
            broker_capability_id: Some("broker-capability-production-1".to_string()),
            dispatch_knowledge: BrokerDispatchKnowledge::Committed,
        },
        &Ed25519Backend::new(signer.clone()),
    )
    .test_expect("signed failure")
}

#[test]
fn enterprise_receipt_binds_every_execution_field_and_excludes_seeded_secret() {
    let signer = Keypair::from_seed(&[41; 32]);
    let receipt = signed_receipt(&signer);
    let encoded = serde_json::to_vec(&receipt).test_expect("receipt JSON");
    assert!(!encoded
        .windows(25)
        .any(|window| window == b"seeded-broker-secret-1234"));

    let mut mutations = Vec::new();
    let mut credential = receipt.clone();
    credential.body.credential_reference_hash = "88".repeat(32);
    mutations.push(credential);
    let mut destination = receipt.clone();
    destination.body.normalized_destination.exact_path_and_query = "/other".to_string();
    mutations.push(destination);
    let mut header = receipt.clone();
    header.body.caller_headers_sha256 = "99".repeat(32);
    mutations.push(header);
    let mut option = receipt.clone();
    option.body.caller_options_sha256 = "aa".repeat(32);
    mutations.push(option);
    let mut quota = receipt.clone();
    quota.body.quotas[0].maximum_executions = 3;
    mutations.push(quota);
    let mut revocation = receipt.clone();
    revocation.body.evidence.revocation_set_digest = "bb".repeat(32);
    mutations.push(revocation);
    let mut capture = receipt.clone();
    capture.body.capture_event_id = "capture-event-production-2".to_string();
    mutations.push(capture);
    let mut provider = receipt.clone();
    provider.body.provider_adapter_version = 2;
    mutations.push(provider);
    let mut bytes = receipt.clone();
    bytes.body.response_body_bytes += 1;
    mutations.push(bytes);
    let mut lineage = receipt.clone();
    lineage.body.source_receipt_ids = vec!["source-receipt-production-2".to_string()];
    mutations.push(lineage);

    for mutation in mutations {
        assert!(verify_execution_receipt(&mutation, &signer.public_key()).is_err());
    }
}

#[test]
fn durable_receipt_sink_is_append_only_idempotent_and_restart_safe() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let path = trusted_directory.join("broker-receipts.sqlite3");
    let signer = Keypair::from_seed(&[41; 32]);
    let receipt = signed_receipt(&signer);
    let sink = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("sink");
    let first = sink.persist(&receipt).test_expect("first append");
    let retry = sink.persist(&receipt).test_expect("exact retry");
    assert_eq!(first, retry);
    drop(sink);

    let reopened = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("reopen");
    let loaded = reopened
        .load(&receipt.body.receipt_id)
        .test_expect("load")
        .test_expect("persisted receipt");
    assert_eq!(loaded, receipt);

    let mut conflicting_body = receipt.body.clone();
    conflicting_body.evidence.upstream_status = 201;
    let conflicting =
        sign_execution_receipt(conflicting_body, &Ed25519Backend::new(signer.clone()))
            .test_expect("conflicting signed receipt");
    assert!(reopened.persist(&conflicting).is_err());
}

#[test]
fn durable_completed_response_replays_exact_bytes_after_restart() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let path = trusted_directory.join("broker-completed-responses.sqlite3");
    let signer = Keypair::from_seed(&[43; 32]);
    let response = completed_response(&signer);
    let sink = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("sink");

    let first = sink
        .persist_completed(&response)
        .test_expect("persist completed response");
    let retry = sink
        .persist_completed(&response)
        .test_expect("persist exact completed retry");
    assert_eq!(first, response.receipt_reference);
    assert_eq!(retry, first);
    drop(sink);

    let reopened = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("reopen");
    assert_eq!(
        reopened
            .load_completed(&response.evidence.attempt_id)
            .test_expect("load completed response")
            .test_expect("completed response exists"),
        response
    );
}

#[test]
fn receipt_store_rejects_success_failure_terminal_conflicts_in_both_orders() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let signer = Keypair::from_seed(&[44; 32]);
    let response = completed_response(&signer);
    let failure = signed_failure_for_attempt(&signer, "broker-failure-event-production-1");

    let success_first = SqliteBrokerReceiptSink::open(
        trusted_directory.join("success-first.sqlite3"),
        signer.public_key(),
    )
    .test_expect("success-first sink");
    success_first
        .persist_completed(&response)
        .test_expect("persist success");
    assert!(success_first.persist_failure(&failure).is_err());

    let failure_first = SqliteBrokerReceiptSink::open(
        trusted_directory.join("failure-first.sqlite3"),
        signer.public_key(),
    )
    .test_expect("failure-first sink");
    failure_first
        .persist_failure(&failure)
        .test_expect("persist failure");
    assert!(failure_first.persist_completed(&response).is_err());
}

#[test]
fn durable_failure_receipt_binds_truthful_dispatch_state_and_survives_restart() {
    let directory = private_tempdir();
    let trusted_directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let path = trusted_directory.join("broker-failure-receipts.sqlite3");
    let signer = Keypair::from_seed(&[51; 32]);
    let body = BrokerFailureReceiptBody {
        schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
        receipt_id: "broker-failure-receipt-production-1".to_string(),
        issued_at_unix_seconds: 100,
        stage: BrokerFailureStage::Capture,
        outcome: BrokerFailureOutcome::Unknown,
        diagnostic_code: "chio.broker.capture_unavailable".to_string(),
        request_digest: "11".repeat(32),
        capability_digest: Some("22".repeat(32)),
        attempt_id: Some("attempt-production-1".to_string()),
        invocation_id: Some("invocation-production-1".to_string()),
        hold_id: Some("hold-production-1".to_string()),
        parent_capability_id: Some("parent-capability-production-1".to_string()),
        broker_capability_id: Some("broker-capability-production-1".to_string()),
        dispatch_knowledge: BrokerDispatchKnowledge::Unknown,
    };
    let receipt = sign_failure_receipt(body, &Ed25519Backend::new(signer.clone()))
        .test_expect("signed failure receipt");
    verify_failure_receipt(&receipt, &signer.public_key()).test_expect("verified failure receipt");

    let mut mutations = Vec::new();
    let mut schema = receipt.clone();
    schema.body.schema = "chio.broker-execution-failure-receipt.v2".to_string();
    mutations.push(schema);
    let mut identifier = receipt.clone();
    identifier.body.receipt_id = "broker-failure-receipt-production-2".to_string();
    mutations.push(identifier);
    let mut time = receipt.clone();
    time.body.issued_at_unix_seconds += 1;
    mutations.push(time);
    let mut stage = receipt.clone();
    stage.body.stage = BrokerFailureStage::Dispatch;
    mutations.push(stage);
    let mut outcome = receipt.clone();
    outcome.body.outcome = BrokerFailureOutcome::Denied;
    mutations.push(outcome);
    let mut diagnostic = receipt.clone();
    diagnostic.body.diagnostic_code = "chio.broker.capture_conflict".to_string();
    mutations.push(diagnostic);
    let mut request = receipt.clone();
    request.body.request_digest = "33".repeat(32);
    mutations.push(request);
    let mut capability = receipt.clone();
    capability.body.capability_digest = Some("44".repeat(32));
    mutations.push(capability);
    let mut attempt = receipt.clone();
    attempt.body.attempt_id = Some("attempt-production-2".to_string());
    mutations.push(attempt);
    let mut invocation = receipt.clone();
    invocation.body.invocation_id = Some("invocation-production-2".to_string());
    mutations.push(invocation);
    let mut hold = receipt.clone();
    hold.body.hold_id = Some("hold-production-2".to_string());
    mutations.push(hold);
    let mut parent = receipt.clone();
    parent.body.parent_capability_id = Some("parent-capability-production-2".to_string());
    mutations.push(parent);
    let mut broker = receipt.clone();
    broker.body.broker_capability_id = Some("broker-capability-production-2".to_string());
    mutations.push(broker);
    let mut dispatch = receipt.clone();
    dispatch.body.dispatch_knowledge = BrokerDispatchKnowledge::Committed;
    mutations.push(dispatch);
    for mutation in mutations {
        assert!(verify_failure_receipt(&mutation, &signer.public_key()).is_err());
    }

    let sink = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("sink");
    let first = sink
        .persist_failure(&receipt)
        .test_expect("first failure append");
    let retry = sink.persist_failure(&receipt).test_expect("failure retry");
    assert_eq!(first, retry);
    drop(sink);

    let reopened = SqliteBrokerReceiptSink::open(&path, signer.public_key()).test_expect("reopen");
    assert_eq!(
        reopened
            .load_failure(&receipt.body.receipt_id)
            .test_expect("load failure")
            .test_expect("persisted failure"),
        receipt
    );
}
