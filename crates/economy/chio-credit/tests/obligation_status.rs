use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::obligation::{
    verify_obligation_status_proof, ObligationAssignmentCasInputV1, ObligationAssignmentCasV1,
    ObligationAssignmentOperationSnapshotV1, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1, ObligationError, ObligationSettlementLifecycleV1,
    ObligationSettlementStateV1, ObligationSettlementTransitionV1, ObligationStatusProofBodyV1,
    ObligationStatusProofContextV1, ObligationStatusProofTrustV1,
    ObligationStatusProofVerificationContextV1, SignedObligationStatusProofV1,
    VerifiedObligationStatusProofV1, OBLIGATION_ASSIGNMENT_CAS_SCHEMA,
    OBLIGATION_SETTLEMENT_LIFECYCLE_SCHEMA, OBLIGATION_STATUS_PROOF_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SNAPSHOT_VERSION: u64 = 7;
const RESOURCE_FENCE: u64 = 11;
const ISSUED_AT: u64 = 1_000;
const EXPIRES_AT: u64 = 1_100;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let value = serde_json::to_value(artifact)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<obligation-status-artifact>"),
        &value,
    )?;
    Ok(())
}

fn require_error<T>(result: Result<T, ObligationError>) -> ObligationError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

struct Fixture {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    lifecycle: ObligationSettlementLifecycleV1,
    signer: Keypair,
    trust: ObligationStatusProofTrustV1,
}

fn fixture() -> Result<Fixture, ObligationError> {
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest("status-intent"),
        source_receipt_id: "status-receipt".to_owned(),
        source_receipt_digest: digest("status-receipt"),
        debtor_id: "did:chio:debtor".to_owned(),
        original_creditor_id: "did:chio:seller".to_owned(),
        original_settlement_destination_ref: "acct:seller".to_owned(),
        payee_binding_digest: digest("status-payee"),
        amount: MonetaryAmount {
            units: 500,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: digest("status-authority"),
        created_at_unix_ms: 100,
        due_at_unix_ms: 10_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let lifecycle = ObligationSettlementLifecycleV1::pending(&atom)?;
    let signer = Keypair::from_seed(&[71; 32]);
    let trust = ObligationStatusProofTrustV1::new(
        "obligor-disposition-authority".to_owned(),
        signer.public_key(),
        3,
        200,
    )?;
    Ok(Fixture {
        atom,
        disposition,
        lifecycle,
        signer,
        trust,
    })
}

struct StatusIssue<'a> {
    disposition: &'a ObligationDispositionRecordV1,
    lifecycle: &'a ObligationSettlementLifecycleV1,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_id: &'a str,
    authority_key_epoch: u64,
    signer: &'a Keypair,
}

fn signed_status(
    fixture: &Fixture,
    issue: &StatusIssue<'_>,
) -> Result<SignedObligationStatusProofV1, ObligationError> {
    SignedObligationStatusProofV1::sign(
        ObligationStatusProofBodyV1::new(&ObligationStatusProofContextV1 {
            atom: &fixture.atom,
            disposition: issue.disposition,
            settlement_lifecycle: issue.lifecycle,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            issued_at_unix_ms: issue.issued_at_unix_ms,
            expires_at_unix_ms: issue.expires_at_unix_ms,
            authority_id: issue.authority_id,
            authority_key_epoch: issue.authority_key_epoch,
        })?,
        issue.signer,
    )
}

fn verify_status(
    fixture: &Fixture,
    signed: SignedObligationStatusProofV1,
    disposition: &ObligationDispositionRecordV1,
    lifecycle: &ObligationSettlementLifecycleV1,
    trusted_now_unix_ms: u64,
) -> Result<VerifiedObligationStatusProofV1, ObligationError> {
    verify_obligation_status_proof(
        signed,
        &ObligationStatusProofVerificationContextV1 {
            atom: &fixture.atom,
            disposition,
            settlement_lifecycle: lifecycle,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            trust: &fixture.trust,
            trusted_now_unix_ms,
        },
    )
}

fn valid_signed_status(
    fixture: &Fixture,
) -> Result<SignedObligationStatusProofV1, ObligationError> {
    signed_status(
        fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &fixture.lifecycle,
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &fixture.signer,
        },
    )
}

fn assignment_input(
    operation_id: String,
    normalized_request_digest: String,
    supplemental_authorization_digest: String,
    status_proof_digest: String,
    agreement_id: &str,
) -> ObligationAssignmentCasInputV1 {
    ObligationAssignmentCasInputV1 {
        schema: OBLIGATION_ASSIGNMENT_CAS_SCHEMA.to_owned(),
        operation_id,
        normalized_request_digest,
        agreement_id: agreement_id.to_owned(),
        buyer_id: "did:chio:factor".to_owned(),
        buyer_settlement_destination_ref: "acct:factor".to_owned(),
        supplemental_authorization_digest,
        status_proof_digest,
        effective_at_unix_ms: 1_050,
    }
}

#[test]
fn settlement_lifecycle_and_status_proof_are_canonical_and_exact() -> TestResult {
    let fixture = fixture()?;
    let lifecycle_json = serde_json::to_value(&fixture.lifecycle)?;
    assert_eq!(
        lifecycle_json
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some(OBLIGATION_SETTLEMENT_LIFECYCLE_SCHEMA)
    );
    validate_schema(
        "obligation-settlement-lifecycle.v1.json",
        &fixture.lifecycle,
    )?;
    let signed = valid_signed_status(&fixture)?;
    validate_schema("obligation-status-proof.v1.json", &signed)?;
    let canonical = signed.canonical_bytes()?;
    let decoded = SignedObligationStatusProofV1::from_canonical_bytes(&canonical)?;
    assert_eq!(decoded, signed);
    let verified = verify_status(
        &fixture,
        decoded,
        &fixture.disposition,
        &fixture.lifecycle,
        1_050,
    )?;
    assert_eq!(verified.body().proof_id().len(), 64);
    assert_eq!(verified.body_digest().len(), 64);
    assert_eq!(verified.envelope_digest().len(), 64);
    assert_eq!(
        serde_json::to_value(verified.body())?
            .get("schema")
            .and_then(serde_json::Value::as_str),
        Some(OBLIGATION_STATUS_PROOF_SCHEMA)
    );

    let settled = fixture.lifecycle.advance(
        &fixture.atom,
        ObligationSettlementTransitionV1::Settle {
            settlement_id: "settlement-1".to_owned(),
            evidence_digest: digest("settlement-evidence"),
            authority_digest: digest("settlement-authority"),
        },
    )?;
    assert!(matches!(
        settled.state(),
        ObligationSettlementStateV1::Settled { .. }
    ));
    assert_eq!(
        require_error(settled.advance(
            &fixture.atom,
            ObligationSettlementTransitionV1::Fail {
                failure_digest: digest("late-failure"),
                authority_digest: digest("failure-authority"),
            },
        )),
        ObligationError::IllegalDispositionTransition
    );

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical);
    assert!(matches!(
        SignedObligationStatusProofV1::from_canonical_bytes(&noncanonical),
        Err(ObligationError::Canonicalization(_))
    ));
    Ok(())
}

#[test]
fn status_proof_rejects_untrusted_stale_future_and_overlong_authority() -> TestResult {
    let fixture = fixture()?;
    let rogue = Keypair::from_seed(&[72; 32]);
    let rogue_signed = signed_status(
        &fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &fixture.lifecycle,
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &rogue,
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            rogue_signed,
            &fixture.disposition,
            &fixture.lifecycle,
            1_050,
        )),
        ObligationError::StatusProofAuthorityVerification
    );

    for (authority_id, epoch) in [("other-authority", 3), ("obligor-disposition-authority", 4)] {
        let signed = signed_status(
            &fixture,
            &StatusIssue {
                disposition: &fixture.disposition,
                lifecycle: &fixture.lifecycle,
                issued_at_unix_ms: ISSUED_AT,
                expires_at_unix_ms: EXPIRES_AT,
                authority_id,
                authority_key_epoch: epoch,
                signer: &fixture.signer,
            },
        )?;
        assert_eq!(
            require_error(verify_status(
                &fixture,
                signed,
                &fixture.disposition,
                &fixture.lifecycle,
                1_050,
            )),
            ObligationError::StatusProofAuthorityVerification
        );
    }

    let stale = signed_status(
        &fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &fixture.lifecycle,
            issued_at_unix_ms: 800,
            expires_at_unix_ms: 900,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &fixture.signer,
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            stale,
            &fixture.disposition,
            &fixture.lifecycle,
            900,
        )),
        ObligationError::StatusProofNotCurrent
    );

    let future = signed_status(
        &fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &fixture.lifecycle,
            issued_at_unix_ms: 1_200,
            expires_at_unix_ms: 1_300,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &fixture.signer,
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            future,
            &fixture.disposition,
            &fixture.lifecycle,
            1_100,
        )),
        ObligationError::StatusProofNotCurrent
    );

    let overlong = signed_status(
        &fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &fixture.lifecycle,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 1_300,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &fixture.signer,
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            overlong,
            &fixture.disposition,
            &fixture.lifecycle,
            1_050,
        )),
        ObligationError::StatusProofNotCurrent
    );
    Ok(())
}

#[test]
fn status_proof_rejects_schema_tampering_and_mixed_snapshots() -> TestResult {
    let fixture = fixture()?;
    let signed = valid_signed_status(&fixture)?;

    let reserved = fixture.disposition.advance(
        &fixture.atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest("clearing-authority"),
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            signed.clone(),
            &reserved,
            &fixture.lifecycle,
            1_050,
        )),
        ObligationError::StatusProofAuthorityVerification
    );

    let failed = fixture.lifecycle.advance(
        &fixture.atom,
        ObligationSettlementTransitionV1::Fail {
            failure_digest: digest("settlement-failure"),
            authority_digest: digest("failure-authority"),
        },
    )?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            signed.clone(),
            &fixture.disposition,
            &failed,
            1_050,
        )),
        ObligationError::StatusProofAuthorityVerification
    );

    let mut unknown_schema = serde_json::to_value(&signed)?;
    unknown_schema["body"]["schema"] = serde_json::json!("chio.obligation.status-proof.v2");
    let unknown_schema: SignedObligationStatusProofV1 = serde_json::from_value(unknown_schema)?;
    assert_eq!(
        require_error(verify_status(
            &fixture,
            unknown_schema,
            &fixture.disposition,
            &fixture.lifecycle,
            1_050,
        )),
        ObligationError::InvalidField("status_proof_schema")
    );

    let mut tampered_atom = serde_json::to_value(&signed)?;
    tampered_atom["body"]["obligationAtomDigest"] = serde_json::json!(digest("other-atom"));
    let tampered_atom: SignedObligationStatusProofV1 = serde_json::from_value(tampered_atom)?;
    assert!(matches!(
        verify_status(
            &fixture,
            tampered_atom,
            &fixture.disposition,
            &fixture.lifecycle,
            1_050,
        ),
        Err(ObligationError::InvalidField("status_proof_binding"))
            | Err(ObligationError::StatusProofAuthorityVerification)
    ));
    Ok(())
}

#[test]
fn assignment_cas_requires_exact_authorization_and_has_one_winner() -> TestResult {
    let fixture = fixture()?;
    let verified = verify_status(
        &fixture,
        valid_signed_status(&fixture)?,
        &fixture.disposition,
        &fixture.lifecycle,
        1_050,
    )?;
    let operation_id = digest("assignment-operation-1");
    let request_digest = digest("assignment-request-1");
    let authorization_digest = digest("assignment-authorization-1");
    let operation = ObligationAssignmentOperationSnapshotV1::new(
        operation_id.clone(),
        request_digest.clone(),
        &fixture.disposition,
        &fixture.lifecycle,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?;
    let input = assignment_input(
        operation_id.clone(),
        request_digest.clone(),
        authorization_digest.clone(),
        verified.envelope_digest().to_owned(),
        "agreement-1",
    );
    assert_eq!(
        require_error(ObligationAssignmentCasV1::new(
            operation.clone(),
            input.clone(),
        )),
        ObligationError::MissingSupplementalAuthorization
    );
    let attached = operation.attach_supplemental_authorization(&authorization_digest)?;
    assert_eq!(
        require_error(
            attached.attach_supplemental_authorization(&digest("replacement-authorization"))
        ),
        ObligationError::SupplementalAuthorizationMismatch
    );
    let assignment = ObligationAssignmentCasV1::new(attached, input)?;
    let assigned = fixture.disposition.compare_and_swap_assignment(
        &fixture.atom,
        &fixture.lifecycle,
        &verified,
        &assignment,
        1_050,
    )?;
    assert_eq!(
        assigned.disposition(),
        &ObligationDispositionV1::Assigned {
            agreement_id: "agreement-1".to_owned(),
            creditor_id: "did:chio:factor".to_owned(),
            settlement_destination_ref: "acct:factor".to_owned(),
        }
    );
    assert_eq!(
        assigned.compare_and_swap_assignment(
            &fixture.atom,
            &fixture.lifecycle,
            &verified,
            &assignment,
            2_000,
        )?,
        assigned
    );

    let competing_operation_id = digest("assignment-operation-2");
    let competing_request = digest("assignment-request-2");
    let competing_authorization = digest("assignment-authorization-2");
    let competing_operation = ObligationAssignmentOperationSnapshotV1::new(
        competing_operation_id.clone(),
        competing_request.clone(),
        &fixture.disposition,
        &fixture.lifecycle,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?
    .attach_supplemental_authorization(&competing_authorization)?;
    let competing = ObligationAssignmentCasV1::new(
        competing_operation,
        assignment_input(
            competing_operation_id,
            competing_request,
            competing_authorization,
            verified.envelope_digest().to_owned(),
            "agreement-2",
        ),
    )?;
    assert_eq!(
        require_error(assigned.compare_and_swap_assignment(
            &fixture.atom,
            &fixture.lifecycle,
            &verified,
            &competing,
            1_050,
        )),
        ObligationError::CompareAndSwapConflict
    );
    Ok(())
}

#[test]
fn assignment_cas_rejects_stale_disposition_and_nonpending_settlement() -> TestResult {
    let fixture = fixture()?;
    let verified = verify_status(
        &fixture,
        valid_signed_status(&fixture)?,
        &fixture.disposition,
        &fixture.lifecycle,
        1_050,
    )?;
    let authorization = digest("stale-authorization");
    let operation_id = digest("stale-operation");
    let request_digest = digest("stale-request");
    let operation = ObligationAssignmentOperationSnapshotV1::new(
        operation_id.clone(),
        request_digest.clone(),
        &fixture.disposition,
        &fixture.lifecycle,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?
    .attach_supplemental_authorization(&authorization)?;
    let mut stale_value = serde_json::to_value(&operation)?;
    stale_value["expectedDispositionVersion"] = serde_json::json!(2);
    let stale: ObligationAssignmentOperationSnapshotV1 = serde_json::from_value(stale_value)?;
    let stale_assignment = ObligationAssignmentCasV1::new(
        stale,
        assignment_input(
            operation_id,
            request_digest,
            authorization,
            verified.envelope_digest().to_owned(),
            "agreement-stale",
        ),
    )?;
    assert_eq!(
        require_error(fixture.disposition.compare_and_swap_assignment(
            &fixture.atom,
            &fixture.lifecycle,
            &verified,
            &stale_assignment,
            1_050,
        )),
        ObligationError::CompareAndSwapConflict
    );

    let settled = fixture.lifecycle.advance(
        &fixture.atom,
        ObligationSettlementTransitionV1::Settle {
            settlement_id: "settlement-2".to_owned(),
            evidence_digest: digest("settlement-evidence-2"),
            authority_digest: digest("settlement-authority-2"),
        },
    )?;
    let settled_signed = signed_status(
        &fixture,
        &StatusIssue {
            disposition: &fixture.disposition,
            lifecycle: &settled,
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            authority_id: "obligor-disposition-authority",
            authority_key_epoch: 3,
            signer: &fixture.signer,
        },
    )?;
    let settled_verified = verify_status(
        &fixture,
        settled_signed,
        &fixture.disposition,
        &settled,
        1_050,
    )?;
    let settled_operation_id = digest("settled-operation");
    let settled_request = digest("settled-request");
    let settled_authorization = digest("settled-authorization");
    let settled_operation = ObligationAssignmentOperationSnapshotV1::new(
        settled_operation_id.clone(),
        settled_request.clone(),
        &fixture.disposition,
        &settled,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?
    .attach_supplemental_authorization(&settled_authorization)?;
    let settled_assignment = ObligationAssignmentCasV1::new(
        settled_operation,
        assignment_input(
            settled_operation_id,
            settled_request,
            settled_authorization,
            settled_verified.envelope_digest().to_owned(),
            "agreement-settled",
        ),
    )?;
    assert_eq!(
        require_error(fixture.disposition.compare_and_swap_assignment(
            &fixture.atom,
            &settled,
            &settled_verified,
            &settled_assignment,
            1_050,
        )),
        ObligationError::CompareAndSwapConflict
    );
    Ok(())
}
