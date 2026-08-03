use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    CHIO_GOVERNED_APPROVAL_TOKEN_DIGEST_DOMAIN,
};
use chio_core_types::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequest,
    ThresholdApprovalRequirement, VerifiedApprovalSetBody, CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
    CHIO_THRESHOLD_APPROVAL_PROPOSAL_SIGNATURE_DOMAIN, CHIO_VERIFIED_APPROVAL_SET_DOMAIN,
    CHIO_VERIFIED_APPROVAL_SET_SCHEMA, MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES,
    MAX_THRESHOLD_APPROVAL_TOKENS,
};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_test_support::ctx::TestUnwrap;

fn sha256(value: u8) -> String {
    format!("{value:02x}").repeat(32)
}

fn proposal_body(subject: &Keypair) -> ThresholdApprovalProposalBody {
    ThresholdApprovalProposalBody::new(
        "proposal-1",
        "request-1",
        sha256(0x11),
        subject.public_key(),
        sha256(0x22),
        sha256(0x33),
        2,
        sha256(0x44),
        1_000,
        900,
        1_800,
        1_700,
    )
    .test_unwrap("proposal body")
}

#[test]
fn proposal_deadline_is_the_minimum_bounded_expiry() {
    let subject = Keypair::generate();
    let body = proposal_body(&subject);
    assert_eq!(body.proposal_created_at(), 1_000);
    assert_eq!(body.proposal_deadline(), 1_700);

    assert!(ThresholdApprovalProposalBody::new(
        "proposal-1",
        "request-1",
        sha256(0x11),
        subject.public_key(),
        sha256(0x22),
        sha256(0x33),
        2,
        sha256(0x44),
        u64::MAX,
        1,
        u64::MAX,
        u64::MAX,
    )
    .is_err());
    assert!(ThresholdApprovalProposalBody::new(
        "proposal-1",
        "request-1",
        sha256(0x11),
        subject.public_key(),
        sha256(0x22),
        sha256(0x33),
        2,
        sha256(0x44),
        1_000,
        900,
        1_000,
        2_000,
    )
    .is_err());
}

#[test]
fn threshold_identifiers_are_bounded_and_reject_controls() {
    use std::collections::BTreeMap;

    let subject = Keypair::generate();
    let too_long = "x".repeat(MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES + 1);
    assert!(ThresholdApprovalRequest::new(&too_long, "payments", "transfer").is_err());
    assert!(ThresholdApprovalRequest::new("request-1", "pay\u{0}ments", "transfer").is_err());
    assert!(ThresholdApprovalProposalBody::new(
        &too_long,
        "request-1",
        sha256(0x11),
        subject.public_key(),
        sha256(0x22),
        sha256(0x33),
        1,
        sha256(0x44),
        1_000,
        900,
        1_800,
        1_700,
    )
    .is_err());
    assert!(ThresholdApprovalRequirement::new(
        1,
        BTreeMap::from([(too_long, Keypair::generate().public_key())]),
        900,
        sha256(0x33),
        1,
    )
    .is_err());
    let oversized_eligible = (0..=MAX_THRESHOLD_APPROVAL_TOKENS)
        .map(|index| {
            (
                format!("approver-{index}"),
                Keypair::generate().public_key(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(
        ThresholdApprovalRequirement::new(1, oversized_eligible.clone(), 900, sha256(0x33), 1,)
            .is_err()
    );
    assert!(ThresholdApprovalRequirement::new(
        u32::try_from(oversized_eligible.len()).test_unwrap("bounded test size"),
        oversized_eligible,
        900,
        sha256(0x33),
        1,
    )
    .is_err());

    let approver = Keypair::generate();
    assert!(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "x".repeat(MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES + 1),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: sha256(0x11),
            threshold_proposal_hash: None,
            request_id: "request-1".to_string(),
            issued_at: 1_100,
            expires_at: 1_500,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .is_err());
}

#[test]
fn proposal_signature_and_hash_are_domain_separated() {
    let subject = Keypair::generate();
    let authority = Keypair::generate();
    let body = proposal_body(&subject);
    let canonical = canonical_json_bytes(&body).test_unwrap("proposal canonical JSON");
    let body_json = serde_json::to_value(&body).test_unwrap("proposal body JSON");
    assert_eq!(
        body_json["schema"],
        serde_json::json!(CHIO_THRESHOLD_APPROVAL_PROPOSAL_SCHEMA)
    );
    assert_eq!(body_json["requestId"], serde_json::json!("request-1"));
    assert_eq!(body_json["required"], serde_json::json!(2));
    assert_eq!(
        body_json["authorizationCapabilityHash"],
        serde_json::json!(sha256(0x22))
    );
    assert!(body_json.get("request").is_none());
    let mut expected_signing_bytes = CHIO_THRESHOLD_APPROVAL_PROPOSAL_SIGNATURE_DOMAIN
        .as_bytes()
        .to_vec();
    expected_signing_bytes.extend_from_slice(&canonical);
    assert_eq!(
        body.signing_bytes().test_unwrap("proposal signing bytes"),
        expected_signing_bytes
    );

    let proposal = ThresholdApprovalProposal::sign(body, &authority).test_unwrap("signed proposal");
    assert!(proposal
        .verify_signature()
        .test_unwrap("proposal signature"));
    assert_eq!(proposal.policy_authority(), &authority.public_key());

    let first_hash = proposal.proposal_hash().test_unwrap("signed proposal hash");
    assert_eq!(first_hash, sha256_hex(&expected_signing_bytes));
    let envelope_canonical =
        canonical_json_bytes(&proposal).test_unwrap("proposal envelope canonical JSON");
    let reparsed: ThresholdApprovalProposal =
        serde_json::from_slice(&envelope_canonical).test_unwrap("proposal envelope");
    assert_eq!(
        first_hash,
        reparsed
            .proposal_hash()
            .test_unwrap("reparsed proposal hash")
    );
}

#[test]
fn threshold_wire_types_reject_unknown_fields() {
    let subject = Keypair::generate();
    let authority = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(proposal_body(&subject), &authority)
        .test_unwrap("signed proposal");
    let mut value = serde_json::to_value(&proposal).test_unwrap("proposal JSON");
    value
        .as_object_mut()
        .test_unwrap("proposal object")
        .insert("ignoredAuthorityHint".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<ThresholdApprovalProposal>(value).is_err());

    let mut body_value = serde_json::to_value(proposal.body()).test_unwrap("proposal body JSON");
    body_value
        .as_object_mut()
        .test_unwrap("proposal body object")
        .insert("ignoredDeadline".to_string(), serde_json::json!(1_699));
    assert!(serde_json::from_value::<ThresholdApprovalProposalBody>(body_value).is_err());
}

#[test]
fn proposal_signature_rejects_a_changed_deadline() {
    let subject = Keypair::generate();
    let authority = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(proposal_body(&subject), &authority)
        .test_unwrap("signed proposal");
    let mut value = serde_json::to_value(proposal).test_unwrap("proposal JSON");
    value["body"]["proposalDeadline"] = serde_json::json!(1_600);
    let changed: ThresholdApprovalProposal =
        serde_json::from_value(value).test_unwrap("changed proposal");
    assert!(!changed
        .verify_signature()
        .test_unwrap("changed proposal signature"));
}

#[test]
fn approval_token_preserves_legacy_body_and_binds_optional_proposal_hash() {
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let legacy_body = GovernedApprovalTokenBody {
        id: "approval-1".to_string(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: sha256(0x11),
        threshold_proposal_hash: None,
        request_id: "request-1".to_string(),
        issued_at: 1_100,
        expires_at: 1_500,
        decision: GovernedApprovalDecision::Approved,
    };
    let legacy_json = serde_json::to_value(&legacy_body).test_unwrap("legacy body JSON");
    assert!(legacy_json.get("threshold_proposal_hash").is_none());
    let legacy =
        GovernedApprovalToken::sign(legacy_body.clone(), &approver).test_unwrap("legacy approval");
    assert!(legacy
        .verify_signature()
        .test_unwrap("legacy approval signature"));
    assert_eq!(legacy.threshold_proposal_hash, None);

    let threshold_body = GovernedApprovalTokenBody {
        threshold_proposal_hash: Some(sha256(0x55)),
        ..legacy_body
    };
    let threshold =
        GovernedApprovalToken::sign(threshold_body, &approver).test_unwrap("threshold approval");
    assert!(threshold
        .verify_signature()
        .test_unwrap("threshold approval signature"));
    assert_ne!(legacy.signature, threshold.signature);
    assert_eq!(threshold.threshold_proposal_hash, Some(sha256(0x55)));

    let malformed = GovernedApprovalTokenBody {
        threshold_proposal_hash: Some("not-a-hash".to_string()),
        ..threshold.body()
    };
    assert!(GovernedApprovalToken::sign(malformed, &approver).is_err());

    let mut token_value = serde_json::to_value(&threshold).test_unwrap("threshold token JSON");
    token_value
        .as_object_mut()
        .test_unwrap("threshold token object")
        .insert("untrustedHint".to_string(), serde_json::json!("ignored"));
    assert!(serde_json::from_value::<GovernedApprovalToken>(token_value).is_err());
}

#[test]
fn approval_token_digest_covers_the_complete_signed_token() {
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-1".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: sha256(0x11),
            threshold_proposal_hash: Some(sha256(0x55)),
            request_id: "request-1".to_string(),
            issued_at: 1_100,
            expires_at: 1_500,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .test_unwrap("approval token");
    let canonical = canonical_json_bytes(&token).test_unwrap("token canonical JSON");
    let mut expected_preimage = CHIO_GOVERNED_APPROVAL_TOKEN_DIGEST_DOMAIN
        .as_bytes()
        .to_vec();
    expected_preimage.extend_from_slice(&canonical);
    assert_eq!(
        token.token_digest().test_unwrap("token digest"),
        sha256_hex(&expected_preimage)
    );
}

#[test]
fn verified_set_sorts_digests_and_hashes_order_independently() {
    let subject = Keypair::generate();
    let authority = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(proposal_body(&subject), &authority)
        .test_unwrap("signed proposal");
    let first = sha256(0x10);
    let second = sha256(0x20);
    let left = VerifiedApprovalSetBody::new(vec![second.clone(), first.clone()], &proposal)
        .test_unwrap("left approval set");
    let right = VerifiedApprovalSetBody::new(vec![first.clone(), second.clone()], &proposal)
        .test_unwrap("right approval set");
    assert_eq!(left.token_digests(), &[first, second]);
    assert_eq!(left, right);
    assert_eq!(
        left.approval_set_hash().test_unwrap("left set hash"),
        right.approval_set_hash().test_unwrap("right set hash")
    );

    let canonical = canonical_json_bytes(&left).test_unwrap("set canonical JSON");
    let set_json = serde_json::to_value(&left).test_unwrap("approval set JSON");
    assert_eq!(
        set_json["schema"],
        serde_json::json!(CHIO_VERIFIED_APPROVAL_SET_SCHEMA)
    );
    assert_eq!(set_json["required"], serde_json::json!(2));
    assert!(set_json.get("canonicalTokenDigests").is_some());
    let mut expected_preimage = CHIO_VERIFIED_APPROVAL_SET_DOMAIN.as_bytes().to_vec();
    expected_preimage.extend_from_slice(&canonical);
    assert_eq!(
        left.approval_set_hash().test_unwrap("set hash"),
        sha256_hex(&expected_preimage)
    );

    let mut set_value = serde_json::to_value(left).test_unwrap("approval set JSON");
    set_value
        .as_object_mut()
        .test_unwrap("approval set object")
        .insert("unverifiedCount".to_string(), serde_json::json!(2));
    assert!(serde_json::from_value::<VerifiedApprovalSetBody>(set_value).is_err());
}

#[test]
fn verified_set_rejects_unbounded_duplicate_or_insufficient_inputs() {
    let subject = Keypair::generate();
    let authority = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(proposal_body(&subject), &authority)
        .test_unwrap("signed proposal");
    assert!(VerifiedApprovalSetBody::new(vec![sha256(0x10)], &proposal).is_err());
    assert!(VerifiedApprovalSetBody::new(vec![sha256(0x10), sha256(0x10)], &proposal).is_err());
    assert!(VerifiedApprovalSetBody::new(vec!["not-a-digest".to_string(); 2], &proposal).is_err());
    assert!(VerifiedApprovalSetBody::new(
        (0..=MAX_THRESHOLD_APPROVAL_TOKENS)
            .map(|index| sha256(u8::try_from(index).test_unwrap("bounded index")))
            .collect(),
        &proposal,
    )
    .is_err());
}
