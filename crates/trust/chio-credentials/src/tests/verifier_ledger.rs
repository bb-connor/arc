use chio_core::federation::verifier_ledger::oid4vp_requests::{
    Oid4vpRequestHash, Oid4vpRequestId, Oid4vpRequestLedger, Oid4vpRequestRecord,
    StoredOid4vpRequest,
};
use chio_core::federation::verifier_ledger::presentation_challenges::{
    ChallengeHash, ChallengeTransition, LiveChallengeStatus, PresentationChallengeId,
    PresentationChallengeLedger, PresentationChallengeRecord, PresentationHash,
    StoredPresentationChallenge,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_store_sqlite::{PassportVerifierStoreError, SqlitePassportVerifierStore};

use super::*;
use crate::verifier_ledger::*;

const ISSUED_AT: u64 = 1_710_000_050;
const EXPIRES_AT: u64 = 1_710_000_350;
const NOW: u64 = 1_710_000_120;

fn ledger() -> (impl Sized, SqlitePassportVerifierStore) {
    let (dir, path) = chio_test_support::temp_sqlite_path("verifier-ledger");
    (
        dir,
        SqlitePassportVerifierStore::open(path).expect("open store"),
    )
}

/// A store whose every spend first loses to a rival spend of the same row.
struct RivalSpends<'a>(&'a SqlitePassportVerifierStore);

impl PresentationChallengeLedger for RivalSpends<'_> {
    type Error = PassportVerifierStoreError;

    fn insert(&self, record: &PresentationChallengeRecord) -> Result<(), Self::Error> {
        PresentationChallengeLedger::insert(self.0, record)
    }

    fn get(
        &self,
        id: &PresentationChallengeId,
    ) -> Result<Option<StoredPresentationChallenge>, Self::Error> {
        PresentationChallengeLedger::get(self.0, id)
    }

    fn expire(
        &self,
        id: &PresentationChallengeId,
        from: LiveChallengeStatus,
    ) -> Result<bool, Self::Error> {
        PresentationChallengeLedger::expire(self.0, id, from)
    }

    fn consume(
        &self,
        id: &PresentationChallengeId,
        transition: ChallengeTransition,
        at: u64,
        hash: &PresentationHash,
    ) -> Result<bool, Self::Error> {
        PresentationChallengeLedger::consume(self.0, id, transition, at, hash)?;
        PresentationChallengeLedger::consume(self.0, id, transition, at, hash)
    }
}

impl Oid4vpRequestLedger for RivalSpends<'_> {
    type Error = PassportVerifierStoreError;

    fn insert(&self, record: &Oid4vpRequestRecord) -> Result<(), Self::Error> {
        Oid4vpRequestLedger::insert(self.0, record)
    }

    fn get(&self, id: &Oid4vpRequestId) -> Result<Option<StoredOid4vpRequest>, Self::Error> {
        Oid4vpRequestLedger::get(self.0, id)
    }

    fn expire(&self, id: &Oid4vpRequestId) -> Result<bool, Self::Error> {
        Oid4vpRequestLedger::expire(self.0, id)
    }

    fn consume(&self, id: &Oid4vpRequestId, at: u64) -> Result<bool, Self::Error> {
        Oid4vpRequestLedger::consume(self.0, id, at)?;
        Oid4vpRequestLedger::consume(self.0, id, at)
    }
}

fn challenge(nonce: &str) -> PassportPresentationChallenge {
    create_passport_presentation_challenge(
        "https://rp.example.com",
        nonce,
        ISSUED_AT,
        EXPIRES_AT,
        PassportPresentationOptions::default(),
        None,
    )
    .expect("challenge")
}

fn presentation(
    challenge: &PassportPresentationChallenge,
    subject_seed: u8,
) -> PassportPresentationResponse {
    let subject = Keypair::from_seed(&[subject_seed; 32]);
    respond_to_passport_presentation_challenge(
        &subject,
        &sample_passport(subject_seed, 1),
        challenge,
        NOW,
    )
    .expect("presentation")
}

fn registered(
    challenge: &PassportPresentationChallenge,
) -> (impl Sized, SqlitePassportVerifierStore) {
    let (dir, store) = ledger();
    register_presentation_challenge(&store, challenge).expect("register");
    (dir, store)
}

#[test]
fn verified_challenge_admits_issuance_only_for_the_verified_presentation() {
    let challenge = challenge("nonce-spend");
    let (_dir, store) = registered(&challenge);
    let verified = presentation(&challenge, 7);
    let other = presentation(&challenge, 8);
    consume_presentation_challenge(
        &store,
        &challenge,
        &verified,
        ChallengeConsumer::Verification,
        NOW,
    )
    .expect("verification spends the issued challenge");
    for (presented, consumer) in [
        (&verified, ChallengeConsumer::Verification),
        (&other, ChallengeConsumer::FederatedIssuance),
    ] {
        assert!(matches!(
            consume_presentation_challenge(&store, &challenge, presented, consumer, NOW),
            Err(LedgerError::AlreadyConsumed(..))
        ));
    }
    consume_presentation_challenge(
        &store,
        &challenge,
        &verified,
        ChallengeConsumer::FederatedIssuance,
        NOW,
    )
    .expect("issuance spends the verified challenge");
    assert!(matches!(
        consume_presentation_challenge(
            &store,
            &challenge,
            &verified,
            ChallengeConsumer::FederatedIssuance,
            NOW,
        ),
        Err(LedgerError::AlreadyConsumed(..))
    ));
}

#[test]
fn challenge_past_expiry_is_marked_expired_on_fetch() {
    let challenge = challenge("nonce-expiry");
    let (_dir, store) = registered(&challenge);
    let id = challenge_identifier(&challenge);
    assert_eq!(
        fetch_active_presentation_challenge(&store, id, NOW).expect("active"),
        challenge
    );
    assert!(matches!(
        fetch_active_presentation_challenge(&store, id, EXPIRES_AT + 1),
        Err(LedgerError::ExpiredInUse(..))
    ));
    assert!(matches!(
        fetch_active_presentation_challenge(&store, id, NOW),
        Err(LedgerError::AlreadyExpired(..))
    ));
    for unknown in ["unknown", ""] {
        assert!(matches!(
            fetch_active_presentation_challenge(&store, unknown, NOW),
            Err(LedgerError::NotRegistered(..))
        ));
    }
}

#[test]
fn stored_challenge_cannot_substitute_another_valid_challenge() {
    let challenge = challenge("owned-nonce");
    let (_dir, store) = ledger();
    let foreign = self::challenge("foreign-nonce");
    verify_passport_presentation_challenge(&foreign, NOW).expect("foreign challenge is valid");
    let id = challenge_identifier(&challenge).to_owned();
    let substituted = PresentationChallengeRecord {
        challenge_id: PresentationChallengeId::parse(id.as_str()).expect("challenge id"),
        challenge_hash: ChallengeHash::parse(sha256_hex(
            &canonical_json_bytes(&challenge).expect("canonical"),
        ))
        .expect("challenge hash"),
        challenge_json: serde_json::to_string(&foreign).expect("encode"),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    };
    PresentationChallengeLedger::insert(&store, &substituted).expect("insert");
    assert!(matches!(
        fetch_active_presentation_challenge(&store, &id, NOW),
        Err(LedgerError::Binding(_))
    ));
    assert!(matches!(
        consume_presentation_challenge(
            &store,
            &foreign,
            &presentation(&foreign, 7),
            ChallengeConsumer::Verification,
            NOW,
        ),
        Err(LedgerError::NotRegistered(..))
    ));
}

#[test]
fn lost_spend_race_is_refused() {
    let challenge = challenge("nonce-race");
    let (_dir, store) = registered(&challenge);
    assert!(matches!(
        consume_presentation_challenge(
            &RivalSpends(&store),
            &challenge,
            &presentation(&challenge, 7),
            ChallengeConsumer::Verification,
            NOW,
        ),
        Err(LedgerError::Contended(..))
    ));
}

fn oid4vp_request() -> Oid4vpRequestObject {
    Oid4vpRequestObject {
        client_id: "https://verifier.example.com".to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
            .to_string(),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "nonce-1".to_string(),
        state: "state-1".to_string(),
        iat: ISSUED_AT,
        exp: EXPIRES_AT,
        jti: "oid4vp-1".to_string(),
        request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-1"
            .to_string(),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: vec!["chio_issuer_dids".to_string()],
                issuer_allowlist: vec!["https://trust.example.com".to_string()],
            }],
        },
        identity_assertion: None,
    }
}

#[test]
fn oid4vp_request_is_consumed_once_with_its_own_jwt() {
    let request = oid4vp_request();
    let (_dir, store) = ledger();
    register_oid4vp_request(&store, &request, "request.jwt").expect("register");
    assert_eq!(
        fetch_active_oid4vp_request(&store, &request.jti, NOW).expect("active"),
        (request.clone(), "request.jwt".to_string())
    );
    assert!(matches!(
        consume_oid4vp_request(&store, &request, "other.jwt", NOW),
        Err(LedgerError::Mismatch(..))
    ));
    consume_oid4vp_request(&store, &request, "request.jwt", NOW).expect("consume");
    assert!(matches!(
        consume_oid4vp_request(&store, &request, "request.jwt", NOW),
        Err(LedgerError::AlreadyConsumed(..))
    ));
    let snapshot = oid4vp_request_snapshot(&store, &request.jti, NOW).expect("snapshot");
    assert_eq!(
        snapshot.transaction,
        WalletExchangeTransactionState::consumed(
            &request.jti,
            &request.jti,
            ISSUED_AT,
            EXPIRES_AT,
            NOW
        )
    );
}

#[test]
fn oid4vp_request_past_expiry_is_reported_and_kept_expired() {
    let request = oid4vp_request();
    let (_dir, store) = ledger();
    register_oid4vp_request(&store, &request, "request.jwt").expect("register");
    let snapshot = oid4vp_request_snapshot(&store, &request.jti, EXPIRES_AT + 1).expect("snapshot");
    assert_eq!(
        snapshot.transaction.status,
        WalletExchangeTransactionStatus::Expired
    );
    assert!(matches!(
        fetch_active_oid4vp_request(&store, &request.jti, NOW),
        Err(LedgerError::AlreadyExpired(..))
    ));
    assert!(matches!(
        consume_oid4vp_request(&store, &request, "request.jwt", NOW),
        Err(LedgerError::AlreadyExpired(..))
    ));
}

#[test]
fn oid4vp_lost_consume_race_is_refused() {
    let request = oid4vp_request();
    let (_dir, store) = ledger();
    register_oid4vp_request(&store, &request, "request.jwt").expect("register");
    assert!(matches!(
        consume_oid4vp_request(&RivalSpends(&store), &request, "request.jwt", NOW),
        Err(LedgerError::Contended(..))
    ));
}

#[test]
fn challenge_spend_refuses_a_changed_payload_and_a_late_spend() {
    let challenge = challenge("nonce-late");
    let (_dir, store) = registered(&challenge);
    let verified = presentation(&challenge, 7);
    let mut altered = challenge.clone();
    altered.verifier = "https://other.example.com".to_string();
    assert!(matches!(
        consume_presentation_challenge(
            &store,
            &altered,
            &verified,
            ChallengeConsumer::Verification,
            NOW,
        ),
        Err(LedgerError::Mismatch(..))
    ));
    consume_presentation_challenge(
        &store,
        &challenge,
        &verified,
        ChallengeConsumer::Verification,
        EXPIRES_AT,
    )
    .expect("a spend at the expiry instant is in time");
    assert!(matches!(
        consume_presentation_challenge(
            &store,
            &challenge,
            &verified,
            ChallengeConsumer::FederatedIssuance,
            EXPIRES_AT + 1,
        ),
        Err(LedgerError::ExpiredInUse(..))
    ));
    assert!(matches!(
        consume_presentation_challenge(
            &store,
            &challenge,
            &verified,
            ChallengeConsumer::FederatedIssuance,
            NOW,
        ),
        Err(LedgerError::AlreadyExpired(..))
    ));
}

#[test]
fn oid4vp_request_refuses_a_late_consume_and_a_rebound_or_redated_row() {
    let request = oid4vp_request();
    let (_dir, store) = ledger();
    register_oid4vp_request(&store, &request, "request.jwt").expect("register");
    assert!(matches!(
        consume_oid4vp_request(&store, &request, "request.jwt", EXPIRES_AT + 1),
        Err(LedgerError::ExpiredInUse(..))
    ));
    let mut rebound = oid4vp_request();
    rebound.jti = "oid4vp-2".to_string();
    let record = Oid4vpRequestRecord {
        request_id: Oid4vpRequestId::parse(rebound.jti.as_str()).expect("request id"),
        request_hash: Oid4vpRequestHash::parse(sha256_hex(b"rebound.jwt")).expect("hash"),
        request_json: serde_json::to_string(&request).expect("encode"),
        request_jwt: "rebound.jwt".to_string(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    };
    Oid4vpRequestLedger::insert(&store, &record).expect("insert");
    assert!(matches!(
        fetch_active_oid4vp_request(&store, "oid4vp-2", NOW),
        Err(LedgerError::Binding(_))
    ));
    let mut redated = oid4vp_request();
    redated.jti = "oid4vp-3".to_string();
    let record = Oid4vpRequestRecord {
        request_id: Oid4vpRequestId::parse(redated.jti.as_str()).expect("request id"),
        request_hash: Oid4vpRequestHash::parse(sha256_hex(b"redated.jwt")).expect("hash"),
        request_json: serde_json::to_string(&redated).expect("encode"),
        request_jwt: "redated.jwt".to_string(),
        issued_at: ISSUED_AT + 1,
        expires_at: EXPIRES_AT,
    };
    Oid4vpRequestLedger::insert(&store, &record).expect("insert");
    assert!(matches!(
        fetch_active_oid4vp_request(&store, "oid4vp-3", NOW),
        Err(LedgerError::Binding("request_id/issued_at/expires_at"))
    ));
}
