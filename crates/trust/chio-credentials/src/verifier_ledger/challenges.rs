use chio_core::federation::verifier_ledger::presentation_challenges::{
    ChallengeHash, ChallengeStatus, ChallengeTransition, LiveChallengeStatus,
    PresentationChallengeId, PresentationChallengeLedger, PresentationChallengeRecord,
    PresentationHash, StoredPresentationChallenge,
};
use chio_core::{canonical_json_bytes, sha256_hex};

use super::{decode_stored, LedgerError, CHALLENGE};
use crate::{
    unix_from_rfc3339, verify_passport_presentation_challenge, PassportPresentationChallenge,
    PassportPresentationResponse,
};

/// A challenge admits one verification and one federated issuance at most;
/// issuance after a verification must carry the verified presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeConsumer {
    Verification,
    FederatedIssuance,
}

type Result<T, E> = std::result::Result<T, LedgerError<E>>;

/// A challenge is stored under its `challenge_id`, or its nonce without one.
pub fn challenge_identifier(challenge: &PassportPresentationChallenge) -> &str {
    challenge
        .challenge_id
        .as_deref()
        .unwrap_or(&challenge.nonce)
}

pub fn register_presentation_challenge<L: PresentationChallengeLedger + ?Sized>(
    ledger: &L,
    challenge: &PassportPresentationChallenge,
) -> Result<(), L::Error> {
    let record = PresentationChallengeRecord {
        challenge_id: PresentationChallengeId::parse(challenge_identifier(challenge))?,
        challenge_hash: ChallengeHash::parse(sha256_hex(&canonical_json_bytes(challenge)?))?,
        challenge_json: serde_json::to_string(challenge)?,
        issued_at: unix_from_rfc3339(&challenge.issued_at)?,
        expires_at: unix_from_rfc3339(&challenge.expires_at)?,
    };
    ledger.insert(&record).map_err(LedgerError::Store)
}

pub fn fetch_active_presentation_challenge<L: PresentationChallengeLedger + ?Sized>(
    ledger: &L,
    challenge_id: &str,
    now: u64,
) -> Result<PassportPresentationChallenge, L::Error> {
    let (id, stored) = stored(ledger, challenge_id)?;
    match stored.status {
        ChallengeStatus::Issued => {}
        ChallengeStatus::Verified | ChallengeStatus::Consumed => {
            return Err(LedgerError::AlreadyConsumed(CHALLENGE, challenge_id.into()))
        }
        ChallengeStatus::Expired => {
            return Err(LedgerError::AlreadyExpired(CHALLENGE, challenge_id.into()))
        }
    }
    let record = &stored.record;
    if now > record.expires_at {
        ledger
            .expire(&id, LiveChallengeStatus::Issued)
            .map_err(LedgerError::Store)?;
        return Err(LedgerError::ExpiredInUse(CHALLENGE, challenge_id.into()));
    }
    let challenge: PassportPresentationChallenge = decode_stored(&record.challenge_json)?;
    if challenge_identifier(&challenge) != challenge_id
        || unix_from_rfc3339(&challenge.expires_at)? != record.expires_at
    {
        return Err(LedgerError::Binding("challenge_id/expires_at"));
    }
    verify_passport_presentation_challenge(&challenge, now)?;
    Ok(challenge)
}

pub fn consume_presentation_challenge<L: PresentationChallengeLedger + ?Sized>(
    ledger: &L,
    challenge: &PassportPresentationChallenge,
    presentation: &PassportPresentationResponse,
    consumer: ChallengeConsumer,
    now: u64,
) -> Result<(), L::Error> {
    let presented = PresentationHash::parse(sha256_hex(&canonical_json_bytes(presentation)?))?;
    let challenge_id = challenge_identifier(challenge);
    let (id, stored) = stored(ledger, challenge_id)?;
    if stored.record.challenge_hash.as_str() != sha256_hex(&canonical_json_bytes(challenge)?) {
        return Err(LedgerError::Mismatch(CHALLENGE, challenge_id.into()));
    }
    let transition = match (stored.status, consumer) {
        (ChallengeStatus::Issued, ChallengeConsumer::Verification) => ChallengeTransition::Verify,
        (ChallengeStatus::Issued, ChallengeConsumer::FederatedIssuance) => {
            ChallengeTransition::Issue
        }
        (ChallengeStatus::Verified, ChallengeConsumer::FederatedIssuance)
            if stored.presentation_hash.as_ref() == Some(&presented) =>
        {
            ChallengeTransition::IssueVerified
        }
        (ChallengeStatus::Verified | ChallengeStatus::Consumed, _) => {
            return Err(LedgerError::AlreadyConsumed(CHALLENGE, challenge_id.into()))
        }
        (ChallengeStatus::Expired, _) => {
            return Err(LedgerError::AlreadyExpired(CHALLENGE, challenge_id.into()))
        }
    };
    if now > stored.record.expires_at {
        ledger
            .expire(&id, transition.from())
            .map_err(LedgerError::Store)?;
        return Err(LedgerError::ExpiredInUse(CHALLENGE, challenge_id.into()));
    }
    if !ledger
        .consume(&id, transition, now, &presented)
        .map_err(LedgerError::Store)?
    {
        return Err(LedgerError::Contended(CHALLENGE, challenge_id.into()));
    }
    Ok(())
}

/// An identifier no ledger could hold is not registered.
fn stored<L: PresentationChallengeLedger + ?Sized>(
    ledger: &L,
    challenge_id: &str,
) -> Result<(PresentationChallengeId, StoredPresentationChallenge), L::Error> {
    let not_registered = || LedgerError::NotRegistered(CHALLENGE, challenge_id.into());
    let id = PresentationChallengeId::parse(challenge_id).map_err(|_| not_registered())?;
    let stored = ledger
        .get(&id)
        .map_err(LedgerError::Store)?
        .ok_or_else(not_registered)?;
    Ok((id, stored))
}
