use chio_federation::verifier_ledger::presentation_challenges::{
    ChallengeHash, ChallengeStatus, ChallengeTransition, LiveChallengeStatus,
    PresentationChallengeId, PresentationChallengeLedger, PresentationChallengeRecord,
    PresentationHash, StoredPresentationChallenge,
};
use rusqlite::{params, OptionalExtension, Row};

use super::{
    duplicate_or, stored_u64, PassportVerifierStoreError, Result, SqlitePassportVerifierStore,
};
use crate::integer::checked;

pub(super) const SCHEMA: &str = include_str!("challenges.sql");

pub(super) const INSERT: &str = "INSERT INTO passport_verifier_challenges (
    challenge_id, challenge_hash, challenge_json, issued_at, expires_at, status
) VALUES (?1, ?2, ?3, ?4, ?5, 'issued')";

pub(super) const SELECT: &str = "SELECT challenge_id, challenge_hash, challenge_json, issued_at,
     expires_at, status, presentation_hash
     FROM passport_verifier_challenges
     WHERE challenge_id = ?1";

pub(super) const EXPIRE: &str = "UPDATE passport_verifier_challenges
     SET status = 'expired'
     WHERE challenge_id = ?1 AND status = ?2";

pub(super) const CONSUME: &str = "UPDATE passport_verifier_challenges
     SET status = ?3, consumed_at = ?4, presentation_hash = ?5
     WHERE challenge_id = ?1 AND status = ?2";

impl PresentationChallengeLedger for SqlitePassportVerifierStore {
    type Error = PassportVerifierStoreError;

    fn insert(&self, record: &PresentationChallengeRecord) -> Result<()> {
        let issued_at: i64 = checked(record.issued_at)?;
        let expires_at: i64 = checked(record.expires_at)?;
        self.transact(|transaction| {
            transaction
                .execute(
                    INSERT,
                    params![
                        record.challenge_id.as_str(),
                        record.challenge_hash.as_str(),
                        record.challenge_json,
                        issued_at,
                        expires_at,
                    ],
                )
                .map_err(|error| duplicate_or(error, record.challenge_id.as_str()))?;
            Ok(())
        })
    }

    fn get(
        &self,
        challenge_id: &PresentationChallengeId,
    ) -> Result<Option<StoredPresentationChallenge>> {
        self.read(|connection| {
            connection
                .query_row(SELECT, [challenge_id.as_str()], |row| Ok(stored(row)))
                .optional()?
                .transpose()
        })
    }

    fn expire(
        &self,
        challenge_id: &PresentationChallengeId,
        from: LiveChallengeStatus,
    ) -> Result<bool> {
        let from = label(from.into());
        self.transact(|transaction| {
            Ok(transaction.execute(EXPIRE, params![challenge_id.as_str(), from])? == 1)
        })
    }

    fn consume(
        &self,
        challenge_id: &PresentationChallengeId,
        transition: ChallengeTransition,
        at: u64,
        presentation_hash: &PresentationHash,
    ) -> Result<bool> {
        let at: i64 = checked(at)?;
        self.transact(|transaction| {
            let updated = transaction.execute(
                CONSUME,
                params![
                    challenge_id.as_str(),
                    label(transition.from().into()),
                    label(transition.to()),
                    at,
                    presentation_hash.as_str(),
                ],
            )?;
            Ok(updated == 1)
        })
    }
}

fn stored(row: &Row<'_>) -> Result<StoredPresentationChallenge> {
    Ok(StoredPresentationChallenge {
        record: PresentationChallengeRecord {
            challenge_id: PresentationChallengeId::parse(row.get::<_, String>(0)?)?,
            challenge_hash: ChallengeHash::parse(row.get::<_, String>(1)?)?,
            challenge_json: row.get(2)?,
            issued_at: stored_u64(row.get(3)?)?,
            expires_at: stored_u64(row.get(4)?)?,
        },
        status: status_from_label(&row.get::<_, String>(5)?)?,
        presentation_hash: row
            .get::<_, Option<String>>(6)?
            .map(PresentationHash::parse)
            .transpose()?,
    })
}

fn label(status: ChallengeStatus) -> &'static str {
    match status {
        ChallengeStatus::Issued => "issued",
        ChallengeStatus::Verified => "verified",
        ChallengeStatus::Consumed => "consumed",
        ChallengeStatus::Expired => "expired",
    }
}

fn status_from_label(label: &str) -> Result<ChallengeStatus> {
    match label {
        "issued" => Ok(ChallengeStatus::Issued),
        "verified" => Ok(ChallengeStatus::Verified),
        "consumed" => Ok(ChallengeStatus::Consumed),
        "expired" => Ok(ChallengeStatus::Expired),
        _ => Err(PassportVerifierStoreError::InvalidRow),
    }
}
