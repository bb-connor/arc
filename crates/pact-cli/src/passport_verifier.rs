use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::DateTime;
use pact_core::{canonical_json_bytes, sha256_hex};
use pact_credentials::{
    ensure_signed_passport_verifier_policy_active, verify_signed_passport_verifier_policy,
    PassportPresentationChallenge, SignedPassportVerifierPolicy,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::CliError;

const VERIFIER_POLICY_REGISTRY_VERSION: &str = "pact.passport-verifier-policies.v1";
const CHALLENGE_STATUS_ISSUED: &str = "issued";
const CHALLENGE_STATUS_CONSUMED: &str = "consumed";
const CHALLENGE_STATUS_EXPIRED: &str = "expired";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyRegistry {
    pub version: String,
    #[serde(default)]
    pub policies: BTreeMap<String, SignedPassportVerifierPolicy>,
}

impl Default for VerifierPolicyRegistry {
    fn default() -> Self {
        Self {
            version: VERIFIER_POLICY_REGISTRY_VERSION.to_string(),
            policies: BTreeMap::new(),
        }
    }
}

impl VerifierPolicyRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let registry: Self = serde_json::from_slice(&bytes)?;
                if registry.version != VERIFIER_POLICY_REGISTRY_VERSION {
                    return Err(CliError::Other(format!(
                        "unsupported verifier policy registry version: {}",
                        registry.version
                    )));
                }
                for document in registry.policies.values() {
                    verify_signed_passport_verifier_policy(document)
                        .map_err(|error| CliError::Other(error.to_string()))?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, policy_id: &str) -> Option<&SignedPassportVerifierPolicy> {
        self.policies.get(policy_id)
    }

    pub fn active_policy(
        &self,
        policy_id: &str,
        now: u64,
    ) -> Result<&SignedPassportVerifierPolicy, CliError> {
        let Some(document) = self.get(policy_id) else {
            return Err(CliError::Other(format!(
                "verifier policy `{policy_id}` was not found"
            )));
        };
        verify_signed_passport_verifier_policy(document)
            .map_err(|error| CliError::Other(error.to_string()))?;
        ensure_signed_passport_verifier_policy_active(document, now)
            .map_err(|error| CliError::Other(error.to_string()))?;
        Ok(document)
    }

    pub fn upsert(&mut self, document: SignedPassportVerifierPolicy) -> Result<(), CliError> {
        verify_signed_passport_verifier_policy(&document)
            .map_err(|error| CliError::Other(error.to_string()))?;
        self.policies
            .insert(document.body.policy_id.clone(), document);
        Ok(())
    }

    pub fn remove(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }
}

#[derive(Debug, Clone)]
pub struct PassportVerifierChallengeStore {
    path: PathBuf,
}

impl PassportVerifierChallengeStore {
    pub fn open(path: &Path) -> Result<Self, CliError> {
        let store = Self {
            path: path.to_path_buf(),
        };
        let connection = store.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS passport_verifier_challenges (
                challenge_id TEXT PRIMARY KEY,
                verifier TEXT NOT NULL,
                nonce TEXT NOT NULL,
                policy_id TEXT,
                challenge_hash TEXT NOT NULL,
                challenge_json TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_passport_verifier_challenges_status
                ON passport_verifier_challenges(status, expires_at);",
        )?;
        Ok(store)
    }

    pub fn register(&self, challenge: &PassportPresentationChallenge) -> Result<(), CliError> {
        let connection = self.connection()?;
        let stored = stored_challenge_row(challenge)?;
        connection.execute(
            "INSERT INTO passport_verifier_challenges (
                challenge_id,
                verifier,
                nonce,
                policy_id,
                challenge_hash,
                challenge_json,
                issued_at,
                expires_at,
                status,
                consumed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                stored.challenge_id,
                stored.verifier,
                stored.nonce,
                stored.policy_id,
                stored.challenge_hash,
                stored.challenge_json,
                stored.issued_at,
                stored.expires_at,
                CHALLENGE_STATUS_ISSUED,
            ],
        )?;
        Ok(())
    }

    pub fn consume(
        &self,
        challenge: &PassportPresentationChallenge,
        now: u64,
    ) -> Result<(), CliError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let challenge_id = challenge_identifier(challenge);
        let Some(stored) = transaction
            .query_row(
                "SELECT challenge_hash, status, expires_at
                 FROM passport_verifier_challenges
                 WHERE challenge_id = ?1",
                [challenge_id.as_ref()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(CliError::Other(format!(
                "challenge `{}` is not registered in the verifier challenge store",
                challenge_id
            )));
        };
        let expected_hash = challenge_hash(challenge)?;
        if stored.0 != expected_hash {
            return Err(CliError::Other(format!(
                "stored verifier challenge `{}` does not match the provided challenge payload",
                challenge_id
            )));
        }
        match stored.1.as_str() {
            CHALLENGE_STATUS_CONSUMED => {
                return Err(CliError::Other(format!(
                    "challenge `{}` has already been consumed",
                    challenge_id
                )))
            }
            CHALLENGE_STATUS_EXPIRED => {
                return Err(CliError::Other(format!(
                    "challenge `{}` has already expired",
                    challenge_id
                )))
            }
            CHALLENGE_STATUS_ISSUED => {}
            other => {
                return Err(CliError::Other(format!(
                    "challenge `{}` has unknown stored status `{other}`",
                    challenge_id
                )))
            }
        }
        if now > stored.2 {
            transaction.execute(
                "UPDATE passport_verifier_challenges
                 SET status = ?2
                 WHERE challenge_id = ?1",
                params![challenge_id.as_ref(), CHALLENGE_STATUS_EXPIRED],
            )?;
            transaction.commit()?;
            return Err(CliError::Other(format!(
                "challenge `{}` expired before it could be consumed",
                challenge_id
            )));
        }
        let updated = transaction.execute(
            "UPDATE passport_verifier_challenges
             SET status = ?2, consumed_at = ?3
             WHERE challenge_id = ?1 AND status = ?4",
            params![
                challenge_id.as_ref(),
                CHALLENGE_STATUS_CONSUMED,
                now,
                CHALLENGE_STATUS_ISSUED,
            ],
        )?;
        if updated != 1 {
            return Err(CliError::Other(format!(
                "challenge `{}` could not be consumed safely",
                challenge_id
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, CliError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Connection::open(&self.path)?)
    }
}

#[derive(Debug)]
struct StoredChallengeRow {
    challenge_id: String,
    verifier: String,
    nonce: String,
    policy_id: Option<String>,
    challenge_hash: String,
    challenge_json: String,
    issued_at: u64,
    expires_at: u64,
}

fn stored_challenge_row(
    challenge: &PassportPresentationChallenge,
) -> Result<StoredChallengeRow, CliError> {
    Ok(StoredChallengeRow {
        challenge_id: challenge_identifier(challenge).into_owned(),
        verifier: challenge.verifier.clone(),
        nonce: challenge.nonce.clone(),
        policy_id: challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.clone()),
        challenge_hash: challenge_hash(challenge)?,
        challenge_json: serde_json::to_string(challenge)?,
        issued_at: unix_from_rfc3339(&challenge.issued_at)?,
        expires_at: unix_from_rfc3339(&challenge.expires_at)?,
    })
}

pub fn challenge_identifier(challenge: &PassportPresentationChallenge) -> Cow<'_, str> {
    challenge
        .challenge_id
        .as_deref()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Borrowed(&challenge.nonce))
}

fn challenge_hash(challenge: &PassportPresentationChallenge) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(challenge)?))
}

fn unix_from_rfc3339(value: &str) -> Result<u64, CliError> {
    let datetime = DateTime::parse_from_rfc3339(value)
        .map_err(|error| CliError::Other(format!("invalid RFC3339 timestamp: {error}")))?;
    u64::try_from(datetime.timestamp())
        .map_err(|_| CliError::Other(format!("invalid RFC3339 timestamp: {value}")))
}
