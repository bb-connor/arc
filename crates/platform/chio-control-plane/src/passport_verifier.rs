use std::collections::BTreeMap;
use std::path::Path;

use chio_core::Keypair;
use chio_credentials::{
    build_oid4vci_passport_offer, ensure_signed_passport_verifier_policy_active,
    issue_chio_passport_jwt_vc_json, issue_chio_passport_sd_jwt_vc, verify_agent_passport,
    verify_signed_passport_verifier_policy, AgentPassport, Oid4vciChioPassportStatusReference,
    Oid4vciCredentialIssuerMetadata, Oid4vciCredentialOffer, Oid4vciCredentialRequest,
    Oid4vciCredentialResponse, Oid4vciTokenRequest, Oid4vciTokenResponse, PassportLifecycleRecord,
    PassportLifecycleResolution, PassportLifecycleState, PassportStatusDistribution,
    SignedPassportVerifierPolicy, CHIO_PASSPORT_JWT_VC_JSON_FORMAT,
    CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::CliError;

#[cfg(test)]
#[path = "passport_verifier/tests/signed_readback.rs"]
mod signed_readback_tests;

#[cfg(test)]
#[path = "passport_verifier/tests/bounded_persistence.rs"]
mod bounded_persistence_tests;

#[cfg(test)]
#[path = "passport_verifier/tests/fixtures.rs"]
pub(crate) mod test_fixtures;

#[cfg(test)]
#[path = "passport_verifier/tests/revocation_capacity.rs"]
pub(crate) mod revocation_capacity_tests;

#[cfg(test)]
#[path = "passport_verifier/tests/older_registry_files.rs"]
mod older_registry_files_tests;

#[cfg(test)]
#[path = "passport_verifier/tests/registry_writer_lock.rs"]
mod registry_writer_lock_tests;

#[cfg(all(test, unix))]
#[path = "passport_verifier/tests/adjacent_registry_transactions.rs"]
mod adjacent_registry_transactions;

const VERIFIER_POLICY_REGISTRY_VERSION: &str = "chio.passport-verifier-policies.v1";
const PASSPORT_STATUS_REGISTRY_VERSION: &str = "chio.passport-status-registry.v1";
const PASSPORT_ISSUANCE_REGISTRY_VERSION: &str = "chio.passport-issuance-offers.v1";

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
        match crate::signed_input::read_bounded(path) {
            Ok(bytes) => {
                let registry: Self = crate::signed_input::decode(&bytes)?;
                if registry.version != VERIFIER_POLICY_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported verifier policy registry version: {}",
                        registry.version
                    )));
                }
                for (key, document) in &registry.policies {
                    if key != &document.body.policy_id {
                        return Err(CliError::RecordBinding("policy_id"));
                    }
                    verify_signed_passport_verifier_policy(document)
                        .map_err(|error| CliError::policy_error(error.to_string()))?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    /// Updates the latest verified registry under its stable writer lock,
    /// returning the outcome only after durable bounded persistence.
    ///
    /// `change` receives freshly verified state under the lock and must change
    /// it in place, preserving signatures and domain invariants. It is a
    /// trusted Rust caller: replacing state with an earlier copy defeats writer
    /// exclusion. Persistence does not revalidate arbitrary mutations.
    pub fn update<R, E>(
        path: &Path,
        change: impl FnOnce(&mut Self) -> Result<R, E>,
    ) -> Result<R, RegistryTransactionError<E>> {
        crate::signed_input::update_bounded_registry(
            path,
            Self::load,
            crate::signed_input::MAX_SIGNED_FILE_BYTES,
            change,
        )
    }

    #[cfg(test)]
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::signed_input::write_bounded_json(path, self)
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
            return Err(CliError::policy_error(format!(
                "verifier policy `{policy_id}` was not found"
            )));
        };
        verify_signed_passport_verifier_policy(document)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        ensure_signed_passport_verifier_policy_active(document, now)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        Ok(document)
    }

    pub fn upsert(&mut self, document: SignedPassportVerifierPolicy) -> Result<(), CliError> {
        verify_signed_passport_verifier_policy(&document)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        self.policies
            .insert(document.body.policy_id.clone(), document);
        Ok(())
    }

    pub fn remove(&mut self, policy_id: &str) -> bool {
        self.policies.remove(policy_id).is_some()
    }
}

/// A registry transaction failure, preserving the caller's typed refusal.
#[derive(Debug)]
pub enum RegistryTransactionError<E> {
    /// The lock, verified load, or durable persistence failed.
    Registry(RegistryUpdateError),
    /// The operation refused to change the verified current registry.
    Refused(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RegistryTransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(error) => std::fmt::Display::fmt(error, f),
            Self::Refused(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RegistryTransactionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Refused(error) => Some(error),
        }
    }
}

impl From<RegistryTransactionError<CliError>> for CliError {
    fn from(error: RegistryTransactionError<CliError>) -> Self {
        match error {
            RegistryTransactionError::Registry(error) => error.into(),
            RegistryTransactionError::Refused(error) => error,
        }
    }
}

/// Why a registry update wrote nothing, or did not finish writing.
#[derive(Debug)]
pub enum RegistryUpdateError {
    /// Another writer holds the registry's lock. Nothing was read or written;
    /// the update may be retried.
    Busy,
    /// This platform has no writer lock, so registries are never written.
    Unsupported,
    /// The registry could not be locked or loaded. Nothing was written.
    Load(CliError),
    /// The change was refused. Nothing was written.
    Refused(CliError),
    /// The changed registry could not be persisted.
    Persist(CliError),
}

impl std::fmt::Display for RegistryUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str(
                "the registry file is being written by another writer; nothing was changed, retry",
            ),
            Self::Unsupported => f.write_str(
                "registry files can be written only where an exclusive writer lock is available",
            ),
            Self::Load(error) | Self::Refused(error) | Self::Persist(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RegistryUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Busy | Self::Unsupported => None,
            Self::Load(error) | Self::Refused(error) | Self::Persist(error) => Some(error),
        }
    }
}

impl From<RegistryUpdateError> for CliError {
    fn from(error: RegistryUpdateError) -> Self {
        match error {
            RegistryUpdateError::Busy | RegistryUpdateError::Unsupported => {
                CliError::cli_other_error(error.to_string())
            }
            RegistryUpdateError::Load(error)
            | RegistryUpdateError::Refused(error)
            | RegistryUpdateError::Persist(error) => error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusRegistry {
    pub version: String,
    #[serde(default)]
    pub passports: BTreeMap<String, PassportLifecycleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusListResponse {
    pub configured: bool,
    pub count: usize,
    pub passports: Vec<PassportLifecycleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishPassportStatusRequest {
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub distribution: PassportStatusDistribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportStatusRevocationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PassportIssuanceOfferState {
    Offered,
    TokenIssued,
    CredentialIssued,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportIssuanceOfferRecord {
    pub offer_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: PassportIssuanceOfferState,
    pub offer: Oid4vciCredentialOffer,
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_issued_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportIssuanceOfferRegistry {
    pub version: String,
    #[serde(default)]
    pub offers: BTreeMap<String, PassportIssuanceOfferRecord>,
}

impl Default for PassportStatusRegistry {
    fn default() -> Self {
        Self {
            version: PASSPORT_STATUS_REGISTRY_VERSION.to_string(),
            passports: BTreeMap::new(),
        }
    }
}

impl Default for PassportIssuanceOfferRegistry {
    fn default() -> Self {
        Self {
            version: PASSPORT_ISSUANCE_REGISTRY_VERSION.to_string(),
            offers: BTreeMap::new(),
        }
    }
}

impl PassportStatusRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match crate::signed_input::read_bounded(path) {
            Ok(bytes) => {
                let registry: Self = crate::signed_input::decode(&bytes)?;
                if registry.version != PASSPORT_STATUS_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported passport status registry version: {}",
                        registry.version
                    )));
                }
                for (key, record) in &registry.passports {
                    if key != &record.passport_id {
                        return Err(CliError::RecordBinding("passport_id"));
                    }
                    if record.updated_at == 0 {
                        return Err(CliError::policy_error(
                            "passport updated_at must be present and nonzero",
                        ));
                    }
                    verify_passport_lifecycle_record(record)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    /// Loads the registry at `path` under its writer lock, applies `change`,
    /// and persists the result, keeping room for every record to be revoked,
    /// before the lock is released. This is the registry's only writer.
    ///
    /// `change` receives the registry freshly loaded under the lock and must
    /// change it in place. Replacing it with a different or earlier value
    /// would persist that value and defeat the single-writer guarantee, so
    /// callers are trusted to only mutate the loaded registry, as the
    /// trust-control handlers and CLI commands do.
    pub fn update<R>(
        path: &Path,
        change: impl FnOnce(&mut Self) -> Result<R, CliError>,
    ) -> Result<R, RegistryUpdateError> {
        crate::signed_input::update_registry(path, Self::load, change)
    }

    /// Persists this copy under the writer lock without loading the file
    /// first; test fixtures only.
    #[cfg(test)]
    pub(crate) fn save(&self, path: &Path) -> Result<(), CliError> {
        let lock = crate::signed_input::lock_registry(path).map_err(CliError::from)?;
        crate::signed_input::write_reserving_registry(&lock, self)
    }

    pub fn get(&self, passport_id: &str) -> Option<&PassportLifecycleRecord> {
        self.passports.get(passport_id)
    }

    pub fn publish(
        &mut self,
        passport: &AgentPassport,
        published_at: u64,
        distribution: PassportStatusDistribution,
    ) -> Result<PassportLifecycleRecord, CliError> {
        let verification = verify_agent_passport(passport, published_at)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        self.version = PASSPORT_STATUS_REGISTRY_VERSION.to_string();
        if let Some(existing) = self.passports.get(&verification.passport_id) {
            return Ok(existing.clone());
        }

        let credential_digests = chio_credentials::passport_credential_digests(passport)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        let record = PassportLifecycleRecord {
            passport_id: verification.passport_id.clone(),
            subject: verification.subject.clone(),
            issuers: verification.issuers.clone(),
            issuer_count: verification.issuer_count,
            credential_digests,
            published_at,
            updated_at: published_at,
            status: PassportLifecycleState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution,
            valid_until: verification.valid_until.clone(),
        };
        // Load refuses an invalid record, so neither the new record nor a
        // record it supersedes is changed unless load would accept the result.
        verify_passport_lifecycle_record(&record)?;
        let mut superseded = Vec::new();
        for existing in self.passports.values() {
            if existing.subject == verification.subject
                && existing.issuers == verification.issuers
                && existing.status == PassportLifecycleState::Active
            {
                if published_at < existing.published_at {
                    return Err(CliError::policy_error(format!(
                        "passport `{}` published at {published_at} cannot supersede passport `{}`, published later at {}",
                        verification.passport_id, existing.passport_id, existing.published_at
                    )));
                }
                let mut replaced = existing.clone();
                replaced.status = PassportLifecycleState::Superseded;
                replaced.superseded_by = Some(verification.passport_id.clone());
                replaced.updated_at = published_at;
                verify_passport_lifecycle_record(&replaced)?;
                superseded.push(replaced);
            }
        }
        for replaced in superseded {
            self.passports
                .insert(replaced.passport_id.clone(), replaced);
        }
        self.passports
            .insert(verification.passport_id, record.clone());
        Ok(record)
    }

    pub fn resolve_for_passport(
        &self,
        passport: &AgentPassport,
        at: u64,
    ) -> Result<PassportLifecycleResolution, CliError> {
        let verification = verify_agent_passport(passport, at)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        Ok(self
            .get(&verification.passport_id)
            .map(|record| passport_lifecycle_resolution_from_record(record, at))
            .unwrap_or_else(|| PassportLifecycleResolution {
                passport_id: verification.passport_id,
                subject: verification.subject,
                issuers: verification.issuers,
                issuer_count: verification.issuer_count,
                state: PassportLifecycleState::NotFound,
                published_at: None,
                updated_at: None,
                superseded_by: None,
                revoked_at: None,
                revoked_reason: None,
                distribution: PassportStatusDistribution::default(),
                valid_until: verification.valid_until,
                source: None,
            }))
    }

    pub fn resolve(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, crate::CliError> {
        let clock_now = unix_timestamp_now()?;
        Ok(self.resolve_at(passport_id, clock_now))
    }

    pub fn resolve_at(&self, passport_id: &str, at: u64) -> PassportLifecycleResolution {
        self.get(passport_id)
            .map(|record| passport_lifecycle_resolution_from_record(record, at))
            .unwrap_or_else(|| PassportLifecycleResolution {
                passport_id: passport_id.to_string(),
                subject: String::new(),
                issuers: Vec::new(),
                issuer_count: 0,
                state: PassportLifecycleState::NotFound,
                published_at: None,
                updated_at: None,
                superseded_by: None,
                revoked_at: None,
                revoked_reason: None,
                distribution: PassportStatusDistribution::default(),
                valid_until: String::new(),
                source: None,
            })
    }

    pub fn revoke(
        &mut self,
        passport_id: &str,
        reason: Option<&str>,
        revoked_at: Option<u64>,
    ) -> Result<PassportLifecycleRecord, CliError> {
        let Some(entry) = self.passports.get_mut(passport_id) else {
            return Err(CliError::policy_error(format!(
                "passport `{passport_id}` was not found in the lifecycle registry"
            )));
        };
        // The reason bound is the one the save reserve accounts for; a blank
        // reason or a time before publication would make load refuse the file.
        if let Some(reason) = reason {
            crate::signed_input::check_revocation_text("revocation reason", reason)?;
            if reason.trim().is_empty() {
                return Err(CliError::policy_error(
                    "revocation reason must not be blank when present",
                ));
            }
        }
        let revoked_at = match revoked_at {
            Some(at) => at,
            None => unix_timestamp_now()?,
        };
        if revoked_at < entry.published_at {
            return Err(CliError::policy_error(format!(
                "passport `{passport_id}` cannot be revoked at {revoked_at}, before its publication at {}",
                entry.published_at
            )));
        }
        entry.status = PassportLifecycleState::Revoked;
        entry.revoked_at = Some(revoked_at);
        entry.updated_at = revoked_at;
        entry.revoked_reason = reason.map(str::to_string);
        // Passport lifecycle revocation is NOT a capability revocation, so it
        // must not emit chio_capability_revocation_lag_seconds. That family is
        // observed from the actual capability revoke paths instead, keeping the
        // capability-revocation SLO measured on real capability revokes.
        Ok(entry.clone())
    }

    pub(crate) fn portable_status_reference_for_passport(
        &self,
        passport: &AgentPassport,
        at: u64,
    ) -> Result<Oid4vciChioPassportStatusReference, CliError> {
        let resolution = self.resolve_for_passport(passport, at)?;
        resolution
            .validate()
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        match resolution.state {
            PassportLifecycleState::Active => {}
            PassportLifecycleState::Stale => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` has stale lifecycle state and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::Superseded => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` is superseded and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::Revoked => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` is revoked and cannot be delivered with portable lifecycle support",
                    resolution.passport_id
                )))
            }
            PassportLifecycleState::NotFound => {
                return Err(CliError::policy_error(format!(
                    "passport `{}` must be published into the lifecycle registry before portable issuance can advertise lifecycle support",
                    resolution.passport_id
                )))
            }
        }
        if resolution.distribution.is_empty() {
            return Err(CliError::policy_error(format!(
                "passport `{}` must publish at least one resolve_url before portable issuance can advertise lifecycle support",
                resolution.passport_id
            )));
        }
        Ok(Oid4vciChioPassportStatusReference {
            passport_id: resolution.passport_id,
            distribution: resolution.distribution,
        })
    }
}

impl crate::signed_input::RevocationReserve for PassportStatusRegistry {
    fn revocation_reserve(&self) -> Result<usize, CliError> {
        let mut reserved = 0usize;
        for record in self.passports.values() {
            let largest = largest_revoked_lifecycle_record(record)?;
            reserved = reserved
                .saturating_add(crate::signed_input::revocation_headroom(record, &largest)?);
        }
        Ok(reserved)
    }
}

impl PassportIssuanceOfferRegistry {
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match crate::signed_input::read_bounded(path) {
            Ok(bytes) => {
                let registry: Self = crate::signed_input::decode(&bytes)?;
                if registry.version != PASSPORT_ISSUANCE_REGISTRY_VERSION {
                    return Err(CliError::policy_error(format!(
                        "unsupported passport issuance registry version: {}",
                        registry.version
                    )));
                }
                for (key, record) in &registry.offers {
                    if key != &record.offer_id {
                        return Err(CliError::RecordBinding("offer_id"));
                    }
                    verify_passport_issuance_offer_record(record)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    /// Updates a live redemption under the registry's stable writer lock.
    /// No outcome is returned before the bounded file replacement is durable.
    ///
    /// `change` receives freshly verified state under the lock and must change
    /// it in place, preserving signatures and domain invariants. It is a
    /// trusted Rust caller: replacing state with an earlier copy defeats writer
    /// exclusion. Persistence does not revalidate arbitrary mutations.
    pub fn update<R, E>(
        path: &Path,
        change: impl FnOnce(&mut Self) -> Result<R, E>,
    ) -> Result<R, RegistryTransactionError<E>> {
        crate::signed_input::update_bounded_registry(
            path,
            Self::load,
            crate::signed_input::MAX_SIGNED_FILE_BYTES,
            change,
        )
    }

    /// Updates offer issuance while preserving its existing redemption reserve.
    ///
    /// `change` receives freshly verified state under the lock and must change
    /// it in place, preserving signatures and domain invariants. It is a
    /// trusted Rust caller: replacing state with an earlier copy defeats writer
    /// exclusion. Persistence does not revalidate arbitrary mutations.
    pub fn update_for_issuance<R, E>(
        path: &Path,
        change: impl FnOnce(&mut Self) -> Result<R, E>,
    ) -> Result<R, RegistryTransactionError<E>> {
        crate::signed_input::update_bounded_registry(
            path,
            Self::load,
            crate::signed_input::MAX_SIGNED_FILE_BYTES
                - crate::signed_input::ISSUANCE_RESERVE_BYTES,
            change,
        )
    }

    #[cfg(test)]
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::signed_input::write_bounded_json(path, self)
    }

    /// Persists after an issuance, refusing to fill the reserve that live
    /// redemptions need.
    #[cfg(test)]
    pub fn save_for_issuance(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::signed_input::write_bounded_json_with_limit(
            path,
            self,
            crate::signed_input::MAX_SIGNED_FILE_BYTES
                - crate::signed_input::ISSUANCE_RESERVE_BYTES,
        )
    }

    /// Removes offers that can never be redeemed again: fully redeemed,
    /// already expired, or past their own expiry at `now`.
    pub fn prune_dead(&mut self, now: u64) -> usize {
        let before = self.offers.len();
        self.offers.retain(|_, record| {
            !matches!(
                record.state,
                PassportIssuanceOfferState::CredentialIssued | PassportIssuanceOfferState::Expired
            ) && !passport_issuance_offer_expired(record, now)
        });
        before - self.offers.len()
    }

    pub fn issue_offer(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        passport: AgentPassport,
        credential_configuration_id: Option<&str>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<PassportIssuanceOfferRecord, CliError> {
        if ttl_secs == 0 {
            return Err(CliError::cli_other_error(
                "passport issuance offers require ttl_secs greater than zero".to_string(),
            ));
        }
        self.prune_dead(now);
        let credential_configuration_id = credential_configuration_id
            .unwrap_or(CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID);
        metadata
            .credential_configuration(credential_configuration_id)
            .map_err(CliError::from)?;
        let offer_id = KeyId::generate();
        let pre_authorized_code = KeyId::generate();
        let expires_at = now.saturating_add(ttl_secs);
        let offer = build_oid4vci_passport_offer(
            metadata,
            credential_configuration_id,
            &pre_authorized_code,
            &passport,
            expires_at,
        )?;
        let record = PassportIssuanceOfferRecord {
            offer_id: offer_id.clone(),
            issued_at: now,
            expires_at,
            state: PassportIssuanceOfferState::Offered,
            offer,
            passport,
            access_token: None,
            access_token_expires_at: None,
            token_issued_at: None,
            credential_issued_at: None,
        };
        verify_passport_issuance_offer_record(&record)?;
        self.offers.insert(offer_id, record.clone());
        Ok(record)
    }

    pub fn redeem_pre_authorized_code(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        request: &Oid4vciTokenRequest,
        now: u64,
        token_ttl_secs: u64,
    ) -> Result<Oid4vciTokenResponse, CliError> {
        request.validate()?;
        metadata.validate()?;
        let Some(offer_id) = self
            .offers
            .iter()
            .find(|(_, record)| {
                record
                    .offer
                    .grants
                    .pre_authorized_code
                    .as_ref()
                    .is_some_and(|grant| grant.pre_authorized_code == request.pre_authorized_code)
            })
            .map(|(offer_id, _)| offer_id.clone())
        else {
            return Err(CliError::cli_other_error(
                "pre-authorized code is not present in the issuance registry".to_string(),
            ));
        };
        let Some(record) = self.offers.get_mut(&offer_id) else {
            return Err(CliError::cli_other_error(
                "pre-authorized code resolved to a missing issuance offer".to_string(),
            ));
        };
        refresh_passport_issuance_offer_state(record, now);
        if normalize_credential_issuer(&record.offer.credential_issuer)?
            != normalize_credential_issuer(&metadata.credential_issuer)?
        {
            return Err(CliError::policy_error(
                "offer credential_issuer does not match the configured issuer metadata".to_string(),
            ));
        }
        match record.state {
            PassportIssuanceOfferState::Offered => {}
            PassportIssuanceOfferState::TokenIssued => {
                return Err(CliError::cli_other_error(
                    "pre-authorized code has already been redeemed".to_string(),
                ))
            }
            PassportIssuanceOfferState::CredentialIssued => {
                return Err(CliError::policy_error(
                    "credential has already been issued for this offer".to_string(),
                ))
            }
            PassportIssuanceOfferState::Expired => {
                return Err(CliError::cli_other_error(
                    "issuance offer has expired".to_string(),
                ))
            }
        }
        let access_token = KeyId::generate();
        let token_expires_at = now
            .saturating_add(token_ttl_secs.max(1))
            .min(record.expires_at);
        if token_expires_at <= now {
            record.state = PassportIssuanceOfferState::Expired;
            return Err(CliError::cli_other_error(
                "issuance offer expired before an access token could be minted".to_string(),
            ));
        }
        record.access_token = Some(access_token.clone());
        record.access_token_expires_at = Some(token_expires_at);
        record.token_issued_at = Some(now);
        record.state = PassportIssuanceOfferState::TokenIssued;
        Ok(Oid4vciTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.saturating_sub(now),
        })
    }

    /// Check current wallet redemption authority without refreshing or consuming it.
    pub(crate) fn validate_credential_entitlement(
        &self,
        configured_credential_issuer: &str,
        access_token: &str,
        now: u64,
    ) -> Result<&PassportIssuanceOfferRecord, CliError> {
        let record = self
            .offers
            .values()
            .find(|record| record.access_token.as_deref() == Some(access_token))
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "access token is not present in the issuance registry".to_string(),
                )
            })?;
        match record.state {
            PassportIssuanceOfferState::TokenIssued => {}
            PassportIssuanceOfferState::Offered => {
                return Err(CliError::cli_other_error(
                    "access token has not been issued for this offer".to_string(),
                ));
            }
            PassportIssuanceOfferState::CredentialIssued => {
                return Err(CliError::cli_other_error(
                    "credential has already been issued for this access token".to_string(),
                ));
            }
            PassportIssuanceOfferState::Expired => {
                return Err(CliError::cli_other_error(
                    "access token entitlement has expired".to_string(),
                ));
            }
        }
        if passport_issuance_offer_expired(record, now) {
            return Err(CliError::cli_other_error(
                "access token entitlement has expired".to_string(),
            ));
        }
        if normalize_credential_issuer(&record.offer.credential_issuer)?
            != normalize_credential_issuer(configured_credential_issuer)?
        {
            return Err(CliError::policy_error(
                "offer credential_issuer does not match the configured issuer metadata".to_string(),
            ));
        }
        Ok(record)
    }

    pub fn redeem_credential(
        &mut self,
        metadata: &Oid4vciCredentialIssuerMetadata,
        access_token: &str,
        request: &Oid4vciCredentialRequest,
        now: u64,
        portable_signing_keypair: Option<&Keypair>,
        portable_status_registry: Option<(&Path, &PassportStatusRegistry)>,
    ) -> Result<Oid4vciCredentialResponse, CliError> {
        request.validate()?;
        metadata.validate()?;
        let offer_id = self
            .validate_credential_entitlement(&metadata.credential_issuer, access_token, now)?
            .offer_id
            .clone();
        let Some(record) = self.offers.get_mut(&offer_id) else {
            return Err(CliError::cli_other_error(
                "access token resolved to a missing issuance offer".to_string(),
            ));
        };
        refresh_passport_issuance_offer_state(record, now);

        let credential_configuration_id = request
            .validate_against_metadata(metadata)
            .map_err(CliError::from)?;
        let expected_configuration_id = record.offer.primary_configuration_id()?;
        if credential_configuration_id != expected_configuration_id {
            return Err(CliError::policy_error(format!(
                "credential_configuration_id `{credential_configuration_id}` does not match offer configuration `{expected_configuration_id}`"
            )));
        }

        let expected_subject = record
            .offer
            .chio_offer_context
            .as_ref()
            .map(|context| context.subject.as_str())
            .unwrap_or(record.passport.subject.as_str());
        if request.subject != expected_subject {
            return Err(CliError::cli_other_error(format!(
                "credential request subject `{}` does not match offer subject `{expected_subject}`",
                request.subject
            )));
        }

        let format = metadata
            .credential_configuration(expected_configuration_id)
            .map_err(CliError::from)?
            .format
            .clone();
        if request
            .format
            .as_ref()
            .is_some_and(|requested_format| requested_format != &format)
        {
            return Err(CliError::cli_other_error(format!(
                "credential request format does not match offer format `{format}`"
            )));
        }
        let portable_status_reference = portable_status_registry
            .map(|(path, registry)| {
                crate::passport_revocation::portable_passport_status_reference(
                    path,
                    registry,
                    &record.passport,
                    now,
                )
            })
            .transpose()?;

        let response = if format == CHIO_PASSPORT_SD_JWT_VC_FORMAT {
            let keypair = portable_signing_keypair.ok_or_else(|| {
                CliError::cli_other_error(
                    "portable sd-jwt vc issuance requires a signing keypair".to_string(),
                )
            })?;
            let status_reference = portable_status_reference.clone();
            let envelope = issue_chio_passport_sd_jwt_vc(
                &record.passport,
                &metadata.credential_issuer,
                keypair,
                now,
                status_reference.clone(),
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?;
            Oid4vciCredentialResponse::new_portable_sd_jwt(
                format.clone(),
                envelope.compact,
                envelope.passport_id,
                envelope.subject_did,
                status_reference,
                envelope.issuer_jwk,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        } else if format == CHIO_PASSPORT_JWT_VC_JSON_FORMAT {
            let keypair = portable_signing_keypair.ok_or_else(|| {
                CliError::cli_other_error(
                    "portable jwt_vc_json issuance requires a signing keypair".to_string(),
                )
            })?;
            let status_reference = portable_status_reference.clone();
            let envelope = issue_chio_passport_jwt_vc_json(
                &record.passport,
                &metadata.credential_issuer,
                keypair,
                now,
                status_reference.clone(),
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?;
            Oid4vciCredentialResponse::new_portable_jwt_vc_json(
                format.clone(),
                envelope.compact,
                envelope.passport_id,
                envelope.subject_did,
                status_reference,
                envelope.issuer_jwk,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        } else {
            Oid4vciCredentialResponse::new_with_status_reference(
                format.clone(),
                record.passport.clone(),
                portable_status_reference,
            )
            .map_err(|error| CliError::policy_error(error.to_string()))?
        };
        response.validate(now, Some(&format), Some(expected_subject))?;
        record.state = PassportIssuanceOfferState::CredentialIssued;
        record.credential_issued_at = Some(now);
        Ok(response)
    }
}

fn unix_from_rfc3339(value: &str) -> Result<u64, CliError> {
    let datetime = DateTime::parse_from_rfc3339(value).map_err(|error| {
        CliError::cli_other_error(format!("invalid RFC3339 timestamp: {error}"))
    })?;
    u64::try_from(datetime.timestamp())
        .map_err(|_| CliError::cli_other_error(format!("invalid RFC3339 timestamp: {value}")))
}

fn unix_timestamp_now() -> Result<u64, chio_security_types::clock::ClockError> {
    use chio_security_types::clock::{Clock, SystemClock};
    SystemClock.unix_millis().map(|now| now.as_secs())
}

fn verify_passport_lifecycle_record(record: &PassportLifecycleRecord) -> Result<(), CliError> {
    record
        .validate()
        .map_err(|error| CliError::policy_error(error.to_string()))
}

/// `record` with every field a revocation writes set to the larger, by JSON
/// encoding, of its current value and the largest value a revocation may
/// write. Revoking `record` any number of times leaves it no larger than
/// this form, and never makes this form larger.
fn largest_revoked_lifecycle_record(
    record: &PassportLifecycleRecord,
) -> Result<PassportLifecycleRecord, CliError> {
    use crate::signed_input::{encoded_len, largest_revocation_reason};
    let mut largest = record.clone();
    if encoded_len(&record.status)? < encoded_len(&PassportLifecycleState::Revoked)? {
        largest.status = PassportLifecycleState::Revoked;
    }
    largest.updated_at = u64::MAX;
    largest.revoked_at = Some(u64::MAX);
    largest.revoked_reason = Some(largest_revocation_reason(record.revoked_reason.as_deref())?);
    Ok(largest)
}

fn passport_lifecycle_resolution_from_record(
    record: &PassportLifecycleRecord,
    at: u64,
) -> PassportLifecycleResolution {
    let state = if record.status == PassportLifecycleState::Active
        && passport_lifecycle_is_stale(record, at)
    {
        PassportLifecycleState::Stale
    } else {
        record.status
    };
    PassportLifecycleResolution {
        passport_id: record.passport_id.clone(),
        subject: record.subject.clone(),
        issuers: record.issuers.clone(),
        issuer_count: record.issuer_count,
        state,
        published_at: Some(record.published_at),
        updated_at: Some(record.updated_at),
        superseded_by: record.superseded_by.clone(),
        revoked_at: record.revoked_at,
        revoked_reason: record.revoked_reason.clone(),
        distribution: record.distribution.clone(),
        valid_until: record.valid_until.clone(),
        source: None,
    }
}

fn passport_lifecycle_is_stale(record: &PassportLifecycleRecord, at: u64) -> bool {
    record
        .distribution
        .cache_ttl_secs
        .is_some_and(|ttl| record.updated_at.saturating_add(ttl) < at)
}

fn verify_passport_issuance_offer_record(
    record: &PassportIssuanceOfferRecord,
) -> Result<(), CliError> {
    if record.offer_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "passport issuance offer entries must include a non-empty offer_id".to_string(),
        ));
    }
    record.offer.validate().map_err(CliError::from)?;
    let verification =
        verify_agent_passport(&record.passport, record.issued_at).map_err(CliError::from)?;
    if let Some(context) = record.offer.chio_offer_context.as_ref() {
        if context.passport_id != verification.passport_id {
            return Err(CliError::cli_other_error(format!(
                    "passport issuance offer `{}` stores a passport_id that does not match the embedded passport",
                record.offer_id
            )));
        }
        if context.subject != verification.subject {
            return Err(CliError::cli_other_error(format!(
                    "passport issuance offer `{}` stores a subject that does not match the embedded passport",
                record.offer_id
            )));
        }
        if unix_from_rfc3339(&context.expires_at)? != record.expires_at {
            return Err(CliError::cli_other_error(format!(
                "passport issuance offer `{}` has mismatched expires_at metadata",
                record.offer_id
            )));
        }
    }
    if record.state == PassportIssuanceOfferState::TokenIssued && record.access_token.is_none() {
        return Err(CliError::cli_other_error(format!(
            "passport issuance offer `{}` cannot be token-issued without an access_token",
            record.offer_id
        )));
    }
    if record.state == PassportIssuanceOfferState::CredentialIssued
        && record.credential_issued_at.is_none()
    {
        return Err(CliError::cli_other_error(format!(
            "passport issuance offer `{}` cannot be credential-issued without credential_issued_at",
            record.offer_id
        )));
    }
    Ok(())
}

fn refresh_passport_issuance_offer_state(record: &mut PassportIssuanceOfferRecord, now: u64) {
    if record.state == PassportIssuanceOfferState::CredentialIssued {
        return;
    }
    if passport_issuance_offer_expired(record, now) {
        record.state = PassportIssuanceOfferState::Expired;
    }
}

fn passport_issuance_offer_expired(record: &PassportIssuanceOfferRecord, now: u64) -> bool {
    now > record.expires_at
        || record
            .access_token_expires_at
            .is_some_and(|expires_at| now > expires_at)
}

fn normalize_credential_issuer(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::policy_constraint_error(
            "credential_issuer must be non-empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

struct KeyId;

impl KeyId {
    fn generate() -> String {
        chio_core::Keypair::generate().public_key().to_hex()
    }
}

#[cfg(test)]
mod revocation_lag_tests {
    use super::*;

    /// Insert a minimal active lifecycle record so revoke() finds an entry.
    fn seed_one_passport(registry: &mut PassportStatusRegistry) -> String {
        let passport_id = "passport-revocation-lag".to_string();
        let record = PassportLifecycleRecord {
            passport_id: passport_id.clone(),
            subject: "did:example:subject".to_string(),
            issuers: Vec::new(),
            issuer_count: 0,
            credential_digests: vec!["ab".repeat(32)],
            published_at: 1_000,
            updated_at: 1_000,
            status: PassportLifecycleState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution: PassportStatusDistribution::default(),
            valid_until: "2099-01-01T00:00:00Z".to_string(),
        };
        registry.passports.insert(passport_id.clone(), record);
        passport_id
    }

    #[test]
    fn passport_lifecycle_revoke_does_not_observe_capability_revocation_lag() {
        // A passport lifecycle revoke must NOT emit the capability-revocation lag
        // family; that SLO is observed from the actual capability revoke paths
        // (see the cluster delta module).
        let mut registry = PassportStatusRegistry::default();
        let passport_id = seed_one_passport(&mut registry);

        let mut before = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut before);

        let now =
            unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
        let revoked_at = now.saturating_sub(45);
        let _ = registry
            .revoke(&passport_id, Some("compromise"), Some(revoked_at))
            .unwrap_or_else(|error| panic!("revoke succeeds: {error:?}"));

        let mut after = String::new();
        chio_metrics_spec::runtime::families::CAPABILITY_REVOCATION_LAG.render(&mut after);
        assert_eq!(
            before, after,
            "a passport lifecycle revoke must not observe a capability revocation lag sample"
        );
    }
}

#[cfg(test)]
mod registry_update_error_tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn registry_update_error_source_reaches_retained_cli_error() {
        for error in [
            RegistryUpdateError::Load(CliError::cli_other_error("cause")),
            RegistryUpdateError::Refused(CliError::cli_other_error("cause")),
            RegistryUpdateError::Persist(CliError::cli_other_error("cause")),
        ] {
            let source = error.source();
            assert!(
                source.is_some_and(|cause| cause.downcast_ref::<CliError>().is_some()),
                "{error:?} must expose its retained CliError"
            );
        }
    }

    #[test]
    fn registry_update_error_without_native_cause_has_no_source() {
        assert!(RegistryUpdateError::Busy.source().is_none());
        assert!(RegistryUpdateError::Unsupported.source().is_none());
    }
}
