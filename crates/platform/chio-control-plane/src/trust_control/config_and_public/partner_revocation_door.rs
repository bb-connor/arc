//! The partner revocation door every passport admission passes through.
//!
//! A door prepares before its acceptance instant: it re-reads the partner
//! registry, matches the presented passport to partners, and syncs every
//! matched mirror that is not fresh. That is the only network phase. The
//! door then admits at one acceptance instant sampled after the last network
//! wait, rechecking every matched mirror at that instant.
use super::*;

use chio_credentials::{credential_digest, passport_artifact_id, AgentPassport};
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, EpochRoot, RevocationKey,
};
use chio_security_types::clock::Clock;

use crate::passport_revocation_mirror::{
    PartnerMirrorCache, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::revocation_partner::{
    RevocationPartner, RevocationPartnerError, RevocationPartnerRegistry,
};

/// How a stale partner mirror catches up with its partner's feed.
pub(crate) trait PartnerMirrorSync: Send + Sync {
    fn sync(
        &self,
        mirror: Arc<PartnerRevocationMirror>,
        partner: &RevocationPartner,
        clock: Arc<dyn Clock>,
    ) -> Result<EpochRoot, PartnerRevocationError>;
}

struct StrictPartnerMirrorSync;

impl PartnerMirrorSync for StrictPartnerMirrorSync {
    fn sync(
        &self,
        mirror: Arc<PartnerRevocationMirror>,
        partner: &RevocationPartner,
        clock: Arc<dyn Clock>,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        sync_partner_revocation_mirror(mirror, partner.clone(), clock)
    }
}

/// The long-lived partner mirror handles and the transport that syncs them.
pub(crate) struct PartnerRevocationDoor {
    mirrors: PartnerMirrorCache,
    sync: Arc<dyn PartnerMirrorSync>,
}

/// What a door binds a presented passport to partner revocations by.
pub(crate) enum PartnerPassportBinding {
    /// A native passport: matched to every partner one of whose issuer keys
    /// signed one of its credentials, and checked by passport id and by the
    /// digest of every credential that partner signed.
    Native(AgentPassport),
    /// A portable credential: matched by its issuer URL and checked by its
    /// passport id.
    Portable { issuer: String, passport_id: String },
}

/// One matched partner mirror and the revocation keys checked against it.
struct MatchedMirror {
    partner: RevocationPartner,
    mirror: Arc<PartnerRevocationMirror>,
    subjects: Vec<RevocationKey>,
}

/// A door after its network phase, ready to admit at one acceptance instant.
pub(crate) struct PreparedPartnerDoor {
    matched: Vec<MatchedMirror>,
}

impl PartnerRevocationDoor {
    /// A door that syncs only over the strict partner feed transport.
    pub(crate) fn strict() -> Self {
        Self::with_sync(Arc::new(StrictPartnerMirrorSync))
    }

    pub(crate) fn with_sync(sync: Arc<dyn PartnerMirrorSync>) -> Self {
        Self {
            mirrors: PartnerMirrorCache::default(),
            sync,
        }
    }

    /// Re-reads the registry at `config.revocation_partners_file`, matches
    /// `binding` to partners and syncs every matched mirror that is not fresh
    /// at the time `clock` reads. A service without a registry matches no
    /// partner.
    pub(crate) fn prepare(
        &self,
        config: &TrustServiceConfig,
        clock: Arc<dyn Clock>,
        binding: &PartnerPassportBinding,
    ) -> Result<PreparedPartnerDoor, CliError> {
        let Some(registry_path) = config.revocation_partners_file.as_deref() else {
            return Ok(PreparedPartnerDoor {
                matched: Vec::new(),
            });
        };
        let registry = RevocationPartnerRegistry::load(registry_path).map_err(registry_error)?;
        self.mirrors.retain(&registry).map_err(partner_error)?;
        let now_ms = clock
            .unix_millis()
            .map_err(|error| CliError::policy_error(format!("revocation clock: {error}")))?
            .get();
        let mut matched = Vec::new();
        for (partner, subjects) in matched_partners(&registry, binding)? {
            let mirror = self
                .mirrors
                .mirror(registry_path, &partner.partner_id)
                .map_err(partner_error)?;
            if mirror.require_fresh(&partner, now_ms).is_err() {
                self.sync
                    .sync(Arc::clone(&mirror), &partner, Arc::clone(&clock))
                    .map_err(partner_error)?;
            }
            matched.push(MatchedMirror {
                partner,
                mirror,
                subjects,
            });
        }
        Ok(PreparedPartnerDoor { matched })
    }
}

impl PreparedPartnerDoor {
    /// Refuses unless every matched mirror is fresh at `now_unix_ms` and holds
    /// none of its revocation keys.
    pub(crate) fn admit(&self, now_unix_ms: u64) -> Result<(), CliError> {
        for matched in &self.matched {
            matched
                .mirror
                .check_passport(&matched.partner, &matched.subjects, now_unix_ms)
                .map_err(partner_error)?;
        }
        Ok(())
    }
}

fn matched_partners(
    registry: &RevocationPartnerRegistry,
    binding: &PartnerPassportBinding,
) -> Result<Vec<(RevocationPartner, Vec<RevocationKey>)>, CliError> {
    match binding {
        PartnerPassportBinding::Native(passport) => {
            let issuers: Vec<String> = passport
                .credentials
                .iter()
                .map(|credential| credential.unsigned.issuer.clone())
                .collect();
            let passport_key = passport_revocation_key(
                &passport_artifact_id(passport)
                    .map_err(|error| CliError::policy_error(error.to_string()))?,
            );
            registry
                .by_issuer_dids(&issuers)
                .into_iter()
                .map(|partner| {
                    let own = partner.issuer_dids().map_err(registry_error)?;
                    let mut subjects = vec![passport_key.clone()];
                    for credential in &passport.credentials {
                        if own.contains(&credential.unsigned.issuer) {
                            let digest = credential_digest(credential)
                                .map_err(|error| CliError::policy_error(error.to_string()))?;
                            subjects.push(credential_revocation_key(&digest));
                        }
                    }
                    Ok((partner.clone(), subjects))
                })
                .collect()
        }
        PartnerPassportBinding::Portable {
            issuer,
            passport_id,
        } => Ok(registry
            .by_issuer(issuer)
            .map_err(registry_error)?
            .map(|partner| (partner.clone(), vec![passport_revocation_key(passport_id)]))
            .into_iter()
            .collect()),
    }
}

fn registry_error(error: RevocationPartnerError) -> CliError {
    match error {
        RevocationPartnerError::Unreadable(_) => {
            CliError::policy_error("revocation partner registry is unreadable")
        }
        other => CliError::policy_error(other.to_string()),
    }
}

fn partner_error(error: PartnerRevocationError) -> CliError {
    CliError::policy_error(error.to_string())
}
