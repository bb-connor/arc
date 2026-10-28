//! Enterprise identity index: one stable identity id per `(provider scope, canonical
//! principal)`, that identity's current keyed enterprise subject under the active tenant index
//! generation, and every prior `(key_id, value)` subject of the identity as history.
//!
//! The index is one JSON document (`chio.enterprise-identity-index.v1`) written only under its
//! registry writer lock and replaced atomically, so every change, including the re-key of every
//! identity after a rotation, commits whole or not at all. Every operation loads the document
//! under the lock, refuses a stored subject whose generation the key set does not hold, and
//! commits the re-key of every identity that is not under the active generation before it
//! reads anything. Deactivation is the one exception: [`deactivate_enterprise_identity`]
//! records it without the re-key, so it persists even when the re-key a rotation requires does
//! not fit.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use chio_core_types::enterprise_subject::{EnterpriseSubjectError, EnterpriseSubjectKey};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::tenant_index::{TenantBindingError, TenantIndexKeySet};
use serde::{Deserialize, Serialize};

use crate::passport_verifier::RegistryUpdateError;
use crate::signed_input::{self, RegistryLock, RevocationReserve};
use crate::CliError;

pub const ENTERPRISE_IDENTITY_INDEX_SCHEMA: &str = "chio.enterprise-identity-index.v1";

const IDENTITY_ID_BYTES: usize = 16;
const IDENTITY_ID_HEX_LEN: usize = 2 * IDENTITY_ID_BYTES;

/// Why an enterprise identity index operation is refused. A refused operation writes nothing.
#[derive(Debug)]
pub enum EnterpriseIdentityIndexError {
    /// A stored or presented subject is refused by the key set: its generation is not loaded,
    /// or it does not verify against its principal.
    Subject(EnterpriseSubjectError),
    /// The index could not be locked, loaded or persisted.
    Registry(RegistryUpdateError),
    /// The document names a schema other than [`ENTERPRISE_IDENTITY_INDEX_SCHEMA`].
    UnsupportedSchema,
    /// An identity id is not 32 lowercase hex characters.
    MalformedIdentityId,
    /// Two identities share an identity id.
    DuplicateIdentityId,
    /// Two identities share a `(provider scope, canonical principal)`.
    DuplicatePrincipal,
    /// Two current or historical subjects share a `(key_id, value)` pair.
    DuplicateSubject,
    /// A history row names no identity.
    OrphanHistory,
    /// No identity has the requested id or principal.
    UnknownIdentity,
    /// The entropy source could not draw an identity id.
    Entropy(RngError),
}

impl fmt::Display for EnterpriseIdentityIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Subject(error) => write!(formatter, "enterprise subject refused: {error}"),
            Self::Registry(error) => fmt::Display::fmt(error, formatter),
            Self::UnsupportedSchema => write!(
                formatter,
                "enterprise identity index schema is not {ENTERPRISE_IDENTITY_INDEX_SCHEMA}"
            ),
            Self::MalformedIdentityId => {
                formatter.write_str("enterprise identity id is not 32 lowercase hex characters")
            }
            Self::DuplicateIdentityId => {
                formatter.write_str("enterprise identity index repeats an identity id")
            }
            Self::DuplicatePrincipal => formatter
                .write_str("enterprise identity index repeats a provider scope and principal"),
            Self::DuplicateSubject => {
                formatter.write_str("enterprise identity index repeats a keyed subject")
            }
            Self::OrphanHistory => {
                formatter.write_str("enterprise identity history names no identity")
            }
            Self::UnknownIdentity => formatter.write_str("enterprise identity is not indexed"),
            Self::Entropy(error) => write!(formatter, "enterprise identity id: {error}"),
        }
    }
}

impl std::error::Error for EnterpriseIdentityIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Subject(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Entropy(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EnterpriseSubjectError> for EnterpriseIdentityIndexError {
    fn from(error: EnterpriseSubjectError) -> Self {
        Self::Subject(error)
    }
}

/// A stable enterprise identity id: 16 bytes drawn from the `Rng` seam, as 32 lowercase hex
/// characters. Rotation never changes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EnterpriseIdentityId(String);

impl EnterpriseIdentityId {
    fn draw(rng: &dyn Rng) -> Result<Self, EnterpriseIdentityIndexError> {
        let mut bytes = [0_u8; IDENTITY_ID_BYTES];
        rng.fill_bytes(&mut bytes)
            .map_err(EnterpriseIdentityIndexError::Entropy)?;
        Ok(Self(hex::encode(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EnterpriseIdentityId {
    type Error = EnterpriseIdentityIndexError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.len() == IDENTITY_ID_HEX_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(text))
        } else {
            Err(EnterpriseIdentityIndexError::MalformedIdentityId)
        }
    }
}

impl From<EnterpriseIdentityId> for String {
    fn from(id: EnterpriseIdentityId) -> Self {
        id.0
    }
}

impl fmt::Display for EnterpriseIdentityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One indexed identity as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseIdentity {
    pub identity_id: EnterpriseIdentityId,
    /// The identity's subject under the active generation.
    pub subject: EnterpriseSubjectKey,
    pub deactivated_at: Option<u64>,
}

/// The identity a principal resolved to, and whether this operation created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    pub identity: EnterpriseIdentity,
    pub inserted: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexDocument {
    schema: String,
    identities: Vec<IdentityRow>,
    history: Vec<HistoryRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityRow {
    identity_id: EnterpriseIdentityId,
    provider_scope: String,
    principal: String,
    subject: EnterpriseSubjectKey,
    deactivated_at: Option<u64>,
}

impl RevocationReserve for IndexDocument {
    /// Each active identity may still grow from `null` to the widest deactivation timestamp.
    fn revocation_reserve(&self) -> Result<usize, CliError> {
        let growth = signed_input::revocation_headroom(&None::<u64>, &Some(u64::MAX))?;
        let active = self
            .identities
            .iter()
            .filter(|row| row.deactivated_at.is_none())
            .count();
        Ok(growth.saturating_mul(active))
    }
}

impl IdentityRow {
    fn view(&self) -> EnterpriseIdentity {
        EnterpriseIdentity {
            identity_id: self.identity_id.clone(),
            subject: self.subject,
            deactivated_at: self.deactivated_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryRow {
    identity_id: EnterpriseIdentityId,
    subject: EnterpriseSubjectKey,
}

/// A loaded index. Every stored subject verifies against its identity's principal under a
/// loaded generation, and subjects are matched only as whole `(key_id, value)` pairs.
#[derive(Debug)]
pub struct EnterpriseIdentityIndex<'k> {
    keys: &'k TenantIndexKeySet,
    identities: BTreeMap<EnterpriseIdentityId, IdentityRow>,
    by_principal: BTreeMap<(String, String), EnterpriseIdentityId>,
    current: BTreeMap<EnterpriseSubjectKey, EnterpriseIdentityId>,
    history: BTreeMap<EnterpriseSubjectKey, EnterpriseIdentityId>,
    changed: bool,
}

impl<'k> EnterpriseIdentityIndex<'k> {
    fn empty(keys: &'k TenantIndexKeySet) -> Self {
        Self {
            keys,
            identities: BTreeMap::new(),
            by_principal: BTreeMap::new(),
            current: BTreeMap::new(),
            history: BTreeMap::new(),
            changed: false,
        }
    }

    fn verified(
        document: IndexDocument,
        keys: &'k TenantIndexKeySet,
    ) -> Result<Self, EnterpriseIdentityIndexError> {
        if document.schema != ENTERPRISE_IDENTITY_INDEX_SCHEMA {
            return Err(EnterpriseIdentityIndexError::UnsupportedSchema);
        }
        let mut index = Self::empty(keys);
        for row in document.identities {
            row.subject
                .verify(keys, &row.provider_scope, &row.principal)?;
            if index.identities.contains_key(&row.identity_id) {
                return Err(EnterpriseIdentityIndexError::DuplicateIdentityId);
            }
            let principal = (row.provider_scope.clone(), row.principal.clone());
            if index
                .by_principal
                .insert(principal, row.identity_id.clone())
                .is_some()
            {
                return Err(EnterpriseIdentityIndexError::DuplicatePrincipal);
            }
            if index
                .current
                .insert(row.subject, row.identity_id.clone())
                .is_some()
            {
                return Err(EnterpriseIdentityIndexError::DuplicateSubject);
            }
            index.identities.insert(row.identity_id.clone(), row);
        }
        for row in document.history {
            let owner = index
                .identities
                .get(&row.identity_id)
                .ok_or(EnterpriseIdentityIndexError::OrphanHistory)?;
            row.subject
                .verify(keys, &owner.provider_scope, &owner.principal)?;
            if index.current.contains_key(&row.subject)
                || index.history.insert(row.subject, row.identity_id).is_some()
            {
                return Err(EnterpriseIdentityIndexError::DuplicateSubject);
            }
        }
        Ok(index)
    }

    fn document(&self) -> IndexDocument {
        let mut history: Vec<HistoryRow> = self
            .history
            .iter()
            .map(|(subject, identity_id)| HistoryRow {
                identity_id: identity_id.clone(),
                subject: *subject,
            })
            .collect();
        history.sort_by(|left, right| {
            (&left.identity_id, &left.subject).cmp(&(&right.identity_id, &right.subject))
        });
        IndexDocument {
            schema: ENTERPRISE_IDENTITY_INDEX_SCHEMA.to_string(),
            identities: self.identities.values().cloned().collect(),
            history,
        }
    }

    /// Re-derives the subject of every identity not under the active generation from its
    /// principal and moves the prior subject to history. Returns how many identities moved.
    fn rekey(&mut self) -> Result<usize, EnterpriseIdentityIndexError> {
        let active = *self.keys.active_key_id();
        let mut moved = 0;
        for (identity_id, row) in &mut self.identities {
            if row.subject.key_id() == &active {
                continue;
            }
            let fresh =
                EnterpriseSubjectKey::derive(self.keys, &row.provider_scope, &row.principal)?;
            let prior = std::mem::replace(&mut row.subject, fresh);
            self.current.remove(&prior);
            if self
                .history
                .remove(&fresh)
                .is_some_and(|owner| owner != *identity_id)
                || self.current.insert(fresh, identity_id.clone()).is_some()
                || self.history.insert(prior, identity_id.clone()).is_some()
            {
                return Err(EnterpriseIdentityIndexError::DuplicateSubject);
            }
            moved += 1;
        }
        if moved > 0 {
            self.changed = true;
        }
        Ok(moved)
    }

    /// The identity of `principal` in `provider_scope`, found by the principal itself, never by
    /// comparing derived subjects.
    #[must_use]
    pub fn resolve(&self, provider_scope: &str, principal: &str) -> Option<EnterpriseIdentity> {
        self.by_principal
            .get(&(provider_scope.to_string(), principal.to_string()))
            .and_then(|identity_id| self.identities.get(identity_id))
            .map(IdentityRow::view)
    }

    /// Resolves the principal and inserts a new identity, under the active generation, only
    /// when none exists. A principal never gets a second identity.
    pub fn resolve_or_insert(
        &mut self,
        rng: &dyn Rng,
        provider_scope: &str,
        principal: &str,
    ) -> Result<ResolvedIdentity, EnterpriseIdentityIndexError> {
        if let Some(identity) = self.resolve(provider_scope, principal) {
            return Ok(ResolvedIdentity {
                identity,
                inserted: false,
            });
        }
        let subject = EnterpriseSubjectKey::derive(self.keys, provider_scope, principal)?;
        let identity_id = EnterpriseIdentityId::draw(rng)?;
        if self.identities.contains_key(&identity_id) {
            return Err(EnterpriseIdentityIndexError::DuplicateIdentityId);
        }
        if self.current.contains_key(&subject) || self.history.contains_key(&subject) {
            return Err(EnterpriseIdentityIndexError::DuplicateSubject);
        }
        let row = IdentityRow {
            identity_id: identity_id.clone(),
            provider_scope: provider_scope.to_string(),
            principal: principal.to_string(),
            subject,
            deactivated_at: None,
        };
        let identity = row.view();
        self.by_principal.insert(
            (provider_scope.to_string(), principal.to_string()),
            identity_id.clone(),
        );
        self.current.insert(subject, identity_id.clone());
        self.identities.insert(identity_id, row);
        self.changed = true;
        Ok(ResolvedIdentity {
            identity,
            inserted: true,
        })
    }

    /// Resolves a subject a login presents: it must verify against the principal under the
    /// generation it names, and the principal must be indexed.
    pub fn resolve_presented(
        &self,
        provider_scope: &str,
        principal: &str,
        presented: &EnterpriseSubjectKey,
    ) -> Result<EnterpriseIdentity, EnterpriseIdentityIndexError> {
        presented.verify(self.keys, provider_scope, principal)?;
        self.resolve(provider_scope, principal)
            .ok_or(EnterpriseIdentityIndexError::UnknownIdentity)
    }

    /// The identity a signed subject attributes to, through the current subjects or history.
    /// A subject under a generation the key set does not hold refuses.
    pub fn resolve_subject(
        &self,
        subject: &EnterpriseSubjectKey,
    ) -> Result<Option<EnterpriseIdentityId>, EnterpriseIdentityIndexError> {
        if !self.keys.key_ids().any(|key_id| key_id == subject.key_id()) {
            return Err(EnterpriseIdentityIndexError::Subject(
                EnterpriseSubjectError::Index(TenantBindingError::TenantIndexKeyUnknown {
                    key_id: *subject.key_id(),
                }),
            ));
        }
        Ok(self
            .current
            .get(subject)
            .or_else(|| self.history.get(subject))
            .cloned())
    }

    /// The prior subjects of one identity, in `(key_id, value)` order.
    #[must_use]
    pub fn history_of(&self, identity_id: &EnterpriseIdentityId) -> Vec<EnterpriseSubjectKey> {
        self.history
            .iter()
            .filter(|(_, owner)| *owner == identity_id)
            .map(|(subject, _)| *subject)
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

/// Runs `operation` on the index at `path` as its single writer.
///
/// Under the registry writer lock this loads the index (a missing file is empty), refuses a
/// stored subject whose generation `keys` does not hold, and commits the re-key of every
/// identity not under the active generation, in one atomic replace, before `operation` reads.
/// A change `operation` makes commits in one further atomic replace; a refused operation
/// writes nothing. With an operation that only reads, this is the startup check.
pub fn with_enterprise_identity_index<R>(
    path: &Path,
    keys: &TenantIndexKeySet,
    operation: impl FnOnce(&mut EnterpriseIdentityIndex<'_>) -> Result<R, EnterpriseIdentityIndexError>,
) -> Result<R, EnterpriseIdentityIndexError> {
    let lock = signed_input::lock_registry(path).map_err(EnterpriseIdentityIndexError::Registry)?;
    let mut index = load(lock.destination(), keys)?;
    index.rekey()?;
    persist_if_changed(&lock, &mut index)?;
    let outcome = operation(&mut index)?;
    persist_if_changed(&lock, &mut index)?;
    Ok(outcome)
}

/// Records `identity_id` as deactivated at `at`, as the single writer of the index at `path`,
/// and returns the deactivation time in force: `at`, or the earlier one already recorded.
/// Deactivation is keyed on the identity id, so no rotation revives it.
///
/// Contract: for an index this module wrote, this persists at any fill level and after any
/// number of rotations, provided `keys` holds every generation the index stores. Every write
/// keeps the compact encoding plus the deactivation reserve of its active identities within the
/// read cap, and recording one deactivation adds at most the reserve it releases. This path
/// loads and verifies the index under the lock but does not re-key it, because the history rows
/// a re-key adds are not reserved and a rotation of a full index cannot be recorded.
pub fn deactivate_enterprise_identity(
    path: &Path,
    keys: &TenantIndexKeySet,
    identity_id: &EnterpriseIdentityId,
    at: u64,
) -> Result<u64, EnterpriseIdentityIndexError> {
    let lock = signed_input::lock_registry(path).map_err(EnterpriseIdentityIndexError::Registry)?;
    let mut index = load(lock.destination(), keys)?;
    let row = index
        .identities
        .get_mut(identity_id)
        .ok_or(EnterpriseIdentityIndexError::UnknownIdentity)?;
    let in_force = match row.deactivated_at {
        Some(earlier) => earlier,
        None => {
            row.deactivated_at = Some(at);
            index.changed = true;
            at
        }
    };
    persist_if_changed(&lock, &mut index)?;
    Ok(in_force)
}

fn load<'k>(
    path: &Path,
    keys: &'k TenantIndexKeySet,
) -> Result<EnterpriseIdentityIndex<'k>, EnterpriseIdentityIndexError> {
    let loading =
        |error: CliError| EnterpriseIdentityIndexError::Registry(RegistryUpdateError::Load(error));
    match signed_input::read_bounded(path) {
        Ok(bytes) => {
            let document: IndexDocument = signed_input::decode(&bytes).map_err(loading)?;
            EnterpriseIdentityIndex::verified(document, keys)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(EnterpriseIdentityIndex::empty(keys))
        }
        Err(error) => Err(loading(CliError::Io(error))),
    }
}

fn persist_if_changed(
    lock: &RegistryLock,
    index: &mut EnterpriseIdentityIndex<'_>,
) -> Result<(), EnterpriseIdentityIndexError> {
    if !index.changed {
        return Ok(());
    }
    signed_input::write_reserving_registry(lock, &index.document()).map_err(|error| {
        EnterpriseIdentityIndexError::Registry(RegistryUpdateError::Persist(error))
    })?;
    index.changed = false;
    Ok(())
}

#[cfg(test)]
#[path = "enterprise_identity_index/tests.rs"]
mod tests;
