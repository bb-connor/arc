//! Enterprise identity index: one stable identity id per `(provider scope, canonical
//! principal)`, that identity's current keyed enterprise subject under the active tenant index
//! generation, and every prior subject of the identity as history.
//!
//! The index is held by an [`EnterpriseIdentityStore`]. Every operation runs inside one
//! exclusive store transaction: the stored rows are verified against the key set, every identity
//! not under the active generation is re-keyed, the operation runs, and the rows are replaced
//! only when the operation succeeds. A refused operation writes nothing.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::enterprise_subject::{EnterpriseSubjectError, EnterpriseSubjectKey};
use crate::rng::{Rng, RngError};
use crate::tenant_index::{TenantBindingError, TenantIndexKeySet};

/// Most identities one index holds. Deactivation never adds a row, so an indexed identity can
/// always be deactivated.
pub const ENTERPRISE_IDENTITY_MAX_IDENTITIES: usize = 65_536;

const IDENTITY_ID_BYTES: usize = 16;
const IDENTITY_ID_HEX_LEN: usize = 2 * IDENTITY_ID_BYTES;

/// Why an enterprise identity index operation is refused. A refused operation writes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseIdentityIndexError {
    /// A stored or presented subject is refused by the key set: its generation is not loaded,
    /// or it does not verify against its principal.
    Subject(EnterpriseSubjectError),
    /// The store could not be opened, locked, read or committed.
    StoreUnavailable,
    /// A stored row does not decode into an identity or history row.
    MalformedRow,
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
    /// The index already holds [`ENTERPRISE_IDENTITY_MAX_IDENTITIES`] identities.
    CapacityExhausted,
    /// The entropy source could not draw an identity id.
    Entropy(RngError),
}

impl fmt::Display for EnterpriseIdentityIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Subject(error) => {
                return write!(formatter, "enterprise subject refused: {error}")
            }
            Self::Entropy(error) => return write!(formatter, "enterprise identity id: {error}"),
            Self::StoreUnavailable => "enterprise identity store is unavailable",
            Self::MalformedRow => "enterprise identity store holds a malformed row",
            Self::MalformedIdentityId => {
                "enterprise identity id is not 32 lowercase hex characters"
            }
            Self::DuplicateIdentityId => "enterprise identity index repeats an identity id",
            Self::DuplicatePrincipal => {
                "enterprise identity index repeats a provider scope and principal"
            }
            Self::DuplicateSubject => "enterprise identity index repeats a keyed subject",
            Self::OrphanHistory => "enterprise identity history names no identity",
            Self::UnknownIdentity => "enterprise identity is not indexed",
            Self::CapacityExhausted => "enterprise identity index is at its identity bound",
        })
    }
}

impl core::error::Error for EnterpriseIdentityIndexError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Subject(error) => Some(error),
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// The identity a principal resolved to, and whether this operation created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    pub identity: EnterpriseIdentityRow,
    pub inserted: bool,
}

/// One indexed identity. Its subject is under the active generation once loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseIdentityRow {
    pub identity_id: EnterpriseIdentityId,
    pub provider_scope: String,
    pub principal: String,
    pub subject: EnterpriseSubjectKey,
    pub deactivated_at: Option<u64>,
}

/// One stored prior subject of an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseSubjectHistoryRow {
    pub identity_id: EnterpriseIdentityId,
    pub subject: EnterpriseSubjectKey,
}

/// Every stored row of an index, in the store's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnterpriseIdentityRows {
    pub identities: Vec<EnterpriseIdentityRow>,
    pub history: Vec<EnterpriseSubjectHistoryRow>,
}

/// What a store transaction returns: its outcome, and the rows that replace the stored rows.
pub type EnterpriseIdentityTransaction<R> =
    Result<(R, Option<EnterpriseIdentityRows>), EnterpriseIdentityIndexError>;

/// Storage for one enterprise identity index.
pub trait EnterpriseIdentityStore {
    /// Runs `transaction` over the stored rows as the only writer. The rows it returns replace
    /// the stored rows atomically; `None` or an error leaves them unchanged.
    fn transact<R>(
        &self,
        transaction: impl FnOnce(EnterpriseIdentityRows) -> EnterpriseIdentityTransaction<R>,
    ) -> Result<R, EnterpriseIdentityIndexError>;
}

/// Runs `operation` on the index `store` holds, as its single writer. One store transaction
/// verifies every stored subject against `keys`, re-keys every identity not under the active
/// generation and runs `operation`; all of it commits only when `operation` succeeds.
pub fn with_enterprise_identity_index<S: EnterpriseIdentityStore, R>(
    store: &S,
    keys: &TenantIndexKeySet,
    operation: impl FnOnce(&mut EnterpriseIdentityIndex<'_>) -> Result<R, EnterpriseIdentityIndexError>,
) -> Result<R, EnterpriseIdentityIndexError> {
    store.transact(|rows| {
        let mut index = EnterpriseIdentityIndex::verified(rows, keys)?;
        index.rekey()?;
        let outcome = operation(&mut index)?;
        let changed = index.changed.then(|| index.rows());
        Ok((outcome, changed))
    })
}

/// A loaded index. Every stored subject verifies against its identity's principal under a
/// loaded generation, and subjects are matched only as whole `(key_id, value)` pairs.
#[derive(Debug)]
pub struct EnterpriseIdentityIndex<'k> {
    keys: &'k TenantIndexKeySet,
    identities: BTreeMap<EnterpriseIdentityId, EnterpriseIdentityRow>,
    by_principal: BTreeMap<(String, String), EnterpriseIdentityId>,
    current: BTreeMap<EnterpriseSubjectKey, EnterpriseIdentityId>,
    history: BTreeMap<EnterpriseSubjectKey, EnterpriseIdentityId>,
    changed: bool,
}

impl<'k> EnterpriseIdentityIndex<'k> {
    fn verified(
        rows: EnterpriseIdentityRows,
        keys: &'k TenantIndexKeySet,
    ) -> Result<Self, EnterpriseIdentityIndexError> {
        if rows.identities.len() > ENTERPRISE_IDENTITY_MAX_IDENTITIES {
            return Err(EnterpriseIdentityIndexError::CapacityExhausted);
        }
        let mut index = Self {
            keys,
            identities: BTreeMap::new(),
            by_principal: BTreeMap::new(),
            current: BTreeMap::new(),
            history: BTreeMap::new(),
            changed: false,
        };
        for row in rows.identities {
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
        for row in rows.history {
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

    fn rows(&self) -> EnterpriseIdentityRows {
        EnterpriseIdentityRows {
            identities: self.identities.values().cloned().collect(),
            history: self
                .history
                .iter()
                .map(|(subject, identity_id)| EnterpriseSubjectHistoryRow {
                    identity_id: identity_id.clone(),
                    subject: *subject,
                })
                .collect(),
        }
    }

    /// Re-derives the subject of every identity not under the active generation from its
    /// principal and moves the prior subject to history.
    fn rekey(&mut self) -> Result<(), EnterpriseIdentityIndexError> {
        let active = *self.keys.active_key_id();
        for (identity_id, row) in &mut self.identities {
            if row.subject.key_id() == &active {
                continue;
            }
            let fresh =
                EnterpriseSubjectKey::derive(self.keys, &row.provider_scope, &row.principal)?;
            let prior = core::mem::replace(&mut row.subject, fresh);
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
            self.changed = true;
        }
        Ok(())
    }

    /// The identity of `principal` in `provider_scope`, found by the principal itself, never by
    /// comparing derived subjects.
    #[must_use]
    pub fn resolve(&self, provider_scope: &str, principal: &str) -> Option<EnterpriseIdentityRow> {
        self.by_principal
            .get(&(String::from(provider_scope), String::from(principal)))
            .and_then(|identity_id| self.identities.get(identity_id))
            .cloned()
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
        if self.identities.len() >= ENTERPRISE_IDENTITY_MAX_IDENTITIES {
            return Err(EnterpriseIdentityIndexError::CapacityExhausted);
        }
        let subject = EnterpriseSubjectKey::derive(self.keys, provider_scope, principal)?;
        let identity_id = EnterpriseIdentityId::draw(rng)?;
        if self.identities.contains_key(&identity_id) {
            return Err(EnterpriseIdentityIndexError::DuplicateIdentityId);
        }
        if self.current.contains_key(&subject) || self.history.contains_key(&subject) {
            return Err(EnterpriseIdentityIndexError::DuplicateSubject);
        }
        let row = EnterpriseIdentityRow {
            identity_id: identity_id.clone(),
            provider_scope: String::from(provider_scope),
            principal: String::from(principal),
            subject,
            deactivated_at: None,
        };
        let identity = row.clone();
        self.by_principal.insert(
            (String::from(provider_scope), String::from(principal)),
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

    /// Records `identity_id` as deactivated at `at` and returns the deactivation time in force:
    /// `at`, or the earlier one already recorded. Deactivation is keyed on the identity id, so
    /// no rotation revives it.
    pub fn deactivate(
        &mut self,
        identity_id: &EnterpriseIdentityId,
        at: u64,
    ) -> Result<u64, EnterpriseIdentityIndexError> {
        let row = self
            .identities
            .get_mut(identity_id)
            .ok_or(EnterpriseIdentityIndexError::UnknownIdentity)?;
        match row.deactivated_at {
            Some(earlier) => Ok(earlier),
            None => {
                row.deactivated_at = Some(at);
                self.changed = true;
                Ok(at)
            }
        }
    }

    /// Resolves a subject a login presents: it must verify against the principal under the
    /// generation it names, and the principal must be indexed.
    pub fn resolve_presented(
        &self,
        provider_scope: &str,
        principal: &str,
        presented: &EnterpriseSubjectKey,
    ) -> Result<EnterpriseIdentityRow, EnterpriseIdentityIndexError> {
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

#[cfg(test)]
#[path = "enterprise_identity_tests.rs"]
mod tests;
