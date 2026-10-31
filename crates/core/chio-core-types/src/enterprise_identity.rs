//! Enterprise identity index: one stable identity id per `(provider scope, canonical
//! principal)`, that identity's current keyed enterprise subject under the active tenant index
//! generation, and every prior subject of the identity as history.
//!
//! The index is held by an [`EnterpriseIdentityStore`]. Every operation runs inside one
//! exclusive store transaction: the stored rows are verified against the key set, every identity
//! not under the active generation is re-keyed, the operation runs, and the changes it made are
//! committed only when the operation succeeds. A refused operation writes nothing.

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

/// Most history rows one index holds. Deactivation never adds history.
pub const ENTERPRISE_IDENTITY_MAX_HISTORY: usize = 262_144;

/// Most bytes of a provider scope or a canonical principal. Both are also non-empty and free
/// of NUL.
pub const ENTERPRISE_PRINCIPAL_MAX_BYTES: usize = 4096;

const MAX_DEACTIVATED_AT: u64 = i64::MAX.unsigned_abs();
const IDENTITY_ID_BYTES: usize = 16;
const IDENTITY_ID_HEX_LEN: usize = 2 * IDENTITY_ID_BYTES;

/// The class of a storage fault, independent of the storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFault {
    /// Another writer holds the store past its wait budget.
    Busy,
    /// The store could not be opened, read or written.
    Io,
    /// The store's storage is corrupt or is not a store of this kind.
    Corrupt,
    /// A write broke a stored integrity constraint.
    Constraint,
}

/// Why an enterprise identity index operation is refused. A refused operation writes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseIdentityIndexError {
    /// A stored or presented subject is refused by the key set: its generation is not loaded,
    /// or it does not verify against its principal.
    Subject(EnterpriseSubjectError),
    /// The store could not be locked, read or committed.
    StoreUnavailable(StoreFault),
    /// A stored row does not decode into an identity or history row, or the store holds more
    /// rows than the index bounds allow.
    MalformedRow,
    /// An identity id is not 32 lowercase hex characters.
    MalformedIdentityId,
    /// A presented provider scope or principal is empty, holds NUL, or exceeds
    /// [`ENTERPRISE_PRINCIPAL_MAX_BYTES`].
    InvalidPrincipal,
    /// A deactivation time exceeds `i64::MAX`.
    InvalidTime,
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
    /// Re-keying would exceed [`ENTERPRISE_IDENTITY_MAX_HISTORY`] history rows.
    HistoryExhausted,
    /// The entropy source could not draw an identity id.
    Entropy(RngError),
}

impl fmt::Display for EnterpriseIdentityIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Subject(error) => return write!(formatter, "enterprise subject: {error}"),
            Self::Entropy(error) => return write!(formatter, "enterprise identity id: {error}"),
            Self::StoreUnavailable(fault) => return write!(formatter, "store fault: {fault:?}"),
            Self::MalformedRow => "enterprise identity store holds a malformed row",
            Self::MalformedIdentityId => "enterprise identity id is not 32 lowercase hex digits",
            Self::InvalidPrincipal => "enterprise provider scope or principal is out of bounds",
            Self::InvalidTime => "enterprise identity deactivation time exceeds i64::MAX",
            Self::DuplicateIdentityId => "enterprise identity index repeats an identity id",
            Self::DuplicatePrincipal => "enterprise identity index repeats a principal",
            Self::DuplicateSubject => "enterprise identity index repeats a keyed subject",
            Self::OrphanHistory => "enterprise identity history names no identity",
            Self::UnknownIdentity => "enterprise identity is not indexed",
            Self::CapacityExhausted => "enterprise identity index is at its identity bound",
            Self::HistoryExhausted => "enterprise identity index is at its history bound",
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

/// Refuses unless `scope` and `principal` are both non-empty, NUL-free and within
/// [`ENTERPRISE_PRINCIPAL_MAX_BYTES`].
fn checked_principal(scope: &str, principal: &str) -> Result<(), EnterpriseIdentityIndexError> {
    let valid = |text: &str| {
        !text.is_empty() && text.len() <= ENTERPRISE_PRINCIPAL_MAX_BYTES && !text.contains('\0')
    };
    let valid = valid(scope) && valid(principal);
    valid
        .then_some(())
        .ok_or(EnterpriseIdentityIndexError::InvalidPrincipal)
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

    /// The id as 32 lowercase hex characters.
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
    /// The resolved identity.
    pub identity: EnterpriseIdentityRow,
    /// Whether this operation inserted the identity.
    pub inserted: bool,
}

/// One indexed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseIdentityRow {
    /// The stable identity id.
    pub identity_id: EnterpriseIdentityId,
    /// The identity provider scope the principal belongs to.
    pub provider_scope: String,
    /// The canonical principal within the provider scope.
    pub principal: String,
    /// The identity's current keyed subject.
    pub subject: EnterpriseSubjectKey,
    /// When the identity was deactivated, in seconds since the Unix epoch, at most `i64::MAX`.
    pub deactivated_at: Option<u64>,
}

/// One stored prior subject of an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseSubjectHistoryRow {
    /// The identity the subject belonged to.
    pub identity_id: EnterpriseIdentityId,
    /// The prior keyed subject.
    pub subject: EnterpriseSubjectKey,
}

/// Every stored row of an index, in the store's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnterpriseIdentityRows {
    /// Every stored identity.
    pub identities: Vec<EnterpriseIdentityRow>,
    /// Every stored history row.
    pub history: Vec<EnterpriseSubjectHistoryRow>,
}

/// The writes one successful operation commits, applied by the store in field order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnterpriseIdentityChanges {
    /// History rows to delete: subjects a re-key made current again.
    pub restored: Vec<EnterpriseSubjectKey>,
    /// Identities to insert.
    pub inserted: Vec<EnterpriseIdentityRow>,
    /// Identities whose stored subject is replaced by the given subject.
    pub rekeyed: Vec<(EnterpriseIdentityId, EnterpriseSubjectKey)>,
    /// History rows to insert.
    pub history: Vec<EnterpriseSubjectHistoryRow>,
    /// Identities to deactivate at the given time, applied only where not yet deactivated.
    pub deactivated: Vec<(EnterpriseIdentityId, u64)>,
}

/// The body of one store transaction: it receives every stored row and returns the changes to
/// commit, `None` to commit nothing, or an error to roll back.
pub type EnterpriseIdentityTransaction<'a> = dyn FnMut(
        EnterpriseIdentityRows,
    ) -> Result<Option<EnterpriseIdentityChanges>, EnterpriseIdentityIndexError>
    + 'a;

/// Storage for one enterprise identity index.
pub trait EnterpriseIdentityStore {
    /// Runs `transaction` over the stored rows as the only writer and commits the changes it
    /// returns atomically. `None` or an error leaves the stored rows unchanged.
    fn transact(
        &self,
        transaction: &mut EnterpriseIdentityTransaction<'_>,
    ) -> Result<(), EnterpriseIdentityIndexError>;
}

/// Runs `operation` on the index `store` holds, as its single writer. One store transaction
/// verifies every stored subject against `keys`, re-keys every identity not under the active
/// generation and runs `operation`; all of it commits only when `operation` succeeds.
pub fn with_enterprise_identity_index<R>(
    store: &dyn EnterpriseIdentityStore,
    keys: &TenantIndexKeySet,
    mut operation: impl FnMut(
        &mut EnterpriseIdentityIndex<'_>,
    ) -> Result<R, EnterpriseIdentityIndexError>,
) -> Result<R, EnterpriseIdentityIndexError> {
    let mut outcome = None;
    store.transact(&mut |rows| {
        let mut index = EnterpriseIdentityIndex::verified(rows, keys)?;
        index.rekey()?;
        outcome = Some(operation(&mut index)?);
        let changed = index.changes != EnterpriseIdentityChanges::default();
        Ok(changed.then_some(index.changes))
    })?;
    outcome.ok_or(EnterpriseIdentityIndexError::StoreUnavailable(
        StoreFault::Io,
    ))
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
    changes: EnterpriseIdentityChanges,
}

impl<'k> EnterpriseIdentityIndex<'k> {
    fn verified(
        rows: EnterpriseIdentityRows,
        keys: &'k TenantIndexKeySet,
    ) -> Result<Self, EnterpriseIdentityIndexError> {
        if rows.identities.len() > ENTERPRISE_IDENTITY_MAX_IDENTITIES
            || rows.history.len() > ENTERPRISE_IDENTITY_MAX_HISTORY
        {
            return Err(EnterpriseIdentityIndexError::MalformedRow);
        }
        let mut index = Self {
            keys,
            identities: BTreeMap::new(),
            by_principal: BTreeMap::new(),
            current: BTreeMap::new(),
            history: BTreeMap::new(),
            changes: EnterpriseIdentityChanges::default(),
        };
        for row in rows.identities {
            if checked_principal(&row.provider_scope, &row.principal).is_err()
                || row.deactivated_at > Some(MAX_DEACTIVATED_AT)
            {
                return Err(EnterpriseIdentityIndexError::MalformedRow);
            }
            row.subject
                .verify(keys, &row.provider_scope, &row.principal)?;
            let id = row.identity_id.clone();
            if index.identities.contains_key(&id) {
                return Err(EnterpriseIdentityIndexError::DuplicateIdentityId);
            }
            let principal = (row.provider_scope.clone(), row.principal.clone());
            if index.by_principal.insert(principal, id.clone()).is_some() {
                return Err(EnterpriseIdentityIndexError::DuplicatePrincipal);
            }
            if index.current.insert(row.subject, id.clone()).is_some() {
                return Err(EnterpriseIdentityIndexError::DuplicateSubject);
            }
            index.identities.insert(id, row);
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
            match self.history.remove(&fresh) {
                Some(owner) if owner != *identity_id => {
                    return Err(EnterpriseIdentityIndexError::DuplicateSubject)
                }
                Some(_) => self.changes.restored.push(fresh),
                None => {}
            }
            if self.history.len() >= ENTERPRISE_IDENTITY_MAX_HISTORY {
                return Err(EnterpriseIdentityIndexError::HistoryExhausted);
            }
            let prior = core::mem::replace(&mut row.subject, fresh);
            self.current.remove(&prior);
            if self.current.insert(fresh, identity_id.clone()).is_some()
                || self.history.insert(prior, identity_id.clone()).is_some()
            {
                return Err(EnterpriseIdentityIndexError::DuplicateSubject);
            }
            self.changes.rekeyed.push((identity_id.clone(), fresh));
            self.changes.history.push(EnterpriseSubjectHistoryRow {
                identity_id: identity_id.clone(),
                subject: prior,
            });
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
        checked_principal(provider_scope, principal)?;
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
        let identity = EnterpriseIdentityRow {
            identity_id: identity_id.clone(),
            provider_scope: String::from(provider_scope),
            principal: String::from(principal),
            subject,
            deactivated_at: None,
        };
        self.by_principal.insert(
            (String::from(provider_scope), String::from(principal)),
            identity_id.clone(),
        );
        self.current.insert(subject, identity_id.clone());
        self.identities.insert(identity_id, identity.clone());
        self.changes.inserted.push(identity.clone());
        Ok(ResolvedIdentity {
            identity,
            inserted: true,
        })
    }

    /// Records `identity_id` as deactivated at `at` and returns the deactivation time in force:
    /// `at`, or the earlier one already recorded. Deactivation is keyed on the identity id, so
    /// no rotation revives it. A time above `i64::MAX` refuses.
    pub fn deactivate(
        &mut self,
        identity_id: &EnterpriseIdentityId,
        at: u64,
    ) -> Result<u64, EnterpriseIdentityIndexError> {
        if at > MAX_DEACTIVATED_AT {
            return Err(EnterpriseIdentityIndexError::InvalidTime);
        }
        let row = self
            .identities
            .get_mut(identity_id)
            .ok_or(EnterpriseIdentityIndexError::UnknownIdentity)?;
        match row.deactivated_at {
            Some(earlier) => Ok(earlier),
            None => {
                row.deactivated_at = Some(at);
                self.changes.deactivated.push((identity_id.clone(), at));
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
        checked_principal(provider_scope, principal)?;
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

    /// How many identities the index holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Whether the index holds no identity.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

#[cfg(test)]
#[path = "enterprise_identity_tests.rs"]
mod tests;
