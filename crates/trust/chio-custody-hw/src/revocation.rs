//! Revocation cascade through the sparse-Merkle revocation oracle.
//!
//! Revoking a WebAuthn credential at the issuer (e.g. operator pulls a
//! stolen authenticator) MUST deny the next custody mint within the
//! current oracle epoch. This module wires the
//! [`chio_revocation_oracle::RevocationOracle`] surface into the issuer
//! mint path:
//!
//! 1. The issuer holds an [`Arc<dyn CredentialRevocationOracle>`]
//!    consulted before signing the capability.
//! 2. Operator-side credential revocation calls
//!    [`CredentialRevocationOracle::revoke_credential`], which inserts a
//!    leaf keyed on the WebAuthn credential id into the oracle AND
//!    cascades to every dependent subject registered under that
//!    credential (see the cascade contract below).
//! 3. The next mint observes the new epoch root, finds the credential
//!    revoked, and fails-closed with
//!    [`crate::CustodyError::CredentialRevoked`].
//!
//! # Cascade contract
//!
//! A custody credential can act as a PARENT for derived capabilities or
//! child credentials (for example a delegated session credential minted
//! from a hardware authenticator). Revoking the parent MUST propagate to
//! every dependent the issuer registered through
//! [`CredentialRevocationOracle::register_dependency`]. The cascade is
//! transitive: revoking A revokes B and, if B was itself a parent of C,
//! revokes C as well. The cascade is computed synchronously inside
//! `revoke_credential` so a single operator revocation atomically denies
//! the parent and the whole dependent subtree within one oracle epoch.
//!
//! # Transactional cascade (all-or-nothing)
//!
//! The cascade is transactional: `revoke_credential` STAGES every
//! dependent leaf and commits the whole batch atomically, or rolls back
//! on any error so a partial failure can never leave a partially-applied
//! revocation. Concretely, the in-memory implementation walks the
//! dependency graph against a SCRATCH clone of the sparse-Merkle oracle;
//! only if every leaf in the transitive closure inserts cleanly is the
//! scratch oracle swapped in for the live one. If any insert errors, the
//! scratch copy is dropped and the live oracle is left byte-identical to
//! its pre-call state. The durable implementation wraps the same staging
//! in a single SQLite transaction so the persisted leaf set and the
//! rebuilt Merkle root advance together or not at all.
//!
//! Fail-closed: if the dependency graph cannot be evaluated (a poisoned
//! lock, an oracle insert error mid-cascade, or a durable-store I/O
//! failure), `revoke_credential` returns [`crate::CustodyError`], the
//! revocation state is left unchanged, and the issuer treats the
//! credential as deny-by-default. [`CredentialRevocationOracle::is_revoked`]
//! likewise surfaces lock failures as errors so the issuer never mints
//! while the revocation state is unknown.
//!
//! # In-flight settlement cancellation (seam)
//!
//! Revoking a credential denies the NEXT mint, but a settlement already
//! in flight under a previously-minted capability is outside this
//! module's reach. The intended seam is for the control-plane operator
//! that drives [`CredentialRevocationOracle::revoke_credential`] to also
//! signal the settlement engine to cancel any in-flight settlement keyed
//! on the revoked subject(s). The full revoked closure is exposed for
//! exactly this fan-out via
//! [`CredentialRevocationOracle::revoked_closure`], which returns the root
//! subject plus every transitively-dependent subject the revocation covers
//! (not just the root the operator passed in), so the cancellation signal
//! can reach the whole subtree. Wiring that cancellation call is left to
//! the settlement crate; this module owns only the deny-the-next-mint half
//! of the contract.
//!
//! # Trust contract
//!
//! - Revocation MUST be observable before the next custody mint completes.
//!   The cascade is therefore synchronous from the issuer's point of view:
//!   `mint_capability` calls `is_revoked` and refuses to mint if it returns
//!   `true`.
//! - The `RevocationOracle` trait operates on
//!   `(SubjectId, EpochNonce)`; for credentials we encode the WebAuthn
//!   credential id (already base64url-no-pad) as the subject id and use a
//!   fixed `EpochNonce(0)` so a single revocation per credential is
//!   sufficient.
//! - This module owns its own keying convention so the oracle does not
//!   need to know about WebAuthn semantics.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use chio_revocation_oracle::{
    EpochNonce, EpochRoot, InMemoryRevocationOracle, RevocationKey, RevocationOracle, SubjectId,
};

use crate::error::CustodyError;

/// Fixed epoch-nonce numeric used for credential revocation leaves.
///
/// We use a single nonce per credential id so the cascade has at most
/// one leaf per WebAuthn credential. The sparse-Merkle layer accepts
/// arbitrary `EpochNonce` values; the issuer-side cascade does not need
/// the additional dimension. The constant is a `u64` because
/// [`EpochNonce::new`] is not currently `const fn`; see
/// [`credential_revocation_nonce`].
pub const CREDENTIAL_REVOCATION_NONCE_VALUE: u64 = 0;

/// Build the fixed [`EpochNonce`] used for credential revocation leaves.
#[must_use]
pub fn credential_revocation_nonce() -> EpochNonce {
    EpochNonce::new(CREDENTIAL_REVOCATION_NONCE_VALUE)
}

/// Issuer-side revocation surface keyed on WebAuthn credential id.
///
/// The custody surface owns this trait; the sparse-Merkle oracle
/// implements [`chio_revocation_oracle::RevocationOracle`] under the
/// hood. We translate between the two so callers do not have to know
/// about `(SubjectId, EpochNonce)`.
pub trait CredentialRevocationOracle: Send + Sync {
    /// Register `dependent` as derived from `parent`. Revoking `parent`
    /// (now or later) MUST cascade to `dependent`. Idempotent: repeated
    /// registration of the same edge is a no-op.
    ///
    /// The cascade is transitive, so a dependent may itself be the parent
    /// of further dependents. Implementations MUST guard against cycles so
    /// a self-referential or mutually-dependent registration cannot wedge
    /// the cascade in an unbounded loop.
    ///
    /// Fail-closed: if the dependency graph cannot be mutated (poisoned
    /// lock), this returns [`CustodyError`] and the edge is NOT recorded;
    /// the caller must treat registration failure as a revocation-state
    /// fault, not silently proceed.
    fn register_dependency(&self, parent: &str, dependent: &str) -> Result<(), CustodyError>;

    /// Mark `credential_id` revoked AND cascade to every dependent
    /// registered (transitively) under it. Subsequent calls to
    /// [`Self::is_revoked`] for the credential or any of its dependents
    /// MUST return `true`.
    ///
    /// Returns the oracle epoch root after the insertion(s) so the operator
    /// can correlate the revocation with the appropriate epoch in
    /// downstream receipts.
    ///
    /// Fail-closed: if any leaf in the cascade cannot be inserted the call
    /// returns [`CustodyError`]; the issuer denies by default rather than
    /// minting against a partially-applied revocation.
    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError>;

    /// True if the credential (or a parent that cascaded to it) is in the
    /// revoked set under the current epoch root. Fail-closed:
    /// implementations MUST return `true` when the subject is present and
    /// MUST surface lock/evaluation failures as `Err(_)` so the issuer
    /// never mints while the revocation state is unknown.
    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError>;

    /// Return the full revoked closure of `credential_id`: the root subject
    /// plus every dependent reachable from it through the registered
    /// adjacency (transitively, cycle-safe). This is the seam the
    /// in-flight-settlement cancellation contract documents: a control-plane
    /// operator that drives [`Self::revoke_credential`] can call this to
    /// enumerate every subject the revocation covers and fan a settlement
    /// cancellation out across the whole subtree, not just the root it
    /// passed in.
    ///
    /// The closure is independent of whether the subjects are already
    /// revoked, so it can be queried before OR after `revoke_credential`.
    /// Each subject appears at most once; the root is always included.
    ///
    /// Fail-closed: lock/evaluation failures surface as `Err(_)`.
    fn revoked_closure(&self, credential_id: &str) -> Result<Vec<String>, CustodyError>;

    /// Snapshot the current oracle epoch root. Surfaced for observability.
    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError>;
}

/// Internal state guarded by a single `Mutex`: the sparse-Merkle
/// oracle plus the parent -> dependents adjacency used by the cascade.
/// Both live under one lock so a revocation and its cascade are applied
/// atomically with respect to a concurrent `is_revoked` consultation.
///
/// Both the in-memory and the durable SQLite backends share this model:
/// the durable backend keeps a `CascadeState` as a write-through cache of
/// the persisted leaf set + edges so reads stay O(1) and the staging /
/// commit logic is identical across backends.
#[derive(Clone)]
struct CascadeState {
    oracle: InMemoryRevocationOracle,
    dependents: HashMap<String, HashSet<String>>,
}

/// Build the fixed revocation key for a credential subject.
fn key_for(credential_id: &str) -> RevocationKey {
    RevocationKey::new(
        SubjectId::from(credential_id),
        credential_revocation_nonce(),
    )
}

/// Reject a subject the sparse-Merkle oracle would later refuse, BEFORE it
/// is staged into the cascade or recorded as a dependency edge.
///
/// The oracle's leaf insert rejects a subject id that is empty,
/// whitespace-only, or surrounded by whitespace (see
/// `RevocationOracle::insert` / its `validate_key`). Catching the same rule
/// up-front means `register_dependency` fails fast and clean on a bad
/// `parent`/`dependent` instead of recording an edge that wedges a later
/// `revoke_credential` cascade: because there is no edge-removal API, one
/// un-revocable edge would otherwise permanently block the kill switch for
/// that subtree. Mirrors the oracle rule exactly so the two never disagree.
fn validate_subject(label: &str, subject: &str) -> Result<(), CustodyError> {
    if subject.trim().is_empty() || subject.trim() != subject {
        return Err(CustodyError::Encoding(format!(
            "revocation {label} subject must be non-empty and unpadded"
        )));
    }
    Ok(())
}

impl CascadeState {
    fn empty() -> Self {
        Self {
            oracle: InMemoryRevocationOracle::new(),
            dependents: HashMap::new(),
        }
    }

    /// Compute the ordered set of not-yet-revoked subjects reachable from
    /// `root_subject` through the dependency adjacency, walking against the
    /// CURRENT (live) oracle to decide which leaves still need inserting.
    /// Cycle-safe via a visited set; the returned vector contains each
    /// subject at most once and never a subject already present in the
    /// oracle (idempotency: a retry or diamond-shaped graph does not
    /// re-stage already-revoked leaves).
    ///
    /// This is the STAGING half of the transactional cascade: it mutates
    /// nothing, so a caller can decide to commit (apply the leaves) or
    /// roll back (drop the plan) without ever leaving partial state.
    fn plan_cascade(&self, root_subject: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut to_revoke: Vec<String> = Vec::new();
        let mut stack: Vec<String> = vec![root_subject.to_string()];

        while let Some(subject) = stack.pop() {
            if !visited.insert(subject.clone()) {
                // Already processed this subject in the current cascade;
                // skip to keep cycles bounded.
                continue;
            }

            if !self.oracle.contains(&key_for(&subject)) {
                to_revoke.push(subject.clone());
            }

            if let Some(children) = self.dependents.get(&subject) {
                for child in children {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
        }

        to_revoke
    }

    /// Compute the FULL transitive closure of `root_subject` through the
    /// dependency adjacency, regardless of current revoked status. Unlike
    /// [`Self::plan_cascade`] (which skips already-revoked leaves because it
    /// drives the insert batch), this returns every reachable subject so a
    /// caller can enumerate the whole revoked closure for fan-out (e.g.
    /// in-flight settlement cancellation). Cycle-safe via a visited set; the
    /// root is always included and each subject appears at most once.
    fn closure(&self, root_subject: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut order: Vec<String> = Vec::new();
        let mut stack: Vec<String> = vec![root_subject.to_string()];

        while let Some(subject) = stack.pop() {
            if !visited.insert(subject.clone()) {
                continue;
            }
            order.push(subject.clone());
            if let Some(children) = self.dependents.get(&subject) {
                for child in children {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
        }

        order
    }

    /// Stage the transitive closure of `root_subject` against a SCRATCH
    /// clone of the oracle WITHOUT committing. Returns the fully-applied
    /// scratch oracle plus the ordered list of newly-revoked subjects, or
    /// an error if any leaf cannot be inserted (in which case the caller's
    /// live state is never touched). The caller commits by swapping the
    /// returned oracle in, or rolls back by dropping it.
    fn stage_cascade(
        &self,
        root_subject: &str,
        now_unix_ms: u64,
    ) -> Result<(InMemoryRevocationOracle, Vec<String>), CustodyError> {
        let to_revoke = self.plan_cascade(root_subject);
        let mut staged = self.oracle.clone();
        for subject in &to_revoke {
            staged
                .insert(key_for(subject), now_unix_ms)
                .map_err(|err| {
                    CustodyError::Encoding(format!(
                        "sparse-merkle revocation oracle insert failed: {err}"
                    ))
                })?;
        }
        Ok((staged, to_revoke))
    }

    /// Transactionally revoke `root_subject` and every subject reachable
    /// from it. STAGES the whole transitive closure against a scratch clone
    /// and COMMITS the batch only if every leaf inserts cleanly; on any
    /// error the scratch clone is dropped and `self.oracle` is left exactly
    /// as it was, so a partial failure can never produce a partially-applied
    /// revocation. Cycle-safe and idempotent. Returns the epoch root after
    /// the (possibly empty) committed batch.
    fn cascade_revoke(
        &mut self,
        root_subject: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError> {
        let (staged, to_revoke) = self.stage_cascade(root_subject, now_unix_ms)?;
        if !to_revoke.is_empty() {
            // Commit: every staged leaf inserted cleanly, so swap the fully
            // applied scratch oracle in for the live one in a single move.
            self.oracle = staged;
        }
        Ok(self.oracle.epoch_root())
    }
}

/// In-memory cascade backed by [`InMemoryRevocationOracle`].
///
/// Wraps the sparse-Merkle oracle (and the parent -> dependents
/// adjacency) in a `Mutex` so the credential revocation surface is
/// `Send + Sync` and consumable behind
/// `Arc<dyn CredentialRevocationOracle>`. Used in tests and
/// single-process deployments; production deployments use the durable
/// [`SqliteCredentialRevocationOracle`] (gated behind `sqlite-store`)
/// without changing call sites.
pub struct InMemoryCredentialRevocationOracle {
    inner: Mutex<CascadeState>,
}

impl Default for InMemoryCredentialRevocationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCredentialRevocationOracle {
    /// Build a fresh cascade.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CascadeState::empty()),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CascadeState>, CustodyError> {
        self.inner.lock().map_err(|err| {
            CustodyError::Encoding(format!("revocation oracle mutex poisoned: {err}"))
        })
    }
}

impl CredentialRevocationOracle for InMemoryCredentialRevocationOracle {
    fn register_dependency(&self, parent: &str, dependent: &str) -> Result<(), CustodyError> {
        // Reject subjects the oracle would later refuse BEFORE staging or
        // recording the edge: an un-revocable subject staged into an edge
        // here would wedge a future revoke_credential cascade with no way to
        // remove the edge (no edge-removal API), permanently blocking the
        // kill switch for that subtree.
        validate_subject("dependency parent", parent)?;
        validate_subject("dependency dependent", dependent)?;
        if parent == dependent {
            // A subject cannot depend on itself; reject so the adjacency
            // never contains a degenerate self-edge.
            return Err(CustodyError::Encoding(
                "revocation dependency parent and dependent must differ".into(),
            ));
        }
        let mut guard = self.lock()?;
        guard
            .dependents
            .entry(parent.to_string())
            .or_default()
            .insert(dependent.to_string());

        // If the parent is already revoked, registering a new dependent
        // must immediately cascade so a late-registered child cannot
        // outlive its already-revoked parent. The cascade is transactional:
        // if the late child cannot be staged, the edge stays recorded but
        // no partial revocation is applied (fail-closed: the caller sees the
        // error and treats registration as a revocation-state fault).
        if guard.oracle.contains(&key_for(parent)) {
            let _ = guard.cascade_revoke(dependent, 0)?;
        }
        Ok(())
    }

    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError> {
        let mut guard = self.lock()?;
        // Idempotency: if the credential is already revoked, we return
        // the current epoch root rather than failing. The custody
        // surface treats double-revocation as a no-op so an operator
        // retrying a failed control-plane call does not surface a
        // false-positive error. The cascade is still re-walked so a
        // dependent registered AFTER the parent's first revocation is
        // picked up on a subsequent revoke call; already-revoked leaves
        // are skipped inside the walk, so this stays epoch-stable when
        // nothing new needs revoking.
        guard.cascade_revoke(credential_id, now_unix_ms)
    }

    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError> {
        let guard = self.lock()?;
        Ok(guard.oracle.contains(&key_for(credential_id)))
    }

    fn revoked_closure(&self, credential_id: &str) -> Result<Vec<String>, CustodyError> {
        Ok(self.lock()?.closure(credential_id))
    }

    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError> {
        Ok(self.lock()?.oracle.epoch_root())
    }
}

#[cfg(feature = "sqlite-store")]
mod sqlite {
    //! Durable [`CredentialRevocationOracle`] over
    //! [`chio_revocation_oracle::SqliteRevocationOracle`].
    //!
    //! Revocation leaves live in the durable oracle. The dependency edges
    //! live beside them in the same database, and every cascade inserts its
    //! edge and its leaves inside one oracle transaction, so they commit
    //! together or not at all. Reads go through the oracle, which observes
    //! revocations committed by any handle on the same file.

    use std::path::Path;

    use chio_revocation_oracle::{
        RevocationTransaction, SqliteRevocationOracle, SqliteRevocationOracleError,
    };
    use rusqlite::{params, Connection};

    use super::{key_for, validate_subject, CredentialRevocationOracle, EpochRoot};
    use crate::error::CustodyError;

    const EDGES_SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS chio_custody_revocation_edges (
            parent TEXT NOT NULL CHECK (
                typeof(parent) = 'text'
                AND length(parent) BETWEEN 1 AND 4096
                AND octet_length(parent) <= 16384
                AND instr(parent, char(0)) = 0
            ),
            dependent TEXT NOT NULL CHECK (
                typeof(dependent) = 'text'
                AND length(dependent) BETWEEN 1 AND 4096
                AND octet_length(dependent) <= 16384
                AND instr(dependent, char(0)) = 0
            ),
            PRIMARY KEY (parent, dependent),
            CHECK (parent <> dependent)
        ) WITHOUT ROWID, STRICT;";

    /// Durable credential revocation cascade.
    pub struct SqliteCredentialRevocationOracle {
        oracle: SqliteRevocationOracle,
    }

    impl SqliteCredentialRevocationOracle {
        /// Opens (creating if absent) the cascade database at `path`.
        pub fn open(path: &Path) -> Result<Self, CustodyError> {
            Self::from_oracle(SqliteRevocationOracle::open(path).map_err(storage)?)
        }

        /// Opens a private in-memory cascade.
        pub fn open_in_memory() -> Result<Self, CustodyError> {
            Self::from_oracle(SqliteRevocationOracle::open_in_memory().map_err(storage)?)
        }

        fn from_oracle(oracle: SqliteRevocationOracle) -> Result<Self, CustodyError> {
            oracle
                .transact(0, |txn| Ok(txn.connection().execute_batch(EDGES_SCHEMA)?))
                .map_err(storage)?;
            Ok(Self { oracle })
        }
    }

    fn storage(error: SqliteRevocationOracleError) -> CustodyError {
        CustodyError::Encoding(format!("durable revocation oracle: {error}"))
    }

    /// Every subject reachable from `root` through the recorded edges, root
    /// first and the rest in byte order. Cycles terminate because the
    /// recursive union keeps each subject once.
    fn closure(connection: &Connection, root: &str) -> Result<Vec<String>, rusqlite::Error> {
        let mut statement = connection.prepare_cached(
            "WITH RECURSIVE reach(subject) AS (
                SELECT ?1
                UNION
                SELECT edge.dependent
                FROM chio_custody_revocation_edges AS edge
                JOIN reach ON edge.parent = reach.subject
             )
             SELECT subject FROM reach WHERE subject <> ?1 ORDER BY subject",
        )?;
        let mut subjects = vec![root.to_owned()];
        for subject in statement.query_map(params![root], |row| row.get::<_, String>(0))? {
            subjects.push(subject?);
        }
        Ok(subjects)
    }

    fn cascade(
        txn: &mut RevocationTransaction<'_>,
        root: &str,
    ) -> Result<(), SqliteRevocationOracleError> {
        for subject in closure(txn.connection(), root)? {
            txn.revoke(&key_for(&subject))?;
        }
        Ok(())
    }

    impl CredentialRevocationOracle for SqliteCredentialRevocationOracle {
        fn register_dependency(&self, parent: &str, dependent: &str) -> Result<(), CustodyError> {
            validate_subject("dependency parent", parent)?;
            validate_subject("dependency dependent", dependent)?;
            if parent == dependent {
                return Err(CustodyError::Encoding(
                    "revocation dependency parent and dependent must differ".into(),
                ));
            }
            self.oracle
                .transact(0, |txn| {
                    txn.connection().execute(
                        "INSERT OR IGNORE INTO chio_custody_revocation_edges (parent, dependent)
                         VALUES (?1, ?2)",
                        params![parent, dependent],
                    )?;
                    if txn.is_revoked(&key_for(parent)) {
                        cascade(txn, dependent)?;
                    }
                    Ok(())
                })
                .map_err(storage)?;
            Ok(())
        }

        fn revoke_credential(
            &self,
            credential_id: &str,
            now_unix_ms: u64,
        ) -> Result<EpochRoot, CustodyError> {
            let ((), root) = self
                .oracle
                .transact(now_unix_ms, |txn| cascade(txn, credential_id))
                .map_err(storage)?;
            Ok(root)
        }

        fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError> {
            self.oracle
                .is_revoked(&key_for(credential_id))
                .map_err(storage)
        }

        fn revoked_closure(&self, credential_id: &str) -> Result<Vec<String>, CustodyError> {
            self.oracle
                .read(|connection| Ok(closure(connection, credential_id)?))
                .map_err(storage)
        }

        fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError> {
            self.oracle.current_epoch_root().map_err(storage)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::SqliteCredentialRevocationOracle;
        use crate::error::CustodyError;
        use crate::revocation::CredentialRevocationOracle;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        #[test]
        fn durable_cascade_and_root_survive_a_reopen() -> TestResult {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("revocation.sqlite3");
            let root_before = {
                let oracle = SqliteCredentialRevocationOracle::open(&path)?;
                oracle.register_dependency("a", "b")?;
                oracle.register_dependency("b", "c")?;
                oracle.revoke_credential("a", 5_000)?
            };
            let reopened = SqliteCredentialRevocationOracle::open(&path)?;
            for subject in ["a", "b", "c"] {
                assert!(reopened.is_revoked(subject)?, "{subject}");
            }
            assert!(!reopened.is_revoked("unrelated")?);
            assert_eq!(reopened.current_epoch_root()?, root_before);
            assert_eq!(reopened.revoked_closure("a")?, ["a", "b", "c"]);
            Ok(())
        }

        #[test]
        fn a_second_handle_observes_a_revocation_without_reopening() -> TestResult {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("revocation.sqlite3");
            let door = SqliteCredentialRevocationOracle::open(&path)?;
            assert!(!door.is_revoked("cred")?);
            let operator = SqliteCredentialRevocationOracle::open(&path)?;
            let root = operator.revoke_credential("cred", 1_000)?;
            assert!(door.is_revoked("cred")?);
            assert_eq!(door.current_epoch_root()?, root);
            Ok(())
        }

        #[test]
        fn a_child_registered_under_a_revoked_parent_is_revoked() -> TestResult {
            let oracle = SqliteCredentialRevocationOracle::open_in_memory()?;
            oracle.revoke_credential("parent", 1_000)?;
            oracle.register_dependency("parent", "late-child")?;
            assert!(oracle.is_revoked("late-child")?);
            Ok(())
        }

        #[test]
        fn invalid_and_self_dependencies_are_refused() -> TestResult {
            let oracle = SqliteCredentialRevocationOracle::open_in_memory()?;
            oracle.register_dependency("root", "good")?;
            assert!(matches!(
                oracle.register_dependency("root", " "),
                Err(CustodyError::Encoding(_))
            ));
            assert!(matches!(
                oracle.register_dependency("root", "root"),
                Err(CustodyError::Encoding(_))
            ));
            oracle.revoke_credential("root", 1_000)?;
            assert!(oracle.is_revoked("good")?);
            Ok(())
        }

        #[test]
        fn double_revoke_is_idempotent_and_epoch_stable() -> TestResult {
            let oracle = SqliteCredentialRevocationOracle::open_in_memory()?;
            let first = oracle.revoke_credential("cred", 1_000)?;
            let second = oracle.revoke_credential("cred", 2_000)?;
            assert_eq!(first, second);
            Ok(())
        }

        #[test]
        fn an_edge_and_its_cascade_leaf_commit_together() -> TestResult {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("revocation.sqlite3");
            let oracle = SqliteCredentialRevocationOracle::open(&path)?;
            oracle.revoke_credential("parent", 1_000)?;
            let raw = rusqlite::Connection::open(&path)?;
            raw.execute_batch(
                "CREATE TRIGGER refuse_late_child BEFORE INSERT ON chio_revocation_oracle_leaves
                 WHEN NEW.subject = 'late-child'
                 BEGIN SELECT RAISE(ABORT, 'injected leaf failure'); END;",
            )?;

            assert!(matches!(
                oracle.register_dependency("parent", "late-child"),
                Err(CustodyError::Encoding(_))
            ));
            let edges: i64 = raw.query_row(
                "SELECT count(*) FROM chio_custody_revocation_edges WHERE dependent = 'late-child'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(edges, 0);
            assert!(!oracle.is_revoked("late-child")?);

            raw.execute_batch("DROP TRIGGER refuse_late_child")?;
            drop(oracle);
            let reopened = SqliteCredentialRevocationOracle::open(&path)?;
            assert!(!reopened.is_revoked("late-child")?);
            assert!(reopened.is_revoked("parent")?);
            Ok(())
        }
    }
}

#[cfg(feature = "sqlite-store")]
pub use sqlite::SqliteCredentialRevocationOracle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_then_is_revoked_round_trip() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let cred = "cred-AAAA";
        let revoked_pre = match oracle.is_revoked(cred) {
            Ok(b) => b,
            Err(e) => panic!("is_revoked pre: {e}"),
        };
        assert!(!revoked_pre);
        if let Err(e) = oracle.revoke_credential(cred, 1_000) {
            panic!("revoke must succeed: {e}");
        }
        let revoked_post = match oracle.is_revoked(cred) {
            Ok(b) => b,
            Err(e) => panic!("is_revoked post: {e}"),
        };
        assert!(revoked_post, "cascade must observe revocation");
    }

    #[test]
    fn double_revoke_is_idempotent() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let cred = "cred-double";
        let r1 = match oracle.revoke_credential(cred, 1_000) {
            Ok(r) => r,
            Err(e) => panic!("first revoke: {e}"),
        };
        let r2 = match oracle.revoke_credential(cred, 2_000) {
            Ok(r) => r,
            Err(e) => panic!("second revoke must be idempotent: {e}"),
        };
        // Epoch advances exactly once; the second call returns the
        // existing root so the custody surface is operationally tolerant
        // to retries on the control-plane revocation endpoint.
        assert_eq!(r1, r2);
    }

    #[test]
    fn distinct_credentials_revoke_independently() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.revoke_credential("cred-A", 1_000) {
            panic!("revoke A: {e}");
        }
        let a = match oracle.is_revoked("cred-A") {
            Ok(b) => b,
            Err(e) => panic!("is_revoked A: {e}"),
        };
        let b = match oracle.is_revoked("cred-B") {
            Ok(v) => v,
            Err(e) => panic!("is_revoked B: {e}"),
        };
        assert!(a);
        assert!(!b, "revoking cred-A must NOT cascade to cred-B");
    }

    #[test]
    fn revoking_parent_cascades_to_registered_child() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("parent", "child") {
            panic!("register: {e}");
        }
        // Child is not revoked until the parent is.
        match oracle.is_revoked("child") {
            Ok(b) => assert!(!b, "child must not be revoked before the parent"),
            Err(e) => panic!("is_revoked child pre: {e}"),
        }
        if let Err(e) = oracle.revoke_credential("parent", 1_000) {
            panic!("revoke parent: {e}");
        }
        match oracle.is_revoked("parent") {
            Ok(b) => assert!(b, "parent must be revoked"),
            Err(e) => panic!("is_revoked parent: {e}"),
        }
        match oracle.is_revoked("child") {
            Ok(b) => assert!(b, "revoking the parent MUST cascade to the child"),
            Err(e) => panic!("is_revoked child post: {e}"),
        }
    }

    #[test]
    fn cascade_is_transitive_across_a_chain() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("a", "b") {
            panic!("register a->b: {e}");
        }
        if let Err(e) = oracle.register_dependency("b", "c") {
            panic!("register b->c: {e}");
        }
        if let Err(e) = oracle.revoke_credential("a", 1_000) {
            panic!("revoke a: {e}");
        }
        for subject in ["a", "b", "c"] {
            match oracle.is_revoked(subject) {
                Ok(b) => assert!(b, "transitive cascade must revoke {subject}"),
                Err(e) => panic!("is_revoked {subject}: {e}"),
            }
        }
    }

    #[test]
    fn cascade_terminates_on_cycle() {
        // A <-> B mutual dependency must not wedge the cascade.
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("a", "b") {
            panic!("register a->b: {e}");
        }
        if let Err(e) = oracle.register_dependency("b", "a") {
            panic!("register b->a: {e}");
        }
        if let Err(e) = oracle.revoke_credential("a", 1_000) {
            panic!("revoke a (cycle) must terminate: {e}");
        }
        for subject in ["a", "b"] {
            match oracle.is_revoked(subject) {
                Ok(b) => assert!(b, "cyclic cascade must still revoke {subject}"),
                Err(e) => panic!("is_revoked {subject}: {e}"),
            }
        }
    }

    #[test]
    fn registering_child_after_parent_revoked_cascades_immediately() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.revoke_credential("parent", 1_000) {
            panic!("revoke parent: {e}");
        }
        if let Err(e) = oracle.register_dependency("parent", "late-child") {
            panic!("register late child: {e}");
        }
        match oracle.is_revoked("late-child") {
            Ok(b) => assert!(
                b,
                "a child registered after the parent was revoked must be revoked immediately"
            ),
            Err(e) => panic!("is_revoked late-child: {e}"),
        }
    }

    #[test]
    fn self_dependency_is_rejected_fail_closed() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let res = oracle.register_dependency("self", "self");
        assert!(
            matches!(res, Err(CustodyError::Encoding(_))),
            "a self-referential dependency must be rejected"
        );
    }

    #[test]
    fn invalid_dependent_is_rejected_so_the_root_cascade_stays_clean() {
        // A dependent with an un-insertable subject id (the sparse-Merkle
        // oracle rejects whitespace-only subjects) is rejected at
        // registration BEFORE it is staged, so it can never poison a later
        // cascade. The good sibling and the root must still revoke cleanly.
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("root", "good-child") {
            panic!("register good child: {e}");
        }
        // " " is a structurally-invalid subject for the sparse-Merkle
        // oracle, so the edge is rejected up-front and never recorded.
        let bad = oracle.register_dependency("root", " ");
        assert!(
            matches!(bad, Err(CustodyError::Encoding(_))),
            "a leaf that the oracle would reject must be refused before staging"
        );

        let root_before = match oracle.current_epoch_root() {
            Ok(r) => r,
            Err(e) => panic!("epoch root before: {e}"),
        };

        // The bad edge was never recorded, so the cascade commits cleanly.
        if let Err(e) = oracle.revoke_credential("root", 1_000) {
            panic!("revoke root after rejected edge must succeed: {e}");
        }

        match oracle.is_revoked("root") {
            Ok(b) => assert!(b, "root must be revoked after a clean cascade"),
            Err(e) => panic!("is_revoked root: {e}"),
        }
        match oracle.is_revoked("good-child") {
            Ok(b) => assert!(
                b,
                "the good sibling must cascade once the bad edge is rejected"
            ),
            Err(e) => panic!("is_revoked good-child: {e}"),
        }
        let root_after = match oracle.current_epoch_root() {
            Ok(r) => r,
            Err(e) => panic!("epoch root after: {e}"),
        };
        assert_ne!(
            root_before, root_after,
            "a clean cascade must advance the epoch root"
        );
    }

    #[test]
    fn cascade_rolls_back_when_a_subject_becomes_unstageable() {
        // Defense in depth: even though register_dependency validates
        // subjects up-front, the staging path itself must still be
        // all-or-nothing. A subject that the oracle rejects at insert time
        // aborts the WHOLE staged batch, leaving neither the root nor any
        // good sibling revoked and the epoch root unchanged.
        let mut state = CascadeState::empty();
        // Inject a degenerate edge directly so the registration guard does
        // not intercept it; this exercises the stage_cascade rollback in
        // isolation.
        state
            .dependents
            .entry("root".to_string())
            .or_default()
            .insert("good-child".to_string());
        state
            .dependents
            .entry("root".to_string())
            .or_default()
            .insert(" ".to_string());

        let root_before = state.oracle.epoch_root();
        let res = state.cascade_revoke("root", 1_000);
        assert!(
            matches!(res, Err(CustodyError::Encoding(_))),
            "an un-stageable leaf must fail the whole staged cascade"
        );

        assert!(
            !state.oracle.contains(&key_for("root")),
            "root must not be revoked after a rolled-back cascade"
        );
        assert!(
            !state.oracle.contains(&key_for("good-child")),
            "the good sibling must not be revoked after a rolled-back cascade"
        );
        assert_eq!(
            root_before,
            state.oracle.epoch_root(),
            "a rolled-back cascade must leave the epoch root unchanged"
        );
    }

    #[test]
    fn clean_revoke_succeeds_after_an_unstageable_cascade_rolls_back() {
        // After a staged cascade rolls back, an unrelated clean revocation
        // must still commit: the rollback left no latent corruption.
        let mut state = CascadeState::empty();
        state
            .dependents
            .entry("bad-root".to_string())
            .or_default()
            .insert(" ".to_string());

        let res = state.cascade_revoke("bad-root", 1_000);
        assert!(matches!(res, Err(CustodyError::Encoding(_))));

        // A clean revocation on an unrelated subject still commits.
        if let Err(e) = state.cascade_revoke("clean", 2_000) {
            panic!("clean revoke after rollback must succeed: {e}");
        }
        assert!(
            state.oracle.contains(&key_for("clean")),
            "clean revoke must commit after a prior rollback"
        );
        assert!(
            !state.oracle.contains(&key_for("bad-root")),
            "bad-root must remain un-revoked"
        );
    }

    #[test]
    fn revoked_closure_enumerates_the_transitive_subtree() {
        // The settlement-cancellation seam needs the FULL closure (root plus
        // every transitive dependent), independent of revoked status, so a
        // cancellation can fan out across the whole subtree.
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("a", "b") {
            panic!("register a->b: {e}");
        }
        if let Err(e) = oracle.register_dependency("b", "c") {
            panic!("register b->c: {e}");
        }
        let mut closure = match oracle.revoked_closure("a") {
            Ok(c) => c,
            Err(e) => panic!("revoked_closure: {e}"),
        };
        closure.sort();
        assert_eq!(
            closure,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "the closure must contain the root and every transitive dependent"
        );

        // Queryable before any revocation, and the root is always included
        // even with no dependents.
        match oracle.revoked_closure("standalone") {
            Ok(c) => assert_eq!(c, vec!["standalone".to_string()]),
            Err(e) => panic!("revoked_closure standalone: {e}"),
        }
    }

    #[test]
    fn register_dependency_rejects_invalid_subjects_before_staging() {
        // An un-revocable subject (whitespace-only / padded) must be rejected
        // up-front so it never wedges a later revoke_credential cascade: there
        // is no edge-removal API, so a bad edge would permanently block the
        // kill switch for that subtree.
        let oracle = InMemoryCredentialRevocationOracle::new();

        let bad_dependent = oracle.register_dependency("root", " ");
        assert!(
            matches!(bad_dependent, Err(CustodyError::Encoding(_))),
            "a whitespace-only dependent must be rejected before staging"
        );
        let bad_parent = oracle.register_dependency(" ", "child");
        assert!(
            matches!(bad_parent, Err(CustodyError::Encoding(_))),
            "a whitespace-only parent must be rejected before staging"
        );
        let padded = oracle.register_dependency("root", "padded ");
        assert!(
            matches!(padded, Err(CustodyError::Encoding(_))),
            "a padded dependent must be rejected before staging"
        );

        // The bad edges were never recorded, so revoking the root still
        // succeeds and is observable (the kill switch is not wedged).
        if let Err(e) = oracle.revoke_credential("root", 1_000) {
            panic!("revoke root after rejected edges must succeed: {e}");
        }
        match oracle.is_revoked("root") {
            Ok(b) => assert!(b, "root must be revocable after bad edges were rejected"),
            Err(e) => panic!("is_revoked root: {e}"),
        }
    }

    #[test]
    fn sibling_dependents_do_not_cross_cascade() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("parent-1", "child-1") {
            panic!("register p1: {e}");
        }
        if let Err(e) = oracle.register_dependency("parent-2", "child-2") {
            panic!("register p2: {e}");
        }
        if let Err(e) = oracle.revoke_credential("parent-1", 1_000) {
            panic!("revoke p1: {e}");
        }
        match oracle.is_revoked("child-1") {
            Ok(b) => assert!(b, "child-1 must be revoked"),
            Err(e) => panic!("is_revoked child-1: {e}"),
        }
        match oracle.is_revoked("child-2") {
            Ok(b) => assert!(!b, "child-2 under a different parent must NOT be revoked"),
            Err(e) => panic!("is_revoked child-2: {e}"),
        }
    }
}
