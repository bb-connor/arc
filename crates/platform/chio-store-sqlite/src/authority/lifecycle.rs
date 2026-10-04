//! Current issuer projections and transactional lifecycle mutations.
use super::*;
use chio_kernel::authority::lifecycle::{
    apply_lifecycle_change, issuer_is_live, AuthorityLifecycleChange,
    DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS,
};
use chio_security_types::clock::{ClockError, UnixMillis};

pub(super) fn observe_time(
    connection: &Connection,
    now: UnixMillis,
) -> Result<(), AuthorityStoreError> {
    let (observed, changed): (i64, i64) = connection.query_row(
        "SELECT observed_ms, rotated_at FROM authority_state WHERE singleton_id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if now.get() < authority_unsigned(observed, "authority clock floor")?
        || now.as_secs() < authority_unsigned(changed, "authority transition time")?
    {
        return Err(ClockError::WallClockRegression.into());
    }
    connection.execute(
        "UPDATE authority_state SET observed_ms = ?1 WHERE singleton_id = 1",
        [authority_sqlite_integer(
            now.get(),
            "authority clock floor",
        )?],
    )?;
    Ok(())
}

pub(super) fn live_public_keys(
    snapshot: &AuthoritySnapshot,
    now: u64,
) -> Result<Vec<PublicKey>, AuthorityStoreError> {
    chio_kernel::authority::replication::validate_state(snapshot)?;
    let mut keys = Vec::new();
    for (index, key) in snapshot.trusted_keys.iter().enumerate() {
        if issuer_is_live(snapshot, index, None, now)? {
            keys.push(PublicKey::from_hex(&key.public_key_hex)?);
        }
    }
    Ok(keys)
}

impl SqliteCapabilityAuthority {
    pub fn rotate_with_verification_deadline(
        &self,
        verify_until: u64,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.mutate_lifecycle(
            Some(AuthorityLifecycleChange::Rotate { verify_until }),
            None,
        )
    }

    /// Sign an irreversible retirement of a historical issuer in a pinned stream.
    pub fn retire_issuer(
        &self,
        issuer: &PublicKey,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.mutate_lifecycle(
            Some(AuthorityLifecycleChange::Retire {
                public_key_hex: issuer.to_hex(),
            }),
            None,
        )
    }

    /// Sign an irreversible compromise decision, retaining public audit history.
    pub fn revoke_issuer(
        &self,
        issuer: &PublicKey,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.mutate_lifecycle(
            Some(AuthorityLifecycleChange::Revoke {
                public_key_hex: issuer.to_hex(),
            }),
            None,
        )
    }

    /// Recovery requires the independent root already pinned in this stream.
    /// The fresh private successor remains in this store; old keys all lose authority.
    pub fn recover_authority(
        &self,
        recovery: &Keypair,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        self.mutate_lifecycle(Some(AuthorityLifecycleChange::Recover), Some(recovery))
    }

    pub(super) fn mutate_lifecycle(
        &self,
        requested: Option<AuthorityLifecycleChange>,
        recovery: Option<&Keypair>,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.custody)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.custody.validate(&transaction)?;
        let now = self.clock.unix_millis()?;
        observe_time(&transaction, now)?;
        let current = replication::read_snapshot(&transaction)?;
        let change = match requested {
            Some(change) => change,
            None => AuthorityLifecycleChange::Rotate {
                verify_until: now
                    .as_secs()
                    .checked_add(DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS)
                    .ok_or_else(|| AuthorityStoreError::Fence("issuer deadline overflow".into()))?,
            },
        };
        let local = Self::read_keypair_from_connection(&transaction)?;
        let signer = match (&change, recovery) {
            (AuthorityLifecycleChange::Recover, Some(signer)) => signer,
            (AuthorityLifecycleChange::Recover, None) => {
                return Err(AuthorityStoreError::Fence(
                    "recovery signer is required".into(),
                ))
            }
            _ if local.public_key().to_hex() == current.public_key_hex => &local,
            _ => {
                return Err(AuthorityStoreError::Fence(
                    "rotation requires custody of the current head".into(),
                ))
            }
        };
        let next_private = matches!(
            change,
            AuthorityLifecycleChange::Rotate { .. } | AuthorityLifecycleChange::Recover
        )
        .then(Keypair::generate);
        let next_public = match &next_private {
            Some(key) => key.public_key(),
            None => PublicKey::from_hex(&current.public_key_hex)?,
        };
        let next = apply_lifecycle_change(&current, &change, &next_public.to_hex(), now.as_secs())?;
        replication::record_lifecycle_change(&transaction, signer, &next_public, change, now)?;
        replication::persist_snapshot(&transaction, &next)?;
        if let Some(key) = next_private {
            self.custody.validate(&transaction)?;
            transaction.execute(
                "UPDATE authority_state SET seed_hex = ?1 WHERE singleton_id = 1",
                [key.seed_hex()],
            )?;
        }
        let mut status = Self::read_status_from_connection(&transaction)?;
        status.trusted_public_keys = live_public_keys(&next, now.as_secs())?;
        transaction.commit()?;
        self.update_cached_public_key(status.public_key.clone());
        Ok(status)
    }

    pub(super) fn check_managed_issuer(
        &self,
        issuer: &PublicKey,
        issued_at: u64,
        now: u64,
    ) -> Result<(), KernelError> {
        let check = || -> Result<bool, AuthorityStoreError> {
            let mut connection = Self::open_connection(&self.custody)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let observed = self.clock.unix_millis()?;
            observe_time(&transaction, observed)?;
            let snapshot = replication::read_snapshot(&transaction)?;
            chio_kernel::authority::replication::validate_state(&snapshot)?;
            let permitted = match snapshot
                .trusted_keys
                .iter()
                .position(|key| key.public_key_hex == issuer.to_hex())
            {
                Some(index) => issuer_is_live(
                    &snapshot,
                    index,
                    Some(issued_at),
                    now.max(observed.as_secs()),
                )?,
                None => true, // Membership remains the kernel's independent required check.
            };
            transaction.commit()?;
            Ok(permitted)
        };
        if check().map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))? {
            Ok(())
        } else {
            Err(KernelError::UntrustedIssuer)
        }
    }
}
