//! Local provisioning and atomic authenticated authority imports.
use super::*;
use chio_kernel::authority::replication::{
    verify_authority_chain, AuthorityReplicationAnchor, SignedAuthoritySnapshot,
    SignedAuthorityTransition, MAX_AUTHORITY_WIRE_BYTES,
};
use chio_security_types::clock::{ClockError, UnixMillis};

mod persistence;
pub(super) use persistence::ensure_schema;
use persistence::*;
#[cfg(test)]
mod tests;

impl SqliteCapabilityAuthority {
    /// Explicit local migration checkpoint. Distribute the returned public anchor
    /// and its digest through an authenticated operator channel, never peer HTTP.
    pub fn initialize_replication(
        &self,
        stream_id: &str,
    ) -> Result<AuthorityReplicationAnchor, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_replication(&transaction)? {
            if existing.anchor.stream_id != stream_id {
                return Err(refused(
                    "authority replication is already pinned to another stream",
                ));
            }
            transaction.commit()?;
            return Ok(existing.anchor);
        }
        let state = read_snapshot(&transaction)?;
        if Self::read_keypair_from_connection(&transaction)?
            .public_key()
            .to_hex()
            != state.public_key_hex
        {
            return Err(refused(
                "only the current signing custodian can initialize a stream",
            ));
        }
        let anchor = AuthorityReplicationAnchor::new(stream_id.into(), state)?;
        let now = self.clock.unix_millis()?;
        if now.as_secs() < anchor.snapshot.rotated_at {
            return Err(ClockError::WallClockRegression.into());
        }
        insert_anchor(&transaction, &anchor, now)?;
        transaction.commit()?;
        Ok(anchor)
    }

    /// Out-of-band local provisioning only. This replaces public verification
    /// state, never private signing material, and cannot repin an existing stream.
    pub fn pin_replication_anchor(
        &self,
        anchor: &AuthorityReplicationAnchor,
    ) -> Result<bool, AuthorityStoreError> {
        anchor.validate()?;
        let mut connection = Self::open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_replication(&transaction)? {
            if existing.anchor != *anchor {
                return Err(refused("authority replication anchor is immutable"));
            }
            transaction.commit()?;
            return Ok(false);
        }
        let now = self.clock.unix_millis()?;
        if now.as_secs() < anchor.snapshot.rotated_at {
            return Err(refused("authority anchor is from the future"));
        }
        persist_snapshot(&transaction, &anchor.snapshot)?;
        insert_anchor(&transaction, anchor, now)?;
        let status = Self::read_status_from_connection(&transaction)?;
        transaction.commit()?;
        self.update_cached_public_key(status.public_key);
        self.update_cached_trusted_public_keys(status.trusted_public_keys);
        Ok(true)
    }

    pub fn replication_anchor(&self) -> Result<AuthorityReplicationAnchor, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        Ok(require_replication(&connection)?.anchor)
    }

    /// Export a fresh head-signed envelope, or relay the exact still-fresh envelope
    /// accepted from the signing custodian. A follower never invents a signature.
    pub fn signed_snapshot(&self) -> Result<SignedAuthoritySnapshot, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut replication = require_replication(&transaction)?;
        let current = read_snapshot(&transaction)?;
        let now = self.clock.unix_millis()?;
        check_clock(&replication, now)?;
        let signer = Self::read_keypair_from_connection(&transaction)?;
        let snapshot = if signer.public_key().to_hex() == current.public_key_hex {
            SignedAuthoritySnapshot::sign(
                &replication.anchor,
                replication.chain.clone(),
                now.as_secs(),
                &signer,
            )?
        } else {
            replication
                .latest
                .clone()
                .ok_or_else(|| refused("follower has no authenticated live envelope to relay"))?
        };
        snapshot.verify(
            &replication.anchor,
            &current,
            &replication.commitment,
            now.as_secs(),
        )?;
        replication.latest = Some(snapshot.clone());
        replication.observed_ms = now.get();
        write_replication(&transaction, &replication)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub fn apply_signed_snapshot(
        &self,
        snapshot: &SignedAuthoritySnapshot,
    ) -> Result<bool, AuthorityStoreError> {
        let mut connection = Self::open_connection(&self.path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut replication = require_replication(&transaction)?;
        let current = read_snapshot(&transaction)?;
        let now = self.clock.unix_millis()?;
        check_clock(&replication, now)?;
        let proof = snapshot.verify(
            &replication.anchor,
            &current,
            &replication.commitment,
            now.as_secs(),
        )?;
        if replication
            .latest
            .as_ref()
            .and_then(|s| s.proof.as_ref())
            .is_some_and(|old| proof.issued_at < old.issued_at)
        {
            return Err(refused("authority envelope replay regresses issuance time"));
        }
        let changed = current != snapshot.snapshot;
        if changed {
            persist_snapshot(&transaction, &snapshot.snapshot)?;
        }
        replication.commitment = proof.chain_commitment.clone();
        replication.chain.clone_from(&proof.transitions);
        replication.latest = Some(snapshot.clone());
        replication.observed_ms = now.get();
        write_replication(&transaction, &replication)?;
        let status = Self::read_status_from_connection(&transaction)?;
        transaction.commit()?;
        self.update_cached_public_key(status.public_key);
        self.update_cached_trusted_public_keys(status.trusted_public_keys);
        Ok(changed)
    }
}

pub(super) fn record_rotation(
    connection: &Connection,
    signer: &Keypair,
    next_key: &PublicKey,
    now: UnixMillis,
) -> Result<(), AuthorityStoreError> {
    let Some(mut replication) = read_replication(connection)? else {
        return Ok(());
    };
    check_clock(&replication, now)?;
    let current = read_snapshot(connection)?;
    let (derived, commitment) = verify_authority_chain(&replication.anchor, &replication.chain)?;
    if derived != current || commitment != replication.commitment {
        return Err(refused(
            "local authority differs from authenticated history",
        ));
    }
    let transition = SignedAuthorityTransition::sign(
        &replication.anchor,
        &current,
        &commitment,
        next_key,
        now.as_secs(),
        signer,
    )?;
    replication.commitment = transition.commitment()?;
    replication.chain.push(transition);
    verify_authority_chain(&replication.anchor, &replication.chain)?;
    // The old envelope cannot assert liveness for the new head.
    replication.latest = None;
    replication.observed_ms = now.get();
    write_replication(connection, &replication)
}

fn check_clock(replication: &ReplicationState, now: UnixMillis) -> Result<(), AuthorityStoreError> {
    if now.get() < replication.observed_ms {
        return Err(ClockError::WallClockRegression.into());
    }
    Ok(())
}
fn refused(message: &str) -> AuthorityStoreError {
    AuthorityStoreError::Fence(message.into())
}
