//! Operator-installed governed approval authority. An install is one fenced,
//! immutable row bound to this destination store and its global commit chain.
//! It confers no participant ownership or dispatch authority by itself.

use chio_kernel::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalAuthorityInstallV1,
    MAX_GOVERNED_APPROVAL_AUTHORITY_CAPACITY,
};

use crate::serving_owner::SqliteServingOwnerError;

use super::*;

const TABLE: &str = "governed_approval_replay_authorities";
const PROJECTION_KIND: &str = "governed_approval_authority";
const INSTALL_MUTATION: &str = "install_governed_approval_authority";
const INSTALL_DOMAIN: &[u8] = b"chio.governed-approval-authority-install.v1\0";
const MAX_AUTHORITIES: i64 = 128;

type IntegrityResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StoredAuthority {
    install: GovernedApprovalAuthorityInstallV1,
    install_digest: String,
    fence: StoreMutationFence,
}

impl SqliteAdmissionOperationStore {
    /// Install one approval authority generation for claims on this store.
    /// This is operator provisioning, never derived from request metadata.
    /// An exact retry returns the existing install; any other install for the
    /// same authority or generation is refused before mutation.
    pub fn install_governed_approval_authority(
        &self,
        binding: &GovernedApprovalAuthorityBindingV1,
        capacity: u64,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedApprovalAuthorityInstallV1, AdmissionOperationStoreError> {
        if capacity == 0 || capacity > MAX_GOVERNED_APPROVAL_AUTHORITY_CAPACITY {
            return Err(invariant("governed approval authority capacity is invalid"));
        }
        {
            let mut connection = self.connection()?;
            let tx = self.begin_write(&mut connection, Some(fence))?;
            let observed = authority_time(&tx, trusted_now_unix_ms, &self.serving_owner)?;
            verify_all_records(&tx).map_err(integrity_error)?;
            if let Some(existing) = load_record(&tx, binding.approval_authority_id().as_str())
                .map_err(integrity_error)?
            {
                require_exact(&existing.install, binding, capacity, fence)?;
                return Ok(existing.install);
            }
            let generation_taken: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_authorities WHERE expectation_id = ?1)",
                    [binding.expectation_id().as_str()],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if generation_taken {
                return Err(invariant(
                    "governed approval authority generation is already installed",
                ));
            }
            let install = GovernedApprovalAuthorityInstallV1::new(
                binding.clone(),
                fence.store_uuid.clone(),
                capacity,
                observed,
            )?;
            let install_digest = install_digest(&install, fence).map_err(integrity_error)?;
            tx.execute(
                "INSERT INTO governed_approval_replay_authorities
                 (approval_authority_id, expectation_id, destination_store_uuid, capacity,
                  installed_at_unix_ms, install_digest, store_uuid, store_lease_id, store_owner_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    binding.approval_authority_id().as_str(),
                    binding.expectation_id().as_str(),
                    fence.store_uuid,
                    sqlite_i64(capacity, "approval_capacity")?,
                    sqlite_i64(observed, "approval_installed_at")?,
                    install_digest,
                    fence.store_uuid,
                    fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "approval_owner_epoch")?,
                ],
            )
            .map_err(sqlite_error)?;
            verify_all_records(&tx).map_err(integrity_error)?;
            self.serving_owner
                .append_global_commit(
                    &tx,
                    INSTALL_MUTATION,
                    PROJECTION_KIND,
                    binding.approval_authority_id().as_str(),
                    1,
                )
                .map_err(map_owner_error)?;
            self.commit_write(tx)?;
            self.sync_after_write(&connection)?;
        }
        let persisted =
            self.load_governed_approval_authority(binding, fence, trusted_now_unix_ms)?;
        require_exact(&persisted, binding, capacity, fence)?;
        Ok(persisted)
    }

    /// Fenced readback of the exact installed authority. A missing install,
    /// a different generation or another destination store refuses.
    pub fn load_governed_approval_authority(
        &self,
        binding: &GovernedApprovalAuthorityBindingV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedApprovalAuthorityInstallV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        verify_governed_approval_authority_projection_coverage(&tx).map_err(map_owner_error)?;
        let install = require_installed_authority(
            &tx,
            binding.approval_authority_id(),
            binding.expectation_id(),
        )?;
        if install.destination_store_uuid() != self.serving_owner.fence.store_uuid {
            return Err(invariant(
                "governed approval authority belongs to another destination store",
            ));
        }
        approval_clock_tx(&tx, &install, trusted_now_unix_ms, &self.serving_owner)?;
        Ok(install)
    }
}

pub(in crate::admission_operation_store) fn require_installed_authority(
    connection: &Connection,
    authority: &AdmissionIdentifier,
    expectation: &AdmissionIdentifier,
) -> Result<GovernedApprovalAuthorityInstallV1, AdmissionOperationStoreError> {
    let record = load_record(connection, authority.as_str())
        .map_err(integrity_error)?
        .ok_or_else(|| invariant("approval authority is not installed"))?;
    if record.install.binding().expectation_id() != expectation {
        return Err(invariant(
            "approval authority is not the exact installed generation",
        ));
    }
    Ok(record.install)
}

/// Require the authority's own observation, and the effective decision time,
/// to have reached the install time of this authority.
pub(in crate::admission_operation_store) fn approval_clock_tx(
    tx: &Transaction<'_>,
    install: &GovernedApprovalAuthorityInstallV1,
    decision_time: u64,
    owner: &SqliteServingOwner,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = schema::observe_authority_time(tx, owner)?;
    verify_install_clock_floor(install, observed)?;
    let effective = authority_time(tx, decision_time, owner)?;
    verify_install_clock_floor(install, effective)?;
    Ok(effective)
}

pub(in crate::admission_operation_store) fn verify_install_clock_floor(
    install: &GovernedApprovalAuthorityInstallV1,
    observed_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if observed_unix_ms < install.installed_at_unix_ms() {
        return Err(invariant(
            "approval authority clock precedes the authority install",
        ));
    }
    Ok(())
}

fn authority_time(
    tx: &Transaction<'_>,
    trusted_now_unix_ms: u64,
    owner: &SqliteServingOwner,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = schema::authority_validation_time(tx, trusted_now_unix_ms, owner)?;
    if !table_exists(tx, TABLE)? {
        return Ok(observed);
    }
    let high_water: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(installed_at_unix_ms), 0) FROM governed_approval_replay_authorities",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let high_water = u64::try_from(high_water)
        .map_err(|_| integrity_error("approval authority install clock is negative"))?;
    if observed < high_water {
        return Err(invariant(
            "governed approval authority time regressed below an install",
        ));
    }
    Ok(observed)
}

fn require_exact(
    install: &GovernedApprovalAuthorityInstallV1,
    binding: &GovernedApprovalAuthorityBindingV1,
    capacity: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if install.binding() != binding
        || install.capacity() != capacity
        || install.destination_store_uuid() != fence.store_uuid
    {
        return Err(invariant(
            "governed approval authority install conflicts with an existing install",
        ));
    }
    Ok(())
}

fn install_digest(
    install: &GovernedApprovalAuthorityInstallV1,
    fence: &StoreMutationFence,
) -> IntegrityResult<String> {
    let encoded = canonical_json_bytes(&(
        install.binding().approval_authority_id().as_str(),
        install.binding().expectation_id().as_str(),
        install.destination_store_uuid(),
        install.capacity(),
        install.installed_at_unix_ms(),
        fence,
    ))
    .map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(INSTALL_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(INSTALL_DOMAIN);
    bytes.extend_from_slice(&encoded);
    Ok(sha256_hex(&bytes))
}

fn table_exists(
    connection: &Connection,
    table: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn validate_storage_bounds(connection: &Connection) -> IntegrityResult<bool> {
    if !table_exists(connection, TABLE).map_err(|error| error.to_string())? {
        return Ok(false);
    }
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM governed_approval_replay_authorities",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !(0..=MAX_AUTHORITIES).contains(&rows) {
        return Err("approval authority row limit exceeded".into());
    }
    let invalid: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_authorities WHERE
                typeof(approval_authority_id) <> 'text' OR length(CAST(approval_authority_id AS BLOB)) NOT BETWEEN 1 AND 2048
                OR typeof(expectation_id) <> 'text' OR length(CAST(expectation_id AS BLOB)) NOT BETWEEN 1 AND 2048
                OR typeof(destination_store_uuid) <> 'text' OR length(CAST(destination_store_uuid AS BLOB)) NOT BETWEEN 1 AND 512
                OR typeof(install_digest) <> 'text' OR length(CAST(install_digest AS BLOB)) <> 64
                OR typeof(store_uuid) <> 'text' OR length(CAST(store_uuid AS BLOB)) NOT BETWEEN 1 AND 512
                OR typeof(store_lease_id) <> 'text' OR length(CAST(store_lease_id AS BLOB)) NOT BETWEEN 1 AND 512
                OR typeof(capacity) <> 'integer' OR capacity NOT BETWEEN 1 AND 65536
                OR typeof(installed_at_unix_ms) <> 'integer' OR installed_at_unix_ms NOT BETWEEN 0 AND 9007199254740991
                OR typeof(store_owner_epoch) <> 'integer' OR store_owner_epoch < 1)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if invalid {
        return Err("approval authority has invalid storage types or sizes".into());
    }
    Ok(true)
}

pub(in crate::admission_operation_store) fn verify_all_records(
    connection: &Connection,
) -> IntegrityResult<Vec<StoredAuthority>> {
    if !validate_storage_bounds(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT approval_authority_id FROM governed_approval_replay_authorities ORDER BY approval_authority_id",
        )
        .map_err(|error| error.to_string())?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    keys.into_iter()
        .map(|key| {
            load_bounded_record(connection, &key)?
                .ok_or_else(|| "approval authority disappeared within its snapshot".into())
        })
        .collect()
}

fn load_record(
    connection: &Connection,
    approval_authority_id: &str,
) -> IntegrityResult<Option<StoredAuthority>> {
    if !validate_storage_bounds(connection)? {
        return Ok(None);
    }
    load_bounded_record(connection, approval_authority_id)
}

fn load_bounded_record(
    connection: &Connection,
    approval_authority_id: &str,
) -> IntegrityResult<Option<StoredAuthority>> {
    type Stored = (String, String, i64, i64, String, String, String, i64);
    let stored: Option<Stored> = connection
        .query_row(
            "SELECT expectation_id, destination_store_uuid, capacity, installed_at_unix_ms,
             install_digest, store_uuid, store_lease_id, store_owner_epoch
             FROM governed_approval_replay_authorities WHERE approval_authority_id = ?1",
            [approval_authority_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((
        expectation_id,
        destination,
        capacity,
        installed_at,
        stored_digest,
        store_uuid,
        lease_id,
        owner_epoch,
    )) = stored
    else {
        return Ok(None);
    };
    let binding = GovernedApprovalAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("approval_authority_id", approval_authority_id)
            .map_err(|error| error.to_string())?,
        AdmissionIdentifier::try_new("expectation_id", expectation_id)
            .map_err(|error| error.to_string())?,
    );
    let install = GovernedApprovalAuthorityInstallV1::new(
        binding,
        destination,
        u64::try_from(capacity).map_err(|error| error.to_string())?,
        u64::try_from(installed_at).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let fence = StoreMutationFence {
        store_uuid,
        lease_id,
        owner_epoch: u64::try_from(owner_epoch).map_err(|error| error.to_string())?,
    };
    if fence.store_uuid != install.destination_store_uuid()
        || install_digest(&install, &fence)? != stored_digest
    {
        return Err("approval authority install binding or digest mismatch".into());
    }
    let lease_matches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_serving_leases
             WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3)",
            params![fence.store_uuid, owner_epoch, fence.lease_id],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if !lease_matches {
        return Err("approval authority install historical owner lease mismatch".into());
    }
    Ok(Some(StoredAuthority {
        install,
        install_digest: stored_digest,
        fence,
    }))
}

fn integrity_error(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("governed approval authority integrity: {detail}"))
}

fn owner_invalid(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("governed approval authority integrity: {detail}"))
}

/// Resolve the single install row for a global commit without recursing
/// through the global coverage verifier that calls it.
pub(crate) fn governed_approval_authority_projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    if sequence != 1 {
        return Err(owner_invalid("global projection names an absent install"));
    }
    load_record(connection, key)
        .map_err(owner_invalid)?
        .map(|record| record.install_digest)
        .ok_or_else(|| owner_invalid("global projection names an absent install"))
}

/// Require a bijection between installs and their global commits, including
/// the exact mutation, digest and historical fence.
pub(crate) fn verify_governed_approval_authority_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let records = verify_all_records(connection).map_err(owner_invalid)?;
    if global_install_count(connection)? != i64::try_from(records.len()).map_err(owner_invalid)? {
        return Err(owner_invalid(
            "approval authority installs and global references have different counts",
        ));
    }
    if records.is_empty() {
        return Ok(());
    }
    let mut statement = connection
        .prepare(
            "SELECT COUNT(*) FROM authority_global_commits
             WHERE projection_kind = ?1 AND projection_key = ?2
               AND projection_sequence = 1 AND mutation_kind = ?3
               AND projection_reference_digest = ?4 AND store_uuid = ?5
               AND store_lease_id = ?6 AND store_owner_epoch = ?7",
        )
        .map_err(owner_invalid)?;
    for record in &records {
        let matching: i64 = statement
            .query_row(
                params![
                    PROJECTION_KIND,
                    record.install.binding().approval_authority_id().as_str(),
                    INSTALL_MUTATION,
                    &record.install_digest,
                    &record.fence.store_uuid,
                    &record.fence.lease_id,
                    i64::try_from(record.fence.owner_epoch).map_err(owner_invalid)?,
                ],
                |row| row.get(0),
            )
            .map_err(owner_invalid)?;
        if matching != 1 {
            return Err(owner_invalid(
                "approval authority install lacks exactly one matching global commit",
            ));
        }
    }
    Ok(())
}

/// Provisioning may encounter no global schema yet, but only an empty install
/// table with no retained global references can qualify as pristine.
pub(crate) fn verify_governed_approval_authority_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if !verify_all_records(connection)
        .map_err(owner_invalid)?
        .is_empty()
    {
        return Err(owner_invalid(
            "governed approval authority state is not pristine",
        ));
    }
    let global_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND lower(name) = 'authority_global_commits')",
            [],
            |row| row.get(0),
        )
        .map_err(owner_invalid)?;
    if global_table_exists && global_install_count(connection)? != 0 {
        return Err(owner_invalid(
            "pristine governed approval authority state has retained global references",
        ));
    }
    Ok(())
}

fn global_install_count(connection: &Connection) -> Result<i64, SqliteServingOwnerError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION_KIND],
            |row| row.get(0),
        )
        .map_err(owner_invalid)
}
