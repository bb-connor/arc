//! Installed return-bank cohort: activation, canonical rows and the frontier.
//!
//! Activation is the owning enrollment transaction: it installs the retained
//! family (schema.sql), creates the meta singleton at the genesis frontier and
//! moves the journal to version eight exactly when the first genuine funded
//! account is retained. Every load or writer re-verifies the complete family
//! catalog, the canonical payload rows and the dense signed event chain before
//! returning anything. An absent or incomplete bank never reads as zero debt.
use super::*;
use serde::{Deserialize, Serialize};

pub(super) const ACCOUNT_ENVELOPE_SCHEMA: &str = "chio.process-native-return-account.v1";
pub(super) const EVENT_SCHEMA: &str = "chio.process-native-return-event.v1";
const GENESIS_SCHEMA: &str = "chio.process-native-return-genesis.v1";
/// Seven tables and eighteen triggers are named by schema.sql.
const FAMILY_OBJECTS: usize = 25;
const MAX_EVENT_SEQUENCE: u64 = 9_007_199_254_740_991;

/// The retained immutable Process account: its exact prepared source DATA and
/// the verified native funding that enrolled it. Canonical bytes only; no
/// constructor, authority or capture shortcut exists on this shape.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountEnvelope {
    schema: String,
    source: ProcessReturnSourceDataV1,
    funding: ProcessReturnFundingDataV1,
}
impl AccountEnvelope {
    pub(super) fn source(&self) -> &ProcessReturnSourceDataV1 {
        &self.source
    }
    pub(super) fn funding(&self) -> &ProcessReturnFundingDataV1 {
        &self.funding
    }
    /// The one canonical encoder of a retained account: the exact prepared
    /// source and its verified native funding, bounded by the account row.
    pub(super) fn encode(
        source: ProcessReturnSourceDataV1,
        funding: ProcessReturnFundingDataV1,
    ) -> Result<Vec<u8>, ProcessError> {
        let bytes = crate::canonical_json_bytes(&Self {
            schema: ACCOUNT_ENVELOPE_SCHEMA.to_owned(),
            source,
            funding,
        })?;
        if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_BYTES {
            return Err(ProcessError::Limit("native return account envelope"));
        }
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventJson {
    schema: String,
    phase: String,
    account_digest: String,
    payload_digest: String,
}

/// One complete immutable account row.
pub(super) struct AccountRow {
    pub(super) account_digest: String,
    pub(super) process_id: String,
    pub(super) operation_key: String,
    pub(super) attempt: u32,
    pub(super) native_operation_id: String,
    pub(super) bytes: Vec<u8>,
}

pub(super) fn family_present(tx: &Connection) -> Result<bool, ProcessError> {
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'process_native_return_*'",
        [],
        |row| row.get(0),
    )?;
    Ok(count != 0)
}

fn runtime_version(tx: &Connection) -> Result<u32, ProcessError> {
    tx.query_row(
        "SELECT version FROM main.process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )
    .map_err(ProcessError::from)
}

/// Immutable bindings of one recorded source against the current journal:
/// the frozen call binding, the exact recorded attempt's derived request
/// identity, the durable authority and kernel key, the immutable process/root
/// identity and capability, and the actual held main-file descriptor. Mutable
/// progress (state, revision, checkpoint, tree_calls, the nonce slot, host
/// observations, and a later current attempt after a retry) never invalidates
/// a retained original account; the persisted current attempt may advance but
/// never regress below the recorded one. The recorded attempt itself is
/// authenticated exactly through its derived request identity, so a different
/// attempt is never treated as the recorded original.
fn verify_recorded_source(
    tx: &Connection,
    source: &ProcessReturnSourceDataV1,
) -> Result<(), ProcessError> {
    let (request_hash, attempts): (String, u32) = tx.query_row(
        "SELECT request_hash,attempts FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
        params![source.process_id, source.operation_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if request_hash != source.call_binding_digest || attempts < source.attempt {
        return Err(ProcessError::Conflict);
    }
    let (namespace, authority, kernel_key): (String, String, String) = tx.query_row(
        "SELECT namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if namespace != source.journal_namespace
        || authority != source.journal_authority
        || digest(&kernel_key)? != source.kernel_key_digest
    {
        return Err(ProcessError::Conflict);
    }
    // The exact recorded attempt is authenticated by its own derived request
    // identity under this namespace, independent of the mutable current
    // attempt counter. This matches the runtime's first- and later-attempt
    // request derivations byte for byte.
    let expected_request_id = if source.attempt <= 1 {
        format!(
            "process:{}",
            digest(&(&namespace, &source.process_id, &source.operation_key))?
        )
    } else {
        format!(
            "process:{}",
            digest(&(
                &namespace,
                &source.process_id,
                &source.operation_key,
                source.attempt
            ))?
        )
    };
    if source.request_id != expected_request_id {
        return Err(ProcessError::Conflict);
    }
    // The recorded source is bound to the actual held main-file descriptor:
    // exact copied rows in another journal file cannot spend this file's debt.
    let file = chio_sqlite_file_identity::main_database_file_identity(tx)
        .map_err(|_| ProcessError::Conflict)?;
    if file.device != source.file_device || file.inode != source.file_inode || file.link_count != 1
    {
        return Err(ProcessError::Conflict);
    }
    let Some(process) = super::super::read_process(tx, &source.process_id)? else {
        return Err(ProcessError::Conflict);
    };
    if process.root_id != source.root_process_id
        || digest(&process.capability)? != source.capability_digest
    {
        return Err(ProcessError::Conflict);
    }
    let Some(root) = super::super::read_process(tx, &source.root_process_id)? else {
        return Err(ProcessError::Conflict);
    };
    if root.root_id != root.id || process.root_id != root.id {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

fn genesis_digest() -> Result<String, ProcessError> {
    digest(&GENESIS_SCHEMA)
}

/// Activate the retained family inside the owning enrollment transaction, or
/// verify an already activated cohort. No partial or absent family is accepted.
pub(super) fn activate(tx: &Transaction<'_>) -> Result<(), ProcessError> {
    if family_present(tx)? {
        if runtime_version(tx)? != 8 {
            return Err(ProcessError::Configuration(
                "Process return bank journal version changed",
            ));
        }
        return verify_cohort(tx);
    }
    let version = runtime_version(tx)?;
    if !matches!(version, 1..=7) {
        return Err(ProcessError::Configuration(
            "Process return bank predecessor version is unsupported",
        ));
    }
    super::super::unused_recovery_reservation::verify_before_open(tx)?;
    super::super::confined_delivery::verify_before_open(tx)?;
    tx.execute_batch(include_str!("schema.sql"))?;
    let changed = tx.execute(
        "INSERT INTO process_native_return_meta(singleton,sequence,active_accounts,head_digest)
         VALUES(1,0,0,?1)",
        params![genesis_digest()?],
    )?;
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

/// The first retained account completes activation by moving the journal to
/// version eight. The schema trigger requires that account to already exist.
pub(super) fn require_version_eight(tx: &Transaction<'_>) -> Result<(), ProcessError> {
    let version = runtime_version(tx)?;
    if version == 8 {
        return Ok(());
    }
    if !matches!(version, 1..=7) || !family_present(tx)? {
        return Err(ProcessError::Configuration(
            "Process return cohort activation is unavailable",
        ));
    }
    let changed = tx.execute(
        "UPDATE process_runtime SET version=8 WHERE singleton=1 AND version=?1",
        params![version],
    )?;
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

fn event_digest(
    sequence: u64,
    account_digest: &str,
    phase: &str,
    payload_digest: &str,
    previous_digest: &str,
) -> Result<String, ProcessError> {
    digest(&(
        "chio.process-native-return-event.v1",
        sequence,
        account_digest,
        phase,
        payload_digest,
        previous_digest,
    ))
}

fn event_json_bytes(
    account_digest: &str,
    phase: &str,
    payload_digest: &str,
) -> Result<Vec<u8>, ProcessError> {
    let bytes = crate::canonical_json_bytes(&EventJson {
        schema: EVENT_SCHEMA.to_owned(),
        phase: phase.to_owned(),
        account_digest: account_digest.to_owned(),
        payload_digest: payload_digest.to_owned(),
    })?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(ProcessError::Limit("native return event"));
    }
    Ok(bytes)
}

/// Append the next frontier event for one retained purpose. The meta update is
/// checked by the schema trigger against this exact event.
pub(super) fn append_event(
    tx: &Transaction<'_>,
    account_digest: &str,
    phase: &str,
    payload_bytes: &[u8],
) -> Result<(u64, String), ProcessError> {
    let (sequence, active, head): (i64, i64, String) = tx.query_row(
        "SELECT sequence,active_accounts,head_digest FROM process_native_return_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let sequence = u64::try_from(sequence).map_err(|_| ProcessError::Conflict)?;
    let active = u64::try_from(active).map_err(|_| ProcessError::Conflict)?;
    let next = sequence
        .checked_add(1)
        .filter(|value| *value <= MAX_EVENT_SEQUENCE)
        .ok_or(ProcessError::Conflict)?;
    let next_active = match phase {
        "enrolled" => active
            .checked_add(1)
            .filter(|value| *value <= MAX_ACTIVE_ACCOUNTS)
            .ok_or(ProcessError::Limit("active native return accounts"))?,
        "reconciled" => active.checked_sub(1).ok_or(ProcessError::Conflict)?,
        "nonce_retained" | "unavailable" | "native_custody" => active,
        _ => return Err(ProcessError::Conflict),
    };
    let payload_digest = chio_core_types::crypto::sha256_hex(payload_bytes);
    let event_json = event_json_bytes(account_digest, phase, &payload_digest)?;
    let event_digest = event_digest(next, account_digest, phase, &payload_digest, &head)?;
    let changed = tx.execute(
        "INSERT INTO process_native_return_events
         (sequence,account_digest,phase,payload_digest,previous_digest,event_digest,event_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            next as i64,
            account_digest,
            phase,
            payload_digest,
            head,
            event_digest,
            event_json
        ],
    )?;
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    let changed = tx.execute(
        "UPDATE process_native_return_meta SET sequence=?1, active_accounts=?2, head_digest=?3
         WHERE singleton=1 AND sequence=?4",
        params![
            next as i64,
            next_active as i64,
            event_digest,
            sequence as i64
        ],
    )?;
    if changed != 1 {
        return Err(ProcessError::Conflict);
    }
    Ok((next, event_digest))
}

/// The retained event of one phase for one account, if it exists.
pub(super) fn phase_event(
    tx: &Connection,
    account_digest: &str,
    phase: &str,
) -> Result<Option<(u64, String, String)>, ProcessError> {
    let event: Option<(i64, String, String)> = tx
        .query_row(
            "SELECT sequence,event_digest,payload_digest FROM process_native_return_events
             WHERE account_digest=?1 AND phase=?2",
            params![account_digest, phase],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    event
        .map(|(sequence, event_digest, payload_digest)| {
            Ok((
                u64::try_from(sequence).map_err(|_| ProcessError::Conflict)?,
                event_digest,
                payload_digest,
            ))
        })
        .transpose()
}

fn payload_table(phase: &str) -> Result<(&'static str, &'static str), ProcessError> {
    match phase {
        "enrolled" => Ok(("process_native_return_accounts", "account_json")),
        "nonce_retained" => Ok(("process_native_return_nonce_receipts", "nonce_receipt_json")),
        "unavailable" => Ok(("process_native_return_notices", "notice_json")),
        "native_custody" => Ok(("process_native_return_fates", "fate_json")),
        "reconciled" => Ok((
            "process_native_return_reconciliations",
            "reconciliation_json",
        )),
        _ => Err(ProcessError::Conflict),
    }
}

fn payload_bytes(
    tx: &Connection,
    phase: &str,
    account_digest: &str,
) -> Result<Option<Vec<u8>>, ProcessError> {
    let (table, column) = payload_table(phase)?;
    let statement = format!("SELECT {column} FROM {table} WHERE account_digest=?1");
    tx.query_row(&statement, params![account_digest], |row| row.get(0))
        .optional()
        .map_err(ProcessError::from)
}

fn account_row_from(row: &rusqlite::Row<'_>) -> Result<AccountRow, rusqlite::Error> {
    Ok(AccountRow {
        account_digest: row.get(0)?,
        process_id: row.get(1)?,
        operation_key: row.get(2)?,
        attempt: row.get(3)?,
        native_operation_id: row.get(4)?,
        bytes: row.get(5)?,
    })
}

const ACCOUNT_COLUMNS: &str =
    "account_digest,process_id,operation_key,attempt,native_operation_id,account_json";

pub(super) fn account_row(
    tx: &Connection,
    account_digest: &str,
) -> Result<Option<AccountRow>, ProcessError> {
    let statement = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM process_native_return_accounts WHERE account_digest=?1"
    );
    tx.query_row(&statement, params![account_digest], account_row_from)
        .optional()
        .map_err(ProcessError::from)
}

pub(super) fn account_row_by_call(
    tx: &Connection,
    process_id: &str,
    operation_key: &str,
    attempt: u32,
) -> Result<Option<AccountRow>, ProcessError> {
    let statement = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM process_native_return_accounts
         WHERE process_id=?1 AND operation_key=?2 AND attempt=?3"
    );
    tx.query_row(
        &statement,
        params![process_id, operation_key, attempt],
        account_row_from,
    )
    .optional()
    .map_err(ProcessError::from)
}

pub(super) fn account_row_by_native_operation(
    tx: &Connection,
    native_operation_id: &str,
) -> Result<Option<AccountRow>, ProcessError> {
    let statement = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM process_native_return_accounts WHERE native_operation_id=?1"
    );
    tx.query_row(&statement, params![native_operation_id], account_row_from)
        .optional()
        .map_err(ProcessError::from)
}

/// Authenticate one retained account row against its own canonical bytes, the
/// genuine native funding contract and the current journal source cut.
pub(super) fn verify_account_row(
    tx: &Connection,
    row: &AccountRow,
) -> Result<AccountEnvelope, ProcessError> {
    let envelope: AccountEnvelope =
        serde_json::from_slice(&row.bytes).map_err(|_| ProcessError::Conflict)?;
    if envelope.schema != ACCOUNT_ENVELOPE_SCHEMA
        || crate::canonical_json_bytes(&envelope)? != row.bytes
        || row.bytes.is_empty()
        || row.bytes.len() > MAX_ACCOUNT_BYTES
    {
        return Err(ProcessError::Conflict);
    }
    chio_kernel::process_return_custody::validate_process_return_funding_data(
        &envelope.source,
        &envelope.funding,
    )
    .map_err(|_| ProcessError::Conflict)?;
    if envelope.funding.process_account_digest != row.account_digest
        || envelope.funding.native_operation_id != row.native_operation_id
        || envelope.source.process_id != row.process_id
        || envelope.source.operation_key != row.operation_key
        || envelope.source.attempt != row.attempt
    {
        return Err(ProcessError::Conflict);
    }
    // The recorded source is authenticated against the journal's immutable
    // original identity. Mutable progress since enrollment (state, revision,
    // checkpoint, tree calls, the nonce slot) never invalidates it.
    verify_recorded_source(tx, &envelope.source)?;
    Ok(envelope)
}

/// Verify the family catalog against the compiled cohort model. Every named
/// object and every autoindex must match exactly; nothing is normalized.
fn verify_family_catalog(tx: &Connection) -> Result<(), ProcessError> {
    let model = Connection::open_in_memory()?;
    model.execute_batch(include_str!("../../store.sql"))?;
    model.execute_batch(include_str!("../unused_recovery_reservation/schema.sql"))?;
    model.execute_batch(include_str!("../confined_delivery/schema.sql"))?;
    model.execute_batch(&format!(
        "{};",
        crate::store::KNOWLEDGE_NO_DOWNGRADE_TRIGGER
    ))?;
    model.execute_batch(include_str!("schema.sql"))?;
    let names: Vec<String> = {
        let mut statement = tx.prepare(
            "SELECT name FROM sqlite_schema WHERE name GLOB 'process_native_return_*' ORDER BY name",
        )?;
        let collected: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };
    if names.len() != FAMILY_OBJECTS {
        return Err(ProcessError::Configuration(
            "Process return bank family inventory changed",
        ));
    }
    for name in &names {
        let expected: (String, String, Option<String>) = model.query_row(
            "SELECT type,sql,tbl_name FROM sqlite_schema WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let actual: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT type,sql,tbl_name FROM sqlite_schema WHERE name=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if actual.as_ref() != Some(&expected) {
            return Err(ProcessError::Configuration(
                "Process return bank family catalog changed",
            ));
        }
    }
    for (table, indexes) in [
        ("process_native_return_accounts", 3),
        ("process_native_return_notices", 1),
        ("process_native_return_nonce_receipts", 1),
        ("process_native_return_fates", 1),
        ("process_native_return_reconciliations", 1),
        ("process_native_return_events", 1),
        ("process_native_return_meta", 0),
    ] {
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='index' AND sql IS NULL AND tbl_name=?1",
            [table],
            |row| row.get(0),
        )?;
        if count != indexes {
            return Err(ProcessError::Configuration(
                "Process return bank family indexes changed",
            ));
        }
    }
    Ok(())
}

/// Verify the complete retained cohort: exact family catalog, meta singleton,
/// dense signed event chain, canonical payload rows and every account
/// envelope bound to the journal's immutable original identity. The complete
/// history is authenticated by streaming ordered rows with per-account
/// indexed phase lookups; no all-history collection, cap or compaction.
pub(super) fn verify_cohort(tx: &Connection) -> Result<(), ProcessError> {
    if !family_present(tx)? {
        return Err(ProcessError::Configuration(
            "Process complete original return bank has not been installed",
        ));
    }
    verify_family_catalog(tx)?;
    let (sequence, active, head): (i64, i64, String) = tx.query_row(
        "SELECT sequence,active_accounts,head_digest FROM process_native_return_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let sequence = u64::try_from(sequence).map_err(|_| ProcessError::Conflict)?;
    let active = u64::try_from(active).map_err(|_| ProcessError::Conflict)?;
    let earlier_event =
        |account: &str, phase: Option<&str>, before: u64| -> Result<bool, ProcessError> {
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM process_native_return_events
              WHERE account_digest=?1 AND (?2 IS NULL OR phase=?2) AND sequence<?3)",
                params![account, phase, before as i64],
                |row| row.get(0),
            )
            .map_err(ProcessError::from)
        };
    let mut statement = tx.prepare(
        "SELECT sequence,account_digest,phase,payload_digest,previous_digest,event_digest,event_json
         FROM process_native_return_events ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = genesis_digest()?;
    let mut live = 0_u64;
    let mut counted = 0_u64;
    while let Some(row) = rows.next()? {
        let (
            raw_sequence,
            account,
            phase,
            payload_digest,
            previous_digest,
            event_digest_value,
            event_json,
        ): (i64, String, String, String, String, String, Vec<u8>) = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
        let row_sequence = u64::try_from(raw_sequence).map_err(|_| ProcessError::Conflict)?;
        counted = counted.checked_add(1).ok_or(ProcessError::Conflict)?;
        if row_sequence != counted
            || previous_digest != previous
            || event_digest(
                row_sequence,
                &account,
                &phase,
                &payload_digest,
                &previous_digest,
            )? != event_digest_value
        {
            return Err(ProcessError::Conflict);
        }
        let event: EventJson =
            serde_json::from_slice(&event_json).map_err(|_| ProcessError::Conflict)?;
        if crate::canonical_json_bytes(&event)? != event_json
            || event.schema != EVENT_SCHEMA
            || event.phase != phase
            || event.account_digest != account
            || event.payload_digest != payload_digest
        {
            return Err(ProcessError::Conflict);
        }
        let payload = payload_bytes(tx, &phase, &account)?.ok_or(ProcessError::Conflict)?;
        if chio_core_types::crypto::sha256_hex(&payload) != payload_digest {
            return Err(ProcessError::Conflict);
        }
        if !earlier_event(&account, None, row_sequence)? {
            // The event's account must already have been retained.
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM process_native_return_accounts WHERE account_digest=?1)",
                params![account],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(ProcessError::Conflict);
            }
        }
        match phase.as_str() {
            "enrolled" => {
                if earlier_event(&account, None, row_sequence)? {
                    return Err(ProcessError::Conflict);
                }
                live = live
                    .checked_add(1)
                    .filter(|value| *value <= MAX_ACTIVE_ACCOUNTS)
                    .ok_or(ProcessError::Conflict)?;
            }
            "nonce_retained" | "unavailable" | "native_custody" => {
                if !earlier_event(&account, Some("enrolled"), row_sequence)? {
                    return Err(ProcessError::Conflict);
                }
            }
            "reconciled" => {
                if !earlier_event(&account, Some("native_custody"), row_sequence)? {
                    return Err(ProcessError::Conflict);
                }
                live = live.checked_sub(1).ok_or(ProcessError::Conflict)?;
            }
            _ => return Err(ProcessError::Conflict),
        }
        previous = event_digest_value;
    }
    if counted != sequence || previous != head || live != active {
        return Err(ProcessError::Conflict);
    }
    // Stream every retained account: exactly one enrolled event whose payload
    // digest is its whole canonical row, and an envelope authenticated against
    // the journal's immutable original identity. Together with the per-event
    // account-existence checks this is the complete cold bijection between
    // events and retained accounts.
    let mut accounts = tx.prepare(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM process_native_return_accounts ORDER BY account_digest"
    ))?;
    let mut rows = accounts.query([])?;
    while let Some(row) = rows.next()? {
        let row = account_row_from(row)?;
        let envelope = verify_account_row(tx, &row)?;
        let event =
            phase_event(tx, &row.account_digest, "enrolled")?.ok_or(ProcessError::Conflict)?;
        if chio_core_types::crypto::sha256_hex(&row.bytes) != event.2
            || envelope.funding.process_account_digest != row.account_digest
        {
            return Err(ProcessError::Conflict);
        }
    }
    Ok(())
}

/// Cold open-time authentication of the retained cohort for the real Store
/// open owner. It writes and repairs nothing: a version-eight journal with an
/// absent, incomplete or forged cohort refuses, and cohort artifacts refuse
/// before their version. How version eight preserves older raw knowledge,
/// closure and delivery semantics belongs to the open owner's own gates.
pub(super) fn verify_before_open(connection: &Connection) -> Result<(), ProcessError> {
    let runtime_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='process_runtime')",
        [],
        |row| row.get(0),
    )?;
    if !runtime_present {
        if family_present(connection)? {
            return Err(ProcessError::Conflict);
        }
        return Ok(());
    }
    let version: Option<u32> = connection
        .query_row(
            "SELECT version FROM main.process_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match version {
        Some(8) => {
            if !family_present(connection)? {
                return Err(ProcessError::Configuration(
                    "Process return bank cohort is absent at version eight",
                ));
            }
            catalog::verify_feature_level_layout(connection, 8)?;
            verify_cohort(connection)
        }
        Some(version @ 1..=7) => {
            if family_present(connection)? {
                return Err(ProcessError::Configuration(
                    "Process return bank artifacts precede version eight",
                ));
            }
            catalog::verify_feature_level_layout(connection, version)?;
            Ok(())
        }
        _ => {
            if family_present(connection)? {
                return Err(ProcessError::Conflict);
            }
            Ok(())
        }
    }
}

fn whole_source_cut_digest(tx: &Connection) -> Result<String, ProcessError> {
    let mut processes = Vec::new();
    {
        let mut statement = tx.prepare(
            "SELECT id,parent_id,root_id,depth,
             CASE WHEN typeof(capability)='text' AND length(CAST(capability AS BLOB)) BETWEEN 1 AND 262144 THEN capability END,
             CASE WHEN typeof(limits)='text' AND length(CAST(limits AS BLOB)) BETWEEN 1 AND 4096 THEN limits END,
             state,revision,
             CASE WHEN typeof(checkpoint)='text' AND length(CAST(checkpoint AS BLOB)) BETWEEN 1 AND 1048576 THEN checkpoint END,
             tree_calls FROM main.processes ORDER BY id",
        )?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            processes.push((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                u64::try_from(row.get::<_, i64>(7)?).map_err(|_| ProcessError::Conflict)?,
                row.get::<_, String>(8)?,
                u64::try_from(row.get::<_, i64>(9)?).map_err(|_| ProcessError::Conflict)?,
            ));
        }
    }
    let mut calls = Vec::new();
    {
        let mut statement = tx.prepare(
            "SELECT process_id,operation_key,request_hash,attempts FROM main.process_calls ORDER BY process_id,operation_key",
        )?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            calls.push((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
            ));
        }
    }
    let mut nonces = Vec::new();
    {
        let mut statement = tx.prepare(
            "SELECT process_id,operation_key,attempt,nonce_json FROM main.process_call_nonces ORDER BY process_id,operation_key,attempt",
        )?;
        let mut query = statement.query([])?;
        while let Some(row) = query.next()? {
            nonces.push((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ));
        }
    }
    digest(
        &((
            "chio.process-native-whole-source-cut.v1",
            processes,
            calls,
            nonces,
        )),
    )
}

fn roots_digest(tx: &Connection) -> Result<String, ProcessError> {
    let mut statement = tx.prepare(
        "SELECT id,state,tree_calls,revision FROM main.processes WHERE root_id=id ORDER BY id",
    )?;
    let rows: Vec<(String, String, u64, u64)> = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                u64::try_from(row.get::<_, i64>(2)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                u64::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    digest(&(("chio.process-native-roots.v1", rows)))
}

/// Complete current file observation consumed by the native bank readback.
/// Both real states are authenticated from actual file content: an installed
/// cohort verifies its complete frontier and canonical rows, while an exact
/// supported predecessor layout authenticates through its profile and reports
/// proven zero counts as DATA. Zeros are measured facts of this file, never
/// inferences from missing tables; the native owner proves them against its
/// whole retained inverse before minting any bank.
pub(super) fn inventory(
    tx: &Connection,
    expected_namespace: &str,
    expected_authority: &str,
    expected_kernel_key: &str,
) -> Result<ProcessReturnInventoryDataV1, ProcessError> {
    let family = family_present(tx)?;
    let (namespace, authority, kernel_key): (String, String, String) = tx.query_row(
        "SELECT namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if namespace != expected_namespace
        || authority != expected_authority
        || kernel_key != expected_kernel_key
    {
        return Err(ProcessError::Conflict);
    }
    // The active profile authenticates the exact current layout, predecessor
    // or installed cohort, from the actual catalog and file identity.
    let store_path = tx.path().ok_or(ProcessError::Conflict)?;
    let profile = catalog::prepare_active_profile(
        tx,
        std::path::Path::new(store_path),
        expected_namespace,
        expected_authority,
        expected_kernel_key,
    )?;
    let file = chio_sqlite_file_identity::main_database_file_identity(tx)
        .map_err(|_| ProcessError::Conflict)?;
    let count = |query: &str| -> Result<u64, ProcessError> {
        u64::try_from(tx.query_row(query, [], |row| row.get::<_, i64>(0))?)
            .map_err(|_| ProcessError::Conflict)
    };
    let (account_count, phase_count, history_sequence, history_digest) = if family {
        verify_cohort(tx)?;
        let (sequence, _, head): (i64, i64, String) = tx.query_row(
            "SELECT sequence,active_accounts,head_digest FROM process_native_return_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        (
            count("SELECT count(*) FROM process_native_return_accounts")?,
            count("SELECT count(*) FROM process_native_return_events")?,
            u64::try_from(sequence).map_err(|_| ProcessError::Conflict)?,
            head,
        )
    } else {
        // A proven-empty predecessor history: the digest binds the actual
        // namespace, authority and authenticated catalog, so it is a
        // measured fact of this file rather than a minted dummy value.
        let head = digest(
            &((
                "chio.process-native-return-history.v1",
                "predecessor",
                &namespace,
                &authority,
                profile.catalog_digest(),
            )),
        )?;
        (0, 0, 0, head)
    };
    let inventory = ProcessReturnInventoryDataV1 {
        schema: chio_kernel::process_return_custody::PROCESS_RETURN_INVENTORY_SCHEMA.to_owned(),
        journal_namespace: namespace,
        journal_authority: authority,
        kernel_key_digest: digest(&kernel_key)?,
        file_device: file.device,
        file_inode: file.inode,
        catalog_digest: profile.catalog_digest().to_owned(),
        physical_profile_digest: profile.recipe_digest().to_owned(),
        whole_source_cut_digest: whole_source_cut_digest(tx)?,
        roots_digest: roots_digest(tx)?,
        root_count: count("SELECT count(*) FROM main.processes WHERE root_id=id")?,
        process_count: count("SELECT count(*) FROM main.processes")?,
        account_count,
        phase_count,
        // This observing writer connection is the single current writer of the
        // retained file.
        current_write_count: 1,
        history_sequence,
        history_digest,
    };
    inventory
        .validate_data()
        .map_err(|_| ProcessError::Conflict)?;
    Ok(inventory)
}

/// Revalidate a bank's inventory inside the owning writer's transaction: the
/// complete observation is recomputed from the live journal and must still be
/// exactly what the native owner minted the proof from. Torn state, family
/// loss with retained history, or any file substitution refuses here.
pub(super) fn revalidate_inventory(
    tx: &Connection,
    minted: &ProcessReturnInventoryDataV1,
) -> Result<(), ProcessError> {
    let (namespace, authority, kernel_key): (String, String, String) = tx.query_row(
        "SELECT namespace,authority,kernel_key FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if &inventory(tx, &namespace, &authority, &kernel_key)? != minted {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

/// Stream every retained enrollment to the native whole-inverse verifier in
/// strictly increasing enrolled-event sequence, which is the integer primary
/// key of the event table. The exact inventory is revalidated from the live
/// file first (including the complete cohort and frontier); each enrolled
/// event then resolves its canonical account row, whose complete contents,
/// funding and payload digest are authenticated before the native callback
/// receives the source, funding, account digest and event coordinates. One row
/// is held at a time: there is no lifetime collection, cap or compaction, and
/// settled historical accounts are included so the native inverse covers the
/// complete retained history. A predecessor layout streams nothing and must
/// report zero accounts. Pure data inspection: no financial or invocation
/// authority, and nothing is written.
pub(super) fn stream_enrollments(
    tx: &Connection,
    minted: &ProcessReturnInventoryDataV1,
    mut verify: impl FnMut(
        &ProcessReturnSourceDataV1,
        &ProcessReturnFundingDataV1,
        &str,
        u64,
        &str,
    )
        -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
) -> Result<u64, chio_kernel::admission_operation::AdmissionOperationStoreError> {
    use chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant;
    let refused = |error: ProcessError| {
        Invariant(format!(
            "Process retained enrollment stream refused: {error}"
        ))
    };
    let sql = |error: rusqlite::Error| refused(ProcessError::from(error));
    revalidate_inventory(tx, minted).map_err(refused)?;
    if !family_present(tx).map_err(refused)? {
        return if minted.account_count == 0 {
            Ok(0)
        } else {
            Err(Invariant(
                "Process predecessor layout reports retained enrollments".to_owned(),
            ))
        };
    }
    let mut statement = tx
        .prepare(
            "SELECT sequence,account_digest,event_digest,payload_digest
             FROM process_native_return_events WHERE phase='enrolled' ORDER BY sequence",
        )
        .map_err(sql)?;
    let mut events = statement.query([]).map_err(sql)?;
    let mut counted: u64 = 0;
    let mut previous: u64 = 0;
    while let Some(event) = events.next().map_err(sql)? {
        let sequence = u64::try_from(event.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| Invariant("Process enrollment sequence is negative".to_owned()))?;
        let account_digest: String = event.get(1).map_err(sql)?;
        let event_digest: String = event.get(2).map_err(sql)?;
        let payload_digest: String = event.get(3).map_err(sql)?;
        if sequence <= previous {
            return Err(Invariant(
                "Process enrollment events are not strictly increasing".to_owned(),
            ));
        }
        previous = sequence;
        let row = account_row(tx, &account_digest)
            .map_err(refused)?
            .ok_or_else(|| {
                Invariant("Process enrolled event lost its retained account".to_owned())
            })?;
        let envelope = verify_account_row(tx, &row).map_err(refused)?;
        if chio_core_types::crypto::sha256_hex(&row.bytes) != payload_digest {
            return Err(Invariant(
                "Process retained enrollment payload diverged".to_owned(),
            ));
        }
        // The native callback's refusal propagates unchanged: its exact
        // source, funding, account and event coordinates are the whole
        // inverse's authority here.
        verify(
            envelope.source(),
            envelope.funding(),
            &account_digest,
            sequence,
            &event_digest,
        )?;
        counted = counted
            .checked_add(1)
            .ok_or_else(|| Invariant("Process retained enrollment count overflowed".to_owned()))?;
    }
    Ok(counted)
}
