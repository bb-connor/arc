use super::*;

use crate::proxy::mediated::MediationKernelInputs;
use chio_http_serve::{
    apply_server_hygiene, run_until_drained, ServeError, ServeHygieneConfig, ShutdownController,
};
use std::time::Duration;

/// Interval between reserved-hold reaper sweeps. A hold reserved on
/// `/v1/evaluate` but never reconciled is released once its execution-nonce TTL
/// lapses; sweeping on this cadence bounds how long abandoned budget stays held.
const RESERVED_HOLD_REAP_INTERVAL_SECS: u64 = 30;

/// Spawn the reserved-hold reaper and retain its `JoinHandle` on the shared
/// state so the worker can be aborted when the server stops. Dropping a
/// `JoinHandle` only detaches the worker (it keeps running); retaining it is what
/// binds the reaper's lifetime to the server's. A no-op without a mediation
/// kernel, since nothing reserves holds there.
pub(crate) async fn spawn_reserved_hold_reaper(state: &Arc<ProxyState>) {
    if state.mediation_kernel.is_none() {
        return;
    }
    let reaper_state = Arc::clone(state);
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            RESERVED_HOLD_REAP_INTERVAL_SECS,
        ));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now().timestamp();
            match reap_expired_reserved_holds_once(&reaper_state, now).await {
                Ok(0) => {}
                Ok(released) => {
                    info!(released, "reaped expired reserved budget holds");
                }
                Err(error) => {
                    warn!("reserved-hold reaper failed: {error}");
                }
            }
        }
    });
    *state.reaper_handle.lock().await = Some(handle);
}

/// Extra window the drain holds open beyond the upstream hop ceiling so a hop
/// that trips its own deadline still has time to record its receipt before the
/// forced drain closes the connection.
const PROXY_DRAIN_MARGIN: Duration = Duration::from_secs(5);

/// Drain window for the proxy serve site, derived from the configured upstream
/// hop ceiling.
///
/// The proxy records its receipt inside the request handler, after the upstream
/// call returns (success or failure), and runs with no generic request timeout:
/// that outer layer would drop the handler mid-hop and skip the receipt entirely.
/// Bounding the upstream call is what keeps a stalled upstream from becoming an
/// unbounded handler, and holding the drain a margin above that ceiling is what
/// lets an in-flight hop resolve and record its receipt before a shutdown
/// force-closes the connection. Deriving the drain from the (configurable) hop
/// ceiling preserves that ordering for any configured value, not just the default.
fn proxy_drain_timeout(upstream_request_timeout: Duration) -> Duration {
    upstream_request_timeout.saturating_add(PROXY_DRAIN_MARGIN)
}

/// Derive the revocation store path that sits beside a receipt store path.
///
/// The receipt boundary resolves operator input to an absolute plain filesystem
/// path before opening any store. Keeping this derivation on that resolved path
/// makes the receipt and revocation databases share the same trusted parent.
fn revocation_sibling_path(receipt_path: &str) -> String {
    format!("{receipt_path}.revocations")
}

pub(crate) fn resolved_plain_database_path(
    path: &str,
    option_name: &str,
) -> Result<String, ProtectError> {
    if path.is_empty() {
        return Err(ProtectError::Config(format!(
            "{option_name} must identify a durable plain filesystem path"
        )));
    }
    if chio_store_sqlite::is_in_memory_sqlite_path(path) {
        return Err(ProtectError::Config(format!(
            "{option_name} must identify a durable plain filesystem path"
        )));
    }
    if path.to_ascii_lowercase().starts_with("file:") {
        return Err(ProtectError::Config(format!(
            "{option_name} must be a plain filesystem path, not a SQLite file URI"
        )));
    }

    let configured = std::path::Path::new(path);
    let resolved = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                ProtectError::Config(format!(
                    "cannot resolve relative {option_name} against the current directory: {error}"
                ))
            })?
            .join(configured)
    };
    if resolved.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(ProtectError::Config(format!(
            "{option_name} must not contain current-directory or parent-directory components"
        )));
    }
    let mut unresolved_suffix = Vec::new();
    let mut candidate = resolved;
    let mut symlink_hops = 0_u8;
    let resolved = loop {
        match std::fs::canonicalize(&candidate) {
            Ok(mut existing) => {
                for component in unresolved_suffix.iter().rev() {
                    existing.push(component);
                }
                break existing;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(&candidate)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    symlink_hops = symlink_hops.saturating_add(1);
                    if symlink_hops > 40 {
                        return Err(ProtectError::Config(format!(
                            "cannot resolve durable {option_name} `{path}`: too many symbolic links"
                        )));
                    }
                    let target = std::fs::read_link(&candidate).map_err(|error| {
                        ProtectError::Config(format!(
                            "cannot resolve durable {option_name} `{path}` symbolic link: {error}"
                        ))
                    })?;
                    candidate = if target.is_absolute() {
                        target
                    } else {
                        candidate
                            .parent()
                            .ok_or_else(|| {
                                ProtectError::Config(format!(
                                    "cannot resolve durable {option_name} `{path}` symbolic link parent"
                                ))
                            })?
                            .join(target)
                    };
                    continue;
                }
                let component = candidate.file_name().ok_or_else(|| {
                    ProtectError::Config(format!(
                        "cannot resolve durable {option_name} `{path}`: missing path component"
                    ))
                })?;
                unresolved_suffix.push(component.to_os_string());
                candidate = candidate
                    .parent()
                    .ok_or_else(|| {
                        ProtectError::Config(format!(
                            "cannot resolve durable {option_name} `{path}`: no existing ancestor"
                        ))
                    })?
                    .to_path_buf();
            }
            Err(error) => {
                return Err(ProtectError::Config(format!(
                    "cannot resolve durable {option_name} `{path}`: {error}"
                )));
            }
        }
    };

    resolved.into_os_string().into_string().map_err(|_| {
        ProtectError::Config(format!("{option_name} must resolve to a valid UTF-8 path"))
    })
}

/// Resolve a configured durable receipt database to the absolute plain path
/// required by the descriptor-bound receipt store.
///
/// Volatile SQLite spellings are handled by the caller as an explicit
/// ephemeral opt-in. Durable SQLite URIs are rejected because URI semantics
/// cannot be bound to the retained filesystem descriptor without ambiguity.
fn durable_receipt_database_path(path: Option<&str>) -> Result<Option<String>, ProtectError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if chio_store_sqlite::is_in_memory_sqlite_path(path) {
        return Ok(None);
    }
    resolved_plain_database_path(path, "receipt_db").map(Some)
}

/// Resolve the exact revocation authority selected for this process. An
/// explicit `revocation_db` wins; otherwise durable receipt deployments use the
/// receipt sibling. Ephemeral receipt deployments fall back to an in-memory
/// authority later in construction.
fn durable_revocation_database_path(
    configured_path: Option<&str>,
    durable_receipt_path: Option<&str>,
) -> Result<Option<String>, ProtectError> {
    match configured_path {
        Some(path) => resolved_plain_database_path(path, "revocation_db").map(Some),
        None => durable_receipt_path
            .map(|path| {
                resolved_plain_database_path(&revocation_sibling_path(path), "revocation_db")
            })
            .transpose(),
    }
}

/// Revocation topology retained before any durable authority is mutated.
pub(crate) enum PreparedRevocationStore {
    Durable {
        resolved_path: String,
        authority_directory: Arc<chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory>,
        existing_identity: Option<Arc<chio_store_sqlite::durable_sqlite::DurableSqliteFile>>,
    },
    Ephemeral,
}

impl PreparedRevocationStore {
    fn durable_path(&self) -> Option<&str> {
        match self {
            Self::Durable { resolved_path, .. } => Some(resolved_path),
            Self::Ephemeral => None,
        }
    }
}

/// Resolve and descriptor-bind the selected revocation authority without
/// creating or modifying its database. Existing databases retain their exact
/// file identity now; missing databases retain the trusted parent and filename
/// for an exclusive hardened open later.
pub(crate) fn prepare_revocation_store(
    configured_path: Option<&str>,
    durable_receipt_path: Option<&str>,
) -> Result<PreparedRevocationStore, ProtectError> {
    let Some(resolved_path) =
        durable_revocation_database_path(configured_path, durable_receipt_path)?
    else {
        return Ok(PreparedRevocationStore::Ephemeral);
    };
    let authority_directory = Arc::new(
        chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(
            &resolved_path,
        )
        .map_err(|error| {
            ProtectError::Config(format!(
                "cannot prepare authoritative revocation store `{resolved_path}`: {error}"
            ))
        })?,
    );
    let existing_identity = match std::fs::symlink_metadata(&resolved_path) {
        Ok(_) => Some(
            authority_directory
                .open_database(&resolved_path, false)
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "cannot prepare authoritative revocation store `{resolved_path}`: {error}"
                    ))
                })?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(ProtectError::Config(format!(
                "cannot inspect authoritative revocation store `{resolved_path}`: {error}"
            )))
        }
    };
    Ok(PreparedRevocationStore::Durable {
        resolved_path,
        authority_directory,
        existing_identity,
    })
}

/// Open the exact revocation authority retained during topology preparation.
pub(crate) type OpenedRevocationStore = (
    Option<Arc<dyn chio_kernel::RevocationStore>>,
    HashSet<String>,
);

pub(crate) fn open_prepared_revocation_store(
    prepared: PreparedRevocationStore,
) -> Result<OpenedRevocationStore, ProtectError> {
    match prepared {
        PreparedRevocationStore::Durable {
            resolved_path,
            authority_directory,
            existing_identity,
        } => {
            let store = match existing_identity {
                Some(identity) => {
                    chio_store_sqlite::SqliteRevocationStore::open_hardened_file(identity)
                }
                None => chio_store_sqlite::SqliteRevocationStore::open_hardened(
                    &resolved_path,
                    authority_directory,
                ),
            }
            .map_err(|error| {
                ProtectError::Config(format!(
                    "cannot open authoritative revocation store `{resolved_path}`: {error}"
                ))
            })?;
            let ids = load_revocation_store_ids(&store, &resolved_path)?;
            Ok((Some(Arc::new(store)), ids))
        }
        PreparedRevocationStore::Ephemeral => Ok((
            Some(Arc::new(chio_kernel::InMemoryRevocationStore::new())),
            HashSet::new(),
        )),
    }
}

#[cfg(unix)]
fn existing_authority_identity(path: &str) -> Result<Option<(u64, u64)>, ProtectError> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProtectError::Config(format!(
            "cannot inspect durable authority path `{path}`: {error}"
        ))),
    }
}

#[cfg(not(unix))]
fn existing_authority_identity(_path: &str) -> Result<Option<(u64, u64)>, ProtectError> {
    Ok(None)
}

fn validate_durable_database_topology(
    receipt_path: Option<&str>,
    revocation_path: Option<&str>,
    prepared_budget: Option<&PreparedBudgetStore>,
) -> Result<(), ProtectError> {
    let mut authorities = Vec::new();
    if let Some(path) = receipt_path {
        authorities.push(("receipt_db", path.to_string()));
    }
    if let Some(path) = revocation_path {
        authorities.push(("revocation_db", path.to_string()));
    }
    if let Some((budget_path, operation_path, nonce_path)) =
        prepared_budget.and_then(PreparedBudgetStore::local_authority_paths)
    {
        authorities.push(("budget_db", budget_path.to_string()));
        authorities.push(("admission operation store", operation_path.to_string()));
        authorities.push(("execution nonce store", nonce_path.to_string()));
    }

    for (index, (left_name, left_path)) in authorities.iter().enumerate() {
        for (right_name, right_path) in authorities.iter().skip(index + 1) {
            let same_existing_file = match (
                existing_authority_identity(left_path)?,
                existing_authority_identity(right_path)?,
            ) {
                (Some(left), Some(right)) => left == right,
                _ => false,
            };
            if left_path == right_path
                || left_path.eq_ignore_ascii_case(right_path)
                || same_existing_file
            {
                return Err(ProtectError::Config(format!(
                    "durable authority path conflict: {left_name} and {right_name} resolve to the same database identity"
                )));
            }
        }
    }
    Ok(())
}

fn validate_durable_mediation_signer(
    signer_seed_hex: Option<&str>,
    durable_mediation_enabled: bool,
) -> Result<(), ProtectError> {
    if durable_mediation_enabled && signer_seed_hex.is_none() {
        return Err(ProtectError::Config(
            "durable direct mediation requires signer_seed_hex so admission ownership remains stable across restart"
                .to_string(),
        ));
    }
    Ok(())
}

const MAX_TRUSTED_HISTORICAL_RECEIPT_SIGNERS: usize = 32;

fn trusted_receipt_signers_for_config(
    config: &ProtectConfig,
    current_signer: &PublicKey,
) -> Result<Vec<PublicKey>, ProtectError> {
    let mut historical = Vec::new();
    for signer in &config.trusted_historical_receipt_signers {
        if signer == current_signer {
            return Err(ProtectError::Config(
                "historical receipt signer trust must not repeat the current signer".to_string(),
            ));
        }
        if config.trusted_capability_issuers.contains(signer) {
            return Err(ProtectError::Config(
                "historical receipt signer trust must not overlap capability issuer trust"
                    .to_string(),
            ));
        }
        if !historical.contains(signer) {
            historical.push(signer.clone());
        }
    }
    if historical.len() > MAX_TRUSTED_HISTORICAL_RECEIPT_SIGNERS {
        return Err(ProtectError::Config(format!(
            "trusted_historical_receipt_signers exceeds the maximum of {MAX_TRUSTED_HISTORICAL_RECEIPT_SIGNERS} unique keys"
        )));
    }
    let mut trusted = Vec::with_capacity(historical.len().saturating_add(1));
    trusted.push(current_signer.clone());
    trusted.extend(historical);
    Ok(trusted)
}

/// Stored receipts for inspection and querying.
pub(crate) struct ReceiptLog {
    pub(crate) receipts: Vec<HttpReceipt>,
}

/// Stored Chio receipts for tool-call sidecar aliases.
pub(crate) struct ToolReceiptLog {
    pub(crate) receipts: Vec<ChioReceipt>,
}

/// Reserved primary key the readiness probe writes and immediately rolls back,
/// so exercising the receipt write path never leaves a durable row.
const RECEIPT_READINESS_PROBE_ID: &str = "__chio_readiness_probe__";
const RECEIPT_STARTUP_CACHE_MAX_ROWS: usize = 1024;

pub(crate) struct SqliteReceiptStore {
    connection: chio_store_sqlite::SqliteReceiptBoundConnection,
}

impl SqliteReceiptStore {
    #[cfg(test)]
    pub(crate) fn open(path: &str) -> Result<Self, ProtectError> {
        let receipt_store = chio_store_sqlite::SqliteReceiptStore::open(path)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Self::open_bound(&receipt_store)
    }

    pub(crate) fn open_bound(
        receipt_store: &chio_store_sqlite::SqliteReceiptStore,
    ) -> Result<Self, ProtectError> {
        let connection = receipt_store
            .open_bound_colocated_connection()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        connection
            .validated_connection()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS http_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY
                );
                ",
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(Self { connection })
    }

    fn validated_connection(
        &self,
    ) -> Result<chio_store_sqlite::SqliteReceiptConnectionGuard<'_>, ProtectError> {
        self.connection
            .validated_connection()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))
    }

    /// Reachability check of the receipt write path, for the readiness probe.
    /// A bare `SELECT 1` answers even when the receipt tables have been dropped or
    /// the database has gone read-only or full, so it would keep an instance in
    /// rotation while every append fails after an already-allowed upstream call.
    /// This exercises the real receipt tables and the write path inside a
    /// transaction that is always rolled back: a dropped table, a read-only mount,
    /// or a full disk fails readiness, and no probe row is ever persisted.
    pub(crate) fn is_reachable(&self) -> bool {
        self.probe_receipt_write_path().is_ok()
    }

    fn probe_receipt_write_path(&self) -> Result<(), rusqlite::Error> {
        let connection = self
            .connection
            .validated_connection()
            .map_err(|error| rusqlite::Error::InvalidParameterName(error.to_string()))?;
        let tx = connection.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO http_receipts (id, receipt_json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
            params![RECEIPT_READINESS_PROBE_ID, "{}"],
        )?;
        tx.execute(
            "INSERT INTO tool_receipts (id, receipt_json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
            params![RECEIPT_READINESS_PROBE_ID, "{}"],
        )?;
        tx.rollback()
    }

    pub(crate) fn load_receipts(
        &self,
        trusted_signers: &[PublicKey],
    ) -> Result<Vec<HttpReceipt>, ProtectError> {
        let connection = self.validated_connection()?;
        let limit = i64::try_from(RECEIPT_STARTUP_CACHE_MAX_ROWS).map_err(|_| {
            ProtectError::ReceiptStore("receipt startup cache limit is invalid".to_string())
        })?;
        let mut statement = connection
            .prepare("SELECT id, receipt_json FROM http_receipts ORDER BY rowid DESC LIMIT ?1")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map(params![limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let (stored_id, receipt_json) =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(verified_http_receipt(
                &stored_id,
                &receipt_json,
                trusted_signers,
            )?);
        }
        receipts.reverse();
        Ok(receipts)
    }

    pub(crate) fn load_tool_receipts(
        &self,
        trusted_signers: &[PublicKey],
    ) -> Result<Vec<ChioReceipt>, ProtectError> {
        let connection = self.validated_connection()?;
        let limit = i64::try_from(RECEIPT_STARTUP_CACHE_MAX_ROWS).map_err(|_| {
            ProtectError::ReceiptStore("receipt startup cache limit is invalid".to_string())
        })?;
        let mut statement = connection
            .prepare("SELECT id, receipt_json FROM tool_receipts ORDER BY rowid DESC LIMIT ?1")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map(params![limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let (stored_id, receipt_json) =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(verified_tool_receipt(
                &stored_id,
                &receipt_json,
                trusted_signers,
            )?);
        }
        receipts.reverse();
        Ok(receipts)
    }

    pub(crate) fn append(&mut self, receipt: &HttpReceipt) -> Result<(), ProtectError> {
        if !receipt
            .verify_signature()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?
        {
            return Err(ProtectError::ReceiptStore(
                "refusing to persist an invalid HTTP receipt".to_string(),
            ));
        }
        let receipt_json = canonical_receipt_json(receipt)?;
        append_exact_receipt(
            self.validated_connection()?,
            "http_receipts",
            &receipt.id,
            &receipt_json,
        )
    }

    pub(crate) fn append_tool_receipt(
        &mut self,
        receipt: &ChioReceipt,
    ) -> Result<(), ProtectError> {
        if !receipt
            .verify_signature()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?
        {
            return Err(ProtectError::ReceiptStore(
                "refusing to persist an invalid tool receipt".to_string(),
            ));
        }
        let receipt_json = canonical_receipt_json(receipt)?;
        append_exact_receipt(
            self.validated_connection()?,
            "tool_receipts",
            &receipt.id,
            &receipt_json,
        )
    }

    #[cfg(test)]
    pub(crate) fn load_revoked_capability_ids(&self) -> Result<HashSet<String>, ProtectError> {
        let connection = self.validated_connection()?;
        let limit = i64::try_from(REVOCATION_ACCELERATION_CACHE_MAX_IDS).map_err(|_| {
            ProtectError::ReceiptStore("revocation cache limit is invalid".to_string())
        })?;
        let mut statement = connection
            .prepare("SELECT capability_id FROM revoked_capabilities ORDER BY rowid DESC LIMIT ?1")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map(params![limit], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut capability_ids = HashSet::new();
        for row in rows {
            let capability_id =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            capability_ids.insert(capability_id);
        }
        Ok(capability_ids)
    }

    pub(crate) fn revoke_capability(&mut self, capability_id: &str) -> Result<(), ProtectError> {
        self.validated_connection()?
            .execute(
                "INSERT INTO revoked_capabilities (capability_id) VALUES (?1) ON CONFLICT(capability_id) DO NOTHING",
                params![capability_id],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }
}

fn canonical_receipt_json(receipt: &impl Serialize) -> Result<String, ProtectError> {
    let bytes = chio_core_types::canonical_json_bytes(receipt)
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| ProtectError::ReceiptStore(error.to_string()))
}

fn append_exact_receipt(
    connection: impl std::ops::Deref<Target = Connection>,
    table: &str,
    receipt_id: &str,
    receipt_json: &str,
) -> Result<(), ProtectError> {
    let (insert_sql, select_sql) = match table {
        "http_receipts" => (
            "INSERT INTO http_receipts (id, receipt_json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
            "SELECT receipt_json FROM http_receipts WHERE id = ?1",
        ),
        "tool_receipts" => (
            "INSERT INTO tool_receipts (id, receipt_json) VALUES (?1, ?2) ON CONFLICT(id) DO NOTHING",
            "SELECT receipt_json FROM tool_receipts WHERE id = ?1",
        ),
        _ => {
            return Err(ProtectError::ReceiptStore(
                "unsupported receipt table".to_string(),
            ))
        }
    };
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
    let inserted = transaction
        .execute(insert_sql, params![receipt_id, receipt_json])
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
    if inserted == 0 {
        let existing = transaction
            .query_row(select_sql, params![receipt_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        if existing.as_deref().map(str::as_bytes) != Some(receipt_json.as_bytes()) {
            return Err(ProtectError::ReceiptStore(format!(
                "receipt id `{receipt_id}` already exists with different canonical bytes"
            )));
        }
    }
    transaction
        .commit()
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))
}

fn verified_http_receipt(
    stored_id: &str,
    receipt_json: &str,
    trusted_signers: &[PublicKey],
) -> Result<HttpReceipt, ProtectError> {
    let receipt: HttpReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
    if receipt.id != stored_id
        || canonical_receipt_json(&receipt)?.as_bytes() != receipt_json.as_bytes()
        || !trusted_signers.contains(&receipt.kernel_key)
        || !receipt
            .verify_signature()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?
    {
        return Err(ProtectError::ReceiptStore(
            "persisted HTTP receipt failed identity, canonical-byte, signer, or signature validation"
                .to_string(),
        ));
    }
    Ok(receipt)
}

fn verified_tool_receipt(
    stored_id: &str,
    receipt_json: &str,
    trusted_signers: &[PublicKey],
) -> Result<ChioReceipt, ProtectError> {
    let receipt: ChioReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
    if receipt.id != stored_id
        || canonical_receipt_json(&receipt)?.as_bytes() != receipt_json.as_bytes()
        || !trusted_signers.contains(&receipt.kernel_key)
        || !receipt
            .verify_signature()
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?
    {
        return Err(ProtectError::ReceiptStore(
            "persisted tool receipt failed identity, canonical-byte, signer, or signature validation"
                .to_string(),
        ));
    }
    Ok(receipt)
}

/// Shared proxy state.
pub(crate) struct ProxyState {
    pub(crate) evaluator: RequestEvaluator,
    pub(crate) signer_keypair: Keypair,
    pub(crate) upstream: String,
    pub(crate) http_client: reqwest::Client,
    pub(crate) egress_contract: HttpEgressContract,
    pub(crate) approval_admin: ApprovalAdmin,
    pub(crate) receipt_log: Mutex<ReceiptLog>,
    pub(crate) tool_receipt_log: Mutex<ToolReceiptLog>,
    pub(crate) receipt_store: Option<Mutex<SqliteReceiptStore>>,
    /// Authoritative revocation store shared with the evaluator and embedded
    /// kernel. An explicit revocation_db wins over the receipt sibling. The
    /// release route writes this exact handle before updating its acceleration
    /// cache or attempting the legacy receipt-table mirror.
    pub(crate) revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    pub(crate) revoked_capability_ids: Mutex<HashSet<String>>,
    pub(crate) trusted_capability_issuers: Vec<PublicKey>,
    pub(crate) trusted_receipt_signers: Vec<PublicKey>,
    pub(crate) sidecar_control_token: Option<String>,
    pub(crate) budget_store: Option<Arc<dyn chio_kernel::budget_store::BudgetStore>>,
    /// Whether the configured `budget_store` implements the pre-execution hold
    /// APIs the mediated reservation path depends on. `true` for the local SQLite
    /// store, `false` for the remote control-plane store (which forwards only
    /// charge/reverse/reconcile and cannot persist a durable reserved hold). The
    /// mediated `/v1/evaluate` and `/v1/reconcile` routes reject fail-closed when
    /// this is `false`, rather than mint a reserved nonce that can never be
    /// reconciled by nonce or reclaimed by the TTL reaper.
    pub(crate) mediation_hold_capable: bool,
    /// The service-lifetime kernel-mediation authority, built once when a budget
    /// store is configured. Serialized access coordinates authorization,
    /// reconciliation, emergency state, and reserved-hold reaping. Reuse keeps
    /// the approval-token and DPoP replay stores authoritative, and ensures the
    /// nonce minted on `/v1/evaluate` is verified and consumed by the same
    /// authority on `/v1/reconcile`.
    pub(crate) mediation_kernel: Option<Mutex<chio_kernel::ChioKernel>>,
    /// Retained `JoinHandle` for the reserved-hold reaper worker. Held so the
    /// reaper can be aborted when the server stops accepting; a dropped
    /// `JoinHandle` only detaches the worker (it keeps running) rather than
    /// aborting it. `None` until the reaper is spawned (and when no mediation
    /// kernel is configured, since nothing reserves holds).
    pub(crate) reaper_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) allow_advisory: bool,
    pub(crate) receipt_backend: &'static str,
    pub(crate) revocation_backend: &'static str,
}

impl ProxyState {
    /// Remember a known-positive revocation without allowing the acceleration
    /// cache to grow beyond its fixed process-memory budget.
    pub(crate) async fn cache_revoked_capability(&self, capability_id: &str) {
        let mut cache = self.revoked_capability_ids.lock().await;
        if cache.len() < REVOCATION_ACCELERATION_CACHE_MAX_IDS {
            cache.insert(capability_id.to_string());
        }
    }

    /// Whether a capability has been revoked. The in-memory set accelerates
    /// known positives, while every cache miss consults the shared authority so
    /// writes made by another handle or replica are visible without a restart.
    /// Fails closed: if the authority cannot be queried, treat the capability as
    /// revoked rather than admit one that may have been released.
    pub(crate) async fn capability_is_revoked(&self, capability_id: &str) -> bool {
        if self
            .revoked_capability_ids
            .lock()
            .await
            .contains(capability_id)
        {
            return true;
        }
        if let Some(revocation_store) = &self.revocation_store {
            match revocation_store.is_revoked(capability_id) {
                Ok(false) => {}
                Ok(true) => {
                    self.cache_revoked_capability(capability_id).await;
                    return true;
                }
                Err(error) => {
                    warn!("failed to query durable revocation store: {error}");
                    return true;
                }
            }
        }
        false
    }
}

impl ProxyState {
    /// Dependency-aware readiness for the `/chio/health` probe.
    ///
    /// Unlike liveness, this reports the state of the runtime dependencies the
    /// sidecar needs to serve honestly. When the durable receipt store's supervised
    /// commit writer has stopped serving, every mediated call would be denied fail
    /// closed, so readiness reports unhealthy and a platform probe pulls the instance
    /// from rotation rather than routing traffic to a sidecar that can only deny.
    pub(crate) async fn readiness_status(&self) -> SidecarStatus {
        if let Some(store) = &self.receipt_store {
            let store = store.lock().await;
            if !store.is_reachable() {
                return SidecarStatus::Unhealthy;
            }
        }
        SidecarStatus::Healthy
    }
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
    threshold_approval_collector: Option<ThresholdApprovalCollectorConfig>,
    verified_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
    /// Operator-configured payment rail for the kernel-mediated authorization
    /// path. Installed on the mediation kernel so a governed `MustPrepay`
    /// (x402/ACP) quote is authorized before a reserved nonce is minted. `None`
    /// by default, which keeps governed `MustPrepay` denied fail-closed: only a
    /// configured adapter enables prepayment.
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self {
            config,
            threshold_approval_collector: None,
            verified_manifest_registry: None,
            payment_adapter: None,
        }
    }

    /// Install the verified manifest registry used to admit tool-targeted
    /// HTTP requests in compatibility mode.
    #[must_use]
    pub fn with_verified_manifest_registry(
        mut self,
        registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Self {
        self.verified_manifest_registry = Some(registry);
        self
    }

    /// Inject the authenticated policy and request authority for threshold collection.
    ///
    /// The threshold routes remain unmounted unless this configuration is supplied.
    #[must_use]
    pub fn with_threshold_approval_collector(
        mut self,
        config: ThresholdApprovalCollectorConfig,
    ) -> Self {
        self.threshold_approval_collector = Some(config);
        self
    }

    /// Install the operator's payment adapter for the kernel-mediated route.
    ///
    /// The sidecar CLI resolves this from the operator's payment configuration
    /// and threads it here before `run`. With an adapter installed, an approved
    /// governed `MustPrepay`/x402 request authorizes (the quote is prepaid before
    /// a reserved nonce is minted); with `None` it stays denied fail-closed.
    #[must_use]
    pub fn with_payment_adapter(
        mut self,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    ) -> Self {
        self.payment_adapter = payment_adapter;
        self
    }

    async fn load_spec_content(&self) -> Result<String, ProtectError> {
        if let Some(spec_content) = &self.config.spec_content {
            return Ok(spec_content.clone());
        }
        if let Some(spec_path) = &self.config.spec_path {
            return load_spec_from_file(spec_path);
        }
        discover_spec(&self.config.upstream).await
    }

    /// Build the route table from the OpenAPI spec.
    /// Parses the spec directly to preserve path and method information.
    fn build_routes(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        let spec = chio_openapi::OpenApiSpec::parse(spec_content)?;
        let mut routes = Vec::new();

        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let method = match method_str.as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "PATCH" => HttpMethod::Patch,
                    "DELETE" => HttpMethod::Delete,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    _ => continue,
                };

                let extensions = ChioExtensions::from_operation(&operation.raw)?;
                let policy = DefaultPolicy::for_method_with_extensions(method, &extensions);
                routes.push(RouteEntry {
                    pattern: path.clone(),
                    method,
                    operation_id: operation.operation_id.clone(),
                    policy,
                });
            }
        }

        Ok(routes)
    }

    /// Start the proxy server. This blocks until the server shuts down.
    pub async fn run(self) -> Result<(), ProtectError> {
        self.run_with_observer(|_| {}).await
    }

    /// Start the proxy server, invoking `observer` once the listener is
    /// bound (with the resolved local `SocketAddr`).
    ///
    /// Used by `chio start` so the friendly banner can report the actual
    /// bound port when the operator passes `--listen 127.0.0.1:0`. The
    /// observer fires before `axum::serve` enters its accept loop, so
    /// callers can forward the address to stdout, write a sentinel file,
    /// or signal readiness over an out-of-band channel.
    pub async fn run_with_observer<F>(self, observer: F) -> Result<(), ProtectError>
    where
        F: FnOnce(SocketAddr),
    {
        // A local budget database enables durable direct mediation. Validate the
        // coordinator identity before resolving or opening any durable store: a
        // missing or malformed seed must not get far enough to run startup
        // recovery under a transient identity.
        validate_durable_mediation_signer(
            self.config.signer_seed_hex.as_deref(),
            self.config.budget_db.is_some(),
        )?;
        let keypair = match &self.config.signer_seed_hex {
            Some(seed_hex) => Keypair::from_seed_hex(seed_hex)
                .map_err(|error| ProtectError::Config(error.to_string()))?,
            None => Keypair::generate(),
        };
        let signer_public_key = keypair.public_key();
        let trusted_receipt_signers =
            trusted_receipt_signers_for_config(&self.config, &signer_public_key)?;

        // Durable-by-default: a missing receipt store means in-memory receipts
        // and revocations that are lost on every restart, so refuse to start
        // unless the embedder explicitly opted into ephemeral operation. This
        // mirrors the CLI boot gate for library callers that construct
        // `ProtectConfig` directly and would otherwise silently lose audit
        // evidence.
        //
        // An in-memory SQLite path (`:memory:` or a `file:...?mode=memory` URI)
        // opens a database that vanishes on restart just like a missing path, so
        // it is filtered out here. The gate and every store opened below key off
        // this durable path; treating an in-memory path as durable would open
        // in-memory stores yet advertise a durable receipt backend and silently
        // lose audit evidence.
        let durable_receipt_db = durable_receipt_database_path(self.config.receipt_db.as_deref())?;
        let prepared_revocation_store = prepare_revocation_store(
            self.config.revocation_db.as_deref(),
            durable_receipt_db.as_deref(),
        )?;
        let prepared_budget_store = prepare_budget_store(&self.config)?;
        validate_durable_database_topology(
            durable_receipt_db.as_deref(),
            prepared_revocation_store.durable_path(),
            prepared_budget_store.as_ref(),
        )?;
        let durable_receipt_db = durable_receipt_db.as_deref();

        if self.config.budget_db.is_some() && durable_receipt_db.is_none() {
            return Err(ProtectError::Config(
                "hold-capable mediation requires a durable authoritative receipt store".to_string(),
            ));
        }

        if durable_receipt_db.is_none() && !self.config.allow_ephemeral_receipts {
            return Err(ProtectError::Config(
                "refusing to start without a durable receipt store: set receipt_db to a durable \
                 SQLite path, or set allow_ephemeral_receipts to run with in-memory receipts that \
                 are lost on every restart"
                    .to_string(),
            ));
        }

        if durable_receipt_db.is_some() {
            chio_store_sqlite::SqliteAuthorityStore::ensure_serving_supported()
                .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        }

        let spec_content = self.load_spec_content().await?;
        let routes = Self::build_routes(&spec_content)?;
        let route_count = routes.len();

        let policy_hash = chio_core_types::sha256_hex(spec_content.as_bytes());

        // Consume the descriptor-bound revocation authority before another
        // durable database is mutated. A path substitution after preparation
        // therefore fails before it can redirect revocation state or partially
        // initialize a receipt, approval, budget, admission, or nonce authority.
        let (revocation_store, authoritative_revoked_capability_ids) =
            open_prepared_revocation_store(prepared_revocation_store)?;

        // Open the durable receipt store first so it owns the shared sidecar
        // file's provenance anchor; the approval store then co-locates onto that
        // file. Opening receipt-first fails closed on a path mistargeted at a
        // foreign approval database: it carries no receipt anchor, so the receipt
        // store refuses it here instead of adopting it and commingling receipt
        // tables into another store's file.
        let durable_receipt_store = match durable_receipt_db {
            Some(path) => Some(Arc::new(
                chio_store_sqlite::SqliteReceiptStore::open(path)
                    .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
            )),
            None => None,
        };
        let evaluator_receipt_store: Option<Arc<dyn chio_kernel::ReceiptStore>> =
            durable_receipt_store
                .as_ref()
                .map(|store| Arc::clone(store) as Arc<dyn chio_kernel::ReceiptStore>);
        let mediation_receipt_store = evaluator_receipt_store.clone();

        let approval_store: Arc<dyn ApprovalStore> =
            if let Some(receipt_store) = durable_receipt_store.as_ref() {
                Arc::new(
                    SqliteApprovalStore::open_colocated_with_receipt_store_handle(receipt_store)
                        .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?,
                )
            } else {
                Arc::new(InMemoryApprovalStore::new())
            };
        if self.threshold_approval_collector.is_some()
            && !approval_store
                .authority_profile()
                .supports_dispatch_workers(1)
        {
            return Err(ProtectError::Config(
                "threshold approval collection requires a durable approval store; configure receipt_db"
                    .to_string(),
            ));
        }

        let mut trusted_capability_issuers = self.config.trusted_capability_issuers.clone();
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }

        let evaluator = RequestEvaluator::new_with_durable_stores(
            routes,
            keypair.clone(),
            policy_hash,
            Arc::clone(&approval_store),
            self.config.trusted_capability_issuers.clone(),
            evaluator_receipt_store,
            revocation_store.clone(),
            self.config.allow_ephemeral_receipts,
        )
        .map_err(|error| ProtectError::Config(error.to_string()))?;
        let evaluator = match self.verified_manifest_registry {
            Some(registry) => evaluator.with_verified_manifest_registry(registry),
            None => evaluator,
        };
        let receipt_backend = evaluator.receipt_backend();
        let revocation_backend = evaluator.revocation_backend();

        let approval_admin = match self.threshold_approval_collector.as_ref() {
            Some(config) => ApprovalAdmin::new_with_threshold_policy(
                Arc::clone(&approval_store),
                config.current_policy_hash.clone(),
                config.trusted_policy_authorities.clone(),
                Arc::clone(&config.request_context_resolver),
            )
            .map_err(|error| {
                ProtectError::Config(format!(
                    "invalid threshold approval collector configuration: {error}"
                ))
            })?,
            None => ApprovalAdmin::new(Arc::clone(&approval_store)),
        };

        let (receipt_log, tool_receipt_log, receipt_store) =
            if let Some(receipt_anchor) = durable_receipt_store.as_ref() {
                let store = SqliteReceiptStore::open_bound(receipt_anchor)?;
                let receipts = store.load_receipts(&trusted_receipt_signers)?;
                let tool_receipts = store.load_tool_receipts(&trusted_receipt_signers)?;
                (
                    ReceiptLog { receipts },
                    ToolReceiptLog {
                        receipts: tool_receipts,
                    },
                    Some(Mutex::new(store)),
                )
            } else {
                (
                    ReceiptLog {
                        receipts: Vec::new(),
                    },
                    ToolReceiptLog {
                        receipts: Vec::new(),
                    },
                    None,
                )
            };
        let revoked_capability_ids = authoritative_revoked_capability_ids;

        if let Some(path) = self.config.revocation_db.as_deref() {
            let loaded = revoked_capability_ids.len();
            info!(
                revocation_db = path,
                loaded,
                "chio api protect: configured the live shared revocation authority; \
                 evaluator, mediation kernel, release route, and proxy checks \
                 observe writes made after startup"
            );
        }

        let egress_contract = default_upstream_egress_contract(&self.config.upstream)?;
        let http_client = client_builder_with_contract(&egress_contract)
            .timeout(self.config.upstream_request_timeout)
            .build()?;
        let configured_budget_store = open_prepared_budget_store(prepared_budget_store)?;
        let mediation_hold_capable = configured_budget_store
            .as_ref()
            .map(|configured| configured.hold_capable)
            .unwrap_or(false);
        let mediation_budget_path = configured_budget_store
            .as_ref()
            .and_then(|configured| configured.resolved_path.clone());
        let mediation_authority_directory = configured_budget_store
            .as_ref()
            .and_then(|configured| configured.authority_directory.clone());
        let mediation_admission_operation_path = configured_budget_store
            .as_ref()
            .and_then(|configured| configured.admission_operation_path.clone());
        let mediation_execution_nonce_path = configured_budget_store
            .as_ref()
            .and_then(|configured| configured.execution_nonce_path.clone());
        let budget_store = configured_budget_store.map(|configured| configured.store);

        if mediation_hold_capable && mediation_receipt_store.is_none() {
            return Err(ProtectError::Config(
                "hold-capable mediation requires a durable authoritative receipt store".to_string(),
            ));
        }

        // Build the kernel-mediation authority once, for the service lifetime, so
        // the approval-token and DPoP replay stores it carries stay authoritative
        // across `/v1/evaluate` requests and the nonce it mints is the one it
        // verifies and consumes on `/v1/reconcile`. It exists exactly when a
        // budget store is configured; without one, `/v1/evaluate` and
        // `/v1/reconcile` deny fail-closed.
        let mediation_admission_authorities = if mediation_hold_capable {
            if !approval_store
                .authority_profile()
                .supports_dispatch_workers(1)
            {
                return Err(ProtectError::Config(
                    "hold-capable mediation requires a durable admission authority".to_string(),
                ));
            }
            let budget_path = mediation_budget_path.as_deref().ok_or_else(|| {
                ProtectError::Config(
                    "hold-capable mediation requires a resolved local budget_db path".to_string(),
                )
            })?;
            let authority_directory = mediation_authority_directory.ok_or_else(|| {
                ProtectError::Config(
                    "hold-capable mediation requires a retained local budget_db parent descriptor"
                        .to_string(),
                )
            })?;
            let operation_path =
                mediation_admission_operation_path
                    .as_deref()
                    .ok_or_else(|| {
                        ProtectError::Config(
                            "hold-capable mediation requires a resolved admission-operation path"
                                .to_string(),
                        )
                    })?;
            let nonce_path = mediation_execution_nonce_path.as_deref().ok_or_else(|| {
                ProtectError::Config(
                    "hold-capable mediation requires a resolved execution-nonce path".to_string(),
                )
            })?;
            Some(build_mediation_admission_authorities_with_paths(
                budget_path,
                operation_path,
                nonce_path,
                authority_directory,
                Arc::clone(&approval_store),
                self.threshold_approval_collector.as_ref(),
            )?)
        } else {
            None
        };
        let payment_adapter = self.payment_adapter;
        let mediation_kernel = match budget_store.as_ref() {
            Some(store) => Some(Mutex::new(build_mediation_kernel(MediationKernelInputs {
                signer: &keypair,
                budget_store: Arc::clone(store),
                receipt_store: mediation_receipt_store,
                revocation_store: revocation_store.clone(),
                trusted_capability_issuers: &trusted_capability_issuers,
                tool_servers: Vec::new(),
                payment_adapter,
                admission_authorities: mediation_admission_authorities,
            })?)),
            None => None,
        };

        // Validate and recover every operation-owned admission before touching
        // the legacy no-payment recovery lane. A signer rotation with unresolved
        // operations fails while those operations and every unstamped legacy hold
        // are still unchanged, instead of partially mutating the budget database
        // before discovering that the original coordinator is unavailable.
        //
        // Automatic reconcile/reverse of other open holds still requires the
        // durable receipt log (ADR-0013) to build a realized-spend arbitration
        // map. Without that map, they remain reserved fail-closed.
        if let Some(store) = budget_store.as_ref() {
            let recovered = store
                .recover_unstamped_caller_reservations()
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "failed to recover unstamped caller reservations: {error}"
                    ))
                })?;
            if recovered > 0 {
                warn!(
                    recovered,
                    "startup: reversed caller reservation(s) interrupted before nonce TTL stamp"
                );
            }
            match store.count_open_holds() {
                Ok(0) => {}
                Ok(count) => {
                    warn!(
                        count,
                        "startup: open budget hold(s) left reserved pending \
                         receipt-log arbitration; automatic reconcile requires \
                         the durable receipt log (ADR-0013) arbitration map"
                    );
                }
                Err(error) => {
                    warn!("startup: failed to count open budget holds: {error}");
                }
            }
        }

        let state = Arc::new(ProxyState {
            evaluator,
            signer_keypair: keypair,
            upstream: self.config.upstream.clone(),
            http_client,
            egress_contract,
            approval_admin,
            receipt_log: Mutex::new(receipt_log),
            tool_receipt_log: Mutex::new(tool_receipt_log),
            receipt_store,
            revocation_store,
            revoked_capability_ids: Mutex::new(revoked_capability_ids),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token: self.config.sidecar_control_token.clone(),
            budget_store,
            mediation_hold_capable,
            mediation_kernel,
            reaper_handle: Mutex::new(None),
            allow_advisory: self.config.allow_advisory,
            receipt_backend,
            revocation_backend,
        });

        // Release expired, unreconciled reserved budget holds on an interval so a
        // caller that authorizes but never reconciles does not permanently burn
        // budget. The reaper's JoinHandle is retained on the shared state and
        // aborted once the server stops accepting (below), bounding the worker's
        // lifetime to the server's.
        spawn_reserved_hold_reaper(&state).await;

        let app = build_app(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                ProtectError::Config(format!("cannot bind {}: {e}", self.config.listen_addr))
            })?;

        let local_addr = listener.local_addr().map_err(|error| {
            ProtectError::Config(format!("cannot resolve bound address: {error}"))
        })?;

        info!(
            has_budget_store = state.budget_store.is_some(),
            "chio api protect: mediation layer ready"
        );
        info!(
            "chio api protect: proxying {} routes to {} on {}",
            route_count, self.config.upstream, local_addr
        );

        observer(local_addr);

        // No generic request timeout: every proxied call writes its receipt
        // synchronously in the handler after the upstream hop returns, and that
        // hop is already bounded by the configured upstream timeout. An outer
        // timeout layer would drop the handler while it awaits the upstream,
        // skipping receipt finalization for a call that may already have reached
        // the upstream. The drain window is held a margin above that upstream
        // ceiling so an in-flight hop is receipted before a forced drain closes
        // it. Body size, concurrency, and the connection cap still apply.
        let hygiene = ServeHygieneConfig {
            request_timeout: None,
            drain_timeout: proxy_drain_timeout(self.config.upstream_request_timeout),
            ..ServeHygieneConfig::default()
        };
        let app = apply_server_hygiene(app, &hygiene);
        let controller = ShutdownController::install();
        // Cap simultaneously accepted connections at the accept loop so a slow or
        // idle connection flood cannot exhaust file descriptors before any request
        // reaches the concurrency limit. The peer address stays available to the
        // sidecar-control loopback/bearer checks via `CappedPeerAddr`.
        let listener =
            MaxConnListener::new(listener, hygiene.max_connections.unwrap_or(usize::MAX));
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<CappedPeerAddr>(),
        )
        .with_graceful_shutdown(controller.signalled());

        // Every proxied call writes its receipt synchronously inside the request
        // handler, so completing the in-flight requests during the drain is the
        // whole durability guarantee: there is nothing queued to flush afterward.
        let serve_result = run_until_drained(
            server,
            controller.subscribe(),
            hygiene.drain_timeout,
            async { Ok::<(), String>(()) },
        )
        .await
        .map(|_outcome| ())
        .map_err(protect_serve_error);

        // The reaper holds a clone of the shared state; abort it now the server
        // has stopped so the worker does not outlive the serving lifetime (a
        // dropped JoinHandle would only detach it, leaving it running).
        if let Some(handle) = state.reaper_handle.lock().await.take() {
            handle.abort();
        }

        serve_result?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

#[cfg(test)]
mod proxy_builder_tests {
    use super::*;

    fn minimal_config() -> ProtectConfig {
        ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            allow_ephemeral_receipts: true,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            trusted_historical_receipt_signers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        }
    }

    #[test]
    fn with_payment_adapter_threads_adapter_and_defaults_none() {
        // The sidecar CLI threads the operator's resolved payment adapter here so
        // the proxy installs it on the mediation kernel and governed MustPrepay
        // can be prepaid. Absent the builder call the adapter defaults to `None`,
        // which keeps governed MustPrepay denied fail-closed.
        let default = ProtectProxy::new(minimal_config());
        assert!(
            default.payment_adapter.is_none(),
            "a proxy defaults to no payment adapter, keeping governed MustPrepay denied"
        );

        let configured = ProtectProxy::new(minimal_config())
            .with_payment_adapter(Some(Box::new(chio_kernel::SimPaymentAdapter::new())));
        assert!(
            configured.payment_adapter.is_some(),
            "with_payment_adapter must thread the configured adapter into the proxy"
        );
    }

    #[test]
    fn durable_mediation_requires_restart_stable_signer_seed() {
        let error = validate_durable_mediation_signer(None, true).unwrap_err();
        assert!(error.to_string().contains("signer_seed_hex"));
        validate_durable_mediation_signer(Some(&"11".repeat(32)), true).unwrap();
        validate_durable_mediation_signer(None, false).unwrap();
    }

    #[test]
    fn historical_receipt_trust_is_opt_in_and_never_inferred_from_storage() {
        let current_signer = Keypair::generate().public_key();
        let historical_signer = Keypair::generate().public_key();
        let mut config = minimal_config();

        assert_eq!(
            trusted_receipt_signers_for_config(&config, &current_signer).unwrap(),
            vec![current_signer.clone()]
        );

        config
            .trusted_historical_receipt_signers
            .push(historical_signer.clone());
        assert_eq!(
            trusted_receipt_signers_for_config(&config, &current_signer).unwrap(),
            vec![current_signer, historical_signer]
        );
    }

    #[tokio::test]
    async fn durable_mediation_signer_gate_precedes_every_store_open() {
        for signer_seed_hex in [None, Some("malformed-seed".to_string())] {
            let directory = tempfile::tempdir().unwrap();
            let budget_db = directory.path().join("budget.db");
            let receipt_db = directory.path().join("receipts.db");
            let mut config = minimal_config();
            config.allow_ephemeral_receipts = false;
            config.budget_db = Some(budget_db.to_string_lossy().into_owned());
            config.receipt_db = Some(receipt_db.to_string_lossy().into_owned());
            config.signer_seed_hex = signer_seed_hex;

            let error = ProtectProxy::new(config)
                .run_with_observer(|_| panic!("signer gate must run before listener bind"))
                .await
                .unwrap_err();
            assert!(matches!(error, ProtectError::Config(_)));
            assert!(
                !budget_db.exists(),
                "invalid durable signer configuration must not open the budget store"
            );
            assert!(
                !receipt_db.exists(),
                "invalid durable signer configuration must not open the receipt store"
            );
            assert!(
                !std::path::Path::new(&format!(
                    "{}.admission-operations",
                    budget_db.to_string_lossy()
                ))
                .exists(),
                "invalid durable signer configuration must not open operation authority"
            );
        }
    }
}

#[cfg(all(test, windows))]
mod windows_authority_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn durable_startup_rejects_windows_before_api_protect_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let state_parent = directory.path().join("state");
        let receipt_database = state_parent.join("receipts.sqlite3");
        let receipt_database_string = receipt_database.to_string_lossy().into_owned();
        let (authority_database, authority_lock_root) =
            authority_sibling_paths(&receipt_database_string);
        let missing_spec = directory.path().join("missing-openapi.json");
        let observer_called = AtomicBool::new(false);

        let result = ProtectProxy::new(ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: None,
            spec_path: Some(missing_spec.to_string_lossy().into_owned()),
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: Some(receipt_database_string),
            allow_ephemeral_receipts: false,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        })
        .run_with_observer(|_| observer_called.store(true, Ordering::SeqCst))
        .await;

        let error = match result {
            Ok(()) => {
                return Err(std::io::Error::other(
                    "Windows durable API-protect startup unexpectedly succeeded",
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(
                &error,
                ProtectError::ReceiptStore(message)
                    if message.contains(
                        "sqlite authority serving requires Unix file identity and positioned I/O"
                    )
            ),
            "the platform preflight must fail before attempting to load the missing spec: {error}"
        );
        assert!(!observer_called.load(Ordering::SeqCst));
        assert!(!state_parent.exists());
        assert!(!receipt_database.exists());
        assert!(!authority_database.exists());
        assert!(!authority_lock_root.exists());
        Ok(())
    }
}

fn protect_serve_error(error: ServeError) -> ProtectError {
    match error {
        ServeError::Io(source) => ProtectError::Io(source),
        ServeError::Flush(message) => ProtectError::Io(std::io::Error::other(message)),
    }
}

#[cfg(test)]
mod durability_tests {
    use super::{durable_receipt_database_path, revocation_sibling_path, SqliteReceiptStore};
    use chio_test_support::prelude::*;

    #[test]
    fn revocation_sibling_path_appends_suffix_to_a_plain_path() {
        assert_eq!(
            revocation_sibling_path("/var/lib/chio/receipts.db"),
            "/var/lib/chio/receipts.db.revocations"
        );
    }

    #[test]
    fn durable_receipt_database_path_normalizes_relative_plain_paths() {
        let resolved = durable_receipt_database_path(Some("receipts.db"))
            .test_unwrap()
            .test_unwrap();
        let expected = std::fs::canonicalize(std::env::current_dir().test_unwrap())
            .test_unwrap()
            .join("receipts.db")
            .into_os_string()
            .into_string()
            .test_unwrap();
        assert_eq!(resolved, expected);
    }

    #[test]
    fn durable_receipt_database_path_filters_volatile_paths_and_rejects_file_uris() {
        assert!(durable_receipt_database_path(None).test_unwrap().is_none());
        for path in [":memory:", "file:receipts.db?mode=memory"] {
            assert!(
                durable_receipt_database_path(Some(path))
                    .test_unwrap()
                    .is_none(),
                "{path} must stay on the opted-in ephemeral path"
            );
        }
        let error = durable_receipt_database_path(Some("file:/var/lib/chio/receipts.db?mode=rwc"))
            .test_unwrap_err();
        assert!(error.to_string().contains("plain filesystem path"));
    }

    #[test]
    fn http_receipt_store_open_configures_wal_and_a_busy_timeout() {
        let path = chio_test_support::private_fs::unique_sqlite_path("chio-http-receipts");
        let path_str = path.to_string_lossy().into_owned();

        let store = SqliteReceiptStore::open(&path_str).test_unwrap();

        let busy_timeout: i64 = store
            .connection
            .validated_connection()
            .test_unwrap()
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            busy_timeout >= 5000,
            "the http receipt writer must share the receipt store busy timeout, got {busy_timeout}"
        );

        let journal_mode: String = store
            .connection
            .validated_connection()
            .test_unwrap()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            journal_mode.eq_ignore_ascii_case("wal"),
            "the http receipt writer must run in WAL mode, got {journal_mode}"
        );

        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod receipt_persistence_security_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn signed_http_receipt(signer: &Keypair, request_id: &str) -> HttpReceipt {
        HttpReceipt::sign(
            HttpReceiptBody {
                id: "computed-by-signer".to_string(),
                request_id: request_id.to_string(),
                route_pattern: "/security-test".to_string(),
                method: HttpMethod::Post,
                caller_identity_hash: chio_core_types::sha256_hex(b"test-caller"),
                session_id: None,
                verdict: Verdict::Allow,
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                evidence: Vec::new(),
                response_status: 200,
                timestamp: 1_700_000_000,
                content_hash: chio_core_types::sha256_hex(b"test-content"),
                policy_hash: chio_core_types::sha256_hex(b"test-policy"),
                trust_level: TrustLevel::Mediated,
                capability_id: Some("cap-security-test".to_string()),
                metadata: None,
                kernel_key: signer.public_key(),
            },
            signer,
        )
        .test_unwrap()
    }

    fn signed_tool_receipt(signer: &Keypair, tool_name: &str) -> ChioReceipt {
        let parameters = serde_json::json!({"path": "/tmp/security-test"});
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "computed-by-signer".to_string(),
                timestamp: 1_700_000_000,
                capability_id: "cap-security-test".to_string(),
                tool_server: "fs".to_string(),
                tool_name: tool_name.to_string(),
                action: ToolCallAction::from_parameters(parameters).test_unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: chio_core_types::sha256_hex(b"test-tool-content"),
                policy_hash: chio_core_types::sha256_hex(b"test-tool-policy"),
                evidence: Vec::new(),
                metadata: None,
                trust_level: TrustLevel::Mediated,
                tenant_id: None,
                kernel_key: signer.public_key(),
                bbs_projection_version: None,
            },
            signer,
        )
        .test_unwrap()
    }

    fn open_store(directory: &std::path::Path) -> SqliteReceiptStore {
        let path = directory.join("receipts.sqlite3");
        SqliteReceiptStore::open(&path.to_string_lossy()).test_unwrap()
    }

    #[test]
    fn receipt_append_is_exactly_idempotent_and_never_overwrites_existing_bytes() {
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-receipt-idempotence-")
                .test_unwrap();
        let signer = Keypair::generate();
        let mut store = open_store(directory.path());

        let http_receipt = signed_http_receipt(&signer, "req-original");
        let http_json = canonical_receipt_json(&http_receipt).test_unwrap();
        store.append(&http_receipt).test_unwrap();
        store.append(&http_receipt).test_unwrap();

        let mut conflicting_http_receipt = http_receipt.clone();
        conflicting_http_receipt.request_id = "req-conflicting".to_string();
        let conflicting_http_json = canonical_receipt_json(&conflicting_http_receipt).test_unwrap();
        let error = append_exact_receipt(
            store.validated_connection().test_unwrap(),
            "http_receipts",
            &http_receipt.id,
            &conflicting_http_json,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("different canonical bytes"));
        let persisted_http_json: String = store
            .validated_connection()
            .test_unwrap()
            .query_row(
                "SELECT receipt_json FROM http_receipts WHERE id = ?1",
                params![http_receipt.id],
                |row| row.get(0),
            )
            .test_unwrap();
        assert_eq!(persisted_http_json, http_json);
        let http_rows: i64 = store
            .validated_connection()
            .test_unwrap()
            .query_row("SELECT COUNT(*) FROM http_receipts", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(http_rows, 1);

        let tool_receipt = signed_tool_receipt(&signer, "read");
        let tool_json = canonical_receipt_json(&tool_receipt).test_unwrap();
        store.append_tool_receipt(&tool_receipt).test_unwrap();
        store.append_tool_receipt(&tool_receipt).test_unwrap();

        let mut conflicting_tool_receipt = tool_receipt.clone();
        conflicting_tool_receipt.tool_name = "write".to_string();
        let conflicting_tool_json = canonical_receipt_json(&conflicting_tool_receipt).test_unwrap();
        let error = append_exact_receipt(
            store.validated_connection().test_unwrap(),
            "tool_receipts",
            &tool_receipt.id,
            &conflicting_tool_json,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("different canonical bytes"));
        let persisted_tool_json: String = store
            .validated_connection()
            .test_unwrap()
            .query_row(
                "SELECT receipt_json FROM tool_receipts WHERE id = ?1",
                params![tool_receipt.id],
                |row| row.get(0),
            )
            .test_unwrap();
        assert_eq!(persisted_tool_json, tool_json);
        let tool_rows: i64 = store
            .validated_connection()
            .test_unwrap()
            .query_row("SELECT COUNT(*) FROM tool_receipts", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(tool_rows, 1);
    }

    #[test]
    fn historical_receipt_signers_require_explicit_trust_and_corruption_still_fails_closed() {
        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-historical-receipts-")
                .test_unwrap();
        let current_signer = Keypair::generate();
        let historical_signer = Keypair::generate();
        let mut store = open_store(directory.path());

        let historical_receipt = signed_http_receipt(&historical_signer, "req-historical");
        let historical_tool_receipt = signed_tool_receipt(&historical_signer, "read-historical");
        store.append(&historical_receipt).test_unwrap();
        store
            .append_tool_receipt(&historical_tool_receipt)
            .test_unwrap();

        let current_only = [current_signer.public_key()];
        let error = store.load_receipts(&current_only).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("signer, or signature validation"));
        let error = store.load_tool_receipts(&current_only).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("signer, or signature validation"));

        let explicitly_trusted = [current_signer.public_key(), historical_signer.public_key()];
        let loaded = store.load_receipts(&explicitly_trusted).test_unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, historical_receipt.id);
        let loaded = store.load_tool_receipts(&explicitly_trusted).test_unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, historical_tool_receipt.id);

        let mut corrupted_historical_receipt =
            signed_http_receipt(&historical_signer, "req-corrupted-historical");
        corrupted_historical_receipt.request_id = "tampered-after-signing".to_string();
        let corrupted_json = canonical_receipt_json(&corrupted_historical_receipt).test_unwrap();
        append_exact_receipt(
            store.validated_connection().test_unwrap(),
            "http_receipts",
            &corrupted_historical_receipt.id,
            &corrupted_json,
        )
        .test_unwrap();
        let mut corrupted_historical_tool_receipt =
            signed_tool_receipt(&historical_signer, "delete-historical");
        corrupted_historical_tool_receipt.tool_name = "tampered-after-signing".to_string();
        let corrupted_tool_json =
            canonical_receipt_json(&corrupted_historical_tool_receipt).test_unwrap();
        append_exact_receipt(
            store.validated_connection().test_unwrap(),
            "tool_receipts",
            &corrupted_historical_tool_receipt.id,
            &corrupted_tool_json,
        )
        .test_unwrap();

        let error = store.load_receipts(&explicitly_trusted).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("signer, or signature validation"));
        let error = store
            .load_tool_receipts(&explicitly_trusted)
            .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("signer, or signature validation"));
    }

    #[test]
    fn direct_api_receipt_writes_are_revoked_by_platform_store_close() {
        let directory = chio_test_support::private_fs::private_tempdir("api-protect-bound-close-")
            .test_unwrap();
        let path = directory.path().join("receipts.sqlite3");
        let platform_store = chio_store_sqlite::SqliteReceiptStore::open(&path).test_unwrap();
        let mut api_store = SqliteReceiptStore::open_bound(&platform_store).test_unwrap();
        let signer = Keypair::generate();
        let receipt = signed_http_receipt(&signer, "req-before-close");
        api_store.append(&receipt).test_unwrap();

        platform_store.close().test_unwrap();

        let error = api_store.append(&receipt).test_unwrap_err();
        assert!(
            error.to_string().contains("revoked by store close"),
            "unexpected post-close API receipt error: {error}"
        );
        directory.close().test_unwrap();
        drop(api_store);
    }

    #[cfg(unix)]
    #[test]
    fn api_receipt_store_rejects_path_rebinding_on_existing_and_new_bound_connections() {
        use std::os::unix::fs::OpenOptionsExt;

        let directory =
            chio_test_support::private_fs::private_tempdir("api-protect-receipt-rebinding-")
                .test_unwrap();
        let directory = std::fs::canonicalize(directory.path()).test_unwrap();
        let path = directory.join("receipts.sqlite3");
        let displaced = directory.join("receipts-displaced.sqlite3");
        let replacement = directory.join("receipts-replacement.sqlite3");
        let platform_store = chio_store_sqlite::SqliteReceiptStore::open(&path).test_unwrap();
        let api_store = SqliteReceiptStore::open_bound(&platform_store).test_unwrap();
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&replacement)
            .test_unwrap();

        std::fs::rename(&path, &displaced).test_unwrap();
        std::fs::rename(&replacement, &path).test_unwrap();

        let existing_error = api_store.validated_connection().err().test_unwrap();
        assert!(existing_error
            .to_string()
            .contains("descriptor identity changed"));
        let new_error = SqliteReceiptStore::open_bound(&platform_store)
            .err()
            .test_unwrap();
        assert!(new_error
            .to_string()
            .contains("descriptor identity changed"));
        assert_eq!(
            std::fs::metadata(&path).test_unwrap().len(),
            0,
            "the replacement file must not be mutated before identity validation"
        );

        std::fs::rename(&path, &replacement).test_unwrap();
        std::fs::rename(&displaced, &path).test_unwrap();
        drop(api_store);
        drop(platform_store);
    }
}

#[cfg(test)]
mod tests {
    use super::{proxy_drain_timeout, PROXY_DRAIN_MARGIN};
    use crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT;
    use chio_http_serve::DEFAULT_DRAIN_TIMEOUT;
    use std::time::Duration;

    /// The drain window must always outlast the upstream hop ceiling so a hop that
    /// is still in flight at shutdown resolves and records its receipt before the
    /// forced drain closes the connection. This must hold for any configured
    /// timeout, including values raised above the default drain window.
    #[test]
    fn drain_window_always_outlasts_the_configured_upstream_timeout() {
        for secs in [1u64, 20, 30, 60, 300] {
            let upstream = Duration::from_secs(secs);
            assert!(
                proxy_drain_timeout(upstream) > upstream,
                "drain window must outlast a {secs}s upstream timeout"
            );
            assert_eq!(proxy_drain_timeout(upstream), upstream + PROXY_DRAIN_MARGIN);
        }
    }

    /// The default configuration keeps the historical 20s hop / 25s drain pairing,
    /// so making the timeout configurable does not shift default behavior.
    #[test]
    fn default_upstream_timeout_preserves_the_default_drain_window() {
        assert_eq!(
            proxy_drain_timeout(DEFAULT_UPSTREAM_REQUEST_TIMEOUT),
            DEFAULT_DRAIN_TIMEOUT
        );
    }
}
