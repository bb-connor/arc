//! Bounds before any checkpoint, projection or membership decoder allocates.
use super::*;

pub(super) struct SessionSqlWork {
    remaining: Arc<AtomicU64>,
    pub(super) exhausted: Arc<AtomicBool>,
}

impl SessionSqlWork {
    pub(super) fn new(steps: u64) -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(steps)),
            exhausted: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn install(&self, connection: &Connection) -> Result<(), ReceiptStoreError> {
        let remaining = Arc::clone(&self.remaining);
        let exhausted = Arc::clone(&self.exhausted);
        let interval = u64::try_from(SQL_PROGRESS_INTERVAL)
            .map_err(|_| boundary("invalid session SQL progress interval"))?;
        // This reader owns and drops both connections. The same counter spans
        // preflight, archive authentication, projections and final collection.
        connection.progress_handler(
            SQL_PROGRESS_INTERVAL,
            Some(move || {
                let before = remaining
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        Some(value.saturating_sub(interval))
                    })
                    .unwrap_or(0);
                let stop = before <= interval;
                if stop {
                    exhausted.store(true, Ordering::Relaxed);
                }
                stop
            }),
        )?;
        Ok(())
    }
}

pub(super) struct SessionPreflight<'a> {
    pub(super) rows: usize,
    pub(super) bytes: usize,
    pub(super) session: SessionBudget,
    pub(super) session_id: &'a str,
    pub(super) tenant: Option<&'a str>,
}

impl SessionPreflight<'_> {
    pub(super) fn inspect(
        &mut self,
        connection: &Connection,
        upper: u64,
    ) -> Result<(), ReceiptStoreError> {
        let live = upper == i64::MAX.unsigned_abs();
        for (table, kind) in [
            ("chio_tool_receipts", "tool_receipt"),
            ("chio_child_receipts", "child_receipt"),
        ] {
            let query = if live {
                format!("SELECT * FROM {table} WHERE ?1 >= 0")
            } else {
                // Uncommitted copied archive tails are outside this snapshot.
                format!(
                    "SELECT r.* FROM {table} r WHERE EXISTS
                (SELECT 1 FROM claim_receipt_log_entries e WHERE e.receipt_kind = '{kind}'
                 AND e.source_seq = r.seq AND e.entry_seq <= ?1)"
                )
            };
            self.table(connection, &query, upper, false)?;
        }
        self.table(
            connection,
            "SELECT * FROM claim_receipt_log_entries WHERE entry_seq <= ?1",
            upper,
            true,
        )?;
        for table in [
            "kernel_checkpoints",
            "capability_lineage",
            "checkpoint_tree_heads",
            "checkpoint_predecessor_witnesses",
            "checkpoint_publication_metadata",
            "checkpoint_publication_trust_anchor_bindings",
        ] {
            self.table(
                connection,
                &format!("SELECT * FROM {table} WHERE ?1 >= 0"),
                upper,
                false,
            )?;
        }
        if live {
            self.table(
                connection,
                "SELECT * FROM receipt_retention_watermark WHERE ?1 >= 0",
                upper,
                false,
            )?;
        }
        Ok(())
    }

    fn table(
        &mut self,
        connection: &Connection,
        query: &str,
        upper: u64,
        claims: bool,
    ) -> Result<(), ReceiptStoreError> {
        let mut statement = connection.prepare(query)?;
        let mut rows = statement.query([sqlite_i64(upper, "preflight claim bound")?])?;
        while let Some(row) = rows.next()? {
            self.rows = self
                .rows
                .checked_sub(1)
                .ok_or_else(|| boundary("session authentication row limit exceeded"))?;
            for column in 0..row.as_ref().column_count() {
                let value = row.get_ref(column)?;
                let bytes = match value {
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes,
                    _ => continue,
                };
                let raw_json = row.as_ref().column_name(column)? == "raw_json";
                let maximum = if raw_json {
                    MAX_MEMBERSHIP_BYTES
                } else {
                    MAX_PROJECTION_BYTES
                };
                if bytes.len() > maximum {
                    return Err(boundary(
                        "session authentication source byte limit exceeded",
                    ));
                }
                self.bytes = self
                    .bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| boundary("session authentication byte limit exceeded"))?;
                if raw_json {
                    let raw = bounded_text(value, maximum)?;
                    bound_json_nodes(raw)?;
                }
            }
            if claims
                && bounded_text(row.get_ref("receipt_kind")?, MAX_PROJECTION_BYTES)?
                    == "tool_receipt"
            {
                let raw = bounded_text(row.get_ref("raw_json")?, MAX_MEMBERSHIP_BYTES)?;
                let value: serde_json::Value =
                    chio_core::canonical::UntrustedJsonText::new(raw).decode_signed()?;
                let root = value
                    .as_object()
                    .ok_or_else(|| boundary("retained receipt membership must be an object"))?;
                // Original bytes remain available: the selected 1 MiB/session
                // budgets are charged before any typed receipt/signature decoder.
                let member = signed_membership(root.get("metadata"))?;
                let tenant = match root.get("tenant_id") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_str()
                            .ok_or_else(|| boundary("signed receipt tenant must be text"))?,
                    ),
                };
                if member == Some(self.session_id)
                    && self.tenant.is_none_or(|expected| tenant == Some(expected))
                {
                    self.session.charge(raw.len())?;
                }
            }
        }
        Ok(())
    }
}

fn bound_json_nodes(raw: &str) -> Result<(), ReceiptStoreError> {
    let mut remaining = MAX_MEMBERSHIP_NODES;
    let mut in_string = false;
    let mut escaped = false;
    // Separators and container starts conservatively bound tree allocations.
    // Strict parsing subsequently checks syntax, duplicates and number tokens.
    for byte in raw.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if matches!(byte, b'{' | b'[' | b',' | b':') {
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| boundary("session membership structure limit exceeded"))?;
        }
    }
    Ok(())
}
