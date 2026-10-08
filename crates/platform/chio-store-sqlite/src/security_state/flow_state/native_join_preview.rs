//! Read-only row images for the exact closed native monotone join.
use super::*;
use crate::security_state::{
    encode_retained_security_values, retained_security_columns, NativeRowChange,
};
use rusqlite::types::{Value, ValueRef};
use rusqlite::{params_from_iter, ToSql};
use std::collections::BTreeMap;

const MAX_CHANGES: usize = 4096;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

/// Proposed row images are data. The source owner separately authenticates its
/// actual transaction, initialization, binding and original join before pricing.
pub(crate) struct NativeFlowJoinPreview {
    request: FlowJoinRequest,
    result: FlowStateSnapshot,
    changes: Vec<NativeRowChange>,
}

impl NativeFlowJoinPreview {
    pub(crate) fn result(&self) -> &FlowStateSnapshot {
        &self.result
    }

    pub(crate) fn changes(&self) -> &[NativeRowChange] {
        &self.changes
    }

    pub(crate) fn verify_actual(
        &self,
        result: &FlowStateSnapshot,
        actual: &[NativeRowChange],
    ) -> PortResult<()> {
        if result != &self.result || actual.len() != self.changes.len() {
            return Err(PortError::integrity_failure());
        }
        // SQLite does not promise UPDATE callback order. Preserve every exact
        // before/after image and multiplicity, including overlapping context
        // invalidations, without inventing an order for independent rows.
        fn sort(changes: &[NativeRowChange]) -> Vec<(&String, &Option<String>, &Option<String>)> {
            let mut rows = changes
                .iter()
                .map(|change| (&change.table, &change.before, &change.after))
                .collect::<Vec<_>>();
            rows.sort_unstable();
            rows
        }
        for change in actual {
            change.validate_flow_join(&self.request)?;
        }
        if sort(actual) != sort(&self.changes) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}

/// This performs no write and enables no native mutation callback.
pub(crate) fn preview_native_flow_join(
    connection: &Connection,
    authority: &str,
    request: &FlowJoinRequest,
) -> PortResult<NativeFlowJoinPreview> {
    let reader = FlowReader::native(connection, authority);
    let request_hash = canonical_request_hash(request)?;
    if scoped_transition_status(
        reader,
        request.key.tenant_id.as_str(),
        request.transition_id.as_str(),
        "flow_join",
        &request_hash,
    )? {
        // A retained replay cannot supply a fresh journal or financing source.
        return Err(PortError::conflict());
    }
    let mut rows = PlannedRows::new(connection, authority, request);
    rows.prepare_epoch()?;
    let principal_stored = load_principal_label(reader, &request.key)?;
    let lineage_stored = load_lineage_label(reader, &request.key)?;
    let session_stored = load_session_label(reader, &request.key)?;
    let membership = session_membership_exists(reader, &request.key)?;
    let context = load_context_generation(reader, &request.key)?;
    if session_stored.is_some() != membership
        || context.is_some()
            && (principal_stored.is_none() || lineage_stored.is_none() || session_stored.is_none())
    {
        return Err(PortError::integrity_failure());
    }
    let principal_current = principal_stored
        .as_ref()
        .map(|value| value.0.clone())
        .unwrap_or_else(InformationLabel::bottom);
    let lineage_current = lineage_stored
        .as_ref()
        .map(|value| value.0.clone())
        .unwrap_or_else(InformationLabel::bottom);
    let session_current = match &session_stored {
        Some(value) => value.0.clone(),
        None => principal_current
            .join_restrictions(&lineage_current)
            .map_err(|_| PortError::invalid_data())?,
    };
    let principal = principal_current
        .join_restrictions(&request.principal_join)
        .map_err(|_| PortError::invalid_data())?;
    let lineage = lineage_current
        .join_restrictions(&request.lineage_join)
        .map_err(|_| PortError::invalid_data())?;
    let session = session_current
        .join_restrictions(&request.session_join)
        .and_then(|label| label.join_restrictions(&principal))
        .and_then(|label| label.join_restrictions(&lineage))
        .map_err(|_| PortError::invalid_data())?;
    let sequence: Option<i64> = reader
        .query_row(
            sql::LOAD_SEQUENCE,
            params![request.key.tenant_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let highest: Option<i64> = reader
        .query_row(
            sql::MAX_GENERATION,
            params![request.key.tenant_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let generation = sequence
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(highest.map(from_i64).transpose()?.unwrap_or(0))
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    let next = to_i64(generation)?;
    let tenant = request.key.tenant_id.as_str();
    let sequence_before = rows.one("security_flow_sequences", "tenant_id=?2", &[&tenant])?;
    rows.push(
        "security_flow_sequences",
        sequence_before,
        vec![Value::Text(tenant.into()), Value::Integer(next)],
    )?;
    rows.invalidate_contexts(
        next,
        principal != principal_current,
        lineage != lineage_current,
        session != session_current,
    )?;
    if principal_stored.is_none() || principal != principal_current {
        rows.store_label("security_principal_flow_state", &principal, next)?;
    }
    if lineage_stored.is_none() || lineage != lineage_current {
        rows.store_label("security_lineage_flow_state", &lineage, next)?;
    }
    if session_stored.is_none() || session != session_current {
        if !membership {
            rows.push(
                "security_session_memberships",
                None,
                rows.session_identity(),
            )?;
        }
        rows.store_label("security_session_flow_state", &session, next)?;
    }
    rows.store_context(next)?;
    rows.push(
        "security_transitions",
        None,
        vec![
            Value::Text(request.transition_id.as_str().into()),
            Value::Text(tenant.into()),
            Value::Text("flow_join".into()),
            Value::Blob(request_hash.to_vec()),
        ],
    )?;
    Ok(NativeFlowJoinPreview {
        request: request.clone(),
        result: FlowStateSnapshot {
            key: request.key.clone(),
            principal_label: principal,
            lineage_label: lineage,
            session_label: session,
            context_generation: generation,
        },
        changes: rows.changes,
    })
}

struct PlannedRows<'a> {
    connection: &'a Connection,
    authority: &'a str,
    request: &'a FlowJoinRequest,
    changes: Vec<NativeRowChange>,
    image_bytes: usize,
    contexts: BTreeMap<String, Vec<Value>>,
}

impl<'a> PlannedRows<'a> {
    fn new(connection: &'a Connection, authority: &'a str, request: &'a FlowJoinRequest) -> Self {
        Self {
            connection,
            authority,
            request,
            changes: Vec::new(),
            image_bytes: 0,
            contexts: BTreeMap::new(),
        }
    }

    fn read(
        &self,
        table: &str,
        predicate: &str,
        parameters: &[&dyn ToSql],
    ) -> PortResult<Vec<Vec<Value>>> {
        self.read_bounded(table, predicate, parameters, MAX_CHANGES + 1)
    }

    fn read_bounded(
        &self,
        table: &str,
        predicate: &str,
        parameters: &[&dyn ToSql],
        limit: usize,
    ) -> PortResult<Vec<Vec<Value>>> {
        if !crate::security_state::is_native_flow_join_table(table) {
            return Err(PortError::integrity_failure());
        }
        let columns =
            retained_security_columns(table).map_err(|_| PortError::integrity_failure())?;
        let names = columns.join(",");
        let suffix = table
            .strip_prefix("security_")
            .ok_or_else(PortError::integrity_failure)?;
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT {names} FROM security_participant_state_{suffix}
             WHERE security_authority_id=?1 AND ({predicate}) ORDER BY {names} LIMIT {limit}"
            ))
            .map_err(sqlite_error)?;
        if !statement.readonly() {
            return Err(PortError::integrity_failure());
        }
        let mut cursor = statement
            .query(params_from_iter(
                [&self.authority as &dyn ToSql]
                    .into_iter()
                    .chain(parameters.iter().copied()),
            ))
            .map_err(sqlite_error)?;
        let mut values = Vec::new();
        while let Some(row) = cursor.next().map_err(sqlite_error)? {
            if values.len() == MAX_CHANGES {
                return Err(PortError::invalid_data());
            }
            values.push(
                (0..columns.len())
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<Value>>>()
                    .map_err(sqlite_error)?,
            );
        }
        Ok(values)
    }

    fn one(
        &self,
        table: &str,
        predicate: &str,
        parameters: &[&dyn ToSql],
    ) -> PortResult<Option<Vec<Value>>> {
        let mut values = self.read(table, predicate, parameters)?;
        if values.len() > 1 {
            return Err(PortError::integrity_failure());
        }
        Ok(values.pop())
    }

    fn image(table: &str, values: &[Value]) -> PortResult<String> {
        let refs = values.iter().map(ValueRef::from).collect::<Vec<_>>();
        String::from_utf8(
            encode_retained_security_values(table, &refs)
                .map_err(|_| PortError::integrity_failure())?,
        )
        .map_err(|_| PortError::integrity_failure())
    }

    fn push(
        &mut self,
        table: &str,
        before: Option<Vec<Value>>,
        after: Vec<Value>,
    ) -> PortResult<()> {
        let change = NativeRowChange {
            table: table.into(),
            before: before
                .as_deref()
                .map(|values| Self::image(table, values))
                .transpose()?,
            after: Some(Self::image(table, &after)?),
        };
        change.validate_flow_join(self.request)?;
        let size = change
            .before
            .as_ref()
            .map_or(0, String::len)
            .checked_add(change.after.as_ref().map_or(0, String::len))
            .ok_or_else(PortError::integrity_failure)?;
        self.image_bytes = self
            .image_bytes
            .checked_add(size)
            .ok_or_else(PortError::integrity_failure)?;
        if self.changes.len() >= MAX_CHANGES || self.image_bytes > MAX_IMAGE_BYTES {
            return Err(PortError::invalid_data());
        }
        self.changes.push(change);
        Ok(())
    }

    fn session_identity(&self) -> Vec<Value> {
        let key = &self.request.key;
        [
            key.tenant_id.as_str(),
            key.principal_id.as_str(),
            key.session_id.as_str(),
            key.isolation_epoch_id.as_str(),
        ]
        .into_iter()
        .map(|text| Value::Text(text.into()))
        .collect()
    }

    fn prepare_epoch(&mut self) -> PortResult<()> {
        let request = self.request;
        let key = &request.key;
        let tenant = key.tenant_id.as_str();
        let principal = key.principal_id.as_str();
        let lineage = key.lineage_id.as_str();
        let epoch = key.isolation_epoch_id.as_str();
        let exact = self.one(
            "security_isolation_epochs",
            "tenant_id=?2 AND principal_id=?3 AND lineage_id=?4 AND isolation_epoch_id=?5",
            &[&tenant, &principal, &lineage, &epoch],
        )?;
        let reader = FlowReader::native(self.connection, self.authority);
        if exact.is_some() {
            if load_principal_label(reader, key)?.is_none()
                || load_lineage_label(reader, key)?.is_none()
            {
                return Err(PortError::integrity_failure());
            }
            return Ok(());
        }
        let mut earlier = self.read_bounded(
            "security_isolation_epochs",
            "tenant_id=?2 AND principal_id=?3 AND isolation_epoch_id=?4",
            &[&tenant, &principal, &epoch],
            1,
        )?;
        let after = if !earlier.is_empty() {
            if load_principal_label(reader, key)?.is_none() {
                return Err(PortError::integrity_failure());
            }
            let mut row = earlier.remove(0);
            row[2] = Value::Text(lineage.into());
            row[8] = Value::Text(self.request.transition_id.as_str().into());
            row
        } else {
            let prior: i64 = reader
                .query_row(sql::COUNT_PRIOR_EPOCHS, params![tenant, principal], |row| {
                    row.get(0)
                })
                .map_err(sqlite_error)?;
            if prior != 0 {
                return Err(PortError::invalid_data());
            }
            vec![
                Value::Text(tenant.into()),
                Value::Text(principal.into()),
                Value::Text(lineage.into()),
                Value::Text(epoch.into()),
                Value::Null,
                Value::Blob(vec![0; 32]),
                Value::Null,
                Value::Null,
                Value::Text(self.request.transition_id.as_str().into()),
                Value::Integer(0),
            ]
        };
        self.push("security_isolation_epochs", None, after)
    }

    fn invalidate_contexts(
        &mut self,
        generation: i64,
        principal: bool,
        lineage: bool,
        session: bool,
    ) -> PortResult<()> {
        let request = self.request;
        let key = &request.key;
        let tenant = key.tenant_id.as_str();
        let principal_id = key.principal_id.as_str();
        let lineage_id = key.lineage_id.as_str();
        let session_id = key.session_id.as_str();
        let epoch = key.isolation_epoch_id.as_str();
        for (enabled, predicate, parameters) in [
            (
                principal,
                "tenant_id=?2 AND principal_id=?3 AND isolation_epoch_id=?4",
                vec![&tenant as &dyn ToSql, &principal_id, &epoch],
            ),
            (
                lineage,
                "tenant_id=?2 AND lineage_id=?3",
                vec![&tenant as &dyn ToSql, &lineage_id],
            ),
            (
                session,
                "tenant_id=?2 AND principal_id=?3 AND session_id=?4 AND isolation_epoch_id=?5",
                vec![&tenant as &dyn ToSql, &principal_id, &session_id, &epoch],
            ),
        ] {
            if !enabled {
                continue;
            }
            for stored in self.read("security_flow_contexts", predicate, &parameters)? {
                let identity = Self::image(
                    "security_flow_contexts",
                    &stored[..5]
                        .iter()
                        .cloned()
                        .chain([Value::Integer(1)])
                        .collect::<Vec<_>>(),
                )?;
                let before = self.contexts.get(&identity).unwrap_or(&stored).clone();
                let mut after = before.clone();
                after[5] = Value::Integer(generation);
                self.push("security_flow_contexts", Some(before), after.clone())?;
                self.contexts.insert(identity, after);
            }
        }
        Ok(())
    }

    fn store_label(
        &mut self,
        table: &str,
        label: &InformationLabel,
        generation: i64,
    ) -> PortResult<()> {
        let request = self.request;
        let key = &request.key;
        let tenant = key.tenant_id.as_str();
        let principal = key.principal_id.as_str();
        let lineage = key.lineage_id.as_str();
        let session = key.session_id.as_str();
        let epoch = key.isolation_epoch_id.as_str();
        let (predicate, parameters, mut after): (&str, Vec<&dyn ToSql>, Vec<Value>) = match table {
            "security_principal_flow_state" => (
                "tenant_id=?2 AND principal_id=?3 AND isolation_epoch_id=?4",
                vec![&tenant, &principal, &epoch],
                [tenant, principal, epoch]
                    .into_iter()
                    .map(|text| Value::Text(text.into()))
                    .collect(),
            ),
            "security_lineage_flow_state" => (
                "tenant_id=?2 AND lineage_id=?3",
                vec![&tenant, &lineage],
                [tenant, lineage]
                    .into_iter()
                    .map(|text| Value::Text(text.into()))
                    .collect(),
            ),
            "security_session_flow_state" => (
                "tenant_id=?2 AND principal_id=?3 AND session_id=?4 AND isolation_epoch_id=?5",
                vec![&tenant, &principal, &session, &epoch],
                self.session_identity(),
            ),
            _ => return Err(PortError::integrity_failure()),
        };
        let before = self.one(table, predicate, &parameters)?;
        let (body, hash) = encode_label(label)?;
        after.extend([
            Value::Blob(body),
            Value::Blob(hash.to_vec()),
            Value::Integer(generation),
        ]);
        self.push(table, before, after)
    }

    fn store_context(&mut self, generation: i64) -> PortResult<()> {
        let request = self.request;
        let key = &request.key;
        let fields = [
            key.tenant_id.as_str(),
            key.principal_id.as_str(),
            key.lineage_id.as_str(),
            key.session_id.as_str(),
            key.isolation_epoch_id.as_str(),
        ];
        let mut after = fields
            .into_iter()
            .map(|text| Value::Text(text.into()))
            .collect::<Vec<_>>();
        after.push(Value::Integer(1));
        let identity = Self::image("security_flow_contexts", &after)?;
        let parameters = fields
            .iter()
            .map(|field| field as &dyn ToSql)
            .collect::<Vec<_>>();
        let before = match self.contexts.get(&identity) {
            Some(before) => Some(before.clone()),
            None => self.one("security_flow_contexts", "tenant_id=?2 AND principal_id=?3 AND lineage_id=?4 AND session_id=?5 AND isolation_epoch_id=?6", &parameters)?,
        };
        after[5] = Value::Integer(generation);
        self.push("security_flow_contexts", before, after)
    }
}
