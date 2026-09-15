//! Semantic checks shared by live row capture and immutable journal readback.
//! Capturing a row change does not make it an authorized monotone mutation.

use super::super::{
    canonical_request_hash, decode_label, decode_retained_security_row, retained_security_columns,
};
use super::{is_native_flow_join_table, NativeRowChange};
use chio_security_types::ports::{FlowJoinRequest, FlowStateKey, PortError, PortResult};
use chio_security_types::InformationLabel;
use rusqlite::types::Value;

struct Row {
    columns: Vec<&'static str>,
    values: Vec<Value>,
}

impl Row {
    fn decode(table: &str, image: &str) -> PortResult<Self> {
        Ok(Self {
            columns: retained_security_columns(table)
                .map_err(|_| PortError::integrity_failure())?,
            values: decode_retained_security_row(table, image.as_bytes())
                .map_err(|_| PortError::integrity_failure())?,
        })
    }

    fn cell(&self, name: &str) -> PortResult<&Value> {
        self.columns
            .iter()
            .zip(&self.values)
            .find_map(|(column, value)| (*column == name).then_some(value))
            .ok_or_else(PortError::integrity_failure)
    }

    fn text_matches(&self, name: &str, expected: &str) -> bool {
        matches!(self.cell(name), Ok(Value::Text(value)) if value == expected)
    }

    fn integer(value: &Value) -> PortResult<i64> {
        match value {
            Value::Integer(value) if (1..=9_007_199_254_740_991).contains(value) => Ok(*value),
            _ => Err(PortError::integrity_failure()),
        }
    }

    fn label(&self) -> PortResult<InformationLabel> {
        match (self.cell("label_json")?, self.cell("label_hash")?) {
            (Value::Blob(body), Value::Blob(hash)) => decode_label(body.clone(), hash.clone()),
            _ => Err(PortError::integrity_failure()),
        }
    }

    fn principal(&self, key: &FlowStateKey) -> bool {
        self.text_matches("principal_id", key.principal_id.as_str())
            && self.text_matches("isolation_epoch_id", key.isolation_epoch_id.as_str())
    }

    fn lineage(&self, key: &FlowStateKey) -> bool {
        self.text_matches("lineage_id", key.lineage_id.as_str())
    }

    fn session(&self, key: &FlowStateKey) -> bool {
        self.principal(key) && self.text_matches("session_id", key.session_id.as_str())
    }

    fn validate_scope(
        &self,
        table: &str,
        request: &FlowJoinRequest,
        inserting: bool,
    ) -> PortResult<()> {
        let key = &request.key;
        let allowed = self.text_matches("tenant_id", key.tenant_id.as_str())
            && match table {
                "security_flow_sequences" => true,
                "security_principal_flow_state" => self.principal(key),
                "security_lineage_flow_state" => self.lineage(key),
                "security_session_flow_state" | "security_session_memberships" => self.session(key),
                // Related contexts can only advance their generation. A join never
                // inserts an unrelated context or changes its identity columns.
                "security_flow_contexts" if !inserting => self.principal(key) || self.lineage(key),
                "security_flow_contexts" => self.session(key) && self.lineage(key),
                "security_isolation_epochs" => {
                    self.principal(key)
                        && self.lineage(key)
                        && (!inserting
                            || self.text_matches("transition_id", request.transition_id.as_str()))
                }
                "security_transitions" => {
                    self.text_matches("transition_id", request.transition_id.as_str())
                        && self.text_matches("transition_kind", "flow_join")
                        && matches!(self.cell("request_hash")?, Value::Blob(hash) if hash.as_slice() == canonical_request_hash(request)?)
                }
                _ => false,
            };
        if !allowed {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}

impl NativeRowChange {
    pub(crate) fn validate_flow_join(&self, request: &FlowJoinRequest) -> PortResult<()> {
        if !is_native_flow_join_table(&self.table) {
            return Err(PortError::integrity_failure());
        }
        let after = Row::decode(
            &self.table,
            self.after
                .as_deref()
                .ok_or_else(PortError::integrity_failure)?,
        )?;
        let before = self
            .before
            .as_deref()
            .map(|image| Row::decode(&self.table, image))
            .transpose()?;
        after.validate_scope(&self.table, request, before.is_none())?;
        for (column, value) in after.columns.iter().zip(&after.values) {
            match *column {
                "generation" | "last_generation" => {
                    let next = Row::integer(value)?;
                    if let Some(before) = &before {
                        if next < Row::integer(before.cell(column)?)? {
                            return Err(PortError::integrity_failure());
                        }
                    }
                }
                "label_json" | "label_hash" => {}
                _ => {
                    if before
                        .as_ref()
                        .is_some_and(|before| before.cell(column).ok() != Some(value))
                    {
                        return Err(PortError::integrity_failure());
                    }
                }
            }
        }
        let required_label = match self.table.as_str() {
            "security_principal_flow_state" => Some(&request.principal_join),
            "security_lineage_flow_state" => Some(&request.lineage_join),
            "security_session_flow_state" => Some(&request.session_join),
            _ => None,
        };
        if let Some(required) = required_label {
            let next = after.label()?;
            if next
                .join_restrictions(required)
                .map_err(|_| PortError::integrity_failure())?
                != next
            {
                return Err(PortError::integrity_failure());
            }
            if let Some(before) = before {
                if before
                    .label()?
                    .join_restrictions(&next)
                    .map_err(|_| PortError::integrity_failure())?
                    != next
                {
                    return Err(PortError::integrity_failure());
                }
            }
        }
        Ok(())
    }
}
