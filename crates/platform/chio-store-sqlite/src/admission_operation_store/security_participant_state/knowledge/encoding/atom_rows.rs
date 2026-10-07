//! Closed row-image encoding interns only the native label-json blob cell.
use crate::admission_operation_store::knowledge::encoding::labels::{
    LabelIndex, LabelTable, LabelTableBuilder,
};
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
    NativeRowChange,
};
use chio_security_types::{ports::BoundedVec, InformationLabel};
use rusqlite::types::{Value, ValueRef};
use serde::{Deserialize, Serialize};

const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FlowTable {
    SecurityFlowContexts,
    SecurityFlowSequences,
    SecurityIsolationEpochs,
    SecurityLineageFlowState,
    SecurityPrincipalFlowState,
    SecuritySessionFlowState,
    SecuritySessionMemberships,
    SecurityTransitions,
}

impl FlowTable {
    fn parse(value: &str) -> Result<Self, AdmissionOperationStoreError> {
        match value {
            "security_flow_contexts" => Ok(Self::SecurityFlowContexts),
            "security_flow_sequences" => Ok(Self::SecurityFlowSequences),
            "security_isolation_epochs" => Ok(Self::SecurityIsolationEpochs),
            "security_lineage_flow_state" => Ok(Self::SecurityLineageFlowState),
            "security_principal_flow_state" => Ok(Self::SecurityPrincipalFlowState),
            "security_session_flow_state" => Ok(Self::SecuritySessionFlowState),
            "security_session_memberships" => Ok(Self::SecuritySessionMemberships),
            "security_transitions" => Ok(Self::SecurityTransitions),
            _ => Err(invalid()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SecurityFlowContexts => "security_flow_contexts",
            Self::SecurityFlowSequences => "security_flow_sequences",
            Self::SecurityIsolationEpochs => "security_isolation_epochs",
            Self::SecurityLineageFlowState => "security_lineage_flow_state",
            Self::SecurityPrincipalFlowState => "security_principal_flow_state",
            Self::SecuritySessionFlowState => "security_session_flow_state",
            Self::SecuritySessionMemberships => "security_session_memberships",
            Self::SecurityTransitions => "security_transitions",
        }
    }

    fn carries_label(self) -> bool {
        matches!(
            self,
            Self::SecurityLineageFlowState
                | Self::SecurityPrincipalFlowState
                | Self::SecuritySessionFlowState
        )
    }
}

/// Cells preserve the compiled row layout and integer/string/blob identity.
/// A label reference can occur only in the single closed label-json column.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum StoredCell {
    Null,
    Integer(String),
    Text(String),
    Blob(String),
    Label(LabelIndex),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRowImage {
    cells: BoundedVec<StoredCell, 64>,
}

impl StoredRowImage {
    fn preflight_labels(
        &self,
        table: FlowTable,
        labels: &LabelTable,
        references: &mut Vec<LabelIndex>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let columns = retained_security_columns(table.name()).map_err(|_| invalid())?;
        if columns.len() != self.cells.len() {
            return Err(invalid());
        }
        for (column, cell) in columns.iter().zip(self.cells.as_slice()) {
            match (*column, cell) {
                ("label_json", StoredCell::Label(index)) if table.carries_label() => {
                    if labels.logical_label_bytes(*index)? > 1_048_576 {
                        return Err(invalid());
                    }
                    references.push(*index);
                }
                ("label_json", _) | (_, StoredCell::Label(_)) => return Err(invalid()),
                _ => {}
            }
        }
        Ok(())
    }
    fn capture(
        table: FlowTable,
        image: &str,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let columns = retained_security_columns(table.name()).map_err(|_| invalid())?;
        let values =
            decode_retained_security_row(table.name(), image.as_bytes()).map_err(|_| invalid())?;
        let mut cells = Vec::with_capacity(values.len());
        for (column, value) in columns.iter().zip(values) {
            let cell = match (*column, value) {
                ("label_json", Value::Blob(body)) if table.carries_label() => {
                    let label: InformationLabel =
                        serde_json::from_slice(&body).map_err(|_| invalid())?;
                    if chio_core::canonical_json_bytes(&label).map_err(|_| invalid())? != body {
                        return Err(invalid());
                    }
                    StoredCell::Label(labels.insert(&label)?)
                }
                ("label_json", _) => return Err(invalid()),
                (_, Value::Null) => StoredCell::Null,
                (_, Value::Integer(value)) => StoredCell::Integer(value.to_string()),
                (_, Value::Text(value)) => StoredCell::Text(value),
                (_, Value::Blob(value)) => StoredCell::Blob(hex::encode(value)),
                (_, Value::Real(_)) => return Err(invalid()),
            };
            cells.push(cell);
        }
        Ok(Self {
            cells: BoundedVec::new(cells).map_err(|_| invalid())?,
        })
    }

    fn expand(
        &self,
        table: FlowTable,
        labels: &LabelTable,
        budget: &mut ExpansionBudget,
    ) -> Result<String, AdmissionOperationStoreError> {
        let columns = retained_security_columns(table.name()).map_err(|_| invalid())?;
        if columns.len() != self.cells.len() {
            return Err(invalid());
        }
        let mut values = Vec::with_capacity(columns.len());
        for (column, cell) in columns.iter().zip(self.cells.as_slice()) {
            let value = match (*column, cell) {
                ("label_json", StoredCell::Label(index)) if table.carries_label() => {
                    Value::Blob(labels.label_bytes(*index)?)
                }
                ("label_json", _) | (_, StoredCell::Label(_)) => return Err(invalid()),
                (_, StoredCell::Null) => Value::Null,
                (_, StoredCell::Integer(text)) => {
                    let value = text.parse::<i64>().map_err(|_| invalid())?;
                    if value.to_string() != *text {
                        return Err(invalid());
                    }
                    Value::Integer(value)
                }
                (_, StoredCell::Text(text)) => Value::Text(text.clone()),
                (_, StoredCell::Blob(text)) => {
                    if text.len() % 2 != 0
                        || !text
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(invalid());
                    }
                    Value::Blob(hex::decode(text).map_err(|_| invalid())?)
                }
            };
            values.push(value);
        }
        let references = values.iter().map(ValueRef::from).collect::<Vec<_>>();
        let encoded =
            encode_retained_security_values(table.name(), &references).map_err(|_| invalid())?;
        budget.add_image(encoded.len())?;
        String::from_utf8(encoded).map_err(|_| invalid())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredRowChange {
    table: FlowTable,
    before: Option<StoredRowImage>,
    after: StoredRowImage,
}

impl StoredRowChange {
    pub(super) fn preflight_labels(
        &self,
        labels: &LabelTable,
        references: &mut Vec<LabelIndex>,
        budget: &mut ExpansionBudget,
    ) -> Result<(), AdmissionOperationStoreError> {
        budget.observe_table(self.table)?;
        if let Some(before) = &self.before {
            before.preflight_labels(self.table, labels, references)?;
        }
        self.after.preflight_labels(self.table, labels, references)
    }
    pub(super) fn capture(
        change: &NativeRowChange,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let table = FlowTable::parse(&change.table)?;
        let before = change
            .before
            .as_deref()
            .map(|image| StoredRowImage::capture(table, image, labels))
            .transpose()?;
        let after =
            StoredRowImage::capture(table, change.after.as_deref().ok_or_else(invalid)?, labels)?;
        Ok(Self {
            table,
            before,
            after,
        })
    }

    pub(super) fn expand(
        &self,
        labels: &LabelTable,
        budget: &mut ExpansionBudget,
    ) -> Result<NativeRowChange, AdmissionOperationStoreError> {
        budget.observe_table(self.table)?;
        Ok(NativeRowChange {
            table: self.table.name().to_owned(),
            before: self
                .before
                .as_ref()
                .map(|image| image.expand(self.table, labels, budget))
                .transpose()?,
            after: Some(self.after.expand(self.table, labels, budget)?),
        })
    }
}

/// The live join writes each of its three label rows once. Keeping that closed
/// layout prevents a small private body from expanding thousands of labels.
#[derive(Default)]
pub(super) struct ExpansionBudget {
    image_bytes: usize,
    label_tables: Vec<FlowTable>,
}

impl ExpansionBudget {
    fn add_image(&mut self, bytes: usize) -> Result<(), AdmissionOperationStoreError> {
        self.image_bytes = self.image_bytes.checked_add(bytes).ok_or_else(invalid)?;
        if self.image_bytes > MAX_IMAGE_BYTES {
            return Err(invalid());
        }
        Ok(())
    }

    fn observe_table(&mut self, table: FlowTable) -> Result<(), AdmissionOperationStoreError> {
        if table.carries_label() {
            if self.label_tables.contains(&table) {
                return Err(invalid());
            }
            self.label_tables.push(table);
        }
        Ok(())
    }
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge row encoding is invalid")
}
