use arc_core::web3::{ARC_SETTLE_CONTROL_STATE_SCHEMA, ARC_SETTLE_CONTROL_TRACE_SCHEMA};
use serde::{Deserialize, Serialize};

use crate::{SettlementError, SettlementFinalityStatus, SettlementRecoveryAction};

pub const ARC_SETTLE_RUNTIME_REPORT_SCHEMA: &str = "arc.settle-runtime-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementIndexerStatus {
    Healthy,
    Lagging,
    Drifted,
    Replaying,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRuntimeStatus {
    Healthy,
    AwaitingFinality,
    Recovering,
    Paused,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEmergencyMode {
    Normal,
    DispatchPaused,
    RefundOnly,
    RecoveryOnly,
    Halted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementOperationKind {
    DispatchEscrow,
    ReleaseEscrow,
    RefundEscrow,
    LockBond,
    ReleaseBond,
    ImpairBond,
    ExpireBond,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementControlChangeRecord {
    pub schema: String,
    pub actor: String,
    pub source: String,
    pub changed_at: u64,
    pub before: SettlementEmergencyControls,
    pub after: SettlementEmergencyControls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementEmergencyControls {
    pub mode: SettlementEmergencyMode,
    pub changed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SettlementEmergencyControls {
    #[must_use]
    pub fn normal(changed_at: u64) -> Self {
        Self {
            mode: SettlementEmergencyMode::Normal,
            changed_at,
            reason: None,
        }
    }

    #[must_use]
    pub fn allows(&self, operation: SettlementOperationKind) -> bool {
        match self.mode {
            SettlementEmergencyMode::Normal => true,
            SettlementEmergencyMode::DispatchPaused => !matches!(
                operation,
                SettlementOperationKind::DispatchEscrow | SettlementOperationKind::LockBond
            ),
            SettlementEmergencyMode::RefundOnly => matches!(
                operation,
                SettlementOperationKind::RefundEscrow
                    | SettlementOperationKind::ImpairBond
                    | SettlementOperationKind::ExpireBond
            ),
            SettlementEmergencyMode::RecoveryOnly => !matches!(
                operation,
                SettlementOperationKind::DispatchEscrow | SettlementOperationKind::LockBond
            ),
            SettlementEmergencyMode::Halted => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementControlState {
    pub schema: String,
    pub updated_at: u64,
    pub controls: SettlementEmergencyControls,
    pub history: Vec<SettlementControlChangeRecord>,
}

impl SettlementControlState {
    #[must_use]
    pub fn new(updated_at: u64, controls: SettlementEmergencyControls) -> Self {
        Self {
            schema: ARC_SETTLE_CONTROL_STATE_SCHEMA.to_string(),
            updated_at,
            controls,
            history: Vec::new(),
        }
    }

    pub fn apply_change(
        &mut self,
        mode: SettlementEmergencyMode,
        changed_at: u64,
        actor: impl Into<String>,
        reason: Option<String>,
        source: impl Into<String>,
    ) {
        let before = self.controls.clone();
        self.controls = SettlementEmergencyControls {
            mode,
            changed_at,
            reason,
        };
        self.updated_at = changed_at;
        self.history.push(SettlementControlChangeRecord {
            schema: ARC_SETTLE_CONTROL_TRACE_SCHEMA.to_string(),
            actor: actor.into(),
            source: source.into(),
            changed_at,
            before,
            after: self.controls.clone(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementIndexerCursor {
    pub service_id: String,
    pub chain_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_indexed_block_number: Option<u64>,
    pub canonical_block_number: u64,
    pub lag_blocks: u64,
    pub status: SettlementIndexerStatus,
    pub checked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SettlementIndexerCursor {
    #[must_use]
    pub fn from_blocks(
        service_id: impl Into<String>,
        chain_id: impl Into<String>,
        last_indexed_block_number: Option<u64>,
        canonical_block_number: u64,
        replaying: bool,
        failed: bool,
        checked_at: u64,
        note: Option<String>,
    ) -> Self {
        let lag_blocks =
            canonical_block_number.saturating_sub(last_indexed_block_number.unwrap_or(0));
        let status = if failed {
            SettlementIndexerStatus::Failed
        } else if replaying {
            SettlementIndexerStatus::Replaying
        } else if lag_blocks == 0 {
            SettlementIndexerStatus::Healthy
        } else if lag_blocks <= 12 {
            SettlementIndexerStatus::Lagging
        } else {
            SettlementIndexerStatus::Drifted
        };
        Self {
            service_id: service_id.into(),
            chain_id: chain_id.into(),
            last_indexed_block_number,
            canonical_block_number,
            lag_blocks,
            status,
            checked_at,
            note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementRecoveryRecord {
    pub execution_receipt_id: String,
    pub chain_id: String,
    pub tx_hash: String,
    pub finality_status: SettlementFinalityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reorg_depth: Option<u32>,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementLaneRuntimeStatus {
    pub chain_id: String,
    pub network_name: String,
    pub status: SettlementRuntimeStatus,
    pub indexer_status: SettlementIndexerStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finality_status: Option<SettlementFinalityStatus>,
    pub queued_recoveries: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SettlementLaneRuntimeStatus {
    #[must_use]
    pub fn new(
        chain_id: impl Into<String>,
        network_name: impl Into<String>,
        indexer_status: SettlementIndexerStatus,
        finality_status: Option<SettlementFinalityStatus>,
        controls: SettlementEmergencyControls,
        queued_recoveries: usize,
        last_observed_at: Option<u64>,
        note: Option<String>,
    ) -> Self {
        let status = classify_settlement_lane(indexer_status, finality_status, controls);
        Self {
            chain_id: chain_id.into(),
            network_name: network_name.into(),
            status,
            indexer_status,
            finality_status,
            queued_recoveries,
            last_observed_at,
            note,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementIncidentAlert {
    pub code: String,
    pub severity: SettlementAlertSeverity,
    pub chain_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_receipt_id: Option<String>,
    pub observed_at: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementRuntimeReport {
    pub schema: String,
    pub generated_at: u64,
    pub controls: SettlementEmergencyControls,
    pub lanes: Vec<SettlementLaneRuntimeStatus>,
    pub indexers: Vec<SettlementIndexerCursor>,
    pub recoveries: Vec<SettlementRecoveryRecord>,
    pub incidents: Vec<SettlementIncidentAlert>,
}

impl SettlementRuntimeReport {
    #[must_use]
    pub fn new(generated_at: u64, controls: SettlementEmergencyControls) -> Self {
        Self {
            schema: ARC_SETTLE_RUNTIME_REPORT_SCHEMA.to_string(),
            generated_at,
            controls,
            lanes: Vec::new(),
            indexers: Vec::new(),
            recoveries: Vec::new(),
            incidents: Vec::new(),
        }
    }
}

#[must_use]
pub fn classify_settlement_lane(
    indexer_status: SettlementIndexerStatus,
    finality_status: Option<SettlementFinalityStatus>,
    controls: SettlementEmergencyControls,
) -> SettlementRuntimeStatus {
    if indexer_status == SettlementIndexerStatus::Failed {
        return SettlementRuntimeStatus::Failed;
    }
    match controls.mode {
        SettlementEmergencyMode::Halted
        | SettlementEmergencyMode::DispatchPaused
        | SettlementEmergencyMode::RefundOnly => {
            return SettlementRuntimeStatus::Paused;
        }
        SettlementEmergencyMode::RecoveryOnly => return SettlementRuntimeStatus::Recovering,
        SettlementEmergencyMode::Normal => {}
    }
    if indexer_status == SettlementIndexerStatus::Replaying
        || finality_status == Some(SettlementFinalityStatus::Reorged)
    {
        SettlementRuntimeStatus::Recovering
    } else if matches!(
        finality_status,
        Some(SettlementFinalityStatus::AwaitingConfirmations)
            | Some(SettlementFinalityStatus::AwaitingDisputeWindow)
    ) || matches!(
        indexer_status,
        SettlementIndexerStatus::Lagging | SettlementIndexerStatus::Drifted
    ) {
        SettlementRuntimeStatus::AwaitingFinality
    } else {
        SettlementRuntimeStatus::Healthy
    }
}

pub fn ensure_settlement_operation_allowed(
    controls: SettlementEmergencyControls,
    operation: SettlementOperationKind,
) -> Result<(), SettlementError> {
    if controls.allows(operation) {
        return Ok(());
    }
    Err(SettlementError::InvalidInput(format!(
        "settlement operation {operation:?} denied while emergency mode {:?} is active",
        controls.mode
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        classify_settlement_lane, ensure_settlement_operation_allowed, SettlementControlState,
        SettlementEmergencyControls, SettlementEmergencyMode, SettlementIndexerCursor,
        SettlementIndexerStatus, SettlementOperationKind, SettlementRuntimeReport,
        SettlementRuntimeStatus, ARC_SETTLE_RUNTIME_REPORT_SCHEMA,
    };
    use crate::SettlementFinalityStatus;

    #[test]
    fn indexer_cursor_classifies_lagging() {
        let cursor = SettlementIndexerCursor::from_blocks(
            "escrow-event-indexer",
            "eip155:8453",
            Some(23_456_789),
            23_456_797,
            false,
            false,
            1_712_337_200,
            Some("eight blocks behind canonical head".to_string()),
        );
        assert_eq!(cursor.lag_blocks, 8);
        assert_eq!(cursor.status, SettlementIndexerStatus::Lagging);
    }

    #[test]
    fn refund_only_mode_denies_new_dispatch() {
        let controls = SettlementEmergencyControls {
            mode: SettlementEmergencyMode::RefundOnly,
            changed_at: 1_712_337_200,
            reason: Some("beneficiary release halted pending replay review".to_string()),
        };
        let error =
            ensure_settlement_operation_allowed(controls, SettlementOperationKind::DispatchEscrow)
                .expect_err("dispatch should be denied");
        assert!(error
            .to_string()
            .contains("settlement operation DispatchEscrow denied"));
    }

    #[test]
    fn reorged_lane_is_marked_recovering() {
        let controls = SettlementEmergencyControls::normal(1_712_337_200);
        let status = classify_settlement_lane(
            SettlementIndexerStatus::Healthy,
            Some(SettlementFinalityStatus::Reorged),
            controls,
        );
        assert_eq!(status, SettlementRuntimeStatus::Recovering);
    }

    #[test]
    fn runtime_report_example_round_trips() {
        let report: SettlementRuntimeReport = serde_json::from_str(include_str!(
            "../../../docs/standards/ARC_SETTLE_RUNTIME_REPORT_EXAMPLE.json"
        ))
        .expect("example report");
        assert_eq!(report.schema, ARC_SETTLE_RUNTIME_REPORT_SCHEMA);
        assert_eq!(report.controls.mode, SettlementEmergencyMode::RefundOnly);
        assert_eq!(report.recoveries.len(), 1);
        assert!(report
            .incidents
            .iter()
            .any(|incident| incident.code == "settlement_reorg"));
    }

    #[test]
    fn control_state_tracks_mode_history() {
        let mut state = SettlementControlState::new(
            1_764_825_600,
            SettlementEmergencyControls::normal(1_764_825_600),
        );
        state.apply_change(
            SettlementEmergencyMode::DispatchPaused,
            1_764_825_620,
            "settlement-operator",
            Some("pause new dispatch".to_string()),
            "unit_test",
        );
        state.apply_change(
            SettlementEmergencyMode::RefundOnly,
            1_764_825_640,
            "settlement-operator",
            Some("refund-first recovery".to_string()),
            "unit_test",
        );
        assert_eq!(state.controls.mode, SettlementEmergencyMode::RefundOnly);
        assert_eq!(state.history.len(), 2);
        assert_eq!(
            state.history[1].after.reason.as_deref(),
            Some("refund-first recovery")
        );
    }
}
