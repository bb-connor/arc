use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::TenantId;
use super::RecordId;
use super::PortResult;


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityAlert {
    pub tenant_id: TenantId,
    pub event_id: RecordId,
    pub idempotency_key: RecordId,
    pub occurred_at_unix_ms: u64,
    pub alert_type: RecordId,
    pub finding_id_hash: Digest32,
    pub action_id_hash: Option<Digest32>,
    pub evidence_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertDeliveryQuery {
    pub alert: SecurityAlert,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum AlertDeliveryStatus {
    Pending {
        attempts: u32,
        next_attempt_at_unix_ms: u64,
    },
    Delivered {
        attempts: u32,
        delivered_at_unix_ms: u64,
    },
}

#[cfg(feature = "std")]
pub trait SecurityAlertPort: Send + Sync {
    fn ensure_alerts_ready(&self) -> PortResult<()>;
    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus>;
    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>>;
}
