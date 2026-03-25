use crate::receipt_store::StoredToolReceipt;

/// Maximum number of receipts returnable in a single query page.
pub const MAX_QUERY_LIMIT: usize = 200;

/// Query parameters for filtering and paginating tool receipts.
#[derive(Debug, Default, Clone)]
pub struct ReceiptQuery {
    /// Filter by capability ID (exact match).
    pub capability_id: Option<String>,
    /// Filter by tool server name (exact match).
    pub tool_server: Option<String>,
    /// Filter by tool name (exact match).
    pub tool_name: Option<String>,
    /// Filter by decision outcome (maps to decision_kind column:
    /// "allow", "deny", "cancelled", "incomplete").
    pub outcome: Option<String>,
    /// Include only receipts with timestamp >= since (Unix seconds, inclusive).
    pub since: Option<u64>,
    /// Include only receipts with timestamp <= until (Unix seconds, inclusive).
    pub until: Option<u64>,
    /// Include only receipts with financial cost_charged >= min_cost (minor units).
    /// Receipts without financial metadata are excluded when this filter is set.
    pub min_cost: Option<u64>,
    /// Include only receipts with financial cost_charged <= max_cost (minor units).
    /// Receipts without financial metadata are excluded when this filter is set.
    pub max_cost: Option<u64>,
    /// Cursor for forward pagination: return only receipts with seq > cursor (exclusive).
    pub cursor: Option<u64>,
    /// Maximum number of receipts to return per page (capped at MAX_QUERY_LIMIT).
    pub limit: usize,
    /// Filter by agent subject public key (hex-encoded Ed25519). Resolved through
    /// capability_lineage JOIN -- does not replay issuance logs.
    pub agent_subject: Option<String>,
}

/// Result of a receipt query, including pagination state.
#[derive(Debug)]
pub struct ReceiptQueryResult {
    /// Receipts matching the query filters, ordered by seq ASC.
    pub receipts: Vec<StoredToolReceipt>,
    /// Total number of receipts matching the filters (independent of limit/cursor).
    pub total_count: u64,
    /// Cursor for the next page: Some(last_seq) when more results exist, None on last page.
    pub next_cursor: Option<u64>,
}
