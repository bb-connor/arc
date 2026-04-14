//! Per-receipt cost attribution metadata.
//!
//! Each receipt can carry cost metadata describing the resources consumed
//! during the tool invocation: compute time, data volume transferred, and
//! monetary API cost.

use arc_core::capability::MonetaryAmount;
use serde::{Deserialize, Serialize};

/// Schema identifier for cost metadata embedded in receipts.
pub const COST_METADATA_SCHEMA: &str = "arc.cost-metadata.v1";

/// A single dimension of cost measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "dimension", rename_all = "snake_case")]
pub enum CostDimension {
    /// Wall-clock compute time in milliseconds.
    ComputeTime {
        /// Duration in milliseconds.
        duration_ms: u64,
    },
    /// Data volume transferred in bytes.
    DataVolume {
        /// Bytes read from upstream.
        bytes_read: u64,
        /// Bytes written to upstream.
        bytes_written: u64,
    },
    /// Monetary cost charged by an upstream API.
    ApiCost {
        /// The cost amount in minor currency units.
        amount: MonetaryAmount,
        /// Provider that charged this cost (e.g. "openai", "anthropic").
        provider: String,
    },
    /// Custom cost dimension for extensibility.
    Custom {
        /// Name of the custom dimension.
        name: String,
        /// Numeric value.
        value: u64,
        /// Optional unit label (e.g. "tokens", "requests").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
}

/// Cost metadata attached to a single receipt.
///
/// This struct is serialized as JSON and stored in the receipt's `metadata`
/// field under the `"cost"` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostMetadata {
    /// Schema version for forward compatibility.
    pub schema: String,
    /// Receipt ID this cost metadata belongs to.
    pub receipt_id: String,
    /// Unix timestamp (seconds) of the receipt.
    pub timestamp: u64,
    /// Session that produced this receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent that made the invocation.
    pub agent_id: String,
    /// Tool server that handled the invocation.
    pub tool_server: String,
    /// Tool that was invoked.
    pub tool_name: String,
    /// Individual cost dimensions.
    pub dimensions: Vec<CostDimension>,
    /// Total monetary cost across all API cost dimensions, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_monetary_cost: Option<MonetaryAmount>,
}

impl CostMetadata {
    /// Create a new cost metadata record.
    pub fn new(
        receipt_id: String,
        timestamp: u64,
        agent_id: String,
        tool_server: String,
        tool_name: String,
    ) -> Self {
        Self {
            schema: COST_METADATA_SCHEMA.to_string(),
            receipt_id,
            timestamp,
            session_id: None,
            agent_id,
            tool_server,
            tool_name,
            dimensions: Vec::new(),
            total_monetary_cost: None,
        }
    }

    /// Add a cost dimension.
    pub fn add_dimension(&mut self, dim: CostDimension) {
        self.dimensions.push(dim);
    }

    /// Compute and set the total monetary cost from all ApiCost dimensions.
    ///
    /// Only sums dimensions with the same currency. If dimensions use different
    /// currencies, the total is set to the first currency encountered and
    /// cross-currency amounts are ignored (use oracle conversion for those).
    pub fn compute_total_monetary_cost(&mut self) {
        let mut total_units: u64 = 0;
        let mut currency: Option<String> = None;

        for dim in &self.dimensions {
            if let CostDimension::ApiCost { amount, .. } = dim {
                match &currency {
                    None => {
                        currency = Some(amount.currency.clone());
                        total_units = amount.units;
                    }
                    Some(c) if c == &amount.currency => {
                        total_units = total_units.saturating_add(amount.units);
                    }
                    _ => {
                        // Cross-currency -- skip without oracle
                    }
                }
            }
        }

        if let Some(cur) = currency {
            self.total_monetary_cost = Some(MonetaryAmount {
                units: total_units,
                currency: cur,
            });
        }
    }

    /// Total compute time across all ComputeTime dimensions.
    #[must_use]
    pub fn total_compute_time_ms(&self) -> u64 {
        self.dimensions
            .iter()
            .filter_map(|d| match d {
                CostDimension::ComputeTime { duration_ms } => Some(*duration_ms),
                _ => None,
            })
            .sum()
    }

    /// Total data volume (read + written) across all DataVolume dimensions.
    #[must_use]
    pub fn total_data_bytes(&self) -> u64 {
        self.dimensions
            .iter()
            .filter_map(|d| match d {
                CostDimension::DataVolume {
                    bytes_read,
                    bytes_written,
                } => Some(bytes_read.saturating_add(*bytes_written)),
                _ => None,
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_metadata_roundtrip() {
        let mut meta = CostMetadata::new(
            "r-1".to_string(),
            1700000000,
            "agent-1".to_string(),
            "srv-1".to_string(),
            "tool-a".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 150 });
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 1024,
            bytes_written: 512,
        });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            },
            provider: "openai".to_string(),
        });
        meta.compute_total_monetary_cost();

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: CostMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.receipt_id, "r-1");
        assert_eq!(deserialized.dimensions.len(), 3);
        assert_eq!(deserialized.total_monetary_cost.as_ref().unwrap().units, 50);
    }

    #[test]
    fn compute_total_sums_same_currency() {
        let mut meta = CostMetadata::new(
            "r-2".to_string(),
            1700000000,
            "agent-1".to_string(),
            "srv-1".to_string(),
            "tool-a".to_string(),
        );
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            provider: "a".to_string(),
        });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 200,
                currency: "USD".to_string(),
            },
            provider: "b".to_string(),
        });
        meta.compute_total_monetary_cost();
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().units, 300);
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().currency, "USD");
    }

    #[test]
    fn total_compute_time() {
        let mut meta = CostMetadata::new(
            "r-3".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 100 });
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 250 });
        assert_eq!(meta.total_compute_time_ms(), 350);
    }

    #[test]
    fn total_data_bytes() {
        let mut meta = CostMetadata::new(
            "r-4".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 100,
            bytes_written: 50,
        });
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 200,
            bytes_written: 30,
        });
        assert_eq!(meta.total_data_bytes(), 380);
    }
}
