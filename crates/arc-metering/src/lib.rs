//! Receipt metering and economics for the ARC protocol.
//!
//! This crate provides per-receipt cost attribution, cumulative cost queries,
//! monetary budget enforcement via arc-link oracle integration, and
//! billing-export-compatible cost metadata.
//!
//! # Modules
//!
//! - [`cost`] -- Per-receipt cost metadata (compute time, data volume, API cost)
//! - [`query`] -- CLI-style cost queries by session, agent, tool, or time range
//! - [`budget`] -- Monetary budget enforcement with denominated currency
//! - [`export`] -- Billing-export-compatible cost records

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod budget;
pub mod cost;
pub mod export;
pub mod query;

pub use budget::{BudgetEnforcer, BudgetPolicy, BudgetViolation};
pub use cost::{CostMetadata, CostDimension};
pub use export::{BillingRecord, BillingExport};
pub use query::{CostQuery, CostQueryResult, CostSummary};
