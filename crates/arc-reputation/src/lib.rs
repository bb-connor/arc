//! arc-reputation: deterministic local reputation scoring for ARC agents.
//!
//! This crate is intentionally pure and storage-agnostic. It scores an agent
//! from a caller-provided local corpus assembled from persisted receipts,
//! capability-lineage snapshots, and budget-usage records. It does not depend
//! on `arc-kernel`, which keeps the scoring model reusable and avoids a future
//! dependency cycle when kernel-side issuance hooks begin consuming it.

use std::collections::{BTreeMap, BTreeSet};

use arc_core::capability::{ArcScope, Operation, ToolGrant};
use arc_core::receipt::{ArcReceipt, Decision, ReceiptAttributionMetadata};
use serde::{Deserialize, Serialize};

const SECONDS_PER_DAY: u64 = 86_400;
const DEFAULT_HISTORY_RECEIPT_TARGET: u64 = 1_000;
const DEFAULT_HISTORY_DAY_TARGET: u64 = 30;
const DEFAULT_INCIDENT_PENALTY: f64 = 0.20;

include!("model.rs");
include!("score.rs");
include!("compare.rs");
include!("issuance.rs");
include!("tests.rs");
