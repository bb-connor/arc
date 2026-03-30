//! arc-siem: SIEM integration for the ARC receipt audit pipeline.
//!
//! This crate provides the foundational abstractions for forwarding ARC receipt
//! events to external SIEM systems (Splunk, Elasticsearch, etc.).
//!
//! # Architecture
//!
//! arc-siem depends on arc-core (for ArcReceipt and FinancialReceiptMetadata)
//! and rusqlite (for direct read access to the kernel receipt database). It does
//! NOT depend on arc-kernel, keeping the kernel TCB free of HTTP client
//! dependencies.
//!
//! The ExporterManager opens its own read-only rusqlite connection and pulls
//! receipts using a seq-based cursor. It fans out to registered Exporter
//! implementations with exponential backoff retry and a bounded DeadLetterQueue.

pub mod dlq;
pub mod event;
pub mod exporter;
pub mod exporters;
pub mod manager;

pub use dlq::{DeadLetterQueue, FailedEvent};
pub use event::SiemEvent;
pub use exporter::{ExportError, ExportFuture, Exporter};
pub use exporters::elastic::{ElasticAuthConfig, ElasticConfig, ElasticsearchExporter};
pub use exporters::splunk::{SplunkConfig, SplunkHecExporter};
pub use manager::{ExporterManager, SiemConfig, SiemError};
