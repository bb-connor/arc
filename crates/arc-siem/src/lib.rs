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
pub mod ocsf;
pub mod ratelimit;

pub use dlq::{DeadLetterQueue, FailedEvent};
pub use event::SiemEvent;
pub use exporter::{ExportError, ExportFuture, Exporter};
pub use exporters::elastic::{ElasticAuthConfig, ElasticConfig, ElasticsearchExporter};
pub use exporters::ocsf_exporter::{OcsfExporter, OcsfExporterConfig, OcsfPayloadFormat};
pub use exporters::splunk::{SplunkConfig, SplunkHecExporter};
pub use manager::{ExporterManager, SiemConfig, SiemError};
pub use ocsf::{
    receipt_to_ocsf, OCSF_CATEGORY_NAME, OCSF_CATEGORY_UID, OCSF_CLASS_NAME, OCSF_CLASS_UID,
    OCSF_PRODUCT_NAME, OCSF_PRODUCT_VENDOR, OCSF_SCHEMA_VERSION,
};
pub use ratelimit::{ExportRateLimiter, RateLimitConfig, RateLimitConfigError};
