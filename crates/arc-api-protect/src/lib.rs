//! Zero-code reverse proxy that protects HTTP APIs with ARC signed receipts.
//!
//! `arc api protect` reads an OpenAPI spec, generates a default ARC policy,
//! and proxies all requests to the upstream API. Every request produces a
//! signed `HttpReceipt`. Side-effect routes (POST/PUT/PATCH/DELETE) require
//! a capability token; safe routes (GET/HEAD/OPTIONS) pass with audit receipts.

mod error;
mod evaluator;
mod proxy;
mod spec_discovery;

pub use error::ProtectError;
pub use evaluator::{EvaluationResult, RequestEvaluator, RouteEntry};
pub use proxy::{ProtectConfig, ProtectProxy};
pub use spec_discovery::{discover_spec, load_spec_from_file};
