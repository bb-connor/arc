// owned-by: M02 (fuzz lane); module authored under M02.P1.T5.b.
//
//! libFuzzer entry-point module for `chio-openapi-mcp-bridge`.
//!
//! Authored under M02.P1.T5.b (`.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1, trust-boundary fuzz target #11). This module is gated behind
//! the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-openapi-mcp-bridge` never pulls in `arbitrary`, never exposes
//! these symbols, and never gets recompiled with libFuzzer
//! instrumentation.
//!
//! The single entry point [`fuzz_openapi_ingest`] consumes arbitrary
//! bytes and drives them through the canonical OpenAPI-spec ingest
//! trust boundary: [`crate::OpenApiMcpBridge::from_spec`]. That call
//! covers the full ingest pipeline:
//!
//! 1. JSON-vs-YAML auto-detection plus parse
//!    (`chio_openapi::OpenApiSpec::parse`).
//! 2. OpenAPI 3.x version validation and `info` / `paths` extraction.
//! 3. Manifest generation
//!    (`chio_openapi::ManifestGenerator::generate_tools`).
//! 4. Tool-definition conversion plus route-binding map population.
//! 5. Manifest validation (`chio_manifest::validate_manifest`).
//!
//! `chio-openapi-mcp-bridge` ingests untrusted bytes (operator-supplied
//! OpenAPI specs at runtime), so this target catches parse-path panics
//! and allocator regressions in the
//! `serde_json` / `serde_yml` -> `OpenApiSpec` -> manifest-validate
//! chain rather than security regressions.

use crate::{BridgeConfig, OpenApiMcpBridge};

/// Drive arbitrary bytes through the OpenAPI-spec ingest trust boundary
/// at [`crate::OpenApiMcpBridge::from_spec`].
///
/// Bytes are first decoded as UTF-8 (non-UTF-8 inputs are silently
/// dropped, mirroring the `serde_json` / `serde_yml` contracts that
/// operate on `&str`). The decoded text is then handed to
/// `OpenApiMcpBridge::from_spec`, which auto-detects JSON vs YAML,
/// parses the spec, generates an MCP tool manifest, populates route
/// bindings, and validates the manifest end-to-end.
///
/// Every error variant ([`crate::BridgeError::OpenApi`],
/// [`crate::BridgeError::Manifest`], etc.) is silently consumed: the
/// trust-boundary contract guarantees the only outcomes are `Err(_)`
/// (good), `Ok(OpenApiMcpBridge)` (good, exercised by valid seed
/// corpus), or a panic / abort (which libFuzzer surfaces as a crash).
/// No arbitrary input can corrupt host state; this target only drives
/// the parse, generate, and validate paths.
///
/// A fixed [`BridgeConfig`] is used for every invocation so the only
/// source of variability is the spec bytes themselves. Mutating
/// [`BridgeConfig`] would not exercise additional ingest-path branches:
/// the config is consumed by the manifest builder after parsing
/// completes.
pub fn fuzz_openapi_ingest(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let config = BridgeConfig {
        server_id: "fuzz-bridge".to_string(),
        server_name: "Fuzz Bridge".to_string(),
        server_version: "0.0.0".to_string(),
        public_key: "00".to_string(),
        base_url: "https://fuzz.invalid".to_string(),
    };
    let _ = OpenApiMcpBridge::from_spec(text, config);
}
