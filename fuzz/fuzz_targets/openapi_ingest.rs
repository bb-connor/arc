// owned-by: M02 (fuzz lane); target authored under M02.P1.T5.b.
//
//! libFuzzer harness for the `chio-openapi-mcp-bridge` spec-ingest
//! trust boundary.
//!
//! The trust boundary is the moment at which `chio` accepts an
//! operator-supplied OpenAPI specification (loaded from disk, fetched
//! over HTTP, or embedded in a config) and hands it to the bridge
//! ingest pipeline. `OpenApiMcpBridge::from_spec` is the canonical
//! entry point; it drives, in order:
//!
//! 1. UTF-8 decode (handled by the Rust string boundary).
//! 2. JSON-vs-YAML auto-detection (`OpenApiSpec::parse`: `serde_json`
//!    if the first non-whitespace byte is `{`, otherwise `serde_yml`).
//! 3. OpenAPI 3.x version validation plus `info` / `paths` extraction.
//! 4. Manifest generation
//!    (`chio_openapi::ManifestGenerator::generate_tools`).
//! 5. Tool-definition conversion plus route-binding map population.
//! 6. Manifest validation (`chio_manifest::validate_manifest`).
//!
//! The contract is that arbitrary bytes either ingest cleanly or
//! surface as `Err(BridgeError::*)`. A panic / abort anywhere along
//! the chain would let a malformed OpenAPI document crash the runtime
//! during cluster bootstrap, so this target exists to keep the
//! parse-then-generate-then-validate path panic-free as `serde_yml`,
//! `serde_json`, the manifest generator, and the validator evolve.
//!
//! `chio-openapi-mcp-bridge` ingests untrusted bytes (operator-supplied
//! OpenAPI specs at runtime), so this target focuses on catching
//! parse-path panics and allocator regressions rather than security
//! regressions.
//!
//! Reference: `.planning/trajectory/02-fuzzing-post-pr13.md` Phase 1
//! (trust-boundary fuzz target #11).

#![no_main]

use chio_openapi_mcp_bridge::fuzz::fuzz_openapi_ingest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_openapi_ingest(data);
});
