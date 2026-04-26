// owned-by: M02 (fuzz lane); target authored under M02.P1.T5.a.
//
//! libFuzzer harness for the `chio-config` YAML-loader trust boundary.
//!
//! The trust boundary is the moment at which `chio` accepts bytes from
//! disk (`chio.yaml`), an embedded config string, or environment-variable
//! interpolation and hands them to the configuration ingest pipeline.
//! `chio_config::loader::load_from_str` is the canonical entry point; it
//! drives, in order:
//!
//! 1. `${VAR}` and `${VAR:-default}` interpolation.
//! 2. `serde_yml` deserialization into `ChioConfig` with
//!    `deny_unknown_fields`.
//! 3. Post-deserialization validation (duplicate ids, broken references,
//!    incomplete auth, etc).
//!
//! The contract is that arbitrary bytes either ingest cleanly or surface
//! as `Err(ConfigError::*)`. A panic / abort anywhere along the chain
//! would let a malformed config file crash the runtime, so this target
//! exists to keep the parse-then-validate path panic-free as `serde_yml`,
//! the schema, and the validator evolve.
//!
//! `chio-config` is not in the trust-boundary set per `OWNERS.toml`, but
//! the loader still ingests untrusted bytes, so this target focuses on
//! catching parse-path panics and allocator regressions rather than
//! security regressions.
//!
//! Reference: `.planning/trajectory/02-fuzzing-post-pr13.md` Phase 1
//! (trust-boundary fuzz target #10).

#![no_main]

use chio_config::fuzz::fuzz_chio_yaml_parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_chio_yaml_parse(data);
});
