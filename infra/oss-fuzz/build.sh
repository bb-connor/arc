#!/usr/bin/env bash
#
# OSS-Fuzz build entry point for Chio (formerly ARC).
#
# Builds every chio-fuzz target listed below and copies the resulting
# binary into $OUT/<target>, plus a per-target seed corpus zip when one
# exists under fuzz/corpus/<target>/.
#
# Source-of-truth: .planning/trajectory/02-fuzzing-post-pr13.md
# (OSS-Fuzz application steps section). Companion docs in
# docs/fuzzing/continuous.md (OSS-Fuzz integration section).

set -euo pipefail

# Move into the standalone fuzz workspace. cargo-fuzz emits binaries under
# the workspace's target/ tree, namespaced by host triple; OSS-Fuzz builders
# run on x86_64-unknown-linux-gnu.
cd "$SRC/arc/fuzz"

TARGETS=(
    attest_verify
    jwt_vc_verify
    oid4vp_presentation
    did_resolve
    anchor_bundle_verify
    mcp_envelope_decode
    a2a_envelope_decode
    acp_envelope_decode
    wasm_preinstantiate_validate
    wit_host_call_boundary
    chio_yaml_parse
    openapi_ingest
    receipt_log_replay
    canonical_json
    capability_receipt
    manifest_roundtrip
)

for target in "${TARGETS[@]}"; do
    cargo +nightly fuzz build "$target" --release --sanitizer "$SANITIZER"
    cp "../target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

    # Pack the per-target seed corpus when one exists in-tree.
    if [ -d "corpus/$target" ] && [ -n "$(ls -A "corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target"/*
    fi
done
