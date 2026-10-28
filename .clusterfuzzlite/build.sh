#!/usr/bin/env bash
#
# ClusterFuzzLite build entry point for Chio.
#
# Builds the chio-fuzz targets listed below and copies each resulting
# binary into $OUT/<target>, plus a per-target seed corpus zip when one
# exists under fuzz/corpus/<target>/. A workflow restricts the build to a
# subset through .clusterfuzzlite/selected-targets (see below).
#
# Companion docs in docs/fuzzing/continuous.md (ClusterFuzzLite bridge section).
#
# This script mirrors fuzz/oss-fuzz/build.sh. The two scripts MUST enumerate
# the same target set; the OSS-Fuzz copy is the source-of-truth, so any new
# fuzz target lands in BOTH files in the same change set.

set -euo pipefail

# Move into the standalone fuzz workspace. cargo-fuzz emits binaries under
# the workspace's target/ tree, namespaced by host triple; CFLite builders
# run on x86_64-unknown-linux-gnu.
cd "$SRC/chio/fuzz"
cargo metadata --locked --format-version 1 --no-deps >/dev/null

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
    wasm_guard_escape
    wasm_guard_smith
    wit_host_call_boundary
    chio_yaml_parse
    openapi_ingest
    receipt_log_replay
    eval_receipt_bundle
    canonical_json
    capability_receipt
    manifest_roundtrip
    federation_trust_establishment
    finding_worker_protocol
    frost_round2_envelope
    response_authority_protocol
    response_lifecycle
    underwriting_policy_input
    settlement_approval_witness
    fuzz_policy_parse_compile
    policy_analyze
    fuzz_sql_parser
    fuzz_merkle_checkpoint
    revocation_oracle_merkle
    rollback_anchor_slots
    commerce_receipt_verify
    peers_lock_decode
    decision_model_artifact
    fuzz_tool_action
)

# The ClusterFuzzLite actions do not forward workflow environment into the
# builder container, so workflows select a subset by writing target names, one
# per line, to .clusterfuzzlite/selected-targets in the checkout before
# build_fuzzers runs. The checkout is the container's $SRC/chio. Without that
# file every target is built.
selection_file="$SRC/chio/.clusterfuzzlite/selected-targets"
selected_targets=("${TARGETS[@]}")
if [ -e "$selection_file" ]; then
    if [ ! -f "$selection_file" ]; then
        echo "$selection_file is not a regular file" >&2
        exit 1
    fi
    mapfile -t requested_targets < <(sed -e 's/[[:space:]]//g' -e '/^$/d' "$selection_file" | sort -u)
    if [ "${#requested_targets[@]}" -eq 0 ]; then
        echo "$selection_file names no targets" >&2
        exit 1
    fi
    selected_targets=()
    for requested in "${requested_targets[@]}"; do
        found=false
        for target in "${TARGETS[@]}"; do
            if [ "$target" = "$requested" ]; then
                found=true
                selected_targets+=("$target")
                break
            fi
        done
        if [ "$found" != "true" ]; then
            echo "unknown target in $selection_file: $requested" >&2
            exit 1
        fi
    done
fi
echo "building ${#selected_targets[@]} of ${#TARGETS[@]} fuzz targets: ${selected_targets[*]}"

for target in "${selected_targets[@]}"; do
    features=""
    case "$target" in
        response_authority_protocol|response_lifecycle) features="$target" ;;
    esac
    cargo +nightly fuzz build "$target" --features "$features" --release --sanitizer "$SANITIZER"
    cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

    # Pack the per-target seed corpus when one exists in-tree.
    if [ -d "corpus/$target" ] && [ -n "$(ls -A "corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target"/*
    fi
done
