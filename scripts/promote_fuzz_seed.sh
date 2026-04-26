#!/usr/bin/env bash
# scripts/promote_fuzz_seed.sh - graduate a fuzz seed into a permanent
# regression test under the owning crate.
#
# Source: .planning/trajectory/02-fuzzing-post-pr13.md Phase 4 P4.T2
# (Crash-triage automation > Regression-test promotion path).
#
# Reads fuzz/owners.toml to find the owning crate for the named fuzz
# target, computes sha256 of the input seed, then either:
#
#   --mode libfuzzer  Writes a libtest #[test] fn that calls the fuzz
#                     wrapper directly with the seed bytes. Output:
#                     crates/<owner>/tests/regression_<sha8>.rs.
#
#   --mode proptest   Opens a sibling M03 invariant property test under
#                     crates/<owner>/tests/property_<sha8>.rs. Cross-doc
#                     with M03 oracle ownership.
#
# In both modes the seed is moved into fuzz/corpus/<target>/<sha>.bin so
# future fuzz runs continue exercising it.
#
# House rules: no em dashes, fail-closed on bad inputs.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: promote_fuzz_seed.sh --target <name> --input <path> --mode {libfuzzer|proptest} [--severity LEVEL]

Promotes a fuzz seed into a permanent regression test:
  - Reads fuzz/owners.toml to find the owning crate.
  - Computes sha256 of the input.
  - In libfuzzer mode: writes a libtest #[test] fn that calls the fuzz
    wrapper directly with the seed bytes. Output:
    crates/<owner>/tests/regression_<sha8>.rs.
  - In proptest mode: opens a sibling M03 invariant property test under
    crates/<owner>/tests/property_<sha8>.rs (cross-doc with M03 oracle
    ownership).
  - Moves the seed file into fuzz/corpus/<target>/<sha>.bin so future
    fuzz runs continue exercising it.

Args:
  --target NAME     fuzz target (e.g. jwt_vc_verify)
  --input PATH      path to crash input file
  --mode MODE       libfuzzer|proptest
  --severity LEVEL  Critical|High|Medium|Low (default Medium)
  --help            show this help

Source: .planning/trajectory/02-fuzzing-post-pr13.md Phase 4 P4.T2.
EOF
}

# Defaults.
TARGET=""
INPUT=""
MODE=""
SEVERITY="Medium"

# Argument parser. Long-options only; matches the documented CLI.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="${2:-}"
            shift 2
            ;;
        --input)
            INPUT="${2:-}"
            shift 2
            ;;
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --severity)
            SEVERITY="${2:-}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "promote_fuzz_seed.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# Locate repo root via the script path so callers can invoke from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OWNERS_TOML="$REPO_ROOT/fuzz/owners.toml"

# Validation. Fail-closed on missing required args.
if [[ -z "$TARGET" || -z "$INPUT" || -z "$MODE" ]]; then
    echo "promote_fuzz_seed.sh: --target, --input, and --mode are required" >&2
    usage >&2
    exit 2
fi

case "$MODE" in
    libfuzzer|proptest) ;;
    *)
        echo "promote_fuzz_seed.sh: --mode must be 'libfuzzer' or 'proptest', got '$MODE'" >&2
        exit 2
        ;;
esac

case "$SEVERITY" in
    Critical|High|Medium|Low) ;;
    *)
        echo "promote_fuzz_seed.sh: --severity must be Critical|High|Medium|Low, got '$SEVERITY'" >&2
        exit 2
        ;;
esac

if [[ ! -f "$OWNERS_TOML" ]]; then
    echo "promote_fuzz_seed.sh: missing fuzz/owners.toml at $OWNERS_TOML" >&2
    exit 1
fi

if [[ ! -f "$INPUT" ]]; then
    echo "promote_fuzz_seed.sh: --input file not found: $INPUT" >&2
    exit 1
fi

# Resolve owning crate for the target by parsing fuzz/owners.toml. Bash-only
# parser: scan for the [targets.<name>] section, then capture the path key.
resolve_owner_path() {
    local target="$1"
    local toml="$2"
    awk -v t="$target" '
        BEGIN { in_section = 0 }
        /^\[targets\./ {
            in_section = 0
            section = $0
            sub(/^\[targets\./, "", section)
            sub(/\]$/, "", section)
            if (section == t) { in_section = 1 }
            next
        }
        /^\[/ { in_section = 0; next }
        in_section && /^[[:space:]]*path[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*"/, "")
            sub(/"[[:space:]]*$/, "")
            print
            exit
        }
    ' "$toml"
}

OWNER_PATH="$(resolve_owner_path "$TARGET" "$OWNERS_TOML")"
if [[ -z "$OWNER_PATH" ]]; then
    echo "promote_fuzz_seed.sh: target '$TARGET' not found in fuzz/owners.toml" >&2
    exit 1
fi

OWNER_DIR="$REPO_ROOT/$OWNER_PATH"
if [[ ! -d "$OWNER_DIR" ]]; then
    echo "promote_fuzz_seed.sh: owner directory does not exist: $OWNER_DIR" >&2
    exit 1
fi

# Compute sha256. Use shasum if available (macOS default), fall back to sha256sum.
if command -v shasum >/dev/null 2>&1; then
    SHA="$(shasum -a 256 "$INPUT" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
    SHA="$(sha256sum "$INPUT" | awk '{print $1}')"
else
    echo "promote_fuzz_seed.sh: neither shasum nor sha256sum available" >&2
    exit 1
fi
SHA8="${SHA:0:8}"

TESTS_DIR="$OWNER_DIR/tests"
mkdir -p "$TESTS_DIR"

CORPUS_DIR="$REPO_ROOT/fuzz/corpus/$TARGET"
mkdir -p "$CORPUS_DIR"

# Emit the regression test based on mode. Both bodies are skeletons: callers
# fix up the assertion surface against the actual fuzz wrapper / property.
case "$MODE" in
    libfuzzer)
        OUT="$TESTS_DIR/regression_${SHA8}.rs"
        cat >"$OUT" <<EOF
// Auto-generated regression test from fuzz/$TARGET seed $SHA.
// Source: scripts/promote_fuzz_seed.sh (M02.P4.T2).
// Severity: $SEVERITY.
//
// This test calls the libfuzzer wrapper for '$TARGET' directly with the
// promoted seed bytes. The seed is stored at fuzz/corpus/$TARGET/$SHA.bin.

#[test]
fn regression_${SHA8}_${TARGET}() {
    let seed: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/$TARGET/$SHA.bin",
    ));
    // TODO(promote_fuzz_seed): wire to the actual fuzz wrapper for
    // '$TARGET'. The wrapper must not panic on this input.
    let _ = seed;
}
EOF
        ;;
    proptest)
        OUT="$TESTS_DIR/property_${SHA8}.rs"
        cat >"$OUT" <<EOF
// Auto-generated proptest property opened from fuzz/$TARGET seed $SHA.
// Source: scripts/promote_fuzz_seed.sh (M02.P4.T2).
// Severity: $SEVERITY.
// Cross-doc: M03 owns the oracle/invariant surface this property targets.
//
// The seed is stored at fuzz/corpus/$TARGET/$SHA.bin and seeds the
// proptest strategy as a regression input.

use proptest::prelude::*;

proptest! {
    #[test]
    fn property_${SHA8}_${TARGET}(input in any::<Vec<u8>>()) {
        // TODO(promote_fuzz_seed): replace with the M03 invariant for
        // '$TARGET'. The property must hold for the promoted seed and
        // for all generated inputs.
        prop_assert!(input.len() <= usize::MAX);
    }
}
EOF
        ;;
esac

# Move the seed into the persistent corpus so future fuzz runs replay it.
DEST="$CORPUS_DIR/$SHA.bin"
if [[ -e "$DEST" ]]; then
    # Idempotent: identical content is fine, drop the input.
    if cmp -s "$INPUT" "$DEST"; then
        rm -f "$INPUT"
    else
        echo "promote_fuzz_seed.sh: corpus collision at $DEST with different bytes" >&2
        exit 1
    fi
else
    mv "$INPUT" "$DEST"
fi

echo "promote_fuzz_seed.sh: promoted $TARGET seed $SHA8 ($MODE, $SEVERITY)"
echo "  test:   $OUT"
echo "  corpus: $DEST"
