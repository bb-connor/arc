#!/usr/bin/env bash
# Behavior tests for the target selection in .clusterfuzzlite/build.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_SCRIPT="${CFLITE_BUILD_SCRIPT:-${ROOT}/.clusterfuzzlite/build.sh}"
inventory_size="$(sed -n '/^TARGETS=(/,/^)/p' "${BUILD_SCRIPT}" | grep -cE '^[[:space:]]+[a-z0-9_]+$')"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
failures=0

mkdir -p "${work}/bin"
cat >"${work}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "metadata" ]]; then
    exit 0
fi
if [[ "$1" == "+nightly" && "$2" == "fuzz" && "$3" == "build" ]]; then
    printf '%s\n' "$4" >>"${CARGO_LOG}"
    mkdir -p target/x86_64-unknown-linux-gnu/release
    : >"target/x86_64-unknown-linux-gnu/release/$4"
    exit 0
fi
echo "unexpected cargo invocation: $*" >&2
exit 1
STUB
chmod +x "${work}/bin/cargo"

# run_build NAME SELECTION_MODE [LINES...]: SELECTION_MODE is none, file, or dir.
run_build() {
    local name="$1" mode="$2"
    shift 2
    local case_dir="${work}/${name}"
    mkdir -p "${case_dir}/src/chio/fuzz" "${case_dir}/src/chio/.clusterfuzzlite" "${case_dir}/out"
    case "${mode}" in
        file) printf '%s\n' "$@" >"${case_dir}/src/chio/.clusterfuzzlite/selected-targets" ;;
        dir) mkdir -p "${case_dir}/src/chio/.clusterfuzzlite/selected-targets" ;;
        none) ;;
    esac
    : >"${case_dir}/cargo.log"
    set +e
    (
        cd "${case_dir}"
        PATH="${work}/bin:${PATH}" SRC="${case_dir}/src" OUT="${case_dir}/out" \
            SANITIZER=address CARGO_LOG="${case_dir}/cargo.log" \
            bash "${BUILD_SCRIPT}"
    ) >"${case_dir}/output.log" 2>&1
    echo "$?" >"${case_dir}/rc"
    set -e
}

expect() {
    local name="$1" rc="$2" built="$3" needle="${4:-}"
    local case_dir="${work}/${name}"
    local actual_rc actual_built
    actual_rc="$(cat "${case_dir}/rc")"
    actual_built="$(sort "${case_dir}/cargo.log" | paste -sd, -)"
    if [[ "${actual_rc}" != "${rc}" || "${actual_built}" != "${built}" ]] \
        || { [[ -n "${needle}" ]] && ! grep -qF -- "${needle}" "${case_dir}/output.log"; }; then
        echo "FAIL ${name}: rc=${actual_rc} built=${actual_built}"
        sed 's/^/  /' "${case_dir}/output.log"
        failures=$(( failures + 1 ))
    else
        echo "PASS ${name}"
    fi
}

run_build no_selection_builds_inventory none
all_built="$(sed -n '/^TARGETS=(/,/^)/p' "${BUILD_SCRIPT}" | grep -E '^[[:space:]]+[a-z0-9_]+$' | tr -d ' ' | sort | paste -sd, -)"
expect no_selection_builds_inventory 0 "${all_built}"
if [[ "$(wc -l <"${work}/no_selection_builds_inventory/cargo.log")" -ne "${inventory_size}" ]]; then
    echo "FAIL no_selection_builds_inventory: expected ${inventory_size} builds"
    failures=$(( failures + 1 ))
fi

run_build selection_builds_subset file canonical_json "" " attest_verify " canonical_json
expect selection_builds_subset 0 "attest_verify,canonical_json" "building 2 of ${inventory_size} fuzz targets"
if [[ ! -e "${work}/selection_builds_subset/out/attest_verify" \
    || -e "${work}/selection_builds_subset/out/did_resolve" ]]; then
    echo "FAIL selection_builds_subset: out directory does not hold exactly the selection"
    failures=$(( failures + 1 ))
fi

run_build unknown_target_rejected file canonical_json not_a_target
expect unknown_target_rejected 1 "" "unknown target in"

run_build empty_selection_rejected file "" "  "
expect empty_selection_rejected 1 "" "names no targets"

run_build non_file_selection_rejected dir
expect non_file_selection_rejected 1 "" "is not a regular file"

# Every build script, the target map and the scheduled matrix name the same
# fuzz inventory.
inventory_of_build() {
    sed -n '/^TARGETS=(/,/^)/p' "$1" | grep -E '^[[:space:]]+[a-z0-9_]+$' | tr -d ' ' | sort
}
reference="$(sed -n 's/^\[targets\.\([a-z0-9_]*\)\]$/\1/p' "${ROOT}/fuzz/target-map.toml" | sort)"
matrix="$(sed -n '/fuzz-scheduled:/,/steps:/p' "${ROOT}/.github/workflows/fuzz.yml" \
    | sed -n 's/^ *- \([a-z0-9_]*\)$/\1/p' | sort)"
cargo_bins="$(awk '/^\[\[bin\]\]/ { in_bin = 1; next }
    in_bin && /^name = "/ { gsub(/^name = "|"$/, ""); print; in_bin = 0 }' \
    "${ROOT}/fuzz/Cargo.toml" | sort)"
for source in "${ROOT}/.clusterfuzzlite/build.sh" "${ROOT}/fuzz/oss-fuzz/build.sh" matrix cargo_bins; do
    case "${source}" in
        matrix) listed="${matrix}" ;;
        cargo_bins) listed="${cargo_bins}" ;;
        *) listed="$(inventory_of_build "${source}")" ;;
    esac
    if [[ "${listed}" != "${reference}" ]]; then
        echo "FAIL inventory_matches_target_map: ${source#"${ROOT}/"}"
        diff <(printf '%s\n' "${reference}") <(printf '%s\n' "${listed}") | sed 's/^/  /'
        failures=$(( failures + 1 ))
    else
        echo "PASS inventory_matches_target_map: ${source#"${ROOT}/"}"
    fi
done

if [[ "${failures}" -ne 0 ]]; then
    echo "${failures} cflite build selection case(s) failed"
    exit 1
fi
echo "PASS: cflite build selection"
