#!/usr/bin/env bash
# Release preflight gate.
#
# Runs the mechanical checks that must be green before release closeout work
# starts. Manual items such as release-tag policy, scope lock, and owner
# assignment stay in the release board.
#
# Exits 0 only if every check passes; otherwise prints a summary of failures
# and exits with the count of failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PLAN_ROOT=".$(printf '%s' planning)"
RELEASE_INPUT_DIR="${PLAN_ROOT}/trajectory-3"
RELEASE_CLOSEOUT_DIR="${PLAN_ROOT}/trajectory-4"

passes=()
fails=()

pass() {
    passes+=("$1")
    printf "  PASS  %s\n" "$1"
}
fail() {
    fails+=("$1")
    printf "  FAIL  %s\n" "$1"
}

section() {
    printf "\n[%s]\n" "$1"
}

#-- 1. Threat-coverage gate ----------------------------------------------------
section "threat-coverage gate"
if bash scripts/check-threat-coverage.sh > /tmp/chio-preflight-threat.log 2>&1; then
    covered=$(grep -E '^  covered:' /tmp/chio-preflight-threat.log | awk '{print $2}')
    pending=$(grep -E '^  pending:' /tmp/chio-preflight-threat.log | awk '{print $2}')
    uncovered=$(grep -E '^  uncovered:' /tmp/chio-preflight-threat.log | awk '{print $2}')
    pass "scripts/check-threat-coverage.sh PASS at ${covered}/${pending}/${uncovered} (covered/pending/uncovered)"
else
    fail "scripts/check-threat-coverage.sh did not return 0; see /tmp/chio-preflight-threat.log"
fi

if bash scripts/check-threat-coverage-mutants.sh > /tmp/chio-preflight-threat-mutants.log 2>&1; then
    passed=$(grep -E '^  passed:' /tmp/chio-preflight-threat-mutants.log | awk '{print $2}')
    pass "scripts/check-threat-coverage-mutants.sh PASS at ${passed} release-covered threat row(s)"
else
    fail "scripts/check-threat-coverage-mutants.sh did not return 0; placeholder or missing mutants evidence is not release-covered; see /tmp/chio-preflight-threat-mutants.log"
fi

#-- 2. Required release workflows present --------------------------------------
section "release workflows"
for wf in release-binaries.yml slsa.yml reproducible-build.yml; do
    if [[ -f ".github/workflows/${wf}" ]]; then
        pass ".github/workflows/${wf} present"
    else
        fail ".github/workflows/${wf} missing"
    fi
done

#-- 3. Spec registries (the Evidence Gate substrate) --------------------------
section "spec registries"
for reg in claim-registry.v1.json proof-manifest.v1.json theorem-inventory.v1.json README.md; do
    if [[ -f "spec/registries/${reg}" ]]; then
        pass "spec/registries/${reg} present"
    else
        fail "spec/registries/${reg} missing"
    fi
done

#-- 4. CI-DEBT.md exists at known path -----------------------------------------
section "CI-DEBT"
debt_path="${RELEASE_INPUT_DIR}/work/CI-DEBT.md"
if [[ -f "${debt_path}" ]]; then
    pass "CI-DEBT.md present"
    if grep -q 'requires-individual-replay-or-deferral' "${debt_path}"; then
        bucket_count=$(awk '/^## requires-individual-replay-or-deferral/,/^## /' "${debt_path}" | grep -cE '^- ' || true)
        if [[ "${bucket_count}" -eq 0 ]]; then
            pass "CI-DEBT.md requires-individual-replay-or-deferral bucket is empty"
        else
            fail "CI-DEBT.md requires-individual-replay-or-deferral bucket has ${bucket_count} entries"
        fi
    else
        pass "CI-DEBT.md has no requires-individual-replay-or-deferral bucket (already drained)"
    fi
else
    fail "CI-DEBT.md missing"
fi

#-- 5. TRAJECTORY-FINAL.md present + no TODO markers ---------------------------
section "TRAJECTORY-FINAL.md"
final_path="${RELEASE_INPUT_DIR}/TRAJECTORY-FINAL.md"
if [[ -f "${final_path}" ]]; then
    pass "TRAJECTORY-FINAL.md present"
    todo_count=$(grep -c -E 'TODO|TBD|FIXME' "${final_path}" || true)
    if [[ "${todo_count}" -eq 0 ]]; then
        pass "TRAJECTORY-FINAL.md has zero TODO/TBD/FIXME markers"
    else
        fail "TRAJECTORY-FINAL.md has ${todo_count} TODO/TBD/FIXME markers"
    fi
else
    fail "TRAJECTORY-FINAL.md missing"
fi

#-- 6. releases.toml present ---------------------------------------------------
section "releases.toml"
if [[ -f "releases.toml" ]]; then
    pass "releases.toml present"
else
    fail "releases.toml missing"
fi

#-- 7. No open legacy release PRs ---------------------------------------------
section "legacy release PR cascade"
if command -v gh > /dev/null 2>&1; then
    legacy_prefix="$(printf 'trj%s/' '3.2')"
    open_count=$(gh pr list --state open --limit 200 --json headRefName --jq '[.[] | select(.headRefName | startswith("'"${legacy_prefix}"'"))] | length' 2>/dev/null || echo "?")
    if [[ "${open_count}" == "0" ]]; then
        pass "zero open legacy release PRs"
    elif [[ "${open_count}" == "?" ]]; then
        fail "could not query GitHub for open legacy release PRs (gh CLI not authenticated?)"
    else
        fail "${open_count} open legacy release PR(s) remaining"
    fi
else
    fail "gh CLI not available; cannot verify legacy release PR cascade is drained"
fi

#-- 8. Audit doc set present ---------------------------------------------------
section "audit doc set"
expected=(
    "T0.A-substrate-closeout.md"
    "T0.B-substrate-hardening.md"
    "T0.C-mobile-attestation.md"
    "T0.D-threat-coverage.md"
    "T1.0-capability-negotiation.md"
    "T1.1-macaroon-attenuation.md"
    "T1.2-receipt-dag.md"
    "T1.3-anchor-batch.md"
    "T1.4-archaeology.md"
    "T1.5-sre-foundations.md"
    "T1.6-chio-explain.md"
    "T2.1-hybrid-pq-cross-surface.md"
)
for doc in "${expected[@]}"; do
    if [[ -f "${RELEASE_CLOSEOUT_DIR}/audits/${doc}" ]]; then
        pass "audit/${doc} present"
    else
        fail "audit/${doc} missing"
    fi
done

#-- 9. EXECUTION-BOARD + SYNTHESIS-V2 present ----------------------------------
section "core planning docs"
for doc in EXECUTION-BOARD.md SYNTHESIS-V2-INTEGRATED-PLAN.md README.md BRAINSTORM-V1-FEATURE-CATALOG.md REJECTED-IDEAS.md; do
    if [[ -f "${RELEASE_CLOSEOUT_DIR}/${doc}" ]]; then
        pass "${doc} present"
    else
        fail "${doc} missing"
    fi
done

#-- 10. Close-bar tracker gate -------------------------------------------------
section "close-bar tracker"
if bash scripts/check-close-bar-tracker.sh > /tmp/chio-release-closure.log 2>&1; then
    rows=$(grep -E '^  rows:' /tmp/chio-release-closure.log | awk '{print $2}')
    done_=$(grep -E '^  DONE:' /tmp/chio-release-closure.log | awk '{print $2}')
    partial=$(grep -E '^  PARTIAL:' /tmp/chio-release-closure.log | awk '{print $2}')
    none=$(grep -E '^  NONE:' /tmp/chio-release-closure.log | awk '{print $2}')
    pass "scripts/check-close-bar-tracker.sh PASS at ${rows} rows (DONE=${done_} / PARTIAL=${partial} / NONE=${none})"
else
    fail "scripts/check-close-bar-tracker.sh did not return 0; see /tmp/chio-release-closure.log"
fi

#-- 11. Em-dash + trailing-whitespace gate -------------------------------------
section "doc-style gate"
em_total=0
ws_total=0
for f in "${RELEASE_CLOSEOUT_DIR}"/*.md "${RELEASE_CLOSEOUT_DIR}"/audits/*.md spec/registries/*.md; do
    [[ -f "$f" ]] || continue
    em=$(grep -c $'\xe2\x80\x94' "$f" 2>/dev/null || true)
    ws=$(grep -c '[[:space:]]$' "$f" 2>/dev/null || true)
    em_total=$((em_total + em))
    ws_total=$((ws_total + ws))
done
if [[ "${em_total}" -eq 0 ]]; then
    pass "zero em-dashes across release docs"
else
    fail "${em_total} em-dash matches across release docs"
fi
if [[ "${ws_total}" -eq 0 ]]; then
    pass "zero trailing-whitespace lines across release docs"
else
    fail "${ws_total} trailing-whitespace lines (git diff --check)"
fi

#-- summary --------------------------------------------------------------------
printf "\n[summary]\n"
printf "  passes: %d\n" "${#passes[@]}"
printf "  fails:  %d\n" "${#fails[@]}"

if [[ "${#fails[@]}" -gt 0 ]]; then
    printf "\nfailures:\n"
    for f in "${fails[@]}"; do
        printf "  - %s\n" "$f"
    done
    exit "${#fails[@]}"
fi

printf "\nrelease preflight: GREEN.\n"
exit 0
