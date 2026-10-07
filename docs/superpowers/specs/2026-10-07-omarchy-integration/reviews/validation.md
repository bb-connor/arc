# Documentation validation record

Date: 2026-10-07. Scope: this proposed research/specification/plan package.
No plugin, controller, native adapter, confinement runtime or release was installed
or implemented by this change. All AT-* runtime cases remain proposed.

## Checks

| Check | Result and scope |
| --- | --- |
| Package verifier with self-test | Passed: 17 specs, 209 requirement/acceptance mappings, 6 schemas, 82 fixtures, 180 response substitutions and 29 validator mutants; documents/synthetic shapes only |
| Source research | Omarchy release/development source, public Pi/native source crosswalk, OMCP and Linux/systemd/Arch primary references inspected and pinned where available |
| Proposed plugin manifest | Passed the inspected upstream structural validator using temporary placeholder entry files; no QML behavior qualified |
| Independent review | All identified P2 issues addressed and re-reviewed; [finding record](independent-review.md) |
| Runner example regression | 32 persistent extracted-sample component tests passed on macOS arm64 and Linux aarch64: launch refusal, adopted-descendant reaping, phase parser, package inventory and release-lock controls; no Omarchy runtime conclusion |
| Python/JSON syntax | 26 Python snippets and retained validator/regression scripts parsed; 5 JSON snippets decoded, 12 Bash snippets passed syntax checks; 93 JSON documents parsed |
| `cargo fmt --all -- --check` | Passed |
| `cargo build --workspace` | Failed on pre-existing finding-worker product imports and missing method |
| `cargo test --workspace` | Failed during compilation on the same finding-worker product surface; no workspace test-pass claim |
| `cargo clippy --workspace -- -D warnings` | Failed during compilation on the same finding-worker product surface |

The Rust failures are outside this documentation diff. No Rust, Cargo manifest or
lockfile changes are included. The checked-out baseline failed with unresolved
imports from `chio_finding_worker` in
`crates/products/chio-finding-worker/src/main.rs` and
`crates/products/chio-finding-market-canary/src/main.rs`, plus missing
`FindingHostedProfile::load_worker_executor`. Build/test/clippy exited 101;
format checking exited 0. These failures were not repaired as part of the Omarchy
research proposal.

## Reproducible document command

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --write-traceability --self-test --write-validation
git diff --check
```

Use Python 3.11+ with the pinned [format-validation dependencies](../contracts/requirements-validation.txt); see the [isolated setup](../contracts/README.md). The verifier checks all numbered requirement
rows against their acceptance definitions, generated traceability, local Markdown
links/anchors, six JSON schemas, positive/negative fixtures and cross-method
response substitutions. It decodes all package JSON, rejects duplicate keys and
non-JSON constants, checks positive/negative requests for all 13 methods, and
classifies selected, unsupported and mismatched Hello versions. Its mutation
checks also cover malformed source pins/validation records, stale counts/content,
missing per-method negatives, wrong Hello outcomes and absent date-time checking.

The committed [document-validation.json](document-validation.json) is the final
structural-check output with a digest of package paths and content; normal
validation rejects stale records. Self-test results are reported separately by
the command and must pass before `--write-validation` can refresh the record. It is deliberately not a `release-evidence` artifact,
native receipt or proof that a named acceptance case executed. Hosted CI and
release publication are not asserted by this record.

## Review repair verification

All eight first-round hosted findings are addressed: the proposed package contains
the navigation opener and desktop/menu registration, launch failures retain named
prerequisite evidence, P0 through P7 parse, all package JSON is validated, task
evidence retains its native owner, unsupported Hello versions can negotiate a
typed refusal, each known method has negative request coverage, and date-time
validation has its required dependency. Strict string-end cases reject trailing
newlines in protocol/native/UUID/digest identifiers.

Re-run the retained extracted regressions from the repository root:

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/distribution-review-regressions.py
bash scripts/check-chio-proof-room-release-truth.sh
```

Both commands pass locally. The release-copy wording failure in plan 01 was
corrected by enumerating the controls whose navigation behavior must be checked.
The component suite does not execute the future Linux qualifier, build an Arch
package or close any proposed runtime acceptance.

## Second review round

The wire limit contract now requires a safe integer for `enforced`; null never
means an enforced ceiling. Invalid null/fraction/overflow fixtures and valid
zero/maximum controls pass. The retained
[scope matrix](scope-limit-review-regressions.py) checks 189 cases across all
seven dimensions and three enforcement states. Removing the conditional ceiling
check is independently rejected by a validator mutant.

```bash
/tmp/chio-omarchy-doc-validation/bin/python docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/scope-limit-review-regressions.py
```

The prerequisite examples pass 16 retained regression tests, including all 35
profile/artifact-removal cells, missing/extra profile inventories, unknown-profile
refusals and omission mutants for tuple/classification diagnostics. The synthetic
control remains unqualified, and removing a specific check now fails its test.

The distribution example passes 32 tests on macOS arm64 (Python 3.11.4) and Linux
aarch64 (kernel 6.8.0-64-generic, glibc 2.36, Python 3.11.2). The original suite
reproduced both descendant failures beneath a non-reaping Linux PID 1; the revised
dedicated subreaper worker completed with zero zombies in the final `/proc`
census. The container used existing local image `chio-docs-transcript:20260930`
with image ID `sha256:f4b2f90e4bb056cb523b2a86b1a393a9a67023383776e5bdea6864012a1ed163`,
a read-only checkout mount and no network. This proves only the extracted helper's
component behavior on that Linux environment, not non-root x86_64 Omarchy
confinement or package qualification. The complete-lock test also detects a
validator that checks missing fields while ignoring floating revisions.

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/prerequisite-review-regressions.py
```

Reproduce the Linux component run from this checkout using that retained local
image. Python PID 1 waits only for its direct test worker; leaked orphan zombies
remain visible to the final census:

```bash
validation_repo=$(pwd)
docker run --rm -i --network none \
  --mount "type=bind,src=$validation_repo,dst=/source,readonly" \
  --entrypoint python3 \
  sha256:f4b2f90e4bb056cb523b2a86b1a393a9a67023383776e5bdea6864012a1ed163 - <<'PYTHON'
import os
import subprocess
import sys
from pathlib import Path
assert os.getpid() == 1
result = subprocess.run([
    sys.executable,
    "/source/docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/distribution-review-regressions.py",
], timeout=30)
zombies = []
for path in Path("/proc").glob("[0-9]*/stat"):
    try:
        state = path.read_text().rsplit(") ", 1)[1].split()[0]
    except FileNotFoundError:
        continue
    if state == "Z":
        zombies.append(path.parent.name)
print("Remaining zombie PIDs:", zombies)
sys.exit(result.returncode or bool(zombies))
PYTHON
```

The concurrent non-normative architecture review is preserved unchanged. Its
product/sequence decisions remain review input; these line-level bot repairs do
not implement or claim resolution of that separate architecture review.
