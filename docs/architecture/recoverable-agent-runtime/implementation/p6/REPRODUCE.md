# Reproduce P6 evidence

Audit the retained package from this checkout without a provider call or cloud
mutation. The harness suite requires the pinned Python environment described
below; its SDK sources must come from this checkout:

```sh
python3 docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/verify-package.py
python3 -m unittest discover \
  -s docs/architecture/recoverable-agent-runtime/implementation/p6/evidence \
  -p 'test_*.py'
PYTHONPATH=sdks/python/chio-sdk-python/src:sdks/python/chio-adapter-base/src:sdks/python/chio-langgraph/src:sdks/python/chio-crewai/src \
  python -m unittest discover -s fixtures/recovery-product -p 'test_*.py'
```

The package auditor recomputes current runtime and qualification-source hashes,
the source archive, exact gate commands and log counts, Linux profile/challenge,
all observed native trial facts, planned interrupted slots, matched authority,
per-stratum reports, performance thresholds, assurance source mapping, review
coverage and immutable P5 artifacts. Missing, changed or stale inputs refuse.
It does not turn historical sources into a current-tree acceptance claim.

`evidence/local-gates.json` and `evidence/catalog.py` retain the 33 exact local
commands and working directories. `evidence/final-linux-postfix/results.json`
retains all four complete Linux commands rerun after the Rust review fix,
nonzero counts and final source stability. The earlier reviewed Linux execution
remains under `evidence/final-linux/`.
`source-snapshot.json` preserves the original fresh review archive and verdict;
`final-source-snapshot.json` identifies the final source archive. The review
manifest separately binds every primary fix and its owning RED/GREEN evidence.
The original runtime archive remains under `evidence/live-manifest/`; the final
precollection runtime archive is `evidence/live-manifest-final/`.

For new real Linux acceptance, use an isolated x86_64 Linux host with GNU and
musl Rust 1.94.1, actual qualified static cage images and the native SQLite
stores. Do not substitute cross compilation for runtime probes. Run the exact
Linux commands from the retained record with normal stack sizes and a new
host-generated cage challenge. The current acceptance host uses Ubuntu 24.04,
kernel 7.0.0-1012-oracle on E4, 8 OCPUs, 64 GiB, debug profile with debug info
disabled. P5 retains its original 6.17.0-1020-oracle profile separately.
The original P5 image archive and its eleven hashes remain unchanged.

For a new model campaign, create a new isolated evidence destination. Install
the exact retained `evidence/host-dependencies.txt`, overlay this checkout's SDK
sources and keep credentials exclusively in the provider-host environment.
Disable optional telemetry. The native child must receive no provider key.
Use the public synthetic authority/task files, then run all eight actual
model-free host/workflow/arm preflights. Declare and seal a new source/corpus
manifest before the first provider completion. Never overwrite the existing
manifest, failed cohort or trial identities.

```sh
python fixtures/recovery-product/preflight.py \
  --checkout "$RECOVERY_CHECKOUT" --evidence new-native-preflight
```

This shipped entry point uses scripted external inputs with zero provider
requests. Its native facts and actual framework invocations remain outside the
live denominator. `evidence/final-host-preflight/` retains all eight cases and
their final source binding; the auditor independently checks each native log,
authority contract, returned facts and CrewAI-visible frame.

The builder's default model is the retained original mini-model. To declare the
qualified candidate's model/protocol before collecting any data, update the new
manifest to the exact full model and pinned CrewAI contract, then recalculate
its hash. Both arms must consume that identical declaration:

```sh
python fixtures/recovery-product/manifest_builder.py \
  --authority-contract authority-contract.json --destination new-live-manifest
python3 - <<'PY'
import hashlib, json
from pathlib import Path
p = Path('new-live-manifest/manifest.json')
manifest = json.loads(p.read_bytes())
manifest['model'] = 'gpt-5.4-2026-03-05'
manifest['framework_protocol'] = {
    'crewai': 'BaseLLM._apply_stop_words before CrewAI parsing; retain provider output and framework-visible frame; no action synthesis or retry',
    'langgraph': 'unchanged closed explicit action parser',
}
p.write_text(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + '\n')
p.with_suffix('.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest() + '\n')
PY
python fixtures/recovery-product/campaign_main.py \
  --manifest new-live-manifest/manifest.json \
  --checkout "$RECOVERY_CHECKOUT" --evidence new-live-campaign
```

The runner requires the real native Rust helper and pinned framework/provider
packages. It does not offer an offline fake-provider qualification mode. The
model has four calls, eight tool actions, bounded prompt/output/deadlines and
zero transport retries. Framework failure or a skipped tool remains a measured
outcome. Exact tasks, actors, authority, budgets and provider behavior match
both arms. Unsupported OpenAPPA semantics are excluded explicitly.

`evidence/live-report.json` recomputes from all five retained row files and the
explicit interruption inventory. Per-trial logs and native facts remain beside
those files; private fixture capability material is synthetic and scoped.

```sh
python3 docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/cohort_report.py \
  --manifest docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live-manifest/manifest.json \
  --initial docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live/initial-account-quota-failure/results.jsonl \
  --qualified docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live/available-account-qualification/results.jsonl \
  --capable-manifest docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live-manifest-capable/manifest.json \
  --capable docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live/capable-model-qualification/results.jsonl \
  --corrected-manifest docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live-manifest-corrected/manifest.json \
  --corrected docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live/corrected-framework-qualification/results.jsonl \
  --review-fix-manifest docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live-manifest-final/manifest.json \
  --review-fix docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/live/review-fix-qualification/results.jsonl \
  --interruption docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/initial-interruption.json \
  --prompt-gaps docs/architecture/recoverable-agent-runtime/implementation/p6/evidence/prior-prompt-gaps.json \
  --output /tmp/recovery-p6-recomputed-report.json
```

The original interruption is a task-owned shutdown-timer error, not an
account-independent provider or cloud outage. Unknown effects/tokens/labels
cannot be reconstructed as zero. Provider credentials and raw provider error bodies are
absent from the public package.

Final performance uses the predeclared isolated Linux profile. Reconstruct the
exact immutable P0 reference from commit `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`
and `evidence/p0-reference-overlay.tar.gz`, checking all 293 source hashes in
`evidence/p0-reference-inventory.json`. Precompile P0 and current P6, then run
both with identical Linux hardware, Rust 1.94.1, debug profile, zero debug info
and default stack sizes while other task jobs are finished. The native command explicitly runs the ignored
`measured_native_baseline` test with `--ignored --nocapture`; omission is not
acceptance. Its 64 samples, eight warmups, eight replays and 72 effects/charges
remain in `evidence/performance.json`. Pure measurements use the retained
`p0_baseline` example, 1000 samples and 100 warmups per budget. Do not raise a
ceiling after measuring a failure.

`evidence/matched-linux-performance-declaration.json` is sealed before any new
E6 Linux benchmark measurement. `evidence/matched-linux-performance/` retains both
subjects, all four raw measurement logs, build logs, exact commands and profile.
The effective native p95 limit is the tighter of 220683049 ns and the unchanged
P0 formula floor(6 * matched Linux P0 p95 / 5) + 1000000 ns. All original Mac
measurements remain separately retained. A current Mac run failed at 450534584 ns;
the user reports no quiet period, and current Mac performance is unqualified.

The finite models are abstractions with explicit uncovered seams.
`evidence/assurance-map.json` binds their current source bytes, owning functions
and actual native/parser/concurrency cutpoint tests. `evidence/model-current/`
retains compiler, outputs and twenty rejected invariant mutations. Loom's
eighteen tests include one shipped Session model and foundation replicas; they
do not prove the complete kernel, SQLite transactions or external providers.

The capable-model precollection manifest/declaration has an explicit custody
correction addendum, sealed before any trial began. The later corrected-framework
manifest separately declares the pinned stop protocol before its first live
trial. The fifth cohort is declared after the primary Rust and preflight fixes,
using the same exact full model, tasks, authority, versions, stop protocol,
budgets and thresholds. All six runtime source changes are enumerated and
audited against the original reviewed runtime. All five cohorts account for
480 planned slots; no earlier row is overwritten or silently repaired.
`evidence/prior-prompt-gaps.json` identifies the
25 earlier attempts whose mutable saved prompt objects no longer reproduce the
recorded request hash. No prompt is reconstructed or repaired. The current
qualification requires exact independent snapshots and exact recomputation of
the CrewAI-visible frame. A model that omits an action remains unsuccessful;
the actual pinned-framework regression proves that this correction cannot
turn a standalone final answer into a tool invocation. Raw provider output and
token usage remain intact even when the framework receives a shorter frame.

`evidence/performance-provenance.json` binds fresh native and pure measurements
to the complete final runtime inventory. The original passing measurements,
their earlier source-isolation argument and every later noisy measurement remain
separately retained. The Rust review fix requires fresh measurements and all
four Linux suites; the earlier source-isolation argument cannot certify it.
The final same-host performance pairing is Linux P0/P6 with both numeric bounds
enforced, rather than relabeling the earlier Mac baseline as a Linux measurement.
All 33 local gates are rerun at the final runtime binding. The single fresh
whole-phase review retains its original two P1 findings; the primary TDD fix
pass resolves them with explicit deltas and complete affected gates. It is not
represented as a second fresh review of the final bytes.

The final performance host is VM.Standard.E6.Flex with eight OCPUs/64 GiB,
AMD EPYC 9J45, kernel 7.0.0-1012-oracle and default stack sizes. Verify actual
OCI guest metadata against the predeclared profile before measuring. Its P0
p95 is 128652683 ns and P6 p95 142600820 ns; the effective original-formula
ceiling is 155383219 ns, tighter than the original 220683049 ns absolute bound.
All four pure budgets passed with unchanged denominators. The earlier complete
E4 attempt remains under `evidence/matched-linux-performance-e4-failed/`, with
its original declaration in `evidence/matched-linux-performance-declaration-e4.json`.
It failed at P6 p95 224502188 ns and also exposed a stale declared kernel.
The package independently recomputes that failed classification and raw values;
no earlier measurement is overwritten or selected into acceptance.
