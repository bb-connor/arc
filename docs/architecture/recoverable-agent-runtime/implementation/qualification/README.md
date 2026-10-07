# Current qualification records

The current recovery tree is unqualified until current byte-bound acceptance,
independent review, Linux execution, live provider trials, formal runs and hosted
CI are complete. [STATUS.md](../STATUS.md) is the current verdict. Historical
phase packages retain their original artifacts and describe their archived
bytes.

The maintained auditor is
[`scripts/verify-recovery-qualification.py`](../../../../../scripts/verify-recovery-qualification.py).
It imports only the Python standard library and owns the versioned command
catalog. It never executes an archived package's Python modules or imports
mutable fixture modules to decide whether archived bytes are intact.

```sh
python3 -B scripts/verify-recovery-qualification.py --catalog
python3 -B scripts/verify-recovery-qualification.py --inventory --source-root "$PWD"
```

The current inventory version is `chio.source-inventory.v3`. Its binding includes the
base commit, the inventory version, and the complete ordered source rows. The
current runtime inventory includes clean tracked inputs and new Git-visible
inputs, contained source aliases, workspace members, model sources and build
configuration. It refuses case aliases, escaping links and cycles. Source
archive members are read through held regular-file descriptors, hashed from
the same bytes that are archived, and published by an atomic rename after all
members pass validation. A failed archive does not replace a completed one.

Version 3 includes Git-visible secret-shaped paths as declared metadata-only
rows. It records their state and permissions through held directory descriptors;
it does not read or hash their contents, follow their links, or add their bytes
to the source archive. Missing and unreachable paths retain their observed
states. Secret metadata and public byte rows share one collision check. Existing
version 2 inventories and every sealed historical package retain their original
version and bytes; their hashes cannot be promoted to version 3 bindings.

## Record and replay a current gate

Use the exact command, working directory and critical environment from the
auditor's catalog. Record the complete allowlisted environment, including PATH,
TMPDIR and any Cargo home/toolchain settings, in `start.json`. Preserve command
exit, runner exit, log hash, executable hash, and source manifests separately.
One successful process exit cannot substitute for a source-stable run.

Capture both full provenance manifests and versioned runtime inventories before
and after execution. The runtime inventories bind materialized aliases and any
reviewed public fixture inputs needed by the compiled profile; a metadata-only
exclusion in a broader provenance policy does not prove their bytes. Every
required source row must match both runtime inventories.

The current cross-host origin format is `chio.rust-profile-source-origin.v2`.
It requires actual `chio.confined-source-snapshot.v2` producer and receiver
records. Their `chio.source-location.v1` observations bind the canonical
repository, host and held directory identity. The first source location must
name the original repository; every subsequent source location must equal the
previous receiver location. Earlier records retain their versions and cannot
acquire this evidence by changing an envelope.

A transport stage also retains the original send result, its actual source
captures before and after transfer, and its exact stdout receiver receipt.
All must join the same archive, snapshot, source binding and candidate. Native
transport requires the observed Linux x86_64 receiver, owner UID 501, private
directory mode 0700 and enabled native profile check. Local preparation retains
its actual platform and owner; it does not establish Linux acceptance. Failed
or timed-out attempts remain failed when a late receiver result is retrieved.

The archive begins with its bounded metadata manifest. Original Git metadata,
the reserved manifest name as a source input, excluded payload bytes, absolute
source links and unrepresentable metadata states are refused. The separately
retained runner must match the mandatory captured source runner; the transfer
utility has its own retained pin. Cache-mode normalization is admitted only
for an independently classified cache path under the exact supported policy.

For commands inside a received candidate, both complete source captures must
match the final full guest inventory, including unselected original source
bytes and regular-file modes and sizes. Their index describes newly generated
empty discovery blobs and absent HEAD. The separate runtime v3 projection
preserves the original qualification identity without inventing guest Git
history. Ignored build outputs and external dependency or compiler inputs
require their own compiled-profile evidence; these source joins do not prove
that dependency closure or native execution occurred.

The compiler publication verifier checks the original recorder filesystem
namespace through an independently supplied runtime source binding:

```sh
python3 -I -B scripts/verify-recovery-qualification.py \
  --compiler-publications /absolute/path/to/original/campaign \
  --source-binding "$SOURCE_BINDING"
```

It independently checks `chio.rust-compilation.v3` rows and
`chio.rust-compilation-completion.v2` markers against their actual held file
identities and byte hashes. Referenced compiler, input and output artifacts are
hashed independently. It never executes or imports the recorder and never opens
an original compiler or source path taken from a row. Copying rows and markers
does not preserve publication authority; export requires a separate custody
contract.

Missing completion markers and malformed authoritative pairs refuse
verification. The incomplete-prefix counter covers only entries in the records
directory, and unreferenced artifacts have names-only coverage. These counters
do not represent every attempted compilation or verified unreferenced bytes.
Compiler failures remain separate from successful rows. The result always says
`compiled_closure_status: not-established`: checking publication does not prove
source-to-unit dependency closure, native sandbox enforcement, generated-input
attribution or Linux acceptance.

The Python SDK gate uses the in-tree qualification venv and isolated Python
import mode. It inserts only the declared in-tree SDK source directories,
verifies `chio_sdk.__file__`, and prints `QUALIFICATION_PYTHON_IMPORTS` with the
resolved module, interpreter and venv paths. The fixture gate records its exact
PYTHONPATH. Both gates require:

```sh
OTEL_SDK_DISABLED=true CREWAI_DISABLE_TELEMETRY=true
```

The model-free preflight additionally installs a socket guard. It permits the
native loopback connection, counts non-loopback resolution/connect attempts,
and refuses them. `provider_requests` is derived from the observed attempts.
Model-free runs stay outside live trial denominators. Native child processes
receive an allowlisted environment rather than inherited provider credentials,
proxy variables or Python import overrides.

The live corpus version is `chio.recovery-live-corpus.v2`. Every row and every
provider attempt carries the declared provider endpoint. The OpenAI client uses
the explicit endpoint, disables ambient proxies and redirects, and has no
transport retries. The campaign requires exact current source membership and
hashes before launching. Failures stay in their declared slots; a later cohort
cannot replace an earlier attempt in the report. The final attempt's acceptance
does not change the recorded pass/fail of earlier attempts.

## Recompute measurements and refusals

The native and pure Rust harnesses emit `samples_ns`, retaining collection order.
The percentile method is nearest rank. The auditor sorts a copy and recomputes
p50, p95, p99 and maximum from every raw sample; it also checks the original
sample counts, warmups, native effects, charges, profiles and unchanged ceilings.
Pure measurements are printed before a ceiling failure so failed measurements
retain their raw observations. Historical summary-only measurements cannot
prove raw-sample recomputation.

Rust counts come from the final result per top-level test binary. In particular,
the historical store suite has 1,831 passed and four ignored tests; its separate
nested child-process pass does not increase that suite's denominator to 1,832.

Mutation tests exercise semantic validation before package integrity. Each
corruption must produce its expected `qualification.<reason>` category, such as
`gate_command`, `gate_environment`, `gate_source_bracket`,
`performance_recomputation`, or `cohort_inventory`. A generic hash mismatch does
not establish that the targeted semantic check worked.

The bounded model runner requires an explicit fresh `--output` directory under
the candidate's `target/` directory. It preserves the source tree's retained
model outputs and records the source hashes, actual compiler, commands and new
output hashes. Toy runner tests establish publication behavior only. Actual
current model execution and primary formal-tool evidence remain separate gates.

## Archive reviewable evidence

Copy retained evidence into a fresh non-phase record under
`implementation/qualification/records/<candidate-binding>/`. Preserve logs,
before/after manifests, current runtime inventories, executable pins, exact
finding dispositions and independent review records. Retain every live cohort
declaration, every measured row and every unknown slot. Package records use real
review finding IDs, never an invented replacement ID.

The record schema is `chio.recovery-qualification-record.v1`. Its `artifacts`
inventory binds the auditor itself and all gate/provenance/dimension references.
Its `qualified` value is recomputed from the closed gate catalog and retained
dimension evidence. A completed record additionally requires an out-of-band
seal hash. Archive-only recomputation is portable and cannot establish that a
different current checkout matches the archived source:

```sh
python3 -B scripts/verify-recovery-qualification.py \
  --record path/to/record.json --root path/to/record-root \
  --expected-seal-sha256 recorded_canonical_record_digest
```

Add `--source-root "$PWD"` to require exact current Git source inventory and
commit agreement. For historical integrity only, use `--historical-package`
with the archived package directory and its pinned integrity manifest hash.
That mode reports `current_qualified: false` and never imports the historical
auditor. It proves byte integrity, not completion of current acceptance.
