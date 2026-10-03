# Verifiable Work artifact companion

This artifact accompanies *Chio: A Peer-to-Peer Economy of Verifiable Work*.
The title was approved on 2026-09-14. The manuscript was first completed as a
research draft on 2026-10-02. Publication readiness is evaluated separately in
`PUBLICATION.json`; the high-bar gates are not waived by a successful PDF build.

## Sources and profiles

The current manuscript adds D1, the dynamic delegation profile in
`crates/platform/chio-workflow/src/delegation/` and
`crates/kernel/chio-kernel/src/delegated_work.rs`. Its
[protocol](../../research/dynamic-delegation/PROTOCOL.md) defines allocation,
signatures, trust boundaries, accepted-output pricing and conservative sealing.
Its [qualification](../../research/dynamic-delegation/evidence/qualification.json)
hashes current Rust/build/spec/tool inputs and fresh terminal command outputs.
The standalone D1 example uses a durable integer rail fixture, two receiver
keys and separate native stores under one administrator. That illustration does
not use F1's escrow; the composed experiment below does.

The prepublication D1 signed records use v2 domains after the namespace replay
repair. Subdivision, offers, selection and permits now bind the protected
allocator/root/slot context. Old v1 records need fresh signatures; an issued
database without its allocator namespace fails open-time validation. No silent
migration of live experimental commitments is performed.

S1 extends `crates/kernel/chio-swarm-authority/` and the existing runtime-core
store and admission hook. Its [protocol](../../research/swarm-evolution/PROTOCOL.md)
defines additive growth, protected head serialization, exact historical lookup
and stable native continuation ownership. The same current qualification record
covers D1 and S1 and their composition with native treaty admission and F1
escrow. The [composed result](../../research/evolving-funded-work/RESULTS.md)
executes work, discovers and funds a new task, installs graph growth, kills the
intermediary after the child becomes payable, and collects the original child
claim. This is one local execution under one administrator, with a private
chain and mock tokens. Independent operation and economic advantage remain
unmeasured.

Historical source evidence is checked at retained Git revision
`71e5cbc3bf7b08f477ed0e0361f2cca0c36eaea3`, which preserves every non-paper input
in the old native inventory. The original source hashes and v2/v3 qualifications
remain unchanged. A full clone containing that revision is required; a shallow
clone missing it fails rather than silently substituting the current tree.
The newer branch base `96c25e99a188bb8d1d084c7324a30050a2fd496d` already includes
a changed recovery fixture, so it cannot substitute for this historical pin.

The original funded implementation is pinned to
`7755d3762baa5e0fda0d171835a9000c26de9033`. The committed security candidate is
`491f585e9013dcb6335589c82d00ac219efbf0a6`. The active security checkout also
contains uncommitted work and is not an input to this paper. The integration
record identifies the exact combined source and its tests separately.

The paper branch now contains combined commit
`71e5cbc3bf7b08f477ed0e0361f2cca0c36eaea3`. The finite model and Solidity checks
initially ran on the funded checkpoint; those files are byte-identical in the
integration. The comparator and Lean proof are new paper artifacts. Native
experiments ran in a separate integrated checkout: their source identity
travels with the evidence. A check from one tree cannot silently qualify the
other.

| Paper object | Implemented location | Qualification boundary |
| --- | --- | --- |
| D1 slots, signed mutations and sealed permits | `crates/platform/chio-workflow/src/delegation/` | Trusted SQLite allocator, finite trees, full-contract offer binding; ceilings are not deposited funds |
| D1 native receiver and checked output | `crates/kernel/chio-kernel/src/delegated_work.rs` | Locally activated allocator keys plus an ordinary receiver-issued capability; durable native custody; no allocator connection at dispatch |
| S1 checked graph growth | `crates/kernel/chio-swarm-authority/src/evolution.rs` | Existing live verifier plus exact retention; declared pool, single-use tasks, additive changes only |
| S1 durable history and native admission | `crates/kernel/chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs` and `src/admission_hook/swarm_authority.rs` | One protected head per pool lineage, exact graph lookup, existing native replay and treaty gates |
| Composed D1/S1/treaty/F1 execution | `examples/federated-work/src/funded_work/composition.rs` and `evolving.rs` | Owner-pinned admission, exact request bindings, additive growth and original earned-child collection after SIGKILL; one local administrator |
| Joint artifact work agreement | `examples/funded-work/artifacts.py`, `PROFILE.md` | `chio.experimental.funded-w0-agreement.v1`, artifact-only |
| Native funded agreement | `examples/federated-work/src/funded_work/agreement.rs` | Experimental native v2; exact request digest, local authority UUID, Finding policy, allocation domain; W0 amount is fixed to 100 mock units |
| Disclosure and procurement | `examples/federated-work/src/subcontract/permit.rs`, `SUBCONTRACT.md` | Bounded three-party example; the conceptual agreement tuple is not a new universal wire schema |
| Acceptance | `examples/funded-work/verifier.py`; native `verification.rs` | Selected trusted verifier; independently implemented Python checker under the same project/operator |
| Financial right | `contracts/src/experimental/ChioWorkClaimEscrow.sol` | Real bytecode on Ganache, allowlisted test token, no public-chain finality |
| Native execution receipt | `examples/federated-work/src/funded_work/execution_evidence.rs` | Bound original operation and execution; historical evidence does not confer fresh dispatch authority |
| Typed rail decision | `_decisionHash` in the escrow | EIP-712, chain and contract domain, exact allocation/commitment/beneficiary/token/amount |
| Abstract proof | `formal/WorkClaims.lean` | Specification safety; no Rust/Solidity refinement |
| Ordinary alternative | `tools/compare.py` | Trusted in-memory SQLite, sequential trace replay, symbolic authenticated roles |

The main paper's slot tuple maps to D1's `WorkSlot` and `WorkContract`. F1's
artifact-only and native profiles have different concrete bodies. A parent
link does not automatically exist in every native agreement, and no parent
field transfers funds or installs a local issuer. Interoperability claims must
name a particular profile and its conformance tests.

## Reproduce the paper

Requirements: Python 3.11+, TeX Live with Latin Modern, TikZ and natbib, BibTeX,
and Poppler (`pdftotext`, `pdfinfo`). From this directory:

```sh
make build
make test
make check
python3 tools/check.py --publication
```

`make build` regenerates PDF output and verifies retained result macros,
bibliography, references, overflowing lines and artifact hashes. The last
command additionally checks the high-bar publication gates. An open gate is
an intentional nonzero result, not a missing PDF dependency. `--refresh`
regenerates numerical macros from retained outcomes. `--freeze` is an explicit
maintainer operation that records new source/artifact hashes after a review;
it must not be used to conceal unexplained evidence drift.
For reviewed source changes, the maintainer sequence is `make render`,
`python3 tools/check.py --freeze`, then `make build`; the last rebuild must
match the recorded PDF bytes.
The recorded [toolchain](evidence/toolchain.json) identifies the TeX engine,
package hashes and other tools. The build fixes its source date and omits
PDF timestamps and trailer IDs. Byte-identical rebuilding was checked in that
environment; a different TeX distribution may produce a different PDF and will
correctly fail the frozen PDF hash. Review that difference before recording a
new artifact rather than treating different typesetting as a scientific result.

From the repository root, reproduce the finite model and comparator:

```sh
python3 -B -m unittest discover -s examples/funded-work-model -v
python3 -B examples/funded-work-model/claim_explorer.py --output /tmp/chio-claim-traces.json
cmp examples/funded-work-model/claim-traces.json /tmp/chio-claim-traces.json
python3 -B docs/papers/verifiable-work/tools/compare.py --corpus /tmp/chio-claim-traces.json --output /tmp/chio-comparison.json
lean +leanprover/lean4:v4.28.0 docs/papers/verifiable-work/formal/WorkClaims.lean
```

For the current dynamic profile, use the repository Rust toolchain on Linux:

```sh
python3 -B docs/papers/verifiable-work/tools/qualify_dynamic.py
CHIO_FUNDED_PYTHON=/tmp/chio-python-buyer-env/bin/python \
  python3 -B docs/papers/verifiable-work/tools/qualify_dynamic.py --record
```

The first command verifies the retained current-source evidence. The second
executes 21 checks, including the real SIGKILL native scenarios, the existing
three-owner and durable-admission regressions, full swarm/runtime and standalone
funded suites, changed-boundary Clippy and formatting. It builds the funded
binary before the evolving execution and four existing earned-child recovery
cases. The environment check requires the existing locked Python dependencies
and records interpreter, Rust and Node versions. It archives previous qualified outputs,
requires fresh recovery and evolving-funded trajectories, records terminal status and rejects source
changes during qualification. It intentionally changes retained evidence; run it
in a reproduction checkout, then review the resulting diff before refreezing.
The composed receiver contract and trial protocol are in
`docs/research/evolving-funded-work/RECEIVER-TRIAL.md`. Its public input package
is the `publicArtifacts` object in the qualified evolving JSON; private receiver
databases and keys are never part of that handoff. Both child collection reports
are retained, including the first open's missing remote co-signer diagnostic.
Payment and local completion do not establish bilateral receipt delivery.

First provision the checker without changing global Python packages:

```sh
uv venv --python /usr/bin/python3 /tmp/chio-python-buyer-env
uv pip sync --python /tmp/chio-python-buyer-env/bin/python --require-hashes \
  --index-url https://pypi.org/simple \
  examples/federated-work/python_buyer/requirements.txt
```

The independently callable native example is `cargo run --locked -p chio-kernel
--example dynamic_delegation`. The complete command arrays live in
`tools/provenance.py`. No broad workspace, hosted CI or release result is implied.

The default standalone Rust suite marks six chain-dependent cases ignored.
The supplementary current-source run selects those cases explicitly:

```sh
CHIO_FUNDED_PYTHON=/tmp/chio-python-buyer-env/bin/python \
  CARGO_TARGET_DIR=/tmp/chio-paper-target CARGO_BUILD_JOBS=2 \
  cargo test --locked --manifest-path examples/federated-work/Cargo.toml -- --ignored
```

Its command, terminal status, output hashes and digest of the unchanged native
source inventory are retained in
`docs/research/evolving-funded-work/evidence/chain-regressions.json`. This is
separate from the 21-command campaign, whose default-suite skips remain recorded.

The [conditional-backing report](../../research/kernel-continuation/CAPITAL.md)
and its `results/capital.json` preserve the 4,095-profile parity result. This is
retained continuation evidence, not a fresh D1 capital experiment.

Install the exact `contracts/pnpm-lock.yaml` dependencies using the repository's
package manager with a frozen lockfile, then run:

```sh
node --test contracts/scripts/work-claim-escrow.test.mjs contracts/scripts/work-claim-model.test.mjs contracts/scripts/funded-work-fit.test.mjs
CHIO_CLAIM_MUTATION=expire-payable node --test --test-name-pattern='accepted claim survives' contracts/scripts/work-claim-escrow.test.mjs
python3 -B examples/funded-work-model/claim_explorer.py --broken-expiry --output /tmp/chio-expiry-negative.json
```

The last two commands must exit 1: the bytecode mutation must fail with
`Missing expected rejection`, and the explorer must identify an accepted claim
refunded. An arbitrary compilation error or missing dependency is not a
successful negative control. The normal contract source is unchanged.

The Solidity fixture compiles sources with optimizer 200 runs and EVM target
Paris, uses actual private-chain ERC20 transfers and tests 118 representative
model traces. The source pin and hash inventory cover the inputs. Neither gas
measurements nor live-rail cost advantages are claimed. The negative mutation
is applied only in memory by the test fixture.

## Proof correspondence

`move_conserves` checks one abstract account move. `all_moves_conserve` lifts it
to arbitrary finite traces. `transfers_bounded` derives paid-plus-refunded at
most deposited. `earned_step`, `earned_persists`, and `earned_never_refunded`
check the allowed claim-state relation. `other_claim_unchanged` checks that a
map update leaves a different claim alone. The recorded axiom output contains
`propext` and, for the arithmetic results, `Quot.sound`; it has no `sorryAx`.

The account and claim-state lemmas are separate. Their joint implementation
requires a unique allocation, an atomic coupling of state and actual transfer,
and no authority path that rewrites either record. The Lean file does not
prove that coupling, signature verification, timestamp correctness, parser
correctness, custody availability or the checker predicate. Solidity trace
replay tests some concrete correspondence; it is not a refinement proof.

## Evidence inventory and limits

`evidence/observations.json` records observed commands and terminal exit codes.
Its timestamp is collection time, not an invented start time. Every retained
log and input is hashed in `artifact-manifest.json`. The first Python run is
retained even though native-binary absence made four subcases error; the later `python-tests-qualified.log` supersedes that failure for all 38 tests,
using the separately hashed integrated binary through `CHIO_W0_BINARY`. Red tests used to develop the SQL
comparator and evidence checker remain available and are not counted as passing
research experiments.

September process experiments remain in
`docs/market/open-agent-work/execution/`. They describe same-host role isolation,
actual process kills, signed transactions, owned observers and native custody.
They are historical results, not fresh tests on the October merged candidate.
The paper's evaluation labels that distinction rather than pooling suite counts.

The SQL comparator is a separate implementation within the same project. It
imports no kernel or reference-model transition, but follows the same state
machine and consumes model-generated expected traces. The additional manually
specified tests reduce, but do not eliminate, correlated mistakes. It does not
model disk loss or Byzantine SQL administrators. A competent ordinary application
can instead use the same external escrow; Chio gets no monopoly on that option.

The [ERC-8183 report](evidence/erc8183/REPORT.md) retains 76 passing upstream
tests and 20 comparison tests on unmodified upstream source at
`142e669c1fd318486a4628395b629f033654dd06`. Both contracts use the same mock token,
zero fees, capital and evaluator trust. The archive includes full command
records and successful reproduction after extraction to another path. Copy
`evidence/erc8183/` to a scratch directory, then run `python3 reproduce.py
--forge /path/to/forge --label rerun` there using the recorded Foundry version.
This keeps new logs and path-specific build configuration separate from the
frozen evidence. The live specification and the upstream code differ in some
details; the report distinguishes them. No result about one pinned
implementation is a result about every implementation or independently
operated companies.

## Security and release reconciliation

The dry merge identified 21 conflicted paths. The dedicated integration owns
semantic resolution and focused qualification. No full workspace, hosted CI,
release approval or operator authorization follows from the paper's model,
contract or PDF checks. This is a research artifact, not a production deployment
instruction or a real-funds escrow approval.
