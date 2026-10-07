# Bilateral consent across isolated role processes

The funded-work lifecycle now runs through five isolated custody domains with six
distinct signing keys. Buyer and provider exchange public proposal and acceptance
artifacts; each signs with its own seed. Governance and status also sign in
separate invocations. The coordinator never loads role seeds, private native
requests or role journals. Correct output pays the original allocation; rejected
output refunds it, preserving one original native operation and hold.

This slice builds on `ff0de59644d924b71da76091e582e07f0dea1032` in the isolated
`feat/funded-native-admission` worktree. The [qualification manifest](32-isolated-consent-evidence.json)
records source, executable, command and artifact hashes. Earlier execution reports
and evidence remain historical and unchanged.

## Exact bilateral consent

The new intent (`chio.experimental.funded-work-intent.v1`) has exact fields
`schema`, `policySha256`, `requestId`, `inputSha256` and `work`. Each party receives
its own administratively selected copy. The policy digest commits all public role
pins, domain, native authority UUID, implementation and complete Finding context.
Work terms retain the existing 100 mock-unit bounded W0 profile.

The provider publishes a proposal (`chio.experimental.funded-work-proposal.v1`)
containing that public policy, the existing agreement body, disclosed input,
issuance time and its signature over the agreement body. Its native request and
capability stay in private provider custody. The buyer verifies the provider
signature, current context, exact policy/request/input selection and every work
term before signing. It adds its signature to the existing registered agreement
v2 and signs an acceptance (`chio.experimental.funded-work-acceptance.v1`) whose
body binds the complete proposal digest and jointly signed agreement. This second
signature binds the input and proposal envelope as well as the agreement body.

Provider execution requires that exact acceptance, the retained original proposal
and its original private request. It checks both agreement signatures, the buyer's
acceptance signature, public proposal digest, private request digest, actual input
and the existing native request/waiver validation. The new consent profile permits
no capture-waiver terms. It does not widen the existing financial waiver path.
The registered agreement v2 format and settlement decision format are unchanged.
The proposal, intent and acceptance are experimental example envelopes; this slice
does not register them as new workspace protocol schemas.

```sh
target/debug/chio-federated-work experimental-work-propose PROVIDER INTENT.json INPUT.json PROPOSAL.json
target/debug/chio-federated-work experimental-work-accept BUYER INTENT.json PROPOSAL.json ACCEPTANCE.json
target/debug/chio-federated-work experimental-provider-execute PROVIDER OBSERVER.sock ACCEPTANCE.json
```

`INPUT.json` is a canonical JSON string containing the exact W0 input bytes.
All artifact inputs use bounded, raw-first canonical typed decoding. Outputs are
created exclusively and existing files are preserved. The provider commits its
intent marker before issuing a capability, then retains the complete original
request/proposal before publication. The buyer commits its intent marker before
signing and its complete first consent before publication. Files and parent
directories are synchronized. Incomplete writes or missing components are
preserved and denied; there is no automatic replacement capability or signature.
Exact completed buyer retries validate historical custody without the buyer seed.
A concurrent attempt during an incomplete write can fail and must retry after the
first attempt completes. Local consent files have no external rollback anchor.

## Separate context signing

```sh
target/debug/chio-federated-work experimental-context-draft GOVERNANCE PINS.json EXPIRES_AT DRAFT.json
target/debug/chio-federated-work experimental-context-attest STATUS PINS.json DRAFT.json CONTEXT.json
```

Governance signs the profile using its own seed and the separately selected status
public key. The draft contains no signed standing. The status operator checks the
selected context authority and adds its own standing, producing the existing
execution context v2. Provider enrollment remains the previously qualified public
pin/context interface. Completed draft/attestation retries retain exact original
artifacts. Context drafts alone cannot admit funded work. Unrequested assurance
facets remain unavailable; no new external revocation service is implied.

The checkpoint/status operator still holds two distinct keys within one custody
domain, as required by the existing checkpoint handoff. Governance, buyer,
provider and verifier each occupy separate domains. This is five isolated domains
and six keys, not six independently administered organizations.

## Enforced local process boundaries

The Linux launcher uses `/usr/bin/bwrap` with user, mount, PID, IPC and network
namespace isolation, dropped capabilities, a cleared environment and a fresh
session. There is no shared host network, host-root mount or repository-wide
mount. Each invocation receives only its own writable `/state`, explicit copied
read-only `/in` artifacts, a fresh writable `/out`, runtime libraries and private
`/tmp`. Existing role seeds are mounted read-only. Initialization also runs inside
the namespace, so the coordinator obtains only public keys from role processes.

Only provider and verifier calls receive their respective configured observer
socket. The verifier socket permits observation only. The Python environment and
exact source files from the pinned checker inventory are mounted only for checking.
The provider's original native request and capability never enter public transfer.
The launcher rejects aliased role directories, symlinked seeds and nonregular
input files. Failure to create a sandbox fails the reproduction; there is no
unsandboxed fallback.

Active probes in every domain check that all four peer state paths and a host
sentinel are absent, including access through `/proc/1/root`; read-only input
writes fail; and a live host-loopback listener is unreachable. These are actual
namespace probes, not assertions based on directory naming. They do not establish
protection against a compromised host kernel or the trusted host administrator.

## Native execution, verification and settlement

Provider-only CLI commands publish original output, sign/retain a submission,
observe its claim and settle the imported signed decision:

```sh
target/debug/chio-federated-work experimental-provider-output PROVIDER REQUEST_ID OUTPUT.json
target/debug/chio-federated-work experimental-provider-submit PROVIDER REQUEST_ID OBSERVER.sock CANDIDATE.json
target/debug/chio-federated-work experimental-provider-settle PROVIDER REQUEST_ID OBSERVER.sock
```

Execution uses normal native startup reconciliation. Artifact preparation,
export/import and explicit financial commands retain the narrow handoff open
mode; they do not bypass the native admission guard. Settlement requires an
already retained verified decision and uses the original record/pay/refund
observation paths. There is no local fallback verifier in the isolated lifecycle.

The process harness reuses the actual checkpoint and verifier CLI interfaces. It
forces consent and decision publication to read-only paths after custody commits,
removes the corresponding role seed, and republishes from retained custody. The
verifier replay has neither its observer socket nor checker dependencies. A
modified buyer acceptance must fail before the valid original work executes.
The final native execution retry reports the original operation, hold,
authorization, authority UUID and single execution.

```sh
CARGO_TARGET_DIR=target cargo build --manifest-path examples/federated-work/Cargo.toml --locked
CHIO_FUNDED_PYTHON=/path/to/pinned/venv/bin/python python3 -B examples/federated-work/test_isolated_consent.py
```

Python verifies the existing public execution witness with separately supplied
allocation pins. It verifies execution authority and output matching; it does not
verify chain funding or independently implement the new consent-envelope verifier.
The retained evidence contains public fixture data and signed public artifacts.

## Qualification

All 87 selected standalone Rust tests pass: 81 regular tests and all six explicitly
selected private-chain tests. Five new Rust regressions cover separate consent,
selected keys/terms, canonical ingress, missing custody and split context signing.
Python passes 28 public execution-verifier tests and six canonical wire tests.

All 22 selected owned process scenarios pass: two isolated lifecycles, two prior
public-authority/verifier lifecycles, two checkpoint handoffs, seven native
refund-resolution scenarios, four earned-child scenarios and five execution-custody
recovery scenarios. These include ten active role-namespace probes and 15 actual
SIGKILL events in the existing native recovery regressions. The prior handoff
suites also retain their malformed-request and corrupted-custody rejection checks.

Strict standalone Clippy, standalone/workspace formatting, Rust file hygiene and
diff checks pass. The manifest records the exact executable used for all process
scenarios, 81 selected source-file hashes and the bubblewrap executable/version.
Original checkout verification confirms all 3,688 saved file hashes and modes,
original HEAD/branch and dirty state are unchanged. Ganache used its JavaScript
fallback for unavailable optional ARM native bindings. Workspace crates and
dependencies are unchanged. Full-workspace tests, fuzz campaigns and new formal
model qualification were not run for this example-only slice. Review was performed
inline without sub-agents; see the [review record](isolated-consent-evidence/review.md).

## Next delivery gate

This closes the local coordinator's shared-key consent path and enforces role
process boundaries. The same trusted host administrator still selects pins,
transfers artifacts, controls the namespaces and owns the mock chain adapter,
including its transaction-signing accounts. Independent companies, public RPC
finality and hostile-network delivery remain unqualified.

Next, replace coordinator file transfer with authenticated peer transport and
qualify separately administered participants with receiver-owned observers. A
second consent implementation should verify the complete signed proposal and
acceptance, alongside the existing Python execution verifier. Capacity remains
one original consent/allocation per role/log slot; rollback-aware custody,
external revocation and useful-work/verification-cost measurements remain open.
No public deployment, remote CI, release qualification or real funds are claimed.
