# Matched outcome ledger comparison

Compare Chio's experimental outcome effect slots with an independently
implemented receiver-issued opaque-handle ledger. The baseline permits the
same application-defined evidence, trusted verifier, owner rule and durable
logical budget. It is not limited by the original composed baseline's carrier
inventory.

From the repository root:

```sh
CARGO_TARGET_DIR=target cargo run --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo test --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
```

The executable writes `comparison.json` and kernel workflow artifacts to a
fresh temporary directory. An optional argument selects a new output directory.
Both implementations use SQLite WAL, `synchronous=FULL`, immediate claim
transactions, identical cryptographic primitives and one fixed test clock.
All keys, contracts and candidate policies are test fixtures.

The shared harness compares:

- 16 positive/substitution cases, each with a valid follow-up and physical
  effect counts.
- Six state-transition cases, including live revocation and expiry, argument
  changes after preparation, and fresh evidence or handles after consumption.
- Five process scenarios: eight competing processes and SIGKILL before claim,
  after claim, after the external append, and after completion.
- An identical Chio kernel/tool host running the same policy-artifact
  publication, receiver reopen and replacement-agent attempt for each gate.

The baseline also rejects a caller-invented handle and demonstrates that two
actually different issued handles share one effect budget. The baseline lives
in [outcome_ledger.rs](../composed-baseline/src/outcome_ledger.rs). It does not
import the Chio runtime's checker or store. The comparison shares the outer
kernel host deliberately, so its claim concerns the outcome gates, not two
complete agent protocols. Both kernel workflows produce signed receipts under
the same test issuer and verify the published result's content binding.

The effect sink is an ordinary append-only file without deduplication. Both
gates must prevent a second append themselves. Before a claim, a replacement
can complete the work. After a claim whose result was not persisted, both
preserve uncertainty and refuse a repeat. These tests terminate owned child
processes at observed checkpoints; they do not qualify host power loss, remote
administration, the entire kernel recovery pipeline or resistance to cloning
the trusted database.

This runner asserts equality only for the tested observations. It does not
claim semantic equivalence of all behaviors, production qualification,
identical wire APIs, an integration-effort result, or performance superiority.
The baseline uses an additional evidence-to-handle exchange, so naive timing
would also compare different preparation operations.

## Three receivers and a replaceable courier

```sh
CARGO_TARGET_DIR=target cargo run --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- --graph
```

This mode starts a fresh kernel process for every receiver operation. A native
scope-contract verifier produces evidence for a publishing receiver, whose
completed result contains evidence for an archive receiver. Each receiver has
its own key, receipt database and local state. A courier receives public job
metadata, artifact bytes and signed responses. It reads receiver state to
recover progress and has no persistent execution state of its own.

The runner compares both gates across eleven execution scenarios and six
adversarial deliveries. It kills eighteen receiver processes and two couriers
at observed checkpoints. Losing a response after completion can be recovered
by reading the persisted output; a claimed effect with no result remains
uncertain and exposes no successor authorization. Kernel receipts on both
execution and status responses are checked against the endpoint's pinned key,
request, target, decision and returned content.

The output contains `graph-comparison.json`, public job files, owner rules,
private test keys, signed request/response traces, databases and physical
effect files. Keep the complete generated directory private; retained review
evidence excludes `key.seed` files. To run a fresh courier against a generated
public job, use `--graph-courier PUBLIC_JOB_JSON none`. The worker mode is an
experimental local test endpoint and is not a production service.

All processes run as the same operating-system user on one host. Separate
processes, key files and stores do not establish isolation from a malicious
process with filesystem access, independent administration, or a remote
transport deployment. The public ingress issues an exact-operation capability
locally; it is not a deployment identity system. Native policies remain data,
and no proposed code is executed. The matched ledger is available throughout;
this experiment does not claim a new workflow theory or a measured integration
cost advantage.

## Isolated courier and receiver processes on Linux

```sh
CARGO_TARGET_DIR=target cargo run --locked \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- --isolated-graph
```

This mode requires `/usr/bin/bwrap`, enabled unprivileged user namespaces, and
the executable's shared libraries under `/usr/lib`. It was tested with
Bubblewrap 0.9.0 on aarch64 Linux. An unavailable sandbox fails the run; there
is no fallback to the unisolated mode. The integration suite runs this mode
as its third test and therefore has the same prerequisites.

The trusted launcher selects all mounts. A courier receives the executable,
read-only libraries and public job, a private temporary directory, and a
read-only directory containing three Unix sockets. Each socket's broker starts
only its configured receiver. RPC arguments cannot select a receiver directory,
key, mount or fault-injection mode. Each receiver receives its own writable
state directory, with its key and owner rule overlaid read-only. Receivers have
no peer state mounts. All four roles use separate mount, user, PID, network,
IPC and UTS namespaces, dropped capabilities and a cleared environment.

The same eleven execution scenarios and six adversarial deliveries run
through isolated receivers for both gates. Normal and replacement couriers
also run inside the sandbox. Adversarial RPC payloads and crash injection are
constructed by the trusted host harness. This is not an arbitrary malicious
program benchmark. For each injected launcher termination, the harness checks
that its observed descendants stopped, comparing process start times to avoid
confusing reused PIDs with surviving children.

Eight probes run under these mount policies: a courier and three receiver
roles for each backend. They attempt read and write access to nine known host
paths, access through `/proc/1/root`, a symlink escape, and a connection to an
owned host loopback listener. Unsandboxed positive controls first open those
same paths and reach that listener. Receiver probes also confirm that their
own mounted key is readable, configuration is read-only and state is writable.
The output retains probe inputs and observations alongside the graph results.

This closes the measured same-user filesystem exposure inside the sandbox.
The host operator, launcher, broker and shared Linux kernel remain trusted;
a process outside the sandbox with host filesystem access is not isolated.
The fixture has bounded RPC frames and waits, but no seccomp policy or aggregate
CPU, memory, process or disk quota. It does not qualify denial-of-service
resistance, kernel exploits, independent remote administration or production
credential issuance. Both outcome gates receive this same isolation layer.
Generated sockets are live only while the comparison's brokers are running;
the retained public job alone cannot restart those brokers.

## A real source repair as the work product

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

This mode checks the repository's Python Git-hook repair, then publishes both
repaired source files into a new review directory through each outcome gate.
The baseline files are copied from the commit pinned in the fixture manifest.
They contain a real defect: `--no-verify` leaves prepare-commit-msg, post-commit
and reference-transaction hooks executable. The candidate comes from the
selected source tree. An optional final argument selects a new output directory.
The workflow does not apply the published files to the operator's checkout.

The owner contract binds the baseline file hashes, the two allowed paths,
seven invocation cases, checker source, candidate shim and isolation policy.
The candidate Python process receives these two source files and public inputs.
It has no receiver key, authority database or checker repository mount. Its
output supplies proposed argument arrays. Neither an exit code of zero nor a
`passed` assertion is treated as a successful verification.

The trusted checker accepts only the original requested direct commit with
optional hook-disabling arguments. It rejects additional Git commands or
executable configuration. A separate Git sandbox then executes that request
in a checker-created repository. The checker observes the committed message,
file contents and five configured hook markers. This separation keeps the
candidate interpreter from monkeypatching the checker or replacing its tests.
The restricted arguments prevent a returned shell alias from erasing markers.

Both gates reject the historical baseline, a repair missing the dedicated
commit path, self-asserted success, a no-op command, an alias that would erase
hook evidence, and a mismatched base. Seven legitimate commit cases pass for
each gate. Changing source bytes after verification denies publication. After
publication, a fresh capability against the reopened receiver cannot publish
the files again. Exact approved bytes and signed receipts are retained.

This is a finite behavioral contract for one real repair, not general program
correctness. The Python source was authored during this session; there is no
live model inside the executable experiment. Candidate Python and Git run in
separate Linux sandboxes; the checker, signer and shared host kernel remain
trusted, and aggregate resource quotas are absent. This mode
also requires `/usr/bin/python3.12`, `/usr/bin/git` and `/usr/bin/dash`.
The fourth integration test runs this comparison. It does not extend the
three-receiver graph's crash evidence to the source-repair workflow.

## Receiver-owned checking without an upstream signature

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-receiver-check examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

This comparison selects two receiver configurations through the trusted owner
path. The attestation profile accepts outcomes signed by its selected upstream
verifier. Its counterexample uses that actual key to sign the original buggy
source as passing; both outcome gates publish those bytes. This deliberately
violates the upstream-honesty assumption, without forging a signature.

The receiver-checking profile takes the raw source artifact and runs the same
bounded checker locally before claiming publication. On success, the receiver
constructs a local outcome for its existing durable gate under its own key.
It does not accept an upstream signature as a substitute for checking and
does not contact an upstream verifier. Normal kernel capabilities still apply.
The input cannot choose or change the receiver's checking profile.

Both gates reject the buggy artifact and a wrong base, then accept the valid
repair without an upstream artifact signature. After reopening, both reject a
repeat before running candidate Python again. The local checker runs twice per
gate, covering seven failing and seven passing commit cases. Published files
remain in the experiment's new review directory.

This removes upstream-verifier honesty and availability from this workload's
requirements by spending receiver computation. It is re-execution, with a
trusted local checker and finite contract. It is not a succinct proof, a zkVM
integration or a new cryptographic mechanism. The fifth integration test
exercises both owner configurations and both gates; the existing sandbox and
deployment limits still apply.

## Recovering a checked Git publication

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-git-recovery examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

The receiver checks the same two source files against all seven behavioral
cases, then prepares a SHA-256 Git commit in a new owned review repository.
Its immutable signed intent binds the source, target commit, fixed reference
and absent expected value. All worker invocations go through the kernel with
fresh capabilities. Candidate Python cannot access the publication repositories
or signing keys, and publication never modifies the input source checkout.

The Git adapter conditionally creates `refs/heads/verified-repair`. After a
crash, a replacement worker compares the exact durable claim, observes the
reference, checks the commit tree against the source bytes, and either reports
the existing publication or attempts the same conditional creation. It rejects
a changed intent, missing commit, symbolic reference or conflicting commit.
No generic dispatch permit is reconstructed. When a permit was lost, the
runtime still reports `claimed`; `git-observation.json` and the new signed
kernel reply describe a separate observation of the Git effect.

Twelve paired scenarios include four SIGKILL boundaries, eight competing
recovery workers per backend, source and target substitutions, reference and
object conflicts, and revocation before and after claim. A claim commits this
specific domain operation: revocation prevents new claims but does not cancel
an already accepted conditional Git creation. The sixth integration test
checks these cases while retaining the five prior experiments, including the
ordinary non-deduplicating append sink that cannot recover uncertain effects.

This depends on a trusted, exclusive owner of one reference. Ref deletion and
recreation, store rollback, crashes inside Git's reference transaction, host
power loss, remote pushes and arbitrary external effects are outside the
qualified model. Reflog counts are test observations under retained history,
not tamper-proof execution evidence. Both outcome gates obtain the same
behavior from the same Git adapter; no novelty or performance advantage is
established.

## Checking a delivered repair without the publisher

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-artifact-audit examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

This creates portable Git bundles and compares ten cases for each gate. A
consumer can check one independently, supplying its own trusted baseline:

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --audit-repair-bundle examples/outcome-ledger-comparison/fixtures/git-hook-repair/base \
  RUN_DIRECTORY/chio/packets/unsigned_valid
```

Both commands accept an optional final argument naming a new output directory.
The auditor imports only `manifest.json` and `repair.bundle`, validates the
commit and exact source bytes, then executes the seven local behavioral checks.
It requires no receiver key, store, signed claim or network service. Any
`receiver-claim.json` sidecar is outside this artifact-only verification and is
not used as an authorization input or treated as a verified identity.

Successful output is `locally-checked-repair.experimental.v1`. It states that
the artifact passed and records the locally executed verifier's binary hash.
`publicationHistoryVerified` and `receiverExecutionVerified` remain false.
A valid receiver signature over a false publication claim does not change
those fields. Consumer software must select the claim it needs; this result
cannot establish private publication, authorized dispatch, payment or history.

The auditor runs in a namespace without receiver mounts or host networking.
It creates inner namespaces for untrusted candidate Python and native Git.
The bundle profile allows one SHA-256 reference, no prerequisites or filters,
at most one MiB of input and 64 packed objects. Git validates the actual pack.
The auditor and descendants inherit per-process limits of 512 MiB address
space, 8 MiB per output file, 20 seconds of CPU and 128 open descriptors. The
existing subprocess deadline remains in effect. These bounds are not an
aggregate process, CPU, memory or disk quota, nor a hostile-code production
qualification. `/usr/bin/prlimit` is an additional prerequisite.

Both backends reject signed buggy source, changed metadata and corrupted or
out-of-profile bundles. They accept the valid unsigned artifact while leaving
private publication history unverified. The seventh integration test includes
the independent consumer command. The trusted local checker and environment
remain necessary; the finite contract does not prove arbitrary correctness or
establish a new cryptographic mechanism.

## Testing whether artifact validity establishes fresh work

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-work-reuse examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

This research harness loads the existing valid repair, generates fresh producer
keys and claims, and constructs variants by appending comments or unreachable
branches. It also binds variants to challenges generated after the repair was
loaded. Every distinct artifact passes the same seven Git checks. A trusted
Python process parses the source as data to compute syntax fingerprints; it
never imports or executes the source while fingerprinting.

The run produces 24 authenticated claims with 19 distinct artifact hashes and
7 distinct syntax hashes from one cached repair. These counts do not establish
new repair-search effort. The original buggy source is a failing control.
Wrong challenges, artifact substitutions and unsigned claim mutations fail
verification. The 19 valid artifacts and buggy control execute 140 Git cases.

A stronger control feeds all 24 candidates through each existing gate under
one immutable receiver-owned job. Only the first appends an effect record;
fresh evidence and artifact variants cannot refill that job. Both gates remain
completed after reopening. This is a direct gate test, without an additional
kernel or capability claim. The prior integration cases still cover those.

This does not implement consensus, attack a deployed protocol or establish a
performance ratio. It rejects a proposed shortcut that would use claim,
artifact or syntax counts as evidence of new repair-solving work. Syntax
deduplication is not a semantic-equivalence proof. The eighth integration test
reproduces the counters and the stronger logical-job control.

## Exchanging a checked repair for local test credits

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-exchange examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .
```

This mode additionally requires the `cryptography` package for
`/usr/bin/python3.12`. It encrypts the real repair with AES-GCM, verifies its
opening through the native-check cache, and binds the complete offer to an
outcome authorization. A trusted Python worker reserves 10 of 100 test credits
and commits the seller credit and released decryption key in one SQLite
transaction. The credits have no monetary value.

Eight cases run against each gate, including buyer abandonment, timeout refund,
wrong keys, substituted offers, eight simultaneous settlement retries and
SIGKILL before and after the settlement commit. A buyer-delivery command
decrypts from the funded offer and committed key view. Plaintext-before-payment
and bare-hash-lock controls respectively let a buyer keep the repair for free
and a seller get paid for the buggy source.

The ninth integration test retains these comparisons. This is direct gate use,
not a new kernel-dispatch test. The controller retains its permits during
settlement-child crashes. The checker, settlement operator and host remain
trusted; no zero-knowledge proof, external payment, new buyer isolation boundary
or trustless fair exchange is implemented. The already-public source fixture
does not test secrecy of an unknown good. Details and retained evidence are in
[the exchange report](../../docs/papers/review-2026-09/26-checked-repair-exchange.md).
