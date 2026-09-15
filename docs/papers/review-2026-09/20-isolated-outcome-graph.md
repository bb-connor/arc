# Receiver credentials stay outside the courier sandbox

2026-09-13. Continuing the breakthrough objective after
[the three-receiver graph](19-receiver-outcome-graph.md). That run separated
processes and stores while leaving them accessible to a malicious process
under the same host user. This continuation implements and tests a Linux
namespace boundary around the same graph. It closes a concrete credential
exposure in the experiment. It does not establish a breakthrough.

## The implementation

The new `--isolated-graph` mode uses
[an explicit Bubblewrap launch policy](../../../examples/outcome-ledger-comparison/src/graph/isolation.rs).
The courier receives public job metadata and three Unix sockets. Each trusted
broker maps one socket to a fixed receiver directory and starts a fresh kernel
process for each request. The receiver sees only its own state under
`/receiver`; its signing key and owner configuration are mounted read-only.
The courier has no receiver directory mount. Supplied endpoint paths and RPC
arguments cannot extend the trusted launcher's mount policy.

All roles receive read-only executable and library mounts, a private temporary
directory and separate mount, user, PID, network, IPC and UTS namespaces.
The launcher clears the environment, drops capabilities, disables nested user
namespaces, creates a new session and requests termination with its parent.
There is no host home-directory or root-filesystem mount. Unix sockets provide
the intentionally permitted communication path despite network isolation.

The broker accepts a bounded JSON request containing a tool and arguments.
Clients cannot select a receiver directory, key or fault-injection mode.
Receipts still bind the configured receiver key, operation, exact arguments,
decision and allowed result content. The broker's transport error is only an
availability error; it cannot authorize a successor. A public test ingress
issues an exact-operation capability inside the receiver, as in report 19.
This fixture is not a production identity service.

Bubblewrap provides mechanisms for constructing a sandbox; the caller's
arguments determine its access policy. This experiment therefore records and
tests the selected mounts and namespaces rather than treating the presence of
Bubblewrap as evidence of confinement.
[Bubblewrap documentation](https://github.com/containers/bubblewrap).

## Boundary probes with positive controls

[The retained comparison](evidence/20-isolated-outcome-graph/graph-comparison.json)
includes one courier and three receiver probes for each outcome gate. The
probes use the same role-specific launch helpers as the graph operations.
Their additional read-only input contains the paths and namespace identifiers
to test, without private key contents.

Before isolation, the host opens every target path for reading and writing
without changing its bytes, and connects to an owned loopback listener. These
positive controls establish that ordinary host access succeeds. Each sandbox
then attempts those same accesses.

| Observation | Final retained result |
| --- | --- |
| Role probes | Eight, covering four roles for both gates |
| Host paths per probe | Nine: three keys, three owner files, two effect databases and one host canary |
| Direct path opens | All 72 read attempts and 72 write attempts denied |
| Paths through `/proc/1/root` | All 72 read attempts denied |
| Namespace comparisons with host | All 48 differ |
| Host loopback connections | All eight denied; host connection control succeeds |
| Symlink escape to a host key | All eight denied |
| Receiver-local positive controls | Six own-key reads and six state create/write/sync/remove operations succeed |
| Receiver configuration writes | Key and owner-file opens for writing denied in all six receiver probes |

A receiver can read its own key at the intentionally mounted `/receiver` path.
Denial of its original host path does not mean that this key is inaccessible
to that receiver. Peers' directories are absent from its mount policy. The
probe checks the selected paths and escape attempts; it is not a proof against
all Linux kernel vulnerabilities or a benchmark of arbitrary malicious code.

## Recovery survives isolation

Both outcome gates run under the same launch policy and retain the same native
scope verifier, kernel host, publishing adapter, archive adapter and courier.
The original append sink still has no deduplication. The independent ledger
continues to match Chio on all eleven execution scenarios and six adversarial
deliveries. Seven execution scenarios complete and four remain uncertain per
gate. Completed responses can be recovered; a claim without a persisted
result exposes no successor evidence and does not permit a repeated effect.

Normal and replacement couriers run inside the sandbox. The trusted host
harness constructs adversarial RPC payloads and injects receiver faults; these
requests reach isolated receivers through the broker, while fault injection
uses the trusted launch path directly. The six attacks remain overbroad policy,
skipped publication, substituted artifact, forged completion, foreign workflow
and duplicate delivery. Legitimate follow-up work completes or retrieves its
existing result, with one publication and archive entry in total.

The fault run observes eighteen receiver launcher exits and two courier
launcher exits as SIGKILL. Killing a wrapper alone would be insufficient
evidence. At each checkpoint, the harness records its owned descendants and
their process start times, kills the wrapper, and requires those original
processes to stop. All twenty checks pass, with two observed descendants each.
Start-time comparison prevents PID reuse from being mistaken for survival.
An absent process or a terminated zombie satisfies this execution-stop check;
it does not assert that the host has already reaped every zombie.

The retained run contains 224 RPC traces, including 206 verified replies and
eighteen receiver checkpoint traces. There are 102 receiver directories with
distinct test keys and 68 effect-store snapshots. The
[evidence manifest](evidence/20-isolated-outcome-graph/manifest.json) hashes
source, logs, probe observations, public configuration, signed outputs and
read-only database snapshots. Private seeds, binary databases and socket files
are excluded from the review export. The complete generated directory remains
a private local test artifact.

## What this changes about the breakthrough judgment

The courier's inability to read receiver keys is now exercised under operating
system enforcement while useful graph operations still succeed. Previously,
the public API withheld keys but the same-user filesystem did not. This is a
necessary improvement to the experiment's trust boundary.

The strongest objection to a breakthrough claim is unchanged: the equally
provisioned independent ledger matches every measured recovery and admission
outcome. Namespace isolation is shared infrastructure, not a new authorization
mechanism. The experiment supplies no measured latency, integration-code,
storage or operator-intervention advantage.

The host kernel, host operator, launcher, brokers, receiver implementations,
verifier, stores and clock remain trusted. A process outside these sandboxes
with host filesystem access can still reach the underlying files. There is no
independent remote administration, transport deployment, host power-loss test
or protection from database cloning. Bounded frames and waits do not establish
aggregate denial-of-service resistance: the fixture has no seccomp policy or
CPU, memory, process and disk quotas. The artifact remains a static native
capability-policy input evaluated at a fixed logical clock, with no live model,
arbitrary proposed executable or external deployment change.

The next result that would change the judgment must carry useful work beyond
this fixture and establish an advantage under a fair comparison, or address a
requirement that the alternative cannot meet under the same assumptions.
Installing more isolation layers or adding more graph stages alone would not
supply that result. Independent administration remains a separate boundary to
qualify, even after the local credential-access checks pass.

## Reproduction and validation

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- --isolated-graph
CARGO_TARGET_DIR=target cargo test --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml
CARGO_TARGET_DIR=target cargo clippy --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml \
  --all-targets -- -D warnings
```

Offline commands require cached dependencies. The isolated mode and third
integration test require `/usr/bin/bwrap`, enabled user namespaces and libraries
at the paths documented in the
[experiment README](../../../examples/outcome-ledger-comparison/README.md).
Sandbox failure aborts the run. The optional next argument selects a new output
directory. Brokers exist only during the comparison process, so saved socket
paths alone do not provide a persistent service.

| Check | Result |
| --- | --- |
| Original local comparison | All 28 paired scenarios still pass |
| Original and isolated graph comparisons | Each passes eleven execution scenarios and six attacks for both gates |
| Integration suite | Three tests passed |
| All-target Clippy | Passed with warnings denied |
| Formatting and diff whitespace | Passed |
| Paper build, references and derived macros | Passed: 12 pages, 4,962 body words |

The standalone run was repeated after adding descendant-termination checks
and correcting the probe's host-file positive control. Its evidence therefore
corresponds to the final tested implementation. No production runtime or
workspace dependency manifest changed in this continuation. The work remains
local and uncommitted on `paper/roadmap-phase-0-1`, based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. It has no exact-commit remote CI,
release qualification or achieved-breakthrough claim.
