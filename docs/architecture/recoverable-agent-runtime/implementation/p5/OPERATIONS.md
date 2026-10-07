# P5 confined-return operating contract

This is trusted host plumbing over the existing native SQLite authority and
process artifact broker. `NativeConfinedRuntime` is constructed by the operator;
workers receive admitted values through the selected sink. Installation data,
reservation DTOs and deserialized cage receipts cannot create execution custody.
The source review covers the declared profile. Phase exit still requires the
real Linux acceptance result; this package must not advance P6 while it is blocked.

## Supported profile

Linux x86_64, retained measured cage-init and a static PIE projection executable,
`NativeMinimalV1`, default-deny Landlock and independent seccomp, exact credentials,
the exact host-fixed environment `LANG=C`, `LC_ALL=C`, `TZ=UTC`, and one fixed
argument. No parent environment variables are permitted. There are no filesystem grants,
network destinations, broker socket, delegated tools, model calls or provider
conversation/cache. A reused provider context cannot satisfy this profile.

Only a root process may attach a confined child. The exact CA-signed parent and
child capabilities must pass the existing delegation verifier, operator trust
root, current time and revocation checks. The child has no tool, resource or
prompt grants and a fixed 625 basis-point parent budget share. The original
process journal also enforces its own aggregate tree, child and depth quotas.
Callers cannot choose child IDs, observation lineage or epochs.

The worker receives a framed immutable canonical JSON observation and up to eight
immutable seed versions. The complete frame is at most 64 KiB, including framing.
The operator pins one exact boolean field projection. Only canonical `true` or
`false`, independently recomputed by the trusted host, can become a return.
The contract bounds that value to one item and eight bytes. A valid boolean alone
authorizes neither disclosure nor an integrity assertion.

Confidentiality narrowing requires an exact signature under the selected
confined-disclosure root. Integrity, when required, uses a distinct selected root
and signature domain. Both bind boundary, measured launch, artifact version,
content, source, influence, parent identity/lineage/epoch, projection, policy and
expiry. The child retains its full source restrictions. The parent's prior
knowledge is preserved and joins the exact admitted return before delivery.

Every other route is withheld: raw stdout, errors, stderr, logs/traces, progress,
completion bodies, file attachments, callbacks and streaming chunks. stdout is a
private eight-byte candidate buffer; stderr is a private bounded classified
buffer that is discarded. Overflows, malformed or incorrect projections,
nonzero exits and unavailable provenance produce only a generic host refusal.
No raw-byte debugging fallback exists. The selected sink receives the admitted
intent and exact boolean; full return evidence stays in trusted review custody.

There are at most 16 permanent reservations per physical parent scope, one
measured launch per reservation, 16 KiB per diagnostic channel, and an absolute
execution deadline no later than 30 seconds after reservation. Disabled model and
tool channels have zero budgets. Native record/history/traversal ceilings and the
existing cage's bounded child supervisor remain applicable. Holding a child
handle or sending another chunk does not renew the deadline: a retained pidfd
monitor terminates that exact process. Profile expansion requires new enforcement
and acceptance, not a larger DTO limit or an environment/argument override.

## Install and run

Configure the native recovery deployment, durable knowledge installation and
process security profile first. Select independent disclosure and endorsement
keys, the exact parent recipient, return contract, measured execution profile and
limits. Configure the kernel's delegation trust root through its existing
operator API. Construct the native runtime with the same authority, mutation
fence and enforced artifact broker; disagreement refuses installation.

1. `reserve` allocates and pins the native logical boundary, then attaches it to
   the existing process journal and registers its authenticated capability.
2. `launch` validates the live attachment and consumes a sealed cage preparation
   once. Only observed fully enforced launch permits input preparation.
3. Native admission joins current parent knowledge, selection/control metadata,
   all seeds and the sensitive observation into the child before writing stdin.
4. Consuming `ConfinedExecution::stage` observes the actual exit, bounds both
   channels, checks canonical output and independently recomputes the predicate.
5. `review_return` can recover classified approval data after lost staging
   acknowledgement. It requires current review authority and audience clearance.
6. `prepare_return` holds immutable bytes privately. `deliver` rechecks current
   parent/recipient, native authority, contract, source and influence, consumes
   scoped evidence and commits the parent's join before calling the sink.

The native commit admits the knowledge join and stable return intent. Immediately
before sink I/O, the broker revalidates context and retained capability liveness,
then reads parent activity under the process journal's cancellation serialization.
That final activity read orders release against process cancellation. Cancellation
completed before it withholds bytes and preserves any committed join and spent
evidence. Later cancellation cannot retract a release already authorized at that
point. No process/store lock or database transaction spans sink I/O.

Delivery acknowledgement is a separate step. A sink failure retains an uncertain intent; retry must use the
same recipient and current authority. Stable redelivery does not create a new
intent or consume another disclosure. Receiving sinks should deduplicate by the
retained release ID if their application requires one visible application action.

## Failure, restart and cancellation

Native authority, process journal and immutable blob journal are separate durable
owners. There is no transaction across them. The native boundary, original input
pins and permanent count commit before attachment. An attachment failure cannot
start a cage or refund the native slot. Repeating the exact reservation may repair
an attachment acknowledgement while it is still `Reserved`.

A prepared launch cannot be automatically retried after a lost acknowledgement.
Dropped execution custody marks retained preparation/enforcement uncertain and
quarantined when current authority allows that update; cage custody still kills
and reaps the exact child. A missing host never implies an observed normal exit.
Input joins, measured launch identity, pins and counts survive all dispositions.

Retained `ReturnStaged` or admitted data can be reconciled without relaunching.
Reopen the original native writer and process journal, restore the same operator
installation and trust root, then review or redeliver the retained return. Fresh
capability, recipient, policy or installation disagreement withholds it. A changed
child source or influence after staging refuses first admission. Reissuing the
same child principal into a new epoch cannot clear prior observation.

`cancel` commits the native terminal disposition before cancelling the process
journal. Execution custody can additionally terminate the actual pidfd. Future
launch, context derivation and return preparation refuse. Cancellation does not
remove pins, refund budgets, clear knowledge or claim previously admitted data
vanished. A delayed acknowledgement cannot reactivate a cancelled child.

## Reproduce qualification

`evidence/run-gates.py` records every actual local command, source binding, exit
code and log. The cached Python interpreter and isolated npm lockfile installs are explicitly
recorded local tooling. Node lifecycle hooks are disabled. Temporary dependency
directories and aliases must be removed before sealing. Source changes invalidate
earlier successful gates.

Run the required real Linux campaign from the same source checkout:

```bash
python3 docs/architecture/recoverable-agent-runtime/implementation/p5/evidence/run-linux-acceptance.py
```

It refuses other platforms with exit 64. On Linux x86_64 it runs the existing
strict cage probe/mutation inventory, builds and measures interpreter-free
static PIE helper/reader plus nine adversarial images, and executes all ten P5
Linux tests without ignored or missing cases. The campaign includes a useful
parent decision, every declared channel, genuine native writer reopen, launch and
return cutpoints, current authority refusal and a held-handle absolute deadline.
Linux needs the repository's normal dependencies, musl Rust target/compiler,
Landlock ABI and ptrace/seccomp facilities. A cross compilation proves types and
lint; a mocked gate rejection test proves the checker, not Linux confinement.

After all required local gates and source review are current:

```bash
python3 docs/architecture/recoverable-agent-runtime/implementation/p5/evidence/seal-package.py
python3 docs/architecture/recoverable-agent-runtime/implementation/p5/evidence/verify-package.py
```

A blocked Linux result can seal local work but leaves `phase_accomplished=false`.
Hosted CI, provider/connector integrations, two-host product acceptance,
comparative workloads and production release qualification remain P6 work.
