# P3 operating contract

This phase implements bounded support reads, issue creation and deterministic
field projection through the existing native process, admission, capture,
outcome and release path. Its assurance scope is the local sequential profile
recorded in `verification.json`. The pure semantic crate verifies descriptions;
the kernel and physical serving store own execution authority.

## Installation and authority

Trusted host setup supplies `NativeSemanticInstallationV1`: independently
selected publisher and operator roots, the actual exposed tool/channel inventory,
the native serving authority and the host-issued security context. The signed
deployment binds all three inventories. A publisher cannot install operator,
resolver, endorsement, transformation or prerequisite authority by itself.

`configure_semantic_deployment` verifies a complete generation before its atomic
activation. Package dependencies resolve locally, with no URL fetches. A changed
deployment requires a strictly newer generation under the same operator and
native authority. Failed reload preserves the prior generation. Removed routes
leave protected refusal tombstones. Captured operations retain their original
contract, destination, disposition and native ledger through reload and restart.

The host constructs a `PinnedSemanticConnector` for each selected route and an
account-specific transport. `SemanticTransportRouter` selects an exact registered
destination and its separately configured credential. Inputs cannot supply an
endpoint or credential. `NativeSemanticRuntime::accept_plan` requires native
Select authority; every executed step still requires its own current capability.

## Exact review and fresh checks

First accept the bounded plan, construct the process request and call
`frame_action`. Obtain separately signed ACL, endorsement, annotation,
transformation and prerequisite evidence for that exact action, then place the
closed `SemanticInvocationV1` in the request's arguments. Signatures bind the
request identity, authenticated namespace, capability, all reviewed request
semantics, payload, input versions, native source generation, influence,
destination, plan, step, disposition and validity interval.

Physical capture checks current native policy, revocation, credentials, input
journals, ACL, semantic generation, exact materialized bytes and prerequisite
state. Only this original call's proven native nonce/input joins may advance its
reviewed source generation. A foreign equal-label update refuses. Scope, labels,
influence and endorsement are separate checks: an integrity endorsement cannot
lower confidentiality or supply a missing disclosure grant or capability.

The connector performs another protected native policy, capability, ACL,
prerequisite and clock check immediately before submission. Its protected
submission marker is consumed once. `CapturedSemanticSubmissionV1` has private
construction, consumes ownership at the transport boundary, and is Send but
neither Sync, Clone nor Deserialize. A duplicated wire description cannot become
a second native submission owner. Blocking store work retains its bounded
semaphore permit even if the waiting task is cancelled.

## ACL and provider contract

The selected resolver publishes `SignedSemanticAudienceV1` scoped to provider,
account, resource, subject mapping and query. Positive evidence requires complete
pagination, an exhausted cursor, matching page counts and fresh bounded validity.
A newer partial, ambiguous, outage or rate-limited observation invalidates an old
positive. Replacing an observation requires a strictly newer observation time;
an identical reinstallation is idempotent. Wildcard, weak, multi-value or malformed
provider versions cannot satisfy a required atomic precondition.

`HttpSemanticTransport` targets a trusted Chio-compatible HTTPS gateway. This is
a closed gateway protocol, not an implementation of arbitrary vendor REST APIs.
The gateway MUST authenticate the configured account, bind the complete
provider/account/resource tuple, and enforce the supplied ACL/resource version
before performing the read or issue creation. For `AtomicIfMatch`, it MUST
atomically compare that version at the effect boundary. Its bounded response
MUST echo the tuple, checked version, native operation and attempt actually used.
Echoing fields after an unguarded effect does not implement this contract.

The HTTP adapter sends one GET (support read) or POST (issue creation), a closed
canonical request and one strong If-Match value. Stored bearer tokens use Zeroizing,
redirects/retries/proxies are disabled, and non-success, raw or unbound responses
produce generic refusal. Hosts explicitly select `AtomicIfMatch` or
`LastLocalCheckOnly` after qualifying their gateway. A route requiring an atomic
precondition refuses the weaker transport. `LastLocalCheckOnly` exposes the gap
between the final local observation and an external effect; it is not an atomic
provider guarantee. No live gateway, vendor or network guarantee was qualified by
this local phase acceptance.

## Transformation and prerequisites

Field projection is a separate native read-only producing step with pinned code,
configuration, input/output schemas and exact retained output. It preserves
source restrictions and influence. Its dependent step must declare that producer
and consume its one exact FutureOutput; unrelated extra transform inputs refuse.
Fresh authority and independently signed provenance bind the dependent action,
output, destination and purpose. Persistent reusable artifact endorsements and
transform certificates remain P4.

Historical facts prove an exact completed producer and input version. Current
predicates additionally require the current selected authority's unrevoked
observation at capture and submission. Held reservations additionally require
current lease ownership, an exact action and one-shot native lease consumption.
Reinstalling an old signature cannot clear revocation or spend. A receipt alone
cannot stand in for a current predicate or held reservation.

`Withhold` is part of the accepted action. The effect and retained native outcome
remain original; caller response and replay receive only
`{"status":"withheld"}`. Withheld producer bytes cannot become a future input or
transformation release. Provider errors have no raw diagnostic fallback. A
missing response, timeout, refusal after capture or withheld result does not
authorize a replacement attempt. Resume/reconcile uses P1's original operation
and known-only process path. Never retry an unknown external effect under a new
step or request identity.

## Limits and unsupported profiles

| Resource | Limit |
|---|---:|
| Packages, total operations, routes, plan steps, selectors | 16 each |
| Dependencies per step, endorsements, annotations, prerequisites | 8 each |
| Endorsement assertions, projection fields | 8 each |
| Aggregate observed annotation/assertion/prerequisite facts | 32 |
| Shared pure verification work units | 4096 |
| Semantic evidence lifetime | 60 seconds maximum |
| Wire ingress and provider request/response | 64 KiB |
| Protected recovery record / native output ceiling | 256 KiB |
| Concurrent connector store/submission owners per connector | 8 |
| HTTP request / connect timeout | 10 / 3 seconds |

Each package explicitly inventories all 13 channels. This profile enables only
input, typed success, sanitized error and no-value paths. Nested, batch,
pagination, redirect, stream, file, log, shell and model-output channels refuse.
Model provenance in a native request is still bound as influence; it does not
enable a model-output transport channel. Selector variants and annotator powers
are finite. No model confidence value grants authority.

## Upgrade, evidence and qualification

Semantic records reuse the existing protected recovery inventory, commit events,
rollback anchor and serving-store fence. This phase introduces no parallel
execution lifecycle or independent database migration. Additive wire schemas use
`https://chio.computer/schemas/`; retained legacy schema identifiers are finite
local aliases and never fetched from those domains. Rust, Python and TypeScript
bindings are regenerated under existing pins, including required nullable proof
fields. Historical P1/P2 phase evidence is preserved byte-for-byte.

Run `python3 docs/architecture/recoverable-agent-runtime/implementation/p3/evidence/verify-package.py`
from the checkout root to verify the retained package against its exact sources,
archives, gates, requirements and dependency pins. This integrity check does not
rerun tests. `run-gates.py` retains the commands and output for executable checks.

Local acceptance is separate from hosted CI, live-provider integration, Linux
confinement, formal proof tools, scale/performance qualification and production
release. Prior broad P1 stress and Node HTTP socket failures remain recorded in
the immutable P2 evidence; this phase does not convert them into passing results.
Current broad Rust attempts also retain six conformance and 12 kernel payment
listener EPERM failures. The qualified kernel library gate explicitly filters
only those 12 unchanged listener tests; there is no unfiltered-kernel green claim.
The owning gate uses two test threads and a canonical temporary directory to
preserve SQLite's no-symlink checks. A corrected store component passed 1,802
library tests with zero failures, four declared ignored cases and 29 exact
unavailable separate Linux `/dev/shm` anchor-device filters. Its aggregate command
then failed 11 remote-delivery cases during EPERM socket setup and remains a
failed command in the retained evidence. Focused rollback regression and store
doctest gates supplement the complete eight-package owning gate and native P3/P2
tests. The failed broad store run and unchanged isolated egress diagnostics remain
retained; there is no distinct-device, default-concurrency, remote-delivery or
unfiltered-store qualification. Three
rollback fixtures now resolve their existing backup parent before VACUUM, retaining
their original stale-restore refusal assertions and all production path checks.
The SDK checks use documented existing offline caches, with the recorded cache
versions distinguished from the unchanged lock pins.

Next: P4 durable knowledge, including mediated artifact publication/read,
labeled checkpoints and model contexts, restore/export, retention, adoption and
safe garbage collection.
