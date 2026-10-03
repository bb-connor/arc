# Swarm evolution result

The new behavior is live extension with preserved old work. This closes the
immutable-bundle storage gap using the existing verifier, runtime store,
bilateral treaty gate and native operation-owned continuation resources.

## Focused observations

Five new pure-verifier tests accept a valid one-worker to two-worker extension
and reject policy, nonce, lifetime, allocation, pool, route, witness and epoch
rewrites. The rewrite table first establishes that each candidate is otherwise
an individually valid signed bundle. Other cases reject supplied-time bypass,
untrusted keys, reused attempts, extra old-task allocations, non-single-use
tokens, no growth and excess declared capacity.

Four durable-store tests preserve both versions after reopen, reject stale heads
and ordinary overwrite, leave head/history unchanged after rejection, elect one
winner between separate SQLite connections and reject corrupt historical
index/hash/payload bindings.

Three native trajectories establish:

- An original worker executes, checked growth installs, and the new worker
  executes. Reopen/replay returns the exact original receipt and physical claim.
  A fresh request for the consumed continuation rejects with the invocation
  counter unchanged. The capability retains separate invocation headroom,
  excluding simple capability exhaustion as the explanation.
- An original unstarted worker executes using its exact earlier graph after
  extension and reopen.
- An original operation retains bilateral treaty evidence and all three
  physical resources (destructive lease, treaty continuation, swarm
  continuation). Explicit claim revalidation passes before and after reopen;
  stripping treaty context rejects, and replay adds no effect.

These seven store/native cases passed together in the focused terminal run.
Final combined qualification also passes: 453 swarm/runtime tests, 54 workflow
tests, 9 native delegation labels, 5 existing native regression labels and 12
artifact tests. One pre-existing workflow doctest remains ignored. All 11
recorded commands exited zero, including strict Clippy, formatting and the
runnable example. Counts include the documented subprocess helper labels.
The [combined qualification](../dynamic-delegation/evidence/qualification.json)
records the full changed-crate suites, lints and formatting on exact source
inputs. Its command streams, not this prose, determine terminal status. The
whole-change review is recorded in [REVIEW.md](REVIEW.md).

## Failure history

The evidence directory retains the initial full runtime build failure: five
pre-existing JSON mappings passed strings to a typed serde_json error variant.
The implementation now preserves those typed errors. The API-missing run is
the expected test-before-implementation failure.

The first full-crate qualification also exposed an inherited treaty substitution
helper calling the removed global-clock API. It now injects the existing fixture
clock and retains the separate receipt ID scope. That failed compilation is
retained in the combined qualification history.

The next full run reached an inherited lease rollback assertion that expected
a string store error after SQLite failures had become typed. The assertion now
matches the exact injected SQLite failure and keeps all rollback/reopen checks.
The subsequent full swarm/runtime run passed 453 tests. This preliminary result
preceded the D1 review repairs; the combined record qualifies final source.

The first native trajectory incorrectly used a helper that selected one
physical operation after the test had created two. It now selects the original
operation through its receipt. The initial treaty-restart fixture regenerated a
verifier key, changing its signed policy inputs; native revalidation correctly
rejected that change. The corrected fixture retains the original policy inputs.
Both failures are retained and identified as fixture mistakes.

Passing reruns do not relabel those initial campaigns as successful. No result
here establishes independent operators, geographic fault tolerance, arbitrary
reconfiguration, automatic reclaim, financial backing, global information-flow
security, or complete production qualification.

## What this changes

The useful implementation result is a compositional lifecycle operation: a
running swarm can add work without invalidating or refreshing issued work.
Conservation follows from monotone allocations and one protected installed
lineage, with replay enforced by existing native custody. Standard transactional
and capability constructions can implement the same discipline.

The outstanding research question is whether the shared interface substantially
reduces the work of assembling useful systems across owners. More local test
counts alone do not answer it. A unified allocation handoff and an independent
implementation are more informative than another bespoke workflow fixture.
