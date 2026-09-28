# Response lifecycle and propagation evidence

`formal/response-lifecycle.toml` names the finite lifecycle model, exact negative
inventory and production functions. `scripts/check-response-lifecycle.py` checks
that inventory, fingerprints the actual source hooks and requires each negative
variant to violate its named invariant. A parse failure, another invariant's
counterexample, timeout or incomplete positive run cannot pass.

The current finite model has two actions, two targets, two workers and four clock
values. TLC completed 87,810 distinct states at depth 33. Eight calibrated
counterexamples cover dry-run dispatch, overlap removal, false clean lift,
unacknowledged activation, unexecuted acknowledgement, fabricated nonexecution,
unresolved timeout and the intentionally false claim that lifting one owner
clears every restriction on its targets.

The Rust corpus drives `ResponseStateMachine`, its canonical record decoder,
effect mutations, timeout handler and reconstructed owner over the committed
store. Its trace includes the durable intermediate Expiring transition even when
one timeout call also commits RollingBack. Set `CHIO_RESPONSE_TRACE_DIR` while
running `lifecycle_seed_corpus_reaches_apply_rollback_expiry_and_restart`, then
pass its `lifecycle.json` to the model runner's `--runtime-traces` option. The
runner validates contiguous mutation generations, request/acknowledgement order,
transition sources and restoration before clean lift, requires the apply,
partial rollback, retry, expiry and terminal states, and fingerprints that trace.
Calibrated checker tests reject reordered commits, unrequested acknowledgements
and a clean lift after failed restoration. The mutations come from the production
state machine over a test store. They do not independently establish an external
effect journal, signed receipt delivery, OS crash behavior or Rust/TLA refinement.
Signed receipt integrity is exercised separately by the owning control-plane
regression.

Four Kani harnesses in `chio-security-types::kani_public_harnesses` call the
production clock fence, deadline, skew arithmetic and response state guards.
Inputs cover the full `u64` domain; overflow and unwinding checks remain enabled,
with unwind 4. The crate-level manifest runner completed all four within their
60-second command bounds. They prove refusal preserves the last accepted clock reading,
retries retain the original deadline, skew arithmetic cannot wrap, terminal
states have no outgoing legal edges, and the shared clean-rollback predicate
requires restoration of every applied reversible effect. They do not prove
external effect completion, signing, durable storage or transport fairness.

## Revocation temporal timeout disposition

The original 4-authority/8-capability, length-24 SMT run timed out at 3,600 seconds.
That result remains unverified. A later four-step SMT projection attempt also
timed out at 60 seconds. Neither timeout is passing evidence or a counterexample.

The scheduled propagation job now runs
`scripts/check-revocation-propagation.py`. Each case has a 60-second bound and the
job has a ten-minute bound. It checks:

1. The finite origin/receiver projection at epoch bound 3 (40 distinct states),
   under explicit conditional observation fairness.
2. A 3-authority/1-capability epoch-order quotient using the original Attenuate,
   Revoke and Propagate actions (3,488 distinct states). This checks
   `PendingCoversLag`, `TemporalProjectionRefines` and `RevocationEventuallySeen`
   with weak fairness of propagation.
3. A three-state issuance/delivery witness ending in a fair stuttering suffix.
4. A counterexample to unconditional observation when fairness is absent.

Evaluate changes the full model's clock and receipt log, neither of which is in
the pair projection. Removing Evaluate and labeling revocations consecutively
preserves the ordering used by propagation. Each authority/capability revokes at
most once, so only finitely many messages are introduced; weakly fair propagation
eventually drains the finite pending set. These reduction and fairness-transfer
arguments are documented reasoning, not mechanized unbounded refinement.
Receipt authorization safety and the original larger temporal bound are outside
this reduced claim. Their existing safety configurations remain unchanged.

Both scripts preserve per-case logs and source hashes. Their workflow verdicts
require terminal success and retain evidence on failure. Local completion does
not establish a hosted result for the current candidate.
