# Revocation progress obligations

The historical Apalache 0.50.1 search at four authorities, eight capabilities and
length 24 timed out after an hour. Its result remains **unverified**. The
scheduled lane now supplements the finite TLC witnesses with inductive SMT
obligations at the original authority/capability cardinalities. It does not rerun
or relabel that old search as passing.

## Projection and correspondence boundary

`scripts/formal/revocation_progress.py` is a manually translated projection of
`RevocationPropagation.tla`. The registry pins both that source and the source
of `PendingCoversLag`; source drift refuses qualification until the translation
has been reviewed. This is not a machine-checked TLA-to-SMT refinement, a proof of
Rust hooks, or a proof of the original receipt/attenuation safety invariants.

The projection keeps all 32 observation epochs and the global clock as unbounded
integers. `issued[a,c]` is a ghost recording the epoch of authority `a`'s sole
local revocation of capability `c`. Zero means no local revocation. There can be
at most one such revocation: `Revoke` requires non-revoked state, all revocation
updates are monotone, and `RevocationStateCoupled` equates revoked state to a
positive observation epoch. Each pending bit `(a,b,c)` denotes exactly the
original message `[from=a,to=b,cap=c,epoch=issued[a,c]]`. Thus 96 bits represent
the entire possible pending set without bounding epoch values.

`Revoke` installs the clock, broadcasts to every other receiver, and increments
the clock. `Propagate` consumes one message and installs the maximum of its epoch
and the receiver's epoch. `Evaluate` only advances the projected clock;
`Attenuate` and explicit stuttering leave the projection unchanged. Omitting
receipt logs and attenuation depths is sound for these progress obligations
because those fields neither enable nor disable propagation. This correspondence
is a reviewed argument, not an automatic translation certificate.

The SMT transition checks use one representative local revocation and one
representative distinct origin/receiver pair. Permuting the four authorities and
eight capabilities preserves every formula and the original actions (there are
no distinguished identities). Therefore these are the 32 and 96 symmetric action
instances, with the full 4-by-8 symbolic state retained. The unconstrained
prestate ranges over the inductive invariant, including unreachable states.

## Checked obligations and fairness argument

The invariant requires natural observation/issuance epochs below the clock,
issuance no greater than the issuer's observed epoch, and a positive issuance
for each pending message. `PendingCoversLag` requires a pending message with an
adequate epoch for every lagging receiver. Initialization and each action
preserve these conditions; every action's premise must itself be satisfiable.

Define `R = pending_count + 4 * nonrevoked_pair_count`. Initially `R = 128`.
A local revocation removes one nonrevoked pair and adds at most three messages,
so it strictly decreases R. Propagation consumes one message and cannot increase
the nonrevoked count, so it strictly decreases R. Evaluation, attenuation and
stuttering preserve R. R is a natural number. An empty pending set implies all
observed revocations have caught up. Z3 checks these statements with unbounded
integer epochs; every query has a ten-second deadline and unknown is failure.

The remaining temporal argument uses the original `WF_vars(PropagateAny)`:
R cannot strictly decrease infinitely. After its last decrease no revocation or
propagation can occur. If pending were nonempty in this suffix, propagation
would be continuously enabled and weak fairness would require another decrease,
a contradiction. Hence pending eventually empties permanently and every lag
closes. The fairness premise is essential; the existing unfair TLC witness
continues to produce the named temporal counterexample. This paragraph is a
manual well-founded argument, not a temporal solver verdict.

Four SMT mutants must be satisfiable counterexamples to their named obligations:
missing a broadcast recipient and consuming without observation break coverage;
retaining a delivered message and allowing repeated local revocation break
strict rank decrease. Syntax errors, unknown, vacuous premises and timeouts do
not count as mutant detection. The finite TLC positive/negative witnesses remain
part of the scheduled acceptance set.
