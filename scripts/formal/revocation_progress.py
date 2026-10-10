"""Inductive progress projection of the pinned RevocationPropagation actions.

No epochs or trace length are bounded. Authorities/capabilities are finite. See
formal/revocation-progress.md for the manual projection and fairness argument.
"""
from itertools import product
import z3

PROCS, CAPS = 4, 8
PAIRS = list(product(range(PROCS), range(CAPS)))
MESSAGES = [(a, b, c) for a, b, c in product(range(PROCS), range(PROCS), range(CAPS)) if a != b]


def symbolic():
    return dict(clock=z3.Int("clock"),
                epochs={k: z3.Int(f"epoch_{k[0]}_{k[1]}") for k in PAIRS},
                issued={k: z3.Int(f"issued_{k[0]}_{k[1]}") for k in PAIRS},
                pending={k: z3.Bool(f"pending_{k[0]}_{k[1]}_{k[2]}") for k in MESSAGES})


def initial():
    return dict(clock=z3.IntVal(1), epochs={k: z3.IntVal(0) for k in PAIRS},
                issued={k: z3.IntVal(0) for k in PAIRS},
                pending={k: z3.BoolVal(False) for k in MESSAGES})


def well_formed(s):
    return z3.And(s["clock"] > 0,
                  *[z3.And(s["epochs"][k] >= 0, s["epochs"][k] < s["clock"],
                           s["issued"][k] >= 0, s["issued"][k] <= s["epochs"][k]) for k in PAIRS],
                  *[z3.Implies(p, s["issued"][a, c] > 0) for (a, _, c), p in s["pending"].items()])


def covers_lag(s):
    return z3.And(*[
        z3.Implies(s["epochs"][a, c] > s["epochs"][b, c],
                   z3.Or(*[z3.And(s["pending"][o, b, c], s["issued"][o, c] >= s["epochs"][a, c])
                           for o in range(PROCS) if o != b]))
        for a, b, c in MESSAGES])


def pending_count(s):
    return z3.Sum(*[z3.If(p, 1, 0) for p in s["pending"].values()])


def rank(s):
    return pending_count(s) + PROCS * z3.Sum(*[z3.If(e == 0, 1, 0) for e in s["epochs"].values()])


def copy_state(s):
    return dict(clock=s["clock"], epochs=s["epochs"].copy(), issued=s["issued"].copy(), pending=s["pending"].copy())


def revoke(s, omit_recipient=False, allow_repeat=False):
    # Permutation symmetry: all 32 choices of (authority, capability) are equivalent.
    a, c = 0, 0
    after = copy_state(s)
    after["clock"] = s["clock"] + 1
    after["epochs"][a, c] = s["clock"]
    after["issued"][a, c] = s["clock"]
    for b in range(1, PROCS):
        if not (omit_recipient and b == 2):
            after["pending"][a, b, c] = z3.BoolVal(True)
    enabled = z3.BoolVal(True) if allow_repeat else s["epochs"][a, c] == 0
    return enabled, after


def propagate(s, forget_observation=False, keep_message=False):
    # All 96 distinct (origin, receiver, capability) choices are symmetric.
    a, b, c = 0, 1, 0
    after = copy_state(s)
    if not keep_message:
        after["pending"][a, b, c] = z3.BoolVal(False)
    if not forget_observation:
        epoch = s["issued"][a, c]
        after["epochs"][b, c] = z3.If(epoch > s["epochs"][b, c], epoch, s["epochs"][b, c])
    return s["pending"][a, b, c], after


def evaluate(s):
    after = copy_state(s)
    after["clock"] = s["clock"] + 1
    return z3.BoolVal(True), after


def witness(model, s):
    return {"clock": str(model.eval(s["clock"], model_completion=True)),
            "rank": str(model.eval(rank(s), model_completion=True)),
            "epochs": {str(k): str(model.eval(v, model_completion=True)) for k, v in s["epochs"].items()},
            "pending": [{"from": a, "to": b, "cap": c,
                         "epoch": str(model.eval(s["issued"][a, c], model_completion=True))}
                        for (a, b, c), v in s["pending"].items() if z3.is_true(model.eval(v, model_completion=True))]}


def obligations():
    s = symbolic()
    invariant = z3.And(well_formed(s), covers_lag(s))
    yield "init", z3.BoolVal(True), z3.And(well_formed(initial()), covers_lag(initial()), rank(initial()) == 128), False, s
    yield "rank_nonnegative", invariant, rank(s) >= 0, False, s
    yield "empty_pending_caught_up", z3.And(invariant, pending_count(s) == 0), z3.And(*[s["epochs"][a, c] == s["epochs"][b, c] for a, b, c in MESSAGES]), False, s
    for name, action, strict in [("revoke", revoke(s), True), ("propagate", propagate(s), True),
                                  ("evaluate", evaluate(s), False), ("attenuate_or_stutter", (z3.BoolVal(True), s), False)]:
        enabled, after = action
        pre = z3.And(invariant, enabled)
        post = z3.And(well_formed(after), covers_lag(after),
                      rank(after) < rank(s) if strict else rank(after) == rank(s))
        yield name, pre, post, False, s
    for name, action, claim in [
        ("missing_recipient", revoke(s, omit_recipient=True), covers_lag),
        ("forgot_observation", propagate(s, forget_observation=True), covers_lag),
        ("retained_message", propagate(s, keep_message=True), lambda after: rank(after) < rank(s)),
        ("repeated_revoke", revoke(s, allow_repeat=True), lambda after: rank(after) < rank(s)),
    ]:
        enabled, after = action
        yield name, z3.And(invariant, enabled), claim(after), True, s
