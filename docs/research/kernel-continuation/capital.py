"""Finite capital model, not a production allocator or economic measurement."""
from dataclasses import dataclass
from itertools import product

@dataclass(frozen=True)
class Claim:
    amount: int
    state: str
    selection: int | None = None

def reserve(refund, claims):
    if type(refund) is not int or refund < 0:
        raise ValueError("refund must be nonnegative integer units")
    fixed = refund
    selectable = {}
    for claim in claims:
        if (type(claim.amount) is not int or claim.amount < 0
                or claim.state not in {"earned", "unknown", "absent", "ready"}
                or (claim.selection is not None and
                    (type(claim.selection) is not int or claim.selection < 0))):
            raise ValueError("invalid claim")
        if claim.state == "absent":
            continue
        # An old selection label is not proof that already dispatched work
        # cannot earn. Only an enforced PRE-dispatch selector gets this saving.
        if claim.state == "ready" and claim.selection is not None:
            selectable[claim.selection] = max(
                selectable.get(claim.selection, 0), claim.amount)
        else:
            fixed += claim.amount
    return fixed + sum(selectable.values())

def exhaustive(refund, claims):
    """B1: enumerate independently specified possible payment vectors."""
    totals = []
    for paid in product((False, True), repeat=len(claims)):
        if any((c.state == "earned" and not p) or (c.state == "absent" and p)
               for c, p in zip(claims, paid)):
            continue
        selected = [c.selection for c, p in zip(claims, paid)
                    if p and c.state == "ready" and c.selection is not None]
        if len(selected) != len(set(selected)):
            continue
        totals.append(refund + sum(c.amount for c, p in zip(claims, paid) if p))
    return max(totals)


def experiment():
    checked = 0
    mismatches = []
    for size in range(6):
        for states in product(("earned", "unknown", "absent", "ready"), repeat=size):
            for partition in ("none", "one", "two"):
                claims = [Claim(10 + 20 * (i % 3), state,
                                None if partition == "none" else
                                0 if partition == "one" else i % 2)
                          for i, state in enumerate(states)]
                candidate, baseline = reserve(100, claims), exhaustive(100, claims)
                checked += 1
                if candidate != baseline:
                    mismatches.append([states, partition, candidate, baseline])
    examples = {
        "two_earned": [Claim(30, "earned", 0), Claim(30, "earned", 0)],
        "three_exclusive_ready": [Claim(50, "ready", 0)] * 3,
        "three_unknown": [Claim(50, "unknown", 0)] * 3,
        "fenced_absent": [Claim(50, "absent")],
    }
    return {"schema": "chio.research.capital.v1", "synthetic": True,
            "profiles": checked, "mismatches": mismatches,
            "examples": {name: {"candidate": reserve(100, claims),
                                "B1": exhaustive(100, claims)}
                         for name, claims in examples.items()}}


if __name__ == "__main__":
    import json
    result = experiment()
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["mismatches"]:
        raise SystemExit(1)
