"""Finite-state exploration and trace export, including a deliberately bad rail.

Two pre-funded obligations, amounts 3 and 2, one child level, a finite set of
timestamps and authenticated symbolic actors. This is not a finality or
cryptographic proof. The broken-expiry switch changes only this test driver.
"""

import argparse
from collections import deque
import copy
import json
from pathlib import Path

from claim_model import ClaimLedger, Terms

TIMES = (0, 2, 3, 4, 5, 6, 7, 8, 9)


def snapshot(ledger):
    return {name: {"state": job.state, "commitment": job.commitment,
                   "decision": job.decision, "accepted": job.accepted,
                   "unknown": job.execution_unknown, "paid": job.paid,
                   "refunded": job.refunded, "locked": job.locked}
            for name, job in ledger.jobs.items()}


def state_key(ledger, now):
    return (now, *(tuple(vars(job).values()) for job in ledger.jobs.values()))


def actions(ledger):
    for name, job in ledger.jobs.items():
        for commitment in ("output", "changed-output"):
            yield dict(job=name, op="submit", actor=job.terms.recipient, commitment=commitment)
        yield dict(job=name, op="submit", actor="X", commitment="output")
        for accepted in (True, False):
            yield dict(job=name, op="decide", actor="V", decision="decision", accepted=accepted)
        yield dict(job=name, op="decide", actor="V", decision="changed-decision", accepted=True)
        yield dict(job=name, op="decide", actor="X", decision="decision", accepted=True)
        yield dict(job=name, op="pay", actor=job.terms.recipient)
        yield dict(job=name, op="pay", actor="X")
        yield dict(job=name, op="refund")
        yield dict(job=name, op="expire")
        yield dict(job=name, op="unknown")


def apply(ledger, action, now, broken_expiry=False):
    job = action["job"]
    op = action["op"]
    if op == "submit":
        return ledger.submit(job, action["actor"], action["commitment"], now=now)
    if op == "decide":
        return ledger.decide(job, action["actor"], action["decision"], action["accepted"], now=now)
    if op == "pay":
        return ledger.pay(job, action["actor"], now=now)
    if op == "refund":
        # Negative calibration: reproduce a rail that expires an earned claim.
        if broken_expiry and ledger.jobs[job].state == "Payable" and now > ledger.jobs[job].terms.refund_after:
            ledger.jobs[job].state = "Submitted"
        return ledger.refund(job, now=now)
    if op == "expire":
        return ledger.expire(job, now=now)
    ledger.mark_unknown(job)
    return True


def violation(ledger):
    for job in ledger.jobs.values():
        if job.accepted and job.refunded:
            return "accepted claim was refunded"
        if job.paid and job.refunded:
            return "incompatible monetary terminals"
        if job.paid > job.terms.amount or job.refunded > job.terms.amount:
            return "duplicate service payment or refund"
        if (job.state == "Paid") != (job.paid == job.terms.amount):
            return "paid state disagrees with transfer"
        if (job.state == "Refunded") != (job.refunded == job.terms.amount):
            return "refunded state disagrees with transfer"
    for source, deposited in ledger.deposits.items():
        amounts = ledger.accounts(source)
        if min(amounts) < 0 or sum(amounts) != deposited:
            return "source conservation failed"
    return None


def explore(*, broken_expiry=False):
    initial = ClaimLedger({"A": 3, "B": 2})
    assert initial.fund("parent", Terms("A", "B", "V", 3, 2, 4, 6, 8), now=0)
    assert initial.fund("child", Terms("B", "C", "V", 2, 2, 4, 6, 8), now=0)
    queue = deque([(initial, 0, [])])
    visited = {state_key(initial, 0)}
    representatives = {}
    states_seen = set()
    transitions = 0
    counterexample = None
    while queue and counterexample is None:
        ledger, now, prefix = queue.popleft()
        states_seen.update(job.state for job in ledger.jobs.values())
        next_index = TIMES.index(now) + 1
        if next_index < len(TIMES):
            next_time = TIMES[next_index]
            key = state_key(ledger, next_time)
            if key not in visited:
                visited.add(key)
                queue.append((ledger, next_time, prefix + [dict(op="advance", time=next_time)]))
        for action in actions(ledger):
            candidate = copy.deepcopy(ledger)
            before = ledger.jobs[action["job"]].state
            ok = apply(candidate, action, now, broken_expiry)
            transitions += 1
            after = candidate.jobs[action["job"]].state
            step = dict(action, time=now, ok=ok, expected=snapshot(candidate))
            path = prefix + [step]
            problem = violation(candidate)
            if not problem and any(job.execution_unknown and not candidate.jobs[name].execution_unknown
                                   for name, job in ledger.jobs.items()):
                problem = "financial transition erased execution uncertainty"
            if not problem and not ok and candidate != ledger:
                problem = "denial changed authoritative state"
            if problem:
                counterexample = dict(property=problem, steps=path)
                break
            # Financial edge representatives become actual bytecode replay cases.
            if action["op"] != "unknown":
                edge = (action["job"], action["op"], before, after, ok, action.get("accepted"))
                representatives.setdefault(edge, dict(op=action["op"], before=before, after=after,
                                                      ok=ok, steps=path))
            key = state_key(candidate, now)
            if key not in visited:
                visited.add(key)
                queue.append((candidate, now, path))
    return dict(schema="chio.experimental.claim-model-exploration.v1", broken_expiry=broken_expiry,
                timestamps=list(TIMES), deposits={"A": 3, "B": 2}, states=len(visited),
                transitions=transitions, states_seen=sorted(states_seen), counterexample=counterexample,
                traces=list(representatives.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--broken-expiry", action="store_true")
    args = parser.parse_args()
    result = explore(broken_expiry=args.broken_expiry)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("traces", "counterexample")}))
    if result["counterexample"]:
        print(json.dumps(result["counterexample"]))
        raise SystemExit(1)
