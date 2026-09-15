#!/usr/bin/env python3
"""Exercise separately agreed unknown-hold releases across isolated HTTPS peers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess

from https_smoke import HttpsScenario
from smoke import write


def run_case(binary, root, fault, before_review=False):
    case = HttpsScenario(binary, root)
    try:
        case.start("before-review" if before_review else "after-review")
        failed = case.invoke("buyer", "work", "/state", case.url)
        assert failed.returncode != 0
        assert case.process.wait(timeout=10) in (-9, 137)
        case.start()
        unresolved = case.call("buyer", "work", "/state", case.url)
        assert unresolved["paymentResolution"] == "required"
        assert (unresolved["available"], unresolved["reserved"], unresolved["spent"]) == (900, 100, 0)
        write(root / "unknown.json", unresolved)
        id = unresolved["operationId"]
        cap = unresolved["request"]["acceptance"]["ask"]["body"]["tokenOffer"]["id"]
        with sqlite3.connect(root / "provider/authority.sqlite") as db:
            original = db.execute("SELECT operation_json FROM admission_operations WHERE operation_id=?", (id,)).fetchone()[0]
            journal = db.execute("SELECT * FROM payment_journal WHERE operation_id=?", (id,)).fetchone()
        before = None
        if fault.startswith("release-"):
            case.stop()
            case.start(fault)
            failed = case.invoke("buyer", "resolve", "/state", case.url)
            assert failed.returncode != 0
            assert case.process.wait(timeout=10) in (-9, 137)
            before = case.counts()
            expected = "held" if fault == "release-before-rail" else "released"
            assert before["payments"] == {expected: 1}, before
            with sqlite3.connect(root / "provider/authority.sqlite") as db:
                assert db.execute("SELECT COUNT(*) FROM unknown_payment_release_records WHERE operation_id=?", (id,)).fetchone()[0] == (2 if fault == "release-after-receipt" else 1)
            case.start()
        elif fault.startswith("buyer-"):
            flag = "--crash-after-intent" if fault == "buyer-after-intent" else "--crash-after-check"
            failed = case.invoke("buyer", "resolve", "/state", case.url, flag)
            assert failed.returncode in (-9, 137), failed.stderr
            before = case.counts()
            assert before["payments"] == {"held" if fault == "buyer-after-intent" else "released": 1}, before
        if fault != "none":
            snapshot = case.snapshot()
            assert (snapshot["available"], snapshot["reserved"], snapshot["spent"]) == (900, 100, 0)
            assert snapshot["mutualReleaseCount"] == 0
        with ThreadPoolExecutor(max_workers=4) as executor:
            outputs = list(executor.map(lambda _: case.call("buyer", "resolve", "/state", case.url), range(4)))
        public = outputs[0]
        assert all(value == public for value in outputs)
        assert public["incident"] == unresolved["incident"]
        assert public["paymentResolution"] == "released_by_agreement" and public["localCreditSettled"]
        assert not public["buyerVerified"] and public["workExecuted"] is None
        assert (public["available"], public["reserved"], public["spent"]) == (1000, 0, 0)
        counts = case.counts()
        assert counts == {"reviews": 0 if before_review else 1, "payments": {"released": 1}, "buyerExpenses": 0}, counts
        with sqlite3.connect(root / "provider/authority.sqlite") as db:
            assert db.execute("SELECT operation_json FROM admission_operations WHERE operation_id=?", (id,)).fetchone()[0] == original
            assert db.execute("SELECT * FROM payment_journal WHERE operation_id=?", (id,)).fetchone() == journal
            assert db.execute("SELECT invocation_count,total_cost_exposed,total_cost_realized_spend FROM capability_grant_budgets WHERE capability_id=?", (cap,)).fetchone() == (1, 0, 0)
            assert db.execute("SELECT COUNT(*) FROM unknown_payment_release_records WHERE operation_id=?", (id,)).fetchone()[0] == 2
        with sqlite3.connect(root / "buyer/buyer.sqlite") as db:
            assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM resolved_reservations").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0] == 0
        (root / "verifier").mkdir(mode=0o700)
        write(root / "verifier/peers.json", case.keys)
        write(root / "verifier/release.json", public["release"])
        python = case.call("verifier", "verify-release", "/state/peers.json", "/state/release.json")
        rust = case.call("rust-verifier", "verify-release", "/state/peers.json", "/state/release.json")
        assert python == rust and python["releaseVerified"]
        write(root / "verification.json", {"python": python, "rust": rust})
        write(root / "public.json", public)
        case.stop()
        case.start()
        assert case.call("buyer", "resolve", "/state", case.url) == public
        case.stop()
        assert case.call("buyer", "resolve", "/state", case.url) == public
        assert case.call("buyer", "work", "/state", case.url) == public
        return {"scenario": root.name, "fault": fault, "beforeRecovery": before, "afterRecovery": counts,
                "buyerAccount": {k: public[k] for k in ("available", "reserved", "spent")},
                "originalIncidentUnchanged": True, "originalInvocationCount": 1, "releaseVerified": True}
    finally:
        case.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--python-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--normal-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    HttpsScenario.python_env = args.python_env.resolve()
    args.output.mkdir(mode=0o700, exist_ok=True)
    cases = [("after-review", "none", False)]
    if not args.normal_only:
        cases += [("before-review", "none", True)]
        cases += [(fault, fault, False) for fault in ("release-before-rail", "release-after-rail", "release-after-receipt", "buyer-after-intent", "buyer-after-check")]
    results = []
    for name, fault, before in cases:
        result = run_case(args.binary.resolve(), args.output.resolve() / name, fault, before)
        results.append(result)
        print(json.dumps(result), flush=True)
    write(args.output / "summary.json", {"passed": len(results), "scenarios": results,
        "independentOperators": False, "externalFundsTransferred": False, "transport": "TLS 1.3"})


if __name__ == "__main__":
    main()
