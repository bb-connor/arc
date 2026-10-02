#!/usr/bin/env python3
"""Execute and verify paid local-credit reviews in separate process namespaces."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
from smoke import Scenario, write


class PaidScenario(Scenario):
    def __init__(self, binary, root):
        super().__init__(binary, root)
        data = Path(__file__).with_name("fixtures").joinpath("openapi.json").read_bytes()
        (root / "buyer/input.json").write_bytes(data)
        self.agreement.update(profile="chio.example.security-review-agreement.v3",
                              creditProfile="provider-local-credit-checked-or-zero-v1",
                              inputSha256=hashlib.sha256(data).hexdigest())
        write(root / "buyer/agreement.json", self.agreement)

    def start(self, fault="none"):
        ready = self.root / "provider/endpoint.json"
        ready.unlink(missing_ok=True)
        with open(self.root / "provider.log", "a") as log:
            self.process = subprocess.Popen(self.command("provider", "serve-work", "/state", "0", fault), stdout=log, stderr=log)
        for _ in range(200):
            if self.process.poll() is not None:
                raise AssertionError((self.root / "provider.log").read_text())
            if ready.exists():
                try:
                    self.url = json.loads(ready.read_text())["url"]
                    return
                except json.JSONDecodeError:
                    pass
            time.sleep(0.025)
        raise AssertionError("provider did not start")

    def counts(self):
        with sqlite3.connect(self.root / "provider/work.sqlite") as db:
            reviews = db.execute("SELECT COUNT(*) FROM review_runs").fetchone()[0]
        with sqlite3.connect(self.root / "provider/payments.sqlite") as db:
            payments = dict(db.execute("SELECT state,COUNT(*) FROM chio_finding_operator_payments GROUP BY state"))
        with sqlite3.connect(self.root / "buyer/buyer.sqlite") as db:
            expenses = db.execute("SELECT COUNT(*) FROM expenses").fetchone()[0]
        return {"reviews": reviews, "payments": payments, "buyerExpenses": expenses}


def complete(binary, root, fault):
    case = PaidScenario(binary, root)
    try:
        case.start("none" if fault == "buyer-after-check" else fault)
        before = None
        if fault == "buyer-after-check":
            failed = case.invoke("buyer", "work", "/state", case.url, "--crash-after-check")
            assert failed.returncode in (-9, 137), failed.stderr
            before = case.counts()
            assert before == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 0}, before
        if fault in ("after-settlement", "after-capture"):
            failed = case.invoke("buyer", "work", "/state", case.url)
            assert failed.returncode != 0
            assert case.process.wait(timeout=10) in (-9, 137)
            before = case.counts()
            assert before == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 0}, before
            case.start()
        public = case.call("buyer", "work", "/state", case.url)
        repeated = case.call("buyer", "work", "/state", case.url)
        assert public == repeated
        assert public["spent"] == 100 and public["reserved"] == 0 and public["available"] == 900
        assert public["buyerVerified"] and public["localCreditSettled"] and not public["externalFundsTransferred"]
        observations = public["delivery"]["report"]["body"]["operations"]
        assert {(v["path"], v["authenticationRequired"]) for v in observations} == {
            ("/accounts", True), ("/refunds", False), ("/health", False), ("/sessions", True)}
        counts = case.counts()
        assert counts == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 1}, counts
        verifier = root / "verifier"
        verifier.mkdir(mode=0o700)
        write(verifier / "peers.json", case.keys)
        write(verifier / "work.json", public)
        verified = case.call("verifier", "verify-work", "/state/peers.json", "/state/work.json")
        assert verified["buyerVerified"]
        for other in ("buyer", "provider"):
            assert not case.call("verifier", "probe", str(root / other / "key.seed"))["readable"]
        # Mutate different trust bindings while keeping the rest of the public package.
        mutations = [
            ("report", lambda v: v["delivery"]["report"]["body"]["operations"][0].update(authenticationRequired=False)),
            ("input", lambda v: v["request"].update(input=v["request"]["input"] + " ")),
            ("finding", lambda v: v["delivery"]["finding"].update(payload_sha256="a" * 64)),
            ("receipt", lambda v: v["delivery"]["receipt"].update(content_hash="a" * 64)),
            ("proof", lambda v: v["delivery"]["inclusion"].update(receipt_seq=999)),
        ]
        for label, mutate in mutations:
            changed = copy.deepcopy(public)
            mutate(changed)
            write(verifier / "changed.json", changed)
            assert case.invoke("verifier", "verify-work", "/state/peers.json", "/state/changed.json").returncode != 0, label
        # A second paid invocation with the same token cannot repeat the review or charge.
        write(root / "buyer/request.json", public["request"])
        duplicate = case.call("buyer", "review-request", "/state", case.url, "/state/request.json", "signed")
        assert duplicate["task"]["status"]["state"] == "TASK_STATE_FAILED"
        assert case.counts() == counts
        write(root / "public.json", public)
        write(root / "verification.json", verified)
        return {"scenario": root.name, "beforeRecovery": before, **counts, "workExecuted": True,
                "buyerVerified": True, "localCreditSettled": True, "externalFundsTransferred": False}
    finally:
        case.stop()


def denied_or_unknown(binary, root, fault):
    case = PaidScenario(binary, root)
    try:
        case.start(fault)
        failed = case.invoke("buyer", "work", "/state", case.url)
        assert failed.returncode != 0
        if fault == "after-review":
            assert case.process.wait(timeout=10) in (-9, 137)
            case.start()
        before = case.counts()
        assert before["reviews"] == 1 and before["payments"].get("captured", 0) == 0 and before["buyerExpenses"] == 0, before
        retry = case.invoke("buyer", "work", "/state", case.url)
        assert retry.returncode != 0
        assert case.counts() == before
        result = {"scenario": root.name, **before, "retriedWork": False,
                  "firstError": failed.stderr.strip(), "recoveryError": retry.stderr.strip()}
        write(root / "public.json", result)
        return result
    finally:
        case.stop()


def rejected(binary, root, fault):
    case = PaidScenario(binary, root)
    try:
        case.start("corrupt-report" if fault == "buyer-after-rejection-check" else fault)
        if fault != "corrupt-report":
            extra = ["--crash-after-check"] if fault == "buyer-after-rejection-check" else []
            failed = case.invoke("buyer", "work", "/state", case.url, *extra)
            if extra:
                assert failed.returncode in (-9, 137), failed.stderr
            else:
                assert failed.returncode != 0
                assert case.process.wait(timeout=10) in (-9, 137)
                case.start()
            assert case.counts() == {"reviews": 1, "payments": {"released": 1}, "buyerExpenses": 0}
        if fault == "buyer-after-rejection-check":
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=4) as executor:
                recovered = list(executor.map(lambda _: case.call("buyer", "work", "/state", case.url), range(4)))
            public = recovered[0]
            assert all(value == public for value in recovered)
        else:
            public = case.call("buyer", "work", "/state", case.url)
        assert public["reviewRejected"] and public["buyerVerified"]
        assert public["available"] == 1000 and public["reserved"] == 0 and public["spent"] == 0
        assert "report" not in public["delivery"] and "finding" not in public["delivery"]
        assert case.call("buyer", "work", "/state", case.url) == public
        before = case.counts()
        assert before == {"reviews": 1, "payments": {"released": 1}, "buyerExpenses": 0}
        verifier = root / "verifier"
        verifier.mkdir(mode=0o700)
        write(verifier / "peers.json", case.keys)
        write(verifier / "work.json", public)
        verified = case.call("verifier", "verify-work", "/state/peers.json", "/state/work.json")
        assert verified["reviewRejected"] and verified["buyerVerified"]
        for other in ("buyer", "provider"):
            assert not case.call("verifier", "probe", str(root / other / "key.seed"))["readable"]
        for label, mutate in [
            ("agreement", lambda v: v["delivery"].update(agreementSha256="a" * 64)),
            ("input", lambda v: v["request"].update(input=v["request"]["input"] + " ")),
            ("charge", lambda v: v["delivery"]["receipt"]["metadata"]["financial"].update(cost_charged=100)),
            ("proof", lambda v: v["delivery"]["inclusion"].update(receipt_seq=999)),
        ]:
            changed = copy.deepcopy(public)
            mutate(changed)
            write(verifier / "changed.json", changed)
            assert case.invoke("verifier", "verify-work", "/state/peers.json", "/state/changed.json").returncode != 0, label
        write(root / "buyer/request.json", public["request"])
        duplicate = case.call("buyer", "review-request", "/state", case.url, "/state/request.json", "signed")
        assert duplicate["task"]["status"]["state"] == "TASK_STATE_FAILED"
        assert case.counts() == before
        with sqlite3.connect(root / "buyer/buyer.sqlite") as db:
            assert db.execute("SELECT COUNT(*) FROM released_reservations").fetchone()[0] == 1
        write(root / "public.json", public)
        write(root / "verification.json", verified)
        return {"scenario": root.name, **before, "reviewRejected": True,
                "available": 1000, "reserved": 0, "spent": 0, "releasedReservations": 1,
                "crashExit": None if fault == "corrupt-report" else 137}
    finally:
        case.stop()


def ingress_denials(binary, root):
    case = PaidScenario(binary, root)
    try:
        case.start()
        accepted = case.call("buyer", "buyer", "/state", case.url)
        request = {"acceptance": accepted["jobs"][0]["acceptance"], "input": (root / "buyer/input.json").read_text()}
        cases = []
        for name, signed, changed in (("missing-sender-proof", False, False), ("changed-disclosed-input", True, True)):
            body = copy.deepcopy(request)
            if changed:
                body["input"] += " "
            write(root / "buyer/request.json", body)
            denied = case.call("buyer", "review-request", "/state", case.url, "/state/request.json", "signed" if signed else "missing")
            assert denied["task"]["status"]["state"] == "TASK_STATE_FAILED", name
            cases.append({"case": name, "response": denied})
        counts = case.counts()
        assert counts["reviews"] == 0 and counts["payments"].get("captured", 0) == 0 and counts["buyerExpenses"] == 0, counts
        write(root / "public.json", {"cases": cases, **counts})
        return {"scenario": root.name, "denials": len(cases), **counts}
    finally:
        case.stop()


def two_jobs(binary, root):
    case = PaidScenario(binary, root)
    try:
        case.start()
        first = case.call("buyer", "work", "/state", case.url)
        case.agreement["jobId"] = "security-review-002"
        write(root / "buyer/agreement.json", case.agreement)
        second = case.call("buyer", "work", "/state", case.url)
        assert second["request"]["acceptance"]["quote"]["agreement"]["jobId"] == "security-review-002"
        assert second["delivery"]["finding"]["finding_id"] != first["delivery"]["finding"]["finding_id"]
        assert second["available"] == 800 and second["spent"] == 200 and second["reserved"] == 0
        counts = case.counts()
        assert counts == {"reviews": 2, "payments": {"captured": 2}, "buyerExpenses": 2}, counts
        write(root / "public.json", {"first": first, "second": second, **counts})
        return {"scenario": root.name, **counts, "available": 800, "spent": 200, "reserved": 0}
    finally:
        case.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/chio-federated-work"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--normal-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="chio-paid-review-"))
    root.mkdir(mode=0o700, exist_ok=True)
    cases = [("normal", "none")] + ([] if args.normal_only else [
        ("after-settlement-sigkill", "after-settlement"), ("after-capture-sigkill", "after-capture"),
        ("buyer-after-check-sigkill", "buyer-after-check")])
    results = [complete(args.binary.resolve(), root / name, fault) for name, fault in cases]
    if not args.normal_only:
        results.append(denied_or_unknown(args.binary.resolve(), root / "after-review-sigkill", "after-review"))
        results += [rejected(args.binary.resolve(), root / name, fault) for name, fault in (
            ("corrupt-report", "corrupt-report"),
            ("corrupt-after-release-sigkill", "corrupt-after-release"),
            ("corrupt-after-denial-sigkill", "corrupt-after-denial"),
            ("buyer-after-rejection-check-sigkill", "buyer-after-rejection-check"))]
        results.append(ingress_denials(args.binary.resolve(), root / "ingress-denials"))
        results.append(two_jobs(args.binary.resolve(), root / "two-jobs"))
    write(root / "summary.json", results)
    print(json.dumps({"output": str(root), "results": results}, indent=2))


if __name__ == "__main__":
    main()
