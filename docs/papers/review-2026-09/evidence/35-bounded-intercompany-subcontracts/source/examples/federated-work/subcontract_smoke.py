#!/usr/bin/env python3
"""Three organizations using separately issued work authority over HTTPS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys

import paid_smoke
from https_smoke import HttpsScenario
from smoke import write
sys.path.insert(0, str(Path(__file__).with_name("python_buyer")))
import subcontract as contract


class ParentScenario(HttpsScenario):
    def command(self, role, *args):
        command = super().command(role, *args)
        if role == "provider":
            offset = command.index("/app", command.index("--chdir"))
            command[offset:offset] = ["--ro-bind", str(self.python_env), "/venv", "--ro-bind",
                                     str(getattr(self, "worker_code", Path(__file__).with_name("python_buyer").resolve())), "/client"]
        return command


class SpecialistScenario(HttpsScenario):
    def start(self, fault="none"):
        # This fixture starts only C's receiver. Its configured client is B's
        # separate agent key, supplied locally before serving.
        paid_smoke.PaidScenario.start(self, fault)


def setup(binary, root, specialist_fault="none"):
    root.mkdir(mode=0o700)
    parent = ParentScenario(binary, root / "parent")
    specialist = SpecialistScenario(binary, root / "specialist")
    try:
        delegate = parent.call("provider", "init", "/state/delegate")["publicKey"]
        specialist.keys["buyer"] = delegate
        write(specialist.root / "provider/peers.json", specialist.keys)
        write(specialist.root / "provider/delegation.json", {"promisor": parent.keys["provider"], "delegate": delegate})
        specialist.start(specialist_fault)
        enrollment = specialist.call("provider", "enrollment", "/state", delegate, specialist.url, "/state/tls-cert.pem")
        write(parent.root / "provider/subcontract.json", {
            "specialist": specialist.keys["provider"], "delegateState": "/state/delegate", "origin": specialist.url,
            "enrollment": enrollment, "pythonEnvironment": "/venv", "buyerCode": "/client"})
        document = json.loads((parent.root / "buyer/input.json").read_text())
        canary = "private-" + secrets.token_hex(24)
        document["x-private"] = canary
        document["paths"]["/refunds"]["post"]["description"] = canary
        source = json.dumps(document, ensure_ascii=False)
        (parent.root / "buyer/input.json").write_text(source)
        paths = ["/accounts", "/refunds"]
        child_input = contract.project(source, paths)
        assert canary not in child_input
        parent.agreement.update(profile=contract.PROFILE, inputSha256=hashlib.sha256(source.encode()).hexdigest(), subcontracting=True,
            subcontract={"specialist": specialist.keys["provider"], "delegate": delegate, "paths": paths,
                         "inputSha256": hashlib.sha256(child_input.encode()).hexdigest(), "priceCeiling": 100})
        write(parent.root / "buyer/agreement.json", parent.agreement)
        return parent, specialist, canary, child_input
    except BaseException:
        parent.stop()
        specialist.stop()
        raise


def complete(binary, root):
    parent, specialist, canary, child_input = setup(binary, root)
    delegate = parent.agreement["subcontract"]["delegate"]
    try:
        parent.start()
        public = parent.call("buyer", "work", "/state", parent.url)
        write(root / "public.json", public)
        assert public["buyerVerified"] and not public["reviewRejected"], public
        child = public["delivery"]["report"]["body"]["subcontract"]
        assert child["request"]["input"] == child_input and canary not in json.dumps(child)
        assert child["request"]["acceptance"]["ask"]["body"]["tokenOffer"]["issuer"] == specialist.keys["provider"]
        assert public["request"]["acceptance"]["ask"]["body"]["tokenOffer"]["issuer"] == parent.keys["provider"]
        assert child["request"]["acceptance"]["quote"]["agreement"]["buyer"] == delegate != parent.keys["provider"]
        with sqlite3.connect(specialist.root / "provider/work.sqlite") as db:
            records = db.execute("SELECT request FROM review_runs").fetchall()
            assert len(records) == 1 and canary not in records[0][0]
        states = list((parent.root / "provider/subcontracts").iterdir())
        assert len(states) == 1
        state = states[0]
        probe = json.loads((state / "worker-isolation.json").read_text())
        assert not probe["directTcpConnected"] and not probe["parentFilesystemReadable"]
        assert probe["agentKey"] == delegate
        for name in ("input.json", "agreement.json", "enrollment.json", "connection.json"):
            assert canary not in (state / name).read_text()
        with sqlite3.connect(state / "buyer.sqlite") as db:
            assert db.execute("SELECT SUM(amount) FROM expenses").fetchone()[0] == 100
        # Verifier role is rooted in the parent scenario's own fixture directory.
        (parent.root / "verifier").mkdir(mode=0o700)
        write(parent.root / "verifier/peers.json", parent.keys)
        write(parent.root / "verifier/work.json", public)
        verification = parent.call("verifier", "verify-work", "/state/peers.json", "/state/work.json")
        write(root / "verification.json", verification)
        write(root / "isolation.json", probe)
        from subcontract_cases import spending_denials
        denials = spending_denials(parent, specialist, state, child, root)
        parent.stop()
        specialist.stop()
        assert parent.call("buyer", "work", "/state", parent.url) == public
        return {"passed": True, "organizations": 3, "distinctKeys": 4, "buyerCharged": 100,
                "delegateCharged": 100, "specialistReviews": 1, "privateCanaryDisclosed": False, "spendingDenials": len(denials),
                "independentOperators": False, "externalFundsTransferred": False}
    finally:
        parent.stop()
        specialist.stop()


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
    results = [complete(args.binary.resolve(), args.output.resolve() / "normal")]
    print(json.dumps(results[0]), flush=True)
    if not args.normal_only:
        from subcontract_cases import failure, disclosure_denials, hostile_worker
        for label, parent_fault, child_fault in (("parent-after-child", "after-subcontract", "none"),
                ("invalid-child-proof", "corrupt-subcontract", "none"),
                ("child-after-capture", "none", "after-capture"),
                ("child-after-review", "none", "after-review"),
                ("child-before-review", "none", "before-review"),
                ("both-after-child-write", "after-subcontract", "after-review")):
            result = failure(args.binary.resolve(), args.output.resolve() / label, parent_fault, child_fault)
            results.append(result)
            print(json.dumps(result), flush=True)
        result = hostile_worker(args.binary.resolve(), args.output.resolve() / "hostile-worker")
        results.append(result)
        print(json.dumps(result), flush=True)
        for configured in (True, False):
            result = disclosure_denials(args.binary.resolve(), args.output.resolve() / ("disclosure" if configured else "no-specialist"), configured)
            results.append(result)
            print(json.dumps(result), flush=True)
    write(args.output / "summary.json", {"passed": len(results), "scenarios": results,
        "independentOperators": False, "externalFundsTransferred": False})


if __name__ == "__main__":
    main()
