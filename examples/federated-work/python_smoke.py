#!/usr/bin/env python3
"""Run the Python buyer and verifier against the Rust provider in separate mounts.

The launcher reuses the existing provider fault suite, but the Python participant
mounts contain no Chio binary, Rust library, provider state, or workspace checkout.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
import tempfile

import paid_smoke
from smoke import write


class PythonScenario(paid_smoke.PaidScenario):
    python_env = None

    def __init__(self, binary, root):
        super().__init__(binary, root)
        isolation = {}
        for role, other in (("buyer", "provider"), ("provider", "buyer")):
            assert self.call(role, "probe", "/state/key.seed")["readable"]
            isolation[role] = self.call(role, "probe", str(root / other / "key.seed"))
            assert not isolation[role]["readable"]
        assert not self.call("buyer", "probe", "/app")["readable"]
        assert not self.call("buyer", "probe", str(binary))["readable"]
        write(root / "isolation.json", {"crossRoleKeyReadable": isolation,
                                       "pythonParticipantHasChioBinary": False})

    def command(self, role, *args):
        if role == "provider":
            return super().command(role, *args)
        if role == "rust-verifier":
            return super().command("verifier", *args)
        return self.python_command(role, *args)

    def python_command(self, role, *args):
        state = self.root / role
        code = Path(__file__).with_name("python_buyer").resolve()
        cmd = ["/usr/bin/bwrap", "--die-with-parent", "--unshare-all", "--share-net",
               "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin",
               "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
               "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib"]
        if Path("/lib64").exists():
            cmd += ["--ro-bind", "/lib64", "/lib64"]
        cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--ro-bind", str(code), "/client", "--ro-bind", str(self.python_env), "/venv",
                "--bind", str(state), "/state", "--chdir", "/state"]
        for name in ("key.seed", "peers.json", "agreement.json", "session.json", "input.json"):
            if (state / name).exists():
                cmd += ["--ro-bind", str(state / name), "/state/" + name]
        if (state / "connection.json").exists() and args[0] != "enroll":
            cmd += ["--ro-bind", str(state / "connection.json"), "/state/connection.json"]
        return cmd + ["/venv/bin/python", "-B", "/client/client.py", *args]

    def call(self, role, *args):
        result = super().call(role, *args)
        if role == "verifier" and args[0] in ("verify-work", "verify-incident"):
            # The separate Rust verifier must also accept Python-created bids,
            # reservations, acceptances, and the resulting native evidence.
            native = super().call("rust-verifier", *args)
            assert native == result
            write(self.root / "cross-verification.json", {"python": result, "rust": native})
        return result


def recorded_unknown(binary, root, buyer_crash=False, before_review=False):
    case = PythonScenario(binary, root)
    try:
        case.start("before-review" if before_review else "after-review")
        failed = case.invoke("buyer", "work", "/state", case.url)
        assert failed.returncode != 0
        assert case.process.wait(timeout=10) in (-9, 137)
        case.start()

        # Startup reconciliation runs before the first kernel evaluation.
        write(root / "buyer/acceptance.json", case.snapshot()["jobs"][0]["acceptance"])
        case.call("buyer", "request", "/state", case.url, "status", "/state/acceptance.json")

        def retained_authority():
            with sqlite3.connect(root / "provider/authority.sqlite") as db:
                rows = db.execute("SELECT operation_id,operation_json FROM admission_operations WHERE state='outcome_unknown_after_dispatch'").fetchall()
                assert len(rows) == 1
                operation_id, raw = rows[0]
                cap = json.loads(raw)["binding"]["capability_id"]
                journal = db.execute("SELECT * FROM payment_journal WHERE operation_id=?", (operation_id,)).fetchone()
                budget = db.execute("SELECT invocation_count,total_cost_exposed,total_cost_realized_spend FROM capability_grant_budgets WHERE capability_id=?", (cap,)).fetchone()
                assert budget == (1, 100, 0)
                return raw, journal, budget

        original = retained_authority()
        if buyer_crash:
            failed = case.invoke("buyer", "work", "/state", case.url, "--crash-after-check")
            assert failed.returncode in (-9, 137), failed.stderr
        with ThreadPoolExecutor(max_workers=4) as executor:
            recovered = list(executor.map(lambda _: case.call("buyer", "work", "/state", case.url), range(4)))
        public = recovered[0]
        assert all(value == public for value in recovered)
        assert public["incidentVerified"] and not public["buyerVerified"] and public["workExecuted"] is None
        assert not public["localCreditSettled"] and public["paymentResolution"] == "required"
        assert (public["available"], public["reserved"], public["spent"]) == (900, 100, 0)
        assert case.counts() == {"reviews": 0 if before_review else 1, "payments": {"held": 1}, "buyerExpenses": 0}
        assert retained_authority() == original
        with sqlite3.connect(root / "buyer/buyer.sqlite") as db:
            assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0] == 0
        (root / "verifier").mkdir(mode=0o700)
        write(root / "verifier/peers.json", case.keys)
        write(root / "verifier/work.json", public)
        verified = case.call("verifier", "verify-incident", "/state/peers.json", "/state/work.json")
        write(root / "public.json", public)
        write(root / "verification.json", verified)
        write(root / "provider/public-incident.json", public)
        command = case.python_command("provider", "init", "/state")
        command[command.index("/client/client.py"):] = ["/client/incident_fixture.py", "/state", "/state/public-incident.json"]
        generated = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert generated.returncode == 0, generated.stderr
        vectors = json.loads(generated.stdout)
        denials = []
        for vector in vectors["cases"]:
            write(root / "verifier/malformed.json", vector["public"])
            errors = {}
            for role in ("verifier", "rust-verifier"):
                denied = case.invoke(role, "verify-incident", "/state/peers.json", "/state/malformed.json")
                assert denied.returncode != 0, (role, vector["case"])
                errors[role] = denied.stderr.strip()
            denials.append({"case": vector["case"], "rejectedByBoth": True, "errors": errors})
        write(root / "incident-vectors.json", vectors)
        write(root / "incident-denials.json", denials)
        # A second provider restart must reproduce the historical signed export.
        case.stop()
        case.start()
        acceptance = public["request"]["acceptance"]
        write(root / "buyer/acceptance.json", acceptance)
        fetched = case.call("buyer", "request", "/state", case.url, "delivery", "/state/acceptance.json")
        assert fetched["task"]["artifacts"][0]["parts"][0]["data"] == public["incident"]
        assert retained_authority() == original
        case.stop()
        assert case.call("buyer", "work", "/state", case.url) == public
        result = {"scenario": root.name, **case.counts(), "reserved": 100, "incidentVerified": True,
                  "immutableOperationJournalAndBudget": True, "concurrentBuyers": 4, "offlineReplay": True,
                  "buyerCrashBeforeRetention": buyer_crash, "paymentResolved": False, "automaticReplay": False}
        result["signedIncidentDenials"] = len(denials)
        write(root / "invariants.json", result)
        return result
    finally:
        case.stop()


def acceptance_recovery(binary, root):
    case = PythonScenario(binary, root)
    try:
        case.start("after-accept")
        failed = case.invoke("buyer", "work", "/state", case.url)
        assert failed.returncode != 0
        assert case.process.wait(timeout=10) in (-9, 137)
        before = case.snapshot()
        assert before["reserved"] == 100 and before["jobs"][0]["state"] == "attempted"
        assert case.provider_snapshot()["acceptanceEvents"] == 1
        case.start()
        public = case.call("buyer", "work", "/state", case.url)
        assert public["spent"] == 100 and public["reserved"] == 0
        assert case.provider_snapshot()["acceptanceEvents"] == 1
        assert case.counts() == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 1}
        write(root / "public.json", public)
        return {"scenario": root.name, "acceptanceEvents": 1, **case.counts()}
    finally:
        case.stop()


def uncertain_send(binary, root, before_work):
    case = PythonScenario(binary, root)
    try:
        case.start()
        args = ("work", "/state", case.url, "--crash-before-work") if before_work else (
            "buyer", "/state", case.url, "--crash-before-send")
        failed = case.invoke("buyer", *args)
        assert failed.returncode in (-9, 137), failed.stderr
        before = case.counts()
        for _ in range(2):
            assert case.invoke("buyer", "work", "/state", case.url).returncode != 0
        assert case.counts() == before == {"reviews": 0, "payments": {}, "buyerExpenses": 0}
        snapshot = case.snapshot()
        assert snapshot["available"] == 900 and snapshot["reserved"] == 100 and snapshot["spent"] == 0
        result = {"scenario": root.name, **before, "reserved": 100, "automaticReplay": False,
                  "buyerState": snapshot["jobs"][0]["state"]}
        write(root / "public.json", result)
        return result
    finally:
        case.stop()


def unicode_exchange(binary, root):
    case = PythonScenario(binary, root)
    try:
        source = json.dumps({"openapi": "3.1.0", "paths": {"/😀": {"get": {}}, "/\ue000": {"post": {"security": []}}}},
                            ensure_ascii=False).encode("utf-8")
        (root / "buyer/input.json").write_bytes(source)
        case.agreement["inputSha256"] = hashlib.sha256(source).hexdigest()
        write(root / "buyer/agreement.json", case.agreement)
        case.start()
        # A rejected request still signs these parameter keys. Their UTF-16
        # canonical order differs from UTF-8 order and crosses both implementations.
        write(root / "buyer/request.json", {"\ue000": 1, "😀": 2})
        denied = case.call("buyer", "request", "/state", case.url, "quote", "/state/request.json")
        assert denied["task"]["status"]["state"] == "TASK_STATE_FAILED"
        public = case.call("buyer", "work", "/state", case.url)
        assert public["delivery"]["report"]["body"]["operations"] == [
            {"path": "/\ue000", "method": "post", "authenticationRequired": False},
            {"path": "/😀", "method": "get", "authenticationRequired": False}]
        (root / "verifier").mkdir(mode=0o700)
        write(root / "verifier/peers.json", case.keys)
        write(root / "verifier/work.json", public)
        verified = case.call("verifier", "verify-work", "/state/peers.json", "/state/work.json")
        write(root / "public.json", {"work": public, "unicodeKeyDenial": denied})
        write(root / "verification.json", verified)
        return {"scenario": root.name, **case.counts(), "unicodeCanonicalization": True}
    finally:
        case.stop()


def concurrent_expense_recovery(binary, root):
    case = PythonScenario(binary, root)
    try:
        case.start()
        failed = case.invoke("buyer", "work", "/state", case.url, "--crash-after-check")
        assert failed.returncode in (-9, 137)
        assert case.counts() == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 0}
        with ThreadPoolExecutor(max_workers=4) as executor:
            recovered = list(executor.map(lambda _: case.call("buyer", "work", "/state", case.url), range(4)))
        assert all(value == recovered[0] for value in recovered)
        assert recovered[0]["spent"] == 100 and recovered[0]["reserved"] == 0
        assert case.counts() == {"reviews": 1, "payments": {"captured": 1}, "buyerExpenses": 1}
        write(root / "public.json", recovered[0])
        return {"scenario": root.name, **case.counts(), "concurrentBuyers": 4}
    finally:
        case.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/chio-federated-work"))
    parser.add_argument("--python-env", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--normal-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    PythonScenario.python_env = args.python_env.resolve()
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="chio-python-review-"))
    root.mkdir(mode=0o700, exist_ok=True)
    binary = args.binary.resolve()
    paid_smoke.PaidScenario = PythonScenario
    results = [paid_smoke.complete(binary, root / "normal", "none")]
    if not args.normal_only:
        results += [paid_smoke.complete(binary, root / name, fault) for name, fault in (
            ("after-settlement-sigkill", "after-settlement"), ("after-capture-sigkill", "after-capture"),
            ("buyer-after-check-sigkill", "buyer-after-check"))]
        results.append(recorded_unknown(binary, root / "after-review-sigkill"))
        results.append(recorded_unknown(binary, root / "before-review-sigkill", before_review=True))
        results.append(recorded_unknown(binary, root / "buyer-after-incident-check-sigkill", True))
        results += [paid_smoke.rejected(binary, root / name, fault) for name, fault in (
            ("corrupt-report", "corrupt-report"), ("corrupt-after-release-sigkill", "corrupt-after-release"),
            ("corrupt-after-denial-sigkill", "corrupt-after-denial"),
            ("buyer-after-rejection-check-sigkill", "buyer-after-rejection-check"))]
        results.append(paid_smoke.ingress_denials(binary, root / "ingress-denials"))
        results.append(paid_smoke.two_jobs(binary, root / "two-jobs"))
        results.append(acceptance_recovery(binary, root / "after-accept-sigkill"))
        results.append(uncertain_send(binary, root / "before-accept-send-sigkill", False))
        results.append(uncertain_send(binary, root / "before-work-send-sigkill", True))
        results.append(unicode_exchange(binary, root / "unicode-wire"))
        results.append(concurrent_expense_recovery(binary, root / "concurrent-expense-recovery"))
    summary = {"scenarios": results, "passed": len(results), "buyerImplementation": "Python",
               "providerImplementation": "Rust", "separateImplementations": True,
               "independentAuthors": False, "independentOperators": False, "externalFundsTransferred": False}
    write(root / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
