#!/usr/bin/env python3
"""Exercise real A2A/market/kernel paths in separate local mount namespaces.

Generated states contain private keys and bearer credentials. Only public.json
and summary.json are suitable for retained review evidence.
"""
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


class Scenario:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.process = None
        root.mkdir(mode=0o700)
        for role in ("buyer", "provider"):
            (root / role).mkdir(mode=0o700)
        self.keys = {role: self.call(role, "init", "/state")["publicKey"]
                     for role in ("buyer", "provider")}
        for role in self.keys:
            write(root / role / "peers.json", self.keys)
        write(root / "buyer" / "session.json",
              self.call("provider", "grant", "/state", self.keys["buyer"]))
        # The review input is named by digest only; this slice does not send it.
        source = b'{"openapi":"3.1.0","paths":{"/health":{"get":{}}}}'
        self.agreement = {
            "profile": "chio.example.security-review-agreement.v1",
            "jobId": "security-review-001", "inputSha256": hashlib.sha256(source).hexdigest(),
            "buyer": self.keys["buyer"], "provider": self.keys["provider"],
            "priceCeiling": 200, "deadline": int(time.time()) + 600,
            "checker": "openapi-explicit-auth-v1", "subcontracting": False,
            "creditProfile": "buyer-local-credit-promise-v1",
        }
        write(root / "buyer" / "agreement.json", self.agreement)

    def command(self, role, *args):
        state = self.root / role
        cmd = ["/usr/bin/bwrap", "--die-with-parent", "--unshare-all", "--share-net",
               "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin",
               "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib"]
        if Path("/lib64").exists():
            cmd += ["--ro-bind", "/lib64", "/lib64"]
        cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--ro-bind", str(self.binary), "/app",
                "--bind", str(state), "/state", "--chdir", "/state"]
        for name in ("key.seed", "peers.json", "agreement.json", "session.json"):
            if (state / name).exists():
                cmd += ["--ro-bind", str(state / name), "/state/" + name]
        return cmd + ["/app", *args]

    def invoke(self, role, *args):
        return subprocess.run(self.command(role, *args), text=True, capture_output=True, timeout=30)

    def call(self, role, *args):
        result = self.invoke(role, *args)
        if result.returncode:
            raise AssertionError(f"{role} {args[0]} failed: {result.stderr}")
        return json.loads(result.stdout)

    def start(self, crash=False):
        ready = self.root / "provider" / "endpoint.json"
        ready.unlink(missing_ok=True)
        log = open(self.root / "provider.log", "a")
        args = ["serve", "/state", "0"] + (["--crash-after-accept"] if crash else [])
        self.process = subprocess.Popen(self.command("provider", *args), stdout=log, stderr=log)
        log.close()
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

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def snapshot(self):
        return self.call("buyer", "snapshot", "/state")

    def provider_snapshot(self):
        with sqlite3.connect(self.root / "provider" / "work.sqlite") as db:
            events = db.execute("SELECT COUNT(*) FROM acceptance_events").fetchone()[0]
            jobs = db.execute("SELECT job,state FROM jobs ORDER BY job").fetchall()
        with sqlite3.connect(self.root / "provider" / "authority.sqlite") as db:
            states = dict(db.execute("SELECT state,COUNT(*) FROM admission_operations GROUP BY state"))
        return {"acceptanceEvents": events, "jobs": jobs, "admissionStates": states}

    def reject(self, label, tool, body):
        write(self.root / "buyer" / "request.json", body)
        output = self.call("buyer", "request", "/state", self.url, tool, "/state/request.json")
        assert output["task"]["status"]["state"] == "TASK_STATE_FAILED", label
        return {"case": label, "response": output}


def run(binary, root, crash):
    scenario = Scenario(binary, root)
    try:
        isolation = {}
        for role, other in (("buyer", "provider"), ("provider", "buyer")):
            assert (root / other / "key.seed").is_file()
            assert scenario.call(role, "probe", "/state/key.seed")["readable"]
            isolation[role] = scenario.call(role, "probe", str(root / other / "key.seed"))
            assert not isolation[role]["readable"]
        scenario.start(crash)
        before_recovery = None
        crash_exit = None
        if crash:
            failed = scenario.invoke("buyer", "buyer", "/state", scenario.url)
            assert failed.returncode != 0, "buyer unexpectedly observed acceptance"
            crash_exit = scenario.process.wait(timeout=10)
            assert crash_exit in (-9, 137), crash_exit
            before_recovery = {"buyer": scenario.snapshot(), "provider": scenario.provider_snapshot(),
                               "buyerError": failed.stderr.strip()}
            assert before_recovery["buyer"]["jobs"][0]["state"] == "attempted"
            assert before_recovery["provider"]["acceptanceEvents"] == 1
            scenario.start()
        accepted = scenario.call("buyer", "buyer", "/state", scenario.url)
        replay = scenario.call("buyer", "buyer", "/state", scenario.url)
        assert accepted == replay
        assert accepted["available"] == 900 and accepted["reserved"] == 100
        assert accepted["reservationCount"] == 1 and accepted["spent"] == 0
        assert accepted["jobs"][0]["state"] == "accepted"
        assert not accepted["workExecuted"] and not accepted["settled"]
        negatives = []
        acceptance = accepted["jobs"][0]["acceptance"]
        write(root / "buyer" / "duplicate.json", acceptance)
        with ThreadPoolExecutor(max_workers=4) as pool:
            duplicates = list(pool.map(lambda _: scenario.call("buyer", "request", "/state", scenario.url,
                                                               "accept", "/state/duplicate.json"), range(4)))
        assert all(item["task"]["status"]["state"] == "TASK_STATE_COMPLETED" for item in duplicates)
        for label, path in (("changed-accepted-price", ("accepted", "body", "quotedPrice", "units")),
                            ("changed-reservation", ("reservation", "body", "receiptId"))):
            changed = copy.deepcopy(acceptance)
            target = changed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = 101 if path[-1] == "units" else "different-reservation"
            negatives.append(scenario.reject(label, "accept", changed))
        for label, field, value in (("changed-job-input", "inputSha256", "a" * 64),
                                     ("subcontract-not-permitted", "subcontracting", True)):
            changed = dict(scenario.agreement, **{field: value})
            write(root / "buyer" / "changed-agreement.json", changed)
            quote = scenario.call("buyer", "sign-quote", "/state", "/state/changed-agreement.json")
            negatives.append(scenario.reject(label, "quote", quote))
        provider = scenario.provider_snapshot()
        assert provider["acceptanceEvents"] == 1 and len(provider["jobs"]) == 1
        with sqlite3.connect(root / "buyer" / "buyer.sqlite") as db:
            observations = [{"tool": tool, "args": json.loads(args), "response": json.loads(response)}
                            for tool, args, response in db.execute("SELECT tool,args,response FROM observations ORDER BY id")]
        public = {"peers": scenario.keys, "isolation": isolation, "crashExit": crash_exit,
                  "beforeRecovery": before_recovery, "buyer": accepted, "provider": provider,
                  "observations": observations, "negatives": negatives}
        write(root / "public.json", public)
        # A verifier gets only public artifacts and separately selected peer pins.
        verifier = root / "verifier"
        verifier.mkdir(mode=0o700)
        write(verifier / "peers.json", scenario.keys)
        write(verifier / "public.json", public)
        verified = scenario.call("verifier", "verify-agreement", "/state/peers.json", "/state/public.json")
        for other in ("buyer", "provider"):
            assert not scenario.call("verifier", "probe", str(root / other / "key.seed"))["readable"]
        changed = copy.deepcopy(public)
        changed["buyer"]["jobs"][0]["acknowledgement"]["body"]["settled"] = True
        write(verifier / "changed.json", changed)
        assert scenario.invoke("verifier", "verify-agreement", "/state/peers.json", "/state/changed.json").returncode != 0
        changed = copy.deepcopy(public)
        changed["observations"][0]["response"]["task"]["status"]["state"] = "TASK_STATE_FAILED"
        write(verifier / "changed.json", changed)
        assert scenario.invoke("verifier", "verify-agreement", "/state/peers.json", "/state/changed.json").returncode != 0
        write(verifier / "wrong-peers.json", dict(scenario.keys, provider=scenario.keys["buyer"]))
        assert scenario.invoke("verifier", "verify-agreement", "/state/wrong-peers.json", "/state/public.json").returncode != 0
        write(root / "verification.json", verified)
        return {"scenario": root.name, "crashExit": crash_exit, "available": 900, "reserved": 100,
                "acceptanceEvents": provider["acceptanceEvents"], "negativeCases": len(negatives),
                "concurrentDuplicateAcceptances": len(duplicates), "verifiedReceipts": verified["verifiedReceipts"],
                "verifierNegativeCases": 3,
                "admissionStates": provider["admissionStates"], "workExecuted": False, "settled": False}
    finally:
        scenario.stop()


def before_send(binary, root):
    scenario = Scenario(binary, root)
    try:
        scenario.start()
        killed = scenario.invoke("buyer", "buyer", "/state", scenario.url, "--crash-before-send")
        assert killed.returncode in (-9, 137), killed.stderr
        first = scenario.snapshot()
        assert first["jobs"][0]["state"] == "attempted"
        retry = scenario.invoke("buyer", "buyer", "/state", scenario.url)
        assert retry.returncode != 0 and "remains uncertain" in retry.stderr, retry.stderr
        second = scenario.snapshot()
        assert first == second and second["available"] == 900 and second["reserved"] == 100
        provider = scenario.provider_snapshot()
        assert provider["acceptanceEvents"] == 0 and provider["jobs"][0][1] == "quoted"
        public = {"buyer": second, "provider": provider, "buyerCrashExit": killed.returncode,
                  "retryError": retry.stderr.strip(), "workExecuted": False, "settled": False}
        write(root / "public.json", public)
        return {"scenario": root.name, "buyerCrashExit": killed.returncode, "acceptanceEvents": 0,
                "available": 900, "reserved": 100, "state": "attempted", "workExecuted": False, "settled": False}
    finally:
        scenario.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/chio-federated-work"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="chio-federated-work-"))
    root.mkdir(mode=0o700, exist_ok=True)
    results = [run(args.binary.resolve(), root / name, crash)
               for name, crash in (("normal", False), ("acceptance-sigkill", True))]
    results.append(before_send(args.binary.resolve(), root / "buyer-before-send-sigkill"))
    write(root / "summary.json", results)
    print(json.dumps({"output": str(root), "results": results}, indent=2))


if __name__ == "__main__":
    main()
