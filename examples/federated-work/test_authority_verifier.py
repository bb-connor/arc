"""Role-origin keys, independent claim observation and original settlement."""
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("CHIO_FUNDED_BINARY", ROOT / "target/debug/chio-federated-work"))


class AuthorityVerifier(unittest.TestCase):
    def assert_custody_and_ingress(self, root):
        request = (root / "verifier-request.json").read_bytes()
        value = json.loads(request)
        canonical = lambda obj: json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        changed = dict(value, observation={"authorityVerified": True})
        mutations = [
            request + b"\n", b'{"schema":"duplicate",' + request[1:],
            canonical(changed), b" " * (256 * 1024 + 1),
            canonical(dict(value, input=value["input"] + " ")),
            canonical(dict(value, output=[] if value["output"] != [] else {})),
        ]
        def decide(state, artifact, output):
            return subprocess.run([str(BINARY), "experimental-verifier-decide", str(state),
                str(artifact), str(root / "missing-observer"), str(output)], cwd=ROOT,
                env=dict(os.environ, CHIO_FUNDED_PYTHON=str(root / "missing-checker")),
                capture_output=True, timeout=30)
        for index, raw in enumerate(mutations):
            path = root / f"mutated-{index}.json"
            output = root / f"denied-{index}.json"
            path.write_bytes(raw)
            result = decide(root / "verifier", path, output)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(output.exists())
        # Deliberately corrupt isolated copies, never the original journal.
        for mutation in ("signature", "observation", "partial", "version", "missing", "truncated"):
            state = root / f"custody-{mutation}"
            state.mkdir()
            database = state / "verifier-custody.sqlite3"
            if mutation not in ("missing", "truncated"):
                with sqlite3.connect(root / "verifier/verifier-custody.sqlite3") as source:
                    with sqlite3.connect(database) as db:
                        source.backup(db)
                        db.execute("DROP TRIGGER custody_no_replace")
                        if mutation == "version":
                            db.execute("PRAGMA user_version=99")
                        elif mutation == "partial":
                            db.execute("PRAGMA ignore_check_constraints=ON")
                            db.execute("UPDATE custody SET decision=NULL")
                        else:
                            body = json.loads(db.execute(f"SELECT { 'decision' if mutation == 'signature' else 'observation'} FROM custody").fetchone()[0])
                            if mutation == "signature":
                                body["body"]["accepted"] = not body["body"]["accepted"]
                                column = "decision"
                            else:
                                body["receipt"]["blockHash"] = "0x" + "ab" * 32
                                column = "observation"
                            db.execute(f"UPDATE custody SET {column}=?", [canonical(body)])
            elif mutation == "truncated":
                database.write_bytes(b"truncated database")
            output = root / f"denied-custody-{mutation}.json"
            result = decide(state, root / "verifier-request.json", output)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertFalse(output.exists())
            if mutation == "missing":
                self.assertFalse(database.exists())
        # All failed attempts leave the actual first response recoverable.
        output = root / "decision-after-adversaries.json"
        result = decide(root / "verifier", root / "verifier-request.json", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), (root / "decision.json").read_bytes())

    def test_separate_verifier_payout_and_refund(self):
        for mode in ("pay", "reject"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="chio-authorities-") as tmp:
                result = subprocess.run([str(BINARY), "experimental-authority-lifecycle", tmp, mode],
                                        cwd=ROOT, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                first, replay, chain = report["first"], report["replay"], report["chain"]
                for field in ("allocationId", "operationId", "holdId", "authorizationId", "authorityUuid"):
                    self.assertEqual(first[field], replay[field], field)
                self.assertEqual(replay["executions"], 1)
                self.assertEqual(chain["state"], "Paid" if mode == "pay" else "Refunded")
                self.assertEqual(chain["payerBalance"], "900" if mode == "pay" else "1000")
                self.assertEqual(chain["beneficiaryBalance"], "100" if mode == "pay" else "0")
                self.assertEqual(chain["escrowBalance"], "0")
                for event in ("Funded", "ClaimSubmitted", "DecisionRecorded"):
                    self.assertEqual(chain["events"][event], 1)
                self.assertEqual(chain["events"]["Paid"] + chain["events"]["Refunded"], 1)
                self.assertTrue(report["keysGeneratedInRoleDirectories"])
                self.assertTrue(report["decisionReplayWithoutSignerObserverOrChecker"])
                self.assertTrue(report["providerHasOnlyProviderSeed"])
                self.assertFalse(report["independentAdministration"])
                self.assertTrue(report["observerAndCheckerOutagesDenied"])
                self.assertTrue(report["observerIsReadOnly"])
                self.assertTrue(report["publicationFailureRecoveredWithoutDependencies"])
                self.assert_custody_and_ingress(Path(tmp))
                self.assertFalse((Path(tmp) / "unavailable.json").exists())
                self.assertFalse((Path(tmp) / "unavailable-checker.json").exists())
                verified = subprocess.run([os.environ["CHIO_FUNDED_PYTHON"], "-B", str(ROOT / "examples/federated-work/execution_evidence.py"),
                    str(Path(tmp) / "witness.json"), "--pins", str(Path(tmp) / "execution-pins.json"), "--evaluated-at", str(report["evaluatedAt"])],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                public = json.loads(verified.stdout)
                self.assertTrue(public["authorityVerified"])
                self.assertEqual(public["executionMatchesSubmission"], mode == "pay")
                self.assertFalse(public["financialBacking"])
                if destination := os.environ.get("CHIO_FUNDED_EVIDENCE_DIR"):
                    out = Path(destination)
                    (out / f"authority-{mode}.json").write_text(json.dumps(report, indent=2) + "\n")
                    (out / f"authority-python-{mode}.json").write_text(verified.stdout)
                    for file in ("witness", "execution-pins", "verifier-request", "verifier-enrollment", "decision", "authority-pins", "context"):
                        (out / f"{'authority-witness' if file == 'witness' else file}-{mode}.json").write_bytes((Path(tmp) / f"{file}.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
