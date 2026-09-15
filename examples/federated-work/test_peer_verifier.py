"""Real HTTPS verification preserves original admission and terminal money."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("CHIO_FUNDED_BINARY", ROOT / "target/debug/chio-federated-work"))


class PeerVerifier(unittest.TestCase):
    def test_https_verifier_payout_and_refund(self):
        for mode in ("pay", "reject"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="chio-peer-") as tmp:
                result = subprocess.run([str(BINARY), "experimental-peer-lifecycle", tmp, mode],
                                        cwd=ROOT, capture_output=True, text=True, timeout=240)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                for field in ("authorityUuid", "allocationId", "operationId", "holdId", "authorizationId"):
                    self.assertEqual(report["first"][field], report["replay"][field], field)
                self.assertEqual(report["replay"]["executions"], 1)
                chain = report["chain"]
                self.assertEqual(chain["state"], "Paid" if mode == "pay" else "Refunded")
                self.assertEqual(chain["payerBalance"], "900" if mode == "pay" else "1000")
                self.assertEqual(chain["beneficiaryBalance"], "100" if mode == "pay" else "0")
                self.assertEqual(chain["escrowBalance"], "0")
                for event in ("Funded", "ClaimSubmitted", "DecisionRecorded"):
                    self.assertEqual(chain["events"][event], 1)
                self.assertEqual(chain["events"]["Paid"] + chain["events"]["Refunded"], 1)
                peer = report["peerTransport"]
                self.assertGreaterEqual(len(peer["denials"]), 15)
                self.assertTrue(peer["responseLossRecovered"])
                self.assertTrue(peer["replayWithoutSignerObserverChecker"])
                self.assertEqual(peer["killedSignal"], 9)
                self.assertFalse(report["independentAdministration"])
                verified = subprocess.run([os.environ["CHIO_FUNDED_PYTHON"], "-B", str(ROOT / "examples/federated-work/execution_evidence.py"),
                    str(Path(tmp) / "witness.json"), "--pins", str(Path(tmp) / "execution-pins.json"), "--evaluated-at", str(report["evaluatedAt"])],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertTrue(json.loads(verified.stdout)["authorityVerified"])
                if destination := os.environ.get("CHIO_FUNDED_EVIDENCE_DIR"):
                    out = Path(destination)
                    (out / f"peer-{mode}.json").write_text(json.dumps(report, indent=2) + "\n")
                    (out / f"peer-python-{mode}.json").write_text(verified.stdout)
                    for name in ("witness", "execution-pins", "verifier-request", "verifier-enrollment", "decision", "peer-call", "peer-endpoint", "peer-report"):
                        (out / f"peer-{mode}-{name}.json").write_bytes((Path(tmp) / f"{name}.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
