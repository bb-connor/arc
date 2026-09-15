"""Separate checkpoint CLI custody followed by original observed settlement."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("CHIO_FUNDED_BINARY", ROOT / "target/debug/chio-federated-work"))


class CheckpointHandoff(unittest.TestCase):
    def test_external_checkpoint_payout_and_refund(self):
        for mode in ("pay", "reject"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="chio-checkpoint-") as tmp:
                completed = subprocess.run(
                    [str(BINARY), "experimental-checkpoint-lifecycle", tmp, mode],
                    cwd=ROOT, capture_output=True, text=True, timeout=180,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = json.loads(completed.stdout)
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
                self.assertTrue(report["responseReplayWithoutKeys"])
                self.assertTrue(report["providerHasNoCheckpointKeys"])
                self.assertEqual(report["operatorProcesses"], 3)
                self.assertEqual(report["providerHandoffProcesses"], 2)
                self.assertFalse(report["independentAdministration"])
                python = os.environ["CHIO_FUNDED_PYTHON"]
                verified = subprocess.run(
                    [python, "-B", str(ROOT / "examples/federated-work/execution_evidence.py"),
                     str(Path(tmp) / "witness.json"), "--pins", str(Path(tmp) / "pins.json"),
                     "--evaluated-at", str(report["evaluatedAt"])],
                    cwd=ROOT, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(verified.returncode, 0, verified.stderr)
                public = json.loads(verified.stdout)
                self.assertTrue(public["authorityVerified"])
                self.assertEqual(public["executionMatchesSubmission"], mode == "pay")
                self.assertFalse(public["financialBacking"])
                raw = (Path(tmp) / "request.json").read_bytes()
                request = json.loads(raw)
                wrong_context = dict(request, contextSha256="ab" * 32)
                mutations = (
                    json.dumps(request, indent=2).encode(),
                    raw.replace(b'"schema":', b'"schema":"foreign","schema":', 1),
                    json.dumps(dict(request, unsignedOverride=True), sort_keys=True, separators=(",", ":")).encode(),
                    json.dumps(wrong_context, sort_keys=True, separators=(",", ":")).encode(),
                    b" " * (256 * 1024 + 1),
                )
                for index, mutation in enumerate(mutations):
                    bad = Path(tmp) / f"bad-{index}.json"
                    output = Path(tmp) / f"unexpected-{index}.json"
                    bad.write_bytes(mutation)
                    denied = subprocess.run(
                        [str(BINARY), "experimental-checkpoint-sign", str(Path(tmp) / "operator"), str(bad), str(output)],
                        cwd=ROOT, capture_output=True, text=True, timeout=15,
                    )
                    self.assertNotEqual(denied.returncode, 0, index)
                    self.assertFalse(output.exists(), index)
                evidence = os.environ.get("CHIO_FUNDED_EVIDENCE_DIR")
                if evidence:
                    target = Path(evidence)
                    (target / f"handoff-{mode}.json").write_text(json.dumps(report, sort_keys=True) + "\n")
                    (target / f"python-{mode}.json").write_text(verified.stdout)
                    for name in ("witness", "pins", "request", "enrollment", "response"):
                        (target / f"{name}-{mode}.json").write_bytes((Path(tmp) / f"{name}.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
