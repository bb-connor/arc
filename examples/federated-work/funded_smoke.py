#!/usr/bin/env python3
"""Private-chain funding to a native operation and hold, with real W0 execution."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("CHIO_FUNDED_BINARY", ROOT / "target/debug/chio-federated-work"))


def retain_summary(name, result):
    """Optionally retain only the public report, never private fixture state."""
    if destination := os.environ.get("CHIO_FUNDED_EVIDENCE_DIR"):
        path = Path(destination)
        path.mkdir(parents=True, exist_ok=True)
        (path / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")


class FundedNativeSmoke(unittest.TestCase):
    def test_killed_workers_preserve_original_funding_operation_and_hold(self):
        for point, executions in (("after-stage", 1), ("before-bind", 0), ("after-hold", 0), ("after-tool", 1)):
            with self.subTest(point=point), tempfile.TemporaryDirectory(prefix="chio-funding-loss-") as directory:
                completed = subprocess.run(
                    [str(BINARY), "experimental-funded-smoke", directory, point],
                    cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual(result["killedSignal"], 9)
                self.assertEqual(result["after"]["operationCount"], 1)
                self.assertEqual(result["after"]["holdCount"], 1)
                self.assertEqual(result["replay"]["executions"], executions)
                if point == "before-bind":
                    self.assertEqual(result["replay"]["paymentState"], "not_authorized")
                    self.assertEqual(result["replay"]["fundingCorrelation"], "not_authorized")
                    self.assertEqual(result["replay"]["nativePaymentState"], "Closed")
                    self.assertIsNone(result["replay"]["nativeAuthorizationId"])
                    self.assertEqual(result["after"]["holdDisposition"], "reversed")
                else:
                    self.assertEqual(result["replay"]["paymentState"], "pending")
                    self.assertEqual(result["replay"]["nativePaymentState"], "Authorized" if point == "after-tool" else "Settling")
                    self.assertEqual(result["replay"]["nativeAuthorizationId"], result["replay"]["authorizationId"])
                    self.assertIsNotNone(result["replay"]["nativeAuthorizationId"])
                    self.assertEqual(result["after"]["holdDisposition"], "reconciled" if point == "after-stage" else "open")
                if point != "after-stage":
                    self.assertEqual(result["before"]["operationId"], result["after"]["operationId"])
                    self.assertEqual(result["before"]["holdId"], result["after"]["holdId"])
                if point == "after-tool":
                    self.assertEqual(result["replay"]["nativeState"], "OutcomeUnknownAfterDispatch")
                self.assertEqual(result["chain"]["escrowBalance"], "100")
                self.assertEqual(result["chain"]["paid"], "0")
                self.assertEqual(result["chain"]["refunded"], "0")
                retain_summary(point, result)

    def test_real_deposit_binds_one_native_operation_and_hold(self):
        with tempfile.TemporaryDirectory(prefix="chio-native-funding-") as directory:
            completed = subprocess.run(
                [str(BINARY), "experimental-funded-smoke", directory],
                cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            first, replay = result["first"], result["replay"]
            for field in ("operationId", "holdId", "authorizationId", "allocationId"):
                self.assertEqual(first[field], replay[field])
            self.assertEqual(first["executions"], 1)
            self.assertEqual(replay["executions"], 1)
            self.assertEqual(replay["paymentState"], "pending")
            self.assertFalse(replay["externalFundsTransferred"])
            self.assertEqual(result["chain"]["state"], "Funded")
            self.assertEqual(result["chain"]["escrowBalance"], "100")
            self.assertEqual(result["chain"]["payerBalance"], "900")
            self.assertEqual(result["chain"]["beneficiaryBalance"], "0")
            self.assertEqual(result["chain"]["paid"], "0")
            self.assertEqual(result["chain"]["refunded"], "0")
            retain_summary("happy", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
