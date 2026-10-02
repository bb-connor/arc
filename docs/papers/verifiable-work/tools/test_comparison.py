"""Observable agreement with model traces, plus checks the traces omit."""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / "examples/funded-work-model"))
from claim_model import ClaimLedger, Terms

spec = importlib.util.find_spec("compare")
if spec:
    from compare import SqlEscrow, compare_corpus
else:
    SqlEscrow = compare_corpus = None


class ComparisonTests(unittest.TestCase):
    def test_replays_representative_traces_in_sql_transactions(self):
        self.assertIsNotNone(compare_corpus, "ordinary SQL comparison is absent")
        result = compare_corpus(ROOT / "examples/funded-work-model/claim-traces.json")
        self.assertEqual(result["mismatches"], [])
        self.assertGreater(result["checked_steps"], result["traces"])
        self.assertGreater(result["traces"], 100)

    def test_parent_refund_cannot_erase_a_child_earned_right(self):
        self.assertIsNotNone(SqlEscrow, "ordinary SQL escrow is absent")
        rail = SqlEscrow({"A": 100, "B": 60})
        self.addCleanup(rail.close)
        self.assertTrue(rail.fund("parent", Terms("A", "B", "V", 100, 2, 4, 6, 8), now=0))
        self.assertTrue(rail.fund("child", Terms("B", "C", "V", 60, 2, 4, 6, 8), now=0))
        self.assertFalse(rail.fund("fork", Terms("B", "D", "V", 60, 2, 4, 6, 8), now=0))
        self.assertTrue(rail.submit("child", "C", "result", now=2))
        self.assertTrue(rail.decide("child", "V", "accepted", True, now=5))
        self.assertTrue(rail.refund("parent", now=9))
        self.assertFalse(rail.refund("child", now=9))
        self.assertFalse(rail.pay("child", "C", now=9, transfer_ok=False))
        self.assertTrue(rail.pay("child", "C", now=9))
        self.assertFalse(rail.pay("child", "C", now=9))
        self.assertEqual(rail.accounts("A"), (0, 0, 100, 0))
        self.assertEqual(rail.accounts("B"), (0, 60, 0, 0))

    def test_unknown_execution_and_unavailable_verifier_do_not_become_rejection(self):
        self.assertIsNotNone(SqlEscrow, "ordinary SQL escrow is absent")
        rail = SqlEscrow({"A": 100})
        self.addCleanup(rail.close)
        self.assertTrue(rail.fund("job", Terms("A", "B", "V", 100, 2, 4, 6, 8), now=0))
        self.assertTrue(rail.submit("job", "B", "result", now=2))
        rail.mark_unknown("job")
        self.assertFalse(rail.decide("job", "X", "invented", False, now=5))
        self.assertTrue(rail.refund("job", now=9))
        self.assertTrue(rail.snapshot()["job"]["unknown"])
        self.assertEqual(rail.snapshot()["job"]["decision"], "")

if __name__ == "__main__":
    unittest.main()
