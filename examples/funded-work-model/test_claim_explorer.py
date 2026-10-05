import unittest

try:
    from claim_explorer import explore
except ImportError:
    explore = None


class ExplorationTests(unittest.TestCase):
    def test_exhaustive_orderings_preserve_claims_and_each_sources_money(self):
        self.assertIsNotNone(explore, "the claim exploration is not implemented")
        result = explore()
        self.assertIsNone(result["counterexample"])
        self.assertEqual(set(result["states_seen"]), {
            "Funded", "Submitted", "Payable", "Paid", "Rejected", "TimedOut", "Refunded",
        })
        # These reachable behaviors matter, not one exact exploration count.
        covered = {(x["op"], x["before"], x["after"], x["ok"]) for x in result["traces"]}
        self.assertIn(("pay", "Payable", "Paid", True), covered)
        self.assertIn(("refund", "Payable", "Payable", False), covered)
        self.assertIn(("refund", "Submitted", "Refunded", True), covered)
        self.assertIn(("decide", "Submitted", "Payable", True), covered)
        # State-only representatives can hide a broken expiry guard behind the
        # earlier RefundNotDue guard. Retain and label both deadline regions.
        for state in ("Payable", "Paid"):
            for op in ("refund", "expire"):
                for after_deadline in (False, True):
                    matches = [trace for trace in result["traces"]
                               if trace["before"] == state and trace["op"] == op
                               and (trace["steps"][-1]["time"] > 8) == after_deadline]
                    self.assertTrue(matches, (state, op, after_deadline))
                    self.assertTrue(all(trace["steps"][-1].get("revert") == "WrongState"
                                        for trace in matches))

    def test_legacy_expiry_mutation_produces_an_earned_claim_refund_trace(self):
        self.assertIsNotNone(explore, "the claim exploration is not implemented")
        result = explore(broken_expiry=True)
        failure = result["counterexample"]
        self.assertIsNotNone(failure)
        self.assertEqual(failure["property"], "accepted claim was refunded")
        self.assertEqual([s["op"] for s in failure["steps"] if s["op"] != "advance"],
                         ["submit", "decide", "refund"])


if __name__ == "__main__":
    unittest.main()
