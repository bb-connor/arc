"""Financial safety tests; expectations are independent of transition helpers."""

import copy
import unittest

try:
    from claim_model import ClaimLedger, Terms
except ImportError:
    ClaimLedger = Terms = None


class ClaimModelTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(ClaimLedger, "the funded-claim model is not implemented")
        self.ledger = ClaimLedger({"A": 100, "B": 60})
        self.terms = Terms("A", "B", "V", 100, 2, 4, 6, 8)
        self.assertTrue(self.ledger.fund("parent", self.terms, now=0))

    def submit(self):
        self.assertTrue(self.ledger.submit("parent", "B", "output", now=2))

    def accept(self):
        self.submit()
        self.assertTrue(self.ledger.decide("parent", "V", "decision", True, now=5))

    def test_accepted_claim_can_be_withdrawn_after_all_deadlines(self):
        self.accept()
        self.assertFalse(self.ledger.refund("parent", now=100))
        self.assertTrue(self.ledger.pay("parent", "B", now=100))
        self.assertEqual(self.ledger.accounts("A"), (0, 100, 0, 0))
        self.assertFalse(self.ledger.pay("parent", "B", now=101))
        self.assertFalse(self.ledger.refund("parent", now=101))

    def test_exact_submission_replays_without_renewing_its_deadline(self):
        self.submit()
        self.assertTrue(self.ledger.submit("parent", "B", "output", now=100))
        self.assertFalse(self.ledger.submit("parent", "B", "replacement", now=2))
        self.assertFalse(self.ledger.submit("parent", "A", "output", now=2))
        self.assertFalse(self.ledger.decide("parent", "V", "late", True, now=7))
        self.assertTrue(self.ledger.refund("parent", now=9))

    def test_decision_window_is_exclusive_then_inclusive(self):
        self.submit()
        self.assertFalse(self.ledger.decide("parent", "V", "d", True, now=4))
        self.assertTrue(self.ledger.decide("parent", "V", "d", True, now=6))
        self.assertTrue(self.ledger.decide("parent", "V", "d", True, now=100))
        self.assertFalse(self.ledger.decide("parent", "V", "d", False, now=6))
        self.assertFalse(self.ledger.decide("parent", "V", "changed", True, now=6))

    def test_unsubmitted_or_uncertified_work_refunds_only_after_timeout(self):
        for submit in (False, True):
            ledger = copy.deepcopy(self.ledger)
            if submit:
                self.assertTrue(ledger.submit("parent", "B", "output", now=2))
            self.assertFalse(ledger.refund("parent", now=8))
            self.assertTrue(ledger.expire("parent", now=9))
            self.assertEqual(ledger.jobs["parent"].state, "TimedOut")
            self.assertTrue(ledger.refund("parent", now=9))
            self.assertEqual(ledger.accounts("A"), (0, 0, 100, 0))
            self.assertFalse(ledger.refund("parent", now=9))
            self.assertFalse(ledger.decide("parent", "V", "d", True, now=9))

    def test_rejected_work_has_only_a_refund_terminal(self):
        self.submit()
        self.assertTrue(self.ledger.decide("parent", "V", "rejection", False, now=5))
        self.assertFalse(self.ledger.pay("parent", "B", now=5))
        self.assertTrue(self.ledger.refund("parent", now=5))
        self.assertFalse(self.ledger.decide("parent", "V", "accept", True, now=5))
        self.assertEqual(self.ledger.accounts("A"), (0, 0, 100, 0))

    def test_transfer_failure_keeps_the_claim_due_and_execution_unknown(self):
        self.accept()
        self.ledger.mark_unknown("parent")
        before = copy.deepcopy(self.ledger)
        self.assertFalse(self.ledger.pay("parent", "B", now=9, transfer_ok=False))
        self.assertEqual(self.ledger, before)
        self.assertTrue(self.ledger.pay("parent", "B", now=9))
        self.assertTrue(self.ledger.jobs["parent"].execution_unknown)

    def test_refund_failure_is_atomic_and_does_not_resolve_unknown_execution(self):
        self.ledger.mark_unknown("parent")
        before = copy.deepcopy(self.ledger)
        self.assertFalse(self.ledger.refund("parent", now=9, transfer_ok=False))
        self.assertEqual(self.ledger, before)
        self.assertTrue(self.ledger.refund("parent", now=9))
        self.assertTrue(self.ledger.jobs["parent"].execution_unknown)

    def test_earned_child_withdraws_after_parent_refund(self):
        child = Terms("B", "C", "V", 60, 2, 4, 6, 8)
        self.assertTrue(self.ledger.fund("child", child, now=0))
        self.assertTrue(self.ledger.submit("child", "C", "child-output", now=2))
        self.assertTrue(self.ledger.decide("child", "V", "child-decision", True, now=5))
        self.assertTrue(self.ledger.refund("parent", now=9))
        self.assertEqual(self.ledger.jobs["child"].state, "Payable")
        self.assertTrue(self.ledger.pay("child", "C", now=20))
        self.assertEqual(self.ledger.accounts("A"), (0, 0, 100, 0))
        self.assertEqual(self.ledger.accounts("B"), (0, 60, 0, 0))

    def test_expected_parent_revenue_is_not_child_backing(self):
        child = Terms("B", "C", "V", 61, 2, 4, 6, 8)
        self.assertFalse(self.ledger.fund("child", child, now=0))
        self.assertEqual(self.ledger.accounts("B"), (60, 0, 0, 0))
        self.assertFalse(self.ledger.fund("parent", self.terms, now=0))

    def test_malformed_terms_or_foreign_authority_cannot_move_money(self):
        for amount in (0, -1, True, 1.5, 2**53):
            self.assertFalse(self.ledger.fund("bad", Terms("B", "C", "V", amount, 2, 4, 6, 8), now=0))
        for deadlines in ((0, 4, 6, 8), (2, 2, 6, 8), (2, 4, 4, 8), (2, 4, 6, 6)):
            self.assertFalse(self.ledger.fund("bad", Terms("B", "C", "V", 1, *deadlines), now=0))
        self.assertFalse(self.ledger.submit("parent", "B", "", now=1))
        self.assertFalse(self.ledger.submit("parent", "B", "late", now=3))
        self.submit()
        self.assertFalse(self.ledger.decide("parent", "A", "d", True, now=5))
        self.assertFalse(self.ledger.decide("parent", "V", "", True, now=5))
        self.assertFalse(self.ledger.pay("parent", "A", now=5))
        self.assertEqual(self.ledger.accounts("A"), (0, 0, 0, 100))


if __name__ == "__main__":
    unittest.main()
