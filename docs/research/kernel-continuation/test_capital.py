import unittest
from capital import Claim, reserve, exhaustive

class CapitalTests(unittest.TestCase):
    def test_refund_and_earned_claims_coexist(self):
        self.assertEqual(reserve(100, [Claim(30,"earned"), Claim(30,"earned")]), 160)
    def test_exclusive_selection_requires_unearned_work(self):
        self.assertEqual(reserve(100, [Claim(30,"ready",0), Claim(50,"ready",0)]), 150)
        self.assertEqual(reserve(100, [Claim(30,"earned",0), Claim(50,"unknown",0)]), 180)
    def test_unknown_retains_backing_and_fenced_absence_releases_it(self):
        self.assertEqual(reserve(100,[Claim(30,"unknown")]),130)
        self.assertEqual(reserve(100,[Claim(30,"absent")]),100)
    def test_invalid_profiles_fail_closed(self):
        for refund, claims in [(-1,[]),(True,[]),(0,[Claim(-1,"ready")]),
                (0,[Claim(1,"guess")]),(0,[Claim(1,"ready",-1)]),
                (0,[Claim(1.5,"earned")]),(0,[Claim(1,"ready",True)])]:
            with self.assertRaises(ValueError): reserve(refund,claims)
    def test_positive_companion_and_underbacked_controls(self):
        claims=[Claim(30,"earned",0),Claim(30,"earned",0)]
        self.assertEqual(exhaustive(100,claims),160)
        self.assertLess(100+max(c.amount for c in claims),exhaustive(100,claims))
        self.assertLess(100,exhaustive(100,[Claim(30,"unknown")]))

if __name__ == "__main__": unittest.main()
