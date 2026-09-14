import itertools
import unittest

from funding_model import AllocationAuthority, Claim


class FundingTests(unittest.TestCase):
    def test_local_forks_can_promise_more_than_the_real_source(self):
        local_views = [100, 100]
        offers = [Claim("s", "c", "C", 100), Claim("s", "d", "D", 100)]
        self.assertTrue(all(c.units <= v for c, v in zip(offers, local_views)))
        self.assertGreater(sum(c.units for c in offers), 100)

    def test_authority_rejects_the_second_incompatible_allocation(self):
        authority = AllocationAuthority("s", 100)
        self.assertTrue(authority.reserve(Claim("s", "c", "C", 100)))
        self.assertFalse(authority.reserve(Claim("s", "d", "D", 100)))
        self.assertEqual(authority.available, 0)

    def test_replay_is_exact_and_does_not_reserve_twice(self):
        authority = AllocationAuthority("s", 100)
        claim = Claim("s", "c", "C", 60)
        self.assertTrue(authority.reserve(claim))
        self.assertTrue(authority.reserve(claim))
        for changed in (
            Claim("s", "c", "D", 60),
            Claim("s", "c", "C", 61),
            Claim("foreign", "x", "C", 1),
            Claim("s", "zero", "C", 0),
        ):
            self.assertFalse(authority.reserve(changed))
        self.assertEqual(authority.available, 40)
        self.assertEqual(list(authority.claims.values()), [claim])

    def test_all_serial_orders_preserve_reserved_plus_available(self):
        claims = [Claim("s", str(i), "C", n) for i, n in enumerate((1, 2, 3, 4))]
        for order in itertools.permutations(claims):
            authority = AllocationAuthority("s", 7)
            for claim in order:
                authority.reserve(claim)
                reserved = sum(c.units for c in authority.claims.values())
                self.assertEqual(reserved + authority.available, 7)
                self.assertGreaterEqual(authority.available, 0)

    def test_invalid_claim_cannot_change_backing(self):
        authority = AllocationAuthority("s", 100)
        for claim in (
            Claim("s", "", "C", 10),
            Claim("s", "c", "", 10),
            Claim("s", "c", "C", -1),
            Claim("s", "c", "C", True),
            Claim("s", "c", "C", 1.5),
            Claim("s", "c", "C", 101),
        ):
            with self.subTest(claim=claim):
                self.assertFalse(authority.reserve(claim))
                self.assertEqual(authority.available, 100)
                self.assertEqual(authority.claims, {})

    def test_invalid_deposit_cannot_create_an_authority(self):
        for source, deposited in (("", 100), ("s", -1), ("s", True), ("s", 1.5)):
            with self.subTest(source=source, deposited=deposited):
                with self.assertRaises(ValueError):
                    AllocationAuthority(source, deposited)
        empty = AllocationAuthority("s", 0)
        self.assertFalse(empty.reserve(Claim("s", "c", "C", 1)))


if __name__ == "__main__":
    unittest.main()
