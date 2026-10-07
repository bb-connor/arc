import unittest

from support import SwarmCase

from swarmlib import agents, claims, items, msgs
from swarmlib.store import SwarmError


class ClaimsTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.a = self.clone("codex-ws2-worker1")
        self.b = self.clone("claude-air-worker2", vendor="claude")
        for store, vendor in ((self.a, "codex"), (self.b, "claude")):
            agents.register(store, agent_id=store.agent, machine="m", vendor=vendor, role="worker",
                            model="m", effort="", tiers=["mid"])

    def test_claim_marks_item_and_writes_lease(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        self.a.sync()
        item = items.load(self.a, "F1")
        self.assertEqual((item.status, item.meta["owner"]), ("claimed", "codex-ws2-worker1"))
        lease = claims.read(self.a, "F1")
        self.assertEqual(lease["paths"], ["crates/f1/**"])
        self.assertEqual(lease["expires"], "2026-10-06T12:45:00Z")

    def test_racing_claims_exactly_one_wins(self):
        self.add_item(self.conductor, "F1")
        calls = []
        original = self.b.transact

        def racing_transact(message, mutate, **kw):
            def wrapped():
                calls.append(1)
                if len(calls) == 1:
                    claims.claim(self.a, "F1", [])  # A lands first, mid-transaction
                return mutate()
            return original(message, wrapped, **kw)

        self.b.transact = racing_transact
        with self.assertRaisesRegex(SwarmError, "claimed by codex-ws2-worker1"):
            claims.claim(self.b, "F1", [])
        self.b.sync()
        self.assertEqual(claims.read(self.b, "F1")["agent"], "codex-ws2-worker1")

    def test_overlapping_paths_refused_unless_shared(self):
        self.add_item(self.conductor, "F1", paths=["crates/kernel/src/**"])
        self.add_item(self.conductor, "F2", paths=["crates/kernel/src/eval.rs"])
        claims.claim(self.a, "F1", [])
        with self.assertRaisesRegex(SwarmError, "overlap"):
            claims.claim(self.b, "F2", [])
        claims.claim(self.b, "F2", [], share=True)
        self.b.sync()
        self.assertTrue(claims.read(self.b, "F2")["shared"])

    def test_unmet_dependencies_refused(self):
        self.add_item(self.conductor, "W1")
        self.add_item(self.conductor, "W2", depends_on=["W1"])
        with self.assertRaisesRegex(SwarmError, "W1 \\(open\\)"):
            claims.claim(self.a, "W2", [])

    # Review focus: a little clock skew must not let someone steal a live claim.
    def test_expiry_respects_grace_then_allows_steal(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        self.at("2026-10-06T12:46:00Z")  # 1 minute past expiry, inside the 2 minute grace
        with self.assertRaisesRegex(SwarmError, "claimed by"):
            claims.claim(self.b, "F1", [], steal=True)
        self.at("2026-10-06T12:48:00Z")
        with self.assertRaisesRegex(SwarmError, "--steal"):
            claims.claim(self.b, "F1", [])
        claims.claim(self.b, "F1", [], steal=True)
        self.a.sync()
        self.assertEqual(claims.read(self.a, "F1")["agent"], "claude-air-worker2")
        notes = msgs.inbox(self.a)
        self.assertEqual([m["subject"] for m in notes], ["claim on F1 taken over"])

    def test_heartbeat_extends_only_my_leases(self):
        self.add_item(self.conductor, "F1")
        self.add_item(self.conductor, "F2")
        claims.claim(self.a, "F1", [])
        claims.claim(self.b, "F2", [])
        self.at("2026-10-06T12:30:00Z")
        claims.heartbeat(self.a)
        self.a.sync()
        self.assertEqual(claims.read(self.a, "F1")["expires"], "2026-10-06T13:15:00Z")
        self.assertEqual(claims.read(self.a, "F2")["expires"], "2026-10-06T12:45:00Z")
        self.assertEqual(agents.load(self.a, "codex-ws2-worker1")["last_heartbeat"], "2026-10-06T12:30:00Z")

    def test_release_requires_owner(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        with self.assertRaises(SwarmError):
            claims.release(self.b, "F1")
        claims.release(self.a, "F1")
        self.a.sync()
        self.assertIsNone(claims.read(self.a, "F1"))

    def test_reassign_is_conductor_only_and_messages_both(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.a, "F1", [])
        with self.assertRaises(SwarmError):
            claims.reassign(self.b, "F1", "claude-air-worker2")
        claims.reassign(self.conductor, "F1", "claude-air-worker2", ttl=480)
        self.b.sync()
        self.assertEqual(items.load(self.b, "F1").meta["owner"], "claude-air-worker2")
        self.assertEqual(claims.read(self.b, "F1")["ttl_minutes"], 480)
        self.assertEqual(len(msgs.inbox(self.a)), 1)
        self.assertEqual(len(msgs.inbox(self.b)), 1)

    def test_conductor_only_claims_for_others(self):
        self.add_item(self.conductor, "F1")
        with self.assertRaises(SwarmError):
            claims.claim(self.a, "F1", [], owner="claude-air-worker2")


if __name__ == "__main__":
    unittest.main()
