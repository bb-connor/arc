import unittest

from support import SwarmCase

from swarmlib import agents, msgs
from swarmlib.store import SwarmError


class MessagesTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="m", effort="", tiers=["mid"])

    def test_direct_role_and_broadcast_delivery(self):
        msgs.send(self.conductor, "codex-ws2-worker1", "request", "F1", "direct", "a")
        msgs.send(self.conductor, "worker", "fyi", "", "to role", "b")
        msgs.send(self.conductor, "all", "fyi", "", "everyone", "c")
        msgs.send(self.conductor, "reviewer", "fyi", "", "not mine", "d")
        subjects = [m["subject"] for m in msgs.inbox(self.worker)]
        self.assertEqual(sorted(subjects), ["direct", "everyone", "to role"])
        self.assertEqual(msgs.inbox(self.worker), [])
        self.assertEqual(len(msgs.inbox(self.worker, include_seen=True)), 3)

    def test_own_broadcasts_are_not_echoed(self):
        msgs.send(self.worker, "all", "fyi", "", "mine", "x")
        self.assertEqual(msgs.inbox(self.worker), [])

    def test_unknown_recipient_and_kind_refused(self):
        with self.assertRaises(SwarmError):
            msgs.send(self.worker, "nobody-here", "fyi", "", "s", "b")
        with self.assertRaises(SwarmError):
            msgs.send(self.worker, "conductor", "shout", "", "s", "b")


if __name__ == "__main__":
    unittest.main()
