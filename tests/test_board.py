import json
import unittest

from support import SwarmCase

from swarmlib import agents, board, claims, items, metrics, msgs


class BoardTest(SwarmCase):
    def test_board_sections_order_and_flags(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        agents.register(worker, agent_id=worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="gpt-6.1-sol", effort="medium", tiers=["mid"])
        self.add_item(conductor, "F1", title="Open | piped title")
        self.add_item(conductor, "F2", title="Claimed one")
        self.add_item(conductor, "W1", wave=2, depends_on=["F1"])
        claims.claim(worker, "F2", [])
        msgs.send(conductor, "human", "request", "F2", "approve train PR", "please")
        self.at("2026-10-06T14:00:00Z")
        conductor.sync()
        text = board.render(conductor)
        self.assertLess(text.index("## Needs Connor"), text.index("## Wave 1"))
        self.assertIn("approve train PR", text)
        self.assertLess(text.index("| F2 |"), text.index("| F1 |"))  # claimed sorts before open
        self.assertIn("Open \\| piped title", text)
        self.assertIn("F1 (open)", text)
        self.assertIn("claim expired", text)
        self.assertIn("STALE", text)
        self.assertTrue(board.write(conductor))
        self.assertFalse(board.write(conductor))  # unchanged board does not commit


class MetricsTest(SwarmCase):
    def test_integrated_bounce_and_slot_wait(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.add_item(conductor, "F1")

        def history() -> bool:
            item = items.load(conductor, "F1")
            item.body += "- 2026-10-06T10:00:00Z r: verdict changes round 1\n"
            item.body += "- 2026-10-06T11:00:00Z r: verdict accept round 1\n"
            item.body += "- 2026-10-06T11:30:00Z i: status ready -> integrated\n"
            items.save(conductor, item)
            return True

        conductor.transact("history", history)
        conductor.sync()
        self.assertEqual(metrics.integrated_since(conductor, metrics.clock.parse("2026-10-06T00:00:00Z")), ["F1"])
        self.assertEqual(metrics.bounce_rate(conductor, metrics.clock.parse("2026-10-06T00:00:00Z")), 0.5)
        log = self.tmp / "waits.log"
        log.write_text("\n".join(json.dumps({"at": f"2026-10-06T1{i}:00:00Z", "slot": 0, "waited_s": w, "item": ""})
                                 for i, w in enumerate([60, 600, 1200])) + "\n")
        self.assertEqual(metrics.slot_wait_median(log, metrics.clock.parse("2026-10-06T00:00:00Z")), 600)


if __name__ == "__main__":
    unittest.main()
