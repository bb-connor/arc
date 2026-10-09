import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import BRIEF, SwarmCase

BIN = Path(__file__).resolve().parent.parent / "bin" / "swarm"


class CLITest(SwarmCase):
    def run_cli(self, store, *args):
        env = {**os.environ, "SWARM_HOME": str(store.root), "SWARM_AGENT": store.agent,
               "SWARM_ROLE": store.role, "SWARM_VENDOR": store.vendor}
        return subprocess.run([sys.executable, str(BIN), *args], env=env, capture_output=True, text=True)

    def test_round_trip_and_exit_codes(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        brief = self.tmp / "brief.md"
        brief.write_text(BRIEF)
        registered = self.run_cli(worker, "register", "--machine", "ws2", "--vendor", "codex", "--role", "worker",
                                  "--model", "m", "--tiers", "mid")
        self.assertEqual(registered.returncode, 0, registered.stderr)
        created = self.run_cli(conductor, "item", "new", "N23", "--title", "Constant time", "--paths", "crates/x/**",
                               "--brief-file", str(brief))
        self.assertEqual(created.returncode, 0, created.stderr)
        picked = self.run_cli(worker, "next")
        self.assertEqual((picked.returncode, picked.stdout.strip()), (0, "N23"))
        self.assertEqual(self.run_cli(worker, "next").stdout.strip(), "N23")
        illegal = self.run_cli(worker, "status", "N23", "ready")
        self.assertEqual(illegal.returncode, 2)
        self.assertIn("not a permitted move", illegal.stderr)
        self.assertEqual(self.run_cli(worker, "inbox").returncode, 1)
        self.run_cli(conductor, "send", "codex-ws2-worker1", "--kind", "fyi", "--subject", "hi", "--body", "x")
        self.assertEqual(self.run_cli(worker, "inbox").returncode, 0)
        leak = self.tmp / "leak.txt"
        leak.write_text("sk-" + "a" * 30)
        self.assertEqual(self.run_cli(worker, "scan", str(leak)).returncode, 1)
        self.assertEqual(self.run_cli(worker, "halt", "--reason", "x").returncode, 2)
        refused = self.run_cli(worker, "merge", "1200")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("only the integrator or the conductor merges", refused.stderr)
        refused = self.run_cli(worker, "review-pr", "1200")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("only the integrator or the conductor requests a whole-PR review", refused.stderr)
        refused = self.run_cli(worker, "check-train")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("only the integrator or the conductor runs check trains", refused.stderr)
        recorded = self.run_cli(conductor, "record", "decision", "pilot-roster", "--file", str(brief))
        self.assertEqual((recorded.returncode, recorded.stdout.strip()), (0, "decisions/0001-pilot-roster.md"))


    # Final review: the red-CI override must survive the hop to the train host.
    def test_check_train_forwards_its_flags_to_the_train_host(self):
        from swarmlib.store import set_config
        set_config(self.clone("claude-ws2-conductor", role="conductor", vendor="claude"), "train_host", json.dumps("fakehost"))
        integrator = self.clone("codex-ws2-integrator", role="integrator", vendor="codex")
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir()
        (fake_bin / "ssh").write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        (fake_bin / "ssh").chmod(0o755)
        env = {**os.environ, "SWARM_HOME": str(integrator.root), "SWARM_AGENT": integrator.agent,
               "SWARM_ROLE": "integrator", "SWARM_VENDOR": "codex", "SWARM_MACHINE": "ws2",
               "PATH": f"{fake_bin}:{os.environ['PATH']}"}
        ran = subprocess.run([sys.executable, str(BIN), "check-train", "--land", "--allow-red"], env=env,
                             capture_output=True, text=True)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn("fakehost", ran.stdout.splitlines())
        self.assertTrue(ran.stdout.rstrip().endswith("check-train --local --land --allow-red"), ran.stdout)


if __name__ == "__main__":
    unittest.main()
