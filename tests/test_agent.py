import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import SwarmCase

from swarmlib import agent, agents, claims, items, lifecycle, msgs
from swarmlib.agent import Context, Execution

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "prompts"


class CommandTest(unittest.TestCase):
    def test_vendor_commands(self):
        cwd = Path("/lane")
        claude = agent.vendor_command({"vendor": "claude", "model": "opus"}, "P", cwd, settings=Path("/s.json"), resume_id="abc")
        self.assertEqual(claude[:3], ["claude", "-p", "P"])
        self.assertIn("bypassPermissions", claude)
        self.assertEqual(claude[-2:], ["--resume", "abc"])
        codex = agent.vendor_command({"vendor": "codex", "model": "gpt-6.1-sol", "effort": "max"}, "P", cwd)
        self.assertEqual(codex[:3], ["codex", "exec", "--json"])
        self.assertIn("model_reasoning_effort=max", codex)
        self.assertEqual(codex[-1], "P")
        resumed = agent.vendor_command({"vendor": "codex", "model": "m"}, "P", cwd, resume_id="t1")
        self.assertEqual(resumed[-3:], ["resume", "t1", "P"])
        cursor = agent.vendor_command({"vendor": "cursor", "model": "sonnet"}, "P", cwd)
        self.assertEqual(cursor[cursor.index("--workspace") + 1], "/lane")
        hermes = agent.vendor_command({"vendor": "hermes", "model": "z-ai/glm-5.2"}, "P", cwd, usage_file=Path("/u.json"))
        self.assertEqual(hermes[:3], ["hermes", "-z", "P"])
        self.assertIn("openrouter", hermes)

    def test_rate_limit_only_on_failure(self):
        self.assertTrue(agent.rate_limited(Execution(1, "Error: 429 Too Many Requests")))
        self.assertFalse(agent.rate_limited(Execution(0, "implemented the rate limit guard")))
        self.assertFalse(agent.rate_limited(Execution(1, "compile error")))

    def test_session_ids(self):
        self.assertEqual(agent.session_id_from("claude", 'noise\n{"type":"result","session_id":"s-1"}\n'), "s-1")
        self.assertEqual(agent.session_id_from("codex", '{"type":"thread.started","thread_id":"t-9"}\n{"type":"x"}\n'), "t-9")
        self.assertEqual(agent.session_id_from("claude", "plain text"), "")

    def test_templates_render_with_their_fields(self):
        fields = dict(agent="a", role="worker", item_id="F1", worktree="/w", branch="lane/F1-x", base="b",
                      paths="p", brief="BRIEF", sender="s", subject="s", request="r", events="- e")
        for template in sorted(PROMPTS.glob("*.md")):
            text = agent.render(template, **fields)
            self.assertNotIn("{", text.replace("{{", ""), template.name)

    def test_render_missing_field_is_swarm_error(self):
        with self.assertRaises(agent.SwarmError):
            agent.render(PROMPTS / "worker.md", agent="a")


class ExecuteTest(SwarmCase):
    def test_agent_cli_cannot_read_the_runners_stdin(self):
        # codex exec reads piped stdin as extra prompt input; the runner must close it.
        code = ("import sys; from pathlib import Path; from swarmlib import agent; "
                "print(repr(agent.execute(['cat'], Path('.'), Path(sys.argv[1])).output))")
        proc = subprocess.run([sys.executable, "-c", code, str(self.tmp / "cat.log")], input="LEAKED-STDIN",
                              capture_output=True, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("LEAKED-STDIN", proc.stdout)


class LoopTest(SwarmCase):
    def setUp(self):
        super().setUp()
        self.conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        self.worker = self.clone("codex-ws2-worker1")
        agents.register(self.worker, agent_id=self.worker.agent, machine="ws2", vendor="codex", role="worker",
                        model="gpt-6.1-sol", effort="medium", tiers=["mid"])
        self.lane = self.tmp / "lane"
        self.lane.mkdir()

    def ctx(self, store, meta, executor, **kw):
        return Context(store=store, meta=meta, executor=executor, make_worktree=lambda _i, _r: self.lane,
                       prompts_dir=PROMPTS, **kw)

    def worker_meta(self):
        return agents.load(self.worker, self.worker.agent)

    def test_worker_iteration_hands_off_when_agent_submits(self):
        self.add_item(self.conductor, "F1")
        seen = {}

        def fake(command, cwd, log):
            seen["prompt"] = command[-1]
            lifecycle.status(self.worker, "F1", "review", "submitted by fake agent")
            return Execution(0, "ok")

        self.assertEqual(agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), fake)), "done")
        self.assertIn("You own exactly one work item: F1", seen["prompt"])
        self.assertIn("## Acceptance", seen["prompt"])

    def test_worker_iteration_blocks_when_agent_quits_without_submit(self):
        self.add_item(self.conductor, "F1")
        result = agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(0, "gave up")))
        self.assertEqual(result, "blocked")
        self.worker.sync()
        self.assertEqual(items.load(self.worker, "F1").status, "blocked")

    def test_worker_iteration_throttles_on_usage_cap(self):
        self.add_item(self.conductor, "F1")
        result = agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(1, "usage limit reached")))
        self.assertEqual(result, "throttled")
        self.worker.sync()
        meta = agents.load(self.worker, self.worker.agent)
        self.assertEqual((meta["status"], meta["throttled_until"]), ("throttled", "2026-10-06T12:30:00Z"))
        self.assertEqual(items.load(self.worker, "F1").status, "in-progress")

    def test_idle_when_nothing_to_do(self):
        self.assertEqual(agent.worker_iteration(self.ctx(self.worker, self.worker_meta(), lambda *a: Execution(0, ""))), "idle")

    def test_reviewer_without_verdict_releases_review(self):
        self.add_item(self.conductor, "F1")
        claims.claim(self.worker, "F1", [])
        lifecycle.status(self.worker, "F1", "in-progress")
        lifecycle.status(self.worker, "F1", "review")
        reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        agents.register(reviewer, agent_id=reviewer.agent, machine="ws2", vendor="claude", role="reviewer",
                        model="opus", effort="", tiers=["premium"])
        meta = agents.load(reviewer, reviewer.agent)
        self.assertEqual(agent.reviewer_iteration(self.ctx(reviewer, meta, lambda *a: Execution(0, ""))), "no-verdict")
        reviewer.sync()
        self.assertEqual(items.load(reviewer, "F1").meta["review"]["reviewer"], "")

    def test_reviewer_diffs_whole_pr_items_against_their_review_base(self):
        integrator = self.clone("codex-ws2-integrator", role="integrator", vendor="codex")
        lifecycle.request_pr_review(integrator, 1200, head="a" * 40, branch="integration/beta-next", author_vendor="codex")
        reviewer = self.clone("claude-ws2-reviewer1", role="reviewer", vendor="claude")
        agents.register(reviewer, agent_id=reviewer.agent, machine="ws2", vendor="claude", role="reviewer",
                        model="opus", effort="", tiers=["premium"])
        seen = {}

        def fake(command, cwd, log):
            seen["prompt"] = command[2]
            lifecycle.verdict(reviewer, "PR1200", "accept", "")
            return Execution(0, "")

        meta = agents.load(reviewer, reviewer.agent)
        self.assertEqual(agent.reviewer_iteration(self.ctx(reviewer, meta, fake)), "done")
        self.assertIn("refs/remotes/swarm/main...HEAD", seen["prompt"])

    def test_session_iteration_saves_and_resumes_session(self):
        conductor = self.clone("claude-ws2-conductor-2", role="conductor", vendor="claude")
        agents.register(conductor, agent_id=conductor.agent, machine="ws2", vendor="claude", role="conductor",
                        model="opus", effort="", tiers=["premium"])
        meta = agents.load(conductor, conductor.agent)
        commands = []

        def fake(command, cwd, log):
            commands.append(command)
            return Execution(0, json.dumps({"type": "result", "session_id": "sess-1"}))

        waits = []

        def waiter(store, timeout, **kwargs):
            waits.append(kwargs)
            return ["item F1: open -> review"]

        ctx = self.ctx(conductor, meta, fake, waiter=waiter)
        self.assertEqual(agent.session_iteration(ctx), "turn")
        self.assertEqual(waits[0], {"digest_every": 1200})  # the conductor wakes on digests
        self.assertIn("conductor of the Chio swarm", commands[0][2])
        self.assertNotIn("--resume", commands[0])
        agent.session_iteration(ctx)
        self.assertEqual(commands[1][-2:], ["--resume", "sess-1"])
        self.assertIn("item F1: open -> review", commands[1][2])

    def test_janitor_answers_requests_addressed_to_it(self):
        janitor = self.clone("hermes-ws2-janitor1", role="janitor", vendor="hermes")
        agents.register(janitor, agent_id=janitor.agent, machine="ws2", vendor="hermes", role="janitor",
                        model="z-ai/glm-5.2", effort="", tiers=["cheap"])
        msgs.send(self.worker, "janitor", "request", "F1", "triage run 42", "why did it fail?")
        meta = agents.load(janitor, janitor.agent)
        done = agent.janitor_iteration(self.ctx(janitor, meta, lambda *a: Execution(0, "flaky network test")))
        self.assertIn("board", done)
        self.assertTrue(any(d.startswith("answered") for d in done))
        replies = msgs.inbox(self.worker)
        self.assertEqual([(m["subject"], m["body"].strip()) for m in replies], [("re: triage run 42", "flaky network test")])

    def test_watchdog_relaunches_missing_sessions_and_flags_stale(self):
        watch = self.clone("watchdog-ws2", role="janitor", vendor="hermes")
        started = []
        actions = agent.watchdog_iteration(watch, "ws2", {}, has=lambda s: False, start=lambda st, a: started.append(a))
        self.assertEqual(started, ["codex-ws2-worker1"])
        self.at("2026-10-06T13:00:00Z")
        actions = agent.watchdog_iteration(watch, "ws2", {}, has=lambda s: True, start=lambda st, a: None)
        self.assertEqual(actions, ["flagged codex-ws2-worker1"])


if __name__ == "__main__":
    unittest.main()
