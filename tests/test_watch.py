import json
import os
import subprocess
import sys
import time
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from support import SwarmCase

from swarmlib import build, items, msgs, secrets, watch

BIN = Path(__file__).resolve().parent.parent / "bin" / "swarm"
NOW = datetime(2026, 10, 9, 3, 0, 0, tzinfo=timezone.utc)


def jsonl(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def tool(name, **params):
    return {"type": "tool_use", "id": "toolu_1", "name": name, "input": params}


def assistant(at, *content, model="claude-opus-5-5", **extra):
    return {"type": "assistant", "timestamp": at, "cwd": "/home/connor/backbay/arc", "sessionId": "S1",
            "message": {"role": "assistant", "model": model, "content": list(content)}, **extra}


CLAUDE_MAIN = [
    {"type": "ai-title", "aiTitle": "Codex multiagent workstation continuity", "sessionId": "S1"},
    assistant("2026-10-09T02:50:00Z", tool("Bash", command="git log -3", description="Read the latest coord entries")),
    {"type": "user", "timestamp": "2026-10-09T02:50:01Z", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]}},
    assistant("2026-10-09T02:51:00Z", tool("Read", file_path="/home/connor/backbay/arc/to-claude.md")),
    assistant("2026-10-09T02:52:00Z", {"type": "text", "text": "\nRESIDUAL-TRIAGE is green.\nMore detail."}),
    {"type": "system", "subtype": "turn_duration", "pendingBackgroundAgentCount": 2,
     "timestamp": "2026-10-09T02:52:01Z"},
]

CODEX_SUB = [
    {"timestamp": "2026-10-08T22:34:44Z", "type": "session_meta", "payload": {
        "id": "T2", "session_id": "T1", "parent_thread_id": "T1", "cwd": "/home/connor/backbay/arc",
        "thread_source": "subagent", "agent_nickname": "Pauli", "agent_path": "/root/kani_final_delta_review"}},
    {"timestamp": "2026-10-09T02:40:00Z", "type": "turn_context", "payload": {"cwd": "/home/connor/backbay/arc",
                                                                             "model": "gpt-6.1-sol"}},
    {"timestamp": "2026-10-09T02:41:00Z", "type": "response_item", "payload": {
        "type": "custom_tool_call", "name": "exec",
        "input": 'text(await tools.exec_command({cmd:"cargo kani -p chio-kernel --harness \\"seal\\"", yield_time_ms: 1000}))'}},
    {"timestamp": "2026-10-09T02:42:00Z", "type": "response_item", "payload": {
        "type": "function_call", "name": "send_message", "namespace": "collaboration",
        "arguments": json.dumps({"target": "/root", "message": "gAAAAABqyDdL5_9KcEMdI" + "x" * 40})}},
    {"timestamp": "2026-10-09T02:43:00Z", "type": "response_item", "payload": {
        "type": "agent_message", "author": "/root", "recipient": "/root/kani_final_delta_review",
        "content": [{"type": "input_text", "text": "Re-run the seal harness with the patched encoder."}]}},
    {"timestamp": "2026-10-09T02:43:30Z", "type": "response_item", "payload": {
        "type": "agent_message", "author": "/root", "recipient": "/root/kani_final_delta_review",
        "content": [{"type": "input_text", "text": "Message Type: NEW_TASK\nTask name: /root/kani\nSender: /root\nPayload:\n"},
                    {"type": "encrypted_content", "encrypted_content": "gAAAAABqyFbOGGfWizhQKqNHfw2Ey5JNBx9XuqgOG9g"}]}},
    {"timestamp": "2026-10-09T02:44:00Z", "type": "event_msg", "payload": {
        "type": "token_count", "rate_limits": {"primary": {"used_percent": 43.0, "window_minutes": 300}}}},
    {"timestamp": "2026-10-09T02:45:00Z", "type": "event_msg", "payload": {
        "type": "task_complete", "last_agent_message": "Seal harness passes."}},
]

PS = """\
3850933    03:42:08 /home/connor/.codex/packages/app-server-daemon/releases/0.162.0/bin/codex app-server daemon pid-update-loop
3851521    03:41:48 claude --dangerously-skip-permissions
3851695 1-03:41:44 /home/connor/.local/share/mise/installs/node/lts/bin/node /home/connor/.bun/bin/codex
  12345       00:05 /usr/bin/cargo test -p chio-kernel
  12346       00:02 grep codex
"""


class TranscriptTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.home = Path(tempfile.mkdtemp())

    def test_claude_session_shows_title_model_and_last_actions(self):
        path = jsonl(self.home / ".claude/projects/-arc/S1.jsonl", CLAUDE_MAIN)
        session = watch.claude_session(path, keep=3)
        self.assertEqual((session.vendor, session.id, session.label), ("claude", "S1",
                                                                      "Codex multiagent workstation continuity"))
        self.assertEqual(session.model, "claude-opus-5-5")
        self.assertEqual(session.cwd, "/home/connor/backbay/arc")
        self.assertEqual(session.actions, ["02:50 Bash: Read the latest coord entries",
                                           "02:51 Read: /home/connor/backbay/arc/to-claude.md",
                                           "02:52 says: RESIDUAL-TRIAGE is green."])
        self.assertEqual(session.note, "2 background agents")

    def test_claude_subagent_is_labelled_from_its_meta_file(self):
        folder = self.home / ".claude/projects/-arc/S1/subagents"
        path = jsonl(folder / "agent-a1.jsonl", [
            assistant("2026-10-09T02:53:00Z", tool("Grep", pattern="fn seal"), model="claude-sonnet-5-5",
                      isSidechain=True, agentId="a1")])
        (folder / "agent-a1.meta.json").write_text(json.dumps(
            {"agentType": "general-purpose", "description": "MCP-ROUTE-BOUND: bounded request route",
             "model": "sonnet"}))
        session = watch.claude_session(path, keep=3)
        self.assertEqual((session.id, session.parent, session.label), ("a1", "S1",
                                                                      "MCP-ROUTE-BOUND: bounded request route"))
        self.assertEqual(session.actions, ["02:53 Grep: fn seal"])

    def test_codex_child_agent_shows_nickname_commands_and_rate_limit(self):
        path = jsonl(self.home / ".codex/sessions/2026/10/08/rollout-x-T2.jsonl", CODEX_SUB)
        session = watch.codex_session(path, keep=6)
        self.assertEqual((session.vendor, session.id, session.parent), ("codex", "T2", "T1"))
        self.assertEqual(session.label, "Pauli /root/kani_final_delta_review")
        self.assertEqual(session.model, "gpt-6.1-sol")
        self.assertEqual(session.actions, [
            '02:41 exec: cargo kani -p chio-kernel --harness "seal"',
            "02:42 send_message -> /root: (encrypted)",
            "02:43 /root -> /root/kani_final_delta_review: Re-run the seal harness with the patched encoder.",
            "02:43 /root -> /root/kani_final_delta_review: new task (encrypted)",
            "02:45 turn done: Seal harness passes.",
        ])
        self.assertEqual(session.note, "rate limit 43% of 300m")

    def test_only_the_tail_of_a_huge_transcript_is_read(self):
        path = self.home / "big.jsonl"
        with open(path, "w") as handle:
            handle.write(json.dumps({"type": "filler", "pad": "x" * 2_000_000}) + "\n")
            for record in CLAUDE_MAIN:
                handle.write(json.dumps(record) + "\n")
        lines = watch.tail_lines(path, max_bytes=4096)
        self.assertEqual([json.loads(line)["type"] for line in lines][-1], "system")
        self.assertTrue(all(line.startswith("{") and line.endswith("}") for line in lines))

    def test_recent_sessions_skip_idle_transcripts(self):
        fresh = jsonl(self.home / ".claude/projects/-arc/S1.jsonl", CLAUDE_MAIN)
        stale = jsonl(self.home / ".codex/sessions/2026/10/01/rollout-old-T9.jsonl", CODEX_SUB)
        old = time.time() - 7200
        os.utime(stale, (old, old))
        found = watch.recent_sessions(self.home, minutes=30, keep=3)
        self.assertEqual([s.id for s in found], ["S1"])
        self.assertLess(found[0].age_s, 60)
        self.assertTrue(fresh.exists())


class HostTest(SwarmCase):
    def test_agent_processes_with_elapsed_time(self):
        found = watch.parse_ps(PS)
        self.assertEqual([(p["vendor"], p["pid"]) for p in found],
                         [("codex", 3850933), ("claude", 3851521), ("codex", 3851695)])
        self.assertEqual(found[2]["elapsed_s"], 86400 + 3 * 3600 + 41 * 60 + 44)

    def test_build_slots_name_their_holder_while_running(self):
        probe = ("import pathlib, os; d = pathlib.Path(os.environ['SWARM_BUILD_DIR']); "
                 "print([p.read_text() for p in sorted(d.glob('slot-*.lock')) if p.read_text()])")
        log = self.tmp / "probe.log"
        with unittest.mock.patch.dict(os.environ, {"SWARM_BUILD_CGROUP": "0", "SWARM_BUILD_DISK_FLOOR_GB": "0",
                                                   "SWARM_AGENT": "claude-ws2-worker1"}):
            build.run([sys.executable, "-c", probe], item="F1", cwd=self.tmp, log_path=log)
        holder = json.loads(eval(log.read_text())[0])  # the list printed by the probe
        self.assertEqual((holder["item"], holder["agent"], holder["class"]), ("F1", "claude-ws2-worker1", "coder"))
        self.assertIn("-c", holder["command"])
        self.assertEqual(watch.slot_status(build.slot_dir())["holders"], [])  # cleared on release

    def test_slot_status_ignores_records_of_dead_processes(self):
        folder = self.tmp / "slots"
        folder.mkdir()
        dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True,
                              text=True).stdout.strip()
        record = {"item": "F1", "agent": "a", "class": "coder", "command": "cargo test", "started": "2026-10-09T02:00:00Z"}
        (folder / "slot-1.lock").write_text(json.dumps({**record, "pid": os.getpid()}))
        (folder / "slot-2.lock").write_text(json.dumps({**record, "pid": int(dead)}))
        (folder / "slot-3.lock").write_text("")
        (folder / f"wait-{os.getpid()}.json").write_text(json.dumps({**record, "pid": os.getpid(), "item": "F2"}))
        (folder / f"wait-{dead}.json").write_text(json.dumps({**record, "pid": int(dead), "item": "F3"}))
        status = watch.slot_status(folder)
        self.assertEqual([(h["slot"], h["item"]) for h in status["holders"]], [(1, "F1")])
        self.assertEqual([w["item"] for w in status["waiting"]], ["F2"])

    def test_mailbox_files_show_their_latest_entries(self):
        box = self.tmp / "to-claude.md"
        box.write_text("# Mailbox\n\n## 2026-10-09T00:51:29Z claude\n\nTo the planner: capacity.\n\n"
                       "## 2026-10-09T00:54:42Z codex rulings and capacity\n\n- Read through your entry.\n")
        boxes = watch.mailboxes([box, self.tmp / "missing.md"], keep=1)
        self.assertEqual(boxes, [{"file": "to-claude.md",
                                  "entries": ["2026-10-09T00:54:42Z codex rulings and capacity: - Read through your entry."]}])


class RedactTest(unittest.TestCase):
    def test_credentials_are_redacted_everywhere_in_a_snapshot(self):
        token = "ghp_" + "a" * 36
        snap = {"sessions": [{"actions": [f"02:00 Bash: GH_TOKEN={token} gh pr list"]}], "note": f"sk-{'b' * 24}"}
        clean = secrets.redact_obj(snap)
        self.assertNotIn(token, json.dumps(clean))
        self.assertNotIn("sk-" + "b" * 24, json.dumps(clean))
        self.assertIn("gh pr list", clean["sessions"][0]["actions"][0])


def sample_snapshot(host="ws2"):
    return {
        "host": host, "hostname": f"{host}-box", "taken": "2026-10-09T03:00:00Z",
        "stats": {"load": [16.2, 15.7, 11.6], "cpus": 48, "mem_free_gb": 116.0, "disk_free_gb": 405.0},
        "slots": {"count": 8, "jobs": 6, "holders": [
            {"slot": 0, "item": "train", "agent": "codex-ws2-integrator", "class": "integrator",
             "command": "cargo check --workspace", "age_s": 300},
            {"slot": 5, "item": "", "agent": "", "class": "coder", "cwd": "/home/ubuntu/lanes/claude-hammer-arch-args",
             "command": "cargo test -p chio-store-sqlite", "age_s": 25}],
            "waiting": [{"item": "F9", "agent": "a", "class": "coder", "command": "cargo test", "age_s": 60}]},
        "processes": [{"vendor": "claude", "pid": 1, "elapsed_s": 100, "args": "claude"},
                      {"vendor": "codex", "pid": 2, "elapsed_s": 100, "args": "codex"},
                      {"vendor": "codex", "pid": 3, "elapsed_s": 100, "args": "codex app-server"}],
        "tmux": ["swarm-codex-ws2-worker1"],
        "mailboxes": [{"file": "to-claude.md", "entries": ["2026-10-09T00:54:42Z codex rulings: - Read it."]}],
        "sessions": [
            {"vendor": "claude", "id": "S1", "label": "Workstation continuity", "cwd": "/home/connor/backbay/arc",
             "model": "claude-opus-5-5", "parent": "", "age_s": 5, "note": "2 background agents",
             "actions": [f"02:5{i} Bash: step {i}" for i in range(6)]},
            {"vendor": "claude", "id": "a1", "label": "MCP-ROUTE-BOUND", "cwd": "/home/connor/backbay/arc",
             "model": "sonnet", "parent": "S1", "age_s": 20, "note": "", "actions": ["02:53 Grep: fn seal"]},
            {"vendor": "codex", "id": "T2", "label": "Pauli /root/kani", "cwd": "/home/connor/backbay/arc",
             "model": "gpt-6.1-sol", "parent": "T1", "age_s": 90, "note": "rate limit 43% of 300m",
             "actions": ["02:41 exec: cargo kani -p chio-kernel"]},
        ],
    }


class RenderTest(unittest.TestCase):
    def test_overview_shows_hosts_builds_agents_and_the_store(self):
        summary = {"items": {"in-progress": 3, "submitted": 1}, "claims": [
            {"item": "F1", "owner": "codex-ws2-worker1", "age_s": 120}],
            "messages": [{"from": "codex", "to": "conductor", "subject": "F1 blocked", "age_s": 30}]}
        text = watch.render([sample_snapshot(), {"host": "builder", "error": "ssh: connect timed out"}], summary,
                            now=NOW, width=200)
        self.assertIn("ws2 (ws2-box)  load 16.2/48  mem 116 GB free  disk 405 GB free", text)
        self.assertIn("slot 0  integrator  codex-ws2-integrator  train  5m  cargo check --workspace", text)
        self.assertIn("queue 1", text)
        self.assertIn("slot 5  coder  -  claude-hammer-arch-args  25s  cargo test -p chio-store-sqlite", text)
        self.assertIn("claude 1, codex 2", text)
        self.assertIn("to-claude.md  2026-10-09T00:54:42Z codex rulings: - Read it.", text)
        self.assertIn("claude  Workstation continuity  claude-opus-5-5  5s ago  2 background agents", text)
        self.assertIn("02:55 Bash: step 5", text)
        self.assertNotIn("02:52 Bash: step 2", text)  # three actions per session in the overview
        self.assertIn("  sub  MCP-ROUTE-BOUND  sonnet  20s ago", text)
        self.assertIn("codex  Pauli /root/kani  gpt-6.1-sol  1m ago  rate limit 43% of 300m", text)
        self.assertIn("builder  unreachable: ssh: connect timed out", text)
        self.assertIn("items  in-progress 3, submitted 1", text)
        self.assertIn("F1 codex-ws2-worker1 2m", text)
        self.assertIn("codex -> conductor: F1 blocked (30s ago)", text)

    def test_agent_filter_zooms_into_matching_sessions(self):
        text = watch.render([sample_snapshot()], None, now=NOW, width=200, agent="continuity")
        self.assertIn("02:52 Bash: step 2", text)  # more history when zoomed in
        self.assertNotIn("Pauli", text)
        self.assertNotIn("MCP-ROUTE-BOUND", text)

    def test_lines_fit_the_terminal(self):
        text = watch.render([sample_snapshot()], None, now=NOW, width=60)
        self.assertTrue(all(len(line) <= 60 for line in text.splitlines()))


class GatherTest(unittest.TestCase):
    def test_hosts_are_gathered_in_parallel_and_failures_are_reported(self):
        def runner(command, timeout):
            host = command[command.index("BatchMode=yes") + 3]
            if host == "builder":
                return subprocess.CompletedProcess(command, 255, "", "ssh: connect timed out")
            return subprocess.CompletedProcess(command, 0, json.dumps(sample_snapshot(host)), "")

        snaps = watch.gather(["local", "ws2", "builder"], local=lambda: {"host": "local"}, runner=runner,
                             minutes=30, keep=3)
        self.assertEqual([s["host"] for s in snaps], ["local", "ws2", "builder"])
        self.assertEqual(snaps[2]["error"], "ssh: connect timed out")

    def test_the_remote_command_reruns_the_snapshot_with_the_hosts_env(self):
        command = watch.remote_snapshot_command("ws2", minutes=30, keep=3)
        self.assertEqual(command[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "ws2"])
        self.assertTrue(command[6].endswith("~/.local/bin/swarm watch --snapshot --minutes 30 --keep 3"))


class StoreSummaryTest(SwarmCase):
    def test_summary_counts_items_and_lists_claims_and_recent_messages(self):
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        worker = self.clone("codex-ws2-worker1")
        self.add_item(conductor, "F1")
        self.add_item(conductor, "F2")
        from swarmlib import claims, lifecycle
        claims.claim(worker, "F1", [])
        lifecycle.status(worker, "F1", "in-progress")
        msgs.send(worker, "conductor", "fyi", "F1", "starting F1", "body")
        summary = watch.store_summary(conductor)
        self.assertEqual(summary["items"], {"in-progress": 1, "open": 1})
        self.assertEqual([(c["item"], c["owner"]) for c in summary["claims"]], [("F1", "codex-ws2-worker1")])
        self.assertEqual([(m["from"], m["to"], m["subject"]) for m in summary["messages"]],
                         [("codex-ws2-worker1", "conductor", "starting F1")])


class WatchCLITest(SwarmCase):
    def run_cli(self, store, *args, home):
        env = {**os.environ, "SWARM_HOME": str(store.root), "SWARM_AGENT": store.agent, "SWARM_ROLE": store.role,
               "SWARM_VENDOR": store.vendor, "HOME": str(home), "SWARM_WATCH_HOSTS": ""}
        return subprocess.run([sys.executable, str(BIN), *args], env=env, capture_output=True, text=True)

    def test_snapshot_prints_json_and_once_prints_the_view(self):
        home = self.tmp / "home"
        jsonl(home / ".claude/projects/-arc/S1.jsonl", CLAUDE_MAIN)
        conductor = self.clone("claude-ws2-conductor", role="conductor", vendor="claude")
        snap = self.run_cli(conductor, "watch", "--snapshot", home=home)
        self.assertEqual(snap.returncode, 0, snap.stderr)
        data = json.loads(snap.stdout)
        self.assertEqual([s["id"] for s in data["sessions"]], ["S1"])
        view = self.run_cli(conductor, "watch", "--once", home=home)
        self.assertEqual(view.returncode, 0, view.stderr)
        self.assertIn("swarm watch", view.stdout)
        self.assertIn("Codex multiagent workstation continuity", view.stdout)
        self.assertIn("items", view.stdout)


if __name__ == "__main__":
    unittest.main()
