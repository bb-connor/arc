"""Checkpoint hooks around upstream DefaultAgent's existing control loop."""

import json

from minisweagent import __version__
from minisweagent.agents.default import DefaultAgent
from minisweagent.exceptions import InterruptAgentFlow

from chio_mini_swe.environment import ChioEnvironment
from chio_mini_swe.state import SCHEMA, Journal, digest, encode


class ChioAgent(DefaultAgent):
    """Resume one task on one Chio process; create a fresh instance per attempt.

    The upstream run loop owns limits, model formatting, action ordering and
    completion. An incomplete provider response stops recovery. A completed
    response is durable before its first command. Command replay uses the
    original turn and action ordinal, including repeated identical commands.
    """

    def __init__(self, model, env: ChioEnvironment, *, run_id: str, model_id: str, **kwargs):
        if __version__ != "2.4.6":
            raise RuntimeError("This adapter requires mini-SWE-agent 2.4.6")
        if not isinstance(env, ChioEnvironment) or any(
            not isinstance(value, str) or not value.strip() or len(value.encode()) > 1024
            for value in (run_id, model_id)
        ):
            raise ValueError("A Chio environment and stable run/model identities are required")
        super().__init__(model, env, **kwargs)
        self.run_id = run_id
        self.model_id = model_id
        self.journal = Journal(env.client)
        self._restored = False
        self._failed = False
        self._phase = "ready"
        self._binding: str | None = None
        self._started = False

    def run(self, task: str = "", **kwargs):
        if self._started:
            raise RuntimeError("Create a fresh ChioAgent for each run attempt")
        self._started = True
        return super().run(task, **kwargs)

    def _restore(self):
        config = self.config.model_dump(mode="json", exclude={"output_path"})
        self._binding = digest(
            [
                SCHEMA,
                self.run_id,
                self.model_id,
                config,
                self.extra_template_vars,
                self.env.server_id,
                self.env.tool_name,
                self.env.config,
            ]
        )
        saved = self.journal.read()
        if saved is not None:
            if saved.get("binding") != self._binding:
                raise RuntimeError("mini-SWE task or configuration changed on resume")
            phase = saved.get("phase")
            if phase not in {"ready", "tools", "model_pending"}:
                raise RuntimeError("Invalid mini-SWE checkpoint phase")
            self.messages = saved["messages"]
            self.n_calls = saved["n_calls"]
            self.cost = saved["cost"]
            self.n_consecutive_format_errors = saved["n_consecutive_format_errors"]
            self._start_time = saved["start_time"]
            self.env.receipts = saved["receipts"]
            self._phase = phase
        self._restored = True

    def _persist(self, phase: str):
        self.journal.write(
            {
                "schema": SCHEMA,
                "binding": self._binding,
                "phase": phase,
                "messages": self.messages,
                "n_calls": self.n_calls,
                "cost": self.cost,
                "n_consecutive_format_errors": self.n_consecutive_format_errors,
                "start_time": self._start_time,
                "receipts": self.env.receipts,
            }
        )
        self._phase = phase

    def step(self):
        try:
            return self._step()
        except InterruptAgentFlow:
            raise
        except BaseException:
            # Upstream saves in finally, including KeyboardInterrupt/SystemExit.
            # Such an exit must retain the last durable pending operation.
            self._failed = True
            raise

    def _step(self):
        if not self._restored:
            self._restore()
        if self._phase == "model_pending":
            raise RuntimeError("Provider response is unknown; automatic regeneration is refused")
        if self._phase == "tools":
            # CAS also fences an attempt that loaded state before another writer.
            self._persist("tools")
            return self.execute_actions(self.messages[-1])
        if self.messages and self.messages[-1].get("role") == "exit":
            raise InterruptAgentFlow()
        return super().step()

    def query(self):
        self._persist("model_pending")
        message = super().query()
        self._persist("tools")
        return message

    def execute_actions(self, message: dict):
        actions = message.get("extra", {}).get("actions", [])
        if not isinstance(actions, list) or len(actions) > 64:
            raise RuntimeError("Invalid mini-SWE action batch")
        self.env.bind(self.run_id, self.n_calls, actions)
        try:
            return super().execute_actions(message)
        finally:
            self.env.unbind()

    def handle_uncaught_exception(self, error):
        self._failed = True
        return super().handle_uncaught_exception(error)

    def save(self, path, *extra_dicts):
        if self._restored and not self._failed:
            self._persist("ready")
        return super().save(path, *extra_dicts)

    def serialize(self, *extra_dicts):
        return super().serialize(
            {
                "info": {
                    "chio": {
                        "run_id": self.run_id,
                        "receipts": json.loads(encode(self.env.receipts)),
                    }
                }
            },
            *extra_dicts,
        )
