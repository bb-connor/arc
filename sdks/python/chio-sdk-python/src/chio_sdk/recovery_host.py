"""Bounded host transport. Every action still requires the native Rust owner."""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from concurrent.futures import Future
import re
from threading import Lock, Thread
from types import MappingProxyType
import httpx
from .recovery import RecoveryClient
from .recovery_errors import RecoveryError
from .recovery_host_outcome import RecoveryHostCategory, RecoveryHostOutcome


class RecoveryHostSession:
    """Carry selected native command bytes once per explicit framework action.

    This object contains no effect implementation or retry policy. A budget
    refusal cannot renew native authority. Checkpoints retain only as_dict().
    """
    def __init__(self, endpoint: str, capability: str, commands: Mapping[str, bytes], *,
                 max_tool_actions: int = 8, transport: httpx.AsyncBaseTransport | None = None,
                 timeout_seconds: int = 20):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("recovery.invalid_budget")
        if type(max_tool_actions) is not int or not 1 <= max_tool_actions <= 8:
            raise ValueError("recovery.invalid_budget")
        if not 1 <= len(commands) <= 8 or len(capability.encode("utf-8")) > 32768 or not capability:
            raise ValueError("recovery.invalid_host_binding")
        if not endpoint or len(endpoint.encode("utf-8")) > 2048:
            raise ValueError("recovery.invalid_endpoint")
        for choice, command in commands.items():
            if not isinstance(choice, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", choice):
                raise ValueError("recovery.invalid_choice")
            if not isinstance(command, bytes) or not 1 <= len(command) <= 32768:
                raise ValueError("recovery.invalid_command")
        self._endpoint = endpoint
        self._capability = capability
        self._commands = MappingProxyType(dict(commands))
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._budget = max_tool_actions
        self._attempts = 0
        self._lock = Lock()
        self._retained_tasks: set[asyncio.Task[None]] = set()
        self._active_action = False
        self._sync_worker_active = False

    def __repr__(self) -> str:
        return "RecoveryHostSession([redacted])"

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    def _retained_completed(self, task: asyncio.Task[None]) -> None:
        with self._lock:
            self._retained_tasks.discard(task)
        try:
            task.result()
        except (Exception, asyncio.CancelledError):
            # Late local task failures carry no framework diagnostics.
            pass

    def _retain(self, task: asyncio.Task[None]) -> None:
        with self._lock:
            self._retained_tasks.add(task)
        task.add_done_callback(self._retained_completed)

    @staticmethod
    async def _close_without_diagnostics(client: RecoveryClient) -> None:
        try:
            await client.aclose()
        except Exception:
            # Consume within the task. An external Runner can otherwise log
            # its retained exception again while shutting down the loop.
            pass

    async def _close_within_deadline(self, client: RecoveryClient, deadline: float) -> None:
        task = asyncio.create_task(self._close_without_diagnostics(client))
        # Keep a bounded number of strong references until cleanup completes.
        # A transport can delay cancellation; it cannot renew the action wait.
        self._retain(task)
        try:
            remaining = max(0, deadline - asyncio.get_running_loop().time())
            await asyncio.wait({task}, timeout=remaining)
        finally:
            if not task.done():
                task.cancel()

    def _admit(self, choice: str, *, synchronous: bool) -> RecoveryHostOutcome | None:
        with self._lock:
            if self._attempts >= self._budget:
                return RecoveryHostOutcome(RecoveryHostCategory.BUDGET_EXHAUSTED)
            self._attempts += 1
            if not isinstance(choice, str) or choice not in self._commands:
                return RecoveryHostOutcome(RecoveryHostCategory.INVALID_CHOICE)
            # Completion callbacks can be queued after the next explicit action.
            # Only unfinished native requests or cleanup retain admission.
            self._retained_tasks = {task for task in self._retained_tasks if not task.done()}
            if self._active_action or self._sync_worker_active or self._retained_tasks:
                return RecoveryHostOutcome(RecoveryHostCategory.BUSY)
            self._active_action = True
            if synchronous:
                self._sync_worker_active = True
        return None

    async def execute(self, choice: str) -> RecoveryHostOutcome:
        refusal = self._admit(choice, synchronous=False)
        if refusal is not None:
            return refusal
        try:
            return await self._execute_admitted(choice)
        finally:
            with self._lock:
                self._active_action = False

    def execute_sync(self, choice: str) -> RecoveryHostOutcome:
        """Deliver from a private loop while its cleanup retains session admission.

        Caller interruption does not start a retry or abandon the admitted call.
        Its worker continues to own the call and cleanup until they finish.
        """
        refusal = self._admit(choice, synchronous=True)
        if refusal is not None:
            return refusal
        delivery: Future[RecoveryHostOutcome] = Future()
        worker = Thread(target=self._run_sync_worker, args=(choice, delivery),
                        name="chio-recovery", daemon=True)
        try:
            worker.start()
        except RuntimeError:
            with self._lock:
                self._active_action = False
                self._sync_worker_active = False
            return RecoveryHostOutcome(RecoveryHostCategory.UNAVAILABLE)
        return delivery.result()

    def _run_sync_worker(self, choice: str, delivery: Future[RecoveryHostOutcome]) -> None:
        async def deliver_then_drain() -> None:
            outcome = await self._execute_admitted(choice)
            delivery.set_result(outcome)
            # A late request can create its close task after delivery. Drain
            # every owned generation before Runner shutdown releases admission.
            while True:
                with self._lock:
                    retained = tuple(self._retained_tasks)
                if not retained:
                    break
                await asyncio.gather(*retained, return_exceptions=True)

        try:
            asyncio.run(deliver_then_drain())
        except BaseException:
            # A private worker never projects exception text to a framework.
            if not delivery.done():
                delivery.set_result(RecoveryHostOutcome(RecoveryHostCategory.UNAVAILABLE))
        finally:
            with self._lock:
                self._active_action = False
                self._sync_worker_active = False

    async def _execute_admitted(self, choice: str) -> RecoveryHostOutcome:
        deadline = asyncio.get_running_loop().time() + self._timeout_seconds
        delivery: asyncio.Future[RecoveryHostOutcome] = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(self._execute_native(choice, deadline, delivery))
        self._retain(task)
        try:
            remaining = max(0, deadline - asyncio.get_running_loop().time())
            await asyncio.wait({task}, timeout=remaining)
            if delivery.done() and not delivery.cancelled():
                # A received native result survives unfinished local cleanup.
                return delivery.result()
            # The native owner must reconcile the original command. A late
            # result cannot replace this delivery or authorize another request.
            return RecoveryHostOutcome(RecoveryHostCategory.UNAVAILABLE)
        finally:
            if not delivery.done():
                delivery.cancel()
                # Delivery and cancellation never wait for a resistant transport.
                # Retained ownership keeps subsequent session actions busy.
                if not task.done():
                    task.cancel()

    async def _execute_native(self, choice: str, deadline: float,
                              delivery: asyncio.Future[RecoveryHostOutcome]) -> None:
        client = None
        outcome = RecoveryHostOutcome(RecoveryHostCategory.REFUSED)
        try:
            if asyncio.get_running_loop().time() >= deadline:
                outcome = RecoveryHostOutcome(RecoveryHostCategory.UNAVAILABLE)
                return
            # A per-action client also supports CrewAI's independent event loops.
            # No cached result can bypass fresh authorization on replay.
            client = RecoveryClient(self._endpoint, transport=self._transport, timeout_seconds=self._timeout_seconds)
            response = await client.execute(self._capability, self._commands[choice])
            outcome = RecoveryHostOutcome.from_status(response.status)
        except TimeoutError:
            outcome = RecoveryHostOutcome(RecoveryHostCategory.UNAVAILABLE)
        except RecoveryError as error:
            outcome = RecoveryHostOutcome.from_error(error)
        except Exception:
            # SDK/network/provider errors may carry secrets. Frameworks receive
            # a fixed category, never exception text or an original response.
            outcome = RecoveryHostOutcome(RecoveryHostCategory.REFUSED)
        finally:
            if not delivery.done():
                delivery.set_result(outcome)
            if client is not None:
                # Cleanup shares the original deadline. It cannot renew the
                # action budget or erase an already received native result.
                await self._close_within_deadline(client, deadline)
