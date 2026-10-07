"""Competent explicit application supervisor over the same native authorities.

Stable Rust-owned IDs, provider idempotency and authoritative outcome recovery
are supplied by the same native recovery/durable knowledge native owner in both arms. This deliberately
compares integration mechanisms; it cannot establish a security advantage over
an independent runtime. No separate retry or authority engine is implemented.
"""
import asyncio
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from threading import Lock, Thread
from chio_sdk.recovery import RecoveryClient
from chio_sdk.recovery_host import RecoveryHostCategory, RecoveryHostOutcome
from chio_sdk.recovery_errors import RecoveryError, RecoveryErrorCode

EFFECT_CATEGORIES = {
    "complete":"complete", "partial":"completed_with_effects", "failed_after_effect":"completed_with_effects",
    "awaiting_approval":"waiting_for_approval", "in_flight":"waiting_for_outcome",
    "awaiting_caller_report":"waiting_for_outcome", "unknown":"reconciliation_required",
    "admission_unresolved":"reconciliation_required", "never_admitted":"closed_without_effect",
    "closed_before_effect":"closed_without_effect",
}
ERROR_CATEGORIES = {
    RecoveryErrorCode.UNKNOWN_EFFECT:"reconciliation_required", RecoveryErrorCode.UNAVAILABLE:"unavailable",
    RecoveryErrorCode.RESTART_REQUIRED:"restart_required", RecoveryErrorCode.CONFLICT:"conflict",
    RecoveryErrorCode.UNSUPPORTED_PROFILE:"unsupported_profile", RecoveryErrorCode.UNCOVERED_MEDIATION:"uncovered_mediation",
    RecoveryErrorCode.PROBE_EXPIRED:"probe_expired", RecoveryErrorCode.ORIGIN_REFUSED:"origin_refused",
    RecoveryErrorCode.BUSY:"busy", RecoveryErrorCode.PROJECTION_TOO_LARGE:"projection_too_large",
}


class SupervisorSession:
    def __init__(self, endpoint, capability, command, *, transport=None, timeout_seconds=120):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("recovery.invalid_budget")
        self._endpoint = endpoint
        self._capability = capability
        self._command = command
        self._transport = transport
        self._lock = Lock()
        self._attempts = 0
        self._timeout_seconds = timeout_seconds
        self._active = False
        self._cleanup_tasks = set()

    def __repr__(self): return "SupervisorSession([redacted])"

    @property
    def attempts(self):
        with self._lock:
            return self._attempts

    def _admit(self, choice):
        with self._lock:
            if self._attempts >= 8:
                return RecoveryHostOutcome("budget_exhausted")
            self._attempts += 1
            if type(choice) is not str or choice != "resume":
                return RecoveryHostOutcome("invalid_choice")
            if self._active or self._cleanup_tasks:
                return RecoveryHostOutcome("busy")
            self._active = True
        return None

    async def execute(self, choice):
        refusal = self._admit(choice)
        if refusal is not None:
            return refusal
        try:
            return await self._execute_admitted()
        finally:
            with self._lock:
                self._active = False

    def execute_sync(self, choice):
        """Bridge the same admitted operation, retaining its private cleanup."""
        refusal = self._admit(choice)
        if refusal is not None:
            return refusal
        delivery = Future()
        received = Future()
        worker = Thread(target=self._run_sync_worker, args=(delivery, received), name="chio-baseline", daemon=True)
        try:
            worker.start()
        except RuntimeError:
            with self._lock:
                self._active = False
            return RecoveryHostOutcome("unavailable")
        try:
            return delivery.result(timeout=self._timeout_seconds)
        except FutureTimeoutError:
            # Retain admission until the owned call and cleanup actually finish.
            return received.result() if received.done() else RecoveryHostOutcome("unavailable")

    def _run_sync_worker(self, delivery, received):
        async def execute_then_drain():
            outcome = await self._execute_admitted(received)
            with self._lock:
                cleanup = tuple(task for task in self._cleanup_tasks if not task.done())
            if cleanup:
                await asyncio.gather(*cleanup, return_exceptions=True)
            return outcome
        outcome = RecoveryHostOutcome("unavailable")
        try:
            outcome = asyncio.run(execute_then_drain())
        except BaseException:
            if received.done():
                outcome = received.result()
        finally:
            with self._lock:
                self._active = False
        delivery.set_result(outcome)

    def _cleanup_completed(self, task):
        with self._lock:
            self._cleanup_tasks.discard(task)
        try:
            task.result()
        except (Exception, asyncio.CancelledError):
            pass

    async def _close_within_deadline(self, client, deadline):
        async def close():
            try:
                await client.aclose()
            except Exception:
                pass
        pending = close()
        try:
            task = asyncio.create_task(pending)
        except Exception:
            pending.close()
            return
        with self._lock:
            self._cleanup_tasks.add(task)
        task.add_done_callback(self._cleanup_completed)
        try:
            await asyncio.wait({task}, timeout=max(0, deadline - asyncio.get_running_loop().time()))
        finally:
            if not task.done():
                task.cancel()

    async def _execute_admitted(self, received=None):
        client = None
        outcome = RecoveryHostOutcome("refused")
        deadline = asyncio.get_running_loop().time() + self._timeout_seconds
        try:
            async with asyncio.timeout_at(deadline):
                client = RecoveryClient(self._endpoint, transport=self._transport, timeout_seconds=self._timeout_seconds)
                response = await client.execute(self._capability, self._command)
            status = response.status.model_dump(mode="json", by_alias=True)
            if status["control"] != "active":
                category = RecoveryHostCategory(status["control"])
            elif status["release"]["kind"] in {"withheld", "denied"}:
                category = RecoveryHostCategory.WITHHELD
            else:
                category = RecoveryHostCategory(EFFECT_CATEGORIES[status["effect"]["kind"]])
            outcome = RecoveryHostOutcome(category, status["command_id"], status["workflow_id"])
        except TimeoutError:
            outcome = RecoveryHostOutcome("unavailable")
        except RecoveryError as error:
            outcome = RecoveryHostOutcome(ERROR_CATEGORIES.get(error.code, "refused"))
        except Exception:
            outcome = RecoveryHostOutcome("refused")
        finally:
            if received is not None:
                received.set_result(outcome)
            if client is not None:
                try:
                    await self._close_within_deadline(client, deadline)
                except Exception:
                    pass
        return outcome
