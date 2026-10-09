"""Own one fixture process group, its bounded shutdown, and its diagnostic log."""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import signal
import subprocess
import time


class NativeProcessCleanupError(RuntimeError):
    """Fixed cleanup categories; never includes process arguments or environment."""


def _timeouts(*values: float) -> tuple[float, ...]:
    try:
        if any(type(value) not in (int, float) for value in values):
            raise ValueError
        converted = tuple(float(value) for value in values)
        if any(not math.isfinite(value) or value <= 0 for value in converted):
            raise ValueError
        if not math.isfinite(sum(converted)):
            raise ValueError
        return converted
    except (ValueError, OverflowError):
        raise ValueError("native_cleanup.timeout") from None


def _wait_group(process: subprocess.Popen, deadline: float, errors: list[str]) -> bool:
    """Reap the direct child while waiting for its owned descendants to exit."""
    while True:
        try:
            if process.poll() is not None:
                # A running leader already proves the group is alive. Probe for
                # remaining descendants only after that leader has been reaped.
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    return True
        except BaseException:
            errors.append("native_cleanup.observe_failed")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.02, remaining))
        except BaseException:
            errors.append("native_cleanup.wait_interrupted")
            return False


def _signal_group(process: subprocess.Popen, number: int, errors: list[str], reason: str) -> None:
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass
    except BaseException:
        errors.append(reason)


class NativeProcessOwner:
    """One launched process/log and one retained shutdown result."""

    def __init__(self, process, log, finish_path, timeouts, errors):
        self.process = process
        self.log = log
        self._finish_path = finish_path
        self._timeouts = timeouts
        self._errors = errors
        self._deadlines = None
        self._result = None

    def finish(self) -> int:
        """Publish finish and complete shutdown once; repeated calls reuse its result."""
        if self._result is None:
            # Refuse retries if an unexpected interruption escapes the operation.
            self._result = NativeProcessCleanupError("native_cleanup.unresolved")
            self._shutdown()
            if self._errors:
                self._result = NativeProcessCleanupError("; ".join(dict.fromkeys(self._errors)))
            else:
                self._result = self.process.returncode
        if isinstance(self._result, NativeProcessCleanupError):
            raise self._result
        return self._result

    def _shutdown(self) -> None:
        # One absolute budget, started by either the body or the finalizer.
        started = None
        try:
            started = time.monotonic()
        except BaseException:
            self._errors.append("native_cleanup.clock_failed")
        # Publication is independent of clock availability.
        try:
            self._finish_path.touch()
        except BaseException:
            self._errors.append("native_cleanup.finish_publication_failed")
        if started is None:
            # Stop the owned group now if the cleanup clock is unavailable.
            # Direct-child reaping is bounded; descendant observation is unresolved.
            _signal_group(self.process, signal.SIGKILL, self._errors, "native_cleanup.kill_failed")
            try:
                self.process.wait(timeout=self._timeouts[2])
            except BaseException:
                self._errors.append("native_cleanup.reap_failed")
            self._errors.append("native_cleanup.unresolved")
            return
        graceful = started + self._timeouts[0]
        terminated = graceful + self._timeouts[1]
        killed = terminated + self._timeouts[2]
        self._deadlines = (graceful, terminated, killed)
        if _wait_group(self.process, graceful, self._errors):
            return
        self._errors.append("native_cleanup.forced_termination")
        _signal_group(self.process, signal.SIGTERM, self._errors, "native_cleanup.terminate_failed")
        if _wait_group(self.process, terminated, self._errors):
            return
        _signal_group(self.process, signal.SIGKILL, self._errors, "native_cleanup.kill_failed")
        if not _wait_group(self.process, killed, self._errors):
            self._errors.append("native_cleanup.unresolved")


@contextmanager
def owned_native_process(command: list[str], *, cwd: Path, env: dict[str, str],
                         log_path: Path, finish_path: Path, grace_seconds: float,
                         terminate_seconds: float = 5, kill_seconds: float = 5):
    """Launch only an owned new POSIX session and close it before the next trial.

    A primary fixture failure remains the raised exception. Cleanup trouble is
    attached as fixed diagnostic notes; without a primary failure it is fatal.
    Forced termination also refuses success, even if all children are reaped.
    """
    timeouts = _timeouts(grace_seconds, terminate_seconds, kill_seconds)
    if os.name != "posix":
        raise ValueError("native_cleanup.posix_required")
    log = log_path.open("wb")
    owner = None
    primary = None
    errors: list[str] = []
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        owner = NativeProcessOwner(process, log, finish_path, timeouts, errors)
        yield owner
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if owner is not None:
                try:
                    owner.finish()
                except NativeProcessCleanupError:
                    # A retained interrupted result is fatal even when the body
                    # caught its first exception before diagnostics were populated.
                    if not errors:
                        errors.append("native_cleanup.unresolved")
                except BaseException:
                    errors.append("native_cleanup.unresolved")
        finally:
            try:
                log.close()
            except BaseException:
                errors.append("native_cleanup.log_close_failed")
            if errors:
                diagnostic = "; ".join(dict.fromkeys(errors))
                if primary is not None:
                    if str(primary) != diagnostic:
                        primary.add_note(diagnostic)
                else:
                    raise NativeProcessCleanupError(diagnostic) from None
