"""Bounded local control processes with no ambient Docker configuration."""

import os
import selectors
import subprocess
import tempfile
import time
from contextlib import contextmanager
from contextvars import ContextVar

DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
OPERATION_DEADLINE = ContextVar("repository_operation_deadline", default=None)


def check_deadline():
    deadline = OPERATION_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Repository operation exceeded its total deadline")


@contextmanager
def operation_budget(seconds):
    token = OPERATION_DEADLINE.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        OPERATION_DEADLINE.reset(token)


def run(
    arguments,
    *,
    data=None,
    limit=65536,
    timeout=30,
    allow_failure=False,
    cwd="/",
    environment=None,
    merge_output=False,
):
    check_deadline()
    deadline = time.monotonic() + timeout
    if OPERATION_DEADLINE.get() is not None:
        deadline = min(deadline, OPERATION_DEADLINE.get())
    with tempfile.TemporaryFile() as incoming:
        if data is not None:
            incoming.write(data)
        incoming.seek(0)
        check_deadline()
        with subprocess.Popen(
            arguments,
            stdin=incoming,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_output else subprocess.PIPE,
            cwd=cwd,
            env=environment or {"PATH": "/usr/bin:/bin"},
        ) as process:
            output, errors = bytearray(), bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, output)
                    if process.stderr is not None:
                        selector.register(process.stderr, selectors.EVENT_READ, errors)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not (events := selector.select(remaining)):
                            raise TimeoutError("Local repository operation exceeded its deadline")
                        for key, _ in events:
                            chunk = os.read(key.fileobj.fileno(), 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            key.data.extend(chunk)
                            if len(output) > limit or len(errors) > min(limit, 512 * 1024):
                                raise ValueError(
                                    "Local repository operation exceeded its output bound"
                                )
                returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                if returncode and not allow_failure:
                    raise RuntimeError("Local repository operation failed; preserve its state")
                return returncode, bytes(output), bytes(errors)
            except BaseException:
                process.kill()
                process.wait()
                raise


def docker(*arguments, **kwargs):
    return run([*DOCKER, *arguments], **kwargs)[1]
