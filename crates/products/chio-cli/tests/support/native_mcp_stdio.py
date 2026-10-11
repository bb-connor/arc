"""Single-threaded timing and input for confined native MCP test servers.

The selected native profile permits poll and monotonic clock reads. It does not
grant thread creation or clock_nanosleep. Keep delayed protocol behavior inside
one event loop and leave the production syscall profile unchanged.
"""

import math
import os
import select
import time


class NativeStdio:
    def __init__(self, input_fd=0):
        self.input_fd = input_fd
        self.input_poll = select.poll()
        self.input_poll.register(input_fd, select.POLLIN)
        self.timer_poll = select.poll()
        self.buffer = b""
        self.eof = False
        self.pending = []
        self.sequence = 0

    def schedule(self, delay, callback):
        if not math.isfinite(delay) or delay < 0:
            raise ValueError("fixture delay must be finite and nonnegative")
        self.sequence += 1
        self.pending.append((time.monotonic() + delay, self.sequence, callback))
        self.pending.sort(key=lambda item: item[:2])

    def _run_ready(self):
        while self.pending and self.pending[0][0] <= time.monotonic():
            _, _, callback = self.pending.pop(0)
            callback()

    def _timeout(self, deadline=None):
        if self.pending:
            next_due = self.pending[0][0]
            deadline = min(deadline, next_due) if deadline is not None else next_due
        if deadline is None:
            return None
        return max(0, math.ceil((deadline - time.monotonic()) * 1000))

    def sleep(self, delay):
        if not math.isfinite(delay) or delay < 0:
            raise ValueError("fixture delay must be finite and nonnegative")
        deadline = time.monotonic() + delay
        while True:
            self._run_ready()
            if time.monotonic() >= deadline:
                return
            self.timer_poll.poll(self._timeout(deadline))

    def readline(self):
        while True:
            self._run_ready()
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                return (line + b"\n").decode("utf-8")
            if self.eof:
                line, self.buffer = self.buffer, b""
                return line.decode("utf-8")
            if self.input_poll.poll(self._timeout()):
                chunk = os.read(self.input_fd, 65536)
                self.eof = not chunk
                self.buffer += chunk

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line


native_io = NativeStdio()
