"""Interrupted comparison cleanup must preserve unrelated processes and containers."""

import contextlib
import json
import os
import signal
import subprocess
import sys

import compare as comparison
import compare_cleanup as helper
import pytest

OWNER = "a" * 32
IMAGE = "sha256:" + "b" * 64
CONTAINER = "c" * 64
FOREIGN_CONTAINER = "d" * 64


def write_private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


@pytest.fixture(autouse=True)
def refuse_real_docker(monkeypatch):
    def unexpected(*arguments, **keywords):
        raise AssertionError("Cleanup tests must never invoke Docker")

    monkeypatch.setattr(helper, "docker", unexpected)


@pytest.fixture
def case(tmp_path):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    config_path = tmp_path / "config.json"
    config = {"output": str(output), "owner": OWNER, "image": IMAGE}
    write_private(config_path, config)
    return config_path, config, output


@contextlib.contextmanager
def sleeper(label):
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)", label],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def worker_control(case, process, **changes):
    config_path, config, output = case
    directory = output / "attempt-1"
    directory.mkdir(mode=0o700)
    identity = helper.process_identity(process.pid)
    record = {
        "config_path": str(config_path),
        **config,
        "uid": identity["uid"],
        "pid": process.pid,
        "start_ticks": identity["start_ticks"],
        "state": "running",
        **changes,
    }
    path = directory / "control.json"
    write_private(path, record)
    return path, [os.fsdecode(argument) for argument in identity["argv"]]


@pytest.mark.parametrize("mismatch", ["pid", "start_ticks", "argv", "uid"])
def test_unrelated_or_changed_worker_identity_is_preserved(case, monkeypatch, mismatch):
    config_path, config, _ = case
    with sleeper("owned") as owned, sleeper("unrelated") as unrelated:
        control, expected = worker_control(case, owned)
        record = json.loads(control.read_text())
        if mismatch == "pid":
            record["pid"] = unrelated.pid
        elif mismatch == "start_ticks":
            record["start_ticks"] += 1
        elif mismatch == "argv":
            expected = [*expected[:-1], "replacement-worker"]
        else:
            identity = helper.process_identity(owned.pid)
            monkeypatch.setattr(
                helper, "process_identity", lambda pid: {**identity, "uid": os.getuid() + 1}
            )
        write_private(control, record)
        with pytest.raises(ValueError, match="identity changed"):
            helper.terminate_attempt(control, config_path, config, expected)
        assert owned.poll() is None and unrelated.poll() is None


def test_owned_worker_uses_pidfd_and_preserves_another_live_child(case, monkeypatch):
    config_path, config, _ = case
    with sleeper("owned") as owned, sleeper("unrelated") as unrelated:
        control, expected = worker_control(case, owned)
        sent = []
        send = signal.pidfd_send_signal

        def signal_descriptor(descriptor, signum, *arguments):
            sent.append(signum)
            return send(descriptor, signum, *arguments)

        def refuse_numeric(*arguments):
            raise AssertionError("Cleanup must signal a pinned descriptor, never a numeric PID")

        with monkeypatch.context() as patch:
            patch.setattr(helper.signal, "pidfd_send_signal", signal_descriptor)
            patch.setattr(helper.os, "kill", refuse_numeric)
            patch.setattr(helper.os, "killpg", refuse_numeric)
            result = helper.terminate_attempt(control, config_path, config, expected)
        assert result == {"pid": owned.pid, "running": False}
        assert sent == [signal.SIGKILL]
        assert owned.wait(timeout=5) == -signal.SIGKILL
        assert unrelated.poll() is None


def test_exit_between_identity_check_and_signal_is_harmless(case, monkeypatch):
    config_path, config, _ = case
    with sleeper("owned") as owned, sleeper("unrelated") as unrelated:
        control, expected = worker_control(case, owned)
        identity = helper.process_identity(owned.pid)
        descriptor = os.pidfd_open(owned.pid)
        send = signal.pidfd_send_signal

        def exit_after_observation(pid):
            assert pid == owned.pid
            send(descriptor, signal.SIGKILL)
            owned.wait(timeout=5)
            return identity

        try:
            monkeypatch.setattr(helper, "process_identity", exit_after_observation)
            result = helper.terminate_attempt(control, config_path, config, expected)
        finally:
            os.close(descriptor)
        assert result == {"pid": owned.pid, "running": False}
        assert unrelated.poll() is None


def test_reaped_record_does_not_signal_a_replacement_process(case):
    config_path, config, _ = case
    with sleeper("unrelated") as unrelated:
        control, expected = worker_control(case, unrelated, state="reaped", start_ticks=0)
        assert helper.terminate_attempt(control, config_path, config, expected) == {
            "pid": unrelated.pid,
            "running": False,
        }
        assert unrelated.poll() is None


class Containers:
    """Only implement the Docker inspection and removal calls used by cleanup."""

    def __init__(self, records):
        self.records = {record["Id"]: record for record in records}
        self.removed = []

    def __call__(self, *arguments):
        if arguments[0] == "ps":
            selector = arguments[arguments.index("--filter") + 1]
            if selector.startswith("id="):
                found = [identifier for identifier in self.records if identifier == selector[3:]]
            else:
                prefix = "label=" + helper.LABEL + "="
                assert selector.startswith(prefix)
                owner = selector.removeprefix(prefix)
                found = [
                    identifier
                    for identifier, record in self.records.items()
                    if record["Config"]["Labels"].get(helper.LABEL) == owner
                ]
            return ("\n".join(found) + ("\n" if found else "")).encode()
        if arguments[0] == "inspect":
            assert len(arguments) == 2
            return json.dumps([self.records[arguments[1]]]).encode()
        assert arguments[:3] == ("rm", "--force", "--volumes")
        assert len(arguments) == 4
        self.removed.append(arguments[3])
        del self.records[arguments[3]]
        return b""


def container(identifier=CONTAINER, *, owner=OWNER, image=IMAGE):
    return {"Id": identifier, "Image": image, "Config": {"Labels": {helper.LABEL: owner}}}


def original_container(case):
    config_path, config, output = case
    write_private(
        output / "container-control.json",
        {"id": CONTAINER, "config_path": str(config_path), **config},
    )


@pytest.mark.parametrize("changed", ["label", "image"])
def test_changed_original_container_refuses_before_any_container_removal(
    case, monkeypatch, changed
):
    config_path, _, _ = case
    original_container(case)
    original = container(
        owner="e" * 32 if changed == "label" else OWNER,
        image="sha256:" + "f" * 64 if changed == "image" else IMAGE,
    )
    transport = Containers([original, container(FOREIGN_CONTAINER)])
    monkeypatch.setattr(helper, "docker", transport)
    with pytest.raises(ValueError, match="ownership changed"):
        helper.cleanup(config_path, [])
    assert transport.removed == []
    assert set(transport.records) == {CONTAINER, FOREIGN_CONTAINER}


def test_correct_owned_container_cleanup_preserves_unrelated_container(case, monkeypatch):
    config_path, _, _ = case
    original_container(case)
    transport = Containers([container(), container(FOREIGN_CONTAINER, owner="e" * 32)])
    monkeypatch.setattr(helper, "docker", transport)
    result = helper.cleanup(config_path, [])
    assert result == {"attempts": [], "removed_container_ids": [CONTAINER], "verified": True}
    assert transport.removed == [CONTAINER]
    assert set(transport.records) == {FOREIGN_CONTAINER}


def test_symlinked_worker_control_is_refused_before_cleanup(case):
    config_path, config, output = case
    with sleeper("owned") as owned:
        control, expected = worker_control(case, owned)
        retained = output / "original-control.json"
        control.rename(retained)
        control.symlink_to(retained)
        with pytest.raises(OSError):
            helper.terminate_attempt(control, config_path, config, expected)
        assert owned.poll() is None


@pytest.mark.parametrize("interrupt", ["keyboard", "timeout"])
def test_driver_is_reaped_before_fallback_and_original_interrupt_survives(
    tmp_path, monkeypatch, interrupt
):
    original = (
        KeyboardInterrupt("interrupted comparison")
        if interrupt == "keyboard"
        else subprocess.TimeoutExpired("comparison-driver", 1)
    )
    popen = subprocess.Popen
    events = []
    owned = []
    streams = []

    class InterruptedWait:
        def __init__(self, *arguments, **keywords):
            self.process = popen(*arguments, **keywords)
            owned.append(self.process)
            streams.extend([keywords["stdout"], keywords["stderr"]])
            self.interrupted = False

        def wait(self, timeout=None):
            events.append("wait")
            if not self.interrupted:
                self.interrupted = True
                assert self.process.poll() is None
                raise original
            return self.process.wait(timeout=timeout)

        def kill(self):
            events.append("kill")
            self.process.kill()

    monkeypatch.setattr(comparison.subprocess, "Popen", InterruptedWait)
    try:
        with pytest.raises(type(original)) as caught:
            try:
                comparison.command(
                    tmp_path,
                    "driver",
                    sys.executable,
                    "-c",
                    "import time; time.sleep(120)",
                    env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
                )
            except BaseException:
                # This is where the caller starts its resource fallback.
                events.append("fallback")
                assert owned[0].returncode == -signal.SIGKILL
                assert owned[0].poll() == -signal.SIGKILL
                raise
        assert caught.value is original
        assert events == ["wait", "kill", "wait", "fallback"]
        assert all(stream.closed for stream in streams)
    finally:
        for process in owned:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
