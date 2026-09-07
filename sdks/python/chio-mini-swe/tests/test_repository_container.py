import pytest
from chio_mini_swe import repository_container as container


@pytest.fixture
def execution(monkeypatch):
    calls = []
    state = {
        "Status": "exited",
        "Running": False,
        "OOMKilled": False,
        "Error": "",
        "ExitCode": 2,
        "StartedAt": "2026-09-07T12:00:00.123456789Z",
        "FinishedAt": "2026-09-07T12:00:01.123456789Z",
    }
    control = container.Containers(
        {"image": "image", "helper_image": "helper", "timeout_seconds": 1},
        "lease",
        {},
        lambda *_: None,
    )

    def docker(*arguments, **_kwargs):
        calls.append(arguments)
        return b"completed snapshot" if "--create" in arguments else b""

    monkeypatch.setattr(container, "docker", docker)
    monkeypatch.setattr(container, "qualify_image", lambda _: None)
    monkeypatch.setattr(container, "run", lambda *_args, **_kwargs: (2, b"test failed\n", b""))
    monkeypatch.setattr(control, "check_engine", lambda: None)
    monkeypatch.setattr(control, "volume_record", lambda: {})
    monkeypatch.setattr(control, "create", lambda role, *_: role)
    monkeypatch.setattr(control, "record", lambda _: {"State": state})
    monkeypatch.setattr(control, "remove", lambda role: calls.append(("remove", role)))
    return control, state, calls


def test_failed_start_does_not_report_success_or_snapshot(execution, monkeypatch):
    control, state, calls = execution
    state.update(
        Status="created",
        ExitCode=0,
        StartedAt="0001-01-01T00:00:00Z",
        FinishedAt="0001-01-01T00:00:00Z",
    )
    monkeypatch.setattr(container, "run", lambda *_args, **_kwargs: (1, b"", b"attach failed"))

    with pytest.raises(RuntimeError, match="known terminal state"):
        control.execute(b"previous snapshot", "change the repository")

    assert ("remove", "worker") not in calls
    assert not any("--create" in arguments for arguments in calls)


@pytest.mark.parametrize(
    "changed",
    [
        {"Status": "created"},
        {"Status": "dead"},
        {"StartedAt": "0001-01-01T00:00:00Z"},
        {"FinishedAt": "0001-01-01T00:00:00Z"},
        {"StartedAt": None},
        {"FinishedAt": "not a timestamp"},
        {"StartedAt": "2026-09-07T12:00:00"},
        {"FinishedAt": "2026-09-07T11:59:59Z"},
    ],
)
def test_unproven_terminal_execution_does_not_snapshot(execution, changed):
    control, state, calls = execution
    state.update(changed)

    with pytest.raises(RuntimeError, match="known terminal state"):
        control.execute(b"previous snapshot", "change the repository")

    assert not any("--create" in arguments for arguments in calls)


def test_completed_nonzero_exit_preserves_result_and_snapshots(execution):
    control, _state, calls = execution

    snapshot, result = control.execute(b"previous snapshot", "run failing tests")

    assert snapshot == b"completed snapshot"
    assert result == {"output": "test failed\n", "returncode": 2, "exception_info": ""}
    removed = calls.index(("remove", "worker"))
    exported = next(index for index, arguments in enumerate(calls) if "--create" in arguments)
    assert removed < exported


def test_attachment_failure_after_exit_does_not_promote_partial_output(execution, monkeypatch):
    control, state, calls = execution
    state["ExitCode"] = 0
    monkeypatch.setattr(container, "run", lambda *_args, **_kwargs: (1, b"partial output", b""))
    with pytest.raises(RuntimeError, match="attachment did not complete"):
        control.execute(b"previous snapshot", "change the repository")
    assert not any("--create" in arguments for arguments in calls)
