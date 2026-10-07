import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def qualifier(monkeypatch):
    directory = Path(__file__).resolve().parents[4] / "examples/mini-swe-recovery"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location(
        "operator_qualification_diagnostics", directory / "qualify_operator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failure_artifact_keeps_only_allowlisted_report_and_classes(qualifier, tmp_path):
    secret = "never-publish-this-native-credential"
    logs = tmp_path / "run/host/run-logs"
    logs.mkdir(parents=True)
    (logs / "coder-1.stderr").write_text(secret + "\nChioModelError: invalid model result\n")
    protected = tmp_path / "signing-key"
    protected.write_text(secret + " permission denied")
    (logs / "coder-2.stderr").symlink_to(protected)
    output = tmp_path / "output"
    output.mkdir()
    report = {
        "schema": "chio.process.run-report.v1",
        "complete": False,
        "pending_container_records": 0,
        "credential": secret,
        "workers": [
            {
                "process": "coder",
                "state": "failed",
                "attempts": 2,
                "outcome": "exit_1",
                "stderr": secret,
                "cpu_ms": secret,
            },
            {"process": {"credential": secret}, "state": "failed"},
        ],
    }
    failure = subprocess.CalledProcessError(
        1, ["operator", secret], output=json.dumps(report), stderr=secret + " connection refused"
    )
    qualifier.save_failure_diagnostics(tmp_path, output, failure)
    text = (output / "operator-failure.json").read_text()
    assert secret not in text
    result = json.loads(text)
    assert result["run_report"] == {
        "schema": "chio.process.run-report.v1",
        "complete": False,
        "pending_container_records": 0,
        "workers": [{"process": "coder", "state": "failed", "attempts": 2, "outcome": "exit_1"}],
    }
    assert result["host_failure_classes"] == ["connection_refused"]
    assert result["worker_logs"][1]["classes"] == ["invalid_model_result"]
    assert result["worker_logs"][3]["available"] is False
    assert list(output.iterdir()) == [output / "operator-failure.json"]


def test_failure_diagnostics_bound_and_tolerate_malformed_output(qualifier, tmp_path):
    logs = tmp_path / "run/host/run-logs"
    logs.mkdir(parents=True)
    (logs / "coder-1.stdout").write_bytes(b"x" * 65537 + b"invalid model result")
    output = tmp_path / "output"
    output.mkdir()
    failure = subprocess.TimeoutExpired(
        ["operator", "private-argument"],
        120,
        output=b"not a JSON report",
        stderr=b"x" * 65537 + b"permission denied",
    )
    qualifier.save_failure_diagnostics(tmp_path, output, failure)
    result = json.loads((output / "operator-failure.json").read_text())
    assert result["timed_out"] and result["run_report"] is None
    assert result["host_failure_classes"] == []
    assert result["worker_logs"][0]["truncated"]
    assert result["worker_logs"][0]["classes"] == []
    assert qualifier.safe_run_report("[" * 65536) is None
    assert qualifier.safe_run_report(" " * 65537) is None


ATTACHMENT_MARKER = (
    "chio container still running after attachment ended: reason {reason}, client {client}\n"
)


def test_failure_classes_name_docker_attach_wait_and_reconciliation(qualifier):
    secret = "never-publish-this-native-credential"
    cases = [
        ("error from daemon in stream: " + secret, ["docker_attach_stream_failed"]),
        (
            'time="2026-10-07T18:59:22Z" level=error msg="error waiting for container: '
            + secret
            + '"',
            ["docker_wait_failed"],
        ),
        ("Error waiting for container: " + secret, ["docker_wait_failed"]),
        (b"error waiting for container: " + secret.encode(), ["docker_wait_failed"]),
        (
            "security dispatch outcome requires reconciliation: " + secret,
            ["reconciliation_required"],
        ),
        ("error during connect: unexpected EOF " + secret, []),
        ("daemon stream waiting reconciliation " + secret, []),
    ]
    for text, classes in cases:
        assert qualifier.failure_classes(text) == classes, classes


def test_runner_attachment_marker_maps_only_fixed_anchored_values(qualifier):
    secret = "never-publish-this-native-credential"
    for reason, client in [
        ("exit_0", "exit_zero"),
        ("exit_1", "exit_error"),
        ("exit_125", "exit_engine"),
        ("exit_255", "exit_other"),
        ("signal", "signal"),
        ("worker_io_failed", "killed_bootstrap"),
        ("runner_interrupted", "killed_interrupt"),
        ("container_attachment_error", "unobserved"),
        ("unclassified", "unclassified"),
    ]:
        marker = ATTACHMENT_MARKER.format(reason=reason, client=client)
        assert qualifier.failure_classes(marker + secret) == [
            "attachment_client_" + client,
            "attachment_reason_" + reason,
        ]
    marker = ATTACHMENT_MARKER.format(reason="exit_125", client="exit_engine")
    for text in [
        "worker output\n" + marker,
        ATTACHMENT_MARKER.format(reason="exit_256", client="exit_other"),
        ATTACHMENT_MARKER.format(reason="exit_01", client="exit_other"),
        ATTACHMENT_MARKER.format(reason=secret, client="exit_error"),
        ATTACHMENT_MARKER.format(reason="exit_1", client=secret),
        marker[:-1] + " " + secret + "\n",
        marker[:-1],
    ]:
        assert qualifier.failure_classes(text) == []


def test_failure_artifact_publishes_attachment_classes_without_raw_text(qualifier, tmp_path):
    secret = "never-publish-this-native-credential"
    logs = tmp_path / "run/host/run-logs"
    logs.mkdir(parents=True)
    (logs / "coder-1.stderr").write_text(
        ATTACHMENT_MARKER.format(reason="exit_125", client="exit_engine")
        + 'time="2026-10-07T18:59:22Z" level=error msg="error waiting for container: '
        + secret
        + '"\n'
    )
    (logs / "coder-1.stdout").write_text("--env=CHIO_TOKEN=" + secret + "\n")
    output = tmp_path / "output"
    output.mkdir()
    worker = {
        "process": "coder",
        "state": "failed",
        "attempts": 1,
        "outcome": "container_attachment_lost",
    }
    report = {
        "schema": "chio.process.run-report.v1",
        "complete": False,
        "pending_container_records": 0,
        "workers": [worker],
    }
    failure = subprocess.CalledProcessError(
        1,
        ["chio-mini-swe", "run", "--state", secret],
        output=json.dumps(report),
        stderr="security dispatch outcome requires reconciliation: " + secret,
    )
    qualifier.save_failure_diagnostics(tmp_path, output, failure)
    text = (output / "operator-failure.json").read_text()
    for private in (
        secret,
        "CHIO_TOKEN",
        "waiting for container",
        "requires reconciliation",
        "still running after",
        "level=error",
    ):
        assert private not in text
    result = json.loads(text)
    assert result["run_report"]["workers"] == [worker]
    assert result["host_failure_classes"] == ["reconciliation_required"]
    assert result["worker_logs"][0]["classes"] == []
    assert result["worker_logs"][1]["classes"] == [
        "attachment_client_exit_engine",
        "attachment_reason_exit_125",
        "docker_wait_failed",
    ]
    assert list(output.iterdir()) == [output / "operator-failure.json"]
