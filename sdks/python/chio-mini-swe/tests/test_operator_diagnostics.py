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
