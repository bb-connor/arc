"""The mini-SWE launcher owns its integration-specific worker environment."""

import json

import container_attempts


def test_mini_launcher_supplies_its_environment(tmp_path, monkeypatch):
    connection = {"socket_path": "/tmp/fixture.sock", "credential": "test-only"}
    (tmp_path / "connection.json").write_text(json.dumps(connection))
    requests = []
    result = object()

    def launch(**options):
        requests.append(options)
        return result

    monkeypatch.setattr(container_attempts, "run_container_worker", launch)
    launcher = container_attempts.ContainerAttempts("sha256:" + "1" * 64, tmp_path)
    assert launcher.invoke(b"pass", timeout=42) is result
    assert requests == [
        {
            "image": "sha256:" + "1" * 64,
            "connection": connection,
            "program": b"pass",
            "environment": {
                "MSWEA_GLOBAL_CONFIG_DIR": "/work/mini-config",
                "MSWEA_SILENT_STARTUP": "1",
            },
            "timeout": 42,
        }
    ]
