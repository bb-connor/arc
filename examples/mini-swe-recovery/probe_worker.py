"""Check the actual worker namespace before running the coding fixture."""

import errno
import hashlib
import inspect
import json
import os
import socket
import sys
from pathlib import Path

from chio_process import ProcessClient, WorkerError
from chio_process import container as container_support
from minisweagent.agents.default import DefaultAgent


def main():
    upstream = hashlib.sha256(Path(inspect.getfile(DefaultAgent)).read_bytes()).hexdigest()
    assert upstream == "e8ef8aa365942d739c2ec5cb0879f60f377d2dc2de8ec670aaedf3bafb45a4c2"
    assert os.getuid() != 0
    process_status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    )
    assert int(process_status["CapEff"].strip(), 16) == 0
    assert process_status["NoNewPrivs"].strip() == "1"
    assert process_status["Seccomp"].strip() == "2"
    assert set(os.getgroups()) <= {os.getgid()}
    assert sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"]
    for value in ["/var/run/docker.sock", "/run/docker.sock", *sys.argv[1:]]:
        for prefix in ("", "/proc/1/root"):
            assert not Path(prefix + value).exists(), value
    for path in ("/run/chio/connection.json", "/app/worker.py", "/etc/worker-probe"):
        try:
            Path(path).write_text("must not write")
        except OSError as error:
            assert error.errno in {errno.EROFS, errno.EACCES}
        else:
            raise AssertionError(f"Worker could modify a protected path: {path}")
    try:
        os.chmod("/run/chio/process.sock", 0o666)
    except OSError as error:
        assert error.errno in {errno.EROFS, errno.EACCES, errno.EPERM}
    else:
        raise AssertionError("Worker could change host socket permissions")
    with socket.socket() as stream:
        stream.settimeout(1)
        try:
            stream.connect(("198.51.100.1", 9))
        except OSError as error:
            assert error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}
        else:
            raise AssertionError("Worker unexpectedly had an external network route")
    descriptor = json.loads(Path("/run/chio/connection.json").read_text())
    client = ProcessClient(descriptor["socket_path"], descriptor["credential"])
    assert client.inspect()["checkpoint"]["revision"] == "0"
    try:
        client._call({"op": "credential", "process_id": "root"})
    except WorkerError as error:
        assert error.code == "invalid_request"
    else:
        raise AssertionError("Worker obtained an administrative credential")
    scratch = os.statvfs("/work")
    assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(512 * 1024 * 1024)
    assert Path("/sys/fs/cgroup/memory.swap.max").read_text().strip() == "0"
    assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "64"
    quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
    assert quota == period
    assert scratch.f_blocks * scratch.f_frsize == 64 * 1024 * 1024
    print(
        json.dumps(
            {
                "unprivileged_uid": os.getuid(),
                "upstream_agent_sha256": upstream,
                "launcher_sha256": hashlib.sha256(
                    Path(container_support.__file__).read_bytes()
                ).hexdigest(),
                "zero_capabilities": True,
                "no_new_privileges": True,
                "seccomp_filter": True,
                "host_files_absent": True,
                "docker_socket_absent": True,
                "readonly_inputs": True,
                "network_none": True,
                "admin_request_refused": True,
                "scratch_bytes": 64 * 1024 * 1024,
            }
        )
    )


if __name__ == "__main__":
    main()
