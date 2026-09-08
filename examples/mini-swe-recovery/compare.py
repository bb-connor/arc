"""Compare installed native coding sessions with the actual upstream Docker agent."""

import argparse
import contextlib
import hashlib
import http.server
import io
import json
import os
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
from pathlib import Path

from chio_mini_swe.operator import protected_executable
from chio_mini_swe.repository_archive import git
from chio_mini_swe.repository_transport import DOCKER, docker
from chio_process.launch import provision_native_demo
from compare_cleanup import cleanup as cleanup_upstream

HERE = Path(__file__).resolve().parent
HARNESS = (
    "compare.py",
    "compare_upstream.py",
    "compare_cleanup.py",
    "compare_fault_worker.py",
    "worker.py",
)
CREDENTIAL = "comparison-fixture-value"
TASK = "Fix addition and verify the existing unit tests."
AGENT = {
    "system_template": "Repair the Python repository using bash commands.",
    "instance_template": "{{task}}",
    "step_limit": 8,
    "cost_limit": 1,
    "wall_time_limit_seconds": 600,
}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def directory_bytes(root):
    return sum(path.lstat().st_size for path in root.rglob("*") if path.is_file())


def command(directory, label, *arguments, timeout=180, env=None):
    """Retain exact command output privately and measure waited driver children."""
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    with (directory / (label + ".stdout")).open("wb") as output:
        with (directory / (label + ".stderr")).open("wb") as errors:
            process = subprocess.Popen(
                [str(a) for a in arguments], stdout=output, stderr=errors, env=env
            )
            try:
                process.wait(timeout=timeout)
            except BaseException:
                # Reap our direct child before ownership-based fallback can
                # reconcile its worker and container. This includes Ctrl-C.
                process.kill()
                process.wait()
                raise
    elapsed = time.monotonic() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    metric = {
        "wall_seconds": elapsed,
        "driver_children_user_seconds": after.ru_utime - before.ru_utime,
        "driver_children_system_seconds": after.ru_stime - before.ru_stime,
        "returncode": process.returncode,
    }
    write(directory / (label + ".measurement.json"), metric)
    if process.returncode != 0:
        raise RuntimeError(f"{label} failed; inspect private diagnostics in {directory}")
    return json.loads((directory / (label + ".stdout")).read_text()), metric


@contextlib.contextmanager
def provider():
    from worker import decisions

    requests = []

    class Endpoint(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024 * 1024:
                    raise ValueError("Invalid fixture request length")
                body = self.rfile.read(length)
                value = json.loads(body)
                if (
                    self.path != "/v1/chat/completions"
                    or self.headers.get("Authorization") != "Bearer " + CREDENTIAL
                    or value.get("model") != "comparison-fixture"
                    or value.get("temperature") != 0
                    or value.get("max_tokens", value.get("max_completion_tokens")) != 1024
                ):
                    raise ValueError("Unexpected fixture provider configuration")
                turn = sum(m.get("role") == "assistant" for m in value["messages"])
                if not 0 <= turn < 3 or len(requests) >= 16:
                    raise ValueError("Unexpected fixture conversation")
                message = decisions()[turn]
                message.pop("extra")
                requests.append(
                    {
                        "turn": turn,
                        "request_sha256": hashlib.sha256(body).hexdigest(),
                        "actions": [
                            json.loads(c["function"]["arguments"])["command"]
                            for c in message["tool_calls"]
                        ],
                        "prompt": value["messages"][:2],
                    }
                )
                response = {
                    "id": f"comparison-{len(requests)}",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "comparison-fixture",
                    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": message}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
                }
                data = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (ValueError, KeyError, TypeError):
                self.send_error(400, "Invalid controlled provider request")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def fixture(root):
    source = root / "source"
    source.mkdir()
    git("init", "--quiet", cwd=source)
    (source / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (source / "test_calculator.py").write_text(
        "import unittest\nfrom calculator import add\n"
        "class Addition(unittest.TestCase):\n"
        "    def test_positive(self):\n        self.assertEqual(add(2, 3), 5)\n"
        "    def test_negative(self):\n        self.assertEqual(add(-2, -3), -5)\n"
    )
    git("add", "--all", cwd=source)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "comparison fixture",
        cwd=source,
    )
    return source, git("rev-parse", "HEAD", cwd=source).decode().strip()


def fault_image(root, image):
    directory = root / "fault-image"
    directory.mkdir()
    shutil.copyfile(HERE / "compare_fault_worker.py", directory / "fault.py")
    (directory / "launcher").write_text(
        "#!/usr/local/bin/python\nfrom runpy import run_path\n"
        "run_path('/opt/chio/comparison-fault.py', run_name='__main__')\n"
    )
    base = json.loads(docker("image", "inspect", image))[0]
    assert base["Id"] == image
    tag = "chio-comparison-base:" + uuid.uuid4().hex
    docker("image", "tag", image, tag)
    (directory / "Dockerfile").write_text(
        "FROM " + tag + "\n"
        "COPY --chmod=0444 fault.py /opt/chio/comparison-fault.py\n"
        "COPY --chmod=0555 launcher /usr/local/bin/chio-mini-swe-worker\n"
    )
    try:
        with (directory / "build.stdout").open("wb") as output:
            with (directory / "build.stderr").open("wb") as errors:
                subprocess.run(
                    [
                        *DOCKER,
                        "build",
                        "--pull=false",
                        "--network=none",
                        "--iidfile",
                        str(directory / "image-id"),
                        str(directory),
                    ],
                    check=True,
                    stdout=output,
                    stderr=errors,
                    timeout=180,
                )
        identifier = (directory / "image-id").read_text().strip()
        built = json.loads(docker("image", "inspect", identifier))[0]
        layers = base["RootFS"]["Layers"]
        assert built["RootFS"]["Layers"][: len(layers)] == layers
        assert json.loads(docker("image", "inspect", tag))[0]["Id"] == image
        return identifier
    finally:
        if json.loads(docker("image", "inspect", tag))[0]["Id"] == image:
            docker("image", "rm", "--no-prune", tag)


def clean_environment(root):
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "LANG": "C.UTF-8",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "PYTHONDONTWRITEBYTECODE": "1",
        "MSWEA_SILENT_STARTUP": "1",
        "MSWEA_GLOBAL_CONFIG_DIR": str(root / "mini-config"),
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "CHIO_COMPARISON_FIXTURE_KEY": CREDENTIAL,
    }


def native(directory, source, revision, image, binary, binary_digest, endpoint, requests, scenario):
    operator = Path(sys.executable).parent / "chio-mini-swe"
    reviewer = Path(sys.executable).parent / "chio-mini-swe-repository"
    environment = clean_environment(directory)
    environment.pop("CHIO_COMPARISON_FIXTURE_KEY")
    configuration = {
        "schema": "chio.mini-swe.session-config.v1",
        "chio": str(binary),
        "repository": str(source),
        "revision": revision,
        "provider_config": "provider.json",
        "worker_image": image["image"],
        "execution_image": image["execution_image"],
        "helper_image": image["helper_image"],
        "command_timeout_seconds": 20,
        "agent": AGENT,
        "max_attempts": 2,
        "timeout_seconds": 240,
        "max_calls": 16,
        "capability_ttl_seconds": 3600,
    }
    write(directory / "configuration.json", configuration)
    write(
        directory / "provider.json",
        {
            "schema": "chio.mini-swe.provider.v1",
            "endpoint": endpoint,
            "model": "comparison-fixture",
            "credential_env": "CHIO_COMPARISON_FIXTURE_KEY",
            "allow_loopback_http": True,
            "max_output_tokens": 1024,
            "temperature": 0,
            "timeout_seconds": 30,
            "input_usd_per_million": 2,
            "output_usd_per_million": 8,
        },
    )
    (directory / "task.md").write_text(TASK)
    state = directory / "session"
    _, initialized = command(
        directory,
        "init",
        operator,
        "session",
        "init",
        "--config",
        directory / "configuration.json",
        "--task-file",
        directory / "task.md",
        "--state",
        state,
        env=environment,
    )
    request = json.loads((state / "provisioning-request.json").read_text())
    assert request["binary_sha256"] == binary_digest
    started = time.monotonic()
    bindings = {}
    # Explicit comparison authority is issued outside the installed product.
    for name, launch in request["servers"].items():
        selected = provision_native_demo(
            binary,
            name,
            launch["command"],
            directory / ("launch-" + name),
            launch["working_directory"],
        )
        bindings[name] = {k: selected[k] for k in ("launch_policy", "launch_policy_signer")}
    authority_seconds = time.monotonic() - started
    write(
        directory / "authorization.json",
        {"schema": "chio.mini-swe.session-authorization.v1", "servers": bindings},
    )
    _, prepared = command(
        directory,
        "prepare",
        operator,
        "session",
        "prepare",
        "--state",
        state,
        "--authorization",
        directory / "authorization.json",
        env=environment,
    )
    before_bytes = directory_bytes(state)
    assert not requests
    environment["CHIO_COMPARISON_FIXTURE_KEY"] = CREDENTIAL
    completed, executed = command(
        directory,
        "execute",
        operator,
        "session",
        "run",
        "--state",
        state,
        timeout=540,
        env=environment,
    )
    assert completed["complete"]
    assert completed["pending_container_records"] == 0
    assert completed["abandoned_socket_intents"] == 0
    attempts = completed["workers"][0]["attempts"]
    assert attempts == (2 if scenario == "patch-return-crash" else 1)
    fault = None
    if scenario == "patch-return-crash":
        lines = (state / "run/host/run-logs/coder-1.stdout").read_text().splitlines()
        events = [json.loads(line) for line in lines if line.startswith("{")]
        faults = [e for e in events if e.get("event") == "comparison_patch_return_crash"]
        assert len(faults) == 1 and faults[0]["attempt"] == 1
        fault = faults[0]
    environment.pop("CHIO_COMPARISON_FIXTURE_KEY")
    # The native result and recipient verification run with no provider key.
    (state / "provider.json").unlink()
    exported, exported_metric = command(
        directory,
        "export",
        operator,
        "session",
        "result",
        "--state",
        state,
        "--out",
        directory / "result",
        env=environment,
    )
    kernel = directory / "result/operator/kernel.pub"
    review, review_metric = command(
        directory,
        "review",
        reviewer,
        "verify-export",
        "--bundle",
        directory / "result/repository",
        "--repository",
        source,
        "--revision",
        revision,
        "--kernel-key",
        kernel,
        "--server-id",
        "sandbox",
        "--chio",
        binary,
        env=environment,
    )
    manifest = json.loads((directory / "result/repository/manifest.json").read_text())
    final_files = {}
    with tarfile.open(
        fileobj=io.BytesIO((directory / "result/repository/workspace.tar").read_bytes())
    ) as archive:
        for entry in archive:
            name = entry.name.removeprefix("./")
            if name in {"calculator.py", "test_calculator.py", "effects.txt", "test-output.txt"}:
                if not entry.isfile() or entry.size > 65536 or name in final_files:
                    raise ValueError("Invalid final comparison fixture file")
                final_files[name] = archive.extractfile(entry).read().decode()
    assert len(final_files) == 4
    assert "return a + b" in final_files["calculator.py"]
    assert final_files["test-output.txt"].rstrip().endswith("OK")
    assert final_files["effects.txt"].splitlines() == ["patched", "audit", "audit"]
    assert review["verified_transitions"] == 5
    assert review["verification"]["receipts_verified"] == 8
    assert [r["turn"] for r in requests] == [0, 1, 2]
    if fault is not None:
        receipts = [
            json.loads(line)
            for line in (directory / "result/operator/receipts.ndjson").read_text().splitlines()
        ]
        assert json.loads(fault["receipt_json"]) in receipts
    return {
        "mode": "chio",
        "initialization": initialized,
        "preparation": prepared,
        "fixture_authority_seconds": authority_seconds,
        "execution": executed,
        "export": exported_metric,
        "recipient_verification": review_metric,
        "completed": completed,
        "exported": exported,
        "review": review,
        "manifest": manifest,
        "final_files": final_files,
        "effects": final_files["effects.txt"].splitlines(),
        "fault": fault,
        "state_bytes_before_execution": before_bytes,
        "state_bytes_after_execution": directory_bytes(state),
        "model_requests": list(requests),
        "execution_image": image["execution_image"],
        "worker_image": image["image"],
        "container_resource_accounting": (
            "unavailable: driver child usage excludes Docker daemon and container cgroups"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=1, choices=range(1, 6))
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-upstream-comparison-"))
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str(root / "mini-config")
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    print("Private comparison state: " + str(root), flush=True)
    write(args.output / "progress.json", {"private_state": str(root), "phase": "preparing"})
    binary = args.chio.resolve(strict=True)
    protected_executable(binary)
    binary_digest = sha(binary)
    harness_digests = {name: sha(HERE / name) for name in HARNESS}
    write(
        args.output / "input-identities.json",
        {"binary_sha256": binary_digest, "comparison_sources_sha256": harness_digests},
    )
    source, revision = fixture(root)
    source_bytes = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    images = json.loads(args.worker_image_file.read_text())
    images["helper_image"] = (
        docker("image", "inspect", images["base"], "--format", "{{.Id}}").decode().strip()
    )
    modified_image = fault_image(root, images["image"])
    results = []
    for trial in range(args.trials):
        for scenario in ("clean", "patch-return-crash"):
            order = (
                ("upstream", "chio")
                if (trial + (scenario != "clean")) % 2 == 0
                else ("chio", "upstream")
            )
            for mode in order:
                case = f"{trial + 1}-{scenario}-{mode}"
                directory = root / case
                directory.mkdir()
                write(
                    args.output / "progress.json",
                    {"private_state": str(root), "phase": case, "completed_cases": len(results)},
                )
                print("Running " + case, flush=True)
                assert sha(binary) == binary_digest
                assert {name: sha(HERE / name) for name in HARNESS} == harness_digests
                with provider() as (endpoint, requests):
                    if mode == "chio":
                        selected = dict(
                            images, image=modified_image if scenario != "clean" else images["image"]
                        )
                        result = native(
                            directory,
                            source,
                            revision,
                            selected,
                            binary,
                            binary_digest,
                            endpoint,
                            requests,
                            scenario,
                        )
                    else:
                        write(
                            directory / "config.json",
                            {
                                "source": str(source),
                                "revision": revision,
                                "image": images["execution_image"],
                                "endpoint": endpoint,
                                "output": str(directory / "upstream"),
                                "scenario": scenario,
                                "owner": uuid.uuid4().hex,
                            },
                        )
                        arguments = [
                            sys.executable,
                            HERE / "compare_upstream.py",
                            "--config",
                            directory / "config.json",
                        ]
                        try:
                            locator, metric = command(
                                directory,
                                "upstream",
                                *arguments,
                                timeout=1800,
                                env=clean_environment(directory),
                            )
                        except BaseException:
                            try:
                                cleanup = cleanup_upstream(directory / "config.json", arguments)
                            except Exception as error:
                                cleanup = {"verified": False, "error_type": type(error).__name__}
                            write(directory / "fallback-cleanup.json", cleanup)
                            raise
                        expected = directory / "upstream/result.json"
                        assert (
                            locator == {"result": str(expected)}
                            and expected.stat().st_size <= 1024 * 1024
                        )
                        result = json.loads(expected.read_text())
                        assert result["completed"] and result["test_output"].rstrip().endswith("OK")
                        assert result["cleanup"]["owned_containers_remaining"] == 0
                        assert (
                            directory / "upstream/final/calculator.py"
                        ).read_text() == "def add(a, b):\n    return a + b\n"
                        result["driver"] = metric
                        result["model_requests"] = list(requests)
                result.update(trial=trial + 1, scenario=scenario, mode=mode)
                expected_prompt = [
                    {"role": "system", "content": AGENT["system_template"]},
                    {"role": "user", "content": TASK},
                ]
                for request in result["model_requests"]:
                    prompt = [{k: m[k] for k in ("role", "content")} for m in request["prompt"]]
                    assert prompt == expected_prompt
                result["effect_oracle"] = {
                    "patch_effects": result["effects"].count("patched"),
                    "audit_effects": result["effects"].count("audit"),
                    "matches_requested_effects": result["effects"] == ["patched", "audit", "audit"],
                }
                if scenario == "clean":
                    assert result["effect_oracle"]["matches_requested_effects"]
                    assert [r["turn"] for r in result["model_requests"]] == [0, 1, 2]
                elif mode == "upstream":
                    assert len(result["attempts"]) == 2
                    assert result["attempts"][0]["returncode"] == -9
                    assert result["attempts"][0]["crash_boundary_exists"]
                    assert result["effects"] == ["patched", "patched", "audit", "audit"]
                    assert [r["turn"] for r in result["model_requests"]] == [0, 1, 0, 1, 2]
                write(directory / "comparison.json", result)
                write(args.output / (case + ".json"), result)
                results.append(result)
                assert source_bytes == {
                    p.name: p.read_bytes() for p in source.iterdir() if p.is_file()
                }
    upstream_hashes = {
        r["upstream_module_sha256"]["agents/default.py"] for r in results if r["mode"] == "upstream"
    }
    assert len(upstream_hashes) == 1
    for result in results:
        if result["mode"] == "chio" and result["fault"]:
            assert result["fault"]["upstream_agent_sha256"] in upstream_hashes
    assert sha(binary) == binary_digest
    assert {name: sha(HERE / name) for name in HARNESS} == harness_digests
    report = {
        "schema": "chio.mini-swe.upstream-comparison.v1",
        "private_state": str(root),
        "source_commit": revision,
        "binary_sha256": binary_digest,
        "images": images,
        "fault_worker_image": modified_image,
        "comparison_sources_sha256": harness_digests,
        "cases": results,
        "limits": [
            "controlled model decisions; no coding-quality or billing conclusion",
            "explicit upstream operator rerun; no claimed upstream automatic recovery",
            "complete native-session architecture cost, not bare kernel overhead",
            "whole-system CPU and container memory accounting unavailable",
            "fixed decisions ignore observations; no prediction of live-model rerun behavior",
        ],
        "source_unchanged": True,
    }
    write(args.output / "comparison.json", report)
    write(
        args.output / "progress.json",
        {"private_state": str(root), "phase": "complete", "completed_cases": len(results)},
    )
    print(json.dumps({"output": str(args.output), "completed_cases": len(results)}), flush=True)


if __name__ == "__main__":
    main()
