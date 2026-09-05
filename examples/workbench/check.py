"""Verify an installed workbench using scripted proposals and real kernel tools."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler, Request

from chio.invariants.capability import verify_capability
from chio.invariants.json import canonicalize_json
from chio.invariants.receipt import verify_receipt
from pure25519.ed25519_oop import SigningKey


FIXTURE = runpy.run_path(str(Path(__file__).with_name("start.py")))
HTTP = build_opener(ProxyHandler({}))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def request(base: str, token: str, path: str, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    with HTTP.open(Request(base + path, data=data, headers=headers), timeout=10) as response:
        return json.load(response)


@contextmanager
def server(binary: Path, workspace: Path, state: Path, client: Path, log: Path):
    env = {"PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
           "PYTHONDONTWRITEBYTECODE": "1"}
    with log.open("wb") as output:
        process = subprocess.Popen(FIXTURE["command"](binary, workspace, state, "installation-test-client", str(client)),
                                   cwd=workspace.parent, env=env, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                require(process.poll() is None, "installed workbench exited before startup; inspect the private server log")
                match = re.search(r"Open: (http://127\.0\.0\.1:\d+)/#access=([a-f0-9]+)", log.read_text())
                if match:
                    yield match[1], match[2]
                    return
                time.sleep(0.1)
            raise TimeoutError("installed workbench did not start within 30 seconds")
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def verify_run(run: dict, signer: str) -> int:
    require(run["status"] == "succeeded", "installed repair did not succeed")
    require(run["model"] == "claude-code:installation-test-client", "unexpected model transport")
    require([task["role"] for task in run["tasks"]] == ["investigator", "editor", "reviewer"], "missing role")
    root = run["root_capability"]
    verified = verify_capability(root, run["started_at"], 0)
    require(root["issuer"] == signer and verified["signature_valid"] and verified["time_valid"], "invalid root authority")
    receipts = set()
    for task in run["tasks"]:
        cap = task["capability"]
        checked = verify_capability(cap, task["actions"][0]["started_at"], 1)
        require(cap["issuer"] == signer and all(checked[key] for key in
                ("signature_valid", "delegation_chain_shape_valid", "time_valid")), "invalid role authority")
        require(len(cap["delegation_chain"]) == 1 and cap["delegation_chain"][0]["capability_id"] == root["id"],
                "role did not descend from this run")
        grants = cap["scope"]["grants"]
        require(all(grant["operations"] == ["invoke"] for grant in grants), "role retained delegation authority")
        names = {grant["tool_name"] for grant in grants}
        expected = {"list_files", "read_file", "run_checks"}
        if task["role"] == "editor":
            expected.add("replace_text")
        require(names == expected and len(grants) == len(expected), "tool authority did not match the role")
        require(all(grant["server_id"] == "workspace" for grant in grants), "role can access another tool server")
        for action in task["actions"]:
            receipt = action["receipt"]
            require(receipt is not None and verify_receipt(receipt, [signer])["authorized"], "invalid kernel receipt")
            require(receipt["capability_id"] == cap["id"] and receipt["tool_name"] == action["tool"]
                    and receipt["action"]["parameters"] == action["arguments"], "receipt does not match the action")
            digest = hashlib.sha256(canonicalize_json(action["output"]).encode()).hexdigest()
            require(receipt["content_hash"] == digest, "receipt does not match the tool output")
            require(receipt["id"] not in receipts, "duplicate tool receipt")
            receipts.add(receipt["id"])
    require(len(receipts) == 7, "installation repair did not produce seven distinct receipts")
    require(run["tasks"][0]["actions"][-1]["output"]["passed"] is False, "failure was not established before editing")
    require(run["tasks"][1]["actions"][1]["state"] == "succeeded", "editor did not change the file")
    require(run["tasks"][2]["actions"][-1]["output"]["passed"] is True, "reviewer did not verify the result")
    return len(receipts)


def check(binary: Path, output: Path) -> None:
    workspace, state = FIXTURE["prepare"](output)
    output = workspace.parent
    client = output / "scripted-client"
    client.write_bytes(Path(__file__).with_name("scripted_client.py").read_bytes())
    client.chmod(0o700)
    with server(binary, workspace, state, client, output / "server.log") as (base, token):
        try:
            request(base, "incorrect", "/api/runs")
        except HTTPError as error:
            require(error.code == 401, "unexpected unauthorized response")
        else:
            raise ValueError("workbench admitted an unauthenticated request")
        identifier = request(base, token, "/api/runs", {"prompt": FIXTURE["TASK"], "call_limit": 24})["id"]
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            run = request(base, token, f"/api/runs/{identifier}")
            if run["status"] not in ("running", "stopping"):
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("installed repair did not finish within 90 seconds")
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        # Pin the public identity independently from this private test kernel's
        # persisted seed. The seed never leaves the fixture directory or report.
        signer = SigningKey((state / "kernel.seed").read_bytes()).get_verifying_key().to_bytes().hex()
        receipts = verify_run(run, signer)
    subprocess.run([sys.executable, "-I", "-c", FIXTURE["CHECK"]], cwd=workspace, check=True)
    with server(binary, workspace, state, client, output / "restart.log") as (base, token):
        restored = request(base, token, f"/api/runs/{identifier}")
        require(restored == run, "restart changed the completed run")
        verify_run(restored, signer)
    evidence = {"kind": "chio.workbench-installation-acceptance.v1", "roles": 3,
                "verified_receipts": receipts, "effects": 1, "model": "scripted-test-client",
                "live_model_verified": False, "restart_verified": True, "operator_checks_passed": True,
                "release_qualified": False}
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    check(args.workbench.resolve(strict=True), args.state_dir)
