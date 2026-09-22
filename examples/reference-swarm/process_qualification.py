"""Shared local harness for Enforced process qualification scenarios."""

import json
import os
import subprocess


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


class Harness:
    def __init__(self, chio, helper, probe, output, anchor, worker_image):
        self.chio, self.helper, self.probe = [
            path.resolve(strict=True) for path in [chio, helper, probe]
        ]
        self.output = output.absolute()
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.output = self.output.resolve(strict=True)
        self.anchor = anchor.resolve(strict=True)
        if not self.anchor.is_dir() or self.anchor.stat().st_mode & 0o077:
            raise ValueError("anchor must be an existing private directory")
        self.worker_image = worker_image
        self.commands = []
        self.servers = []
        self.state = self.output / "state"

    def run(self, label, command, success=True):
        command = list(map(str, command))
        stdout_path = self.output / f"{label}.stdout"
        stderr_path = self.output / f"{label}.stderr"
        observation = {
            "stage": label,
            "command": command,
            "exit": None,
            "expected_success": success,
        }
        # Stream host diagnostics to retained files while a scenario is running.
        # In particular, a command timeout must not discard its partial evidence.
        try:
            with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
                result = subprocess.run(
                    command,
                    text=True,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=600,
                    check=False,
                )
            observation["exit"] = result.returncode
        except subprocess.TimeoutExpired:
            observation["timed_out"] = True
            observation["timeout_seconds"] = 600
            raise
        finally:
            self.commands.append(observation)
            (self.output / "commands.json").write_text(
                json.dumps(self.commands, indent=2) + "\n"
            )
        if (result.returncode == 0) != success:
            raise RuntimeError(
                f"{label} failed; inspect {self.output / (label + '.stderr')}"
            )
        return json.loads(stdout_path.read_text()) if success else stderr_path.read_text()

    def server(self, name, read_directory, write_paths=()):
        launch = self.output / (name + "-launch")
        command = [
            self.chio,
            "security",
            "provision-reference-runtime",
            "--output-dir",
            launch,
            "--cage-init",
            self.helper,
            "--target",
            self.probe,
            "--working-directory",
            read_directory,
            "--read-path",
            read_directory,
            "--max-artifact-bytes",
            "2097152",
            "--receipt-rollback-anchor-root",
            self.anchor,
            "--discover-tools",
            "--execution-uid",
            os.getuid(),
            "--execution-gid",
            os.getgid(),
            "--server-id",
            name,
        ]
        for gid in sorted(set(os.getgroups()) - {os.getgid()}):
            command.extend(["--execution-supplementary-gid", gid])
        for path in write_paths:
            command.extend(["--write-path", path])
        self.run("provision-" + name, command)
        report = json.loads((launch / "provision-report.json").read_text())
        assert report["securityMode"] == "enforced_cage", report
        self.servers.append(
            {
                "id": name,
                "command": [str(self.probe)],
                "launch_policy": str(launch / "cage-launch-policy.json"),
                "launch_policy_signer": report["cagePolicyPublicKey"],
            }
        )

    def initialize(self, calls, *, plan=None, aggregate_invocations=None):
        policy = self.output / "policy.yaml"
        policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
  require_swarm_admission: true
capabilities:
  default:
    tools:
      - server: '*'
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
        share, remainder = divmod(10000, len(calls))
        config = {
            "schema": "chio.process.host.v1",
            "execution_nonces": True,
            "policy": str(policy),
            "servers": self.servers,
            "limits": {
                "max_processes": len(calls) + 1,
                "max_depth": 1,
                "max_calls": len(calls) * 8,
            },
            "children": [
                {
                    "id": call["process"],
                    "parent": "root",
                    "budget_share_bps": share + (index < remainder),
                    "tools": [
                        {"server_id": call["server_id"], "tool_name": call["tool_name"]}
                    ],
                }
                for index, call in enumerate(calls)
            ],
        }
        write(self.output / "host.json", config)
        write(
            self.output / "tasks.json",
            plan if plan is not None else {
                "schema": "chio.process.swarm-plan.v1",
                "graph_id": "confinement-probes",
                "calls": calls,
            },
        )
        self.run(
            "initialize",
            [
                self.chio,
                "process",
                "init",
                "--config",
                self.output / "host.json",
                "--state",
                self.state,
                "--aggregate-invocations",
                len(calls) if aggregate_invocations is None else aggregate_invocations,
                "--swarm-plan",
                self.output / "tasks.json",
            ],
        )
        return json.loads((self.state / "swarm-calls.json").read_text())["calls"]

    def observe(self, call):
        name = call["process"]
        retained = self.run(
            "state-" + name,
            [
                self.chio,
                "process",
                "state",
                "--state",
                self.state,
                "--process",
                name,
            ],
        )
        response = retained["data"]["checkpoint"]["value"]["response"]
        self.verify_response(name, call, response)
        return response

    def verify_response(self, name, call, response):
        request = {
            field: call[field]
            for field in ["operation_key", "server_id", "tool_name", "arguments"]
        }
        request["known_outcome_only"] = False
        bundle = json.loads((self.state / "swarm-bootstrap.json").read_text())
        runtime = json.loads((self.state / "swarm-calls.json").read_text())[
            "runtime_id"
        ]
        context = {
            "runtime_id": runtime,
            "process_id": call["process"],
            "capability_id": bundle["action"]["parameters"]["capabilities"][
                call["process"]
            ]["id"],
        }
        folder = self.output / name
        folder.mkdir(mode=0o700)
        for label, value in [
            ("request", request),
            ("context", context),
            ("response", response),
        ]:
            write(folder / (label + ".json"), value)
        self.run(
            "verify-" + name,
            [
                self.chio,
                "--json",
                "receipt",
                "verify-process-response",
                "--request",
                folder / "request.json",
                "--context",
                folder / "context.json",
                "--response",
                folder / "response.json",
                "--trusted-kernel-pubkey",
                self.state / "authority.db.kernel.pub",
            ],
        )
        return response
