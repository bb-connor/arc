"""Exercise the real TLS resource and worker DB role, before native composition.

This component check does not qualify a cage, kernel receipt or broker proof.
"""

import argparse
import http.client
import json
import os
import secrets
import socket
import ssl
from pathlib import Path

import host
import postgres
from resources import ResourceGateway, SERVER_NAME


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    state = json.loads(args.database_state.read_text())
    gateway = Path(state["binary"]).resolve(strict=True)
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    tenant = "resource-" + secrets.token_hex(6)
    host.command([gateway, "seed", tenant], directory,
                 env=postgres.database_env(state, "runtime"),
                 input=b'{"job_id":"one","task":{"p95":12.5}}\n')
    observations = []
    with ResourceGateway(gateway, tenant, directory, postgres.database_env(state, "worker")) as resource:
        routes = {route["tool"]: route for route in resource.routes}
        context = ssl.create_default_context(cafile=str(resource.root / "cert.pem"))

        def call(operation, arguments, caller="ab" * 32, *, mutate=None, bearer=None):
            route = routes[operation]
            envelope = {"schema": "chio.host-resource-invocation.v1",
                        "route": {"resource": "postgres-jobs", "tenant": tenant,
                                  "operation": operation},
                        "caller_capability_sha256": caller, "arguments": arguments}
            if mutate is not None:
                mutate(envelope)
            credential = bearer or Path(route["credential_file"]).read_text()
            port = route["adapter"]["port"]
            connection = http.client.HTTPSConnection(SERVER_NAME, port, timeout=5, context=context)
            # Keep certificate and hostname verification while dialing loopback.
            connection.sock = context.wrap_socket(
                socket.create_connection(("127.0.0.1", port), timeout=5),
                server_hostname=SERVER_NAME,
            )
            try:
                connection.request("POST", "/execute", json.dumps(envelope), {
                    "Authorization": "Bearer " + credential, "Content-Type": "application/json",
                })
                response = connection.getresponse()
                assert response.status == 200
                result = json.loads(response.read(131073))
                observations.append({"operation": operation, "caller": caller, "result": result})
                return result
            finally:
                connection.close()

        def refused(operation, arguments, **options):
            try:
                call(operation, arguments, **options)
            except (http.client.RemoteDisconnected, ssl.SSLError, ConnectionError):
                return
            raise AssertionError("unauthenticated or cross-route request was accepted")

        refused("inspect", {"job_id": "one"}, bearer="00" * 32)
        refused("inspect", {"job_id": "one"}, mutate=lambda value: value["route"].update(tenant="other"))
        refused("inspect", {"job_id": "one"}, mutate=lambda value: value["route"].update(operation="assign"))
        refused("inspect", {"job_id": "one", "_meta": {"chioCallerCapabilitySha256": "cd" * 32}})
        before = call("inspect", {"job_id": "one"})
        assert before["state"] == "pending" and before["lease_fence"] == 0
        assigned = call("assign", {"owner_capability_sha256": "ab" * 32, "lease_seconds": 600, "limit": 1})["jobs"][0]
        fence = assigned["lease_fence"]
        result = {"job_id": "one", "expected_fence": fence, "result": {"p95": 12.5}}
        assert call("complete", result, "cd" * 32) == {"status": "superseded"}
        assert call("renew", {"job_id": "one", "expected_fence": fence, "lease_seconds": 600}, "cd" * 32) == {"status": "superseded"}
        assert call("release", {"job_id": "one", "owner_capability_sha256": "ab" * 32, "expected_fence": fence}) == {"status": "released"}
        replacement = call("assign", {"owner_capability_sha256": "cd" * 32, "lease_seconds": 600, "limit": 1})["jobs"][0]
        assert replacement["lease_fence"] > fence
        result["expected_fence"] = replacement["lease_fence"]
        assert call("complete", result) == {"status": "superseded"}
        assert call("complete", result, "cd" * 32) == {"status": "completed"}
        assert call("complete", result, "cd" * 32) == {"status": "already_completed"}
        final = call("task", {"job_id": "one"})
        assert final["state"] == "completed" and final["result"] == result["result"]
    host.write(directory / "component.json", {
        "schema": "chio.postgres-resource-component.v1", "passed": True,
        "refused_controls": 4, "observations": observations,
        "native_broker_or_cage_qualified": False,
    })
    print(json.dumps({"component_passed": True, "refused_controls": 4,
                      "native_composition_qualified": False}))


if __name__ == "__main__":
    main()
