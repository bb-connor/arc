"""Q5 probe: what policy identity can a Chio component fetch from the gateway?

Calls GetSandboxPolicyStatus, ListSandboxPolicies, GetSandbox, and a short
WatchSandbox(follow_status, follow_events) window using the v0.1.2 SDK stubs.
"""

from __future__ import annotations

import sys
import threading
import time

import grpc
from google.protobuf.json_format import MessageToDict

from openshell._proto import datamodel_pb2, openshell_pb2, openshell_pb2_grpc

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:27602"
SANDBOX = sys.argv[2] if len(sys.argv) > 2 else "chio-spike-1"
WATCH_SECONDS = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0

channel = grpc.insecure_channel(ENDPOINT)
stub = openshell_pb2_grpc.OpenShellStub(channel)
scope = datamodel_pb2.WorkspaceSelector(workspace="default") if hasattr(datamodel_pb2, "WorkspaceSelector") else None


def with_scope(message):
    if scope is not None and "workspace_scope" in message.DESCRIPTOR.fields_by_name:
        message.workspace_scope.CopyFrom(scope)
    return message


started = time.perf_counter()
status = stub.GetSandboxPolicyStatus(with_scope(openshell_pb2.GetSandboxPolicyStatusRequest(sandbox=SANDBOX, version=0)))
elapsed = (time.perf_counter() - started) * 1000
rev = status.revision
print("GetSandboxPolicyStatus", {"active_version": status.active_version, "version": rev.version, "policy_hash": rev.policy_hash,
                                 "status": openshell_pb2.PolicyStatus.Name(rev.status), "loaded_time": MessageToDict(rev).get("loadedTime"),
                                 "provenance": dict(rev.provenance), "latency_ms": round(elapsed, 2)})
listing = stub.ListSandboxPolicies(with_scope(openshell_pb2.ListSandboxPoliciesRequest(sandbox=SANDBOX, page_size=10)))
print("ListSandboxPolicies", [(r.version, r.policy_hash[:16], openshell_pb2.PolicyStatus.Name(r.status)) for r in listing.revisions])
sandbox = stub.GetSandbox(with_scope(openshell_pb2.GetSandboxRequest(name=SANDBOX)))
print("GetSandbox.status.current_policy_version", sandbox.sandbox.status.current_policy_version)

events = []


def watch():
    request = with_scope(openshell_pb2.WatchSandboxRequest(sandbox=SANDBOX, follow_status=True, follow_events=True, event_tail=5))
    try:
        for event in stub.WatchSandbox(request, timeout=WATCH_SECONDS):
            kind = event.WhichOneof("payload")
            if kind == "sandbox":
                events.append(("sandbox", event.sandbox.status.current_policy_version))
            elif kind == "event":
                events.append(("event", MessageToDict(event.event)))
            else:
                events.append((kind, None))
    except grpc.RpcError as error:
        events.append(("end", error.code().name))


thread = threading.Thread(target=watch)
thread.start()
thread.join()
for kind, value in events[:12]:
    print("WatchSandbox", kind, str(value)[:300])
