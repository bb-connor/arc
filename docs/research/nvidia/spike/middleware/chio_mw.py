"""Chio spike middleware for OpenShell supervisor middleware (openshell.middleware.v1).

Research spike only. Verifies a Chio capability token carried in the
x-chio-capability-token request header, enforces tool name and argument
constraints on MCP tools/call bodies, signs a receipt, and records exactly what
OpenShell delivered so the spike can answer header, body, context, and logging
questions.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import threading
import time
from concurrent import futures

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "gen"))
REPO_ROOT = os.environ.get(
    "CHIO_REPO_ROOT", os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "sdks", "python", "chio-py", "src"))

import grpc  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import extension_pb2 as ext  # noqa: E402
import supervisor_middleware_pb2 as pb  # noqa: E402
import supervisor_middleware_pb2_grpc as pbg  # noqa: E402
from chio.invariants.capability import capability_signing_body_canonical_json  # noqa: E402
from chio.invariants.json import canonicalize_json  # noqa: E402

CONTROL_PATH = os.environ.get("CHIO_MW_CONTROL", os.path.join(HERE, "control.json"))
LOG_LOCK = threading.Lock()
MAX_PAYLOAD = 4 * 1024 * 1024
KERNEL_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"chio-spike-kernel").digest())


def control() -> dict:
    try:
        with open(CONTROL_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


class Logger:
    def __init__(self, path: str) -> None:
        self.path = path

    def write(self, record: dict) -> None:
        record["ts"] = time.time()
        line = json.dumps(record, sort_keys=True)
        with LOG_LOCK:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def struct_to_dict(struct) -> dict:
    from google.protobuf.json_format import MessageToDict

    return MessageToDict(struct) if struct is not None else {}


def b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def verify_token(raw: str, trusted_issuers: set[str]) -> tuple[dict | None, str]:
    try:
        capability = json.loads(b64url_decode(raw))
    except (ValueError, UnicodeDecodeError):
        return None, "token_malformed"
    try:
        message = capability_signing_body_canonical_json(capability).encode("utf-8")
        issuer = bytes.fromhex(capability["issuer"])
        signature = bytes.fromhex(capability["signature"])
        Ed25519PublicKey.from_public_bytes(issuer).verify(signature, message)
    except Exception:  # noqa: BLE001 - spike: any verification failure denies
        return None, "token_signature_invalid"
    if trusted_issuers and capability["issuer"] not in trusted_issuers:
        return None, "token_issuer_untrusted"
    now = int(time.time())
    if not capability["issued_at"] <= now < capability["expires_at"]:
        return None, "token_expired"
    return capability, "ok"


def authorize_tool_call(capability: dict, tool: str, arguments: dict) -> tuple[bool, str]:
    for grant in capability.get("scope", {}).get("grants", []):
        if grant.get("tool_name") not in (tool, "*"):
            continue
        ok = True
        for constraint in grant.get("constraints", []):
            if constraint.get("type") == "path_prefix":
                path = str(arguments.get("path", ""))
                if not path.startswith(constraint.get("value", "")):
                    ok = False
        if ok:
            return True, "granted"
        return False, "argument_constraint_violation"
    return False, "tool_not_granted"


def sign_receipt(body: dict) -> dict:
    canonical = canonicalize_json(body)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    receipt_id = "rcpt_" + digest[:32]
    signature = KERNEL_KEY.sign(canonical.encode("utf-8")).hex()
    return {"id": receipt_id, "body": body, "signature": signature}


class Middleware(pbg.SupervisorMiddlewareServicer):
    def __init__(self, logger: Logger, receipts: Logger, max_payload: int) -> None:
        self.logger = logger
        self.receipts = receipts
        self.max_payload = max_payload

    def Describe(self, request, context):  # noqa: N802
        self.logger.write(
            {
                "rpc": "Describe",
                "gateway": {
                    "impl": request.gateway.implementation_name,
                    "version": request.gateway.implementation_version,
                    "protocol": [
                        request.gateway.protocol_version.major,
                        request.gateway.protocol_version.minor,
                    ],
                    "supported": list(request.gateway.supported_capabilities),
                    "required": list(request.gateway.required_capabilities),
                },
                "auth": dict(context.invocation_metadata()).get("authorization", "")[:40],
            }
        )
        contract = "openshell.supervisor-middleware.contract"
        return pb.MiddlewareManifest(
            name="chio-spike",
            bindings=[
                pb.MiddlewareBinding(
                    operation=pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
                    phase=pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
                    max_payload_bytes=self.max_payload,
                ),
                pb.MiddlewareBinding(
                    operation=pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE,
                    phase=pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN,
                    max_payload_bytes=self.max_payload,
                ),
            ],
            extension=ext.PeerMetadata(
                protocol_version=ext.ProtocolVersion(major=1, minor=0),
                implementation_name="chio/openshell-middleware-spike",
                implementation_version="0.0.1",
                supported_capabilities=[contract],
                required_capabilities=[contract],
            ),
        )

    def ValidateConfig(self, request, context):  # noqa: N802
        self.logger.write(
            {"rpc": "ValidateConfig", "name": request.middleware_name, "config": struct_to_dict(request.config)}
        )
        return pb.ValidateConfigResponse(valid=True)

    def EvaluateHttpRequest(self, request, context):  # noqa: N802
        started = time.perf_counter()
        ctl = control()
        if ctl.get("sleep_ms"):
            time.sleep(ctl["sleep_ms"] / 1000.0)
        if ctl.get("crash"):
            os._exit(17)
        config = struct_to_dict(request.config)
        if (ctl.get("mode_override") or config.get("mode")) == "null":
            return pb.HttpRequestResult(decision=pb.DECISION_ALLOW)
        headers = [(h.name, h.value) for h in request.headers]
        header_map = {}
        for name, value in headers:
            header_map.setdefault(name, value)
        ctxt = request.context
        record = {
            "rpc": "EvaluateHttpRequest",
            "phase": request.phase,
            "middleware_name": request.middleware_name,
            "config": config,
            "context": {
                "request_id": ctxt.request_id,
                "sandbox_id": ctxt.sandbox_id,
                "sandbox": ctxt.sandbox,
                "workspace": ctxt.workspace,
                "originating_process_present": ctxt.HasField("originating_process"),
                "originating_process": {
                    "binary": ctxt.originating_process.binary,
                    "pid": ctxt.originating_process.pid,
                    "ancestors": list(ctxt.originating_process.ancestors),
                },
            },
            "target": {
                "scheme": request.target.scheme,
                "host": request.target.host,
                "port": request.target.port,
                "method": request.target.method,
                "path": request.target.path,
                "query": request.target.query,
            },
            "header_names": [name for name, _ in headers],
            "chio_header_values": {name: value[:48] for name, value in headers if name.startswith("x-chio-")},
            "policy_ref": config.get("policy_ref"),
            "body_len": len(request.body),
            "body_sha256": hashlib.sha256(request.body).hexdigest(),
            "grpc_metadata_keys": sorted(k for k, _ in context.invocation_metadata()),
            "authorization_metadata_prefix": dict(context.invocation_metadata()).get("authorization", "")[:24],
        }
        mode = ctl.get("mode_override") or config.get("mode", "chio")
        decision = pb.DECISION_ALLOW
        reason_code = ""
        tool = None
        arguments: dict = {}
        verdict = "allow"
        detail = "passthrough"
        if mode == "chio":
            token = header_map.get("x-chio-capability-token")
            record["token_present"] = token is not None
            record["token_len"] = len(token) if token else 0
            try:
                message = json.loads(request.body) if request.body else {}
            except ValueError:
                message = {}
            if isinstance(message, dict):
                record["jsonrpc_method"] = message.get("method")
                if message.get("method") == "tools/call":
                    params = message.get("params") or {}
                    tool = params.get("name")
                    arguments = params.get("arguments") or {}
                    record["tool"] = tool
                    record["arguments"] = arguments
            if tool is not None or config.get("require_token_for_all"):
                if token is None:
                    verdict, detail = "deny", "token_missing"
                else:
                    capability, status = verify_token(token, set(config.get("trusted_issuers", [])))
                    if capability is None:
                        verdict, detail = "deny", status
                    elif tool is not None:
                        allowed, why = authorize_tool_call(capability, tool, arguments)
                        verdict, detail = ("allow" if allowed else "deny"), why
                    record["capability_id"] = capability["id"] if capability else None
        elif mode == "deny":
            verdict, detail = "deny", "configured_deny"
        receipt = sign_receipt(
            {
                "decision": verdict,
                "detail": detail,
                "tool": tool,
                "openshell_request_id": ctxt.request_id,
                "openshell_sandbox_id": ctxt.sandbox_id,
                "target": f"{request.target.scheme}://{request.target.host}:{request.target.port}{request.target.path}",
                "body_sha256": record["body_sha256"],
                "issued_at": int(time.time()),
            }
        )
        self.receipts.write(receipt)
        receipt_code = "chio_" + receipt["id"][5:37]
        result = pb.HttpRequestResult(decision=pb.DECISION_ALLOW)
        result.findings.append(
            pb.Finding(type="chio.receipt", label=receipt["id"], count=1, confidence="high", severity="low")
        )
        result.metadata["chio_receipt_id"] = receipt["id"]
        result.metadata["chio_verdict"] = verdict
        result.reason = f"chio receipt {receipt['id']} verdict {verdict} {detail}"
        if verdict == "deny":
            result.decision = pb.DECISION_DENY
            result.reason_code = receipt_code if config.get("reason_code_receipt", True) else detail
        else:
            if config.get("reason_code_on_allow"):
                result.reason_code = receipt_code
            result.header_mutations.append(
                pb.HeaderMutation(
                    write=pb.WriteHeader(
                        name="x-chio-receipt-id",
                        value=receipt["id"],
                        on_existing=pb.EXISTING_HEADER_ACTION_OVERWRITE,
                    )
                )
            )
            if config.get("strip_token", True):
                result.header_mutations.append(
                    pb.HeaderMutation(remove=pb.RemoveHeader(name="x-chio-capability-token"))
                )
        record["verdict"] = verdict
        record["detail"] = detail
        record["receipt_id"] = receipt["id"]
        record["reason_code"] = result.reason_code
        record["mw_elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
        self.logger.write(record)
        return result

    def EvaluateWebSocketSession(self, request_iterator, context):  # noqa: N802
        for event in request_iterator:
            if event.HasField("preflight"):
                yield pb.WebSocketSessionEventResult(
                    preflight_decision=pb.WebSocketPreflightDecision(action=pb.WEB_SOCKET_PREFLIGHT_ACTION_SKIP)
                )
                return


class ResponseMiddleware(pbg.HttpResponsePreReturnServicer):
    def __init__(self, logger: Logger) -> None:
        self.logger = logger

    def Evaluate(self, request_iterator, context):  # noqa: N802
        for event in request_iterator:
            kind = event.WhichOneof("event")
            if kind == "preflight":
                pre = event.preflight
                self.logger.write(
                    {
                        "rpc": "HttpResponsePreReturn.preflight",
                        "request_id": pre.context.request_id,
                        "status": pre.status_code,
                        "header_names": [h.name for h in pre.headers],
                        "permitted_modes": list(pre.permitted_body_modes),
                        "originating_process_present": pre.context.HasField("originating_process"),
                    }
                )
                yield pb.HttpResponseEventResult(
                    preflight_result=pb.HttpResponsePreflightResult(skip=pb.HttpResponsePreflightSkip())
                )
            elif kind == "session_end":
                return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0:50071")
    parser.add_argument("--log", default=os.path.join(HERE, "mw.jsonl"))
    parser.add_argument("--receipts", default=os.path.join(HERE, "receipts.jsonl"))
    parser.add_argument("--max-payload", type=int, default=MAX_PAYLOAD)
    parser.add_argument("--workers", type=int, default=32)
    args = parser.parse_args()
    logger = Logger(args.log)
    receipts = Logger(args.receipts)
    options = [
        ("grpc.max_receive_message_length", 5 * 1024 * 1024),
        ("grpc.max_send_message_length", 5 * 1024 * 1024),
    ]
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=args.workers), options=options)
    pbg.add_SupervisorMiddlewareServicer_to_server(Middleware(logger, receipts, args.max_payload), server)
    pbg.add_HttpResponsePreReturnServicer_to_server(ResponseMiddleware(logger), server)
    server.add_insecure_port(args.bind)
    server.start()
    logger.write({"event": "started", "bind": args.bind, "pid": os.getpid()})
    server.wait_for_termination()


if __name__ == "__main__":
    main()
