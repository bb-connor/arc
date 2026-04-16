#!/usr/bin/env python3
"""Provider coordinator: entry point for cross-org provider engagement.

Uses arc_asgi middleware for ARC-governed request evaluation. Every
incoming request is evaluated by the ARC sidecar, and the receipt is
available to the handler via request.state.arc_receipt.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel

from arc_asgi import ArcASGIMiddleware, ArcASGIConfig
from arc_fastapi import get_arc_receipt

from incident_network.capabilities import PublicKey, delegate, from_seed
from incident_network.arc import TrustControl


class ProcessTaskRequest(BaseModel):
    task: dict
    provider_coordinator_seed_hex: str
    provider_executor_public_key: str
    control_url: str
    service_token: str
    provider_executor_url: str
    execute_now: bool = True
    requested_service: str | None = None
    requested_rule: str | None = None
    executed_at: int | None = None
    executor_ttl_seconds: int = 600
    provider_ops_mcp_url: str | None = None
    arc_auth_token: str | None = None


def create_app() -> FastAPI:
    sidecar_url = os.environ.get("ARC_SIDECAR_URL", "http://127.0.0.1:9090")

    app = FastAPI(title="incident-network-provider-coordinator")
    # fail_open=True: receipt attachment without blocking. The coordinator
    # validates capabilities at the application level via trust-control.
    app.add_middleware(
        ArcASGIMiddleware,
        config=ArcASGIConfig(
            sidecar_url=sidecar_url,
            exclude_paths=frozenset({"/health"}),
            fail_open=True,
        ),
    )

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "arc_sidecar": sidecar_url}

    @app.post("/process-task")
    def process_task(payload: ProcessTaskRequest, request: Request) -> dict:
        receipt = getattr(request.state, "arc_receipt", None)
        task = payload.task
        coordinator_capability = task["provider_coordinator_capability"]

        coordinator_identity = from_seed(
            "provider-coordinator",
            payload.provider_coordinator_seed_hex,
        )
        executor_ref = PublicKey(
            name="provider-executor",
            pk=payload.provider_executor_public_key,
        )

        executor_capability = delegate(
            parent=coordinator_capability,
            delegator=coordinator_identity,
            delegatee=executor_ref,
            scope={
                "grants": [{
                    "server_id": "provider-ops",
                    "tool_name": "disable_edge_rule",
                    "operations": ["invoke"],
                    "constraints": [
                        {"type": "custom", "value": ["required_service", task["target_service"]]},
                        {"type": "custom", "value": ["required_rule", task["target_rule"]]},
                    ],
                    "maxInvocations": 1,
                    "maxCostPerInvocation": {"units": 500, "currency": "USD"},
                    "maxTotalCost": {"units": 500, "currency": "USD"},
                }],
                "resource_grants": [],
                "prompt_grants": [],
            },
            ttl=payload.executor_ttl_seconds,
            attenuations=[{
                "type": "remove_operation",
                "server_id": "provider-ops",
                "tool_name": "disable_edge_rule",
                "operation": "delegate",
            }],
            cap_id=f"{task['task_id']}-provider-executor",
        )
        trust = TrustControl(payload.control_url, payload.service_token)
        trust.record_lineage(executor_capability, coordinator_capability["id"])

        result: dict = {
            "provider_coordinator_capability_id": coordinator_capability["id"],
            "provider_executor_capability": executor_capability,
            "arc_receipt_id": receipt.id if receipt else None,
        }

        if not payload.execute_now:
            result["delegated"] = True
            return result

        execute_payload: dict = {
            "task": task,
            "capability": executor_capability,
            "control_url": payload.control_url,
            "service_token": payload.service_token,
            "requested_service": payload.requested_service,
            "requested_rule": payload.requested_rule,
            "executed_at": payload.executed_at,
        }
        if payload.provider_ops_mcp_url:
            execute_payload["provider_ops_mcp_url"] = payload.provider_ops_mcp_url
            execute_payload["arc_auth_token"] = payload.arc_auth_token

        execution = httpx.post(
            f"{payload.provider_executor_url.rstrip('/')}/execute",
            json=execute_payload,
            timeout=30.0,
        )
        execution.raise_for_status()
        result["execution"] = execution.json()
        return result

    return app


app = create_app()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8422)
    parser.add_argument("--sidecar-url", default=None)
    args = parser.parse_args()
    if args.sidecar_url:
        os.environ["ARC_SIDECAR_URL"] = args.sidecar_url
    uvicorn.run("coordinator:app", host=args.host, port=args.port, log_level="warning", factory=False)
