#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from incident_network.capabilities import from_seed, intent_hash, issue_approval


DEFAULT_APPROVER_SEED_HEX = "11" * 32
app = FastAPI(title="incident-network-approval-service")


class ApprovalRequest(BaseModel):
    request_id: str
    subject_public_key: str
    governed_intent: dict
    ttl_seconds: int = 300
    decision: str = "approved"


@app.get("/health")
def health() -> dict:
    approver = from_seed(
        "approval-service",
        os.getenv("APPROVAL_SERVICE_SEED_HEX", DEFAULT_APPROVER_SEED_HEX),
    )
    return {
        "ok": True,
        "approver_public_key": approver.public_key_hex,
    }


@app.post("/approve")
def approve(payload: ApprovalRequest) -> dict:
    approver = from_seed(
        "approval-service",
        os.getenv("APPROVAL_SERVICE_SEED_HEX", DEFAULT_APPROVER_SEED_HEX),
    )
    intent_hash_val = intent_hash(payload.governed_intent)
    token = issue_approval(
        approver=approver,
        subject_pk=payload.subject_public_key,
        intent_hash_val=intent_hash_val,
        request_id=payload.request_id,
        ttl=payload.ttl_seconds,
        decision=payload.decision,
    )
    return {
        "governed_intent_hash": intent_hash_val,
        "approval_token": token,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8424)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
