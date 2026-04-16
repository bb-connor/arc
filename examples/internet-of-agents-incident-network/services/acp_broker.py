#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]

app = FastAPI(title="incident-network-acp-broker")
STATE_DIR = Path(
    os.getenv(
        "INCIDENT_NETWORK_ACP_STATE_DIR",
        str(ROOT / "state" / "acp-broker"),
    )
)


def task_path(task_id: str) -> Path:
    return STATE_DIR / f"{task_id}.json"


def write_task(task: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    task_path(task["task_id"]).write_text(json.dumps(task, indent=2) + "\n", encoding="utf-8")


def read_task(task_id: str) -> dict | None:
    path = task_path(task_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


class CreateTaskRequest(BaseModel):
    incident_id: str
    target_service: str
    target_rule: str
    bounded_action: str
    provider_instructions: str
    vendor_liaison_capability: dict
    execution_deadline: int | None = None


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/tasks")
def create_task(payload: CreateTaskRequest) -> dict:
    task_id = f"acp-task-{uuid.uuid4().hex[:12]}"
    task = {
        "task_id": task_id,
        "status": "created",
        "created_at": int(time.time()),
        **payload.model_dump(),
    }
    write_task(task)
    return task


@app.get("/tasks/{task_id}")
def get_task(task_id: str) -> dict:
    task = read_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@app.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, payload: dict) -> dict:
    task = read_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    verdict = payload.get("execution", {}).get("verdict")
    reason = payload.get("execution", {}).get("reason")
    now = int(time.time())
    deadline = task.get("execution_deadline")
    if verdict == "deny" and reason == "expired_capability":
        task["status"] = "expired"
    elif verdict == "deny" and reason == "revoked_ancestor":
        task["status"] = "revoked"
    elif verdict == "deny":
        task["status"] = "denied"
    elif deadline is not None and now > deadline:
        task["status"] = "expired"
    else:
        task["status"] = "completed"
    task["completed_at"] = now
    task["completion"] = payload
    write_task(task)
    return task


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8421)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
