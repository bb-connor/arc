"""Procurement agent: reasons about security review procurement using the Agents SDK."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

log = logging.getLogger("commerce-network")


PROCUREMENT_PROMPT = """\
You are a procurement agent for a platform security team. Your job is to
procure security reviews from an external provider through a governed API.

Available tools:
- request_quote: Submit a quote request for a security review scope
- create_job: Accept a quote and create a governed job (will check budget)
- approve_job: Approve a job that exceeds the auto-approval threshold
- get_job: Check the status of a job
- dispute_job: Open a dispute if the review quality is insufficient

Workflow:
1. Request a quote for the specified scope and target
2. Evaluate the quote (price, scope match, approval requirements)
3. Create a job to accept the quote (set budget appropriately)
4. If approval is required, approve the job with justification
5. Check the job status to confirm fulfillment
6. If the review has issues, consider disputing

Respond with JSON:
{
  "quote_id": "...",
  "job_id": "...",
  "final_status": "fulfilled|denied_budget|disputed|pending_approval",
  "price_minor": <int>,
  "currency": "USD",
  "rationale": "why you made these decisions"
}"""

FALLBACK_OUTPUT = {
    "final_status": "fulfilled",
    "rationale": "deterministic fallback -- no API key set",
}


def _get_provider() -> str:
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "fallback"


def run_procurement_agent(
    *,
    buyer_url: str,
    auth_token: str,
    capability_token: dict | None = None,
    scope: str,
    target: str,
    budget_minor: int,
    release_window: str | None = None,
    max_turns: int = 10,
) -> dict[str, Any]:
    """Run the procurement agent. Uses Agents SDK, Anthropic, or fallback."""
    provider = _get_provider()
    http = httpx.Client(timeout=30.0)
    call_log: list[dict] = []

    # Serialize capability token for the Chio sidecar header
    cap_header = json.dumps(capability_token, separators=(",", ":")) if capability_token else None

    def _call_buyer(method: str, path: str, body: dict | None = None) -> dict:
        headers: dict[str, str] = {"Authorization": f"Bearer {auth_token}"}
        if cap_header:
            headers["X-Chio-Capability"] = cap_header
        if method == "GET":
            r = http.get(f"{buyer_url}{path}", headers=headers)
        else:
            r = http.post(f"{buyer_url}{path}", headers=headers, json=body)
        r.raise_for_status()
        return r.json()

    def request_quote(service_family: str = "security-review", target: str = target,
                      requested_scope: str = scope, release_window: str | None = release_window) -> dict:
        return _call_buyer("POST", "/procurement/quote-requests", {
            "service_family": service_family, "target": target,
            "requested_scope": requested_scope, "release_window": release_window,
        })

    def create_job(quote_id: str, provider_id: str = "vanguard-security",
                   service_family: str = "security-review", budget_minor: int = budget_minor) -> dict:
        return _call_buyer("POST", "/procurement/jobs", {
            "quote_id": quote_id, "provider_id": provider_id,
            "service_family": service_family, "budget_minor": budget_minor,
        })

    def approve_job(job_id: str, approver: str = "procurement-agent", reason: str = "auto-approved") -> dict:
        return _call_buyer("POST", f"/procurement/jobs/{job_id}/approve", {
            "approver": approver, "reason": reason,
        })

    def get_job(job_id: str) -> dict:
        return _call_buyer("GET", f"/procurement/jobs/{job_id}")

    def dispute_job(job_id: str, reason_code: str = "quality", summary: str = "insufficient findings") -> dict:
        return _call_buyer("POST", f"/procurement/jobs/{job_id}/disputes", {
            "reason_code": reason_code, "summary": summary,
        })

    if provider == "fallback":
        return _fallback_flow(request_quote, create_job, approve_job, get_job, call_log, scope)

    if provider == "openai":
        return _agents_sdk_flow(
            request_quote, create_job, approve_job, get_job, dispute_job,
            call_log, scope, target, budget_minor, max_turns,
        )

    return _anthropic_flow(
        request_quote, create_job, approve_job, get_job, dispute_job,
        call_log, scope, target, budget_minor, max_turns,
    )


def _fallback_flow(request_quote, create_job, approve_job, get_job, call_log, scope):
    """Deterministic flow for CI -- no LLM needed."""
    log.info("[procurement] fallback mode")
    quote_resp = request_quote(requested_scope=scope)
    call_log.append({"tool": "request_quote", "output": quote_resp})

    quote = quote_resp["quote"]
    job_resp = create_job(quote_id=quote["quote_id"])
    call_log.append({"tool": "create_job", "output": job_resp})

    if job_resp["status"] == "pending_approval":
        job_resp = approve_job(job_id=job_resp["job_id"], reason="within policy for hotfix scope")
        call_log.append({"tool": "approve_job", "output": job_resp})

    return {
        "quote_id": quote["quote_id"],
        "job_id": job_resp["job_id"],
        "final_status": job_resp["status"],
        "price_minor": quote["price_minor"],
        "currency": quote.get("currency", "USD"),
        "rationale": "deterministic fallback",
        "mode": "fallback",
        "tool_calls": call_log,
    }


def _agents_sdk_flow(request_quote, create_job, approve_job, get_job, dispute_job,
                     call_log, scope, target, budget_minor, max_turns):
    """Run via OpenAI Agents SDK."""
    try:
        from agents import Agent, FunctionTool, Runner
    except ImportError:
        log.warning("openai-agents not installed, using fallback")
        return _fallback_flow(request_quote, create_job, approve_job, get_job, call_log, scope)

    def _wrap(fn, name, desc, schema):
        async def invoke(ctx, args_json):
            args = json.loads(args_json) if args_json else {}
            log.info("[procurement] %s(%s)", name, json.dumps(args)[:200])
            try:
                out = fn(**args)
            except Exception as exc:
                out = {"error": str(exc)}
            call_log.append({"tool": name, "input": args, "output": out})
            return json.dumps(out)
        return FunctionTool(name=name, description=desc, params_json_schema=schema,
                           on_invoke_tool=invoke, strict_json_schema=False)

    tools = [
        _wrap(request_quote, "request_quote", "Request a security review quote", {
            "type": "object",
            "properties": {
                "requested_scope": {"type": "string", "enum": ["hotfix-review", "release-review", "release-plus-cloud-review", "full-estate-review"]},
                "target": {"type": "string"},
                "service_family": {"type": "string", "default": "security-review"},
            },
            "required": ["requested_scope", "target"],
        }),
        _wrap(create_job, "create_job", "Accept a quote and create a governed procurement job", {
            "type": "object",
            "properties": {
                "quote_id": {"type": "string"},
                "budget_minor": {"type": "integer", "description": "Budget in minor currency units (cents)"},
                "provider_id": {"type": "string", "default": "vanguard-security"},
                "service_family": {"type": "string", "default": "security-review"},
            },
            "required": ["quote_id"],
        }),
        _wrap(approve_job, "approve_job", "Approve a job that requires approval", {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "approver": {"type": "string", "default": "procurement-agent"},
                "reason": {"type": "string"},
            },
            "required": ["job_id", "reason"],
        }),
        _wrap(get_job, "get_job", "Check job status", {
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
        }),
        _wrap(dispute_job, "dispute_job", "Open a dispute against a fulfilled review", {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "reason_code": {"type": "string"},
                "summary": {"type": "string"},
            },
            "required": ["job_id", "reason_code", "summary"],
        }),
    ]

    agent = Agent(
        name="procurement-agent",
        instructions=PROCUREMENT_PROMPT,
        tools=tools,
        model=os.getenv("OPENAI_MODEL", "gpt-4.1"),
    )

    user_msg = json.dumps({
        "task": "procure a security review",
        "scope": scope, "target": target,
        "budget_minor": budget_minor,
    })

    try:
        result = Runner.run_sync(agent, user_msg, max_turns=max_turns)
    except Exception as exc:
        log.error("[procurement] agents SDK error: %s", exc)
        return {**FALLBACK_OUTPUT, "mode": "fallback", "error": str(exc), "tool_calls": call_log}

    raw = result.final_output or ""
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        parsed = {**FALLBACK_OUTPUT, "raw_text": raw}
    if isinstance(parsed, dict):
        parsed["mode"] = "openai_agents_sdk"
        parsed["tool_calls"] = call_log
    return parsed


def _anthropic_flow(request_quote, create_job, approve_job, get_job, dispute_job,
                    call_log, scope, target, budget_minor, max_turns):
    """Anthropic SDK with manual tool loop."""
    try:
        import anthropic
    except ImportError:
        return _fallback_flow(request_quote, create_job, approve_job, get_job, call_log, scope)

    tool_fns = {
        "request_quote": request_quote, "create_job": create_job,
        "approve_job": approve_job, "get_job": get_job, "dispute_job": dispute_job,
    }
    api_tools = [
        {"name": "request_quote", "description": "Request a security review quote",
         "input_schema": {"type": "object", "properties": {"requested_scope": {"type": "string"}, "target": {"type": "string"}}, "required": ["requested_scope", "target"]}},
        {"name": "create_job", "description": "Accept a quote and create a job",
         "input_schema": {"type": "object", "properties": {"quote_id": {"type": "string"}, "budget_minor": {"type": "integer"}}, "required": ["quote_id"]}},
        {"name": "approve_job", "description": "Approve a pending job",
         "input_schema": {"type": "object", "properties": {"job_id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["job_id", "reason"]}},
        {"name": "get_job", "description": "Check job status",
         "input_schema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
        {"name": "dispute_job", "description": "Dispute a fulfilled review",
         "input_schema": {"type": "object", "properties": {"job_id": {"type": "string"}, "reason_code": {"type": "string"}, "summary": {"type": "string"}}, "required": ["job_id", "reason_code", "summary"]}},
    ]

    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": json.dumps({"task": "procure a security review", "scope": scope, "target": target, "budget_minor": budget_minor})}]

    for _ in range(max_turns):
        resp = client.messages.create(
            model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=4096, system=PROCUREMENT_PROMPT,
            tools=api_tools, messages=messages,
        )
        if resp.stop_reason != "tool_use":
            raw = "\n".join(b.text for b in resp.content if b.type == "text")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {**FALLBACK_OUTPUT, "raw_text": raw}
            parsed["mode"] = "anthropic"
            parsed["tool_calls"] = call_log
            return parsed

        asst, results = [], []
        for block in resp.content:
            if block.type == "tool_use":
                fn = tool_fns.get(block.name)
                try:
                    out = fn(**block.input) if fn else {"error": f"unknown tool: {block.name}"}
                except Exception as exc:
                    out = {"error": str(exc)}
                call_log.append({"tool": block.name, "input": block.input, "output": out})
                asst.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(out)})
            elif block.type == "text":
                asst.append({"type": "text", "text": block.text})
        messages.append({"role": "assistant", "content": asst})
        messages.append({"role": "user", "content": results})

    return {**FALLBACK_OUTPUT, "mode": "fallback_max_turns", "tool_calls": call_log}
