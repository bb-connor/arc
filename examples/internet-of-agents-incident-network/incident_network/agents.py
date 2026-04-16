"""Agent definitions, system prompts, and runner dispatch."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from incident_network.arc import ArcMcpClient, StdioMcpClient

log = logging.getLogger("incident-network")

McpClient = ArcMcpClient | StdioMcpClient

# -- System prompts -----------------------------------------------------------

PROMPTS: dict[str, str] = {
    "triage-agent": """\
You are the triage agent for a live production incident. Investigate using
the observability, git, and PagerDuty tools available to you.

Strategy:
1. get_incident_summary -- understand symptoms
2. query_spans -- find elevated error rates, unusual status codes, latency spikes
3. get_deploy_timeline -- correlate with recent deployments
4. search_commits -- find config or code changes near symptom onset
5. get_oncall_state -- responder context

Respond with JSON:
{
  "incident_summary": "...",
  "root_cause": "...",
  "suspected_rule": "...",
  "evidence": ["..."],
  "recommended_action": "...",
  "confidence": "high|medium|low"
}

Cite trace IDs, commit SHAs, and error messages. Recommend the narrowest fix.""",

    "change-agent": """\
You are the change planning agent. Given triage findings, propose remediation.
You have no tools -- reason from the triage output.

Respond with JSON:
{
  "rollback_option": "narrowest fix",
  "rollback_risk": "what could go wrong",
  "broader_option": "wider rollback if narrow fix fails",
  "broader_option_requires_approval": true/false,
  "reason": "why broader needs approval",
  "recommendation": "which option and why"
}""",

    "commander-agent": """\
You are the commander agent. Given triage findings and change proposals, decide:
1. Execute narrow fix internally
2. Engage external provider for bounded remediation
3. Escalate for broader rollback (requires approval)

Respond with JSON:
{
  "decision": "engage_external_provider|internal_fix|escalate_for_approval",
  "reason": "...",
  "scope_constraint": "what the provider may do"
}""",

    "vendor-liaison-agent": """\
You are the vendor liaison. Convert the commander decision into a bounded
task specification for the external provider.

Respond with JSON:
{
  "task_title": "...",
  "target_service": "exact service name",
  "target_rule": "exact rule name",
  "bounded_action": "disable_rule|modify_rule|...",
  "provider_instructions": "precise instructions"
}""",
}

# -- Fallback outputs (CI / offline mode) -------------------------------------

FALLBACKS: dict[str, dict[str, Any]] = {
    "triage-agent": {
        "incident_summary": (
            "Inference gateway returning 403 for legitimate requests from "
            "eu-west-1 and ap-southeast-1 after edge rule geo-restrict-v42 "
            "was promoted from dry-run to blocking mode."
        ),
        "root_cause": "geo-restrict-v42 blocking legitimate inference traffic",
        "suspected_rule": "geo-restrict-v42",
        "evidence": [
            "5xx/403 spike correlates with deploy d-20260415-0902",
            "Trace spans show edge_rule_evaluation returning BLOCK for geo-restrict-v42",
            "Commit a3f7c91 changed geo-restrict-v42 from dry-run to blocking",
        ],
        "recommended_action": "Disable geo-restrict-v42 on inference-gateway via provider",
        "confidence": "high",
    },
    "change-agent": {
        "rollback_option": "disable geo-restrict-v42 for inference-gateway only",
        "rollback_risk": "minimal -- dry-run showed no true positives",
        "broader_option": "global edge rule rollback across all services",
        "broader_option_requires_approval": True,
        "reason": "global rollback affects rate-limiting and bot-protection on other services",
        "recommendation": "narrow disable is sufficient based on triage evidence",
    },
    "commander-agent": {
        "decision": "engage_external_provider",
        "reason": "provider-managed edge rule; customer cannot disable directly",
        "scope_constraint": "disable geo-restrict-v42 on inference-gateway only",
    },
    "vendor-liaison-agent": {
        "task_title": "Disable geo-restrict-v42 on inference-gateway",
        "target_service": "inference-gateway",
        "target_rule": "geo-restrict-v42",
        "bounded_action": "disable_rule",
        "provider_instructions": (
            "Disable edge rule geo-restrict-v42 for inference-gateway only. "
            "Do not modify other rules. Report evidence of the change."
        ),
    },
}


# -- Tool-to-client mapping ---------------------------------------------------

def _map_tools(
    mcp_clients: dict[str, McpClient],
    tool_defs: list[dict[str, Any]],
) -> dict[str, McpClient]:
    m: dict[str, McpClient] = {}
    for c in mcp_clients.values():
        try:
            for t in c.list_tools():
                m[t["name"]] = c
        except Exception:
            pass
    for t in tool_defs:
        if t["name"] not in m:
            for c in mcp_clients.values():
                m.setdefault(t["name"], c)
    return m


# -- Public entry point -------------------------------------------------------

def run_agent(
    role: str,
    user_message: str,
    *,
    mcp_clients: dict[str, McpClient] | None = None,
    tools: list[dict[str, Any]] | None = None,
    max_turns: int = 10,
) -> dict[str, Any]:
    """Run an agent. Dispatches to Agents SDK, Anthropic, or fallback."""
    mcp_clients = mcp_clients or {}
    tools = tools or []
    prompt = PROMPTS.get(role, f"You are {role}. Respond with JSON.")
    fallback = FALLBACKS.get(role, {"role": role, "status": "fallback"})

    provider = _get_provider()
    if provider == "fallback":
        log.info("[%s] no API key, using fallback", role)
        return {**fallback, "role": role, "mode": "fallback"}

    tool_map = _map_tools(mcp_clients, tools)

    if provider == "openai":
        return _openai(role, prompt, user_message, tools, tool_map, fallback, max_turns)
    return _anthropic(role, prompt, user_message, tools, tool_map, fallback, max_turns)


def _get_provider() -> str:
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "fallback"


# -- OpenAI Agents SDK --------------------------------------------------------

def _openai(
    role: str, prompt: str, user_msg: str,
    tool_defs: list[dict], tool_map: dict[str, McpClient],
    fallback: dict, max_turns: int,
) -> dict[str, Any]:
    try:
        from agents import Agent, FunctionTool, Runner
    except ImportError:
        log.warning("[%s] openai-agents not installed", role)
        return {**fallback, "role": role, "mode": "fallback"}

    call_log: list[dict] = []

    sdk_tools = []
    for t in tool_defs:
        client = tool_map.get(t["name"])
        if not client:
            continue
        name = t["name"]

        async def invoke(ctx: Any, args_json: str, _c: McpClient = client, _n: str = name) -> str:
            args = json.loads(args_json) if args_json else {}
            log.info("[%s] %s(%s)", role, _n, json.dumps(args)[:200])
            try:
                out = _c.call_tool(_n, args)
            except Exception as exc:
                out = {"error": str(exc)}
            call_log.append({"tool": _n, "input": args, "output": out})
            return json.dumps(out)

        sdk_tools.append(FunctionTool(
            name=name,
            description=t.get("description", name),
            params_json_schema=t.get("inputSchema", {"type": "object", "properties": {}}),
            on_invoke_tool=invoke,
            strict_json_schema=False,
        ))

    agent = Agent(
        name=role,
        instructions=prompt,
        tools=sdk_tools,
        model=os.getenv("OPENAI_MODEL", "gpt-4.1"),
    )

    try:
        result = Runner.run_sync(agent, user_msg, max_turns=max_turns)
    except Exception as exc:
        log.error("[%s] agents SDK error: %s", role, exc)
        return {**fallback, "role": role, "mode": "fallback", "error": str(exc)}

    return _parse_output(result.final_output, fallback, role, "openai_agents_sdk", call_log)


# -- Anthropic SDK (manual tool loop) ----------------------------------------

def _anthropic(
    role: str, prompt: str, user_msg: str,
    tool_defs: list[dict], tool_map: dict[str, McpClient],
    fallback: dict, max_turns: int,
) -> dict[str, Any]:
    try:
        import anthropic
    except ImportError:
        log.warning("[%s] anthropic not installed", role)
        return {**fallback, "role": role, "mode": "fallback"}

    api_tools = [
        {
            "name": t["name"],
            "description": t.get("description", t["name"]),
            "input_schema": t["inputSchema"],
        }
        for t in tool_defs
    ]
    call_log: list[dict] = []
    client = anthropic.Anthropic()
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    messages: list[dict] = [{"role": "user", "content": user_msg}]

    for turn in range(max_turns):
        resp = client.messages.create(
            model=model, max_tokens=4096, system=prompt,
            tools=api_tools if api_tools else [], messages=messages,
        )
        if resp.stop_reason != "tool_use":
            raw = "\n".join(b.text for b in resp.content if b.type == "text")
            return _parse_output(raw, fallback, role, "anthropic", call_log)

        asst, results = [], []
        for block in resp.content:
            if block.type == "tool_use":
                mc = tool_map.get(block.name)
                try:
                    out = mc.call_tool(block.name, block.input) if mc else {"error": "unknown tool"}
                except Exception as exc:
                    out = {"error": str(exc)}
                call_log.append({"tool": block.name, "input": block.input, "output": out})
                asst.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": json.dumps(out)})
            elif block.type == "text":
                asst.append({"type": "text", "text": block.text})
        messages.append({"role": "assistant", "content": asst})
        messages.append({"role": "user", "content": results})

    return {**fallback, "role": role, "mode": "fallback_max_turns", "tool_calls": call_log}


# -- Output parsing -----------------------------------------------------------

def _parse_output(
    raw: Any, fallback: dict, role: str, mode: str, call_log: list[dict],
) -> dict[str, Any]:
    if isinstance(raw, dict):
        parsed = raw
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            parsed = {**fallback, "raw_text": raw}
    else:
        parsed = {**fallback}
    parsed["role"] = role
    parsed["mode"] = mode
    parsed["tool_calls"] = call_log
    return parsed
