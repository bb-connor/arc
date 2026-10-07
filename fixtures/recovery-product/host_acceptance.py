"""Model-free actual-framework/native acceptance, separate from comparative trials."""
from __future__ import annotations
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
from typing import TypedDict
import httpx
from qualification_runtime import disable_telemetry, native_environment, require, wait_endpoint

disable_telemetry()


class NativeTrace(httpx.AsyncBaseTransport):
    """Record only fixed transport categories, never credentials or raw results."""
    def __init__(self, destination: Path):
        self._http = httpx.AsyncHTTPTransport(retries=0)
        self._destination = destination
    async def handle_async_request(self, request):
        response = await self._http.handle_async_request(request)
        data = await response.aread()
        category = "opaque"
        if response.is_success:
            value = json.loads(data)
            category = value.get("status", {}).get("effect", {}).get("kind", "opaque")
        elif data in [b"recovery.authority_denied", b"recovery.unavailable", b"recovery.conflict", b"recovery.invalid_command"]:
            category = data.decode()
        with self._destination.open("a") as file:
            file.write(json.dumps({"http_status":response.status_code, "bytes":len(data), "category":category})+"\n")
        return response
    async def aclose(self):
        await self._http.aclose()


async def graph_case(session, revoked):
    from langgraph.graph import END, START, StateGraph
    from langgraph.checkpoint.memory import InMemorySaver
    from chio_langgraph.recovery import recovery_node
    class State(TypedDict):
        choice: str
        recovery: dict[str, str]
    graph = StateGraph(State)
    graph.add_node("recovery", recovery_node(session))
    graph.add_edge(START, "recovery")
    graph.add_edge("recovery", END)
    app = graph.compile(checkpointer=InMemorySaver())
    config = {"configurable":{"thread_id":"public-native-acceptance"}}
    first = await app.ainvoke({"choice":"resume"}, config)
    replay = await app.ainvoke({"choice":"resume"}, config)
    require(first["recovery"] == replay["recovery"], "host_replay")
    require(first["recovery"]["category"] == "complete", "host_completion")
    require(set(first["recovery"]) == {"category", "command_id", "workflow_id"}, "host_projection")
    await revoked()
    refused = await app.ainvoke({"choice":"resume"}, config)
    require(refused["recovery"] == {"category":"refused"}, "host_revoked")
    for snapshot in app.get_state_history(config):
        require("canary" not in json.dumps(snapshot.values), "host_checkpoint_exposure")
        require("capability" not in json.dumps(snapshot.values), "host_checkpoint_exposure")
    return {"first":first["recovery"], "replay":replay["recovery"], "revoked":refused["recovery"]}


def crew_action(session):
    from crewai import Agent, BaseLLM, Crew, Task
    from chio_crewai.recovery import RecoveryTool
    class OneAction(BaseLLM):
        def __init__(self):
            super().__init__(model="model-free-native-acceptance", temperature=0)
            self.calls = 0
        def supports_function_calling(self):
            return False
        def call(self, messages, **kwargs):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("model-free dispatch bound")
            return 'Thought: Use the owned command.\nAction: recovery\nAction Input: {"choice":"resume"}'
    llm = OneAction()
    tool = RecoveryTool(session=session)
    agent = Agent(role="Recovery operator", goal="Use the selected native command",
                  backstory="Public synthetic qualification", llm=llm, tools=[tool],
                  max_iter=2, max_retry_limit=0, cache=False, verbose=False, allow_delegation=False)
    task = Task(description="Call recovery choice resume exactly once.", expected_output="Native bounded category", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], cache=False, memory=False, planning=False, tracing=False, verbose=False)
    result = crew.kickoff()
    require(llm.calls == 1, "host_model_free_budget")
    require("canary" not in result.raw and "capability" not in result.raw, "host_result_exposure")
    return json.loads(result.raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    from chio_sdk.recovery_host import RecoveryHostSession
    args.evidence.mkdir(parents=True, exist_ok=True)
    results = []
    for framework in ["langgraph", "crewai"]:
        exchange = args.evidence / framework
        exchange.mkdir(mode=0o700, parents=True, exist_ok=False)
        log = (exchange / "native-host.log").open("wb")
        environment = native_environment("CHIO_RECOVERY_HOST_EXCHANGE", exchange)
        environment["CARGO_INCREMENTAL"] = "0"
        try:
            process = subprocess.Popen(["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib",
                "native_framework_qualification_host", "--", "--ignored", "--nocapture", "--test-threads=1"],
                cwd=args.checkout, env=environment, stdout=log, stderr=subprocess.STDOUT)
        except BaseException:
            log.close()
            raise
        def wait(name):
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if (exchange/name).is_file():
                    return
                if process.poll() is not None:
                    raise RuntimeError("native framework fixture terminated")
                time.sleep(0.05)
            raise TimeoutError("native fixture phase deadline")
        try:
            endpoint = wait_endpoint(exchange/"ready", process, 180, fixed_port=20096)
            session = RecoveryHostSession(endpoint, (exchange/"capability.json").read_text(),
                {"resume":(exchange/"command.json").read_bytes()}, max_tool_actions=3, timeout_seconds=120,
                transport=NativeTrace(exchange/"transport.jsonl"))
            def revoke():
                (exchange/"revoke").touch()
                wait("revoked")
            if framework == "langgraph":
                async def revoked():
                    await asyncio.to_thread(revoke)
                outputs = asyncio.run(graph_case(session, revoked))
            else:
                first = crew_action(session)
                replay = crew_action(session)
                require(first == replay and first["category"] == "complete", "host_replay")
                revoke()
                refused = crew_action(session)
                require(refused == {"category":"refused"}, "host_revoked")
                outputs = {"first":first, "replay":replay, "revoked":refused}
            require(session.attempts == 3, "host_tool_budget")
            (exchange/"finish").touch()
            status = process.wait(timeout=90)
            require(status == 0, "host_native_execution")
            native = json.loads((exchange/"native-evidence.json").read_bytes())
            require(native["workload_effects"] == 1 and native["effects"] == 2 and native["revoked"] is True,
                    "host_native_facts")
            results.append({"framework":framework, "outputs":outputs, "native":native, "tool_actions":session.attempts})
        finally:
            if process.poll() is None:
                (exchange/"finish").touch()
                process.wait(timeout=30)
            log.close()
    (args.evidence/"result.json").write_text(json.dumps({"passed":True, "cases":results}, indent=2)+"\n")
    print("Actual LangGraph/CrewAI native benign, identical replay and revoked replay passed")


if __name__ == "__main__":
    main()
