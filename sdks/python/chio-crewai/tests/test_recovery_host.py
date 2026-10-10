"""The real Crew dispatches only the native transport, with tool caching disabled."""
import json
import httpx
from crewai import Agent, BaseLLM, Crew, Task
from chio_sdk.recovery_host import RecoveryHostSession
from chio_crewai.recovery import RecoveryTool


class OneAction(BaseLLM):
    def __init__(self):
        super().__init__(model="model-free-adapter-test", temperature=0)
        self.calls = 0
    def supports_function_calling(self):
        return False
    def call(self, messages, **kwargs):
        self.calls += 1
        if self.calls > 1:
            raise RuntimeError("model-free test budget exhausted")
        return 'Thought: Use the owned native command.\nAction: recovery\nAction Input: {"choice":"resume"}'


def test_actual_crew_has_no_fallback_and_retains_no_credentials_or_raw_errors():
    wires = []
    command = b'{"command_id":"native-stable-command"}'
    def transport(request):
        wires.append(json.loads(request.content))
        return httpx.Response(403, text="credential-canary private-provider-error")
    session = RecoveryHostSession("http://localhost:1", "credential-canary", {"resume":command},
                                  transport=httpx.MockTransport(transport), max_tool_actions=1)
    tool = RecoveryTool(session=session)
    llm = OneAction()
    agent = Agent(role="Recovery operator", goal="Use the owned native command",
                  backstory="Public synthetic qualification", llm=llm, tools=[tool],
                  max_iter=2, max_retry_limit=0, cache=False, verbose=False,
                  allow_delegation=False)
    task = Task(description="Invoke recovery with choice resume once.", expected_output="Bounded native category",
                agent=agent)
    crew = Crew(agents=[agent], tasks=[task], cache=False, memory=False, planning=False,
                tracing=False, verbose=False)
    output = crew.kickoff()
    assert json.loads(output.raw)["category"] == "refused"
    assert llm.calls == 1
    assert len(wires) == 1
    assert wires[0]["command"].encode() == command
    assert "canary" not in output.raw
    assert "canary" not in repr(tool)
    assert json.loads(tool.run(choice="resume"))["category"] == "budget_exhausted"
    assert len(wires) == 1
