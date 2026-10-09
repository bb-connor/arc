"""CrewAI transport to the native recovery owner, without local tool fallback."""
from __future__ import annotations
import json
from typing import Annotated
from crewai.tools import BaseTool
from crewai.tools.structured_tool import CrewStructuredTool
from pydantic import BaseModel, ConfigDict, PrivateAttr, StringConstraints
from chio_sdk.recovery_host import RecoveryHostSession


def _disable_recovery_cache(*_args: object) -> bool:
    return False


class RecoveryChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    choice: Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


class _RecoveryStructuredTool(CrewStructuredTool):
    """Discard reserved framework metadata before closed choice validation."""

    def _parse_args(self, raw_args: str | dict) -> dict:
        if type(raw_args) is str:
            try:
                if len(raw_args) > 32768 or len(raw_args.encode("utf-8")) > 32768:
                    raise ValueError("recovery.invalid_choice")
                arguments = json.loads(raw_args)
            except (ValueError, RecursionError):
                raise ValueError("recovery.invalid_choice") from None
        elif type(raw_args) is dict:
            arguments = raw_args
        else:
            raise ValueError("recovery.invalid_choice")
        if (type(arguments) is not dict or len(arguments) > 2
                or any(type(key) is not str for key in arguments)
                or any(key not in {"choice", "security_context"} for key in arguments)):
            raise ValueError("recovery.invalid_choice")
        choice = arguments.get("choice")
        if type(choice) is not str or not 1 <= len(choice) <= 64:
            raise ValueError("recovery.invalid_choice")
        # Context is deliberately opaque and supplies no Chio authority.
        # Do not traverse, retain, stringify or forward its value.
        try:
            return RecoveryChoice.model_validate({"choice": choice}).model_dump()
        except ValueError:
            raise ValueError("recovery.invalid_choice") from None


class RecoveryTool(BaseTool):
    """Use with Crew(cache=False, memory=False, planning=False, tracing=False).

    Stable native command bytes and capability remain private. The model selects
    a task-owned choice; it cannot approve a report or issue new authority.
    """
    name: str = "recovery"
    description: str = "Submit one selected native recovery command. Input: choice. Return: closed native state, error codes and opaque references."
    args_schema: type[BaseModel] = RecoveryChoice
    _session: RecoveryHostSession = PrivateAttr()

    def __init__(self, *, session: RecoveryHostSession):
        super().__init__(cache_function=_disable_recovery_cache, max_usage_count=8, result_as_answer=True)
        self._session = session

    def to_structured_tool(self) -> CrewStructuredTool:
        structured = _RecoveryStructuredTool(
            name=self.name, description=self.description,
            args_schema=RecoveryChoice, func=self._run,
            result_as_answer=self.result_as_answer,
            max_usage_count=self.max_usage_count,
            current_usage_count=self.current_usage_count,
        )
        structured._original_tool = self
        return structured

    def _run(self, choice: str) -> str:
        outcome = self._session.execute_sync(choice)
        return json.dumps(outcome.as_dict(), sort_keys=True, separators=(",", ":"))

    async def _arun(self, choice: str) -> str:
        outcome = await self._session.execute(choice)
        return json.dumps(outcome.as_dict(), sort_keys=True, separators=(",", ":"))
