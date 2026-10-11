"""Pure, deterministic decoding of a retained broker Chat Completions body."""

import math


def response_policy(config):
    return {
        key: config[key]
        for key in ("max_output_tokens", "input_usd_per_million", "output_usd_per_million")
    }


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {
        "max_output_tokens",
        "input_usd_per_million",
        "output_usd_per_million",
    }:
        raise ValueError("Explicit provider response policy is required")
    if (
        type(policy["max_output_tokens"]) is not int
        or not 1 <= policy["max_output_tokens"] <= 32768
    ):
        raise ValueError("Invalid output token bound")
    for key in ("input_usd_per_million", "output_usd_per_million"):
        if (
            type(policy[key]) not in (int, float)
            or not math.isfinite(policy[key])
            or not 0 <= policy[key] <= 10000
        ):
            raise ValueError("Invalid provider token price")
    return dict(policy)


def parse_completion(raw, policy):
    from minisweagent.exceptions import FormatError
    from minisweagent.models.utils.actions_toolcall import parse_toolcall_actions
    from openai.types.chat import ChatCompletion

    policy = validate_policy(policy)
    result = ChatCompletion.model_validate(raw)
    if len(result.choices) != 1 or result.choices[0].finish_reason not in {"tool_calls", "stop"}:
        raise ValueError("Provider did not complete one decision")
    usage = raw.get("usage")
    if not isinstance(usage, dict):
        raise ValueError("Provider usage is required")
    for name in ("prompt_tokens", "completion_tokens"):
        if type(usage.get(name)) is not int or not 0 <= usage[name] <= 2**31:
            raise ValueError("Invalid provider token usage")
    if usage["completion_tokens"] > policy["max_output_tokens"]:
        raise ValueError("Provider exceeded its token limit")
    cost = (
        usage["prompt_tokens"] * policy["input_usd_per_million"]
        + usage["completion_tokens"] * policy["output_usd_per_million"]
    ) / 1_000_000
    # The provider's retained creation time keeps recovery deterministic.
    if type(raw.get("created")) is not int or not 0 <= raw["created"] < 2**53:
        raise ValueError("Invalid provider creation time")
    extra = {"cost": cost, "usage": usage, "timestamp": raw["created"]}
    message = result.choices[0].message.model_dump(exclude_none=True)
    try:
        actions = parse_toolcall_actions(
            result.choices[0].message.tool_calls or [], format_error_template="{{error}}"
        )
    except FormatError as error:
        error.messages[0].setdefault("extra", {}).update(extra)
        error.messages[0]["extra"]["response"] = raw
        raise
    message["extra"] = {"actions": actions, **extra}
    return message
