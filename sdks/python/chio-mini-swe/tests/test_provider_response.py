import copy
import json

import pytest

from chio_mini_swe.provider_response import parse_completion

POLICY = {"max_output_tokens": 128, "input_usd_per_million": 2, "output_usd_per_million": 10}


def completion():
    return {
        "id": "retained",
        "object": "chat.completion",
        "created": 123,
        "model": "selected",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": json.dumps({"command": "printf ok"}),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def test_original_completion_decodes_identically_without_time_or_network():
    raw = completion()
    original = copy.deepcopy(raw)
    first = parse_completion(raw, POLICY)
    assert parse_completion(copy.deepcopy(raw), POLICY) == first
    assert raw == original
    assert first["extra"]["timestamp"] == 123
    assert first["extra"]["cost"] == pytest.approx(0.00022)
    assert first["extra"]["actions"] == [{"command": "printf ok", "tool_call_id": "call-1"}]


@pytest.mark.parametrize(
    "field,value",
    [
        ("prompt_tokens", True),
        ("completion_tokens", 129),
        ("prompt_tokens", -1),
        ("completion_tokens", 0.5),
    ],
)
def test_incomplete_or_malformed_usage_cannot_be_charged_as_a_complete_decision(field, value):
    raw = completion()
    raw["usage"][field] = value
    with pytest.raises(ValueError):
        parse_completion(raw, POLICY)


def test_incomplete_choice_and_mutated_clock_are_rejected():
    for change in (
        lambda raw: raw.update(created=True),
        lambda raw: raw["choices"][0].update(finish_reason="length"),
    ):
        raw = completion()
        change(raw)
        with pytest.raises(ValueError):
            parse_completion(raw, POLICY)
