"""Front matter: `key: <json value>` lines between `---` fences, then a body."""

from __future__ import annotations

import json

FENCE = "---"


class FrontMatterError(ValueError):
    pass


def parse(text: str) -> tuple[dict, str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\n") != FENCE:
        raise FrontMatterError("missing opening ---")
    meta: dict = {}
    for index, raw in enumerate(lines[1:], start=1):
        line = raw.rstrip("\n")
        if line == FENCE:
            return meta, "".join(lines[index + 1 :])
        key, sep, value = line.partition(": ")
        if not sep or not key:
            raise FrontMatterError(f"line {index + 1}: expected 'key: value', got {line!r}")
        try:
            meta[key] = json.loads(value)
        except json.JSONDecodeError as err:
            raise FrontMatterError(f"line {index + 1}: value for {key!r} is not JSON: {err}") from err
    raise FrontMatterError("missing closing ---")


def dump(meta: dict, body: str) -> str:
    head = "".join(f"{key}: {json.dumps(value, ensure_ascii=False)}\n" for key, value in meta.items())
    return f"{FENCE}\n{head}{FENCE}\n{body}"
