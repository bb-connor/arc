#!/usr/bin/env python3
"""Validate this specification package; never qualify a runtime or native authority."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
PLANS = ROOT.parents[1] / "plans" / ROOT.name
REPO = ROOT.parents[3]
MAX_BYTES = 65536
MAX_DEPTH = 16
SAFE_INTEGER = 9007199254740991
REQUIREMENT_PREFIXES = {
    "PRD", "UX", "KER", "AUT", "ARC", "IPC", "VM", "ES", "NE", "RES",
    "REC", "DST", "PRV", "OPS", "HST", "DEL", "VER", "CLW", "RDM",
}
CHECKER = FormatChecker()


@CHECKER.checks("uint64-decimal")
def uint64_decimal(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0|[1-9][0-9]{0,19}", value)) and int(value) <= 18446744073709551615


def reject_float(value: str) -> None:
    raise ValueError(f"Non-integer numeric literal: {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate key: {key}")
        result[key] = value
    return result


def scalar_bounds(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Nesting limit exceeded")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("Unpaired surrogate")
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise ValueError("Unsafe JSON integer")
    elif isinstance(value, list):
        for item in value:
            scalar_bounds(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            scalar_bounds(key, depth + 1)
            scalar_bounds(item, depth + 1)
    else:
        raise ValueError("Unsupported JSON value")


def wire_decode(data: bytes) -> object:
    if len(data) > MAX_BYTES:
        raise ValueError("Envelope byte limit exceeded")
    value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique_object,
                       parse_float=reject_float, parse_constant=reject_float)
    scalar_bounds(value)
    return value


def read_json(path: Path) -> object:
    # Schema/catalog files are not wire envelopes and may be larger/deeper.
    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_float=reject_float, parse_constant=reject_float)


def pair_matches(request: dict, response: dict) -> bool:
    if any(request.get(k) != response.get(k) for k in ("version", "request_id", "method")):
        return False
    if not response.get("ok"):
        if response["error"].get("retry") == "same_intent" and "intent_id" not in request["params"]:
            return False
        original = request["params"].get("operation_ref")
        echoed = response["error"].get("operation_ref")
        binding = response["error"].get("request_binding")
        if (echoed is not None or binding is not None) and binding != request["params"]:
            return False
        return original is None or echoed is None or original == echoed
    params, result = request["params"], response["result"]
    if result.get("request_binding") != params:
        return False
    required_bindings = {
        "task.get": ("task_id",), "task.stop": ("task_id", "scope"),
        "operation.get": ("operation_ref",), "review.open": ("operation_ref",),
        "approval.submit": ("operation_ref", "decision"),
        "events.ack": ("subscription_id",),
    }
    for key in required_bindings.get(request["method"], ()):
        if key not in params or key not in result or params[key] != result[key]:
            return False
    if request["method"] == "hello" and result["selected_version"] not in params["supported_versions"]:
        return False
    if request["method"] == "health.get":
        # Shapes/sources are closed by the schema. JSON Schema cannot compare
        # two fields, so freshness also needs this mandatory semantic check.
        for observation in result["observations"].values():
            if observation["freshness"] == "fresh" and observation["age_ms"] > observation["max_age_ms"]:
                return False
        if not set(result["available_profiles"]).issubset(result["observation_scope"]["evaluated_profiles"]):
            return False
    if request["method"] == "tasks.list" and len(result["tasks"]) > params["limit"]:
        return False
    if request["method"] == "review.open":
        try:
            artifact = result["projection"]["artifact"]
            content = artifact["content_utf8"].encode("utf-8", errors="strict")
            if len(content) != int(artifact["byte_length"]) or hashlib.sha256(content).hexdigest() != artifact["content_sha256"]:
                return False
        except (KeyError, TypeError, ValueError, UnicodeError):
            return False
    return True


def validators() -> dict[str, Draft202012Validator]:
    schemas = {p.name: read_json(p) for p in sorted((ROOT / "contracts").glob("*.schema.json"))}
    registry = Registry()
    for name, value in schemas.items():
        Draft202012Validator.check_schema(value)
        registry = registry.with_resource(name, Resource.from_contents(value))
    return {name: Draft202012Validator(value, registry=registry, format_checker=CHECKER)
            for name, value in schemas.items()}


def markdown_definitions(text: str) -> str:
    # Code examples can contain Markdown-looking definitions. Preserve offsets
    # while excluding fenced bodies from requirement/heading censuses.
    visible, fence = [], None
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})([^\r\n]*)[\r\n]*$", line)
        if fence is not None:
            visible.append(re.sub(r"[^\n]", " ", line))
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= fence[1] and not marker[2].strip():
                fence = None
        elif marker and (marker[1][0] == "~" or "`" not in marker[2]):
            fence = (marker[1][0], len(marker[1]))
            visible.append(re.sub(r"[^\n]", " ", line))
        else:
            visible.append(line)
    return "".join(visible)


def plan_task_body(text: str, heading: str) -> str:
    headings = list(re.finditer(r"^(#{1,6}) (.+)$", markdown_definitions(text), re.M))
    matches = [i for i, match in enumerate(headings) if match[2] == heading]
    if len(matches) != 1 or not re.fullmatch(r"Task [0-9]+: .+", heading):
        raise ValueError(f"Missing or duplicate implementation task: {heading}")
    index = matches[0]
    start, level = headings[index].end(), len(headings[index][1])
    end = next((match.start() for match in headings[index + 1:] if len(match[1]) <= level), len(text))
    return text[start:end]


def validate_plan_coverage(entries: list[dict], identifiers: set[str], plans: dict[str, str]) -> dict[str, list[dict]]:
    coverage = {}
    for entry in entries:
        if set(entry) != {"id", "tasks"} or entry["id"] in coverage:
            raise ValueError("Malformed or duplicate plan coverage entry")
        tasks = entry["tasks"]
        if not isinstance(tasks, list) or not tasks:
            raise ValueError(f"No implementation actions: {entry['id']}")
        seen = set()
        for task in tasks:
            if set(task) != {"plan", "heading", "action"}:
                raise ValueError(f"Malformed implementation action: {entry['id']}")
            name, heading, action = task["plan"], task["heading"], task["action"]
            if name not in plans or Path(name).name != name:
                raise ValueError(f"Missing implementation plan: {name}")
            body = plan_task_body(plans[name], heading)
            if not isinstance(action, str) or not 30 <= len(action) <= 500 or action not in body:
                raise ValueError(f"Missing mapped implementation action: {entry['id']} in {name}: {heading}")
            if "- [ ]" not in body or (name, heading, action) in seen:
                raise ValueError(f"Missing task work or duplicate mapping: {entry['id']}")
            seen.add((name, heading, action))
        coverage[entry["id"]] = tasks
    if set(coverage) != identifiers:
        raise ValueError(f"Plan requirement coverage drift: {sorted(set(coverage) ^ identifiers)}")
    return coverage


def validate_acceptance_definitions(records: list[dict], documents: dict[str, str]) -> None:
    expected = {record["acceptance"]: record["spec"] for record in records}
    definitions: dict[str, list[str]] = {}
    pattern = re.compile(r"^ {0,3}(?:\|[ \t]*(AT-MAC-[A-Z]+-\d{3})[ \t]*\||#{1,6}[ \t]+(AT-MAC-[A-Z]+-\d{3})(?=:|[ \t]|$))", re.M)
    for name, text in documents.items():
        for match in pattern.finditer(markdown_definitions(text)):
            identifier = match[1] or match[2]
            definitions.setdefault(identifier, []).append(name)
    if set(definitions) != set(expected):
        raise ValueError(f"Missing/orphan acceptance definitions: {sorted(set(definitions) ^ set(expected))}")
    for identifier, owner in expected.items():
        if definitions[identifier] != [owner]:
            raise ValueError(f"Acceptance must be defined once in {owner}: {identifier}: {definitions[identifier]}")


def requirement_records() -> list[dict]:
    records, identifiers = [], set()
    for path in sorted(ROOT.glob("[0-9][0-9]-*.md")):
        text = path.read_text()
        for line_no, line in enumerate(markdown_definitions(text).splitlines(), 1):
            match = re.fullmatch(r"\| (MAC-([A-Z]+)-\d{3}) \| (.+) \| (AT-MAC-[A-Z]+-\d{3}) \|", line)
            if not match:
                if re.match(r"\| MAC-[A-Z]+-\d{3} \|", line):
                    raise ValueError(f"Malformed requirement table: {path.name}:{line_no}")
                continue
            identifier, prefix, statement, acceptance = match.groups()
            if identifier in identifiers or acceptance != "AT-" + identifier:
                raise ValueError(f"Duplicate or mismatched requirement: {identifier}")
            if prefix not in REQUIREMENT_PREFIXES:
                raise ValueError(f"Unmapped requirement prefix: {prefix}")
            identifiers.add(identifier)
            records.append({"id": identifier, "spec": path.name, "line": line_no,
                            "requirement": statement, "acceptance": acceptance,
                            "acceptance_status": "specified_not_executed"})
    if not records:
        raise ValueError("No requirements found")
    documents = {path.relative_to(ROOT).as_posix(): path.read_text() for path in ROOT.rglob("*.md")}
    documents.update({"plans/" + path.relative_to(PLANS).as_posix(): path.read_text() for path in PLANS.rglob("*.md")})
    validate_acceptance_definitions(records, documents)
    entries = []
    for path in sorted((ROOT / "contracts").glob("plan-coverage-*.json")):
        document = read_json(path)
        if set(document) != {"requirements"}:
            raise ValueError(f"Malformed plan coverage file: {path.name}")
        entries.extend(document["requirements"])
    plans = {path.name: path.read_text() for path in PLANS.glob("[0-9][0-9]-*.md")}
    coverage = validate_plan_coverage(entries, identifiers, plans)
    for record in records:
        record["plan"] = coverage[record["id"]][0]["plan"]
        record["plan_tasks"] = coverage[record["id"]]
    return records


def check_documents() -> int:
    paths = sorted(ROOT.rglob("*.md")) + sorted(PLANS.rglob("*.md"))
    for path in paths:
        text = path.read_text()
        if "\u2014" in text or any(line != line.rstrip() for line in text.splitlines()):
            raise ValueError(f"Prose/whitespace convention violation: {path}")
        if re.search(r"\b(?:TO" + r"DO|TB" + r"D|FIX" + r"ME)\b", text):
            raise ValueError(f"Unresolved placeholder: {path}")
        fences = [line for line in text.splitlines() if re.match(r"^\s*```", line)]
        if len(fences) % 2:
            raise ValueError(f"Unbalanced fences: {path}")
        for link in re.findall(r"\]\(([^\s)]+)\)", text):
            if link.startswith(("http:", "https:", "mailto:")):
                continue
            file_part, _, fragment = link.partition("#")
            target = (path.parent / file_part).resolve() if file_part else path
            if not target.is_relative_to(REPO) or not target.is_file():
                raise ValueError(f"Missing/nonportable local reference {link} in {path}")
            if fragment and target.suffix == ".md":
                headings = re.findall(r"^#{1,6}\s+(.+)$", target.read_text(), re.M)
                anchors = {re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings}
                if fragment not in anchors:
                    raise ValueError(f"Missing local anchor {link} in {path}")
    return len(paths)


def check_method_fixture_coverage(methods: list[dict], entries: dict, values: dict) -> None:
    for method in methods:
        name = method["name"]
        for role, schema in (("request_example", "operator-request.schema.json"),
                             ("response_example", "operator-response.schema.json")):
            fixture = method[role]
            entry, value = entries.get(fixture, {}), values.get(fixture)
            if entry.get("schema") != schema or entry.get("schema_valid") is not True or not isinstance(value, dict) or value.get("method") != name:
                raise ValueError(f"Missing positive {role} coverage: {name}")
            if role == "response_example" and (entry.get("request") != method["request_example"] or entry.get("pair_valid") is not True):
                raise ValueError(f"Missing positive response pairing: {name}")
        negatives = method.get("negative_examples", [])
        if not negatives or len(set(negatives)) != len(negatives):
            raise ValueError(f"Missing or duplicate negative coverage: {name}")
        for fixture in negatives:
            entry, value = entries.get(fixture, {}), values.get(fixture)
            if entry.get("schema") not in ("operator-request.schema.json", "operator-response.schema.json") or not isinstance(value, dict):
                raise ValueError(f"Missing negative fixture: {name}: {fixture}")
            if value.get("method") != name and entry.get("request") != method["request_example"]:
                raise ValueError(f"Foreign method negative fixture: {name}: {fixture}")
            if entry.get("schema_valid") is not False:
                paired = entry.get("request")
                request_entry, request_value = entries.get(paired, {}), values.get(paired)
                if (entry.get("schema") != "operator-response.schema.json" or entry.get("pair_valid") is not False
                        or request_entry.get("schema") != "operator-request.schema.json"
                        or request_entry.get("schema_valid") is not True
                        or not isinstance(request_value, dict) or request_value.get("method") != name):
                    raise ValueError(f"Negative fixture has no executable rejection oracle: {name}: {fixture}")


def check_fixtures(loaded: dict) -> tuple[int, int]:
    catalog = read_json(ROOT / "contracts/fixture-catalog.json")
    if catalog.get("synthetic_only") is not True:
        raise ValueError("Examples must remain synthetic")
    files, coverage, correlated = set(), set(), 0
    entries, values = {}, {}
    for entry in catalog["fixtures"]:
        name = entry["file"]
        if name in files or Path(name).name != name:
            raise ValueError(f"Duplicate/unsafe fixture path: {name}")
        files.add(name)
        if not isinstance(entry.get("schema_valid"), bool):
            raise ValueError(f"Invalid schema expectation: {name}")
        if ("request" in entry) != ("pair_valid" in entry):
            raise ValueError(f"Incomplete pair oracle: {name}")
        if "request" in entry and (entry["schema"] != "operator-response.schema.json" or not isinstance(entry["pair_valid"], bool)):
            raise ValueError(f"Invalid pair oracle: {name}")
        data = (ROOT / "examples" / name).read_bytes()
        try:
            value = wire_decode(data)
            valid = not list(loaded[entry["schema"]].iter_errors(value))
        except (ValueError, UnicodeError):
            value, valid = None, False
        entries[name], values[name] = entry, value
        if valid != entry["schema_valid"]:
            raise ValueError(f"Unexpected schema result for {name}: {valid}")
        if valid and entry["schema"] == "operator-request.schema.json":
            coverage.add(value["method"])
        if "request" in entry:
            request = wire_decode((ROOT / "examples" / entry["request"]).read_bytes())
            if list(loaded["operator-request.schema.json"].iter_errors(request)):
                raise ValueError(f"Pair uses invalid request: {name}")
            if (valid and pair_matches(request, value)) != entry["pair_valid"]:
                raise ValueError(f"Unexpected response correlation result: {name}")
            correlated += 1
        if entry["schema"] == "release-evidence.schema.json" and valid:
            if value["synthetic"] is not True or value["status"] != "candidate":
                raise ValueError("Checked-in release vectors cannot qualify runtime")
    actual = {p.name for p in (ROOT / "examples").glob("*.json")}
    if actual != files:
        raise ValueError(f"Fixture catalog drift: {sorted(actual ^ files)}")
    methods = read_json(ROOT / "contracts/method-catalog.json")
    expected = {entry["name"] for entry in methods["methods"]}
    if coverage != expected or len(expected) != len(methods["methods"]):
        raise ValueError("Missing method request coverage or duplicate catalog method")
    check_method_fixture_coverage(methods["methods"], entries, values)
    for method in methods["methods"]:
        request = wire_decode((ROOT / "examples" / method["request_example"]).read_bytes())
        response = wire_decode((ROOT / "examples" / method["response_example"]).read_bytes())
        if method["mutation"] != ("intent_id" in request["params"]):
            raise ValueError(f"Method intent classification drift: {method['name']}")
        if request["method"] != method["name"] or not pair_matches(request, response):
            raise ValueError(f"Method catalog substitution: {method['name']}")
        # Every method must reject unexpected parameters, independently of hand-written vectors.
        mutant = copy.deepcopy(request)
        mutant["params"]["unexpected_authority"] = True
        if not list(loaded["operator-request.schema.json"].iter_errors(mutant)):
            raise ValueError(f"Open parameter shape: {method['name']}")
    return len(files), correlated


def check_rejection_repairs(loaded: dict, entries: dict, values: dict) -> int:
    """A negative's declared single-field repair must restore its valid control."""
    checked = 0
    for name, entry in entries.items():
        if "rejection_repair" not in entry:
            continue
        repair = entry["rejection_repair"]
        if not isinstance(repair, dict) or set(repair) != {"base", "path"}:
            raise ValueError(f"Malformed rejection repair: {name}")
        source, path = repair["base"], repair["path"]
        control = entries.get(source, {})
        if (entry.get("pair_valid") is not False or control.get("pair_valid") is not True
                or control.get("schema_valid") is not True or entry.get("schema") != control.get("schema")
                or entry.get("request") != control.get("request") or not isinstance(path, list) or not path):
            raise ValueError(f"Invalid rejection repair control: {name}")
        repaired, original = copy.deepcopy(values[name]), values[source]
        target, expected = repaired, original
        for component in path[:-1]:
            target, expected = target[component], expected[component]
        key = path[-1]
        if isinstance(expected, dict) and key not in expected:
            del target[key]
        else:
            target[key] = copy.deepcopy(expected[key])
        request = values[entry["request"]]
        if repaired != original or not loaded[entry["schema"]].is_valid(repaired) or not pair_matches(request, repaired):
            raise ValueError(f"Rejection fixture has an unrelated defect: {name}")
        checked += 1
    return checked


def semantic_self_test(loaded: dict, methods: list[dict], entries: dict, values: dict) -> int:
    """Exercise all-method parameter correlation and independent state dimensions."""
    checked = check_rejection_repairs(loaded, entries, values)
    response_schema = loaded["operator-response.schema.json"]

    def accepts(request: dict, response: dict) -> bool:
        return response_schema.is_valid(response) and pair_matches(request, response)

    def leaves(value: object, prefix: tuple = ()):
        if isinstance(value, (dict, list)):
            items = value.items() if isinstance(value, dict) else enumerate(value)
            for key, item in items:
                yield from leaves(item, prefix + (key,))
        else:
            yield prefix, value

    def substitute(key: str, value: object) -> object:
        if isinstance(value, int):
            return value + 1
        if isinstance(value, str) and value.isdecimal():
            return str(int(value) + 1)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
            return ("c" if value != "c" * 64 else "d") * 64
        alternatives = {"scope": ("task", "task_and_descendants"), "decision": ("approve", "deny"),
                        "execution_profile": ("vm-project-v1", "remote-project-v1")}
        if key in alternatives:
            left, right = alternatives[key]
            return right if value == left else left
        return "synthetic-substitution"

    for method in methods:
        request = values[method["request_example"]]
        for location, filename in (("result", method["response_example"]),
                                   ("error", "response-" + method["name"].replace(".", "-") + "-recovery.json")):
            response = values[filename]
            if not accepts(request, response):
                raise ValueError(f"Invalid request binding positive control: {filename}")
            checked += 1
            # Change every scalar, including each native reference field, every
            # resource/endorsement, every limit, the scope and logical intent.
            for path, value in leaves(request["params"]):
                mutant = copy.deepcopy(response)
                node = mutant[location]["request_binding"]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = substitute(path[-1], value)
                if accepts(request, mutant):
                    raise ValueError(f"Parameter correlation accepted {method['name']} {location} {path}")
                checked += 1
            mutant = copy.deepcopy(response)
            del mutant[location]["request_binding"]
            if response_schema.is_valid(mutant) or pair_matches(request, mutant):
                raise ValueError(f"Missing request binding accepted: {method['name']} {location}")
            checked += 1
            mutant = copy.deepcopy(response)
            mutant[location]["request_binding"]["unexpected_authority"] = True
            if response_schema.is_valid(mutant):
                raise ValueError(f"Open request binding shape: {method['name']} {location}")
            checked += 1
        # A refusal without an operation reference can be returned before a
        # request is valid; it asserts no recoverable operation or authority.
        refusal = copy.deepcopy(values[filename])
        refusal["error"]["operation_ref"] = None
        del refusal["error"]["request_binding"]
        if not accepts(request, refusal):
            raise ValueError(f"Unbound no-operation refusal rejected: {method['name']}")
        checked += 1

    # Limits constrain page size independently of the exact echoed request;
    # subscription rebasing changes the issued cursor, not the requested start.
    for limit in (1, 100):
        request = copy.deepcopy(values["request-tasks-list.json"])
        request["params"]["limit"] = limit
        response = copy.deepcopy(values["response-tasks-list.json"])
        response["result"]["request_binding"] = copy.deepcopy(request["params"])
        task = response["result"]["tasks"][0]
        response["result"]["tasks"] = []
        for index in range(limit):
            item = copy.deepcopy(task)
            item["task_id"] = f"synthetic-boundary-task-{index}"
            item["operation_ref"]["native_id"] = f"synthetic-boundary-operation-{index}"
            response["result"]["tasks"].append(item)
        if not loaded["operator-request.schema.json"].is_valid(request) or not accepts(request, response):
            raise ValueError(f"Page limit positive boundary failed: {limit}")
        checked += 1
    for rebased in (False, True):
        for cursor in (None, "synthetic-requested-cursor"):
            request = copy.deepcopy(values["request-events-subscribe.json"])
            request["params"]["after_cursor"] = cursor
            response = copy.deepcopy(values["response-events-subscribe.json"])
            response["result"].update(request_binding=copy.deepcopy(request["params"]), rebase_required=rebased)
            if not accepts(request, response):
                raise ValueError(f"Exact subscription start rejected: {rebased} {cursor}")
            response["result"]["request_binding"]["after_cursor"] = "synthetic-other-cursor"
            if not response_schema.is_valid(response) or pair_matches(request, response):
                raise ValueError(f"Subscription start substitution accepted: {rebased} {cursor}")
            checked += 2
    # The shared task fields stay closed in pages; request binding belongs to
    # the outer method result and must not leak into nested task projections.
    response = copy.deepcopy(values["response-tasks-list.json"])
    response["result"]["tasks"][0]["request_binding"] = {"task_id": "synthetic-task"}
    if response_schema.is_valid(response):
        raise ValueError("Nested task projection accepted a request binding")
    checked += 1

    health_request = values["request-health-get.json"]
    health = values["response-health-get-ready.json"]
    for dimension in health["result"]["observations"]:
        for age_delta in (0, 1):
            mutant = copy.deepcopy(health)
            observation = mutant["result"]["observations"][dimension]
            observation["age_ms"] = observation["max_age_ms"] + age_delta
            if not response_schema.is_valid(mutant) or pair_matches(health_request, mutant) != (age_delta == 0):
                raise ValueError(f"Health freshness boundary failed: {dimension} +{age_delta}")
            checked += 1
        for field, value in (("state", "unknown"), ("source", "synthetic-observer")):
            mutant = copy.deepcopy(health)
            mutant["result"]["observations"][dimension][field] = value
            if response_schema.is_valid(mutant):
                raise ValueError(f"Health accepted ready unknown/unbounded source: {dimension} {field}")
            checked += 1
    for method, filename in (("task.get", "response-task-get-stopped.json"),
                             ("tasks.list", "response-tasks-list-stopped.json")):
        request = values["request-" + method.replace(".", "-") + ".json"]
        for field, value, valid in (("worker", "unknown", False), ("network", "unknown", False),
                                    ("cleanup", "unknown", True), ("external_outcome", "unresolved", True)):
            mutant = copy.deepcopy(values[filename])
            task = mutant["result"] if method == "task.get" else mutant["result"]["tasks"][0]
            task["stop_state"][field] = value
            if accepts(request, mutant) != valid:
                raise ValueError(f"Stop dimension independence failed: {method} {field}")
            checked += 1
    return checked


def self_test(loaded: dict) -> int:
    malformed = [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.1}', b'"\\ud800"',
                 b'"\xff"', b'{"a":9007199254740992}', b' ' * (MAX_BYTES + 1),
                 ("[" * 18 + "0" + "]" * 18).encode()]
    for value in malformed:
        try:
            wire_decode(value)
        except (ValueError, UnicodeError):
            continue
        raise ValueError(f"Strict decoder accepted invalid input: {value[:40]!r}")
    wire_decode(b'{"safe":9007199254740991,"flag":true}')
    if not uint64_decimal("18446744073709551615") or uint64_decimal("18446744073709551616"):
        raise ValueError("Unsigned decimal boundary validation failed")
    request = wire_decode((ROOT / "examples/request-approval-submit.json").read_bytes())
    response = wire_decode((ROOT / "examples/response-approval-submit.json").read_bytes())
    for field in ("request_id", "method", "version"):
        mutant = copy.deepcopy(response)
        mutant[field] = "substituted"
        if pair_matches(request, mutant):
            raise ValueError(f"Correlation accepted substitution: {field}")
    mutant = copy.deepcopy(response)
    mutant["result"]["decision"] = "deny"
    if pair_matches(request, mutant):
        raise ValueError("Correlation accepted different decision")
    mutant = copy.deepcopy(request)
    mutant["params"]["endorsement_ref"]["generation"] = "18446744073709551616"
    if not list(loaded["operator-request.schema.json"].iter_errors(mutant)):
        raise ValueError("Schema accepted overflowing native generation")
    for method in ("task.stop", "review.open"):
        request = wire_decode((ROOT / f"examples/request-{method.replace('.', '-')}.json").read_bytes())
        response = wire_decode((ROOT / f"examples/response-{method.replace('.', '-')}.json").read_bytes())
        key = "task_id" if method == "task.stop" else "operation_ref"
        for remove in (False, True):
            mutant = copy.deepcopy(response)
            if remove:
                del mutant["result"][key]
            else:
                mutant["result"][key] = "substituted"
            if pair_matches(request, mutant):
                raise ValueError(f"Correlation accepted missing/substituted {method} binding")
    identifier = "MAC-IPC-001"
    heading = "Task 1: Authenticate native peers"
    action = "Reject a peer whose audit identity differs from the selected native session."
    plan = f"# Plan\n\n## {heading}\n\n- [ ] {action}\n"
    entry = {"id": identifier, "tasks": [{"plan": "02-protocol-controller.md", "heading": heading, "action": action}]}
    plans = {"02-protocol-controller.md": plan}
    validate_plan_coverage([entry], {identifier}, plans)
    fenced_plan = plan.replace("- [ ]", "```python\n# Not a plan heading\n```\n\n- [ ]")
    validate_plan_coverage([entry], {identifier}, {"02-protocol-controller.md": fenced_plan})
    bad_cases = [([], plans), ([entry, entry], plans), ([entry], {}),
                 ([entry], {"02-protocol-controller.md": plan.replace(action, "Removed action.")}),
                 ([entry], {"02-protocol-controller.md": plan.replace(heading, "Task 2: Different task")}),
                 ([entry], {"02-protocol-controller.md": plan.replace("- [ ]", "Narrative only:")})]
    for entries, mutated_plans in bad_cases:
        try:
            validate_plan_coverage(entries, {identifier}, mutated_plans)
        except ValueError:
            continue
        raise ValueError("Plan coverage accepted removed, unbound or duplicate implementation work")
    acceptance = "AT-" + identifier
    acceptance_records = [{"acceptance": acceptance, "spec": "06-protocol.md"}]
    table = f"| {acceptance} | Exercise refusal. | No effect. |\n"
    heading_definition = f"### {acceptance}: Exercise refusal\n\nNo effect.\n"
    definition_docs = {"06-protocol.md": table, "research/example.md": f"```markdown\n{table}```\n"}
    validate_acceptance_definitions(acceptance_records, definition_docs)
    validate_acceptance_definitions(acceptance_records, {"06-protocol.md": heading_definition})
    fence_cases = [f"~~~markdown\n{table}~~~\n", f"````markdown\n```\n{table}```\n````\n"]
    for example in fence_cases:
        validate_acceptance_definitions(acceptance_records, {"06-protocol.md": table, "research/example.md": example})
    bad_definitions = [
        {},
        {"06-protocol.md": table + table},
        {"06-protocol.md": table, "07-vm.md": table},
        {"06-protocol.md": table, "plans/02-protocol.md": heading_definition},
        {"06-protocol.md": table + table.replace(acceptance, "AT-MAC-IPC-999")},
        {"07-vm.md": table},
        {"06-protocol.md": f"```markdown\n{table}```\n"},
        {"06-protocol.md": table, "07-vm.md": "  " + heading_definition},
        {"06-protocol.md": table, "07-vm.md": heading_definition.replace("### ", "###  ")},
        {"06-protocol.md": table, "07-vm.md": table.replace("| ", "|").replace(" |", "|")},
    ]
    for documents in bad_definitions:
        try:
            validate_acceptance_definitions(acceptance_records, documents)
        except ValueError:
            continue
        raise ValueError("Acceptance census accepted a missing, duplicate, orphan or wrong-owner definition")
    request = wire_decode((ROOT / "examples/request-task-stop.json").read_bytes())
    response = wire_decode((ROOT / "examples/response-task-stop.json").read_bytes())
    response["result"]["scope"] = "task"
    if pair_matches(request, response):
        raise ValueError("Correlation accepted parent-only result for descendant stop")
    catalog = read_json(ROOT / "contracts/fixture-catalog.json")
    entries = {entry["file"]: entry for entry in catalog["fixtures"]}
    values = {}
    for name in entries:
        try:
            values[name] = wire_decode((ROOT / "examples" / name).read_bytes())
        except (ValueError, UnicodeError):
            values[name] = None
    methods = read_json(ROOT / "contracts/method-catalog.json")["methods"]
    coverage_checks = 0
    for method in methods:
        mutant = copy.deepcopy(method)
        mutant["negative_examples"] = []
        try:
            check_method_fixture_coverage([mutant], entries, values)
        except ValueError:
            coverage_checks += 1
        else:
            raise ValueError(f"Missing negative coverage accepted: {method['name']}")
        missing = dict(entries)
        del missing[method["negative_examples"][0]]
        try:
            check_method_fixture_coverage([method], missing, values)
        except ValueError:
            coverage_checks += 1
        else:
            raise ValueError(f"Deleted negative fixture accepted: {method['name']}")
    for method in methods:
        for name in method["negative_examples"]:
            if entries[name].get("schema_valid") is True:
                unpaired = copy.deepcopy(entries)
                del unpaired[name]["request"]
                try:
                    check_method_fixture_coverage([method], unpaired, values)
                except ValueError:
                    coverage_checks += 1
                else:
                    raise ValueError(f"Negative correlation oracle accepted without request: {name}")
    retry_checks = 0
    for method in methods:
        if method["mutation"]:
            continue
        name = "invalid-retry-" + method["name"].replace(".", "-") + ".json"
        response = copy.deepcopy(values[name])
        response["error"]["retry"] = "never"
        if list(loaded["operator-response.schema.json"].iter_errors(response)):
            raise ValueError(f"Retry fixture has an unrelated shape defect: {name}")
        retry_checks += 1
    semantic_checks = semantic_self_test(loaded, methods, entries, values)
    return len(malformed) + 7 + 4 + 2 + len(bad_cases) + 2 + len(fence_cases) + len(bad_definitions) + 1 + coverage_checks + retry_checks + semantic_checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-traceability", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        records = requirement_records()
        trace = {"status": "specified_not_executed", "requirements": records}
        encoded = json.dumps(trace, indent=2, ensure_ascii=False) + "\n"
        path = ROOT / "requirements.json"
        if args.write_traceability:
            path.write_text(encoded)
        elif not path.exists() or path.read_text() != encoded:
            raise ValueError("Traceability drift; review changes then run --write-traceability")
        docs = check_documents()
        loaded = validators()
        fixtures, correlated = check_fixtures(loaded)
        checks = self_test(loaded) if args.self_test else 0
        print(json.dumps({"document_validation": "pass", "documents": docs,
                          "requirements": len(records), "schemas": len(loaded),
                          "synthetic_fixtures": fixtures, "response_pairs": correlated,
                          "self_checks": checks, "runtime_qualification": False}, indent=2))
        return 0
    except (ValueError, OSError, KeyError) as error:
        print(f"Document validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
