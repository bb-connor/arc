from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from chio.computer import (
    DescriptionError, ProgramExpr, compile_program, parallel, parse_description,
    parse_compiled_description, namespace_digest, revision_digest, validate_compiled_program,
)
from chio.invariants import canonicalize_json

FIXTURE = json.loads((Path(__file__).resolve().parents[4] / "tests/bindings/vectors/computer/v1.json").read_text())


def replace_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def pin(computer):
    revision = computer["revision"]
    revision["namespaceDigest"] = namespace_digest(revision["resources"])
    revision["revisionId"] = revision_digest(revision)
    computer["record"]["headRevision"] = revision["revisionId"]
    computer["image"]["revisionId"] = revision["revisionId"]
    computer["image"]["resourceManifestDigest"] = revision["namespaceDigest"]


class ComputerContractTests(unittest.TestCase):
    def assert_code(self, code, call):
        with self.assertRaises(DescriptionError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_revision_digest_bounds_the_excluded_placeholder(self):
        revision = copy.deepcopy(FIXTURE["cases"][0]["computer"]["revision"])
        expected = revision_digest(revision)
        revision["revisionId"] = ""
        self.assertEqual(revision_digest(revision), expected)
        for value in ("0" * 65, "0" * (8 * 1024 * 1024)):
            revision["revisionId"] = value
            self.assert_code("digest_format", lambda: revision_digest(revision))

    def test_original_numbers_retain_exact_integral_identity(self):
        for case in FIXTURE["numbers"] + FIXTURE["wireStrings"]:
            with self.subTest(source=case["source"]):
                if "error" in case:
                    self.assert_code(case["error"], lambda: parse_description(case["source"]))
                else:
                    self.assertEqual(parse_description(case["source"]), case["value"])
        case = FIXTURE["cases"][0]
        text = json.dumps(case["computer"], separators=(",", ":"))
        for number in ("1.0", "1e0", "10e-1"):
            computer = parse_description(text.replace('"lifecycleGeneration":1', '"lifecycleGeneration":' + number))
            self.assertEqual(compile_program(computer, case["requestId"], case["expression"]), case["expected"])
        self.assertEqual(parse_description('"1.00000000000000001"'), "1.00000000000000001")
        self.assertEqual(parse_description(r'{"text":"quote\"1.00000000000000001","value":1.0}'), {"text": 'quote"1.00000000000000001', "value": 1})
        self.assert_code("json_shape", lambda: parse_description('{"value":{"id":1.0,"id":1e0}}'))

    def test_shared_canonical_vectors(self):
        for case in FIXTURE["cases"]:
            with self.subTest(case=case["id"]):
                result = compile_program(case["computer"], case["requestId"], case["expression"])
                self.assertEqual(result, case["expected"])
                self.assertEqual(canonicalize_json(result), case["canonical"])
                self.assertEqual(parse_compiled_description(case["canonical"]), result)
                self.assertEqual(validate_compiled_program(case["computer"], case["requestId"], case["expression"], result), result)

    def test_shared_exact_refusals(self):
        for refusal in FIXTURE["refusals"]:
            with self.subTest(case=refusal["id"]):
                case = copy.deepcopy(FIXTURE["cases"][0])
                replace_path(case[refusal["section"]], refusal["path"], refusal["value"])
                self.assert_code(refusal["error"], lambda: compile_program(case["computer"], case["requestId"], case["expression"]))

    def test_real_operator_precedence(self):
        case = next(case for case in FIXTURE["cases"] if case["id"] == "operator_precedence")
        a, b, c, d, e = [ProgramExpr.leaf(item["leaf"]) for item in case["expected"]["occurrences"]]
        self.assertEqual(compile_program(case["computer"], case["requestId"], a & b & c | d | e), case["expected"])
        self.assertEqual(compile_program(case["computer"], case["requestId"], parallel(a, b, c).pipe(d).pipe(e)), case["expected"])

    def test_occurrence_identity_and_retry(self):
        for name in ("repeated_parallel", "repeated_sequence"):
            case = next(case for case in FIXTURE["cases"] if case["id"] == name)
            result = compile_program(case["computer"], case["requestId"], case["expression"])
            identities = [item["occurrenceId"] for item in result["occurrences"]]
            self.assertEqual(len(set(identities)), 2)
            self.assertEqual(compile_program(case["computer"], case["requestId"], case["expression"]), result)
            other = compile_program(case["computer"], "different-request", case["expression"])
            self.assertTrue(set(identities).isdisjoint(item["occurrenceId"] for item in other["occurrences"]))

    def test_forged_description_fields(self):
        case = FIXTURE["cases"][0]
        for path, replacement in [
            (["digest"], "0" * 64), (["requestId"], "other"), (["revisionId"], "0" * 64),
            (["ownerDomain"], "other"), (["lifecycleGeneration"], 2),
            (["occurrences", 0, "occurrenceId"], "0" * 64), (["occurrences", 0, "path"], [1]),
            (["occurrences", 0, "parents"], ["0" * 64]),
            (["occurrences", 0, "leaf", "resources", 0, "generation"], 2),
        ]:
            with self.subTest(path=path):
                supplied = copy.deepcopy(case["expected"])
                replace_path(supplied, path, replacement)
                self.assert_code("compiled_mismatch", lambda: validate_compiled_program(case["computer"], case["requestId"], case["expression"], supplied))

    def test_boolean_cannot_alias_plan_generation(self):
        case = FIXTURE["cases"][0]
        supplied = copy.deepcopy(case["expected"])
        supplied["lifecycleGeneration"] = True
        self.assert_code("generation", lambda: validate_compiled_program(case["computer"], case["requestId"], case["expression"], supplied))

    def test_supplied_occurrence_rejects_oversized_leaf_before_comparison(self):
        case = FIXTURE["cases"][0]
        supplied = copy.deepcopy(case["expected"])
        supplied["occurrences"][0]["leaf"]["resources"] *= 257
        self.assert_code("resource_count", lambda: validate_compiled_program(case["computer"], case["requestId"], case["expression"], supplied))

    def test_unicode_scalar_values_are_required(self):
        self.assertEqual(parse_description(r'"\ud83d\ude00"'), "😀")
        for text in (r'"\ud800"', r'{"\ud800":0}', '"' + chr(0xd800) + '"'):
            self.assert_code("json_shape", lambda: parse_description(text))

    def test_typed_namespace_rejects_non_scalar_text(self):
        case = copy.deepcopy(FIXTURE["cases"][0])
        case["expression"]["leaf"]["resources"][0]["namespace"] = "/" + chr(0xd800)
        self.assert_code("namespace", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))

    def test_compiled_collection_limit(self):
        self.assertEqual(len(parse_compiled_description(json.dumps([0] * 262144))), 262144)
        self.assert_code("json_entries", lambda: parse_compiled_description(json.dumps([0] * 262145)))

    def test_required_null_and_closed_fields(self):
        case = copy.deepcopy(FIXTURE["cases"][0])
        compile_program(case["computer"], case["requestId"], case["expression"])
        del case["computer"]["record"]["parentRevision"]
        self.assert_code("json_shape", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))
        case = copy.deepcopy(FIXTURE["cases"][0])
        case["computer"]["revision"]["boot"]["extra"] = True
        self.assert_code("json_shape", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))

    def test_decode_limits_and_duplicate_keys(self):
        self.assertEqual(parse_description("0" + " " * (2 * 1024 * 1024 - 1)), 0)
        self.assert_code("wire_bytes", lambda: parse_description("0" + " " * (2 * 1024 * 1024)))
        self.assert_code("json_shape", lambda: parse_description('{"value":{"id":1,"id":2}}'))
        self.assertEqual(parse_description("[" * 96 + "0" + "]" * 96), json.loads("[" * 96 + "0" + "]" * 96))
        self.assert_code("json_depth", lambda: parse_description("[" * 97 + "0" + "]" * 97))
        self.assertEqual(len(parse_description(json.dumps([0] * 65536))), 65536)
        self.assert_code("json_entries", lambda: parse_description(json.dumps([0] * 65537)))
        self.assertEqual(parse_description(json.dumps("é" * 512)), "é" * 512)
        self.assert_code("string_bytes", lambda: parse_description(json.dumps("é" * 512 + "a")))

    def test_expression_depth_and_parent_bounds(self):
        case = FIXTURE["cases"][0]
        expression = case["expression"]
        for _ in range(31):
            expression = {"op": "sequence", "items": [case["expression"], expression]}
        self.assertEqual(len(compile_program(case["computer"], case["requestId"], expression)["occurrences"]), 32)
        expression = {"op": "sequence", "items": [case["expression"], expression]}
        self.assert_code("expression_depth", lambda: compile_program(case["computer"], case["requestId"], expression))
        for count in (16, 17):
            expression = {"op": "parallel", "items": [case["expression"]] * count}
            if count == 16:
                self.assertEqual(len(compile_program(case["computer"], case["requestId"], expression)["occurrences"]), 16)
            else:
                self.assert_code("parent_count", lambda: compile_program(case["computer"], case["requestId"], expression))

    def test_expression_node_and_leaf_maxima(self):
        case = FIXTURE["cases"][0]
        expression = case["expression"]
        for _ in range(10):
            expression = {"op": "sequence", "items": [expression, expression]}
        result = compile_program(case["computer"], case["requestId"], expression)
        self.assertEqual(len(result["occurrences"]), 1024)
        self.assertEqual(parse_compiled_description(canonicalize_json(result)), result)
        for count, error in [(2047, "expression_nodes"), (1025, "leaf_count")]:
            self.assert_code(error, lambda: compile_program(case["computer"], case["requestId"], {"op": "sequence", "items": [case["expression"]] * count}))

    def test_exact_edge_limit(self):
        case = FIXTURE["cases"][0]

        def stage(parents, width):
            leaf = copy.deepcopy(case["expression"])
            schema = leaf["leaf"]["outputSchema"]
            leaf["leaf"]["inputSchema"] = {"kind": "value", "schema": schema} if parents == 1 else {"kind": "all_success", "schemas": [schema] * parents}
            return leaf if width == 1 else {"op": "parallel", "items": [leaf] * width}

        stages = [stage(1, 16)] + [stage(16, 16) for _ in range(15)] + [stage(16, 15), stage(15, 1), stage(1, 1)]
        result = compile_program(case["computer"], case["requestId"], {"op": "sequence", "items": stages})
        self.assertEqual(sum(len(item["parents"]) for item in result["occurrences"]), 4096)
        stages.append(stage(1, 1))
        self.assert_code("dependency_edges", lambda: compile_program(case["computer"], case["requestId"], {"op": "sequence", "items": stages}))

    def test_resource_and_profile_limits(self):
        case = copy.deepcopy(FIXTURE["cases"][0])
        computer = case["computer"]
        original = computer["revision"]["resources"][0]
        for index in range(255):
            resource = copy.deepcopy(original)
            resource["namespace"] = f"/resource-{index}"
            computer["revision"]["resources"].append(resource)
        pin(computer)
        compile_program(computer, case["requestId"], case["expression"])
        computer["revision"]["resources"].append(original)
        self.assert_code("resource_count", lambda: compile_program(computer, case["requestId"], case["expression"]))
        case = copy.deepcopy(FIXTURE["cases"][0]); computer = case["computer"]
        profiles = computer["revision"]["profileRefs"]
        for index in range(63):
            profile = copy.deepcopy(profiles[0]); profile["artifactId"] = f"profile-{index}"; profiles.append(profile)
        computer["record"]["profileRefs"] = profiles
        computer["image"]["requirements"] = profiles
        pin(computer)
        compile_program(computer, case["requestId"], case["expression"])
        profiles.append(profiles[0])
        self.assert_code("profiles", lambda: compile_program(computer, case["requestId"], case["expression"]))

    def test_identifier_namespace_generation_and_transfer_limits(self):
        case = copy.deepcopy(FIXTURE["cases"][0])
        compile_program(case["computer"], "a" * 128, case["expression"])
        self.assert_code("identifier", lambda: compile_program(case["computer"], "a" * 129, case["expression"]))
        self.assert_code("identifier", lambda: compile_program(case["computer"], "a\n", case["expression"]))
        case["computer"]["record"]["lifecycleGeneration"] = 9007199254740991
        compile_program(case["computer"], case["requestId"], case["expression"])
        case["computer"]["record"]["lifecycleGeneration"] += 1
        self.assert_code("generation", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))
        case = copy.deepcopy(FIXTURE["cases"][0])
        namespace = "/" + "a" * 128 + "/" + "b" * 126
        case["computer"]["revision"]["resources"][0]["namespace"] = namespace
        case["expression"]["leaf"]["resources"][0]["namespace"] = namespace
        pin(case["computer"])
        compile_program(case["computer"], case["requestId"], case["expression"])
        case["expression"]["leaf"]["resources"][0]["namespace"] += "b"
        self.assert_code("namespace", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))
        case = copy.deepcopy(FIXTURE["cases"][0])
        pending = [case["computer"], case["expression"]]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if "byteLength" in value: value["byteLength"] = 0
                pending.extend(value.values())
            elif isinstance(value, list): pending.extend(value)
        case["expression"]["leaf"]["contract"]["byteLength"] = 64 * 1024 * 1024
        pin(case["computer"])
        compile_program(case["computer"], case["requestId"], case["expression"])
        case["expression"]["leaf"]["contract"]["byteLength"] += 1
        self.assert_code("transfer_bytes", lambda: compile_program(case["computer"], case["requestId"], case["expression"]))

    def test_authoring_and_compilation_perform_no_io(self):
        case = FIXTURE["cases"][0]
        with patch("builtins.open", side_effect=AssertionError("file operation")), patch("socket.socket", side_effect=AssertionError("network operation")), patch("subprocess.Popen", side_effect=AssertionError("process operation")):
            expression = ProgramExpr.leaf(case["expression"]["leaf"])
            self.assertEqual(compile_program(case["computer"], case["requestId"], expression), case["expected"])
