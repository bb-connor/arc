#!/usr/bin/env python3
"""Reject implementation planning labels in maintained source and names."""

import argparse
import ast
from functools import lru_cache
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tokenize


SOURCE_ROOTS = frozenset({
    ".cargo", ".clusterfuzzlite", ".config", ".dst", ".github", ".kani", ".loom",
    "arena", "bench", "ci-gates", "config", "contracts", "crates", "deploy", "examples",
    "fixtures", "formal", "fuzz", "integrations", "labs", "packaging", "scripts", "sdks",
    "spec", "supply-chain", "tests", "tools", "wit", "xtask",
})
# Dated research observations preserve their original source provenance.
HISTORICAL_EVIDENCE_ROOTS = (Path("labs/openappa-recovery/evidence"),)
HISTORICAL_EVIDENCE_FILES = frozenset({Path("tests/replay/.bless-audit.log")})
EXCLUDED_DIRECTORIES = frozenset({
    "node_modules", "target", "dist", ".venv", "__pycache__", "vendor",
})
ROOT_SOURCE_FILES = frozenset({
    "Cargo.toml", "Makefile", "CMakeLists.txt", "Dockerfile", "deny.toml", "osv-scanner.toml", "package.json",
    "playwright.config.ts", "rust-toolchain.toml", "rustfmt.toml",
})
KNOWN_TEXT_SUFFIXES = frozenset({
    ".rs", ".inc", ".py", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs",
    ".cjs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".go", ".sh",
    ".toml", ".json", ".yaml", ".yml", ".sql", ".lean", ".tla", ".proto", ".cmake",
    ".kt", ".kts", ".swift", ".cs", ".csproj", ".in", ".tmpl", ".mod", ".cfg",
    ".conf", ".sb", ".service", ".sol", ".wit", ".txt", ".log", ".jsonl",
    ".svg", ".xml", ".html", ".css", ".scss", ".sass", ".less", ".rb", ".dart",
    ".properties", ".csv", ".tsv", ".lock", ".sum", ".snap",
})
TEXT_FILE_NAMES = frozenset({"README.md", "Makefile", "Dockerfile", "CMakeLists.txt"})
PATH_LABEL = re.compile(r"(?:^|[/_.-])(?:[pm][0-9]+|phase[_-]?[0-9]+|milestone[_-]?[0-9]+|task[_-]?[0-9]+)(?=[/_.-]|$)", re.I)
CONTENT_LABELS = (
    re.compile(r"\b(?:security|Chio) roadmap\b", re.I),
    re.compile(r"\bW[0-9]+(?:\.[0-9]+)+(?= +(?:lifecycle|rollout)\b)"),
    re.compile(r"\bdocs/architecture/recoverable-agent-runtime/implementation/p[0-9]+(?=/|[\"']|$)"),
    re.compile(r"\bfuture milestone\b", re.I),
    re.compile(r"\broadmap (?:items|properties|tasks)\b", re.I),
    re.compile(r"\b(?:tracked|gated)[^\r\n]*\broadmap\b", re.I),
    re.compile(r"\bproject/roadmap[-_][0-9]", re.I),
    re.compile(r"\b(?:phase|milestone)[ _-]*[0-9]+[a-z]?(?=[ _.:/-]|$)", re.I),
    re.compile(r"(?:\b|(?<=[a-z0-9_]))(?:[Pp]hase|[Mm]ilestone)[0-9]+(?=[A-Z_]|[^a-zA-Z0-9]|$)"),
    re.compile(r"\bM[0-9]+[ ._-]P[0-9]+(?:[ ._-]T[0-9]+)?\b"),
    re.compile(r"\bP[0-9]+\.T[0-9]+\b"),
    re.compile(r"\bCHIO_(?:[A-Z0-9]+_)*[PM][0-9]+(?:_|\b)"),
    re.compile(r"(?<![a-z0-9])[pm][0-9]+(?:[_-](?=[a-z])|(?=\.(?:contracts?|schema|vectors?))|(?= +(?:contracts?|schema|tests?|fixtures?|cutpoint|canary)))", re.I),
    re.compile(r"(?<![a-zA-Z0-9])[pm][0-9]+(?=[A-Z])"),
    re.compile(r"(?<=[a-zA-Z0-9][_.-])[pm][0-9]+(?=[^a-zA-Z0-9]|$)", re.I),
    re.compile(r"(?<![a-z0-9])m[0-9]{2}(?=[ _-][a-z])", re.I),
    re.compile(r"\bM[0-9]+(?= +[A-Za-z])"),
    re.compile(r"[\"'](?:introducedBy|provenance|schema)[\"']\s*:\s*[\"'][^\"'\r\n]*[_.-][pm][0-9]+(?=[\"'])", re.I),
    re.compile(r"\brecovery[-_/]p[0-9]+(?=[_./-]|$)", re.I),
    re.compile(r"\b(?:fn|def)\s+(?:\w*_)?(?:p[0-9]|phase_[0-9]+(?:_[0-9]+)*|task_[0-9]+)_"),
    re.compile(r"(?:^\s*(?://|#|\*|/\*)\s*|[\"'])Task\s+[0-9]+\b"),
    re.compile(r"\b(?:phase|milestone)[ _-]+(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\b", re.I),
)
BARE_LABEL = re.compile(r"(?<![a-zA-Z0-9_])[pm][0-9]+(?![a-zA-Z0-9_])|\btask[ _-]*[0-9]+\b", re.I)
RECOVERY_SOURCE = re.compile(r"recovery|recoverable-agent-runtime|semantic[-_]", re.I)
NUMBERED_COMMENT = re.compile(r"//|/\*|(?:^|\s)#(?![0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?\b)|^\s*(?:\*|<!--)")
QUOTED_TEXT = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
OPAQUE_BINARY_SUFFIXES = frozenset({".bin", ".seed", ".wasm", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".xz"})
SVG_GEOMETRY = re.compile(r"\bd\s*=\s*([\"'])(.*?)\1")
JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
C_COMMENT_SUFFIXES = JAVASCRIPT_SUFFIXES | frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".go", ".kt", ".kts",
    ".swift", ".cs", ".proto", ".sol", ".wit", ".inc",
})
C_RAW_LITERAL = re.compile(r'(?:u8|u|U|L)?R"([^()\s\\]{0,16})\(')
JSX_START = re.compile(r"<(?:[A-Za-z][A-Za-z0-9_.:-]*(?=[\s/>])|(?=>))")

# These literal values identify existing release records and frozen signed captures.
# Limit exceptions to their exact files; new source uses behavioral names.
def legacy_label(number, suffix, *, padded=False):
    """Represent an existing external record without naming new source after it."""
    return "m" + (str(number).zfill(2) if padded else str(number)) + suffix


LEGACY_ACCEPTANCE_KEY = legacy_label(5, "_acceptance_complete")
LEGACY_ACCEPTANCE_JSON_FILES = frozenset({
        "crates/products/chio-cli/tests/fixtures/process-call-observation/interrupted-provenance.json",
        "crates/products/chio-cli/tests/fixtures/process-call-observation/provenance.json",
        "crates/products/chio-cli/tests/fixtures/process-call-observation/unknown.json",
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/provenance.json",
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v1-network.json",
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-budget.json",
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-policy-bound-budget.json",
})
LEGACY_ACCEPTANCE_OUTPUT_FILES = frozenset({
    "crates/products/chio-cli/src/cli/process_host/call_evidence.rs",
    "crates/products/chio-cli/src/cli/process_host/call_evidence/export.rs",
    "crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs",
    "crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes_export.rs",
    "crates/products/chio-cli/src/cli/process_host/run_evidence.rs",
    "crates/products/chio-cli/src/cli/process_host/run_evidence/export.rs",
})
LEGACY_ACCEPTANCE_TEST_FILES = frozenset({
    "crates/products/chio-cli/tests/process_call_evidence.rs",
    "crates/products/chio-cli/tests/process_outcomes_evidence.rs",
    "crates/products/chio-cli/tests/process_run_evidence.rs",
})
COMPATIBILITY_LABELS = {
    legacy_label(8, "_internal_readiness_draft", padded=True): {"scripts/check-release-inputs.sh"},
    legacy_label(8, "_final_report", padded=True): {"scripts/check-release-inputs.sh"},
    legacy_label(9, "_hitrust_i1_readiness_package", padded=True): {"scripts/check-release-inputs.sh"},
    legacy_label(3, " hybrid canonical round trip", padded=True): {
        "crates/core/chio-core/tests/golden/hybrid_signature_v1.json",
    },
    legacy_label(5, "-release-budget-cb5a34e72-retry1"): {
        "crates/products/chio-cli/tests/fixtures/process-call-observation/unknown.json",
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-budget.json",
    },
    legacy_label(5, "-budget-release-cb5a34e72-retry1-anchor"): {
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-budget.json",
    },
    legacy_label(5, "-release-network-cb5a34e72"): {
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v1-network.json",
    },
    legacy_label(5, "-policy-binding-f3a9a558e"): {
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-policy-bound-budget.json",
    },
    legacy_label(5, "-policy-binding-f3a9a558e-anchor"): {
        "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-policy-bound-budget.json",
    },
}
# These complete data lines preserve existing versioned report and corpus
# interfaces. They do not permit comments, changed values or other symbols.
RETAINED_INTERFACE_DATA_LINES = {
    "scripts/check-corpus-metadata.sh": frozenset({
        json.dumps(legacy_label(3, "_counterexample", padded=True)) + ': "policy_counterexample",',
        json.dumps(legacy_label(2, "_verdict_divergence", padded=True)) + ': "sdk_verdict_divergence",',
    }),
    "examples/reference-swarm/process-run.py": frozenset({
        json.dumps(LEGACY_ACCEPTANCE_KEY) + ": False,",
    }),
    "scripts/tests/legacy-machine-interfaces.test.py": frozenset({
        "result = self.check_corpus_source(" + json.dumps(legacy_label(3, "_counterexample", padded=True)) + ")",
        "result = self.check_corpus_source(" + json.dumps(legacy_label(2, "_verdict_divergence", padded=True)) + ")",
        "self.assertIn(" + json.dumps(LEGACY_ACCEPTANCE_KEY) + ", report)",
        "self.assertIs(report[" + json.dumps(LEGACY_ACCEPTANCE_KEY) + "], False)",
    }),
}
SEVERITY_VALUE = re.compile(
    r"((?:\bseverity|\bpriority)[\"']?(?:\s*:\s*&?[a-z_][a-z0-9_:<> ]{0,24})?\s*[:=]\s*[\"']?)"
    r"P[0-5](?:(?:[-/, ]+)P[0-5])*(?=[\"';,\s]|$)", re.I,
)
FORMAL_PROPERTY_VALUE = re.compile(r"\bP[0-9]+(?:-P[0-9]+)?\b")
FORMAL_PROPERTY_FIELD = re.compile(
    r"((?:[\"']?(?:required_property_ids|property_ids|mapsTo)[\"']?)\s*[:=]\s*\[)"
    r"((?:\s*[\"']P[0-9]+[\"']\s*,?)*\s*)(\])",
)
FORMAL_PROPERTY_ANNOTATION = re.compile(r"(^\s*(?:///|/--|--)?\s*)P[0-9]+(?=:)")
FORMAL_PROPERTY_COVERAGE = re.compile(r"(\b(?:theorems|properties)\s+cover\s+)P[0-9]+(?:-P[0-9]+)?\b")
FORMAL_PROOF_FAMILY = re.compile(r"\bP[0-9]+(?:-P[0-9]+)?(?=\s+proof family\b)")
FORMAL_MONOTONICITY_PROPERTY = re.compile(r"(\bcapability monotonicity\s*\()P[0-9]+(?=\))")
FORMAL_FAIL_CLOSED_PROPERTY = re.compile(r"\bP[0-9]+(?=\s+fail-closed claim\b)")
FORMAL_REVOCATION_PROPERTY = re.compile(r"(\bdenial results for\s+)P[0-9]+\b")
SEVERITY_GAP = re.compile(r"\bP[0-5](?=\s+(?:soundness|safety|security|availability) gap\b)", re.I)
SEVERITY_PROSE = re.compile(r"\bP[0-5](?:[-/]P[0-5])*(?=\s+(?:alerts?|issues?|findings?|risks?|defects?|incidents?|bugs?|errors?|priority)\b)", re.I)
SEVERITY_CONTEXT = re.compile(
    r"((?:\bpriority|\bseverity)\s*\(?\s*|(?:\bpage|\bpaging)\s*\(?\s*(?:the\s+)?)"
    r"P[0-5](?:[-/]P[0-5])*\b", re.I,
)
SEVERITY_COUNT_KEY = re.compile(r"(?<=[\"'])open_p[0-3](?=[\"'])", re.I)
PACKAGE_RELEASE_PATCH = re.compile(r"(\b[a-z0-9][a-z0-9+_.-]*-[0-9]+(?:\.[0-9]+){1,3})_p[0-9]+(?=-r[0-9]+\b)", re.I)
GO_MODULE_DIGEST = re.compile(r"(?<=h1:)[a-zA-Z0-9+/]+={0,2}(?=\s|$)")
COMMAND_OPTIONS = (
    re.compile(r"(\bgrep\s+)-m[0-9]+\b"),
    re.compile(r"(\bpatch\s+)-p[0-9]+\b"),
    re.compile(r"([\"']patch[\"']\s*,\s*[\"'])-p[0-9]+(?=[\"'])"),
)
INCIDENT_ANCHOR = re.compile(r"(?<=incidents\.md#)p[01]-criteria\b")
NON_PLANNING_NUMBERED_NAMES = re.compile(r"(?<![a-zA-Z0-9])[pP](?:25|50|75|90|95|99|999|256|384|521)(?=[A-Z]|[^a-zA-Z0-9]|$)")
PKCS12_SUFFIX = ".p12"
CERTIFICATE_SUFFIX_LITERAL = re.compile(r"(?<=[\"'])" + re.escape(PKCS12_SUFFIX) + r"(?=[\"'])")
PACKAGE_PATCH_VERSION = re.compile(r"(?<=_)p[0-9]{8}(?=-r[0-9]+)")
INTEGRITY_DIGEST = re.compile(r"\bsha(?:256|384|512)-[a-zA-Z0-9+/]+={0,2}")
BASE64_SIGNATURE = re.compile(r"([\"'](?:sig|signature)[\"']\s*:\s*[\"'])[a-zA-Z0-9+/_-]{64,}={0,2}(?=[\"'])")
POTENTIAL_LABEL = re.compile(
    r"[pm][0-9]|phase|milestone|roadmap|task[ _-]*[0-9]|Root|sub[ -]?agent|owning worker|expected RED|[AW][0-9]+\.[0-9]+",
    re.I,
)
WORKFLOW_PROSE = (
    re.compile(r"\bRoot(?:['’]s)?[^\r\n]{0,80}\b(?:source|compiler) (?:lease|freeze)\b"),
    re.compile(r"\b(?:sub[ -]?agent|owning worker)(?:['’]s)?[^\r\n]{0,80}\b(?:draft|handoff|append|merge)\b", re.I),
    re.compile(r"\b[A-Z][0-9]+(?:\.[0-9]+)+\b[^\r\n]{0,80}\b(?:draft|PR|roadmap|task)\b"),
    re.compile(r"\bexplicit Root probes\b"),
    re.compile(r"\b(?:[Cc]leanup|[Rr]elease|[Aa]uthenticate)\b[^\r\n]{0,120}\b(?:before(?: (?:the|every))?|on the) expected RED\b"),
)
HISTORICAL_LOCATOR_SITES = frozenset({
    "fixtures/recovery-product/manifest_builder.py",
    "scripts/verify-recovery-qualification.py",
    "scripts/run-confined-return-linux-acceptance.py",
})
PROVENANCE_CONTROL = Path("scripts/source-name-provenance.json")
PROVENANCE_SHA256 = "4e76c30a18cee0e2e76e9d99843fc4e12e282b14aa39f0560233885d8b04c4d3"


def closed_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate provenance field: {key}")
        result[key] = value
    return result


@lru_cache(maxsize=1)
def provenance_policy():
    data = (Path(__file__).resolve().parents[1] / PROVENANCE_CONTROL).read_bytes()
    if hashlib.sha256(data).hexdigest() != PROVENANCE_SHA256:
        raise ValueError("historical provenance control changed without review")
    policy = json.loads(data, object_pairs_hook=closed_json_object)
    if policy["schema"] != "chio.source-name-provenance/v1":
        raise ValueError("unknown historical provenance control")
    return {item["path"]: item for item in policy["files"]}


def json_object_spans(text):
    """Locate JSON objects without treating braces inside strings as structure."""
    decoder = json.JSONDecoder(object_pairs_hook=closed_json_object)
    stack = []
    spans = []
    position = 0
    while position < len(text):
        if text[position] == '"':
            _, position = decoder.raw_decode(text, position)
            continue
        if text[position] == "{":
            stack.append(position)
        elif text[position] == "}":
            start = stack.pop()
            value, end = decoder.raw_decode(text, start)
            if end != position + 1:
                raise ValueError("ambiguous historical provenance object")
            spans.append((start, end, value))
        position += 1
    return spans


def mask_json_provenance(text, policy):
    document = json.loads(text, object_pairs_hook=closed_json_object)
    collection = "artifacts" if policy["path"] == "spec/schemas/registry.json" else "threats"
    records = document[collection]
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        raise ValueError("invalid historical provenance record collection")
    spans = json_object_spans(text)
    masks = []
    decoder = json.JSONDecoder()
    for approved in policy["records"]:
        candidates = [record for record in records if record.get(approved["record_key"]) == approved["record_value"]]
        if len(candidates) > 1:
            raise ValueError("duplicate historical provenance record")
        if not candidates or candidates[0].get(approved["field"]) != approved["value"]:
            continue
        objects = [(start, end) for start, end, value in spans if value == candidates[0]]
        if len(objects) != 1:
            raise ValueError("ambiguous historical provenance record location")
        start, end = objects[0]
        field = re.compile(r'"' + re.escape(approved["field"]) + r'"\s*:\s*')
        fields = []
        for match in field.finditer(text, start, end):
            value, finish = decoder.raw_decode(text, match.end())
            if value == approved["value"]:
                fields.append((match.end(), finish))
        if len(fields) != 1:
            raise ValueError("ambiguous historical provenance field location")
        masks.extend(fields)
    for start, end in sorted(masks, reverse=True):
        text = text[:start] + "".join("\n" if char == "\n" else " " for char in text[start:end]) + text[end:]
    return text


def mask_coverage_provenance(text, policy):
    """Support the historical coverage map's explicit scalar-record format."""
    approved = {(record["record_value"], record["field"]): record["value"] for record in policy["records"]}
    record = None
    seen = set()
    fields = set()
    lines = []
    for line in text.splitlines(keepends=True):
        identifier = re.fullmatch(r"  - id: ([a-z0-9_]+)\s*", line)
        if identifier:
            record = identifier[1]
            if record in seen:
                raise ValueError("duplicate historical coverage record")
            seen.add(record)
            fields = set()
        elif line.strip() and not line.startswith(("    ", "  #")):
            record = None
        field = re.match(r"    ([a-z_]+): ([^\r\n]*)(\r?\n)?$", line) if record else None
        if field:
            if field[1] in fields:
                raise ValueError("duplicate historical coverage field")
            fields.add(field[1])
            if approved.get((record, field[1])) == field[2]:
                line = line[:field.start(2)] + " " * len(field[2]) + line[field.end(2):]
        lines.append(line)
    return "".join(lines)


def source_lines(path, relative):
    policy = provenance_policy().get(relative.as_posix())
    compatibility = relative.as_posix() in LEGACY_ACCEPTANCE_JSON_FILES | LEGACY_ACCEPTANCE_OUTPUT_FILES | LEGACY_ACCEPTANCE_TEST_FILES
    is_compiled_source = relative.suffix in {".rs", ".lean"} | C_COMMENT_SUFFIXES
    is_python = relative.suffix == ".py"
    if policy or compatibility or is_compiled_source or is_python:
        text = path.read_text(encoding="utf-8")
        if policy:
            text = mask_json_provenance(text, policy) if policy["format"] == "json" else mask_coverage_provenance(text, policy)
        if compatibility:
            text = mask_legacy_interface(text, relative)
        has_hint = POTENTIAL_LABEL.search(text)
        if is_python and (has_hint or relative.as_posix() in HISTORICAL_LOCATOR_SITES):
            try:
                tree = ast.parse(text)
                comments = python_prose_lines(text, tree)
                text = mask_historical_artifact_locators(text, relative, tree)
            except (SyntaxError, tokenize.TokenError) as error:
                raise ValueError(f"invalid Python source: {error}") from error
        elif is_compiled_source and has_hint:
            comments = compiled_comment_lines(text, relative)
        else:
            comments = [""] * len(text.split("\n") if is_python else text.splitlines())
        lines = text.split("\n") if is_python else text.splitlines()
        if relative.parts[0] == "formal":
            comments = FORMAL_FAIL_CLOSED_PROPERTY.sub(lambda match: " " * len(match[0]), "\n".join(comments)).split("\n")
        for number, line in enumerate(lines, 1):
            yield number, line, comments[number - 1] if is_compiled_source or is_python else None
    else:
        with path.open(encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                yield number, line, None


@lru_cache(maxsize=1)
def rust_lexer():
    path = Path(__file__).resolve().with_name("check-recovery-boundaries.py")
    spec = importlib.util.spec_from_file_location("source_gate_rust", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.rust_tokens


def rust_comment_lines(text):
    """Preserve full-source comments while masking code and multiline literals."""
    pieces = []
    position = 0
    for _, _, start, end in rust_lexer()(text, with_spans=True):
        pieces.append(text[position:start])
        pieces.append(blank_code(text[start:end]))
        position = end
    pieces.append(text[position:])
    return "".join(pieces).splitlines()


def blank_code(text):
    """Mask code without changing the line coordinates used in diagnostics."""
    breaks = "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"
    return "".join(char if char in breaks else " " for char in text)


def physical_line_starts(text):
    """Locate Python physical lines without splitting Unicode text separators."""
    return [0, *(match.end() for match in re.finditer("\n", text))]


def node_offsets(text, node, starts=None):
    """Convert AST UTF-8 byte columns into source character offsets."""
    starts = physical_line_starts(text) if starts is None else starts
    offsets = []
    for number, column in ((node.lineno, node.col_offset), (node.end_lineno, node.end_col_offset)):
        start = starts[number - 1]
        end = starts[number] if number < len(starts) else len(text)
        prefix = text[start:end].encode("utf-8")[:column].decode("utf-8")
        offsets.append(start + len(prefix))
    return tuple(offsets)


def historical_artifact_prefixes(relative=None):
    """Describe the existing closed metadata-only artifact policy."""
    base = "docs/architecture/recoverable-agent-runtime/implementation"
    values = (
        "docs/integrations/acceptance",
        *(f"{base}/p{number}/evidence" for number in range(7)),
        "sdks/python/chio-hermes/evidence", "audits/evidence",
        "docs/integrations/session-credentials/evidence", "docs/evidence",
        "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
        "formal/mutation/evidence",
    )
    if relative is not None and relative.as_posix() == "scripts/run-confined-return-linux-acceptance.py":
        return tuple(sorted(values))
    return values


def binds_artifact_prefixes(node):
    """Recognize syntactic bindings without evaluating Python source."""
    name = "ARTIFACT_PREFIXES"
    if isinstance(node, ast.Name):
        return node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler,
                         ast.MatchAs, ast.MatchStar)):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, ast.arg):
        return node.arg == name
    if isinstance(node, ast.alias):
        return node.name == "*" or (node.asname or node.name.split(".", 1)[0]) == name
    return False


def mask_historical_artifact_locators(text, relative, tree):
    """Mask only literal values in the exact closed historical assignment."""
    if relative.as_posix() not in HISTORICAL_LOCATOR_SITES:
        return text
    bindings = [node for node in ast.walk(tree) if binds_artifact_prefixes(node)]
    declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "ARTIFACT_PREFIXES"]
    if len(bindings) != 1 or len(declarations) != 1:
        return text
    value = declarations[0].value
    if not isinstance(value, ast.Tuple) or not all(isinstance(node, ast.Constant)
            and isinstance(node.value, str) for node in value.elts):
        return text
    if tuple(node.value for node in value.elts) != historical_artifact_prefixes(relative):
        return text
    spans = []
    for node in value.elts[1:8]:
        start, end = node_offsets(text, node)
        tokens = list(tokenize.generate_tokens(io.StringIO(text[start:end]).readline))
        literals = [token for token in tokens if token.type == tokenize.STRING]
        if len(literals) != 1:
            return text
        spans.append((start, end))
    for start, end in reversed(spans):
        text = text[:start] + blank_code(text[start:end]) + text[end:]
    return text


def python_prose_lines(text, tree):
    """Preserve Python comments, documentation and unittest skip reasons."""
    starts = physical_line_starts(text)
    spans = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            line, column = token.start
            start = starts[line - 1] + column
            spans.append((start, start + len(token.string)))
    for node in ast.walk(tree):
        values = []
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr):
                values.append(first.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            function = node.func
            if isinstance(function.value, ast.Name) and function.value.id == "unittest":
                position = {"skip": 0, "skipIf": 1, "skipUnless": 1}.get(function.attr)
                if position is not None:
                    if len(node.args) > position:
                        values.append(node.args[position])
                    values.extend(keyword.value for keyword in node.keywords if keyword.arg == "reason")
        for value in values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                spans.append(node_offsets(text, value, starts))
    masked = list(blank_code(text))
    for start, end in spans:
        masked[start:end] = text[start:end]
    return "".join(masked).split("\n")


def lean_comment_lines(text):
    """Preserve Lean's line and nested block comments, excluding string literals."""
    masked = list(blank_code(text))
    position = 0
    while position < len(text):
        start = position
        if text.startswith("--", position):
            end = text.find("\n", position + 2)
            position = len(text) if end == -1 else end
            masked[start:position] = text[start:position]
        elif text.startswith("/-", position):
            position += 2
            depth = 1
            while depth and position < len(text):
                if text.startswith("/-", position):
                    depth += 1
                    position += 2
                elif text.startswith("-/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            if depth:
                raise ValueError("unterminated Lean block comment")
            masked[start:position] = text[start:position]
        elif text[position] == '"':
            position += 1
            while position < len(text) and text[position] != '"':
                position += 2 if text[position] == "\\" else 1
            if position >= len(text):
                raise ValueError("unterminated Lean string literal")
            position += 1
        else:
            position += 1
    return "".join(masked).splitlines()


def c_comment_lines(text, relative):
    """Preserve C-family comments, including JavaScript template expressions."""
    masked = list(blank_code(text))
    javascript = relative.suffix in JAVASCRIPT_SUFFIXES
    nested_comments = relative.suffix in {".kt", ".kts", ".swift"}

    def quoted(position, delimiter, *, escaped=True):
        position += len(delimiter)
        while position < len(text):
            if text.startswith(delimiter, position):
                return position + len(delimiter)
            position += 2 if escaped and text[position] == "\\" else 1
        raise ValueError("unterminated source literal")

    def regex_literal(position):
        position += 1
        in_class = False
        while position < len(text):
            char = text[position]
            if char == "\\":
                position += 2
                continue
            if char in "\r\n":
                raise ValueError("unterminated JavaScript regex literal")
            if char == "[":
                in_class = True
            elif char == "]":
                in_class = False
            elif char == "/" and not in_class:
                position += 1
                while position < len(text) and text[position].isalpha():
                    position += 1
                return position
            position += 1
        raise ValueError("unterminated JavaScript regex literal")

    def template(position):
        position += 1
        while position < len(text):
            if text[position] == "`":
                return position + 1
            if text[position] == "\\":
                position += 2
            elif text.startswith("${", position):
                position = code(position + 2, closing_brace=True)
            else:
                position += 1
        raise ValueError("unterminated JavaScript template literal")

    def jsx_tag(position):
        position += 1
        closing = text[position:position + 1] == "/"
        if closing:
            position += 1
        while position < len(text):
            if text.startswith("/>", position):
                return position + 2, True
            char = text[position]
            if char == ">":
                return position + 1, closing
            if char in {'"', "'"}:
                position = quoted(position, char)
            elif char == "{":
                position = code(position + 1, closing_brace=True)
            else:
                position += 1
        raise ValueError("unterminated JSX tag")

    def jsx(position):
        position, closed = jsx_tag(position)
        if closed:
            return position
        start = position
        while position < len(text):
            if text[position] in "<{":
                masked[start:position] = text[start:position]
                if text.startswith("</", position):
                    return jsx_tag(position)[0]
                if text[position] == "<":
                    position = jsx(position)
                else:
                    position = code(position + 1, closing_brace=True)
                start = position
            else:
                position += 1
        raise ValueError("unterminated JSX element")

    def code(position, *, closing_brace=False):
        braces = 1 if closing_brace else 0
        expression_position = True
        statement_position = not closing_brace
        parentheses = []
        brace_contexts = []
        pending_control = False
        pending_function = None
        pending_classes = []
        pending_body = None
        async_declaration = None
        module_declaration = False
        pending_label = None
        pending_case = None
        ternaries = []
        line_break = False
        previous_token = None
        while position < len(text):
            start = position
            char = text[position]
            raw = C_RAW_LITERAL.match(text, position) if relative.suffix in {".cc", ".cpp", ".cxx", ".hpp", ".hxx"} else None
            if text.startswith("//", position):
                end = text.find("\n", position + 2)
                position = len(text) if end == -1 else end
                masked[start:position] = text[start:position]
            elif text.startswith("/*", position):
                position += 2
                depth = 1
                while depth and position < len(text):
                    if nested_comments and text.startswith("/*", position):
                        depth += 1
                        position += 2
                    elif text.startswith("*/", position):
                        depth -= 1
                        position += 2
                    else:
                        position += 1
                if depth:
                    raise ValueError("unterminated source block comment")
                masked[start:position] = text[start:position]
                line_break = line_break or any(char in text[start:position] for char in "\r\n\u2028\u2029")
            elif raw:
                end = text.find(")" + raw[1] + '"', raw.end())
                if end == -1:
                    raise ValueError("unterminated C++ raw literal")
                position = end + len(raw[1]) + 2
                expression_position = False
                statement_position = False
                pending_body = None
                module_declaration = False
                line_break = False
                pending_control = False
                previous_token = "literal"
            elif relative.suffix in {".jsx", ".tsx"} and expression_position and char == "<" and JSX_START.match(text, position):
                position = jsx(position)
                expression_position = False
                statement_position = False
                pending_body = None
                module_declaration = False
                line_break = False
                pending_control = False
                previous_token = "literal"
            elif relative.suffix in {".cc", ".cpp", ".cxx", ".hpp", ".hxx"} and char.isdigit():
                position += 1
                while position < len(text) and (text[position].isalnum() or text[position] in "_.'"):
                    position += 1
                expression_position = False
                statement_position = False
                pending_body = None
                module_declaration = False
                line_break = False
                pending_control = False
                previous_token = "number"
            elif char in {'"', "'", "`"}:
                if char == "`" and javascript:
                    position = template(position)
                else:
                    delimiter = char * 3 if char != "`" and text.startswith(char * 3, position) and not javascript else char
                    position = quoted(position, delimiter, escaped=not (char == "`" and relative.suffix == ".go"))
                expression_position = False
                statement_position = False
                pending_body = None
                module_declaration = False
                line_break = False
                pending_control = False
                previous_token = "literal"
            elif javascript and char == "/" and expression_position:
                position = regex_literal(position)
                expression_position = False
                statement_position = False
                pending_body = None
                module_declaration = False
                line_break = False
                pending_control = False
                previous_token = "literal"
            elif char.isalpha() or char in "_$":
                position += 1
                while position < len(text) and (text[position].isalnum() or text[position] in "_$"):
                    position += 1
                word = text[start:position]
                if javascript and line_break and word in {"function", "class"} and not expression_position:
                    statement_position = True
                declaration = statement_position or module_declaration
                context = (len(parentheses), len(brace_contexts))
                if javascript and word in {"case", "default"} and statement_position and not module_declaration:
                    pending_case = context
                    pending_label = None
                else:
                    pending_label = context if javascript and statement_position else None
                if javascript and previous_token != ".":
                    if word == "function":
                        pending_function = async_declaration if previous_token == "async" and not line_break else declaration
                    elif word == "class":
                        pending_classes.append((declaration, len(parentheses), len(brace_contexts)))
                pending_control = javascript and (
                    previous_token != "." and word in {"if", "while", "for", "with", "switch", "catch"}
                    or word == "await" and previous_token == "for" and pending_control
                )
                async_declaration = declaration if word == "async" else None
                module_declaration = javascript and previous_token != "." and (
                    word == "export" and statement_position
                    or word in {"default", "async"} and module_declaration
                )
                expression_position = word in {"return", "throw", "case", "yield", "await", "typeof", "void", "delete", "in", "instanceof", "else", "do"} or word == "default" and module_declaration
                statement_position = word in {"else", "do", "try", "finally", "catch"} or word == "export" and module_declaration
                previous_token = word
                line_break = False
            else:
                if javascript and text[position:position + 2] in {"++", "--"}:
                    # Postfix updates finish a value. A preceding line break
                    # starts a prefix update and permits a regex operand.
                    expression_position = expression_position or line_break
                    statement_position = False
                    pending_body = None
                    pending_control = False
                    module_declaration = False
                    pending_label = None
                    line_break = False
                    previous_token = text[position:position + 2]
                    position += 2
                    continue
                if javascript and text.startswith("=>", position):
                    pending_body = False
                    expression_position = True
                    statement_position = True
                    pending_control = False
                    module_declaration = False
                    line_break = False
                    previous_token = "=>"
                    position += 2
                    continue
                if javascript and char == "(":
                    parentheses.append(("function", pending_function) if pending_function is not None
                                       else ("control", pending_control))
                    pending_function = None
                elif javascript and char == ")":
                    kind, context = parentheses.pop() if parentheses else ("control", False)
                    expression_position = kind == "control" and context
                    statement_position = expression_position
                    pending_body = context if kind == "function" else None
                    pending_control = False
                    module_declaration = False
                    line_break = False
                    previous_token = char
                    position += 1
                    continue
                if closing_brace and char == "{":
                    braces += 1
                elif closing_brace and char == "}":
                    braces -= 1
                    if not braces:
                        return position + 1
                if javascript and char == "{":
                    if line_break and (not expression_position or previous_token in {"return", "break", "continue"}):
                        statement_position = True
                    class_body = None
                    if (pending_body is None and pending_classes
                            and pending_classes[-1][1:] == (len(parentheses), len(brace_contexts))):
                        class_body = pending_classes.pop()[0]
                    body = pending_body if pending_body is not None else class_body
                    block = body is not None or statement_position or previous_token == ")"
                    # A statement body permits a new regex; expression bodies
                    # retain value context when their closing brace is reached.
                    brace_contexts.append((block, body if body is not None else statement_position))
                    pending_body = None
                    expression_position = True
                    statement_position = block
                    pending_control = False
                    module_declaration = False
                    pending_label = None
                    line_break = False
                    previous_token = char
                    position += 1
                    continue
                if javascript and char == "}":
                    _, expression_position = brace_contexts.pop() if brace_contexts else (False, False)
                    statement_position = expression_position
                    pending_control = False
                    module_declaration = False
                    line_break = False
                    previous_token = char
                    position += 1
                    continue
                if not char.isspace():
                    context = (len(parentheses), len(brace_contexts))
                    labelled_statement = False
                    if javascript and char == "?" and text[position + 1:position + 2] not in {"?", "."} and previous_token != "?":
                        ternaries.append(context)
                    elif javascript and char == ":":
                        if ternaries and ternaries[-1] == context:
                            ternaries.pop()
                        elif context in {pending_label, pending_case}:
                            labelled_statement = True
                            pending_label = None
                            pending_case = None
                    expression_position = char in "([{,:;=!?&|+-*/%~^<>"
                    statement_position = char == ";" or labelled_statement
                    pending_label = None
                    if char == ";":
                        pending_case = None
                    pending_body = None
                    pending_control = False
                    module_declaration = False
                    line_break = False
                    previous_token = char
                elif char in "\r\n\u2028\u2029":
                    line_break = True
                position += 1
        if closing_brace:
            raise ValueError("unterminated JavaScript template expression")
        return position

    code(0)
    return "".join(masked).splitlines()


def compiled_comment_lines(text, relative):
    if relative.suffix == ".rs" or (relative.suffix == ".inc" and relative.parts[0] == "crates"):
        return rust_comment_lines(text)
    if relative.suffix == ".lean":
        return lean_comment_lines(text)
    return c_comment_lines(text, relative)


def macro_ranges(tokens, names):
    ranges = []
    closing = {"(": ")", "[": "]", "{": "}"}
    for index, token in enumerate(tokens[:-2]):
        if token[0] != "identifier" or token[1] not in names or tokens[index + 1][1] != "!":
            continue
        opening = tokens[index + 2][1]
        if opening not in closing:
            continue
        stack = [closing[opening]]
        cursor = index + 3
        while stack and cursor < len(tokens):
            value = tokens[cursor][1]
            if value in closing:
                stack.append(closing[value])
            elif value in closing.values():
                if value != stack.pop():
                    raise ValueError("unbalanced interface macro")
            cursor += 1
        if stack:
            raise ValueError("unterminated interface macro")
        ranges.append((index + 3, cursor - 1))
    return ranges


def mask_legacy_interface(text, relative):
    """Permit an existing external key only in its serialized/asserted interface."""
    masks = []
    name = relative.as_posix()
    if name in LEGACY_ACCEPTANCE_JSON_FILES:
        json.loads(text, object_pairs_hook=closed_json_object)
        decoder = json.JSONDecoder()
        position = 0
        while position < len(text):
            if text[position] == '"':
                value, end = decoder.raw_decode(text, position)
                following = end
                while following < len(text) and text[following].isspace():
                    following += 1
                if value == LEGACY_ACCEPTANCE_KEY and text[following:following + 1] == ":":
                    masks.append((position, end))
                position = end
            else:
                position += 1
    else:
        tokens = rust_lexer()(text, with_spans=True)
        names = {"json"} if name in LEGACY_ACCEPTANCE_OUTPUT_FILES else {"assert", "assert_eq", "assert_ne"}
        contexts = macro_ranges(tokens, names)
        literal = json.dumps(LEGACY_ACCEPTANCE_KEY)
        for index, token in enumerate(tokens):
            if token[:2] != ("literal", literal) or not any(start <= index < end for start, end in contexts):
                continue
            if name in LEGACY_ACCEPTANCE_OUTPUT_FILES:
                permitted = index + 1 < len(tokens) and tokens[index + 1][1] == ":"
            else:
                permitted = (
                    index >= 2 and tokens[index - 1][1] == "["
                    and tokens[index - 2][0] == "identifier"
                    and index + 1 < len(tokens) and tokens[index + 1][1] == "]"
                )
            if permitted:
                masks.append((token[2], token[3]))
    for start, end in sorted(masks, reverse=True):
        text = text[:start] + " " * (end - start) + text[end:]
    return text


def comment_text(relative, line):
    """Locate prose without treating URL literals as comment markers."""
    if relative.suffix in {".rs", ".lean"} | C_COMMENT_SUFFIXES:
        return "\n".join(compiled_comment_lines(line, relative))
    def blank(match):
        return " " * len(match[0])
    masked = QUOTED_TEXT.sub(blank, line)
    match = NUMBERED_COMMENT.search(masked)
    return line[match.start():] if match else ""


@lru_cache(maxsize=128)
def compatibility_patterns_for(relative):
    name = relative.as_posix()
    return tuple(
        re.compile(r"(?<![a-zA-Z0-9_-])" + re.escape(label) + r"(?![a-zA-Z0-9_-])")
        for label, allowed_paths in COMPATIBILITY_LABELS.items()
        if name in allowed_paths
    )


def mask_semantic_values(relative, text):
    text = INTEGRITY_DIGEST.sub("", text)
    text = BASE64_SIGNATURE.sub(r"\1", text)
    text = NON_PLANNING_NUMBERED_NAMES.sub("", text)
    text = CERTIFICATE_SUFFIX_LITERAL.sub("", text)
    text = PACKAGE_PATCH_VERSION.sub("", text)
    text = PACKAGE_RELEASE_PATCH.sub(r"\1", text)
    text = SEVERITY_VALUE.sub(r"\1", text)
    text = SEVERITY_PROSE.sub("", text)
    text = SEVERITY_CONTEXT.sub(r"\1", text)
    text = SEVERITY_COUNT_KEY.sub("", text)
    text = SEVERITY_GAP.sub("", text)
    for option in COMMAND_OPTIONS:
        text = option.sub(r"\1", text)
    if relative.parts[0] == "formal":
        text = FORMAL_PROPERTY_FIELD.sub(lambda match: match[1] + FORMAL_PROPERTY_VALUE.sub("", match[2]) + match[3], text)
        text = FORMAL_PROPERTY_ANNOTATION.sub(r"\1", text)
        text = FORMAL_PROPERTY_COVERAGE.sub(r"\1", text)
        text = FORMAL_PROOF_FAMILY.sub("", text)
        text = FORMAL_MONOTONICITY_PROPERTY.sub(r"\1", text)
        text = FORMAL_REVOCATION_PROPERTY.sub(r"\1", text)
    if relative.suffix == ".svg":
        text = SVG_GEOMETRY.sub("", text)
    if relative.name == "go.sum":
        text = GO_MODULE_DIGEST.sub("", text)
    text = INCIDENT_ANCHOR.sub("", text)
    for pattern in compatibility_patterns_for(relative):
        text = pattern.sub("", text)
    return text


def has_planning_label(relative, line, *, prose=None):
    if not POTENTIAL_LABEL.search(line):
        return False
    if (line.strip() in RETAINED_INTERFACE_DATA_LINES.get(relative.as_posix(), ())
            and not (prose if prose is not None else comment_text(relative, line)).strip()):
        return False
    text = mask_semantic_values(relative, line)
    if any(pattern.search(text) for pattern in CONTENT_LABELS):
        return True
    name = relative.as_posix()
    # Bare tokens in runtime protocol IDs and ordinary variables are ambiguous.
    # Recovery sources, prose annotations and plain text inputs have no such
    # exception; explicit phase/milestone/task annotations are rejected globally.
    bare_is_label = (
        RECOVERY_SOURCE.search(name)
        or name in {"scripts/check-source-names.py", "scripts/tests/check-source-names.test.py"}
        or name in LEGACY_ACCEPTANCE_OUTPUT_FILES | LEGACY_ACCEPTANCE_TEST_FILES | LEGACY_ACCEPTANCE_JSON_FILES
        or name in provenance_policy()
        or relative.suffix.lower() == ".svg"
        or relative.suffix.lower() not in KNOWN_TEXT_SUFFIXES
        or relative.suffix.lower() in {".txt", ".log", ".jsonl"}
        or relative.name == ".gitkeep"
    )
    comments = comment_text(relative, text) if prose is None else mask_semantic_values(relative, prose)
    if any(pattern.search(comments) for pattern in WORKFLOW_PROSE):
        return True
    return bool(BARE_LABEL.search(text if bare_is_label else comments))


def is_dockerfile(path):
    name = path.name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def source_paths(root):
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root,
    ).decode("utf-8").split("\0")
    for name in sorted(set(names) - {""}):
        path = Path(name)
        is_model = path.is_relative_to("docs/architecture/recoverable-agent-runtime/model")
        is_root_input = name in ROOT_SOURCE_FILES or (len(path.parts) == 1 and is_dockerfile(path))
        if path.parts[0] not in SOURCE_ROOTS and not is_root_input and not is_model:
            continue
        if EXCLUDED_DIRECTORIES.intersection(path.parts):
            continue
        if any(path.is_relative_to(base) for base in HISTORICAL_EVIDENCE_ROOTS):
            continue
        if path in HISTORICAL_EVIDENCE_FILES:
            continue
        # Specifications and acceptance records can retain their planning history.
        if path.suffix == ".md" and not (path.parts[0] == "crates" and path.name == "README.md"):
            continue
        if (root / path).is_file() and not (root / path).is_symlink():
            yield path


def violations(root):
    for relative in source_paths(root):
        if PATH_LABEL.search(NON_PLANNING_NUMBERED_NAMES.sub("", relative.as_posix())):
            yield f"{relative}: numbered planning label in source path"
        try:
            if relative == PROVENANCE_CONTROL:
                if hashlib.sha256((root / relative).read_bytes()).hexdigest() != PROVENANCE_SHA256:
                    yield f"{relative}: historical provenance control changed without review"
                continue
            with (root / relative).open("rb") as source:
                header = source.read(512)
            known_text = (
                relative.suffix.lower() in KNOWN_TEXT_SUFFIXES
                or relative.name in TEXT_FILE_NAMES
                or relative.name == ".gitkeep"
                or is_dockerfile(relative)
                or header.startswith(b"#!")
                or (relative.parts[0] == "scripts" and not relative.suffix)
            )
            # Text is scanned regardless of suffix. Recognized binary assets are
            # excluded by their bytes; adding a binary byte to source cannot hide it.
            binary = b"\0" in header or header.startswith((
                b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"\xff\xd8\xff",
                b"%PDF-", b"PK\x03\x04", b"\x1f\x8b", b"\xfd7zXZ\0", b"\x7fELF",
            ))
            if binary:
                if known_text:
                    yield f"{relative}: binary bytes in maintained text source"
                continue
            for number, line, prose in source_lines(root / relative, relative):
                if "\0" in line:
                    yield f"{relative}:{number}: binary bytes in maintained text source"
                elif has_planning_label(relative, line, prose=prose):
                    yield f"{relative}:{number}: numbered planning label in source"
        except UnicodeDecodeError:
            if relative.suffix.lower() not in OPAQUE_BINARY_SUFFIXES:
                yield f"{relative}: maintained text is not valid UTF-8"
        except (ValueError, KeyError, TypeError) as error:
            yield f"{relative}: invalid maintained source: {error}"
        except OSError as error:
            yield f"{relative}: source could not be read: {error}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    findings = list(violations(args.root.resolve(strict=True)))
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("Source names: no implementation planning labels.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
