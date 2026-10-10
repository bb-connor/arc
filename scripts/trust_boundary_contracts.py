"""Scoped lexical evidence for the JSON trust-boundary inventory.

Input is Rust with comments, literals and test items masked by the caller. This
is deliberately not Rust name resolution, macro expansion or dataflow analysis.
Recognized chains, local bindings and named function bodies give reviewable
tripwires; an unrecognized constructor must not silently become evidence.
"""
from collections import Counter, defaultdict
from functools import lru_cache
import importlib.util
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location("trust_boundary_reader_rules", Path(__file__).with_name("trust_boundary_reader_rules.py"))
_rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rules)
SUPPORT_PATHS = _rules.SUPPORT_PATHS

METHODS = frozenset({
    "canonicalize", "decode_external", "decode_document", "decode_signed",
    "decode_canonical", "decode_canonical_with",
})
FUNCTION = re.compile(r"\bfn\s+(\w+)\s*(?:<[^{};]*>)?\s*\(")


def closing(code, start, left="(", right=")"):
    depth = 1
    for index in range(start + 1, len(code)):
        depth += (code[index] == left) - (code[index] == right)
        if not depth:
            return index + 1
    return len(code)


@lru_cache(maxsize=8192)
def functions(code):
    """Return actual function extents, including nested/duplicate definitions."""
    rows = []
    for match in FUNCTION.finditer(code):
        parameters_end = closing(code, match.end() - 1)
        body = parameters_end
        while body < len(code) and code[body] not in ";{":
            if code[body] in "[(":
                body = closing(code, body, code[body], "]" if code[body] == "[" else ")")
            else:
                body += 1
        if body == len(code) or code[body] == ";":
            continue
        rows.append((match.group(1), match.start(), body, closing(code, body, "{", "}")))
    counts = Counter(row[0] for row in rows)
    ordinals = Counter()
    result = []
    for name, start, body, end in rows:
        ordinals[name] += 1
        symbol = name if counts[name] == 1 else f"{name}#{ordinals[name]}"
        result.append((symbol, start, body, end))
    return tuple(result)


def function_at(code, offset):
    return next((row for row in reversed(functions(code)) if row[1] <= offset < row[3]), None)


@lru_cache(maxsize=16384)
def owner_code(code, row):
    """Do not accept a nested helper's calls as evidence for its enclosing owner."""
    output = list(code[row[1]:row[3]])
    for nested in functions(code):
        if row[1] < nested[1] < nested[3] <= row[3]:
            output[nested[1] - row[1]:nested[3] - row[1]] = " " * (nested[3] - nested[1])
    return "".join(output)


def input_names(code):
    names = {"UntrustedJsonText"}
    names.update(re.findall(r"\bUntrustedJsonText\s+as\s+(\w+)", code))
    names.update(re.findall(r"\btype\s+(\w+)(?:<[^;=]*>)?\s*=\s*(?:\w+::)*UntrustedJsonText\b", code))
    return names


def receiver_methods(code, receiver):
    pattern = r"\b" + re.escape(receiver) + r"\s*\.\s*(\w+)\s*(?=\(|::<)"
    return [match.group(1) for match in re.finditer(pattern, code) if match.group(1) in METHODS]


def chain_methods(code, start):
    methods = []
    cursor = start
    while True:
        match = re.match(r"\s*\??\s*\.\s*(\w+)\s*(?:::<[^;{}]*?>\s*)?\(", code[cursor:])
        if not match:
            return methods, cursor
        method = match.group(1)
        argument_start = cursor + match.end() - 1
        argument_end = closing(code, argument_start)
        if method in METHODS:
            methods.append(method)
        elif method in {"and_then", "map"}:
            arguments = code[argument_start + 1:argument_end - 1]
            closure = re.match(r"\s*(?:move\s+)?\|\s*(\w+)\s*\|", arguments)
            if closure:
                methods.extend(receiver_methods(arguments[closure.end():], closure.group(1)))
        cursor = argument_end


@lru_cache(maxsize=8192)
def decoding_contracts(code):
    contracts, errors, ordinals = [], [], Counter()
    names = "|".join(re.escape(name) for name in sorted(input_names(code)))
    for match in re.finditer(rf"\b(?:{names})\s*::\s*(new|from_wire)\s*\(", code):
        row = function_at(code, match.start())
        if not row:
            errors.append("constructor outside a named function")
            continue
        constructor = match.group(1)
        ordinals[row[0]] += 1
        site = f"{row[0]}::{constructor}#{ordinals[row[0]]}"
        arguments_end = closing(code, match.end() - 1)
        methods, chain_end = chain_methods(code, arguments_end)
        if not methods:
            prefix = code[row[2] + 1:match.start()]
            binding = re.search(r"\blet\s+(?:mut\s+)?(\w+)(?:\s*:[^=;]+)?\s*=\s*(?:\w+\s*::\s*)*$", prefix)
            if binding:
                # Only the constructor's local receiver (and direct aliases) can
                # witness its contract. Another receiver or function cannot.
                body = owner_code(code, row)
                remaining = body[arguments_end - row[1]:]
                receivers = [(binding.group(1), remaining)]
                names_seen = {binding.group(1)}
                for receiver, receiver_scope in receivers:
                    shadow = re.search(r"\b(?:let\s+(?:mut\s+)?" + re.escape(receiver) + r"\b|" + re.escape(receiver) + r"\s*=(?!=))", receiver_scope)
                    scope = receiver_scope[:shadow.start()] if shadow else receiver_scope
                    methods.extend(receiver_methods(scope, receiver))
                    for alias in re.finditer(r"\blet\s+(\w+)\s*=\s*&?" + re.escape(receiver) + r"\s*;", scope):
                        if alias.group(1) not in names_seen:
                            names_seen.add(alias.group(1))
                            receivers.append((alias.group(1), scope[alias.end():]))
            elif constructor == "from_wire" and re.match(r"\s*\?\s*;", code[chain_end:]):
                # A discarded wire validation checks size/UTF-8 only. Private
                # seed DTOs intentionally decode directly into wiping fields.
                methods = ["bounds_only"]
            elif constructor == "from_wire" and re.match(r"\s*\.\s*map\s*\(\s*\|_\|", code[arguments_end:]):
                methods = ["bounds_only"]
        if not methods:
            errors.append(f"unresolved decoding contract: {site}")
        contracts.append(f"{site}::{'+'.join(methods) or 'unresolved'}")
    return tuple(contracts), tuple(errors)


def reader_observations(code, decoders):
    readers = defaultdict(list)
    missing = []
    for offset, decoder in decoders:
        row = function_at(code, offset)
        if row:
            readers[row].append(decoder)
        else:
            missing.append(decoder)
    return readers, missing


def calls(body, name):
    return bool(re.search(r"(?<![\w:.])" + re.escape(name) + r"\s*(?:::<[^;{}]*?>\s*)?\(", body))


def canonical_call(body, name):
    return any(calls(body, prefix + name) for prefix in (
        "", "super::", "crate::", "chio_core::", "chio_core::canonical::",
        "chio_core_types::", "chio_core_types::canonical::", "chio_cage_plan::",
    ))


def canonical_equality(body):
    """Require a canonical encoder result in an inequality rejection condition."""
    encode = r"(?:(?:chio_core|chio_core_types)::(?:canonical::)?|chio_cage_plan::|crate::|super::)?canonical_json_bytes(?:_zeroizing)?\s*\("
    for match in re.finditer(r"\blet\s+(\w+)\s*=\s*(?:Zeroizing::new\s*\(\s*)?" + encode, body):
        variable = re.escape(match.group(1))
        if re.search(r"(?:\bif\b[^{};]*\b" + variable + r"(?:\.(?:as_slice|as_bytes)\(\))?\s*!=|\bif\b[^{};]*!=\s*" + variable + r"\b)", body[match.end():]):
            return True
    return bool(re.search(r"\bif\s+" + encode + r"[^;{}]*!=", body))


def local_apis(path, code, row, decoders, constructors, production_code, supports):
    """Small allowlist of meaningful lexical APIs, never catalog-supplied regexes.

    Call evidence is scoped to the raw reader. Projections/deserializers describe
    typed conversion only; they do not assert authentication or original bytes.
    """
    body = owner_code(code, row)
    apis = []
    if not production_code[row[1]:row[3]].strip():
        return ["cfg(test)"], True
    if "examples" in path.split("/") or path.endswith("/fuzz.rs"):
        return ["example-or-fuzz"], True
    if "from_value" in decoders:
        apis.append("serde_json::from_value")
    if "custom_deserialize" in decoders and row[0].split("#")[0] == "deserialize" and re.search(r"\bDeserializer\s*<", body):
        apis.append("serde::Deserializer")
    raw = [decoder for decoder in decoders if decoder not in {"from_value", "custom_deserialize"}]
    if not raw:
        return apis, bool(apis) and ("custom_deserialize" not in decoders or "serde::Deserializer" in apis)
    for contract in constructors:
        if contract.split("::", 1)[0] == row[0] and not contract.endswith("unresolved"):
            apis.append("UntrustedJsonText::" + contract.split("::", 1)[1])
    if canonical_call(body, "canonical_json_bytes_from_str"):
        apis.append("canonical_json_bytes_from_str")
    if canonical_equality(body):
        apis.append("canonical_json_bytes+original_equality")
    for writer in re.findall(r"\bserde_json::to_writer\s*\(\s*&mut\s+(\w+)\s*,", body):
        if re.search(r"\bserde_json::from_slice\s*\(\s*&" + re.escape(writer) + r"\.", body):
            apis.append("serde_json::to_writer+same_buffer")
    for name in re.findall(r"\b(\w+)\s*:\s*&(?:\w+::)*CanonicalBody\b", body[:row[2] - row[1]]):
        if re.search(r"\bserde_json::from_slice\s*\(\s*" + re.escape(name) + r"\.as_bytes\s*\(", body):
            apis.append("CanonicalBody::as_bytes")
    apis.extend(_rules.special_apis(path, row[0], body, supports))
    constrained = [api for api in apis if api not in {"serde_json::from_value", "serde::Deserializer"}]
    return sorted(set(apis)), bool(constrained)


def reader_evidence(path, code, decoders, production_code, supports=None):
    return _reader_evidence(path, code, tuple(decoders), production_code, tuple(sorted((supports or {}).items())))


@lru_cache(maxsize=2048)
def _reader_evidence(path, code, decoders, production_code, support_items):
    supports = dict(support_items)
    grouped, missing = reader_observations(code, decoders)
    constructors, _ = decoding_contracts(code)
    bodies = {row[0]: owner_code(code, row) for row in functions(code)}
    checked_helpers = {}
    for row in functions(code):
        apis, valid = local_apis(path, code, row, ["from_str"], constructors, production_code, supports)
        if valid and apis not in (["cfg(test)"], ["example-or-fuzz"]):
            checked_helpers[row[0]] = apis
    observations = []
    for row, sites in grouped.items():
        apis, valid = local_apis(path, code, row, sites, constructors, production_code, supports)
        if not valid:
            for helper, helper_apis in checked_helpers.items():
                helper_name = helper.split("#")[0]
                alternatives = [name for name in bodies if name.split("#")[0] == helper_name]
                if helper != row[0] and all(name in checked_helpers for name in alternatives) and calls(bodies[row[0]], helper_name):
                    apis.extend(f"call::{helper}::{api}" for api in helper_apis)
            apis.extend(_rules.private_producer_apis(path, row[0], bodies[row[0]], bodies, calls, canonical_equality))
            valid = any(api not in {"serde_json::from_value", "serde::Deserializer"} for api in apis)
        observations.append({"reader": row[0], "decoders": sorted(sites), "apis": apis, "checked": valid})
    for decoder in missing:
        observations.append({"reader": "<unresolved>", "decoders": [decoder], "apis": [], "checked": False})
    # Generated wire types have hundreds of equally named Deserialize methods.
    # Check every body above, then group only identical evidence. A weaker or
    # missing API in one body yields a separate invalid row, never an exemption.
    groups = defaultdict(list)
    for observed in observations:
        key = (observed["reader"].split("#")[0], tuple(observed["decoders"]), tuple(observed["apis"]), observed["checked"])
        groups[key].append(observed)
    compact = []
    for key, equivalent in groups.items():
        first = equivalent[0].copy()
        if len(equivalent) > 1:
            first["reader"] = key[0]
            first["instances"] = len(equivalent)
        compact.append(first)
    return sorted(compact, key=lambda row: row["reader"])
