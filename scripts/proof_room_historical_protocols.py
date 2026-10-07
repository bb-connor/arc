"""Classify exact retained review references without editing their provenance.

Only the bare ACP token is classified. Public-release and all other stop-pattern
checks still inspect these lines. This module cannot excuse current claim copy.
"""
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

HISTORICAL_LINE_PROTOCOLS = {
    "docs/reviews/2026-10-06-pr1160/architecture.md": {
        "615c1cca5a29de3942fefb31956dbedd2c9c5562d20e8db4a09162dfdd117d32": "ACP-Client"
    },
    "docs/reviews/2026-10-06-pr1160/findings.md": {
        "48fa99307ffe89e43e8bbd538dac031098639b802d490437fb4600eea7730fcf": "ACP-Commerce",
        "8e5cb2f54df008a67a9cfb7c8db7a03e60615a0b5acd9d2990f70f9b2907ff2b": "ACP-Client",
        "d08a972ca7b258e7dd45387d1a51b770873cc9090c6a2a064cde3e25034cd2cb": "ACP-Client"
    },
    "docs/reviews/2026-10-06-pr1160/slices.md": {
        "1fd29f6302c15d18bec53f1901860dcfcb5064d70a793b6c9b20b68c94936fa2": "ACP-Client",
        "20d3bcfee1939cbfaac0596daddc46411efbee73da8dee86deb44701d3201495": "ACP-Client",
        "4f3e317ab0aaf7c5189d27ec0d66c74b512c0da9ebc5fe317cce0c0c61875eed": "ACP-Client",
        "8fa06ae9bc5a60a9aee0fda94ac4fe1aae616aa68295c9a679df16b0213cc138": "ACP-Client",
        "be2e35b58ceb476446dd08b37ff8e3a074698af446d7e69995ef32f7bc0b61ae": "ACP-Client",
        "c29afce4db7f5c163ef5b0bb0d5b1ff5e367791c161f2f2bcd752949044b67e0": "ACP-Client"
    },
    "docs/security/audits/review-followup-20261007/published-independent-review.md": {
        "c22c44dd135b31820635c0211a52acef9fc9743ecb4474dcf169b5c9dfdc7cde": "ACP-Client"
    },
    "docs/security/landing-ledger.md": {
        "e52e2161c7ddab43bc13f9c4aa2faa0b9834f91448ccd803b23598781ac2d283": "ACP-Client"
    }
}
HISTORICAL_SOURCE_SHA256 = {
    "docs/reviews/2026-10-06-pr1160/architecture.md": "513fe0f8efbb09a4034f917f3ecb8de1f07e1ce861c2ad33ebefa7edff6ebdf5",
    "docs/reviews/2026-10-06-pr1160/findings.md": "81b2fc55736cb9e681b540c2cef803cc43f97c679c7062b70d9a39c23d12cb26",
    "docs/reviews/2026-10-06-pr1160/slices.md": "b511b0b2cd1e53d21c491af7b0725e33a5d3a05333752f6779309e53b559c3e5",
    "docs/security/audits/review-followup-20261007/published-independent-review.md": "4bc816f26d702413502b18f298b68b341cc31befc96dccc78d5deabc93ae23d7"
}
LEDGER = "docs/security/landing-ledger.json"
REQUIREMENT_ID = 'incoming-pr1160-review-20261006:F062'
REQUIREMENT = 'Decode unsigned ACP envelopes with document semantics, not signed-number rules'
SOURCE_IDENTITY = {
    "additional_lines": [],
    "checkpoint": "5696c4cf04a1a8368ef36dd51618ea1bd5f7fbfc",
    "line": 507,
    "line_sha256": "d08a972ca7b258e7dd45387d1a51b770873cc9090c6a2a064cde3e25034cd2cb",
    "path": "docs/reviews/2026-10-06-pr1160/findings.md",
    "reviewed_source": "d0496c14d824a327f00b98576132834306ff6694"
}
COMPACT_ROW_SHA256 = '6a0f2582ce387b33680ad91f839f70a1fb196bd87cfec7c523d07500a8a4f1ed'
PRETTY_REQUIREMENT_SHA256 = 'cf382547e483be7351486fb49e3339a9ca0a228cfce5d481aa9bf24e1bfdbcff'
OLD_SCOPE_SHA256 = '5dcf1c5b8af1974c39a4680ca585e418619af72e5b75e1ba09c401f07e3e494f'
OLD_SCOPE_CONTEXT_SHA256 = '666c8e89963526e8de10743d6cf8b823e5c32e33d39787ef0efdbd26a21ed291'
OLD_SCOPE = 'ACP/MCP/OpenAPI test fixture source/external ownings do not qualify finalSource'


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate historical context key")
        result[key] = value
    return result


@lru_cache(maxsize=4)
def ledger_context(text):
    try:
        document = json.loads(text, object_pairs_hook=unique_object)
        rows = [row for row in document["requirements"] if row["id"] == REQUIREMENT_ID]
        current = document["current_requirement_states"][REQUIREMENT_ID]
        scope = document["current_view_refresh_488_observations_20261007"]["source_basis"]
        source_valid = len(rows) == 1 and rows[0]["source"] == SOURCE_IDENTITY and rows[0]["requirement"] == REQUIREMENT
        current_valid = current["historical_source_identity"] == SOURCE_IDENTITY and current["requirement"] == REQUIREMENT
        # The two retained summary copies are the only appearances. A same-text
        # current claim or moved field cannot borrow historical provenance.
        summaries_valid = source_valid and current_valid and text.count(json.dumps(REQUIREMENT)) == 2
        scope_valid = scope["external_protocol_owning_scope"] == OLD_SCOPE and digest(json.dumps(scope, sort_keys=True, separators=(",", ":"))) == OLD_SCOPE_CONTEXT_SHA256 and text.count(json.dumps(OLD_SCOPE)) == 1
        return summaries_valid, scope_valid
    except (ValueError, TypeError, KeyError):
        return False, False


def typed_historical_protocol(root: Path, path: Path, line: str, match):
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return None
    family = HISTORICAL_LINE_PROTOCOLS.get(relative, {}).get(digest(line))
    if family:
        expected_source = HISTORICAL_SOURCE_SHA256.get(relative)
        if expected_source and hashlib.sha256(path.read_bytes()).hexdigest() != expected_source:
            return None
        if not expected_source and path.read_text(encoding="utf-8").splitlines().count(line) != 1:
            return None
        return family
    if relative != LEDGER:
        return None
    summaries_valid, scope_valid = ledger_context(path.read_text(encoding="utf-8"))
    fingerprint = digest(line)
    if summaries_valid and fingerprint in {COMPACT_ROW_SHA256, PRETTY_REQUIREMENT_SHA256}:
        field = re.search(r'"requirement"\s*:\s*(?P<value>"(?:\\.|[^"\\])*")', line)
        if field and json.loads(field["value"]) == REQUIREMENT and field.start("value") <= match.start() < match.end() <= field.end("value"):
            return "ACP-Client"
    if scope_valid and fingerprint == OLD_SCOPE_SHA256:
        field = re.search(r'"external_protocol_owning_scope"\s*:\s*(?P<value>"(?:\\.|[^"\\])*")', line)
        if field and json.loads(field["value"]) == OLD_SCOPE and field.start("value") <= match.start() < match.end() <= field.end("value"):
            return "ACP-Client"
    return None
