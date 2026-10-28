#!/usr/bin/env python3
"""Census every `subject_key` reader and writer as a real key or a derived enterprise subject.

A real key is an agent's Ed25519 public key: entropy-backed, read by signature and
authorization readers, and kept in its hex form. A derived enterprise subject names an
enterprise principal, and the only derivation of one is the keyed `esk1.` value under the
`enterprise-subject` purpose of the tenant index key set
(`chio_core_types::enterprise_subject`).

Every line of Rust under crates/ that names the token `subject_key` or `subjectKey` is
classified:

- A file that names enterprise identity (any ENTERPRISE_MARKERS pattern) is classified line
  by line through LINE_RULES. A line that no rule matches fails the census.
- Any other file is real-key when it lies in one of REAL_KEY_CRATES. A file outside them fails.

The census also refuses unkeyed enterprise subject derivations and the unkeyed SCIM receipt
aliases (UNKEYED_PATTERNS). Each site is identified by its file, the function that owns it
(the nearest preceding `fn` item) and its kind. PENDING_UNKEYED pins the count of every
remaining site; a site not in it fails, a count above or below its pin fails, and an entry with
no matching site fails, so the set only shrinks.

Usage: python3 -I scripts/check-enterprise-subject-census.py [--list]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"\b(?:subject_key|subjectKey)\b")
GENERATED = "/_generated/"

ENTERPRISE_MARKERS = re.compile(
    r"EnterpriseIdentityContext|\benterprise_identity\b|enterpriseIdentity|EnterpriseAdmissionAudit"
    r"|EnterpriseIdentityProvenance|ChioScimUserExtension|ScimLifecycle|scimLifecycle"
    r"|CHIO_SCIM_USER_EXTENSION_SCHEMA|derive_enterprise_subject_key"
)

REAL_KEY_CRATES = (
    "crates/core/chio-core/",
    "crates/core/chio-core-types/",
    "crates/economy/chio-autonomy/",
    "crates/economy/chio-credit/",
    "crates/economy/chio-market/",
    "crates/economy/chio-settle/",
    "crates/economy/chio-underwriting/",
    "crates/economy/chio-web3/",
    "crates/kernel/chio-kernel/",
    "crates/kernel/chio-process/",
    "crates/platform/chio-control-plane/",
    "crates/platform/chio-store-sqlite/",
    "crates/products/chio-api-protect/",
    "crates/products/chio-cli/",
    "crates/protocol/chio-mcp-edge/",
    "crates/protocol/chio-mcp-remote/",
    "crates/security/chio-secret-broker/",
    "crates/tooling/chio-bundle-verify/",
    "crates/trust/chio-credentials/",
    "crates/trust/chio-federation/",
    "crates/trust/chio-reputation/",
)

REAL = "real-key"
DERIVED = "derived-enterprise"

CONTROL_PLANE = "crates/platform/chio-control-plane/src/"
CLI_TESTS = "crates/products/chio-cli/tests/"
CREDENTIALS = "crates/trust/chio-credentials/"

# (path, line pattern, class). Patterns match the stripped source line.
LINE_RULES: tuple[tuple[str, str, str], ...] = (
    ("crates/core/chio-core-types/src/session/auth.rs", r"^pub subject_key: String,$", DERIVED),
    ("crates/core/chio-core-types/src/session/tests.rs", r'^subject_key: "subject-key-123"', DERIVED),
    ("crates/core/chio-core-types/src/receipt/metadata/key_registry.rs", r"Under enterprise attribution subject_key is", DERIVED),
    ("crates/core/chio-core/src/standards.rs", r'"subjectKey"\.to_string\(\), "subjectKeySource"', REAL),
    ("crates/kernel/chio-kernel/src/kernel/tests/multi_tenant_receipt.rs", r"^subject_key: format!\(\"subject-key-\{tenant\}\"\)", DERIVED),
    ("crates/kernel/chio-kernel/tests/durable_admission_sqlite/review_boundaries.rs", r'^subject_key: "tenant-b-subject"', DERIVED),
    ("crates/security/chio-secret-broker/src/kernel_admission/tests/original_selection.rs", r'^subject_key: "tenant-b-subject"', DERIVED),
    (CONTROL_PLANE + "scim_lifecycle.rs", r".", DERIVED),
    (CONTROL_PLANE + "trust_control/config_and_public.rs", r"identity\.subject_key|\bsubject_key: &str|bind_capability\(provider_id, subject_key|subject `\{subject_key\}`", DERIVED),
    (CONTROL_PLANE + "trust_control/passport_handlers.rs", r"identity\.subject_key|missing subject_key|requires subject_key", DERIVED),
    (CONTROL_PLANE + "trust_control/passport_handlers/partner_revocation_door_tests.rs", r"^subject_key: token\.subject\.to_hex\(\),$", REAL),
    (CONTROL_PLANE + "trust_control/service_types/paths.rs", r"\{subject_key\}", REAL),
    (CONTROL_PLANE + "trust_control/service_types/requests.rs", r"^pub subject_key: String,$", DERIVED),
    (CONTROL_PLANE + "trust_control/service_types/requests.rs", r"token\.subject\.to_hex\(\)|^subject_key: &str,$|\"subjectKey\": subject_key|subject_key: subject_key\.to_string\(\)|/v1/agents/:subject_key/receipts", REAL),
    (CONTROL_PLANE + "trust_control/underwriting_and_support.rs", r".", REAL),
    ("crates/products/chio-cli/src/admin.rs", r"response\.subject_key", REAL),
    ("crates/products/chio-cli/src/passport.rs", r".", REAL),
    (CLI_TESTS + "federated_issue.rs", r'"subjectKey": "enterprise-subject-key"|"subjectKey": subject_key,|^let subject_key = derive_enterprise_subject_key', DERIVED),
    (CLI_TESTS + "federated_issue.rs", r"^subject_key: &str,$|subject_key: subject_key\.to_string\(\)|public_key\(\)\.to_hex\(\)|^&subject_key,$|^subject_key$", REAL),
    (CLI_TESTS + "mcp_serve_http.rs", r'\["enterpriseIdentity"\]\["subjectKey"\]', DERIVED),
    (CLI_TESTS + "mcp_serve_http.rs", r'\["attribution"\]\["subject_key"\]', REAL),
    (CLI_TESTS + "passport.rs", r'"subjectKey": "enterprise-subject-key"', DERIVED),
    (CLI_TESTS + "passport.rs", r"sample_scorecard\(subject_key: &str\)|subject_key: subject_key\.to_string\(\)|subject_public_key\.to_hex\(\)|sample_scorecard\(&subject_key\)", REAL),
    (CLI_TESTS + "scim_lifecycle.rs", r'\[CHIO_SCIM_USER_EXTENSION_SCHEMA\]\["subjectKey"\]', DERIVED),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs", r"subject_key: derive_enterprise_subject_key", DERIVED),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/tests/bearer_verifier.rs", r"^enterprise_identity\.subject_key,$", DERIVED),
    (CREDENTIALS + "src/artifact.rs", r"^pub subject_key: String,$|context\.subject_key|self\.subject_key, \"subjectKey\"", DERIVED),
    (CREDENTIALS + "src/challenge.rs", r"scorecard\.subject_key|metrics\.subject_key", REAL),
    (CREDENTIALS + "src/tests.rs", r'"enterprise-subject-key"|"subjectKey"', DERIVED),
    (CREDENTIALS + "src/tests.rs", r"sample_scorecard\(subject_key: &str\)|subject_key: subject_key\.to_string\(\)", REAL),
    (CREDENTIALS + "tests/financial_agent_passport.rs", r".", REAL),
)

# (kind, pattern). Each match is an unkeyed enterprise subject derivation or SCIM alias.
UNKEYED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("unkeyed enterprise subject derivation", re.compile(r"\bfn\s+derive_enterprise_subject_key\b")),
    ("unkeyed scim deprovision receipt id", re.compile(r'"scim-deprovision-\{')),
    ("unkeyed scim capability id", re.compile(r'"scim-user:\{')),
    ("unkeyed scim policy hash", re.compile(r"chio\.scim-lifecycle-delete\.v1")),
)

PENDING_UNKEYED: dict[tuple[str, str, str], int] = {
    (CONTROL_PLANE + "scim_lifecycle.rs", "derive_enterprise_subject_key", "unkeyed enterprise subject derivation"): 1,
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs", "derive_enterprise_subject_key", "unkeyed enterprise subject derivation"): 1,
    (CONTROL_PLANE + "trust_control/config_and_public.rs", "build_scim_deprovision_receipt", "unkeyed scim deprovision receipt id"): 1,
    (CONTROL_PLANE + "trust_control/config_and_public.rs", "build_scim_deprovision_receipt", "unkeyed scim capability id"): 1,
    (CONTROL_PLANE + "trust_control/config_and_public.rs", "build_scim_deprovision_receipt", "unkeyed scim policy hash"): 1,
}

FN_ITEM = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


def rust_sources() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "crates/*.rs"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    return sorted(path for path in listed.split("\0") if path and GENERATED not in path)


def classify_line(path: str, line: str) -> str | None:
    classes = {
        cls
        for rule_path, pattern, cls in LINE_RULES
        if rule_path == path and re.search(pattern, line)
    }
    if len(classes) == 1:
        return classes.pop()
    return None


def census(sources: list[str]) -> tuple[list[tuple[str, int, str, str]], list[str]]:
    rows: list[tuple[str, int, str, str]] = []
    failures: list[str] = []
    for path in sources:
        text = (ROOT / path).read_text(encoding="utf-8")
        lines = [(number, line.strip()) for number, line in enumerate(text.splitlines(), 1) if TOKEN.search(line)]
        if not lines:
            continue
        line_by_line = ENTERPRISE_MARKERS.search(text) is not None
        in_real_crate = path.startswith(REAL_KEY_CRATES)
        for number, line in lines:
            if line_by_line:
                cls = classify_line(path, line)
            elif in_real_crate:
                cls = REAL
            else:
                cls = None
            if cls is None:
                failures.append(f"{path}:{number}: unclassified subject_key line: {line}")
            else:
                rows.append((path, number, cls, line))
    return rows, failures


def owner_of(text: str, offset: int) -> str:
    owner = "<module>"
    for item in FN_ITEM.finditer(text):
        if item.start() > offset:
            break
        owner = item.group(1)
    return owner


def unkeyed_sites(sources: list[str]) -> tuple[dict[tuple[str, str, str], int], list[str]]:
    found: dict[tuple[str, str, str], int] = {}
    lines: dict[tuple[str, str, str], list[int]] = {}
    failures: list[str] = []
    for path in sources:
        text = (ROOT / path).read_text(encoding="utf-8")
        for kind, pattern in UNKEYED_PATTERNS:
            for match in pattern.finditer(text):
                site = (path, owner_of(text, match.start()), kind)
                found[site] = found.get(site, 0) + 1
                lines.setdefault(site, []).append(text.count("\n", 0, match.start()) + 1)
    for site in sorted(found.keys() | PENDING_UNKEYED.keys()):
        path, owner, kind = site
        count = found.get(site, 0)
        pinned = PENDING_UNKEYED.get(site, 0)
        at = ",".join(str(number) for number in lines.get(site, []))
        if pinned == 0:
            failures.append(f"{path}:{at}: {kind} in `{owner}`; derive it with chio_core_types::enterprise_subject")
        elif count == 0:
            failures.append(f"{path}: pending entry `{kind}` in `{owner}` has no site; remove it from PENDING_UNKEYED")
        elif count > pinned:
            failures.append(
                f"{path}:{at}: {count} `{kind}` sites in `{owner}`, pinned at {pinned}; "
                "derive the new ones with chio_core_types::enterprise_subject"
            )
        elif count < pinned:
            failures.append(f"{path}: {count} `{kind}` site(s) in `{owner}`, pinned at {pinned}; lower its pin in PENDING_UNKEYED")
    return found, failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print every derived-enterprise line")
    args = parser.parse_args(argv)
    sources = rust_sources()
    rows, failures = census(sources)
    _, unkeyed_failures = unkeyed_sites(sources)
    failures.extend(unkeyed_failures)
    if args.list:
        for path, number, cls, line in rows:
            if cls == DERIVED:
                print(f"{path}:{number}: {line}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(f"enterprise subject census: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    derived = sum(1 for row in rows if row[2] == DERIVED)
    print(
        f"enterprise subject census: {len(rows) - derived} real-key, {derived} derived-enterprise, "
        f"{sum(PENDING_UNKEYED.values())} pending unkeyed site(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
