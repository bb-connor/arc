#!/usr/bin/env python3
"""Keep cryptographic domain separation single-sourced and one shape.

Every signed or hashed payload type carries a distinct domain prefix, and the
whole point of the prefix is that a signature over one payload type cannot be
read as a signature over another. Two properties make that hold, and neither is
visible to the compiler:

One value, one declaration. When the same bytes are declared in a producer crate
and again in a verifier crate, the strings agree until the day one is bumped to
`.v2`. Then the producer and the verifier disagree about identity, silently,
with no compile error anywhere. Names do not protect against this: the same
bytes already carry four different constant names here, so only a search by
value finds the duplication.

One convention, always terminated. An unterminated, variable-shape prefix is how
prefix-ambiguity mistakes get made later even where every current use is safe.
The convention is `chio.<area>.<payload>.v<N>` followed by a NUL, with one or
more dot-separated lowercase segments before the version, which is the shape the
canonical constants in the shared types crate already use.

A placeholder domain must not be reachable from a shipping binary, so a
declaration whose name or value says placeholder has to be test scope.

Scope: byte-string domain constants under `crates/`, meaning
`const NAME: &[u8] = b"..."` where the name says DOMAIN or SIGNATURE. That is
the form a signing input takes. The `&str` constants in the same families are
not covered, because that name space also carries algorithm names, header names
and feature flags, and separating the domains from them needs a naming
convention that does not exist yet; extending this gate is cheap once it does.

Duplication is measured across test scope as well as production, because a test
that re-declares a production domain instead of importing it is the same drift
risk. Shape and placeholder rules apply to production declarations only: a test
may use a fixture domain of its own, it may not fork a real one.

Debt policy: entries are debt, not configuration. Renew only through
`--ratchet`, which re-caps each entry at the value's current declaration count
(caps can only shrink), drops entries whose values are compliant, and advances
the expiry one month. The duplicate values are not fixed here; the caps exist so
that consolidating them is visible and so the count cannot grow first.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import subprocess
import sys


SOURCE_PATTERNS = ("crates/*.rs", "crates/*.inc")
DOMAIN_SHAPE = re.compile(rb"\Achio(?:\.[a-z0-9][a-z0-9-]*)+\.v[0-9]+\x00\Z")
# Words that only appear in a stand-in. `example` and `sample` are left out on
# purpose: they name real crates here, so they would flag legitimate domains.
PLACEHOLDER_MARKERS = (
    "PLACEHOLDER",
    "DUMMY",
    "FAKE",
    "CHANGEME",
    "TODO",
    "FIXME",
    "OVERRIDE-IN-PRODUCTION",
)

DEBT_WAVES = 4


@dataclass(frozen=True)
class DomainDebt:
    rationale: str
    expires: str
    declarations: int | None = None
    shape: bool = False


def allow(
    expires: str,
    rationale: str,
    *,
    declarations: int | None = None,
    shape: bool = False,
) -> DomainDebt:
    return DomainDebt(
        rationale=rationale, expires=expires, declarations=declarations, shape=shape
    )


# `declarations` caps how many places may declare the value; `shape` excuses a
# spelling that predates the convention. Expiries are spread across four waves,
# fewest declarations first: a single misspelled domain is a rename, a value
# declared in four places has four call sites to reconcile first.
DEBT: dict[str, DomainDebt] = {
    r"chio.response-affected-set.v1\0": allow(
        "2027-01-31",
        "declared in 4 places across chio-kernel, chio-security-types; retires when one module owns the value and the rest import it",
        declarations=4,
    ),
    r"chio.response-effect.v1\0": allow(
        "2027-01-31",
        "declared in 3 places across chio-kernel, chio-quarantine; retires when one module owns the value and the rest import it",
        declarations=3,
    ),
    r"chio.channel.release-authorization.signed-digest.v1\0": allow(
        "2026-12-31",
        "declared in 2 places across chio-settle, chio-store-sqlite; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.fincred.source-artifact.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-credentials, chio-credit; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.fincred.source-disclosure.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-credentials, chio-credit; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.response-request.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-core-types, chio-quarantine; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.response-transition.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-core-types, chio-quarantine; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.runtime-replay-source-seal.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-kernel, chio-runtime-core; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.verified-security-event-evidence.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-control-plane, chio-store-sqlite; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"chio.verified-security-event-receipt-evidence.v1\0": allow(
        "2027-01-31",
        "declared in 2 places across chio-control-plane, chio-store-sqlite; retires when one module owns the value and the rest import it",
        declarations=2,
    ),
    r"CHIO-CHANNEL-TERMINAL-OUTCOME-COMMITMENT-V1\0": allow(
        "2026-10-31",
        "channel terminal outcome signing domain, uppercase convention; retires with a versioned rename",
        shape=True,
    ),
    r"chio-decoy-arm-operation-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-artifact-index-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-envelope-aad-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-evidence-id-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-file-ownership-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-marker-index-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-operation-index-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-public-ref-index-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-quarantine-name-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-transition-index-v1": allow(
        "2026-10-31",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-decoy-version-hash-v1": allow(
        "2026-11-30",
        "decoy registry hyphen convention, unterminated; retires with the decoy domain migration",
        shape=True,
    ),
    r"chio-revocation-oracle:v1:epoch-root": allow(
        "2026-11-30",
        "revocation oracle epoch root, trailing payload after the version, unterminated; retires with a versioned rename",
        shape=True,
    ),
    r"chio.bbs.header.v1": allow(
        "2026-11-30",
        "BBS selective-disclosure domain, unterminated; retires with a terminator and a schema bump",
        shape=True,
    ),
    r"chio.bbs.message.v1": allow(
        "2026-11-30",
        "BBS selective-disclosure domain, unterminated; retires with a terminator and a schema bump",
        shape=True,
    ),
    r"chio.lineage.frontier-signature/v1\0": allow(
        "2026-11-30",
        "lineage frontier signature domain separates the version with a slash; retires with a versioned rename",
        shape=True,
    ),
    r"chio:active-defense-evidence-id:v1": allow(
        "2026-11-30",
        "active-defense evidence id, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:correlated-finding:v1": allow(
        "2026-11-30",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:declassification-consumption:v1": allow(
        "2026-11-30",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:declassification-outcome:v1": allow(
        "2026-11-30",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:detector-health:v1": allow(
        "2026-11-30",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:effect-transition:v1": allow(
        "2026-11-30",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:flow-denial:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:lift-rollback-completion:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:response-completion:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:response-plan:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:response-state-transition:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:scheduler-health:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:active-defense-receipt:tripwire-observation:v1": allow(
        "2026-12-31",
        "active-defense receipt body digest, colon convention, unterminated; retires with the receipt domain migration",
        shape=True,
    ),
    r"chio:dpop-replay-source-inventory:v1\0": allow(
        "2026-12-31",
        "colon convention; retires with a versioned rename",
        shape=True,
    ),
    r"chio:governed-approval-replay-source-inventory:v1\0": allow(
        "2026-12-31",
        "colon convention; retires with a versioned rename",
        shape=True,
    ),
    r"chio:response-plan:v1\0": allow(
        "2026-12-31",
        "colon convention; retires with a versioned rename",
        shape=True,
    ),
}


TEST_SEGMENTS = ("tests", "benches")
TEST_SEGMENT_SUFFIXES = ("_tests", "_test")

DECLARATION = re.compile(
    r"const\s+(?P<name>[A-Za-z0-9_]*(?:DOMAIN|SIGNATURE)[A-Za-z0-9_]*)\s*:"
    r'\s*&\s*\[\s*u8\s*\]\s*=\s*b"(?P<value>(?:[^"\\]|\\.)*)"',
    re.S,
)
RUST_NOISE = re.compile(
    r"""
      //[^\n]*                            # line comment
    | /\*                                 # block comment; nesting handled below
    | (?:b|c)?r(\#*)"                     # raw string opener, hashes captured
    | (?:b|c)?"(?:[^"\\]|(?s:\\.))*"      # string, including \<newline> continuation
    | b?'(?:(?s:\\.)|[^\\'])'             # char literal, never a lifetime
    """,
    re.VERBOSE,
)
TEST_SCOPED_ITEM = re.compile(
    r"#\[\s*cfg\s*\([^\n]*\b(?:test|test-support)\b[^\n]*\)\s*\]"
)
BYTE_ESCAPES = {
    "0": b"\x00",
    "n": b"\n",
    "r": b"\r",
    "t": b"\t",
    "\\": b"\\",
    '"': b'"',
    "'": b"'",
}


@dataclass(frozen=True)
class Declaration:
    path: str
    line: int
    name: str
    value: bytes
    test_scope: bool


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover_sources(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *SOURCE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line and (root / line).is_file()]


def is_test_path(path: str) -> bool:
    segments = path.split("/")
    directories, name = segments[:-1], segments[-1]
    if any(
        directory in TEST_SEGMENTS or directory.endswith(TEST_SEGMENT_SUFFIXES)
        for directory in directories
    ):
        return True
    return name == "tests.rs" or name.endswith(("_tests.rs", "_test.rs"))


def blank_span(span: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in span)


def blank_rust_comments(text: str) -> str:
    """Blank comments, keep literals. A domain lives inside a literal."""
    chunks: list[str] = []
    position = 0
    while True:
        match = RUST_NOISE.search(text, position)
        if match is None:
            chunks.append(text[position:])
            return "".join(chunks)
        chunks.append(text[position : match.start()])
        if match.group(0) == "/*":
            end = match.end()
            depth = 1
            while depth and end < len(text):
                opened = text.find("/*", end)
                closed = text.find("*/", end)
                if closed == -1:
                    end = len(text)
                    break
                if opened != -1 and opened < closed:
                    depth += 1
                    end = opened + 2
                else:
                    depth -= 1
                    end = closed + 2
            chunks.append(blank_span(text[match.start() : end]))
            position = end
            continue
        if match.group(1) is not None:
            terminator = '"' + match.group(1)
            end = text.find(terminator, match.end())
            end = len(text) if end == -1 else end + len(terminator)
            chunks.append(text[match.start() : end])
            position = end
            continue
        if match.group(0).startswith("//"):
            chunks.append(blank_span(match.group(0)))
        else:
            chunks.append(match.group(0))
        position = match.end()


def blank_test_scoped_items(text: str) -> str:
    blanked = list(text)
    for match in TEST_SCOPED_ITEM.finditer(text):
        cursor = match.end()
        depth = 0
        body = None
        while cursor < len(text):
            char = text[cursor]
            if char == "{":
                depth += 1
                if body is None:
                    body = cursor
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            elif char == ";" and depth == 0:
                break
            cursor += 1
        end = min(cursor + 1 if body is not None else cursor, len(text))
        for index in range(match.start(), end):
            if blanked[index] != "\n":
                blanked[index] = " "
    return "".join(blanked)


def decode_byte_literal(literal: str) -> tuple[bytes | None, str | None]:
    decoded = bytearray()
    index = 0
    while index < len(literal):
        char = literal[index]
        if char != "\\":
            decoded.extend(char.encode("utf-8"))
            index += 1
            continue
        if index + 1 >= len(literal):
            return None, "byte string ends in a backslash"
        escape = literal[index + 1]
        if escape == "x":
            code = literal[index + 2 : index + 4]
            if len(code) != 2:
                return None, "truncated \\x escape"
            try:
                decoded.append(int(code, 16))
            except ValueError:
                return None, f"unreadable \\x{code} escape"
            index += 4
            continue
        replacement = BYTE_ESCAPES.get(escape)
        if replacement is None:
            return None, f"unsupported \\{escape} escape"
        decoded.extend(replacement)
        index += 2
    return bytes(decoded), None


def render(value: bytes) -> str:
    """The value as its source spelling, so an entry is greppable by value."""
    rendered = []
    for byte in value:
        if byte == 0:
            rendered.append("\\0")
        elif 0x20 <= byte < 0x7F and byte not in (0x22, 0x5C):
            rendered.append(chr(byte))
        else:
            rendered.append(f"\\x{byte:02x}")
    return "".join(rendered)


def collect_declarations(
    root: Path, paths: list[str], failures: list[str]
) -> list[Declaration]:
    declarations: list[Declaration] = []
    for path in sorted(paths):
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        if "DOMAIN" not in text and "SIGNATURE" not in text:
            continue
        readable = blank_rust_comments(text)
        production = blank_test_scoped_items(readable)
        test_path = is_test_path(path)
        for match in DECLARATION.finditer(readable):
            line = readable.count("\n", 0, match.start()) + 1
            value, reason = decode_byte_literal(match.group("value"))
            if value is None:
                failures.append(
                    f"{path}:{line} {match.group('name')}: {reason}"
                )
                continue
            declarations.append(
                Declaration(
                    path=path,
                    line=line,
                    name=match.group("name"),
                    value=value,
                    test_scope=test_path
                    or production[match.start()] != readable[match.start()],
                )
            )
    return declarations


def is_placeholder(declaration: Declaration) -> bool:
    subject = f"{declaration.name} {render(declaration.value)}".upper()
    return any(marker in subject for marker in PLACEHOLDER_MARKERS)


def group_by_value(declarations: list[Declaration]) -> dict[str, list[Declaration]]:
    grouped: dict[str, list[Declaration]] = {}
    for declaration in declarations:
        grouped.setdefault(render(declaration.value), []).append(declaration)
    return grouped


def site(declaration: Declaration) -> str:
    return f"{declaration.path}:{declaration.line} {declaration.name}"


def validate_debt(errors: list[str]) -> None:
    for value, entry in sorted(DEBT.items()):
        if not entry.rationale.strip():
            errors.append(f"{value}: debt entry has an empty rationale")
        if entry.declarations is None and not entry.shape:
            errors.append(f"{value}: debt entry excuses nothing")
        if entry.declarations is not None and entry.declarations < 2:
            errors.append(
                f"{value}: debt entry caps declarations below two, which is not debt"
            )
        if not entry.expires.strip():
            errors.append(f"{value}: debt entry has an empty expiry date")
            continue
        try:
            expires_on = date.fromisoformat(entry.expires)
        except ValueError:
            errors.append(f"{value}: debt entry expiry {entry.expires!r} is not an ISO date")
            continue
        if expires_on < date.today():
            errors.append(f"{value}: debt entry expired on {entry.expires}")


def next_month_end(today: date) -> date:
    year, month = (
        (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    )
    if month == 12:
        return date(year, 12, 31)
    return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)


def wave_expiries(today: date) -> list[str]:
    deadlines = [next_month_end(today)]
    for _ in range(DEBT_WAVES - 1):
        deadlines.append(next_month_end(deadlines[-1].replace(day=1)))
    return [deadline.isoformat() for deadline in deadlines]


def ratchet_debt(root: Path) -> int:
    grouped = group_by_value(collect_declarations(root, discover_sources(root), []))
    expiries = wave_expiries(date.today())
    kept: list[tuple[int, str, str, int | None, bool]] = []
    dropped: list[str] = []
    tightened: list[str] = []
    for value, entry in DEBT.items():
        sites = grouped.get(value, [])
        if not sites:
            dropped.append(f"{value}: no longer declared anywhere")
            continue
        declarations = None
        if len(sites) > 1:
            declarations = min(len(sites), entry.declarations or len(sites))
            if entry.declarations is not None and declarations < entry.declarations:
                tightened.append(f"{value}: declarations {entry.declarations} -> {declarations}")
        elif entry.declarations is not None:
            tightened.append(f"{value}: declaration cap dropped, single declaration")
        shape = entry.shape and any(
            not declaration.test_scope and not DOMAIN_SHAPE.match(declaration.value)
            for declaration in sites
        )
        if entry.shape and not shape:
            tightened.append(f"{value}: shape excuse dropped, value matches the convention")
        if declarations is None and not shape:
            dropped.append(f"{value}: compliant")
            continue
        kept.append(
            (declarations if declarations is not None else 1, value, entry.rationale, declarations, shape)
        )
    per_wave = max(1, -(-len(kept) // DEBT_WAVES))
    by_count = sorted(kept, key=lambda item: (item[0], item[1]))
    schedule = {
        value: expiries[min(index // per_wave, len(expiries) - 1)]
        for index, (_, value, _, _, _) in enumerate(by_count)
    }
    rendered = [
        f'    r"{value}": allow(\n'
        f'        "{schedule[value]}",\n'
        f'        "{rationale}",\n'
        + (f"        declarations={declarations},\n" if declarations is not None else "")
        + ("        shape=True,\n" if shape else "")
        + "    ),\n"
        for _, value, rationale, declarations, shape in kept
    ]
    script = Path(__file__).resolve()
    source = script.read_text(encoding="utf-8")
    start_marker = "DEBT: dict[str, DomainDebt] = {\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index("\n}\n", start)
    script.write_text(
        source[:start] + "".join(rendered).rstrip("\n") + source[end:], encoding="utf-8"
    )
    for line in dropped:
        print(f"dropped: {line}")
    for line in tightened:
        print(f"tightened: {line}")
    print(
        f"domain debt ratcheted: {len(kept)} entries kept, {len(dropped)} dropped, "
        f"{len(tightened)} tightened, expiries {', '.join(expiries)}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check cryptographic domain separation constants."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="repository root")
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help=(
            "rewrite the debt list in place: re-cap each entry at the value's "
            "current declaration count (never larger than before), drop entries "
            "whose values are compliant, and advance expiries one month"
        ),
    )
    args = parser.parse_args()

    if args.ratchet:
        return ratchet_debt(args.root.resolve())

    root = args.root.resolve()
    failures: list[str] = []
    validate_debt(failures)

    try:
        paths = discover_sources(root)
    except subprocess.CalledProcessError as exc:
        print(f"failed to list Rust sources under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    declarations = collect_declarations(root, paths, failures)
    grouped = group_by_value(declarations)
    duplicated = {value: sites for value, sites in grouped.items() if len(sites) > 1}
    malformed = {
        value: sites
        for value, sites in grouped.items()
        if any(
            not declaration.test_scope and not DOMAIN_SHAPE.match(declaration.value)
            for declaration in sites
        )
    }
    print(
        f"Domain separation: {len(declarations)} byte-string domain constants, "
        f"{len(grouped)} distinct values, {len(duplicated)} declared more than "
        f"once, {len(malformed)} off the convention"
    )

    used: set[str] = set()
    for value, sites in sorted(duplicated.items()):
        entry = DEBT.get(value)
        cap = entry.declarations if entry is not None else None
        if cap is not None and len(sites) <= cap:
            used.add(value)
            continue
        failures.append(
            f"{value}: declared in {len(sites)} places"
            + (f", cap is {cap}" if cap is not None else "")
            + f"; one module owns a domain and everything else imports it "
            f"({'; '.join(site(declaration) for declaration in sites)})"
        )

    for value, sites in sorted(malformed.items()):
        entry = DEBT.get(value)
        if entry is not None and entry.shape:
            used.add(value)
            continue
        offenders = "; ".join(
            site(declaration)
            for declaration in sites
            if not declaration.test_scope and not DOMAIN_SHAPE.match(declaration.value)
        )
        failures.append(
            f"{value}: not chio.<area>.<payload>.v<N> with a NUL terminator ({offenders})"
        )

    for declaration in declarations:
        if declaration.test_scope or not is_placeholder(declaration):
            continue
        failures.append(
            f"{site(declaration)}: placeholder domain is reachable outside test "
            "scope; put it behind a test cfg"
        )

    for value in sorted(set(DEBT) - used):
        if value in grouped:
            failures.append(
                f"{value}: debt entry no longer excuses a violation; remove it "
                "(run --ratchet)"
            )

    if failures:
        print("\nDomain separation failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nDomain separation check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
