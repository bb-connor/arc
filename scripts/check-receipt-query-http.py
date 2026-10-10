#!/usr/bin/env python3
"""Keep full-history receipt authentication outside trust-control HTTP reads."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "crates/platform/chio-control-plane/src/trust_control"
FORBIDDEN = re.compile(
    r"\.\s*"
    r"(?P<method>query_receipts|load_chio_receipt_with_context|with_retained_snapshot)\s*\("
)


def production_sources():
    for path in sorted(SOURCES.rglob("*.rs")):
        relative = path.relative_to(SOURCES)
        if any(part == "tests" or part.endswith("_tests") for part in relative.parts[:-1]):
            continue
        if path.stem == "tests" or path.stem.endswith("_tests"):
            continue
        yield path


def main() -> int:
    violations = []
    if not (SOURCES / "receipt_handlers.rs").is_file():
        print("missing receipt HTTP handlers", file=sys.stderr)
        return 1
    for path in production_sources():
        source = path.read_text()
        for match in FORBIDDEN.finditer(source):
            # The typed snapshot adapter is the single production call site.
            # Other methods and receivers in that file remain checked.
            if (
                path == SOURCES / "receipt_query_service.rs"
                and re.search(r"\bsnapshots\s*$", source[:match.start()])
                and match["method"] == "query_receipts"
            ):
                continue
            number = source.count("\n", 0, match.start()) + 1
            violations.append(f"{path.relative_to(ROOT)}:{number}: full-history receipt read in HTTP handler")
    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("receipt query HTTP boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
