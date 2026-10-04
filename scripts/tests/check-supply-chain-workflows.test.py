#!/usr/bin/env python3
"""Release producers must depend on the same complete supply-chain gate."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRODUCERS = {
    "sidecar-image.yml": "build",
    "release-binaries.yml": "build",
    "release-cpp.yml": "qualify",
    "release-npm.yml": "build",
}


def job(text, name):
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:|\Z)",
                      text.split("\njobs:\n", 1)[1], re.M | re.S)
    if match is None:
        raise AssertionError(f"missing {name} job")
    return match.group(1)


def require_dependency(text, producer):
    gate = job(text, "supply-chain")
    if "    uses: ./.github/workflows/cargo-vet.yml\n" not in gate:
        raise AssertionError("release must call the complete reusable gate")
    if re.search(r"^    (if|continue-on-error):", gate, re.M):
        raise AssertionError("supply-chain prerequisite must be unconditional")
    build = job(text, producer)
    needs = re.search(r"^    needs: ([^\n]+)$", build, re.M)
    if needs is None or "supply-chain" not in re.findall(r"[\w-]+", needs[1]):
        raise AssertionError("producer must depend on successful supply-chain qualification")
    if re.search(r"^    if:.*(?:always|cancelled)\(", build, re.M):
        raise AssertionError("producer must not run after prerequisite failure")


def require_cpp_source_binding(text):
    publisher = job(text, "publish-vcpkg")
    if 'archive/${SOURCE_SHA}.tar.gz' not in publisher:
        raise AssertionError("C++ source archive must use the audited immutable commit")
    if publisher.count('SOURCE_SHA: ${{ github.sha }}') != 2:
        raise AssertionError("archive and registry rendering must use the audited event commit")
    if 'ref: ${{ github.sha }}' not in publisher:
        raise AssertionError("port templates must come from the audited event commit")
    if '--source-repository "$SOURCE_REPOSITORY"' not in publisher:
        raise AssertionError("registry must retain the qualified source repository")
    if '--source-sha "$SOURCE_SHA"' not in publisher:
        raise AssertionError("registry must retain the qualified source commit")


class PublishingBoundaryTests(unittest.TestCase):
    def test_cpp_archive_and_ports_use_the_audited_source(self):
        text = (ROOT / ".github/workflows/release-cpp.yml").read_text()
        require_cpp_source_binding(text)
        for old, new in (
            ('archive/${SOURCE_SHA}.tar.gz', 'archive/refs/tags/cpp/v${VERSION}.tar.gz'),
            ('SOURCE_SHA: ${{ github.sha }}', 'SOURCE_SHA: ${{ github.ref }}'),
            ('--source-sha "$SOURCE_SHA"', '--source-sha "$VERSION"'),
            ('--source-repository "$SOURCE_REPOSITORY"', '--source-repository backbay-labs/chio'),
        ):
            with self.subTest(mutation=new), self.assertRaises(AssertionError):
                require_cpp_source_binding(text.replace(old, new))

    def test_release_producers_require_successful_composite_gate(self):
        for name, producer in PRODUCERS.items():
            with self.subTest(workflow=name):
                text = (ROOT / ".github/workflows" / name).read_text()
                require_dependency(text, producer)
                with self.assertRaises(AssertionError):
                    require_dependency(text.replace("needs: supply-chain", "needs: []")
                                       .replace("plan, supply-chain", "plan"), producer)
                with self.assertRaises(AssertionError):
                    require_dependency(text.replace("  supply-chain:\n",
                                       "  supply-chain:\n    if: false\n"), producer)

    def test_reusable_gate_binds_event_source_and_runs_composite(self):
        text = (ROOT / ".github/workflows/cargo-vet.yml").read_text()
        self.assertIn("  workflow_call:\n", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("bash scripts/check-supply-chain.sh", text)
        self.assertIn("github.workflow", text.split("\nconcurrency:\n", 1)[1])


if __name__ == "__main__":
    unittest.main()
