#!/usr/bin/env python3
"""Published registry ports must consume the source that passed qualification."""

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("renderer", ROOT / "scripts/render-vcpkg-release.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class ReleasePortTests(unittest.TestCase):
    def test_all_real_templates_bind_repository_commit_and_archive(self):
        templates = list((ROOT / "tools/vcpkg-overlay/ports").glob("*/portfile.cmake"))
        self.assertEqual({path.parent.name for path in templates},
                         {"chio-cpp", "chio-cpp-kernel", "chio-guard-cpp", "chio-drogon"})
        for path in templates:
            with self.subTest(port=path.parent.name):
                rendered = renderer.render(path.read_text(), "owner/reviewed", "a" * 40, "b" * 128)
                self.assertIn('    REPO "owner/reviewed"\n', rendered)
                self.assertIn('    REF "' + "a" * 40 + '"\n', rendered)
                self.assertIn("    SHA512 " + "b" * 128 + "\n", rendered)
                self.assertNotRegex(rendered, r"(?m)^\s*HEAD_REF\b")
                self.assertNotIn('REF "cpp/v${VERSION}"', rendered)

    def test_missing_duplicate_or_changed_template_fields_reject(self):
        template = (ROOT / "tools/vcpkg-overlay/ports/chio-cpp/portfile.cmake").read_text()
        for field in ('    REPO backbay-labs/chio\n', '    REF "cpp/v${VERSION}"\n',
                      '    SHA512 0\n', '    HEAD_REF main\n'):
            for replacement in ("", field + field, "    UNREVIEWED value\n"):
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                    renderer.render(template.replace(field, replacement), "owner/repo", "a" * 40, "b" * 128)

    def test_invalid_or_mutable_identities_reject(self):
        template = (ROOT / "tools/vcpkg-overlay/ports/chio-cpp/portfile.cmake").read_text()
        for repository, commit, digest in (
            ("owner/repo", "cpp/v1.0.0", "b" * 128),
            ("owner/repo", "main", "b" * 128),
            ("owner/repo", "a" * 39, "b" * 128),
            ("owner/repo\nREF main", "a" * 40, "b" * 128),
            ("owner/repo", "a" * 40, "0"),
        ):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                renderer.render(template, repository, commit, digest)


if __name__ == "__main__":
    unittest.main()
