#!/usr/bin/env python3
"""Regression checks for silent converter and validator acceptance failures."""
import copy
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
import shutil
from check_fonts import FONTS, check as check_fonts
from compare_pages import TOLERANCE, compare as compare_pages
from idnits_gate import validate
from normalize_xml import normalize

WRAPPER_DIR = Path(__file__).resolve().parent / "bin"

CLEAN = {"result": "pass", "file": {"path": "draft.xml", "size": 100},
         "nitsBySeverity": {"error": 0, "warning": 0, "comment": 0}, "nits": []}


class IdnitsGate(unittest.TestCase):
    def test_completed_clean_report(self):
        self.assertEqual(validate(CLEAN), CLEAN["nitsBySeverity"])

    def test_completed_comments_are_allowed(self):
        report = copy.deepcopy(CLEAN)
        report.update(result="fail", nits=[{"severity": "ValidationComment", "code": "comment", "desc": "Informational"}])
        report["nitsBySeverity"]["comment"] = 1
        self.assertEqual(validate(report)["comment"], 1)

    def test_errors_and_warnings_are_rejected(self):
        for severity, key in [("ValidationError", "error"), ("ValidationWarning", "warning")]:
            report = copy.deepcopy(CLEAN)
            report.update(result="fail", nits=[{"severity": severity, "code": "nit", "desc": "Failure"}])
            report["nitsBySeverity"][key] = 1
            with self.subTest(severity=severity), self.assertRaises(ValueError):
                validate(report)

    def test_a_stale_date_is_rejected_unless_explicitly_allowed(self):
        report = copy.deepcopy(CLEAN)
        report.update(result="fail", nits=[{"severity": "ValidationWarning", "code": "DOC_DATE_IN_PAST",
                                            "desc": "The document date is 9 days in the past."}])
        report["nitsBySeverity"]["warning"] = 1
        with self.assertRaises(ValueError):
            validate(report)
        self.assertEqual(validate(report, allow_stale_date=True)["warning"], 1)

    def test_allowing_a_stale_date_keeps_other_findings_fatal(self):
        for severity, key, code in [("ValidationWarning", "warning", "DOC_DATE_IN_FUTURE"),
                                    ("ValidationWarning", "warning", "nit"),
                                    ("ValidationError", "error", "DOC_DATE_IN_PAST")]:
            report = copy.deepcopy(CLEAN)
            report.update(result="fail", nits=[
                {"severity": "ValidationWarning", "code": "DOC_DATE_IN_PAST", "desc": "Stale"},
                {"severity": severity, "code": code, "desc": "Failure"}])
            report["nitsBySeverity"]["warning"] += 1
            report["nitsBySeverity"][key] += 1
            with self.subTest(code=code, severity=severity), self.assertRaises(ValueError):
                validate(report, allow_stale_date=True)

    def test_incomplete_and_contradictory_reports_are_rejected(self):
        reports = [None, {}, {"nits": [], "nitsBySeverity": None}]
        for change in [{"result": "fail"}, {"file": {"path": "draft.xml", "size": True}},
                       {"nitsBySeverity": {"error": 1, "warning": 0, "comment": 0}},
                       {"nitsBySeverity": {"error": False, "warning": 0, "comment": 0}},
                       {"result": "fail", "nits": [{"severity": "warning", "code": "nit", "desc": "Failure"}]}]:
            report = copy.deepcopy(CLEAN); report.update(change); reports.append(report)
        for report in reports:
            with self.subTest(report=report), self.assertRaises((ValueError, TypeError)):
                validate(report)


class AasvgWrapper(unittest.TestCase):
    """tools/bin/aasvg must not hide a failure of the real renderer."""

    def run_with_fake(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "aasvg"
            fake.write_text("#!/bin/sh\ncat >/dev/null\n" + body)
            fake.chmod(0o755)
            env = dict(os.environ, PATH=os.pathsep.join([str(WRAPPER_DIR), tmp, os.environ.get("PATH", "")]))
            return subprocess.run(["sh", str(WRAPPER_DIR / "aasvg"), "--spaces=1"], input="+--+\n",
                                  capture_output=True, text=True, env=env, check=False)

    def test_a_renderer_failure_reaches_the_caller(self):
        result = self.run_with_fake("printf '<svg>'\nexit 42\n")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "")

    def test_a_rendered_figure_has_its_styles_inlined(self):
        result = self.run_with_fake("printf '<svg><style>path{}</style><path d=\"M0 0\"/></svg>'\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("<style>", result.stdout)
        self.assertIn('stroke="black"', result.stdout)


class FontManifest(unittest.TestCase):
    """The PDF fonts and licenses are the hash-pinned files in sources.json."""

    def copy(self, tmp):
        directory = Path(tmp) / "fonts"
        shutil.copytree(FONTS, directory)
        return directory

    def test_the_committed_fonts_match_their_manifest(self):
        self.assertEqual(check_fonts(), 8)

    def test_a_changed_missing_or_unlisted_file_is_rejected(self):
        def change_license(d):
            path = d / "notoserif-OFL.txt"
            path.write_bytes(path.read_bytes().replace(b"Copyright", b"Copyleft", 1))

        def swap_font(d):
            (d / "RobotoMono[wght].ttf").write_bytes((d / "RobotoMono-Italic[wght].ttf").read_bytes())

        cases = {
            "changed license text": change_license,
            "substituted font": swap_font,
            "missing font": lambda d: (d / "NotoSansSymbols2-Regular.ttf").unlink(),
            "unlisted font": lambda d: shutil.copy(d / "RobotoMono[wght].ttf", d / "Extra.ttf"),
        }
        for name, change in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                directory = self.copy(tmp)
                change(directory)
                with self.assertRaises(ValueError):
                    check_fonts(directory)


class PageComparison(unittest.TestCase):
    """Rasterized PDF pages must agree beyond antialiasing noise."""

    def pages(self, tmp, name, pages):
        directory = Path(tmp) / name
        directory.mkdir()
        for index, (width, height, pixels) in enumerate(pages, 1):
            (directory / f"page-{index}.pgm").write_bytes(b"P5\n%d %d\n255\n" % (width, height) + bytes(pixels))
        return directory

    def run_compare(self, committed, fresh):
        with tempfile.TemporaryDirectory() as tmp:
            return compare_pages(self.pages(tmp, "committed", committed), self.pages(tmp, "fresh", fresh))

    def test_identical_and_noise_level_pages_pass(self):
        white = (4, 2, [255] * 8)
        noisy = (4, 2, [255 - TOLERANCE] + [255] * 7)
        self.assertEqual(self.run_compare([white, white], [white, white]), ([], []))
        failures, notes = self.run_compare([white], [noisy])
        self.assertEqual(failures, [])
        self.assertEqual(len(notes), 1)

    def test_changed_artwork_page_count_and_size_fail(self):
        white = (4, 2, [255] * 8)
        stroke = (4, 2, [255, 255, 40, 255, 255, 255, 40, 255])
        for committed, fresh in [([white], [stroke]), ([white], [white, white]), ([white], [(2, 4, [255] * 8)])]:
            with self.subTest(fresh=fresh):
                failures, _ = self.run_compare(committed, fresh)
                self.assertTrue(failures)

    def test_malformed_or_missing_pages_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            with self.assertRaises(ValueError):
                compare_pages(empty, empty)
            bad = Path(tmp) / "bad"
            bad.mkdir()
            (bad / "page-1.pgm").write_bytes(b"P5\n4 2\n255\n" + bytes(3))
            with self.assertRaises(ValueError):
                compare_pages(bad, bad)


class XmlNormalization(unittest.TestCase):
    def test_known_dtd_entities_preserve_typed_text(self):
        source = '<!DOCTYPE rfc [<!ENTITY nbsp "&#160;">]><rfc><t>&nbsp;&nbhy;&amp;</t></rfc>'
        self.assertEqual(ET.fromstring(normalize(source)).findtext('t'), '\u00a0\u2011&')

    def test_cdata_comments_and_non_line_pi_preserve_literal_bytes(self):
        protected = '<sourcecode><![CDATA[{"literal":"&nbsp; <!DOCTYPE rfc> <?line 1?>"}]]></sourcecode><!-- &nbsp; (Ruby 4.0.6) --><\x3fexample &nbsp;\x3f>'
        source = '<rfc>' + protected + '</rfc>'
        self.assertEqual(normalize(source), source)
        self.assertEqual(ET.fromstring(normalize(source)).findtext('sourcecode'), '{"literal":"&nbsp; <!DOCTYPE rfc> <?line 1?>"}')

    def test_only_generator_runtime_and_line_pi_are_removed(self):
        source = '<!-- generated by https://github.com/cabo/kramdown-rfc version 1.7.43 (Ruby 4.0.6) --><rfc><?line -2?><t>ok</t></rfc>'
        result = normalize(source)
        self.assertNotIn('(Ruby', result)
        self.assertNotIn('<?line', result)
        self.assertIn('version 1.7.43', result)

    def test_unknown_or_changed_dtd_is_rejected(self):
        for declaration in ['<!DOCTYPE rfc SYSTEM "https://example.invalid/evil.dtd">',
                            '<!DOCTYPE rfc [<!ENTITY nbsp "&#1;">]>',
                            '<!DOCTYPE rfc [<!ENTITY payload SYSTEM "file:///etc/passwd">]>']:
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                normalize(declaration + '<rfc/>')


if __name__ == '__main__':
    unittest.main()
