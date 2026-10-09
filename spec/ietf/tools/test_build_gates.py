#!/usr/bin/env python3
"""Regression checks for silent converter and validator acceptance failures."""
import copy
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
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
