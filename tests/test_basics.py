import unittest

from swarmlib import clock, frontmatter, paths, secrets


class FrontMatterTest(unittest.TestCase):
    def test_round_trip_preserves_order_and_types(self):
        meta = {"id": "F1", "wave": 2, "paths": ["a/**"], "review": {"round": 1}, "title": "x: y"}
        text = frontmatter.dump(meta, "## Brief\n\nbody\n")
        parsed, body = frontmatter.parse(text)
        self.assertEqual(parsed, meta)
        self.assertEqual(list(parsed), list(meta))
        self.assertEqual(body, "## Brief\n\nbody\n")

    def test_rejects_missing_fences_and_bad_values(self):
        for text in ("id: \"x\"\n---\n", "---\nid: \"x\"\n", "---\nid: x\n---\n", "---\nnocolon\n---\n"):
            with self.assertRaises(frontmatter.FrontMatterError):
                frontmatter.parse(text)


class ClockTest(unittest.TestCase):
    def test_format_parse_round_trip(self):
        moment = clock.parse("2026-10-06T12:34:56Z")
        self.assertEqual(clock.fmt(moment), "2026-10-06T12:34:56Z")
        self.assertEqual(clock.stamp(moment), "20261006T123456Z")


class SecretsTest(unittest.TestCase):
    def test_detects_credential_shapes(self):
        # Built at runtime so this file never contains a real-looking key.
        samples = [
            "token " + "gh" + "p_" + "A1b2" * 9,
            "OPENROUTER=" + "sk-" + "or-v1-" + "x" * 30,
            "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
            "key " + "e2b" + "_" + "f" * 40,
            "aws " + "AKIA" + "Z" * 16,
            "api_key = " + "Q" * 30,
        ]
        for sample in samples:
            self.assertTrue(secrets.scan(sample), sample[:12])

    def test_ignores_hashes_and_prose(self):
        clean = [
            "commit 15d5b373a8e3d7f7f76404261ce6be7234806954",
            "pdf sha256 39d292f325c5f9e427f58fff39089ac7894538366c6b92e29c8c185c87fa4598",
            "the token budget is 4096 and the rate limit is 59 calls per second",
        ]
        for text in clean:
            self.assertEqual(secrets.scan(text), [], text)


class PathsTest(unittest.TestCase):
    def test_overlap_rules(self):
        self.assertTrue(paths.globs_overlap("crates/a/src/**", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("crates/*/src/lib.rs", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("crates/a", "crates/a/src/lib.rs"))
        self.assertTrue(paths.globs_overlap("**", "anything/at/all"))
        self.assertFalse(paths.globs_overlap("crates/a/**", "crates/b/**"))
        self.assertFalse(paths.globs_overlap("crates/a/x.rs", "crates/a/x.rs.bak"))

    def test_find_overlaps_pairs(self):
        self.assertEqual(
            paths.find_overlaps(["crates/a/**", "docs/x.md"], ["crates/a/src/lib.rs", "docs/y.md"]),
            [("crates/a/**", "crates/a/src/lib.rs")],
        )


if __name__ == "__main__":
    unittest.main()
