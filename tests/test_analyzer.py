"""
Unit tests for PhishGuard Triage.

Run with:  python -m pytest tests/ -v
Or stdlib: python -m unittest discover -s tests -v

Covers: URL heuristics, parsing, end-to-end analysis on both malicious and
benign mock payloads (no live/malicious network content is ever fetched).
"""

import sys
import unittest
from pathlib import Path

# Allow running tests without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import url_inspector
from src.analyzer import PhishingAnalyzer, parse_eml, parse_plaintext
from src.risk_scorer import score_findings
from src.utils import levenshtein_distance, load_config

CONFIG = load_config()
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"


class TestLevenshtein(unittest.TestCase):
    def test_identical_strings(self):
        self.assertEqual(levenshtein_distance("amazon", "amazon"), 0)

    def test_single_substitution(self):
        self.assertEqual(levenshtein_distance("amazon", "amaz0n"), 1)

    def test_completely_different(self):
        self.assertGreaterEqual(levenshtein_distance("amazon", "xyz"), 3)


class TestUrlInspector(unittest.TestCase):
    def test_extract_urls_basic(self):
        text = "Click here: https://example.com/path and also www.test.com"
        urls = url_inspector.extract_urls(text)
        self.assertEqual(len(urls), 2)

    def test_typosquat_detection(self):
        finding = url_inspector.analyze_url(
            "https://amaz0n-secure.click/confirm",
            trusted_brands=["amazon"],
            shorteners=[],
            suspicious_tlds=[".click"],
            typosquat_max_distance=2,
        )
        categories = finding.severity_categories
        self.assertIn("typosquat_domain", categories)
        self.assertIn("suspicious_tld", categories)

    def test_ip_literal_detection(self):
        finding = url_inspector.analyze_url(
            "http://192.168.1.10/login",
            trusted_brands=[], shorteners=[], suspicious_tlds=[],
            typosquat_max_distance=2,
        )
        self.assertIn("ip_literal_url", finding.severity_categories)

    def test_subdomain_trap_detection(self):
        finding = url_inspector.analyze_url(
            "https://www.decodelabs.tech.login-update.com/verify",
            trusted_brands=["decodelabs"], shorteners=[], suspicious_tlds=[],
            typosquat_max_distance=2,
        )
        self.assertIn("subdomain_trap", finding.severity_categories)

    def test_legitimate_url_no_false_positive(self):
        finding = url_inspector.analyze_url(
            "https://www.company.com/docs/q3-status",
            trusted_brands=["amazon", "paypal", "microsoft"],
            shorteners=["bit.ly"], suspicious_tlds=[".click", ".top"],
            typosquat_max_distance=2,
        )
        self.assertEqual(finding.issues, [])


class TestParsing(unittest.TestCase):
    def test_parse_eml_extracts_headers(self):
        raw = (SAMPLES_DIR / "phishing_sample_1.eml").read_bytes()
        parsed = parse_eml(raw)
        self.assertIn("executive-update.com", parsed.reply_to_address)
        self.assertTrue(parsed.subject.upper().startswith("URGENT"))

    def test_parse_eml_extracts_attachment(self):
        raw = (SAMPLES_DIR / "phishing_sample_2.eml").read_bytes()
        parsed = parse_eml(raw)
        self.assertTrue(any(f.endswith(".scr") for f in parsed.attachment_filenames))

    def test_parse_plaintext_smishing(self):
        raw = (SAMPLES_DIR / "smishing_sample_1.txt").read_text()
        parsed = parse_plaintext(raw)
        self.assertIn("usps-track.club", parsed.body_text)


class TestEndToEndVerdicts(unittest.TestCase):
    """
    Full-pipeline tests: parse -> analyze -> score, asserting the final
    verdict lands where a human triager would expect for each mock payload.
    """

    def _run(self, path: Path, is_text: bool = False):
        raw = path.read_bytes()
        parsed = parse_plaintext(raw.decode("utf-8")) if is_text else parse_eml(raw)
        analyzer = PhishingAnalyzer(CONFIG)
        findings = analyzer.analyze(parsed)
        return score_findings(findings, CONFIG)

    def test_bec_wire_transfer_sample_is_malicious(self):
        result = self._run(SAMPLES_DIR / "phishing_sample_1.eml")
        self.assertEqual(result.verdict, "MALICIOUS")
        self.assertEqual(result.action, "Block Domain & Escalate")
        categories = {f.category for f in result.findings}
        self.assertIn("secrecy_bypass_language", categories)
        self.assertIn("urgency_language", categories)

    def test_credential_harvest_sample_is_malicious(self):
        result = self._run(SAMPLES_DIR / "phishing_sample_2.eml")
        self.assertEqual(result.verdict, "MALICIOUS")
        categories = {f.category for f in result.findings}
        self.assertIn("dangerous_attachment", categories)
        self.assertIn("subdomain_trap", categories)

    def test_smishing_sample_flags_suspicious_or_worse(self):
        result = self._run(SAMPLES_DIR / "smishing_sample_1.txt", is_text=True)
        self.assertIn(result.verdict, ("SUSPICIOUS", "MALICIOUS"))

    def test_safe_sample_1_is_safe(self):
        result = self._run(SAMPLES_DIR / "safe_sample_1.eml")
        self.assertEqual(result.verdict, "SAFE")
        self.assertEqual(result.action, "Close")

    def test_safe_sample_2_is_safe(self):
        result = self._run(SAMPLES_DIR / "safe_sample_2.txt", is_text=True)
        self.assertEqual(result.verdict, "SAFE")


if __name__ == "__main__":
    unittest.main()
