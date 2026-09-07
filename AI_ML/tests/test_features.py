"""Tests for feature extraction modules."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.features.text_features import TextFeatures
from ml.features.url_features import UrlFeatures
from ml.features.header_features import HeaderFeatures
from ml.preprocessing import preprocess_email


class TestTextFeatures:
    def setup_method(self):
        self.extractor = TextFeatures()

    def test_urgency_detection(self):
        flags = self.extractor.extract("URGENT: Please verify your account immediately")
        assert flags["urgency_detected"] is True
        assert flags["urgency_score"] > 0

    def test_fear_detection(self):
        flags = self.extractor.extract("Your account has been compromised. Unauthorized access detected.")
        assert flags["fear_detected"] is True

    def test_credential_request(self):
        flags = self.extractor.extract("Please verify your password and login credentials")
        assert flags["credential_request"] is True

    def test_financial_request(self):
        flags = self.extractor.extract("Wire transfer of $5000 required. Bank account details inside.")
        assert flags["financial_request"] is True

    def test_impersonation_cues(self):
        flags = self.extractor.extract("Dear employee, please confirm your CEO credentials")
        assert flags["impersonation_detected"] is True

    def test_flagged_spans_substring(self):
        text = "Please verify your password immediately"
        spans = self.extractor.get_flagged_spans(text, "", top_k=5)
        for span in spans:
            assert span["text"] in text.lower()

    def test_empty_text(self):
        flags = self.extractor.extract("")
        assert flags["overall_score"] == 0.0


class TestUrlFeatures:
    def setup_method(self):
        self.extractor = UrlFeatures()

    def test_clean_url_low_score(self):
        result = self.extractor.analyze_url("https://www.google.com/")
        assert result["malicious_prob"] < 20

    def test_suspicious_tld(self):
        result = self.extractor.analyze_url("https://login.microsoft.xyz/verify")
        assert "suspicious_tld" in str(result["flags"])

    def test_ip_address_host(self):
        result = self.extractor.analyze_url("https://192.168.1.1/login")
        assert "ip_address_host" in result["flags"]

    def test_http_not_https(self):
        result = self.extractor.analyze_url("http://secure-bank.com/login")
        assert "http_not_https" in result["flags"]

    def test_punycode(self):
        result = self.extractor.analyze_url("https://microsoft-verify.xn--p1ai/")
        assert "punycode_detected" in result["flags"]

    def test_at_symbol_obfuscation(self):
        result = self.extractor.analyze_url("https://google.com@evil.com/login")
        assert "at_symbol_obfuscation" in result["flags"]

    def test_aggregate_score(self):
        urls = [
            "https://google.com",
            "https://login.microsoft.xyz/verify"
        ]
        results = [self.extractor.analyze_url(u) for u in urls]
        score = self.extractor.aggregate_score(results)
        assert 0 <= score <= 100


class TestHeaderFeatures:
    def setup_method(self):
        self.extractor = HeaderFeatures()

    def test_all_auth_pass_low_score(self):
        email = {
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        }
        result = self.extractor.extract(email)
        assert result["score"] < 20

    def test_all_auth_fail_high_score(self):
        email = {
            "auth_results": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
        }
        result = self.extractor.extract(email)
        assert result["score"] > 50

    def test_reply_to_mismatch(self):
        email = {
            "from_address": "ceo@company.com",
            "reply_to": "attacker@gmail.com",
            "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        }
        result = self.extractor.extract(email)
        assert any(a["feature"] == "reply_to_domain_mismatch" for a in result["anomalies"])

    def test_auth_explanations(self):
        email = {
            "auth_results": {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
        }
        result = self.extractor.extract(email)
        assert "spf" in result["auth_explanations"]
        assert "not authorized" in result["auth_explanations"]["spf"].lower()

    def test_empty_email(self):
        email = {}
        result = self.extractor.extract(email)
        assert "score" in result


class TestPreprocessing:
    def test_strip_html(self):
        from ml.preprocessing import strip_html
        html = "<p>Hello <b>World</b></p>"
        text = strip_html(html)
        assert "<" not in text
        assert "Hello" in text
        assert "World" in text

    def test_preprocess_email_basic(self):
        email = {
            "subject": "Test Subject",
            "body_text": "Test body content",
            "urls_in_body": ["http://example.com"],
            "reply_to": "test@example.com"
        }
        result = preprocess_email(email)
        assert result.subject == "Test Subject"
        assert result.body_text == "Test body content"
        assert "example.com" in result.domains

    def test_preprocess_email_with_html(self):
        email = {
            "subject": "Test",
            "body_text": "",
            "body_html": "<p>HTML content</p>",
            "urls_in_body": [],
            "reply_to": None
        }
        result = preprocess_email(email)
        assert "HTML content" in result.body_text
