"""Synthetic provider tests; run with CAPEv2's base.py available on PYTHONPATH."""

import unittest
from unittest.mock import Mock, patch

import requests

from lib.cuckoo.common.integrations.threatintelligence.ismalicious_provider import IsMaliciousProvider


class IsMaliciousTests(unittest.TestCase):
    def setUp(self):
        self.provider = IsMaliciousProvider({"api_key": "synthetic-key", "timeout": 25})

    @patch("requests.get")
    def check(self, payload, mock_get):
        mock_get.return_value = Mock(status_code=200, json=Mock(return_value=payload))
        return self.provider.lookup("example.invalid", "domain")

    def test_malicious_evidence(self):
        result = self.check({"malicious": True, "evidence": {"verdict": "malicious", "reasons": ["synthetic evidence"]}})
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.matches[0].confidence_level, None)

    def test_risk_is_not_confidence(self):
        result = self.check({"malicious": True, "riskScore": {"score": 99}, "confidence": {"score": 62}})
        self.assertEqual(result.matches[0].confidence_level, 62)

    def test_context_only_is_unknown(self):
        result = self.check({"malicious": False, "sources": [{"name": "context-only"}], "riskScore": {"score": 0}})
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.matches, [])

    def test_unknown_hash(self):
        result = self.check({"malicious": False, "lookupStatus": "unknown", "evidence": {"verdict": "unknown"}})
        self.assertEqual(result.status, "skipped")

    def test_delisted(self):
        result = self.check({"malicious": True, "delisted": True})
        self.assertEqual(result.status, "no_match")

    def test_missing_confidence_cannot_pass_threshold(self):
        self.provider.minimum_confidence = 75
        result = self.check({"malicious": True})
        self.assertEqual(result.status, "skipped")

    def test_invalid_response(self):
        result = self.check([])
        self.assertEqual(result.status, "error")

    @patch("requests.get")
    def test_auth_and_rate_limit(self, mock_get):
        for status in (401, 403, 429, 500, 302):
            mock_get.return_value = Mock(status_code=status)
            result = self.provider.lookup("example.invalid", "domain")
            self.assertEqual(result.status, "error")
            self.assertIn(str(status), result.error)

    @patch("requests.get", side_effect=requests.Timeout)
    def test_timeout(self, mock_get):
        self.assertEqual(self.provider.lookup("example.invalid", "domain").status, "timeout")

    @patch("requests.get")
    def test_url_encoded_by_client_no_redirects(self, mock_get):
        mock_get.return_value = Mock(status_code=200, json=Mock(return_value={"malicious": False}))
        query = "https://example.invalid/path?a=1&b=2"
        self.provider.lookup(query, "url")
        self.assertEqual(mock_get.call_args.kwargs["params"]["query"], query)
        self.assertEqual(mock_get.call_args.kwargs["headers"]["X-API-KEY"], "synthetic-key")
        self.assertFalse(mock_get.call_args.kwargs["allow_redirects"])

    @patch("requests.get")
    def test_empty_and_disabled_do_not_call(self, mock_get):
        self.assertEqual(self.provider.lookup("", "ip").status, "skipped")
        self.assertEqual(IsMaliciousProvider({}).lookup("8.8.8.8", "ip").status, "disabled")
        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
