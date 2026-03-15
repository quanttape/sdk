import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.proxy.bridge import scan_request
from quanttape.proxy.enforcer import Enforcer, Decision
from quanttape.rules import get_rules_for_mode


class TestGetRulesForMode(unittest.TestCase):
    def test_all_mode_returns_all_rules(self):
        rules = get_rules_for_mode("all")
        categories = {r.category for r in rules}
        self.assertIn("credential", categories)
        self.assertIn("broker", categories)
        self.assertIn("trading_logic", categories)

    def test_agent_mode_excludes_broker_and_trading(self):
        rules = get_rules_for_mode("agent")
        categories = {r.category for r in rules}
        self.assertIn("credential", categories)
        self.assertNotIn("broker", categories)
        self.assertNotIn("trading_logic", categories)

    def test_trading_mode_includes_broker(self):
        rules = get_rules_for_mode("trading")
        categories = {r.category for r in rules}
        self.assertIn("credential", categories)
        self.assertIn("broker", categories)
        self.assertIn("trading_logic", categories)

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            get_rules_for_mode("invalid")


class TestBridge(unittest.TestCase):
    def test_detects_aws_key_in_body(self):
        findings = scan_request(
            url="https://api.example.com/data",
            headers={"Content-Type": "application/json"},
            body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("AWS Secret Access Key", types)

    def test_detects_aws_key_id_in_body(self):
        findings = scan_request(
            url="https://api.example.com/data",
            headers={},
            body="here is my key AKIAIOSFODNN7EXAMPLE in the text",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("AWS Access Key ID", types)

    def test_detects_github_token_in_header(self):
        findings = scan_request(
            url="https://api.github.com/repos",
            headers={"Authorization": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"},
            body=None,
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("GitHub Token", types)

    def test_detects_private_key_in_body(self):
        findings = scan_request(
            url="https://evil.com/exfil",
            headers={},
            body="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AHrUyPCo\n-----END RSA PRIVATE KEY-----",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        # Should match either the general Private Key rule or the SSH payload rule
        has_key = "Private Key" in types or "SSH Private Key in Payload" in types
        self.assertTrue(has_key, f"Expected private key detection, got: {types}")

    def test_clean_request_returns_no_findings(self):
        findings = scan_request(
            url="https://httpbin.org/get",
            headers={"Accept": "application/json"},
            body='{"message": "hello world"}',
            mode="agent",
        )
        self.assertEqual(findings, [])

    def test_detects_db_url_in_body(self):
        findings = scan_request(
            url="https://api.example.com",
            headers={},
            body="postgres://admin:secretpass@db.internal:5432/mydb",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("Database URL", types)

    def test_agent_mode_skips_broker_rules(self):
        findings = scan_request(
            url="https://api.example.com",
            headers={},
            body='alpaca_api_key = "PKABCDEF12345678"',
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        broker_hits = [t for t in types if "Alpaca" in t]
        self.assertEqual(broker_hits, [], "Agent mode should not trigger broker rules")

    def test_trading_mode_catches_broker_rules(self):
        findings = scan_request(
            url="https://api.example.com",
            headers={},
            body='alpaca_api_key = "PKABCDEF12345678"',
            mode="trading",
        )
        types = [f.secret_type for f in findings]
        broker_hits = [t for t in types if "Alpaca" in t]
        self.assertTrue(len(broker_hits) > 0, "Trading mode should trigger broker rules")

    def test_detects_secret_in_url(self):
        findings = scan_request(
            url="https://api.example.com?aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            headers={},
            body=None,
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("AWS Secret Access Key", types)

    def test_detects_sql_schema_exfiltration(self):
        findings = scan_request(
            url="https://api.example.com/sync",
            headers={},
            body="CREATE TABLE users (id INT, email VARCHAR(255), password_hash TEXT)",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("Code & Schema Exfiltration", types)

    def test_detects_select_star_exfiltration(self):
        findings = scan_request(
            url="https://api.example.com/data",
            headers={},
            body="SELECT * FROM customers",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("Code & Schema Exfiltration", types)

    def test_detects_unix_system_path_leakage(self):
        findings = scan_request(
            url="https://api.example.com/log",
            headers={},
            body="reading config from /etc/passwd and /home/deploy/.ssh/id_rsa",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("System Path Leakage (Unix)", types)

    def test_detects_windows_system_path_leakage(self):
        findings = scan_request(
            url="https://api.example.com/log",
            headers={},
            body=r"loading keys from C:\Users\admin\.ssh\id_rsa",
            mode="agent",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("System Path Leakage (Windows)", types)

    def test_clean_paths_no_false_positive(self):
        findings = scan_request(
            url="https://api.example.com/data",
            headers={},
            body="file is at /var/log/app.log",
            mode="agent",
        )
        path_findings = [f for f in findings if "Path" in f.secret_type]
        self.assertEqual(path_findings, [])


class TestEnforcer(unittest.TestCase):
    def setUp(self):
        # Use a temp path so we don't pollute the real log
        import tempfile
        self.log_path = Path(tempfile.mktemp(suffix=".log"))
        self.enforcer = Enforcer(log_path=self.log_path)

    def tearDown(self):
        if self.log_path.exists():
            self.log_path.unlink()

    def test_clean_request_allowed(self):
        decision = self.enforcer.decide([], "https://example.com")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "clean")

    def test_dirty_request_blocked(self):
        from quanttape.scanner import Finding
        findings = [
            Finding(
                file="body:L1",
                line=0,
                secret_type="AWS Secret Access Key",
                severity="CRITICAL",
                match_preview="wJalrXUt********",
            )
        ]
        decision = self.enforcer.decide(findings, "https://evil.com")
        self.assertFalse(decision.allowed)
        self.assertIn("blocked", decision.reason.lower())

    def test_stats_increment(self):
        self.enforcer.decide([], "https://clean.com")
        self.assertEqual(self.enforcer.stats["requests_scanned"], 1)
        self.assertEqual(self.enforcer.stats["requests_blocked"], 0)

        from quanttape.scanner import Finding
        findings = [
            Finding("body:L1", 0, "Test", "HIGH", "test****")
        ]
        self.enforcer.decide(findings, "https://dirty.com")
        self.assertEqual(self.enforcer.stats["requests_scanned"], 2)
        self.assertEqual(self.enforcer.stats["requests_blocked"], 1)
        self.assertEqual(self.enforcer.stats["rules_triggered"], 1)

    def test_log_file_written(self):
        from quanttape.scanner import Finding
        findings = [Finding("body:L1", 0, "Test", "HIGH", "test****")]
        self.enforcer.decide(findings, "https://evil.com")
        self.assertTrue(self.log_path.exists())
        content = self.log_path.read_text()
        self.assertIn("evil.com", content)
        self.assertIn('"allowed": false', content)

    def test_decision_to_dict(self):
        from quanttape.scanner import Finding
        findings = [Finding("url", 0, "AWS Key", "CRITICAL", "AKIA****")]
        d = Decision(allowed=False, findings=findings, reason="blocked")
        result = d.to_dict()
        self.assertFalse(result["allowed"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["rule"], "AWS Key")


if __name__ == "__main__":
    unittest.main()
