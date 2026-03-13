import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.output import SarifFormatter
from quanttape.scanner import SecretScanner


class SarifSnapshotTests(unittest.TestCase):
    def _assert_snapshot_matches(self, fixture_name: str, snapshot_name: str) -> None:
        scanner = SecretScanner()
        fixture_path = Path("tests") / "fixtures" / fixture_name
        snapshot_path = ROOT / "tests" / "snapshots" / snapshot_name
        findings = scanner.scan_file(str(fixture_path))
        actual = json.loads(SarifFormatter().format(findings))
        expected = json.loads(snapshot_path.read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)

    def test_sarif_snapshot_for_trading_rule_hits(self):
        self._assert_snapshot_matches(
            "trading_rule_hits.py",
            "trading_rule_hits.sarif.json",
        )

    def test_sarif_snapshot_for_suppressed_trading_bot_context(self):
        self._assert_snapshot_matches(
            "trading_rule_suppressed.py",
            "trading_rule_suppressed.sarif.json",
        )


if __name__ == "__main__":
    unittest.main()
