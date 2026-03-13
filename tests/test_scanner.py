import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.scanner import SecretScanner


class ScannerIntegrationTests(unittest.TestCase):
    def test_default_scanner_suppresses_trading_bot_false_positives(self):
        source = """
def close_position():
    while True:
        if done:
            break
        time.sleep(0.5)
    return api.submit_order(type="market", position_intent="sell_to_close")
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as handle:
            handle.write(source)
            temp_path = Path(handle.name)

        try:
            scanner = SecretScanner()
            findings = scanner.scan_file(str(temp_path))
            names = {finding.secret_type for finding in findings}
            self.assertNotIn("Infinite Loop Risk", names)
            self.assertNotIn("Market Order Without Limit", names)
            self.assertNotIn("No Error Handling on Order", names)
        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
