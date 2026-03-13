import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape import __version__
from quanttape.output import ConsoleFormatter, SarifFormatter
from quanttape.scanner import Finding


class OutputTests(unittest.TestCase):
    def test_console_formatter_empty_message_is_generic(self):
        self.assertEqual(ConsoleFormatter().format([]), "No findings detected.")

    def test_sarif_formatter_uses_package_version_and_normalized_uri(self):
        finding = Finding(
            file=r"E:\repo\bot.py",
            line=12,
            secret_type="Generic API Key",
            severity="MEDIUM",
            match_preview="abcd********",
        )
        sarif = json.loads(SarifFormatter().format([finding]))
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "QuantTape")
        self.assertEqual(run["tool"]["driver"]["version"], __version__)
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "E:/repo/bot.py",
        )


if __name__ == "__main__":
    unittest.main()
