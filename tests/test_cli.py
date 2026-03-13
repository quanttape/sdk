import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape import __version__
from quanttape.cli import _git_history_root, build_parser, main


class CliTests(unittest.TestCase):
    def test_scan_defaults_to_trading_bot_mode(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "bot.py"])
        self.assertTrue(args.trading_bot_mode)

    def test_scan_generic_mode_disables_trading_bot_mode(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "bot.py", "--generic-mode"])
        self.assertFalse(args.trading_bot_mode)

    def test_scan_trading_bot_mode_flag_remains_valid(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "bot.py", "--trading-bot-mode"])
        self.assertTrue(args.trading_bot_mode)

    def test_git_history_root_uses_parent_for_file_paths(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_dir = Path(tmp_dir)
            file_path = repo_dir / "bot.py"
            file_path.write_text("print('x')\n", encoding="utf-8")
            self.assertEqual(_git_history_root(str(file_path)), str(repo_dir))
            self.assertEqual(_git_history_root(str(repo_dir)), str(repo_dir))

    def test_main_json_output_avoids_banner_text(self):
        with patch("quanttape.cli.os.path.isfile", return_value=True), \
             patch("quanttape.cli.os.path.isdir", return_value=False), \
             patch("quanttape.cli.SecretScanner") as scanner_cls, \
             patch("sys.argv", ["quanttape", "scan", "bot.py", "--output", "json"]), \
             patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            scanner_cls.return_value.scan_file.return_value = []
            main()
            output = fake_stdout.getvalue()
            self.assertEqual(output.strip(), '{\n  "total": 0,\n  "findings": []\n}')
            self.assertNotIn(f"QuantTape Scanner v{__version__}", output)

    def test_main_git_history_uses_repo_root_for_file_scan(self):
        with patch("quanttape.cli.os.path.isfile", return_value=True), \
             patch("quanttape.cli.os.path.isdir", return_value=False), \
             patch("quanttape.cli.SecretScanner") as scanner_cls, \
             patch("sys.argv", ["quanttape", "scan", r"E:\repo\bot.py", "--git-history"]), \
             patch("sys.stdout", new_callable=io.StringIO):
            scanner = scanner_cls.return_value
            scanner.scan_file.return_value = []
            scanner.scan_git_history.return_value = []
            main()
            scanner.scan_git_history.assert_called_once_with(r"E:\repo")


if __name__ == "__main__":
    unittest.main()
