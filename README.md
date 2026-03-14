# Quant Tape

**The Last Line Before The Market.**

Quant Tape is a local security scanner for trading bots and algorithmic trading code.
It finds exposed broker keys, embedded credentials, and risky execution patterns before they hit production.

- Local-first - scans your files, repos, and optional git history without uploading code
- Trading-aware - built for broker wrappers, sizing logic, execution flows, and bot loops
- CI-ready - outputs findings as Console, JSON, and SARIF

## What The SDK Does Today

Quant Tape currently ships with a scanner built for trading codebases.

- Detects **33 built-in rules** across credentials, broker secrets, and trading-code risk patterns
- Suppresses obvious false positives in common trading-bot structures
- Scans single files, full directories, and optional git history
- Fits local development, pre-commit checks, and CI pipelines
- Exports findings as Console, JSON, or SARIF

## What It Looks For

- Hardcoded broker/API secrets
- Embedded credentials and webhook URLs
- Unsafe market-order usage
- Full-account position sizing without caps
- Busy loops and risky blocking sleeps
- Hardcoded trading symbols and other reusable-bot mistakes

Supported broker and market-data patterns include:

- Alpaca
- Binance
- Coinbase
- Interactive Brokers
- Kraken
- TD Ameritrade / Schwab
- Tradier
- Polygon.io

## Quick Start

### CLI

```bash
pip install quanttape
quanttape scan my_bot.py
quanttape scan ./my_project/ --output json
quanttape scan ./my_project/ --git-history
```

Default behavior is trading-aware scanning.
If you want generic raw scanning behavior instead:

```bash
quanttape scan my_bot.py --generic-mode
```

### Python SDK

```python
from quanttape import SecretScanner

scanner = SecretScanner()

# Scan a single file
findings = scanner.scan_file("my_bot.py")

# Scan an entire directory
findings = scanner.scan_directory("./trading_bots/")

# Check results
for f in findings:
    print(f"{f.severity} | {f.secret_type} | {f.file}:{f.line}")
```

With custom rules or generic mode:

```python
from quanttape import SecretScanner

scanner = SecretScanner(
    config_path="my_rules.yaml",    # custom rules file
    trading_bot_mode=False,          # generic scanning (no AST suppression)
)
findings = scanner.scan_directory("./src/")
```

#### Output Formats

```python
from quanttape import SecretScanner
from quanttape.output import format_results

findings = SecretScanner().scan_directory("./bots/")

# Rich console output (prints directly)
format_results(findings, "console")

# JSON string
json_output = format_results(findings, "json")

# SARIF string (for GitHub Code Scanning, VS Code, CI)
sarif_output = format_results(findings, "sarif")
```

#### Finding Object

Each finding has these attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `file` | `str` | Path to the file |
| `line` | `int` | Line number |
| `secret_type` | `str` | Rule that matched (e.g. "Alpaca API Key") |
| `severity` | `str` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `match_preview` | `str` | Partially redacted preview of the match |

## Coming Soon

- Guard SDK - runtime trade validation, kill-switch, drawdown controls
- Zero-Knowledge Vault - encrypted local-first credential storage

Join the waitlist: [quanttape.com](https://quanttape.com)

