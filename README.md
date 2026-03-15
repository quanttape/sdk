# QuantTape

Local security scanner and egress firewall for trading bots and AI agents.

[![PyPI](https://img.shields.io/pypi/v/quanttape)](https://pypi.org/project/quanttape/)
[![Tests](https://github.com/quanttape/sdk/actions/workflows/test.yml/badge.svg)](https://github.com/quanttape/sdk/actions/workflows/test.yml)
[![Python](https://img.shields.io/pypi/pyversions/quanttape)](https://pypi.org/project/quanttape/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Quick Start

Install:

```bash
pip install quanttape
```

Scan your code for secrets:

```bash
quanttape scan my_bot.py
```

Start the Guard proxy to block secrets in outbound requests:

```bash
pip install quanttape[guard]
quanttape guard --mode agent
```

Test it:

```bash
curl -x http://127.0.0.1:8080 \
     --cacert ~/.quanttape/ca.pem \
     "https://api.example.com/data?token=ghp_a1b2c3SECRET"
```

```
403 Forbidden
X-QuantTape-Action: blocked
{"error": "QuantTape Guard: request blocked", "allowed": false, "reason": "Blocked: 1 secret(s) detected"}
```

Everything runs locally. No cloud service required.

---

## What QuantTape Does

### Scanner

Static detection of secrets and risky patterns in code and files.

- **33+ built-in rules** across credentials, broker secrets, and trading-code risk patterns
- Suppresses false positives in common trading-bot structures
- Scans single files, directories, and git history
- Outputs Console, JSON, or SARIF

### Guard

Local egress proxy that intercepts outbound HTTP/HTTPS requests and blocks secrets before they leave your machine.

- HTTPS interception via locally generated CA
- Inspects URLs, headers, and request bodies
- Deterministic block-or-forward decision
- JSON audit logging to `~/.quanttape/guard.log`
- Real-client MITM validated with curl, requests, and httpx (24/24 tests passing)

## What It Looks For

- Hardcoded broker/API secrets (Alpaca, Binance, Coinbase, IB, Kraken, Tradier, Polygon)
- AWS, GCP, Azure, Slack, Telegram, JWT credentials
- SSH private keys, `.env` content, webhook URLs
- Unsafe market-order usage, position sizing without caps
- Busy loops, risky blocking sleeps, hardcoded symbols

## Scanner CLI

```bash
quanttape scan my_bot.py
quanttape scan ./my_project/ --output json
quanttape scan ./my_project/ --output sarif
quanttape scan ./my_project/ --git-history
quanttape scan my_bot.py --generic-mode
```

## Guard CLI

```bash
quanttape guard                     # start on :8080
quanttape guard --port 9090         # custom port
quanttape guard --mode agent        # credential + general rules
quanttape guard --mode trading      # all rules including broker + trading logic
quanttape guard --mode all          # everything (default)
```

## Python SDK

```python
from quanttape import SecretScanner

scanner = SecretScanner()

# Scan a single file
findings = scanner.scan_file("my_bot.py")

# Scan an entire directory
findings = scanner.scan_directory("./trading_bots/")

for f in findings:
    print(f"{f.severity} | {f.secret_type} | {f.file}:{f.line}")
```

### Output Formats

```python
from quanttape import SecretScanner
from quanttape.output import format_results

findings = SecretScanner().scan_directory("./bots/")

format_results(findings, "console")  # rich terminal output
json_output = format_results(findings, "json")
sarif_output = format_results(findings, "sarif")
```

### Finding Object

| Attribute | Type | Description |
|-----------|------|-------------|
| `file` | `str` | Path to the file |
| `line` | `int` | Line number |
| `secret_type` | `str` | Rule that matched |
| `severity` | `str` | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `match_preview` | `str` | Partially redacted preview |

## License

[MIT](LICENSE)

## Links

- [Website](https://quanttape.com)
- [Guard](https://quanttape.com/guard)
- [Changelog](CHANGELOG.md)
