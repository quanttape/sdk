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

## Coming Soon

- Guard SDK - runtime trade validation, kill-switch, drawdown controls
- Zero-Knowledge Vault - encrypted local-first credential storage

Join the waitlist: [quanttape.com](https://quanttape.com)

