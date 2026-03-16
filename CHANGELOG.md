# Changelog

## 0.0.22 - Scanner Rule Upgrades

**Release date:** 2026-03-16

4 new trading logic rules, 3 bug fixes, 45 total rules.

### New Rules

- **Extended Hours Without Limit Order** (HIGH) - Flags `extended_hours=True` without limit order context. Market orders and non-day TIF are rejected in extended sessions.
- **Leverage Without Cap** (HIGH) - Detects bare `leverage = 4` assignments with no min/max/config guard. Over-leverage amplifies losses and triggers margin calls.
- **Hardcoded Notional Amount** (MEDIUM) - Catches large fixed dollar values like `notional = 100000`. Use calculated position sizing with risk budgets instead.
- **Hardcoded Crypto Pair** (LOW) - Flags hardcoded crypto pairs like `symbol="BTCUSDT"` or `pair='ETH/USD'`. Make configurable for reusability.

### Bug Fixes

- **Infinite Loop Risk** - Now catches `while 1:` in addition to `while True:`
- **Sleep Without Kill Switch** - Now matches single-decimal sleeps like `time.sleep(0.5)`
- **Custom rule loading** - `load_custom_rules()` now reads `category` from YAML, so custom rules work with `--mode trading` and `--mode agent`

---

## 0.0.21 - Housekeeping

**Release date:** 2026-03-15

Cleanup release with no functional changes to the scanner or guard engines.

- **License**: Changed from Proprietary to MIT
- **README**: Rewritten with quick start guide, usage examples, and PyPI badges
- **Text cleanup**: Removed em dashes and non-ASCII characters from comments, docstrings, and documentation
- **CI**: Fixed live test exclusion and cross-platform CLI test compatibility

---

## 0.0.20 - Real-Client MITM Validation

**Release date:** 2026-03-14

This release marks the transition from "structurally validated" to "live MITM validated." The HTTPS interception path has been proven end-to-end with real HTTP clients through a trusted local CA.

### HTTPS MITM - Now Real-Client Validated

- Validated with **curl**, **requests**, and **httpx** using a trusted local CA
- 24 MITM live-validation tests covering: clean forward, blocked request, untrusted CA failure, secret in URL/header/body, binary passthrough, gzip body scanning, large body forwarding
- Full client matrix: all scenarios pass across all three clients

### Certificate Chain Fixes (correctness)

- **IP address SAN**: `make_host_cert` now uses `x509.IPAddress()` for IP addresses instead of `x509.DNSName()`. This fixes TLS verification failures when proxying traffic to IP-addressed hosts.
- **Authority Key Identifier**: Host certs now include `AuthorityKeyIdentifier` referencing the CA's `SubjectKeyIdentifier`. Required by OpenSSL 3.x / Python 3.12+.
- **CA KeyUsage**: CA cert now includes `KeyUsage(key_cert_sign=True)`. Required by Python 3.14 / OpenSSL 3.x strict validation.
- **CA SubjectKeyIdentifier**: CA cert now includes `SubjectKeyIdentifier` for proper X.509 chain linkage.

### TLS Transport Fix (Windows compatibility)

- Replaced manual `StreamReaderProtocol` reconstruction after `start_tls()` with protocol reuse pattern. The existing `StreamReader` stays wired to the original protocol, which `start_tls()` automatically reconnects to the new TLS transport. This fixes data flow on Windows `ProactorEventLoop`.

### Benchmark Results

Measured on localhost with httpx client, 20 iterations per scenario:

| Metric | Value |
|---|---|
| HTTP proxy overhead vs direct | +1.6ms |
| HTTP blocked (no forward) | 2.6ms median |
| HTTPS MITM clean (empty) | 94ms median |
| HTTPS MITM blocked (1KB) | 99ms median |
| Scan-only, <1KB body | <0.3ms |
| Scan-only, 100KB body | 27ms |

### Other Changes

- Version bump from 0.0.19 to 0.0.20
- Website copy updated: speculative latency claims replaced with measured numbers
- README updated with validation matrix and benchmark tables
- Test suite: 61 tests total (23 unit + 14 integration + 24 MITM live)

---

## 0.0.19

- Guard proxy module: HTTP + HTTPS interception
- Enforcer with timing instrumentation
- Edge-case handling: chunked, gzip, binary, large bodies
- Detection rules: code/schema exfiltration, system path leakage
- End-to-end integration tests
- CLI `guard` subcommand
