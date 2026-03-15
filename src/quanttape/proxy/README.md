# QuantTape Guard -- Proxy Module Technical Reference

## Overview

The `proxy/` package implements a local egress proxy that intercepts outbound HTTP/HTTPS traffic, scans it through the QuantTape rules engine, and blocks requests containing secrets. It reuses the same regex + entropy detection from the static scanner, but operates on raw HTTP payloads instead of Python ASTs.

**Maturity status:** Real-client validated with curl, requests, and httpx using a trusted local CA. 24 MITM live-validation tests + 37 unit/integration tests passing. Both HTTP and HTTPS inspection paths are validated end-to-end.

---

## Module Map

```
proxy/
├── __init__.py      # Public exports: scan_request, Enforcer, Decision, cert helpers
├── bridge.py        # HTTP request → rules engine adapter (no AST)
├── enforcer.py      # Block/allow decision engine + audit logging
├── certs.py         # Local Certificate Authority generation + per-host certs
├── server.py        # Raw asyncio TCP proxy (HTTP + HTTPS CONNECT)
└── README.md        # This file
```

---

## Request Lifecycle

### HTTP (plain text)

```
Client ──HTTP──▶ GuardProxy._handle_http()
                  │
                  ├─ Parse request line, headers, body
                  ├─ bridge.scan_request(url, headers, body, mode)
                  │   ├─ Compile rules for mode (get_rules_for_mode)
                  │   ├─ Regex match URL, each header value, each body line
                  │   ├─ Shannon entropy check on high-entropy tokens
                  │   └─ Return List[Finding]
                  │
                  ├─ enforcer.decide(findings, url)
                  │   ├─ No findings → Decision(allowed=True, reason="clean")
                  │   └─ Findings → Decision(allowed=False), log to guard.log
                  │
                  ├─ BLOCKED → 403 Forbidden JSON response to client
                  └─ ALLOWED → Forward via httpx.AsyncClient, relay response back
```

### HTTPS (CONNECT tunnel with MITM)

```
Client ──CONNECT──▶ GuardProxy._handle_connect()
                     │
                     ├─ Parse host:port from CONNECT target
                     ├─ Consume remaining CONNECT headers
                     │
                     ├─ [No cryptography?] → 200 Connection Established
                     │                       → _blind_tunnel() (transparent, no inspection)
                     │
                     ├─ Send "200 Connection Established" to client
                     ├─ make_host_cert(host) → generate per-host cert signed by local CA
                     │
                     ├─ TLS upgrade (client side):
                     │   └─ loop.start_tls(writer.transport, server_ctx, server_side=True)
                     │   └─ Rebuild StreamReader/StreamWriter on new TLS transport
                     │
                     ├─ TLS connect (upstream):
                     │   └─ asyncio.open_connection(host, port, ssl=True)
                     │   └─ If --no-verify: permissive SSL context (CERT_NONE)
                     │
                     └─ _mitm_relay():
                         ├─ Read decrypted HTTP request from client
                         ├─ Reconstruct URL as https://{host}{path}
                         ├─ bridge.scan_request() → enforcer.decide()
                         ├─ BLOCKED → 403 on decrypted channel
                         └─ ALLOWED → Forward raw bytes to upstream, pipe response back
```

### Transparent Tunnel (fallback)

When `cryptography` is not installed or cert generation fails:

```
Client ◀──TCP──▶ _blind_tunnel() ◀──TCP──▶ Upstream
```

Bidirectional byte relay with no inspection. Data passes through unmodified. This is the graceful degradation path -- Guard still runs but HTTPS content is opaque.

---

## Bridge (bridge.py)

**Purpose:** Adapt raw HTTP request data for the rules engine.

**Key function:**
```python
scan_request(url, headers, body, rules=None, mode="agent") -> List[Finding]
```

**How it differs from the scanner:**
- No AST parsing (HTTP payloads aren't Python source)
- No file I/O -- operates on in-memory strings
- Scans URL, each header value, and each body line independently
- Same regex patterns + Shannon entropy (threshold: 4.5, min length: 20 chars)
- Sources are tagged as `url`, `header:{name}`, or `body:L{n}`

**Internal flow:**
1. Load rules for mode via `get_rules_for_mode(mode)`
2. Compile all rule patterns once
3. For each text segment: run all compiled patterns, then entropy check
4. Return aggregated `List[Finding]`

---

## Enforcer (enforcer.py)

**Purpose:** Binary block/allow decision + audit trail.

**Decision logic:**
- Zero findings → `Decision(allowed=True, reason="clean")`
- Any findings → `Decision(allowed=False)`, increment stats, write audit log

**Audit log format:** JSON-lines at `~/.quanttape/guard.log`
```json
{
  "timestamp": "2026-03-14T14:32:05.123456+00:00",
  "target": "https://webhook.site/abc123",
  "allowed": false,
  "reason": "Blocked: 1 secret(s) detected",
  "findings": [
    {
      "rule": "AWS Secret Access Key",
      "severity": "CRITICAL",
      "source": "body:L1",
      "preview": "wJalrXUt********"
    }
  ]
}
```

**Stats tracking (in-memory):**
- `requests_scanned` -- total requests evaluated
- `requests_blocked` -- requests denied
- `rules_triggered` -- total individual rule hits

---

## Certificate Authority (certs.py)

**Storage:** `~/.quanttape/`
```
~/.quanttape/
├── ca-key.pem          # CA private key (RSA-2048)
├── ca.pem              # CA certificate (valid 10 years)
└── certs/
    ├── example.com.pem      # Per-host cert
    └── example.com-key.pem  # Per-host key
```

**CA generation (`ensure_ca`):**
- Creates RSA-2048 key + self-signed X.509 cert
- Subject: `CN=QuantTape Guard CA, O=QuantTape Local`
- BasicConstraints: `CA=True, pathLength=None`
- Idempotent: skips if ca-key.pem and ca.pem already exist

**Per-host certs (`make_host_cert`):**
- Generates RSA-2048 key for the hostname
- Signs with the local CA key
- SubjectAlternativeName: `DNSName` for hostnames, `IPAddress` for IPs
- AuthorityKeyIdentifier references the CA's SubjectKeyIdentifier
- Valid for 1 year
- Cached to disk at `~/.quanttape/certs/{hostname}.pem`

**Trust model:**
The user must explicitly trust the CA cert. `quanttape setup-certs` prints platform-specific instructions:
- **macOS:** `security add-trusted-cert`
- **Linux:** `update-ca-certificates` or `update-ca-trust`
- **Windows:** `certutil -addstore "Root"`
- **Python:** `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE`
- **Node.js:** `NODE_EXTRA_CA_CERTS`

---

## Server (server.py)

**Architecture:** Raw asyncio TCP server (not FastAPI/uvicorn).

**Why raw asyncio:**
- FastAPI/uvicorn cannot handle the CONNECT method (it's HTTP-level, not application-level)
- Raw TCP allows protocol detection: CONNECT → HTTPS path, everything else → HTTP path
- Minimal dependency footprint: only `httpx` for HTTP forwarding, `cryptography` for certs

**Key classes:**
- `GuardConfig` -- dataclass: port, host, mode, config_path, no_verify
- `GuardProxy` -- main proxy handler with connection routing

**Methods:**
| Method | Role |
|---|---|
| `handle_client()` | Entry point. Read first line, route to HTTP or CONNECT handler |
| `_handle_http()` | Full HTTP inspection: parse → scan → block/forward via httpx |
| `_handle_connect()` | HTTPS MITM: cert gen → TLS upgrade → decrypt → scan → relay |
| `_mitm_relay()` | Read decrypted HTTP from client, scan, forward or block |
| `_blind_tunnel()` | Transparent TCP relay, no inspection (fallback) |
| `_pipe()` | Async bidirectional byte relay |

**TLS upgrade mechanism:**
Uses `asyncio.get_event_loop().start_tls()` to upgrade the existing plain-text transport to TLS in-place. After upgrade, the existing `StreamReader` (wired to the original protocol) continues to receive data through the TLS transport, and a new `StreamWriter` is created pointing to the TLS transport. This approach works correctly on both Windows (ProactorEventLoop) and Unix, avoiding the fragile socket-detach or manual StreamReaderProtocol reconstruction patterns.

**Forwarding (HTTP path):**
Uses `httpx.AsyncClient` with 30s timeout. Strips proxy-specific headers (`Proxy-Connection`, `Proxy-Authorization`) before forwarding. Reconstructs raw HTTP response with explicit `Content-Length` and `Connection: close`.

---

## Guard Modes

Modes filter which rules are active:

| Mode | Categories loaded | Use case |
|---|---|---|
| `agent` | `credential` | AI agent egress -- catches secrets, skips trading logic |
| `trading` | `credential`, `broker`, `trading_logic` | Trading bot egress -- full broker key + logic checks |
| `all` | Everything | No filter, all rules active |

Mode filtering happens in `rules.get_rules_for_mode()`. The bridge calls this when no explicit rule list is provided.

---

## Failure Modes

| Failure | Behavior |
|---|---|
| `cryptography` not installed | HTTPS falls back to transparent tunnel (no inspection) |
| Per-host cert generation fails | Falls back to transparent tunnel for that host |
| TLS handshake fails (client rejects CA) | Connection dropped, debug log |
| Upstream unreachable | 502 Bad Gateway returned to client |
| httpx forwarding error | 502 Bad Gateway with error detail |
| Audit log write fails | Warning logged, request still blocked |

---

## Performance Considerations

- Rules are compiled once per `scan_request()` call, not per line
- Entropy check only runs on tokens >= 20 chars matching `[A-Za-z0-9/+=_-]{20,}`
- HTTP forwarding uses httpx async client with connection pooling
- Per-host certs are cached to disk -- only generated once per hostname
- No disk I/O in the hot path (scan is pure in-memory regex)
- **Measured latency (localhost, httpx client, 20 iterations per scenario):**

  | Scenario | Median | P95 |
  |---|---|---|
  | HTTP proxy overhead vs direct | +1.6ms | - |
  | HTTP blocked (no forward) | 2.6ms | 3.7ms |
  | HTTPS MITM clean (empty body) | 94ms | 139ms |
  | HTTPS MITM clean (1KB body) | 93ms | 162ms |
  | HTTPS MITM clean (100KB body) | 127ms | 171ms |
  | HTTPS MITM clean (500KB body) | 242ms | 299ms |
  | HTTPS MITM blocked (1KB) | 99ms | 136ms |

  **Scan-only overhead (no I/O, 100 iterations):**

  | Body size | Median |
  |---|---|
  | Empty | 0.017ms |
  | 1KB | 0.23ms |
  | 100KB | 27ms |
  | 500KB | 128ms |

  The scan engine is sub-millisecond for typical API payloads (<1KB). HTTPS end-to-end latency is dominated by TLS handshake and cert generation, not scanning.

---

## Real-Client MITM Validation

Validated with `curl`, `requests`, and `httpx` using a trusted local CA (`test_mitm_live.py`).

| Scenario | curl | requests | httpx |
|---|---|---|---|
| HTTP clean forward | PASS | PASS | PASS |
| HTTP blocked request | PASS | PASS | PASS |
| HTTPS clean forward (trusted CA) | PASS | PASS | PASS |
| HTTPS blocked request (MITM) | PASS | PASS | PASS |
| HTTPS untrusted CA failure | PASS | PASS | PASS |
| HTTPS secret in header (MITM) | PASS | PASS | - |
| Secret in URL | - | PASS | - |
| HTTPS binary passthrough | - | PASS | - |
| HTTPS gzip body scanned | - | PASS | - |
| HTTPS large body forward | - | - | PASS |
| Blocked response format | - | PASS | - |
| Audit log written | PASS | | |
| Enforcer stats accurate | PASS | | |

**Total: 24/24 PASS**

---

## Dependencies

| Package | Required for | Optional? |
|---|---|---|
| `httpx` | HTTP forwarding | Required for guard |
| `cryptography` | CA generation, per-host certs, HTTPS MITM | Optional (graceful fallback) |

Install both via: `pip install quanttape[guard]`

---

## CLI Entry Points

```bash
quanttape guard                        # Start proxy on :8080, agent mode
quanttape guard --port 9090            # Custom port
quanttape guard --mode trading         # Load trading + credential rules
quanttape guard --mode all             # Load all rules
quanttape guard --no-verify            # Skip upstream TLS verification (testing)
quanttape guard --config rules.yml     # Custom rules file
quanttape setup-certs                  # Generate CA and print trust instructions
```
