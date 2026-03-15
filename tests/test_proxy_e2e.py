"""End-to-end integration tests for Guard proxy.

Starts an actual asyncio proxy server on a random port, sends real HTTP
requests through it, and verifies block/allow behavior.

These tests validate:
- Clean HTTP requests forward correctly
- Dirty HTTP requests get blocked with 403
- Binary content passes through without false positives
- Large bodies are handled without hanging
- Compressed (gzip) bodies are decompressed and scanned
- Timing instrumentation is populated
- Response headers include X-QuantTape-Action on blocks
"""

import asyncio
import gzip
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.proxy.server import GuardProxy, GuardConfig

# A simple upstream HTTP server for testing
_UPSTREAM_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"OK"
)


async def _start_upstream(host="127.0.0.1", port=0):
    """Start a trivial HTTP server that always returns 200 OK."""

    async def handle(reader, writer):
        # Read request line + headers
        content_length = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore").lower()
            if decoded.startswith("content-length:"):
                content_length = int(decoded.split(":", 1)[1].strip())
        # Drain body
        if content_length > 0:
            remaining = content_length
            while remaining > 0:
                chunk = await reader.read(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
        writer.write(_UPSTREAM_RESPONSE)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, host, port)
    addr = server.sockets[0].getsockname()
    return server, addr[1]


async def _send_http_via_proxy(proxy_port, method, url, headers=None, body=None):
    """Send a raw HTTP request through the proxy and return (status, headers_dict, body)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

    # Build raw HTTP request
    request_line = f"{method} {url} HTTP/1.1\r\n"
    raw = request_line.encode()

    if headers:
        for k, v in headers.items():
            raw += f"{k}: {v}\r\n".encode()

    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    if body_bytes:
        raw += f"Content-Length: {len(body_bytes)}\r\n".encode()

    raw += b"\r\n"
    if body_bytes:
        raw += body_bytes

    writer.write(raw)
    await writer.drain()

    # Read response
    response_data = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            if not chunk:
                break
            response_data += chunk
    except asyncio.TimeoutError:
        pass

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    # Parse response
    if not response_data:
        return 0, {}, b""

    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}, response_data

    header_section = response_data[:header_end].decode("utf-8", errors="ignore")
    resp_body = response_data[header_end + 4:]

    lines = header_section.split("\r\n")
    status_line = lines[0] if lines else ""
    status_code = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    return status_code, resp_headers, resp_body


class TestProxyE2E(unittest.TestCase):
    """End-to-end tests with a real proxy and upstream server."""

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # Start upstream and proxy
        async def setup():
            # Start upstream
            self.upstream_server, self.upstream_port = await _start_upstream()

            # Start proxy (with custom config, no_verify for testing)
            import tempfile
            self.log_path = Path(tempfile.mktemp(suffix=".log"))

            self.config = GuardConfig(
                port=0,  # auto-assign
                host="127.0.0.1",
                mode="agent",
            )
            self.proxy = GuardProxy(self.config)
            self.proxy.enforcer.log_path = self.log_path

            self.proxy_server = await asyncio.start_server(
                self.proxy.handle_client, "127.0.0.1", 0
            )
            self.proxy_port = self.proxy_server.sockets[0].getsockname()[1]

        self.loop.run_until_complete(setup())

    def tearDown(self):
        async def cleanup():
            self.proxy_server.close()
            await self.proxy_server.wait_closed()
            self.upstream_server.close()
            await self.upstream_server.wait_closed()

        self.loop.run_until_complete(cleanup())
        self.loop.close()

        if self.log_path.exists():
            self.log_path.unlink()

    def _run(self, coro):
        return self.loop.run_until_complete(coro)

    def test_clean_request_forwards(self):
        """Clean HTTP request should be forwarded and return 200."""
        url = f"http://127.0.0.1:{self.upstream_port}/test"
        status, headers, body = self._run(
            _send_http_via_proxy(self.proxy_port, "GET", url, {"Accept": "text/plain"})
        )
        self.assertEqual(status, 200)
        self.assertIn(b"OK", body)

    def test_dirty_request_blocked_with_403(self):
        """Request containing AWS key should be blocked with 403."""
        url = f"http://127.0.0.1:{self.upstream_port}/data"
        status, headers, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "POST", url,
                {"Content-Type": "text/plain"},
                body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-quanttape-action"), "blocked")

        # Parse response body
        resp_json = json.loads(body.decode("utf-8"))
        self.assertFalse(resp_json["allowed"])
        self.assertTrue(len(resp_json["findings"]) > 0)

    def test_blocked_response_includes_scan_time(self):
        """Blocked response should include scan_time_ms in JSON."""
        url = f"http://127.0.0.1:{self.upstream_port}/data"
        status, headers, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "POST", url,
                {"Content-Type": "text/plain"},
                body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            )
        )
        resp_json = json.loads(body.decode("utf-8"))
        self.assertIn("scan_time_ms", resp_json)
        self.assertGreater(resp_json["scan_time_ms"], 0)

    def test_secret_in_url_blocked(self):
        """Secret embedded in the URL should be detected and blocked."""
        url = f"http://127.0.0.1:{self.upstream_port}/data?aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        status, _, body = self._run(
            _send_http_via_proxy(self.proxy_port, "GET", url)
        )
        self.assertEqual(status, 403)

    def test_secret_in_header_blocked(self):
        """Secret in a header value should be detected and blocked."""
        url = f"http://127.0.0.1:{self.upstream_port}/repos"
        status, _, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "GET", url,
                {"Authorization": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"},
            )
        )
        self.assertEqual(status, 403)

    def test_binary_content_passes_through(self):
        """Binary content (image/png) should not trigger false positives."""
        url = f"http://127.0.0.1:{self.upstream_port}/upload"
        # Random-looking binary bytes
        binary_body = bytes(range(256)) * 4
        status, _, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "POST", url,
                {"Content-Type": "image/png"},
                body=binary_body,
            )
        )
        # Should forward successfully (200 from upstream) -- not blocked
        self.assertEqual(status, 200)

    def test_gzip_body_scanned(self):
        """Gzip-compressed body with a secret should still be detected."""
        url = f"http://127.0.0.1:{self.upstream_port}/data"
        secret_text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        compressed = gzip.compress(secret_text.encode("utf-8"))
        status, _, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "POST", url,
                {"Content-Type": "application/json", "Content-Encoding": "gzip"},
                body=compressed,
            )
        )
        self.assertEqual(status, 403)

    def test_large_clean_body_forwards(self):
        """Large clean body should forward without hanging or crashing."""
        url = f"http://127.0.0.1:{self.upstream_port}/bulk"
        # 500KB of clean JSON-like data
        large_body = '{"data": "' + "a" * 500_000 + '"}'
        status, _, body = self._run(
            _send_http_via_proxy(
                self.proxy_port, "POST", url,
                {"Content-Type": "application/json"},
                body=large_body,
            )
        )
        self.assertEqual(status, 200)

    def test_enforcer_stats_populated(self):
        """After processing requests, enforcer stats should be accurate."""
        url = f"http://127.0.0.1:{self.upstream_port}/test"

        # Clean request
        self._run(_send_http_via_proxy(self.proxy_port, "GET", url))

        # Dirty request
        self._run(_send_http_via_proxy(
            self.proxy_port, "POST", url,
            {"Content-Type": "text/plain"},
            body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        ))

        stats = self.proxy.enforcer.stats
        self.assertEqual(stats["requests_scanned"], 2)
        self.assertEqual(stats["requests_blocked"], 1)
        self.assertGreater(stats["total_scan_time_ms"], 0)

    def test_audit_log_written_on_block(self):
        """Blocked request should produce an entry in the audit log file."""
        url = f"http://127.0.0.1:{self.upstream_port}/data"
        self._run(_send_http_via_proxy(
            self.proxy_port, "POST", url,
            {"Content-Type": "text/plain"},
            body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        ))

        self.assertTrue(self.log_path.exists())
        content = self.log_path.read_text()
        entry = json.loads(content.strip())
        self.assertFalse(entry["allowed"])
        self.assertIn("AWS Secret Access Key", entry["findings"][0]["rule"])
        self.assertIn("scan_time_ms", entry)

    def test_empty_body_clean(self):
        """Request with no body should pass through cleanly."""
        url = f"http://127.0.0.1:{self.upstream_port}/health"
        status, _, _ = self._run(
            _send_http_via_proxy(self.proxy_port, "GET", url)
        )
        self.assertEqual(status, 200)


class TestScanResultDetailed(unittest.TestCase):
    """Test the detailed scan result interface directly."""

    def test_scan_result_has_timing(self):
        from quanttape.proxy.bridge import scan_request_detailed
        result = scan_request_detailed(
            url="https://api.example.com",
            headers={"Accept": "application/json"},
            body='aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            mode="agent",
        )
        self.assertGreater(result.scan_time_ms, 0)
        self.assertGreater(len(result.findings), 0)
        self.assertGreater(result.body_scanned_bytes, 0)
        self.assertFalse(result.body_truncated)

    def test_large_body_truncation(self):
        from quanttape.proxy.bridge import scan_request_detailed, MAX_BODY_SCAN_BYTES
        # Body larger than MAX_BODY_SCAN_BYTES
        huge_body = "x" * (MAX_BODY_SCAN_BYTES + 1000)
        result = scan_request_detailed(
            url="https://api.example.com",
            headers={},
            body=huge_body,
            mode="agent",
        )
        self.assertTrue(result.body_truncated)
        self.assertLessEqual(result.body_scanned_bytes, MAX_BODY_SCAN_BYTES)

    def test_clean_scan_timing(self):
        from quanttape.proxy.bridge import scan_request_detailed
        result = scan_request_detailed(
            url="https://httpbin.org/get",
            headers={"Accept": "application/json"},
            body='{"message": "hello"}',
            mode="agent",
        )
        self.assertEqual(len(result.findings), 0)
        self.assertGreaterEqual(result.scan_time_ms, 0)


if __name__ == "__main__":
    unittest.main()
