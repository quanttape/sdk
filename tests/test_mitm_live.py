"""Real-client MITM validation harness for QuantTape Guard.

Starts a real HTTPS upstream server and a real Guard proxy (each in their own
asyncio event loop thread), then validates the full MITM inspection path using
real synchronous HTTP clients: curl, requests, httpx.

Usage:
    python tests/test_mitm_live.py

Requires: pip install quanttape[guard] requests httpx
"""

import asyncio
import gzip
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.proxy.server import GuardProxy, GuardConfig
from quanttape.proxy.certs import ensure_ca, CA_CERT_FILE


# ── Self-signed HTTPS upstream ──────────────────────────────────────

def _generate_upstream_cert(cert_dir: Path):
    """Generate a self-signed cert for the test HTTPS upstream."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = cert_dir / "upstream.pem"
    key_path = cert_dir / "upstream-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    return str(key_path), str(cert_path)


# ── Async server runner (runs in its own thread) ────────────────────

class AsyncServerThread:
    """Runs asyncio servers in a background thread with its own event loop."""

    def __init__(self):
        self.loop = None
        self._thread = None
        self._started = threading.Event()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started.wait(timeout=10)

    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._started.set()
        self.loop.run_forever()

    def run_coroutine(self, coro):
        """Schedule a coroutine on the background loop and wait for result."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=30)

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread:
            self._thread.join(timeout=5)


async def _start_upstream(cert_path, key_path, host="127.0.0.1"):
    """Start HTTPS upstream that echoes 200 OK with JSON body."""
    async def handle(reader, writer):
        content_length = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore").lower()
            if decoded.startswith("content-length:"):
                content_length = int(decoded.split(":", 1)[1].strip())
        if content_length > 0:
            remaining = content_length
            while remaining > 0:
                chunk = await reader.read(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
        body = b'{"status":"ok"}'
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server = await asyncio.start_server(handle, host, 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _start_http_upstream(host="127.0.0.1"):
    """Start plain HTTP upstream."""
    async def handle(reader, writer):
        content_length = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore").lower()
            if decoded.startswith("content-length:"):
                content_length = int(decoded.split(":", 1)[1].strip())
        if content_length > 0:
            remaining = content_length
            while remaining > 0:
                chunk = await reader.read(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
        body = b'{"status":"ok"}'
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, host, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


# ── Test data ────────────────────────────────────────────────────────

AWS_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"

RESULTS = []


def record(client, scenario, passed, latency_ms=0, notes=""):
    RESULTS.append({
        "client": client,
        "scenario": scenario,
        "result": "PASS" if passed else "FAIL",
        "latency_ms": round(latency_ms, 2),
        "notes": notes,
    })


# ── Test class ───────────────────────────────────────────────────────

class TestMITMLive(unittest.TestCase):
    """Real-client MITM validation across curl, requests, httpx."""

    @classmethod
    def setUpClass(cls):
        # Background thread for asyncio servers
        cls.server_thread = AsyncServerThread()
        cls.server_thread.start()

        # Generate upstream self-signed cert
        cls.cert_dir = Path(tempfile.mkdtemp(prefix="qt_mitm_test_"))
        cls.upstream_key, cls.upstream_cert = _generate_upstream_cert(cls.cert_dir)

        # Ensure QuantTape CA exists
        cls.ca_key, cls.ca_cert = ensure_ca()
        cls.ca_cert_path = str(CA_CERT_FILE)

        # Log file
        cls.log_path = cls.cert_dir / "guard_test.log"

        # Start HTTP upstream
        cls.http_server, cls.http_port = cls.server_thread.run_coroutine(
            _start_http_upstream()
        )

        # Start HTTPS upstream
        cls.https_server, cls.https_port = cls.server_thread.run_coroutine(
            _start_upstream(cls.upstream_cert, cls.upstream_key)
        )

        # Start Guard proxy (no_verify for self-signed upstream)
        cls.config = GuardConfig(
            port=0,
            host="127.0.0.1",
            mode="agent",
            no_verify=True,
        )
        cls.proxy = GuardProxy(cls.config)
        cls.proxy.enforcer.log_path = cls.log_path

        async def start_proxy():
            server = await asyncio.start_server(
                cls.proxy.handle_client, "127.0.0.1", 0
            )
            port = server.sockets[0].getsockname()[1]
            return server, port

        cls.proxy_server, cls.proxy_port = cls.server_thread.run_coroutine(
            start_proxy()
        )

        cls.has_curl = shutil.which("curl") is not None

    @classmethod
    def tearDownClass(cls):
        async def cleanup():
            cls.proxy_server.close()
            await cls.proxy_server.wait_closed()
            cls.https_server.close()
            await cls.https_server.wait_closed()
            cls.http_server.close()
            await cls.http_server.wait_closed()

        try:
            cls.server_thread.run_coroutine(cleanup())
        except Exception:
            pass
        cls.server_thread.stop()

        try:
            shutil.rmtree(cls.cert_dir, ignore_errors=True)
        except Exception:
            pass

    # ── curl tests ────────────────────────────────────────────────

    def _curl(self, args, timeout=15):
        if not self.has_curl:
            self.skipTest("curl not found on PATH")
        cmd = ["curl", "-s", "-S", "--max-time", "10"]
        # On Windows, Schannel requires CRL/OCSP. Our local CA has no CRL.
        if sys.platform == "win32":
            cmd.append("--ssl-no-revoke")
        cmd.extend(args)
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr

    def test_curl_01_http_clean(self):
        """curl: HTTP clean request forwards."""
        url = f"http://127.0.0.1:{self.http_port}/test"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}", url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        passed = rc == 0 and b'"status":"ok"' in out
        record("curl", "HTTP clean forward", passed, elapsed)
        self.assertEqual(rc, 0, f"curl failed: {err.decode()}")
        self.assertIn(b'"status":"ok"', out)

    def test_curl_02_http_blocked(self):
        """curl: HTTP request with secret is blocked."""
        url = f"http://127.0.0.1:{self.http_port}/data"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}",
            "-X", "POST", "-H", "Content-Type: text/plain",
            "-d", AWS_SECRET, url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        body = json.loads(out.decode("utf-8")) if out else {}
        passed = body.get("allowed") is False
        record("curl", "HTTP blocked request", passed, elapsed)
        self.assertFalse(body.get("allowed"), f"Expected blocked: {out.decode()}")

    def test_curl_03_https_clean_trusted_ca(self):
        """curl: HTTPS clean request with trusted CA forwards."""
        url = f"https://127.0.0.1:{self.https_port}/secure"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}",
            "--cacert", self.ca_cert_path, url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        passed = rc == 0 and b'"status":"ok"' in out
        record("curl", "HTTPS clean forward (trusted CA)", passed, elapsed,
               f"rc={rc} err={err[:200].decode(errors='ignore')}")
        self.assertEqual(rc, 0, f"curl HTTPS failed: {err.decode(errors='ignore')}")
        self.assertIn(b'"status":"ok"', out)

    def test_curl_04_https_blocked(self):
        """curl: HTTPS request with secret is blocked via MITM."""
        url = f"https://127.0.0.1:{self.https_port}/data"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}",
            "--cacert", self.ca_cert_path,
            "-X", "POST", "-H", "Content-Type: text/plain",
            "-d", AWS_SECRET, url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        body = json.loads(out.decode("utf-8")) if out else {}
        passed = body.get("allowed") is False
        record("curl", "HTTPS blocked request (MITM)", passed, elapsed)
        self.assertFalse(body.get("allowed"))

    def test_curl_05_https_untrusted_ca_fails(self):
        """curl: HTTPS without trusted CA fails (proves MITM is active)."""
        url = f"https://127.0.0.1:{self.https_port}/secure"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}", url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        passed = rc != 0
        record("curl", "HTTPS untrusted CA failure", passed, elapsed, f"rc={rc}")
        self.assertNotEqual(rc, 0, "curl should reject untrusted MITM cert")

    def test_curl_06_secret_in_header_https(self):
        """curl: Secret in header via HTTPS MITM."""
        url = f"https://127.0.0.1:{self.https_port}/repos"
        t0 = time.perf_counter()
        rc, out, err = self._curl([
            "-x", f"http://127.0.0.1:{self.proxy_port}",
            "--cacert", self.ca_cert_path,
            "-H", f"Authorization: token {GH_TOKEN}", url,
        ])
        elapsed = (time.perf_counter() - t0) * 1000
        body = json.loads(out.decode("utf-8")) if out else {}
        passed = body.get("allowed") is False
        record("curl", "HTTPS secret in header (MITM)", passed, elapsed)
        self.assertFalse(body.get("allowed"))

    # ── requests tests ────────────────────────────────────────────

    def test_requests_01_http_clean(self):
        """requests: HTTP clean forward."""
        import requests
        t0 = time.perf_counter()
        resp = requests.get(
            f"http://127.0.0.1:{self.http_port}/test",
            proxies={"http": f"http://127.0.0.1:{self.proxy_port}"},
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200 and resp.json().get("status") == "ok"
        record("requests", "HTTP clean forward", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    def test_requests_02_http_blocked(self):
        """requests: HTTP blocked request."""
        import requests
        t0 = time.perf_counter()
        resp = requests.post(
            f"http://127.0.0.1:{self.http_port}/data",
            data=AWS_SECRET,
            headers={"Content-Type": "text/plain"},
            proxies={"http": f"http://127.0.0.1:{self.proxy_port}"},
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403 and resp.json().get("allowed") is False
        record("requests", "HTTP blocked request", passed, elapsed)
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(resp.json()["allowed"])

    def test_requests_03_https_clean_trusted_ca(self):
        """requests: HTTPS clean forward with trusted CA."""
        import requests
        t0 = time.perf_counter()
        resp = requests.get(
            f"https://127.0.0.1:{self.https_port}/secure",
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200 and resp.json().get("status") == "ok"
        record("requests", "HTTPS clean forward (trusted CA)", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    def test_requests_04_https_blocked(self):
        """requests: HTTPS request with secret blocked via MITM."""
        import requests
        t0 = time.perf_counter()
        resp = requests.post(
            f"https://127.0.0.1:{self.https_port}/data",
            data=AWS_SECRET,
            headers={"Content-Type": "text/plain"},
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403 and resp.json().get("allowed") is False
        record("requests", "HTTPS blocked request (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    def test_requests_05_https_untrusted_ca_fails(self):
        """requests: HTTPS without trusted CA raises SSLError."""
        import requests
        t0 = time.perf_counter()
        passed = False
        try:
            requests.get(
                f"https://127.0.0.1:{self.https_port}/secure",
                proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
                verify=True,
                timeout=10,
            )
        except requests.exceptions.SSLError:
            passed = True
        except Exception as e:
            passed = "SSL" in str(e) or "certificate" in str(e).lower()
        elapsed = (time.perf_counter() - t0) * 1000
        record("requests", "HTTPS untrusted CA failure", passed, elapsed)
        self.assertTrue(passed)

    def test_requests_06_secret_in_url(self):
        """requests: Secret in URL query string detected."""
        import requests
        t0 = time.perf_counter()
        resp = requests.get(
            f"http://127.0.0.1:{self.http_port}/data?aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            proxies={"http": f"http://127.0.0.1:{self.proxy_port}"},
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403
        record("requests", "Secret in URL", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    def test_requests_07_secret_in_header_https(self):
        """requests: Secret in header via HTTPS MITM."""
        import requests
        t0 = time.perf_counter()
        resp = requests.get(
            f"https://127.0.0.1:{self.https_port}/repos",
            headers={"Authorization": f"token {GH_TOKEN}"},
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403
        record("requests", "HTTPS secret in header (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    def test_requests_08_binary_https_passthrough(self):
        """requests: Binary content via HTTPS passes without false positive."""
        import requests
        binary_body = bytes(range(256)) * 4
        t0 = time.perf_counter()
        resp = requests.post(
            f"https://127.0.0.1:{self.https_port}/upload",
            data=binary_body,
            headers={"Content-Type": "image/png"},
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200
        record("requests", "HTTPS binary passthrough (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    def test_requests_09_gzip_https_body(self):
        """requests: Gzip-compressed body with secret detected via MITM."""
        import requests
        compressed = gzip.compress(AWS_SECRET.encode("utf-8"))
        t0 = time.perf_counter()
        resp = requests.post(
            f"https://127.0.0.1:{self.https_port}/data",
            data=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403
        record("requests", "HTTPS gzip body scanned (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    # ── httpx tests ───────────────────────────────────────────────

    def test_httpx_01_http_clean(self):
        """httpx: HTTP clean forward."""
        import httpx
        t0 = time.perf_counter()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{self.proxy_port}", timeout=10
        ) as client:
            resp = client.get(f"http://127.0.0.1:{self.http_port}/test")
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200
        record("httpx", "HTTP clean forward", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    def test_httpx_02_http_blocked(self):
        """httpx: HTTP blocked request."""
        import httpx
        t0 = time.perf_counter()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{self.proxy_port}", timeout=10
        ) as client:
            resp = client.post(
                f"http://127.0.0.1:{self.http_port}/data",
                content=AWS_SECRET,
                headers={"Content-Type": "text/plain"},
            )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403
        record("httpx", "HTTP blocked request", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    def test_httpx_03_https_clean_trusted_ca(self):
        """httpx: HTTPS clean forward with trusted CA."""
        import httpx
        t0 = time.perf_counter()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{self.proxy_port}",
            verify=self.ca_cert_path,
            timeout=10,
        ) as client:
            resp = client.get(f"https://127.0.0.1:{self.https_port}/secure")
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200
        record("httpx", "HTTPS clean forward (trusted CA)", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    def test_httpx_04_https_blocked(self):
        """httpx: HTTPS request with secret blocked via MITM."""
        import httpx
        t0 = time.perf_counter()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{self.proxy_port}",
            verify=self.ca_cert_path,
            timeout=10,
        ) as client:
            resp = client.post(
                f"https://127.0.0.1:{self.https_port}/data",
                content=AWS_SECRET,
                headers={"Content-Type": "text/plain"},
            )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 403
        record("httpx", "HTTPS blocked request (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 403)

    def test_httpx_05_https_untrusted_ca_fails(self):
        """httpx: HTTPS without trusted CA fails."""
        import httpx
        t0 = time.perf_counter()
        passed = False
        try:
            with httpx.Client(
                proxy=f"http://127.0.0.1:{self.proxy_port}",
                verify=True, timeout=10,
            ) as client:
                client.get(f"https://127.0.0.1:{self.https_port}/secure")
        except httpx.ConnectError:
            passed = True
        except Exception as e:
            passed = "SSL" in str(e) or "certificate" in str(e).lower()
        elapsed = (time.perf_counter() - t0) * 1000
        record("httpx", "HTTPS untrusted CA failure", passed, elapsed)
        self.assertTrue(passed)

    def test_httpx_06_large_https_body(self):
        """httpx: Large clean body via HTTPS forwards without hanging."""
        import httpx
        large_body = '{"data":"' + "a" * 500_000 + '"}'
        t0 = time.perf_counter()
        with httpx.Client(
            proxy=f"http://127.0.0.1:{self.proxy_port}",
            verify=self.ca_cert_path, timeout=30,
        ) as client:
            resp = client.post(
                f"https://127.0.0.1:{self.https_port}/bulk",
                content=large_body,
                headers={"Content-Type": "application/json"},
            )
        elapsed = (time.perf_counter() - t0) * 1000
        passed = resp.status_code == 200
        record("httpx", "HTTPS large body forward (MITM)", passed, elapsed)
        self.assertEqual(resp.status_code, 200)

    # ── Cross-client verification ─────────────────────────────────

    def test_verify_01_blocked_response_format(self):
        """Verify blocked response has correct headers and JSON body."""
        import requests
        resp = requests.post(
            f"https://127.0.0.1:{self.https_port}/data",
            data=AWS_SECRET,
            headers={"Content-Type": "text/plain"},
            proxies={"https": f"http://127.0.0.1:{self.proxy_port}"},
            verify=self.ca_cert_path,
            timeout=10,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.headers.get("X-QuantTape-Action"), "blocked")
        body = resp.json()
        self.assertFalse(body["allowed"])
        self.assertIn("findings", body)
        self.assertGreater(len(body["findings"]), 0)
        self.assertIn("scan_time_ms", body)
        record("requests", "Blocked response format verification", True, 0)

    def test_verify_02_audit_log(self):
        """Verify audit log has entries after blocked requests."""
        # Allow a small delay for log writes
        time.sleep(0.5)
        if not self.log_path.exists():
            record("system", "Audit log written", False, 0, "log file missing")
            self.fail("Audit log not found")
        content = self.log_path.read_text().strip()
        entries = [json.loads(line) for line in content.splitlines()]
        blocked = [e for e in entries if not e.get("allowed")]
        passed = len(blocked) > 0
        record("system", "Audit log written", passed, 0, f"{len(blocked)} blocked entries")
        self.assertGreater(len(blocked), 0)

    def test_verify_03_enforcer_stats(self):
        """Verify enforcer stats reflect all requests processed."""
        stats = self.proxy.enforcer.stats
        passed = (
            stats["requests_scanned"] > 0
            and stats["requests_blocked"] > 0
            and stats["total_scan_time_ms"] > 0
        )
        record("system", "Enforcer stats accurate", passed, 0,
               f"scanned={stats['requests_scanned']}, blocked={stats['requests_blocked']}, "
               f"avg={self.proxy.enforcer.avg_scan_time_ms:.3f}ms")
        self.assertGreater(stats["requests_scanned"], 0)
        self.assertGreater(stats["requests_blocked"], 0)


# ── Results matrix printer ───────────────────────────────────────────

def print_matrix():
    if not RESULTS:
        return

    print("\n" + "=" * 80)
    print("  QUANTTAPE GUARD — REAL-CLIENT MITM VALIDATION MATRIX")
    print("=" * 80)

    clients = {}
    for r in RESULTS:
        clients.setdefault(r["client"], []).append(r)

    total_pass = sum(1 for r in RESULTS if r["result"] == "PASS")
    total_fail = sum(1 for r in RESULTS if r["result"] == "FAIL")

    for client, tests in clients.items():
        print(f"\n  [{client}]")
        for t in tests:
            icon = "PASS" if t["result"] == "PASS" else "FAIL"
            latency = f"{t['latency_ms']:.1f}ms" if t["latency_ms"] > 0 else "-"
            notes = f"  ({t['notes']})" if t["notes"] else ""
            print(f"    {icon}  {t['scenario']:<45} {latency:>10}{notes}")

    print(f"\n  TOTAL: {total_pass} passed, {total_fail} failed out of {len(RESULTS)}")

    latencies = [r["latency_ms"] for r in RESULTS if r["latency_ms"] > 0]
    if latencies:
        latencies.sort()
        median = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        print(f"  LATENCY: median={median:.1f}ms, p95={p95:.1f}ms, "
              f"min={min(latencies):.1f}ms, max={max(latencies):.1f}ms")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestMITMLive)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print_matrix()
    sys.exit(0 if result.wasSuccessful() else 1)
