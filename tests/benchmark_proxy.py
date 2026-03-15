"""QuantTape Guard -- Proxy Benchmark Harness.

Measures latency overhead across dimensions:
  - Protocol: HTTP vs HTTPS (MITM)
  - Outcome: clean (forwarded) vs blocked
  - Body size: empty, small (1KB), medium (100KB), large (500KB)

Reports: median, p95, p99, min, max for each combination.
Also measures scan-only overhead (bridge.scan_request_detailed) isolated from I/O.

Usage:
    python tests/benchmark_proxy.py
"""

import asyncio
import ipaddress
import json
import ssl
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quanttape.proxy.server import GuardProxy, GuardConfig
from quanttape.proxy.certs import ensure_ca, CA_CERT_FILE
from quanttape.proxy.bridge import scan_request_detailed


# ── Infrastructure ───────────────────────────────────────────────────

class AsyncServerThread:
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
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=30)

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread:
            self._thread.join(timeout=5)


def generate_upstream_cert(cert_dir):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt

    key = rsa.generate_private_key(65537, 2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
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


async def start_upstream(cert_path=None, key_path=None):
    async def handle(reader, writer):
        cl = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            d = line.decode("utf-8", errors="ignore").lower()
            if d.startswith("content-length:"):
                cl = int(d.split(":", 1)[1].strip())
        if cl > 0:
            rem = cl
            while rem > 0:
                c = await reader.read(min(rem, 8192))
                if not c:
                    break
                rem -= len(c)
        body = b'{"status":"ok"}'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    kwargs = {}
    if cert_path:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        kwargs["ssl"] = ctx
    server = await asyncio.start_server(handle, "127.0.0.1", 0, **kwargs)
    port = server.sockets[0].getsockname()[1]
    return server, port


# ── Benchmark runner ─────────────────────────────────────────────────

AWS_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'

BODY_SIZES = {
    "empty": "",
    "1KB": '{"data":"' + "a" * 1000 + '"}',
    "100KB": '{"data":"' + "a" * 100_000 + '"}',
    "500KB": '{"data":"' + "a" * 500_000 + '"}',
}

ITERATIONS = 20  # per scenario


def percentile(data, pct):
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


def run_benchmark():
    import httpx
    import shutil

    cert_dir = Path(tempfile.mkdtemp(prefix="qt_bench_"))
    upstream_key, upstream_cert = generate_upstream_cert(cert_dir)
    ca_key, ca_cert = ensure_ca()
    ca_cert_path = str(CA_CERT_FILE)

    server_thread = AsyncServerThread()
    server_thread.start()

    # Start servers
    http_server, http_port = server_thread.run_coroutine(start_upstream())
    https_server, https_port = server_thread.run_coroutine(
        start_upstream(upstream_cert, upstream_key)
    )

    config = GuardConfig(port=0, host="127.0.0.1", mode="agent", no_verify=True)
    proxy = GuardProxy(config)
    log_path = cert_dir / "bench.log"
    proxy.enforcer.log_path = log_path

    async def start_proxy():
        server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    proxy_server, proxy_port = server_thread.run_coroutine(start_proxy())

    results = []

    def measure(label, protocol, outcome, body_size_name, body_content, is_dirty):
        latencies = []
        for i in range(ITERATIONS):
            if protocol == "HTTP":
                url = f"http://127.0.0.1:{http_port}/test"
                proxy_url = f"http://127.0.0.1:{proxy_port}"
                verify = False
            else:
                url = f"https://127.0.0.1:{https_port}/test"
                proxy_url = f"http://127.0.0.1:{proxy_port}"
                verify = ca_cert_path

            t0 = time.perf_counter()
            try:
                with httpx.Client(proxy=proxy_url, verify=verify, timeout=15) as client:
                    if is_dirty:
                        resp = client.post(url, content=body_content,
                                           headers={"Content-Type": "text/plain"})
                    elif body_content:
                        resp = client.post(url, content=body_content,
                                           headers={"Content-Type": "application/json"})
                    else:
                        resp = client.get(url)
                elapsed = (time.perf_counter() - t0) * 1000
                latencies.append(elapsed)
            except Exception as e:
                elapsed = (time.perf_counter() - t0) * 1000
                latencies.append(elapsed)

        med = statistics.median(latencies)
        p95 = percentile(latencies, 95)
        p99 = percentile(latencies, 99)
        results.append({
            "scenario": label,
            "protocol": protocol,
            "outcome": outcome,
            "body_size": body_size_name,
            "iterations": ITERATIONS,
            "median_ms": round(med, 2),
            "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2),
            "min_ms": round(min(latencies), 2),
            "max_ms": round(max(latencies), 2),
        })

    # ── Warmup ────────────────────────────────────────────────────
    print("  Warming up...")
    for _ in range(3):
        with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}", timeout=10) as c:
            c.get(f"http://127.0.0.1:{http_port}/warmup")
        with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}",
                          verify=ca_cert_path, timeout=10) as c:
            c.get(f"https://127.0.0.1:{https_port}/warmup")

    # ── HTTP benchmarks ───────────────────────────────────────────
    print("  Benchmarking HTTP...")
    measure("HTTP clean (empty)", "HTTP", "clean", "empty", "", False)
    measure("HTTP clean (1KB)", "HTTP", "clean", "1KB", BODY_SIZES["1KB"], False)
    measure("HTTP clean (100KB)", "HTTP", "clean", "100KB", BODY_SIZES["100KB"], False)
    measure("HTTP clean (500KB)", "HTTP", "clean", "500KB", BODY_SIZES["500KB"], False)
    measure("HTTP blocked (1KB)", "HTTP", "blocked", "1KB", AWS_SECRET, True)

    # ── HTTPS benchmarks ──────────────────────────────────────────
    print("  Benchmarking HTTPS (MITM)...")
    measure("HTTPS clean (empty)", "HTTPS", "clean", "empty", "", False)
    measure("HTTPS clean (1KB)", "HTTPS", "clean", "1KB", BODY_SIZES["1KB"], False)
    measure("HTTPS clean (100KB)", "HTTPS", "clean", "100KB", BODY_SIZES["100KB"], False)
    measure("HTTPS clean (500KB)", "HTTPS", "clean", "500KB", BODY_SIZES["500KB"], False)
    measure("HTTPS blocked (1KB)", "HTTPS", "blocked", "1KB", AWS_SECRET, True)

    # ── Scan-only benchmark (no I/O) ─────────────────────────────
    print("  Benchmarking scan-only (no I/O)...")
    scan_latencies = {"empty": [], "1KB": [], "100KB": [], "500KB": [], "dirty": []}
    for _ in range(100):
        for size_name, body in BODY_SIZES.items():
            t0 = time.perf_counter()
            scan_request_detailed(
                url="https://api.example.com/test",
                headers={"Accept": "application/json"},
                body=body if body else None,
                mode="agent",
            )
            scan_latencies[size_name].append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        scan_request_detailed(
            url="https://api.example.com/test",
            headers={"Accept": "application/json"},
            body=AWS_SECRET,
            mode="agent",
        )
        scan_latencies["dirty"].append((time.perf_counter() - t0) * 1000)

    # ── Baseline (direct, no proxy) ──────────────────────────────
    print("  Benchmarking baseline (no proxy)...")
    baseline_latencies = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        with httpx.Client(timeout=10) as c:
            c.get(f"http://127.0.0.1:{http_port}/baseline")
        baseline_latencies.append((time.perf_counter() - t0) * 1000)

    # ── Cleanup ───────────────────────────────────────────────────
    async def cleanup():
        proxy_server.close()
        await proxy_server.wait_closed()
        https_server.close()
        await https_server.wait_closed()
        http_server.close()
        await http_server.wait_closed()

    server_thread.run_coroutine(cleanup())
    server_thread.stop()
    shutil.rmtree(cert_dir, ignore_errors=True)

    # ── Report ────────────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("  QUANTTAPE GUARD -- BENCHMARK REPORT")
    print("=" * 90)

    print(f"\n  Baseline (direct HTTP, no proxy): "
          f"median={statistics.median(baseline_latencies):.1f}ms, "
          f"p95={percentile(baseline_latencies, 95):.1f}ms")

    print(f"\n  {'Scenario':<30} {'Median':>8} {'P95':>8} {'P99':>8} {'Min':>8} {'Max':>8}")
    print("  " + "-" * 78)
    for r in results:
        print(f"  {r['scenario']:<30} {r['median_ms']:>7.1f}ms {r['p95_ms']:>7.1f}ms "
              f"{r['p99_ms']:>7.1f}ms {r['min_ms']:>7.1f}ms {r['max_ms']:>7.1f}ms")

    print(f"\n  Scan-only overhead (no I/O, 100 iterations each):")
    print(f"  {'Body size':<20} {'Median':>8} {'P95':>8} {'P99':>8}")
    print("  " + "-" * 48)
    for name, latencies in scan_latencies.items():
        label = f"dirty ({name})" if name == "dirty" else name
        med = statistics.median(latencies)
        p95v = percentile(latencies, 95)
        p99v = percentile(latencies, 99)
        print(f"  {label:<20} {med:>7.3f}ms {p95v:>7.3f}ms {p99v:>7.3f}ms")

    # Proxy overhead calculation
    http_clean_empty = next(r for r in results if r["scenario"] == "HTTP clean (empty)")
    https_clean_empty = next(r for r in results if r["scenario"] == "HTTPS clean (empty)")
    baseline_med = statistics.median(baseline_latencies)
    http_overhead = http_clean_empty["median_ms"] - baseline_med
    https_overhead = https_clean_empty["median_ms"] - baseline_med

    print(f"\n  Proxy overhead (median, vs baseline):")
    print(f"    HTTP:  {http_overhead:>+.1f}ms")
    print(f"    HTTPS: {https_overhead:>+.1f}ms (includes TLS handshake + cert gen)")

    enforcer_stats = proxy.enforcer.stats
    print(f"\n  Enforcer totals:")
    print(f"    Requests scanned: {enforcer_stats['requests_scanned']}")
    print(f"    Requests blocked: {enforcer_stats['requests_blocked']}")
    print(f"    Avg scan time: {proxy.enforcer.avg_scan_time_ms:.3f}ms")

    print("\n" + "=" * 90)

    return results, scan_latencies, baseline_latencies


if __name__ == "__main__":
    run_benchmark()
