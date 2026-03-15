"""Guard Proxy Server: local HTTP/HTTPS proxy that intercepts outbound requests.

Uses raw asyncio to handle both:
  - HTTP forward proxy: full request inspection (URL, headers, body)
  - HTTPS CONNECT tunnel: inspects the decrypted stream via MITM with a
    local CA cert (auto-generated on first run at ~/.quanttape/ca.pem)

Runs on localhost, scans all outbound traffic through the QuantTape rules
engine, blocks requests containing secrets, forwards clean ones.
"""

import asyncio
import gzip
import json
import logging
import ssl
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .certs import ensure_ca, make_host_cert, CA_CERT_FILE

logger = logging.getLogger("quanttape.guard")

# Body limits
MAX_BODY_READ = 2_097_152  # 2 MB max body read from network
MAX_BODY_LOG = 256  # chars of body to include in debug logs


@dataclass
class GuardConfig:
    port: int = 8080
    host: str = "127.0.0.1"
    mode: str = "agent"
    config_path: Optional[str] = None
    no_verify: bool = False  # skip upstream TLS verification (testing only)


# ── Helpers ─────────────────────────────────────────────────────────

def _is_text_content(headers: dict) -> bool:
    """Check if Content-Type suggests text-based content we should scan."""
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if not ct:
        return True  # assume text if no content-type
    text_types = ("text/", "application/json", "application/xml",
                  "application/x-www-form-urlencoded", "application/graphql",
                  "application/javascript", "application/yaml")
    return any(t in ct for t in text_types)


def _decode_body(body_bytes: bytes, headers: dict) -> Optional[str]:
    """Decode body bytes, handling gzip/deflate Content-Encoding."""
    if not body_bytes:
        return None

    # Check Content-Encoding for compression
    encoding = ""
    for k, v in headers.items():
        if k.lower() == "content-encoding":
            encoding = v.lower().strip()
            break

    try:
        if encoding == "gzip":
            body_bytes = gzip.decompress(body_bytes)
        elif encoding == "deflate":
            body_bytes = zlib.decompress(body_bytes, -zlib.MAX_WBITS)
    except (gzip.BadGzipFile, zlib.error, OSError):
        pass  # if decompression fails, scan raw bytes as text

    return body_bytes.decode("utf-8", errors="ignore")


async def _read_body(reader, content_length: int, headers: dict) -> tuple:
    """Read body with size limits and chunked transfer support.

    Returns (body_bytes, body_text_or_None).
    """
    # Check for chunked transfer encoding
    te = ""
    for k, v in headers.items():
        if k.lower() == "transfer-encoding":
            te = v.lower().strip()
            break

    if te == "chunked":
        body_bytes = await _read_chunked(reader)
    elif content_length > 0:
        read_size = min(content_length, MAX_BODY_READ)
        body_bytes = await reader.readexactly(read_size)
        # Drain remaining if we capped
        if content_length > MAX_BODY_READ:
            remaining = content_length - MAX_BODY_READ
            while remaining > 0:
                chunk = await reader.read(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
    else:
        return b"", None

    if not _is_text_content(headers):
        return body_bytes, None  # binary content -- skip scanning

    body_text = _decode_body(body_bytes, headers)
    return body_bytes, body_text


async def _read_chunked(reader) -> bytes:
    """Read HTTP chunked transfer encoding."""
    body = bytearray()
    total = 0
    while True:
        size_line = await reader.readline()
        if not size_line:
            break
        try:
            chunk_size = int(size_line.strip(), 16)
        except ValueError:
            break
        if chunk_size == 0:
            await reader.readline()  # trailing CRLF
            break
        if total + chunk_size > MAX_BODY_READ:
            # Read up to limit, drain rest
            remaining_allowed = MAX_BODY_READ - total
            if remaining_allowed > 0:
                body.extend(await reader.readexactly(remaining_allowed))
            # Drain remainder of this chunk
            to_drain = chunk_size - remaining_allowed
            while to_drain > 0:
                d = await reader.read(min(to_drain, 8192))
                if not d:
                    break
                to_drain -= len(d)
            await reader.readline()  # trailing CRLF
            total = MAX_BODY_READ
            # Drain remaining chunks
            while True:
                sl = await reader.readline()
                if not sl:
                    break
                try:
                    cs = int(sl.strip(), 16)
                except ValueError:
                    break
                if cs == 0:
                    await reader.readline()
                    break
                while cs > 0:
                    d = await reader.read(min(cs, 8192))
                    if not d:
                        break
                    cs -= len(d)
                await reader.readline()
            break
        chunk_data = await reader.readexactly(chunk_size)
        body.extend(chunk_data)
        total += chunk_size
        await reader.readline()  # trailing CRLF after each chunk
    return bytes(body)


# ── Proxy handler ────────────────────────────────────────────────────

class GuardProxy:
    def __init__(self, config: GuardConfig):
        self.config = config
        self.ca_key_path: Optional[str] = None
        self.ca_cert_path: Optional[str] = None
        self._has_crypto = False

        from .bridge import scan_request_detailed
        from .enforcer import Enforcer

        self.scan_request_detailed = scan_request_detailed
        self.enforcer = Enforcer()

        # Try to set up CA for HTTPS - graceful fallback if cryptography missing
        try:
            self.ca_key_path, self.ca_cert_path = ensure_ca()
            self._has_crypto = True
        except ImportError:
            logger.warning("cryptography not installed - HTTPS inspection disabled, tunnel-only mode")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not request_line:
                writer.close()
                return

            request_str = request_line.decode("utf-8", errors="ignore").strip()
            parts = request_str.split()
            if len(parts) < 3:
                writer.close()
                return

            method, target, _version = parts[0], parts[1], parts[2]

            if method.upper() == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_http(reader, writer, method, target)
        except asyncio.TimeoutError:
            logger.debug("Client connection timed out waiting for request line")
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logger.debug("Connection error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_http(self, reader, writer, method, url):
        """Handle plain HTTP forward proxy request - full inspection."""
        # Read headers
        headers = {}
        content_length = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore").strip()
            if ":" in decoded:
                key, val = decoded.split(":", 1)
                key, val = key.strip(), val.strip()
                headers[key] = val
                if key.lower() == "content-length":
                    content_length = int(val)

        # Read body with edge case handling
        body_bytes, body = await _read_body(reader, content_length, headers)

        # Scan
        result = self.scan_request_detailed(
            url=url,
            headers=headers,
            body=body,
            mode=self.config.mode,
        )

        decision = self.enforcer.decide(result.findings, url, result.scan_time_ms)

        if not decision.allowed:
            await self._send_blocked(writer, decision)
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            for f in result.findings:
                logger.info("[%s] BLOCK  %s  %s: %s (%.1fms)", ts, url, f.secret_type, f.match_preview, result.scan_time_ms)
            return

        # Forward clean request
        try:
            import httpx
            skip_headers = {"host", "transfer-encoding", "connection", "proxy-connection", "proxy-authorization"}
            clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=clean_headers,
                    content=body_bytes if body_bytes else None,
                )

            # Build raw response
            status_line = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase or 'OK'}\r\n".encode()
            resp_headers = b""
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "connection"):
                    resp_headers += f"{k}: {v}\r\n".encode()
            resp_headers += f"Content-Length: {len(resp.content)}\r\n".encode()
            resp_headers += b"Connection: close\r\n"

            writer.write(status_line + resp_headers + b"\r\n" + resp.content)
            await writer.drain()
        except Exception as e:
            await self._send_502(writer, f"upstream error - {e}")

    async def _handle_connect(self, reader, writer, target):
        """Handle HTTPS CONNECT tunnel with MITM inspection."""
        # Parse host:port
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = target, 443

        # Consume remaining headers from the CONNECT request
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        if not self._has_crypto:
            # No cryptography package - transparent tunnel (no inspection)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            self.enforcer.stats["requests_scanned"] += 1
            await self._blind_tunnel(reader, writer, host, port)
            return

        # MITM: tell client tunnel is established
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # Generate host cert signed by local CA
        try:
            host_key_path, host_cert_path = make_host_cert(host, self.ca_key_path, self.ca_cert_path)
        except Exception as e:
            logger.warning("Failed to generate cert for %s: %s - falling back to tunnel", host, e)
            await self._blind_tunnel(reader, writer, host, port)
            return

        # TLS handshake with client (pretend to be the target server)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(host_cert_path, host_key_path)

        # Upgrade the existing client connection to TLS using start_tls.
        # Reuse the existing protocol/reader -- start_tls reconnects them
        # to the new TLS transport automatically. This approach works
        # correctly on both Windows (ProactorEventLoop) and Unix.
        loop = asyncio.get_event_loop()
        try:
            old_protocol = writer.transport.get_protocol()
            new_transport = await loop.start_tls(
                writer.transport,
                old_protocol,
                server_ctx,
                server_side=True,
            )
            # The old reader is now wired to the TLS transport via old_protocol.
            # Just create a new writer pointing to the TLS transport.
            client_ssl_reader = reader
            client_ssl_writer = asyncio.StreamWriter(
                new_transport, old_protocol, reader, loop
            )
        except (ssl.SSLError, OSError, ConnectionResetError) as e:
            logger.debug("TLS handshake failed for %s: %s", host, e)
            return

        # Connect to actual upstream with TLS
        try:
            upstream_ssl = True
            if self.config.no_verify:
                upstream_ssl = ssl.create_default_context()
                upstream_ssl.check_hostname = False
                upstream_ssl.verify_mode = ssl.CERT_NONE
            upstream_reader, upstream_writer = await asyncio.open_connection(
                host, port, ssl=upstream_ssl
            )
        except Exception as e:
            error_msg = f"QuantTape Guard: cannot reach {host}:{port} - {e}"
            try:
                response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(error_msg)}\r\nConnection: close\r\n\r\n{error_msg}"
                client_ssl_writer.write(response.encode())
                await client_ssl_writer.drain()
            except Exception:
                pass
            return

        # Now intercept: read client request, scan, forward or block
        try:
            await self._mitm_relay(client_ssl_reader, client_ssl_writer, upstream_reader, upstream_writer, host)
        except Exception as e:
            logger.debug("MITM relay error for %s: %s", host, e)
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass
            try:
                client_ssl_writer.close()
                await client_ssl_writer.wait_closed()
            except Exception:
                pass

    async def _mitm_relay(self, client_reader, client_writer, upstream_reader, upstream_writer, host):
        """Read HTTP request from decrypted client stream, scan, then forward."""
        # Read the request line
        request_line = await asyncio.wait_for(client_reader.readline(), timeout=30.0)
        if not request_line:
            return

        request_str = request_line.decode("utf-8", errors="ignore").strip()
        parts = request_str.split(None, 2)
        if len(parts) < 2:
            return

        method = parts[0]
        path = parts[1]
        url = f"https://{host}{path}"

        # Read headers
        headers = {}
        raw_headers = request_line
        content_length = 0
        while True:
            line = await client_reader.readline()
            raw_headers += line
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore").strip()
            if ":" in decoded:
                key, val = decoded.split(":", 1)
                key, val = key.strip(), val.strip()
                headers[key] = val
                if key.lower() == "content-length":
                    content_length = int(val)

        # Read body with edge case handling
        body_bytes_raw, body = await _read_body(client_reader, content_length, headers)

        # Scan
        result = self.scan_request_detailed(
            url=url,
            headers=headers,
            body=body,
            mode=self.config.mode,
        )

        decision = self.enforcer.decide(result.findings, url, result.scan_time_ms)

        if not decision.allowed:
            await self._send_blocked(client_writer, decision)
            return

        # Forward to upstream: raw_headers + original body bytes
        upstream_writer.write(raw_headers + body_bytes_raw)
        await upstream_writer.drain()

        # Relay response back
        await self._pipe(upstream_reader, client_writer)

    async def _blind_tunnel(self, reader, writer, host, port):
        """Transparent TCP tunnel - no inspection (fallback when crypto unavailable)."""
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.debug("Cannot connect to %s:%d: %s", host, port, e)
            return

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(8192)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(reader, upstream_writer),
            pipe(upstream_reader, writer),
        )

    async def _pipe(self, src, dst):
        """Pipe data from src reader to dst writer until EOF."""
        try:
            while True:
                data = await src.read(8192)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass

    # ── Response helpers ────────────────────────────────────────────

    async def _send_blocked(self, writer, decision) -> None:
        """Send a deterministic 403 Forbidden response."""
        blocked_body = json.dumps({
            "error": "QuantTape Guard: request blocked",
            **decision.to_dict(),
        }, separators=(",", ":")).encode("utf-8")
        response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: application/json\r\n"
            b"Connection: close\r\n"
            b"X-QuantTape-Action: blocked\r\n"
            b"Content-Length: " + str(len(blocked_body)).encode() + b"\r\n"
            b"\r\n" + blocked_body
        )
        try:
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def _send_502(self, writer, detail: str) -> None:
        """Send a deterministic 502 Bad Gateway response."""
        error_body = json.dumps(
            {"error": f"QuantTape Guard: {detail}"},
            separators=(",", ":"),
        ).encode("utf-8")
        response = (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: application/json\r\n"
            b"Connection: close\r\n"
            b"X-QuantTape-Action: error\r\n"
            b"Content-Length: " + str(len(error_body)).encode() + b"\r\n"
            b"\r\n" + error_body
        )
        try:
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass


# ── Entry point ──────────────────────────────────────────────────────

def run_guard(config: Optional[GuardConfig] = None):
    """Start the guard proxy server."""
    try:
        import httpx  # noqa: F401
    except ImportError:
        raise ImportError(
            "Guard proxy requires extra dependencies.\n"
            "Install with: pip install quanttape[guard]"
        )

    if config is None:
        config = GuardConfig()

    proxy = GuardProxy(config)

    print(f"\n  QuantTape Guard v0.0.20")
    print(f"  Listening on http://{config.host}:{config.port}")
    print(f"  Mode: {config.mode}")
    print(f"  HTTP + HTTPS interception {'(full MITM)' if proxy._has_crypto else '(HTTPS: tunnel-only, install cryptography for full inspection)'}")
    print(f"\n  Configure your AI agent:")
    print(f"    export HTTP_PROXY=http://{config.host}:{config.port}")
    print(f"    export HTTPS_PROXY=http://{config.host}:{config.port}")
    if proxy._has_crypto:
        print(f"\n  Trust the CA cert for HTTPS inspection:")
        print(f"    {CA_CERT_FILE}")
        print(f"    export REQUESTS_CA_BUNDLE={CA_CERT_FILE}")
        print(f"    export SSL_CERT_FILE={CA_CERT_FILE}")
    print()

    async def _serve():
        server = await asyncio.start_server(
            proxy.handle_client, config.host, config.port
        )
        logger.info("Guard listening on %s:%d", config.host, config.port)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("\n  Guard stopped.")
