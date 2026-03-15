"""Bridge: feeds raw HTTP request data through the QuantTape rules engine.

No AST parsing (HTTP payloads aren't Python code). Reuses the same regex
rules and entropy detection from the scanner module.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..rules import Rule, get_rules_for_mode
from ..scanner import Finding, _mask_secret, _shannon_entropy, _ENTROPY_PATTERN

# Maximum body size to scan (1 MB). Larger payloads are truncated.
MAX_BODY_SCAN_BYTES = 1_048_576


@dataclass
class ScanResult:
    findings: List[Finding]
    scan_time_ms: float
    body_scanned_bytes: int
    body_truncated: bool


def scan_request(
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    rules: Optional[List[Rule]] = None,
    mode: str = "agent",
) -> List[Finding]:
    """Scan an outbound HTTP request for secrets.

    Args:
        url: The target URL.
        headers: Request headers as key-value pairs.
        body: Request body as a string (or None).
        rules: Custom rule list. If None, loads rules for the given mode.
        mode: Guard mode - "agent", "trading", or "all".

    Returns:
        List of Finding objects for any detected secrets.
    """
    return scan_request_detailed(url, headers, body, rules, mode).findings


def scan_request_detailed(
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    rules: Optional[List[Rule]] = None,
    mode: str = "agent",
) -> ScanResult:
    """Scan with detailed timing and metadata.

    Returns a ScanResult with findings, scan_time_ms, and body metadata.
    """
    t0 = time.perf_counter()

    if rules is None:
        rules = get_rules_for_mode(mode)

    compiled = [(rule, rule.compile()) for rule in rules]
    findings: List[Finding] = []

    # Scan URL
    findings.extend(_scan_text("url", url, compiled))

    # Scan each header value
    for name, value in headers.items():
        findings.extend(_scan_text(f"header:{name}", value, compiled))

    # Scan body with size limit
    body_scanned = 0
    body_truncated = False
    if body:
        body_bytes_len = len(body.encode("utf-8", errors="ignore"))
        if body_bytes_len > MAX_BODY_SCAN_BYTES:
            body = body[:MAX_BODY_SCAN_BYTES]
            body_truncated = True
        body_scanned = len(body.encode("utf-8", errors="ignore"))
        for line_num, line in enumerate(body.splitlines(), start=1):
            findings.extend(_scan_text(f"body:L{line_num}", line, compiled))

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return ScanResult(
        findings=findings,
        scan_time_ms=round(elapsed_ms, 3),
        body_scanned_bytes=body_scanned,
        body_truncated=body_truncated,
    )


def _scan_text(source: str, text: str, compiled_rules: list) -> List[Finding]:
    """Run all compiled rules + entropy check against a single text string."""
    findings: List[Finding] = []

    for rule, pattern in compiled_rules:
        match = pattern.search(text)
        if not match:
            continue
        matched_text = match.group(1) if match.lastindex else match.group(0)
        findings.append(
            Finding(
                file=source,
                line=0,
                secret_type=rule.name,
                severity=rule.severity,
                match_preview=_mask_secret(matched_text),
            )
        )

    # Entropy check
    for match in _ENTROPY_PATTERN.finditer(text):
        value = match.group(1)
        if len(value) >= 20:
            entropy = _shannon_entropy(value)
            if entropy >= 4.5:
                findings.append(
                    Finding(
                        file=source,
                        line=0,
                        secret_type="High Entropy String",
                        severity="MEDIUM",
                        match_preview=_mask_secret(value),
                    )
                )

    return findings
