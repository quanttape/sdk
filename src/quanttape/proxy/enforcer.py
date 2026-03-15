"""Enforcer: decides whether to block or allow a request based on findings.

Logs blocked attempts to ~/.quanttape/guard.log.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..scanner import Finding

logger = logging.getLogger("quanttape.guard")

LOG_DIR = Path.home() / ".quanttape"
LOG_FILE = LOG_DIR / "guard.log"


@dataclass
class Decision:
    allowed: bool
    findings: List[Finding] = field(default_factory=list)
    reason: str = ""
    scan_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "allowed": self.allowed,
            "reason": self.reason,
            "findings": [
                {
                    "rule": f.secret_type,
                    "severity": f.severity,
                    "source": f.file,
                    "preview": f.match_preview,
                }
                for f in self.findings
            ],
        }
        if self.scan_time_ms > 0:
            d["scan_time_ms"] = self.scan_time_ms
        return d


class Enforcer:
    """Evaluate findings and decide block/allow."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or LOG_FILE
        self._ensure_log_dir()
        self.stats: Dict[str, Any] = {
            "requests_scanned": 0,
            "requests_blocked": 0,
            "rules_triggered": 0,
            "total_scan_time_ms": 0.0,
        }

    def decide(
        self,
        findings: List[Finding],
        target_url: str = "",
        scan_time_ms: float = 0.0,
    ) -> Decision:
        self.stats["requests_scanned"] += 1
        self.stats["total_scan_time_ms"] += scan_time_ms

        if not findings:
            return Decision(allowed=True, reason="clean", scan_time_ms=scan_time_ms)

        self.stats["requests_blocked"] += 1
        self.stats["rules_triggered"] += len(findings)

        decision = Decision(
            allowed=False,
            findings=findings,
            reason=f"Blocked: {len(findings)} secret(s) detected",
            scan_time_ms=scan_time_ms,
        )

        self._log_block(decision, target_url)
        return decision

    @property
    def avg_scan_time_ms(self) -> float:
        scanned = self.stats["requests_scanned"]
        if scanned == 0:
            return 0.0
        return round(self.stats["total_scan_time_ms"] / scanned, 3)

    def _log_block(self, decision: Decision, target_url: str) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target_url,
            **decision.to_dict(),
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            logger.warning("Failed to write guard log to %s", self.log_path)

    def _ensure_log_dir(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
