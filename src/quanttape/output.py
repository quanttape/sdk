import json
from typing import List

from . import __version__
from .scanner import Finding


class ConsoleFormatter:
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # red
        "HIGH": "\033[93m",      # yellow
        "MEDIUM": "\033[94m",    # blue
        "LOW": "\033[37m",       # white
    }
    RESET = "\033[0m"

    def format(self, findings: List[Finding]) -> str:
        if not findings:
            return "No findings detected."

        lines = [f"\n{'='*60}", f"  SecretScanner Results: {len(findings)} finding(s)", f"{'='*60}\n"]

        for f in findings:
            color = self.SEVERITY_COLORS.get(f.severity, "")
            lines.append(
                f"  {color}[{f.severity}]{self.RESET} {f.secret_type}\n"
                f"    File: {f.file}:{f.line}\n"
                f"    Preview: {f.match_preview}\n"
            )

        lines.append(f"{'='*60}")
        return "\n".join(lines)


class JsonFormatter:
    def format(self, findings: List[Finding]) -> str:
        results = {
            "total": len(findings),
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "secret_type": f.secret_type,
                    "severity": f.severity,
                    "match_preview": f.match_preview,
                }
                for f in findings
            ],
        }
        return json.dumps(results, indent=2)


class SarifFormatter:
    """sarif output - works with github code scanning and vscode"""

    def format(self, findings: List[Finding]) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "QuantTape",
                            "version": __version__,
                            "rules": self._build_rules(findings),
                        }
                    },
                    "results": [
                        {
                            "ruleId": self._rule_id(f.secret_type),
                            "level": self._sarif_level(f.severity),
                            "message": {"text": f"Potential {f.secret_type} detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": self._artifact_uri(f.file)},
                                        "region": {"startLine": f.line},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, findings: List[Finding]) -> list:
        seen = set()
        rules = []
        for f in findings:
            rule_id = self._rule_id(f.secret_type)
            if rule_id not in seen:
                seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": f.secret_type},
                })
        return rules

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }.get(severity, "note")

    @staticmethod
    def _rule_id(name: str) -> str:
        return name.lower().replace(" ", "-")

    @staticmethod
    def _artifact_uri(path: str) -> str:
        return path.replace("\\", "/")


def format_results(findings: List[Finding], output_format: str = "console") -> str:
    formatters = {
        "console": ConsoleFormatter,
        "json": JsonFormatter,
        "sarif": SarifFormatter,
    }
    formatter_class = formatters.get(output_format, ConsoleFormatter)
    return formatter_class().format(findings)
