import json
from typing import List

from . import __version__
from .scanner import Finding


# --------------------------------------------------------------------------
# Rich console formatter
# --------------------------------------------------------------------------

def _console_format(findings: List[Finding]) -> None:
    import sys
    from pathlib import Path
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box

    _stdout_utf8 = open(sys.stdout.fileno(), mode="w", encoding="utf-8", closefd=False)
    try:
        console = Console(force_terminal=True, highlight=False, file=_stdout_utf8)

        # Skull banner
        l1 = Text(); l1.append("    +-----+", style="bold green")
        l2 = Text(); l2.append("    | ", style="bold green"); l2.append("Q Q", style="bold white"); l2.append(" |", style="bold green"); l2.append("  QUANTTAPE", style="bold white"); l2.append(f"  v{__version__}", style="dim")
        l3 = Text(); l3.append("    |  ", style="bold green"); l3.append("T", style="bold white"); l3.append("  |", style="bold green"); l3.append("  The Last Line Before The Market.", style="dim")
        l4 = Text(); l4.append("    +-+-+-+", style="bold green")
        console.print()
        console.print(l1)
        console.print(l2)
        console.print(l3)
        console.print(l4)

        if not findings:
            console.print(
                Panel(
                    Text("✓  No findings detected.", style="bold green"),
                    box=box.ROUNDED,
                    border_style="green",
                    padding=(0, 2),
                )
            )
            return

        # Severity counts
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        severity_style = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "bold cyan",
            "LOW":      "dim white",
        }
        severity_icon = {
            "CRITICAL": "◆",
            "HIGH":     "◆",
            "MEDIUM":   "◆",
            "LOW":      "◆",
        }

        # Findings table - drop PREVIEW column on narrow terminals
        term_width = console.width or 120
        show_preview = term_width >= 90

        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold dim",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("SEV", width=14, no_wrap=True)
        table.add_column("RULE", min_width=20, no_wrap=True, overflow="ellipsis")
        table.add_column("FILE", min_width=16, no_wrap=True)
        if show_preview:
            table.add_column("PREVIEW", no_wrap=True, overflow="ellipsis")

        for f in findings:
            style = severity_style.get(f.severity, "white")
            icon  = severity_icon.get(f.severity, "◆")
            sev_text = Text(f"{icon}  {f.severity}", style=style)
            short_path = f"{Path(f.file).name}:{f.line}"
            row = [
                sev_text,
                Text(f.secret_type, style="white"),
                Text(short_path, style="dim cyan"),
            ]
            if show_preview:
                row.append(Text(f.match_preview, style="dim"))
            table.add_row(*row)

        console.print(
            Panel(table, title="[bold]FINDINGS[/bold]", box=box.ROUNDED,
                  border_style="dim", padding=(0, 1))
        )

        # Summary bar
        summary = Text()
        summary.append(f"  {len(findings)} finding{'s' if len(findings) != 1 else ''}", style="bold white")
        summary.append("  ·  ", style="dim")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = counts[sev]
            if n:
                summary.append(f"{n} {sev.lower()}  ", style=severity_style[sev])
        console.print(summary)
        console.print(Text("  * previews are partially redacted for safety", style="dim"))
        console.print()
    finally:
        _stdout_utf8.close()


# --------------------------------------------------------------------------
# String-returning formatters for JSON / SARIF
# --------------------------------------------------------------------------

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
    """SARIF 2.1.0 - works with GitHub Code Scanning and VS Code."""

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
        seen: set = set()
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
            "HIGH":     "error",
            "MEDIUM":   "warning",
            "LOW":      "note",
        }.get(severity, "note")

    @staticmethod
    def _rule_id(name: str) -> str:
        return name.lower().replace(" ", "-")

    @staticmethod
    def _artifact_uri(path: str) -> str:
        return path.replace("\\", "/")


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def format_results(findings: List[Finding], output_format: str = "console") -> str | None:
    """
    For 'console' output, renders directly to the terminal via rich (returns None).
    For 'json' / 'sarif', returns the formatted string.
    """
    if output_format == "console":
        _console_format(findings)
        return None

    formatters = {
        "json":  JsonFormatter,
        "sarif": SarifFormatter,
    }
    formatter_class = formatters.get(output_format, JsonFormatter)
    return formatter_class().format(findings)
