import argparse
import os
import sys
from pathlib import Path
from typing import List

from . import __version__
from .output import format_results
from .scanner import Finding, SecretScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quanttape",
        description="QuantTape - Trading-aware local security scanner for bots, strategies, and execution code.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan trading code for secrets and vulnerabilities")
    scan_parser.add_argument(
        "path",
        help="Path to file or directory to scan",
    )
    scan_parser.add_argument(
        "--output",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format (default: console)",
    )
    scan_parser.add_argument(
        "--config",
        help="Path to custom rules YAML file",
    )
    scan_parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan git commit history",
    )

    mode_group = scan_parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--trading-bot-mode",
        dest="trading_bot_mode",
        action="store_true",
        default=True,
        help="Enable context-aware suppression for trading bots. This is the default.",
    )
    mode_group.add_argument(
        "--generic-mode",
        dest="trading_bot_mode",
        action="store_false",
        help="Disable trading-bot suppressions and use generic raw scanning behavior.",
    )

    # --- guard subcommand ---
    guard_parser = subparsers.add_parser(
        "guard", help="Start egress proxy to intercept outbound HTTP and block secret leakage"
    )
    guard_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    guard_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    guard_parser.add_argument(
        "--mode",
        choices=["agent", "trading", "all"],
        default="agent",
        help="Rule mode: agent (credential+general), trading (all trading rules), all (default: agent)",
    )
    guard_parser.add_argument(
        "--config", help="Path to custom rules YAML file"
    )
    guard_parser.add_argument(
        "--no-verify",
        action="store_true",
        default=False,
        help="Skip upstream TLS certificate verification (for testing only)",
    )

    # --- setup-certs subcommand ---
    subparsers.add_parser(
        "setup-certs",
        help="Generate local CA certificate for HTTPS inspection and print trust instructions",
    )

    return parser


def _print_banner(output_format: str) -> None:
    if output_format != "console":
        return
    import sys
    from rich.console import Console
    from rich.text import Text
    fh = open(sys.stdout.fileno(), mode="w", encoding="utf-8", closefd=False)
    try:
        console = Console(force_terminal=True, highlight=False, file=fh)
        msg = Text()
        msg.append("  Scanning", style="dim")
        msg.append(" for credential exposure and security vulnerabilities", style="dim")
        msg.append("...", style="bold green")
        console.print(msg)
    finally:
        fh.close()


def _git_history_root(path: str) -> str:
    target = Path(path)
    return str(target if target.is_dir() else target.parent)


def _run_guard(args) -> None:
    try:
        from .proxy.server import GuardConfig, run_guard
    except ImportError:
        print(
            "Error: Guard requires extra dependencies.\n"
            "Install with: pip install quanttape[guard]",
            file=sys.stderr,
        )
        sys.exit(1)

    config = GuardConfig(
        port=args.port,
        host=args.host,
        mode=args.mode,
        config_path=getattr(args, "config", None),
        no_verify=getattr(args, "no_verify", False),
    )
    run_guard(config)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "guard":
        _run_guard(args)
        return

    if args.command == "setup-certs":
        try:
            from .proxy.certs import setup_certs_interactive
        except ImportError:
            print(
                "Error: Guard requires extra dependencies.\n"
                "Install with: pip install quanttape[guard]",
                file=sys.stderr,
            )
            sys.exit(1)
        setup_certs_interactive()
        return

    if args.command != "scan":
        parser.print_help()
        sys.exit(0)

    _print_banner(args.output)

    scanner = SecretScanner(
        config_path=args.config,
        trading_bot_mode=args.trading_bot_mode,
    )

    findings: List[Finding] = []

    if os.path.isfile(args.path):
        findings = scanner.scan_file(args.path)
    elif os.path.isdir(args.path):
        findings = scanner.scan_directory(args.path)
    else:
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    if args.git_history:
        findings.extend(scanner.scan_git_history(_git_history_root(args.path)))

    output = format_results(findings, args.output)
    if output is not None:
        print(output)

    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
