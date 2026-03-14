import ast
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from .rules import DEFAULT_RULES, Rule, load_custom_rules

# skip these, they'll just produce garbage matches
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".eggs",
}

_ORDER_SUBMISSION_RULE = "No Error Handling on Order"
_MARKET_ORDER_RULE = "Market Order Without Limit"
_INFINITE_LOOP_RULE = "Infinite Loop Risk"
_HARDCODED_TICKER_RULE = "Hardcoded Ticker Symbol"

_EXIT_HINTS = (
    "close",
    "exit",
    "flatten",
    "liquidat",
    "shutdown",
    "eod",
    "reduce",
)
_WRAPPER_HINTS = (
    "submit",
    "place",
    "create",
    "replace",
    "cancel",
    "close",
    "recover",
    "normalize",
    "fallback",
)
_SHUTDOWN_HINTS = (
    "shutdown",
    "stop",
    "stopped",
    "alive",
    "closed",
    "exit",
    "kill",
    "running",
    "done",
)
_MARKET_EXIT_WINDOW_HINTS = (
    "position_intent",
    "_to_close",
    "close_position",
    "force_close",
    "flatten",
    "liquidat",
    "shutdown",
    "close fallback",
    "close qty",
    "eod",
)
_AGGREGATE_SYMBOL_HINTS = (
    'symbol="all"',
    "symbol='all'",
    'ticker="all"',
    "ticker='all'",
    "compute_metrics(",
    "aggregate",
    "summary",
    "report",
)


@dataclass
class Finding:
    file: str
    line: int
    secret_type: str
    severity: str
    match_preview: str

    def __repr__(self) -> str:
        return f"Finding({self.secret_type} in {self.file}:{self.line} [{self.severity}])"


@dataclass
class PythonScanContext:
    safe_order_submission_lines: Set[int] = field(default_factory=set)
    safe_market_order_lines: Set[int] = field(default_factory=set)
    safe_true_loop_lines: Set[int] = field(default_factory=set)


def _mask_secret(text: str, visible_chars: int = 8) -> str:
    stripped = text.strip()
    if len(stripped) <= visible_chars:
        return stripped[:2] + "*" * max(0, len(stripped) - 2)
    return stripped[:visible_chars] + "*" * (len(stripped) - visible_chars)


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class _PythonContextBuilder(ast.NodeVisitor):
    def __init__(self) -> None:
        self._function_stack: List[str] = []
        self._try_depth = 0
        self.context = PythonScanContext()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Try(self, node: ast.Try) -> None:
        self._try_depth += 1
        self.generic_visit(node)
        self._try_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            if self._is_safe_loop(node):
                self._mark_node_lines(node, self.context.safe_true_loop_lines)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func).lower()
        parent = getattr(node, "_qt_parent", None)
        current_fn = self._function_stack[-1].lower() if self._function_stack else ""

        if name in {"submit_order", "place_order", "create_order"}:
            if self._try_depth > 0 or isinstance(parent, ast.Return):
                self._mark_node_lines(node, self.context.safe_order_submission_lines)
            elif any(hint in current_fn for hint in _WRAPPER_HINTS):
                self._mark_node_lines(node, self.context.safe_order_submission_lines)

        if self._call_uses_market_order(node):
            if any(hint in current_fn for hint in _EXIT_HINTS) or self._call_is_explicit_close(node):
                self._mark_node_lines(node, self.context.safe_market_order_lines)

        self.generic_visit(node)

    def _mark_node_lines(self, node: ast.AST, target: Set[int]) -> None:
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)
        if start is None:
            return
        for line in range(start, (end or start) + 1):
            target.add(line)

    def _call_uses_market_order(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg not in {"type", "order_type"}:
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if kw.value.value.lower() == "market":
                    return True
        return False

    def _call_is_explicit_close(self, node: ast.Call) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                value = child.value.lower()
                if value.endswith("_to_close") or any(hint in value for hint in _EXIT_HINTS):
                    return True
        return False

    def _is_safe_loop(self, node: ast.While) -> bool:
        has_guarded_exit = False
        has_wait = False
        has_shutdown_hint = False
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.Break, ast.Return, ast.Raise)):
                # only count exits that are guarded by an If condition
                # (direct children of the loop body that are unconditional
                # would end the loop on first iteration - still safe)
                has_guarded_exit = True
            elif isinstance(child, ast.Call):
                if _call_name(child.func).lower() in {"sleep", "wait", "join"}:
                    has_wait = True
            elif isinstance(child, ast.Await) and isinstance(child.value, ast.Call):
                if _call_name(child.value.func).lower() in {"sleep", "wait"}:
                    has_wait = True
            elif isinstance(child, ast.Name):
                if any(hint in child.id.lower() for hint in _SHUTDOWN_HINTS):
                    has_shutdown_hint = True
            elif isinstance(child, ast.Attribute):
                if any(hint in child.attr.lower() for hint in _SHUTDOWN_HINTS):
                    has_shutdown_hint = True

        # require exit + (wait or shutdown hint) - a bare break with no
        # sleep/shutdown pattern is not enough to mark as safe
        if has_guarded_exit and (has_wait or has_shutdown_hint):
            return True
        # direct break/return in loop body (not nested in unreachable if)
        for stmt in node.body:
            if isinstance(stmt, (ast.Break, ast.Return, ast.Raise)):
                return True
        return has_wait and has_shutdown_hint


_ENTROPY_PATTERN = re.compile(
    r'''(?i)(?:secret|token|key|credential|auth|password|passwd|'''
    r'''config|endpoint_auth|broker_credential|api_credential|'''
    r'''alpaca_config|binance_config|ib_config|kraken_config|'''
    r'''live_endpoint|access_key|private_key)\s*[=:]\s*['"]?([A-Za-z0-9+/=_\-]{20,})['"]?'''
)


class SecretScanner:
    ENTROPY_THRESHOLD = 4.5  # tuned to reduce FPs, bump up if too noisy
    MIN_ENTROPY_LENGTH = 20

    def __init__(self, config_path: Optional[str] = None, trading_bot_mode: bool = True):
        self.rules: List[Rule] = list(DEFAULT_RULES)
        if config_path:
            self.rules.extend(load_custom_rules(config_path))
        self._compiled = [(rule, rule.compile()) for rule in self.rules]
        self.trading_bot_mode = trading_bot_mode

    def scan_file(self, filepath: str) -> List[Finding]:
        path = Path(filepath)
        if path.suffix.lower() in BINARY_EXTENSIONS:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        lines = content.splitlines()
        python_context = self._build_python_context(path, content)

        findings: List[Finding] = []
        for line_num, line in enumerate(lines, start=1):
            findings.extend(self._scan_line(str(path), line_num, line, lines, python_context))

        return findings

    def scan_directory(self, directory: str) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(directory)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                findings.extend(self.scan_file(filepath))

        return findings

    def scan_git_history(self, repo_path: str) -> List[Finding]:
        try:
            from git import Repo
        except ImportError:
            raise ImportError("GitPython required for git history scanning: pip install gitpython")

        repo = Repo(repo_path)
        findings: List[Finding] = []

        # cap at 500 commits so we don't choke on huge repos
        for commit in repo.iter_commits("--all", max_count=500):
            if not commit.parents:
                diffs = commit.diff(None, create_patch=True)
            else:
                diffs = commit.parents[0].diff(commit, create_patch=True)

            for diff in diffs:
                try:
                    patch = diff.diff.decode("utf-8", errors="ignore")
                except AttributeError:
                    continue

                filepath = diff.b_path or diff.a_path or "unknown"

                # skip binary files (same extensions as scan_file)
                ext = Path(filepath).suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    continue

                # extract only the added source lines (strip diff markers)
                added_lines: List[str] = []
                for raw_line in patch.splitlines():
                    if raw_line.startswith("+") and not raw_line.startswith("+++"):
                        added_lines.append(raw_line[1:])

                label = f"{filepath} (commit {commit.hexsha[:8]})"
                for line_num, line in enumerate(added_lines, start=1):
                    findings.extend(
                        self._scan_line(
                            label,
                            line_num,
                            line,
                            added_lines,  # pass clean source lines, not raw patch
                            None,
                        )
                    )

        return findings

    def _build_python_context(self, path: Path, content: str) -> Optional[PythonScanContext]:
        if path.suffix.lower() != ".py":
            return None
        try:
            tree = ast.parse(content.lstrip("\ufeff"))
        except SyntaxError:
            return None
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                setattr(child, "_qt_parent", parent)
        builder = _PythonContextBuilder()
        builder.visit(tree)
        return builder.context

    def _scan_line(
        self,
        filepath: str,
        line_num: int,
        line: str,
        lines: Optional[List[str]] = None,
        python_context: Optional[PythonScanContext] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for rule, compiled in self._compiled:
            match = compiled.search(line)
            if not match:
                continue
            if self._should_suppress_match(rule, line_num, line, lines, python_context):
                continue
            matched_text = match.group(1) if match.lastindex else match.group(0)
            findings.append(
                Finding(
                    file=filepath,
                    line=line_num,
                    secret_type=rule.name,
                    severity=rule.severity,
                    match_preview=_mask_secret(matched_text),
                )
            )

        findings.extend(self._entropy_check(filepath, line_num, line))

        return findings

    def _should_suppress_match(
        self,
        rule: Rule,
        line_num: int,
        line: str,
        lines: Optional[List[str]],
        python_context: Optional[PythonScanContext],
    ) -> bool:
        if not self.trading_bot_mode:
            return False

        stripped = line.strip()
        window = self._window_text(lines, line_num, radius=6).lower()

        if rule.name == _ORDER_SUBMISSION_RULE:
            if stripped.startswith("return "):
                return True
            if python_context and line_num in python_context.safe_order_submission_lines:
                return True
            if "try:" in window and "except" in window:
                return True

        if rule.name == _MARKET_ORDER_RULE:
            if python_context and line_num in python_context.safe_market_order_lines:
                return True
            if any(hint in window for hint in _MARKET_EXIT_WINDOW_HINTS):
                return True

        if rule.name == _INFINITE_LOOP_RULE:
            if python_context and line_num in python_context.safe_true_loop_lines:
                return True

        if rule.name == _HARDCODED_TICKER_RULE:
            lowered = stripped.lower()
            if any(hint in lowered for hint in _AGGREGATE_SYMBOL_HINTS):
                return True
            if re.search(r'''(?i)\b(?:symbol|ticker)\s*=\s*['"](?:ALL|NONE|AUTO)['"]''', stripped):
                return True

        return False

    def _window_text(self, lines: Optional[List[str]], line_num: int, radius: int = 4) -> str:
        if not lines:
            return ""
        start = max(0, line_num - 1 - radius)
        end = min(len(lines), line_num + radius)
        return "\n".join(lines[start:end])

    def _entropy_check(self, filepath: str, line_num: int, line: str) -> List[Finding]:
        """catches high-entropy strings the regex rules miss"""
        findings: List[Finding] = []
        for match in _ENTROPY_PATTERN.finditer(line):
            value = match.group(1)
            if len(value) >= self.MIN_ENTROPY_LENGTH:
                entropy = _shannon_entropy(value)
                if entropy >= self.ENTROPY_THRESHOLD:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=line_num,
                            secret_type="High Entropy String",
                            severity="MEDIUM",
                            match_preview=_mask_secret(value),
                        )
                    )
        return findings
