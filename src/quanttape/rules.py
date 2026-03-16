import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml


@dataclass
class Rule:
    name: str
    pattern: str
    severity: str
    description: str
    category: str = "general"

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern)


# ============================================================
# BUILT-IN DETECTION RULES
# Add more via --config yaml
# ============================================================

# --- General credential rules ---
GENERAL_RULES: List[Rule] = [
    Rule(
        name="AWS Access Key ID",
        pattern=r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)",
        severity="CRITICAL",
        description="AWS access key ID (always starts with AKIA)",
        category="credential",
    ),
    Rule(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="CRITICAL",
        description="Amazon Web Services secret access key",
        category="credential",
    ),
    Rule(
        name="GitHub Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)",
        severity="HIGH",
        description="GitHub personal access token or service token",
        category="credential",
    ),
    Rule(
        name="Private Key",
        pattern=r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----",
        severity="CRITICAL",
        description="PEM-encoded private key header",
        category="credential",
    ),
    Rule(
        name="JWT Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^A-Za-z0-9_-]|$)",
        severity="HIGH",
        description="JSON Web Token (3-part base64url)",
        category="credential",
    ),
    Rule(
        name="Database URL",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        severity="CRITICAL",
        description="Database connection string with embedded credentials",
        category="credential",
    ),
    Rule(
        name="Generic API Key",
        pattern=r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        severity="MEDIUM",
        description="Generic API key assignment",
        category="credential",
    ),
    Rule(
        name="Generic Password",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="MEDIUM",
        description="Hardcoded password assignment",
        category="credential",
    ),
    Rule(
        name="GCP Service Account Key",
        pattern=r"\"type\"\s*:\s*\"service_account\"",
        severity="CRITICAL",
        description="Google Cloud Platform service account JSON key file",
        category="credential",
    ),
    Rule(
        name="Azure Client Secret",
        pattern=r"(?i)(?:azure|client)[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-.~]{30,})['\"]?",
        severity="CRITICAL",
        description="Azure Active Directory client secret",
        category="credential",
    ),
    Rule(
        name="Slack Token",
        pattern=r"(xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)",
        severity="HIGH",
        description="Slack API token (bot, user, or workspace)",
        category="credential",
    ),
    Rule(
        name="Telegram Bot Token",
        pattern=r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        severity="HIGH",
        description="Telegram bot API token",
        category="credential",
    ),
]

# --- Broker & exchange API key rules ---
BROKER_RULES: List[Rule] = [
    Rule(
        name="Alpaca API Key (Header)",
        pattern=r"(?i)APCA-API-KEY-ID\s*[=:]\s*['\"]?([A-Za-z0-9]{16,})['\"]?",
        severity="CRITICAL",
        description="Alpaca broker API key ID found hardcoded in header",
        category="broker",
    ),
    Rule(
        name="Alpaca Secret Key (Header)",
        pattern=r"(?i)APCA-API-SECRET-KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{36,})['\"]?",
        severity="CRITICAL",
        description="Alpaca broker secret key found hardcoded in header",
        category="broker",
    ),
    Rule(
        name="Alpaca API Key (Variable)",
        pattern=r"(?i)(?:alpaca|apca)[_-]?(?:api)?[_-]?(?:key|id)\s*[=:]\s*['\"]([A-Za-z0-9]{16,})['\"]",
        severity="CRITICAL",
        description="Alpaca broker API key hardcoded in variable assignment",
        category="broker",
    ),
    Rule(
        name="Alpaca Secret (Variable)",
        pattern=r"(?i)(?:alpaca|apca)[_-]?(?:api)?[_-]?secret\s*[=:]\s*['\"]([A-Za-z0-9]{36,})['\"]",
        severity="CRITICAL",
        description="Alpaca broker secret key hardcoded in variable assignment",
        category="broker",
    ),
    Rule(
        name="Binance API Key",
        pattern=r"(?i)(?:binance)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9]{64})['\"]",
        severity="CRITICAL",
        description="Binance exchange API key or secret (64-char)",
        category="broker",
    ),
    Rule(
        name="Coinbase API Key",
        pattern=r"(?i)(?:coinbase|cb)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        severity="CRITICAL",
        description="Coinbase exchange API key or secret",
        category="broker",
    ),
    Rule(
        name="Coinbase Pro / Advanced",
        pattern=r"(?i)(?:cb[_-]?access[_-]?passphrase)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        severity="CRITICAL",
        description="Coinbase Pro/Advanced Trade API passphrase",
        category="broker",
    ),
    Rule(
        name="Interactive Brokers Gateway",
        pattern=r"(?i)(?:ib[_-]?(?:gateway|tws)[_-]?(?:password|pwd))\s*[=:]\s*['\"]([^'\"]+)['\"]",
        severity="CRITICAL",
        description="Interactive Brokers TWS/Gateway password hardcoded",
        category="broker",
    ),
    Rule(
        name="Kraken API Key",
        pattern=r"(?i)(?:kraken)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40,})['\"]",
        severity="CRITICAL",
        description="Kraken exchange API key or private key",
        category="broker",
    ),
    Rule(
        name="TD Ameritrade / Schwab Key",
        pattern=r"(?i)(?:td[_-]?ameritrade|schwab|tda)[_-]?(?:api)?[_-]?(?:key|client[_-]?id|secret)\s*[=:]\s*['\"]([A-Za-z0-9@_\-]{16,})['\"]",
        severity="CRITICAL",
        description="TD Ameritrade / Charles Schwab API client ID or key",
        category="broker",
    ),
    Rule(
        name="Tradier API Token",
        pattern=r"(?i)(?:tradier)[_-]?(?:api)?[_-]?(?:token|key|secret)\s*[=:]\s*['\"]([A-Za-z0-9]{20,})['\"]",
        severity="CRITICAL",
        description="Tradier brokerage API access token",
        category="broker",
    ),
    Rule(
        name="Polygon.io API Key",
        pattern=r"(?i)(?:polygon)[_-]?(?:api)?[_-]?(?:key|token)\s*[=:]\s*['\"]([A-Za-z0-9_]{20,})['\"]",
        severity="HIGH",
        description="Polygon.io market data API key",
        category="broker",
    ),
    Rule(
        name="Webhook URL (Discord/Slack)",
        pattern=r"https://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services)/[^\s'\"]+",
        severity="HIGH",
        description="Webhook URL that could be used to exfiltrate data or send unauthorized alerts",
        category="broker",
    ),
]

# --- Trading logic vulnerability rules ---
TRADING_LOGIC_RULES: List[Rule] = [
    Rule(
        name="Hardcoded Live Trading URL",
        pattern=r"(?i)(?:base[_-]?url|endpoint)\s*[=:]\s*['\"]https?://api\.alpaca\.markets['\"]",
        severity="HIGH",
        description="Live Alpaca trading URL hardcoded. Use environment variable or config to switch between paper/live.",
        category="trading_logic",
    ),
    Rule(
        name="Hardcoded Binance Live Endpoint",
        pattern=r"(?i)(?:base[_-]?url|endpoint)\s*[=:]\s*['\"]https?://api\.binance\.com['\"]",
        severity="HIGH",
        description="Live Binance endpoint hardcoded. Use environment variable to switch between testnet/live.",
        category="trading_logic",
    ),
    Rule(
        name="No Position Size Limit",
        pattern=r"(?ix)"
                r"^\s*(?:qty|quantity|shares|size|order_qty|n_shares|num_shares|trade_qty|lot_size|amount)\s*=\s*"
                r"(?!.*\b(?:min|max|cap|limit|notional|risk|budget|clip|clamp)\b)"
                r"\(?\s*(?:balance|equity|portfolio_value|buying_power|cash|"
                r"account\.cash|account\.equity|get_portfolio_value\(\)|get_buying_power\(\))\b\s*(?:[*/]|//)",
        severity="HIGH",
        description="Position size appears to be derived directly from full account buying power/equity without an explicit cap or risk budget.",
        category="trading_logic",
    ),
    Rule(
        name="Market Order Without Limit",
        pattern=r"(?ix)"
                r"^(?!.*\b(?:close|close_reason|flatten|liquidat|reduce|exit|shutdown|position_intent)\b)"
                r".*\b(?:order_type|type)\s*[=:]\s*['\"]market['\"]"
                r"(?:.*\b(?:qty|quantity|shares|symbol|ticker|side|action|tif)\b)?",
        severity="MEDIUM",
        description="Market order detected. Consider using limit orders to avoid slippage, especially in volatile conditions.",
        category="trading_logic",
    ),
    Rule(
        name="No Error Handling on Order",
        pattern=r"^(?!\s*return\b)(?!\s*yield\b).*\.(?:submit_order|place_order|create_order)\(",
        severity="LOW",
        description="Order submission detected. Ensure it is wrapped in try/except to handle API failures, insufficient funds, or rejected orders.",
        category="trading_logic",
    ),
    Rule(
        name="Infinite Loop Risk",
        pattern=r"^\s*while\s+(?:True|1)\s*:\s*(?:#.*)?$",
        severity="LOW",
        description="Infinite loop detected. Ensure there is a break condition or kill switch to prevent runaway execution.",
        category="trading_logic",
    ),
    Rule(
        name="Sleep Without Kill Switch",
        pattern=r"(?ix)^\s*time\.sleep\(\s*(?:[1-9]\d*(?:\.\d+)?|0?\.\d+)\s*\)\s*(?:\#.*)?$",
        severity="LOW",
        description="Hardcoded numeric sleep detected. Prefer configurable polling intervals with explicit shutdown/kill-switch checks around the loop.",
        category="trading_logic",
    ),
    Rule(
        name="Hardcoded Ticker Symbol",
        pattern=r"(?i)\b(?:symbol|ticker)\s*=\s*['\"](?!ALL\b|NONE\b|AUTO\b)[A-Z]{1,5}['\"]",
        severity="LOW",
        description="Hardcoded ticker symbol. Consider making this configurable for reusability and testing.",
        category="trading_logic",
    ),
    Rule(
        name="Extended Hours Without Limit Order",
        pattern=r"(?i)extended_hours\s*[=:]\s*True",
        severity="HIGH",
        description="Extended hours trading requires limit orders with time_in_force=day. Market orders and non-day TIF are rejected in extended sessions.",
        category="trading_logic",
    ),
    Rule(
        name="Leverage Without Cap",
        pattern=r"(?ix)^\s*(?:leverage|margin_multiplier|margin_ratio)\s*=\s*"
                r"(?!.*\b(?:min|max|cap|limit|clamp|config|env|setting)\b)"
                r"\d+",
        severity="HIGH",
        description="Leverage or margin multiplier set without an explicit cap or config reference. Over-leverage amplifies losses and can trigger margin calls.",
        category="trading_logic",
    ),
    Rule(
        name="Hardcoded Notional Amount",
        pattern=r"(?ix)\b(?:notional|order_value|trade_value)\s*=\s*['\"]?\d{5,}['\"]?",
        severity="MEDIUM",
        description="Large hardcoded notional/dollar amount in order. Use calculated position sizing with risk budgets instead of fixed dollar values.",
        category="trading_logic",
    ),
    Rule(
        name="Hardcoded Crypto Pair",
        pattern=r"(?i)\b(?:symbol|ticker|pair)\s*=\s*['\"](?:[A-Z]{2,5}(?:USDT|BUSD|USD|USDC|BTC|ETH)|[A-Z]{2,5}/[A-Z]{2,5})['\"]",
        severity="LOW",
        description="Hardcoded crypto trading pair. Consider making this configurable for reusability across markets and testing.",
        category="trading_logic",
    ),
]

# --- AI agent egress rules (PII, env files, SSH keys in payloads) ---
AI_AGENT_RULES: List[Rule] = [
    Rule(
        name="SSH Private Key in Payload",
        pattern=r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----[\s\S]{20,}-----END",
        severity="CRITICAL",
        description="Full SSH private key content detected in payload",
        category="credential",
    ),
    Rule(
        name=".env File Content",
        pattern=r"(?im)^(?:DATABASE_URL|SECRET_KEY|API_KEY|AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*\S+",
        severity="HIGH",
        description="Environment variable assignments typical of .env files detected in payload",
        category="credential",
    ),
    Rule(
        name="Credit Card Number",
        pattern=r"(?:^|[^0-9])([3-6]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4})(?:[^0-9]|$)",
        severity="CRITICAL",
        description="Potential credit card number detected (Visa/MC/Amex/Discover pattern)",
        category="credential",
    ),
    Rule(
        name="US SSN Pattern",
        pattern=r"(?:^|[^0-9])(\d{3}-\d{2}-\d{4})(?:[^0-9]|$)",
        severity="CRITICAL",
        description="US Social Security Number pattern detected",
        category="credential",
    ),
    Rule(
        name="Code & Schema Exfiltration",
        pattern=r"(?i)(?:CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*\s+FROM)\s+\w+",
        severity="HIGH",
        description="SQL schema or bulk data query detected in outbound payload",
        category="credential",
    ),
    Rule(
        name="Code & Schema Exfiltration (Source Code)",
        pattern=r"(?:^|\n)\s*(?:def |class |import |from \S+ import |async def )\S+.*(?:\n\s+.+){3,}",
        severity="HIGH",
        description="Multi-line source code block detected in outbound payload",
        category="credential",
    ),
    Rule(
        name="System Path Leakage (Unix)",
        pattern=r"(?:/etc/(?:passwd|shadow|hosts|ssh|ssl)|/home/[a-z_][a-z0-9_-]*/\.(?:ssh|gnupg|aws|env)|/root/\.(?:ssh|bash_history|env))",
        severity="MEDIUM",
        description="Sensitive Unix system path or dotfile reference in outbound payload",
        category="credential",
    ),
    Rule(
        name="System Path Leakage (Windows)",
        pattern=r"(?i)(?:C:\\Users\\[^\\]+\\(?:\.ssh|\.aws|AppData\\Roaming)|C:\\Windows\\System32\\config)",
        severity="MEDIUM",
        description="Sensitive Windows system path reference in outbound payload",
        category="credential",
    ),
]

DEFAULT_RULES: List[Rule] = GENERAL_RULES + BROKER_RULES + TRADING_LOGIC_RULES + AI_AGENT_RULES

# Mode-to-category mapping for Guard proxy
GUARD_MODES = {
    "all": None,  # no filter, load everything
    "agent": {"credential"},
    "trading": {"credential", "broker", "trading_logic"},
}


def get_rules_for_mode(mode: str = "all") -> List[Rule]:
    """Return rules filtered by guard mode."""
    if mode not in GUARD_MODES:
        raise ValueError(f"Unknown mode '{mode}'. Choose from: {list(GUARD_MODES.keys())}")
    categories = GUARD_MODES[mode]
    if categories is None:
        return DEFAULT_RULES[:]
    return [r for r in DEFAULT_RULES if r.category in categories]


def load_custom_rules(config_path: str) -> List[Rule]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "rules" not in data:
        return []

    rules = []
    for entry in data["rules"]:
        rules.append(
            Rule(
                name=entry["name"],
                pattern=entry["pattern"],
                severity=entry.get("severity", "MEDIUM"),
                description=entry.get("description", ""),
                category=entry.get("category", "general"),
            )
        )
    return rules
