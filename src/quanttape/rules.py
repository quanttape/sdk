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
    ),
    Rule(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        severity="CRITICAL",
        description="Amazon Web Services secret access key",
    ),
    Rule(
        name="GitHub Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(gh[ps]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9_]|$)",
        severity="HIGH",
        description="GitHub personal access token or service token",
    ),
    Rule(
        name="Private Key",
        pattern=r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?:\s+BLOCK)?-----",
        severity="CRITICAL",
        description="PEM-encoded private key header",
    ),
    Rule(
        name="JWT Token",
        pattern=r"(?:^|[^A-Za-z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^A-Za-z0-9_-]|$)",
        severity="HIGH",
        description="JSON Web Token (3-part base64url)",
    ),
    Rule(
        name="Database URL",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        severity="CRITICAL",
        description="Database connection string with embedded credentials",
    ),
    Rule(
        name="Generic API Key",
        pattern=r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        severity="MEDIUM",
        description="Generic API key assignment",
    ),
    Rule(
        name="Generic Password",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        severity="MEDIUM",
        description="Hardcoded password assignment",
    ),
    Rule(
        name="GCP Service Account Key",
        pattern=r"\"type\"\s*:\s*\"service_account\"",
        severity="CRITICAL",
        description="Google Cloud Platform service account JSON key file",
    ),
    Rule(
        name="Azure Client Secret",
        pattern=r"(?i)(?:azure|client)[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-.~]{30,})['\"]?",
        severity="CRITICAL",
        description="Azure Active Directory client secret",
    ),
    Rule(
        name="Slack Token",
        pattern=r"(xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)",
        severity="HIGH",
        description="Slack API token (bot, user, or workspace)",
    ),
    Rule(
        name="Telegram Bot Token",
        pattern=r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
        severity="HIGH",
        description="Telegram bot API token",
    ),
]

# --- Broker & exchange API key rules ---
BROKER_RULES: List[Rule] = [
    Rule(
        name="Alpaca API Key (Header)",
        pattern=r"(?i)APCA-API-KEY-ID\s*[=:]\s*['\"]?([A-Za-z0-9]{16,})['\"]?",
        severity="CRITICAL",
        description="Alpaca broker API key ID found hardcoded in header",
    ),
    Rule(
        name="Alpaca Secret Key (Header)",
        pattern=r"(?i)APCA-API-SECRET-KEY\s*[=:]\s*['\"]?([A-Za-z0-9]{36,})['\"]?",
        severity="CRITICAL",
        description="Alpaca broker secret key found hardcoded in header",
    ),
    Rule(
        name="Alpaca API Key (Variable)",
        pattern=r"(?i)(?:alpaca|apca)[_-]?(?:api)?[_-]?(?:key|id)\s*[=:]\s*['\"]([A-Za-z0-9]{16,})['\"]",
        severity="CRITICAL",
        description="Alpaca broker API key hardcoded in variable assignment",
    ),
    Rule(
        name="Alpaca Secret (Variable)",
        pattern=r"(?i)(?:alpaca|apca)[_-]?(?:api)?[_-]?secret\s*[=:]\s*['\"]([A-Za-z0-9]{36,})['\"]",
        severity="CRITICAL",
        description="Alpaca broker secret key hardcoded in variable assignment",
    ),
    Rule(
        name="Binance API Key",
        pattern=r"(?i)(?:binance)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9]{64})['\"]",
        severity="CRITICAL",
        description="Binance exchange API key or secret (64-char)",
    ),
    Rule(
        name="Coinbase API Key",
        pattern=r"(?i)(?:coinbase|cb)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
        severity="CRITICAL",
        description="Coinbase exchange API key or secret",
    ),
    Rule(
        name="Coinbase Pro / Advanced",
        pattern=r"(?i)(?:cb[_-]?access[_-]?passphrase)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        severity="CRITICAL",
        description="Coinbase Pro/Advanced Trade API passphrase",
    ),
    Rule(
        name="Interactive Brokers Gateway",
        pattern=r"(?i)(?:ib[_-]?(?:gateway|tws)[_-]?(?:password|pwd))\s*[=:]\s*['\"]([^'\"]+)['\"]",
        severity="CRITICAL",
        description="Interactive Brokers TWS/Gateway password hardcoded",
    ),
    Rule(
        name="Kraken API Key",
        pattern=r"(?i)(?:kraken)[_-]?(?:api)?[_-]?(?:key|secret)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40,})['\"]",
        severity="CRITICAL",
        description="Kraken exchange API key or private key",
    ),
    Rule(
        name="TD Ameritrade / Schwab Key",
        pattern=r"(?i)(?:td[_-]?ameritrade|schwab|tda)[_-]?(?:api)?[_-]?(?:key|client[_-]?id|secret)\s*[=:]\s*['\"]([A-Za-z0-9@_\-]{16,})['\"]",
        severity="CRITICAL",
        description="TD Ameritrade / Charles Schwab API client ID or key",
    ),
    Rule(
        name="Tradier API Token",
        pattern=r"(?i)(?:tradier)[_-]?(?:api)?[_-]?(?:token|key|secret)\s*[=:]\s*['\"]([A-Za-z0-9]{20,})['\"]",
        severity="CRITICAL",
        description="Tradier brokerage API access token",
    ),
    Rule(
        name="Polygon.io API Key",
        pattern=r"(?i)(?:polygon)[_-]?(?:api)?[_-]?(?:key|token)\s*[=:]\s*['\"]([A-Za-z0-9_]{20,})['\"]",
        severity="HIGH",
        description="Polygon.io market data API key",
    ),
    Rule(
        name="Webhook URL (Discord/Slack)",
        pattern=r"https://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services)/[^\s'\"]+",
        severity="HIGH",
        description="Webhook URL that could be used to exfiltrate data or send unauthorized alerts",
    ),
]

# --- Trading logic vulnerability rules ---
TRADING_LOGIC_RULES: List[Rule] = [
    Rule(
        name="Hardcoded Live Trading URL",
        pattern=r"(?i)(?:base[_-]?url|endpoint)\s*[=:]\s*['\"]https?://api\.alpaca\.markets['\"]",
        severity="HIGH",
        description="Live Alpaca trading URL hardcoded. Use environment variable or config to switch between paper/live.",
    ),
    Rule(
        name="Hardcoded Binance Live Endpoint",
        pattern=r"(?i)(?:base[_-]?url|endpoint)\s*[=:]\s*['\"]https?://api\.binance\.com['\"]",
        severity="HIGH",
        description="Live Binance endpoint hardcoded. Use environment variable to switch between testnet/live.",
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
    ),
    Rule(
        name="Market Order Without Limit",
        pattern=r"(?ix)"
                r"^(?!.*\b(?:close|close_reason|flatten|liquidat|reduce|exit|shutdown|position_intent)\b)"
                r".*\b(?:order_type|type)\s*[=:]\s*['\"]market['\"]"
                r"(?:.*\b(?:qty|quantity|shares|symbol|ticker|side|action|tif)\b)?",
        severity="MEDIUM",
        description="Market order detected. Consider using limit orders to avoid slippage, especially in volatile conditions.",
    ),
    Rule(
        name="No Error Handling on Order",
        pattern=r"^(?!\s*return\b)(?!\s*yield\b).*\.(?:submit_order|place_order|create_order)\(",
        severity="LOW",
        description="Order submission detected. Ensure it is wrapped in try/except to handle API failures, insufficient funds, or rejected orders.",
    ),
    Rule(
        name="Infinite Loop Risk",
        pattern=r"^\s*while\s+True\s*:\s*(?:#.*)?$",
        severity="LOW",
        description="Infinite loop detected. Ensure there is a break condition or kill switch to prevent runaway execution.",
    ),
    Rule(
        name="Sleep Without Kill Switch",
        pattern=r"(?ix)^\s*time\.sleep\(\s*(?:[1-9]\d*(?:\.\d+)?|0?\.\d{2,})\s*\)\s*(?:\#.*)?$",
        severity="LOW",
        description="Hardcoded numeric sleep detected. Prefer configurable polling intervals with explicit shutdown/kill-switch checks around the loop.",
    ),
    Rule(
        name="Hardcoded Ticker Symbol",
        pattern=r"(?i)\b(?:symbol|ticker)\s*=\s*['\"](?!ALL\b|NONE\b|AUTO\b)[A-Z]{1,5}['\"]",
        severity="LOW",
        description="Hardcoded ticker symbol. Consider making this configurable for reusability and testing.",
    ),
]

DEFAULT_RULES: List[Rule] = GENERAL_RULES + BROKER_RULES + TRADING_LOGIC_RULES


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
            )
        )
    return rules
