"""
Quant Tape — The Last Line Before The Market.

The security SDK for algorithmic trading.

https://quanttape.com
"""

__version__ = "0.0.9"
__author__ = "Quant Tape LLC"

from .scanner import SecretScanner, Finding
from .rules import Rule, DEFAULT_RULES

__all__ = ["SecretScanner", "Finding", "Rule", "DEFAULT_RULES"]
