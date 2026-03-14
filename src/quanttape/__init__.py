"""
Quant Tape - The Last Line Before The Market.

Trading-aware local security scanner for bots, strategies, and execution code.

https://quanttape.com
"""

__version__ = "0.0.17"
__author__ = "Quant Tape LLC"

from .scanner import SecretScanner, Finding
from .rules import Rule, DEFAULT_RULES

__all__ = ["SecretScanner", "Finding", "Rule", "DEFAULT_RULES"]