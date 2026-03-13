"""
Quant Tape — The Last Line Before The Market.

Security SDK for algorithmic trading.
Zero latency. Zero exposure. Zero compromise.

https://quanttape.com
"""

__version__ = "0.0.3a1"
__author__ = "Quant Tape LLC"

def _welcome():
    msg = f"""
  ╔══════════════════════════════════════════════════╗
  ║              QUANT TAPE  v{__version__}               ║
  ║  Security middleware for algorithmic trading.    ║
  ║                                                  ║
  ║  Zero latency. Zero exposure. Zero compromise.   ║
  ║                                                  ║
  ║  Full SDK coming soon — join early access:       ║
  ║  https://quanttape.com                           ║
  ╚══════════════════════════════════════════════════╝
"""
    print(msg)

_welcome()
