"""WAM Silent Payments: WSP-1 qualification build; external audit pending."""

from .core import Input, Match, address, decode_address, pub, scan, send, spending_key

__all__ = ["Input", "Match", "address", "decode_address", "pub", "scan", "send", "spending_key"]

from .api import SilentWallet, create_silent_wallet

__version__ = "1.0.0.dev0"
__all__ += ["SilentWallet", "create_silent_wallet"]

from .contracts import MatchedOutput, ScanCapability, ScannerStatus

__all__ += ["ScanCapability", "ScannerStatus", "MatchedOutput"]
