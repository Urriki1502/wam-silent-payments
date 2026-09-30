"""Offline, synthetic keys only. Run: python examples/derive.py"""

from wam_sp import Input, address, pub, send, scan, spending_key
from wam_sp.transaction import p2wpkh

# PUBLIC DEMO CONSTANTS. Never fund these keys on any live network.
scan_secret, spend_secret, sender_secret = 11, 29, 31
code = address(scan_secret, pub(spend_secret))
vin = Input(
    "ab" * 32, 0, p2wpkh(sender_secret), witness=(b"", pub(sender_secret)), secret=sender_secret
)
outputs = send([vin], [code])
(match,) = scan([vin], outputs, scan_secret, pub(spend_secret))
assert spending_key(spend_secret, match).public_key.format()[1:] == outputs[0]
print("Offline send / scan / spend-key check: PASS")
