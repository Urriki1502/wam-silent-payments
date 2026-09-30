"""WAM monetary/network facts pinned to Core v0.1.11; no invented consensus."""

PROFILE = "WSP-1"
API_VERSION = 1
MAX_MONEY = 22_000_000 * 100_000_000
CORE_VERSION = "0.1.11"
CORE_COMMIT = "8a3f4fe4f1d804c378f795d4cc281ec5125f75f3"
REGTEST_GENESIS = "b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d"
# Mainnet/testnet Silent Payment HRP and WAM's HD coin-type assignment require
# adoption by the WAM project. This release qualification build never guesses.
MAINNET_ENABLED = False
