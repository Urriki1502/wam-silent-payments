"""Adapter for the actual wam-sdk 0.1 WamClient/Transport contract."""

from ..watcher import GENESIS

READ = frozenset(
    {
        "getbestblockhash",
        "getblockcount",
        "getblockhash",
        "getblock",
        "getrawmempool",
        "getrawtransaction",
        "gettxout",
        "testmempoolaccept",
    }
)


class SDKChain:
    def __init__(self, client, allow_broadcast=False):
        from wam_sdk.client import WamClient

        if not isinstance(client, WamClient) or client.config.network.genesis != GENESIS:
            raise ValueError("SDK_NETWORK_OR_VERSION")
        self.client = client
        self.allow_broadcast = bool(allow_broadcast)

    def attest(self):
        status = self.client.status()
        if status.network.genesis != GENESIS or not status.ready:
            raise ValueError("SDK_CHAIN_NOT_READY")

    def call(self, method, params=None):
        if method not in READ and not (method == "sendrawtransaction" and self.allow_broadcast):
            raise ValueError("SDK_CAPABILITY_DENIED")
        self.attest()
        return self.client._transport.call(
            method, [] if params is None else params, mutation=method == "sendrawtransaction"
        )
