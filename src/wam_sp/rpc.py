"""Bounded JSON-RPC with no DNS, proxy, redirect, raw errors or automatic retries."""

import base64
import http.client
import json
import math
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from urllib.parse import quote, urlsplit

from .errors import WSPError, Category


class RPCError(WSPError):
    def __init__(self, code, rpc_code=None):
        super().__init__(Category.RPC, code)
        self.rpc_code = rpc_code


HarnessError = RPCError  # Internal alias; fixed codes never include remote messages.

GENESIS = "b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d"
MAX_RESPONSE = 4 * 1024 * 1024
READ = frozenset(
    {
        "getblockchaininfo",
        "getblockhash",
        "getblockcount",
        "getbestblockhash",
        "getblock",
        "getrawmempool",
        "getrawtransaction",
        "gettxout",
        "testmempoolaccept",
    }
)
MUTATE = frozenset({"sendrawtransaction"})


def endpoint(url):
    """Accept only canonical IPv4 loopback URLs; no alternative IP spellings/DNS."""
    try:
        p = urlsplit(url)
        if not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/?", url):
            raise ValueError
        if not 1 <= p.port <= 65535:
            raise ValueError
        return p.port
    except (ValueError, TypeError, AttributeError):
        raise HarnessError("INVALID_ENDPOINT") from None


def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError
        d[k] = v
    return d


def _constant(_):
    raise ValueError


@dataclass(frozen=True, repr=False)
class Cookie:
    path: Path

    def header(self):
        try:
            # Re-read for cookie rotation. Do not put credentials in argv or reports.
            if self.path.is_symlink():
                raise ValueError
            with self.path.open("rb") as f:
                raw = f.read(4097).strip()
            if not 1 < len(raw) <= 4096 or b":" not in raw or b"\n" in raw or b"\r" in raw:
                raise ValueError
            return "Basic " + base64.b64encode(raw).decode("ascii")
        except (OSError, ValueError):
            raise HarnessError("RPC_CREDENTIALS") from None


class RPC:
    def __init__(
        self, url, cookie, wallet=None, timeout=30, max_response=MAX_RESPONSE, allow_broadcast=False
    ):
        self.port = endpoint(url)
        if not isinstance(cookie, Cookie):
            raise HarnessError("RPC_CREDENTIALS")
        if (
            not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 180
        ):
            raise HarnessError("RPC_ENVELOPE")
        if type(max_response) is not int or not 256 <= max_response <= 16 * 1024 * 1024:
            raise HarnessError("RPC_ENVELOPE")
        if wallet is not None:
            raise HarnessError("RPC_METHOD_DENIED")
        self.allow_broadcast = allow_broadcast is True
        self.cookie, self.wallet_name = cookie, wallet
        self.timeout, self.max_response = timeout, max_response

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def attest(self):
        info = self._request("getblockchaininfo", [])
        genesis = self._request("getblockhash", [0])
        if not isinstance(info, dict) or info.get("chain") != "regtest" or genesis != GENESIS:
            raise HarnessError("CHAIN_MISMATCH")

    def call(self, method, params=None):
        if method not in READ | MUTATE:
            raise HarnessError("RPC_METHOD_DENIED")
        if params is None:
            params = []
        if not isinstance(params, list):
            raise HarnessError("RPC_ENVELOPE")
        if method in MUTATE and not self.allow_broadcast:
            raise HarnessError("RPC_METHOD_DENIED")
        if method in MUTATE:
            self.attest()  # Re-check before EVERY mutation; never attach to live wallets.
        return self._request(method, params)

    def _request(self, method, params):
        request_id = uuid.uuid4().hex
        try:
            body = json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                allow_nan=False,
            ).encode()
        except (ValueError, TypeError):
            raise HarnessError("RPC_ENVELOPE") from None
        path = "/" if self.wallet_name is None else "/wallet/" + quote(self.wallet_name, safe="")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            conn.request(
                "POST",
                path,
                body,
                {"Content-Type": "application/json", "Authorization": self.cookie.header()},
            )
            response = conn.getresponse()
            # HTTPConnection never follows redirects; never retry a mutating request.
            if response.status not in (200, 400, 404, 500):
                raise HarnessError("RPC_HTTP")
            raw = response.read(self.max_response + 1)
            if len(raw) > self.max_response:
                raise HarnessError("RPC_OVERSIZE")
            try:
                data = json.loads(
                    raw, parse_float=Decimal, parse_constant=_constant, object_pairs_hook=_unique
                )
            except (ValueError, RecursionError, UnicodeError):
                raise HarnessError("RPC_ENVELOPE") from None
            if (
                not isinstance(data, dict)
                or data.get("id") != request_id
                or data.get("jsonrpc") != "2.0"
            ):
                raise HarnessError("RPC_ENVELOPE")
            if data.get("error") is not None:
                err = data["error"]
                if (
                    not isinstance(err, dict)
                    or type(err.get("code")) is not int
                    or data.get("result") is not None
                ):
                    raise HarnessError("RPC_ENVELOPE")
                raise RPCError("RPC_REMOTE", err["code"])
            if "result" not in data or response.status != 200:
                raise HarnessError("RPC_ENVELOPE")
            return data["result"]
        except HarnessError:
            raise
        except (OSError, http.client.HTTPException, ValueError, OverflowError):
            raise HarnessError("RPC_TRANSPORT") from None
        finally:
            conn.close()
