"""Pinned BIP392 single-key sp() + BIP393 annotations and BIP380 checksum.

Two-key WIF/xprv/musig expressions are rejected explicitly, never reinterpreted.
Wire annotations are not the storage schema. Unknown annotations are preserved.
"""

import re
from dataclasses import dataclass
from ..codec import encode, decode, ALPHABET
from ..core import ser, scalar, pub, compressed
from ..keystore import ScanAccount
from ..watcher import GENESIS

CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
GENERATORS = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)


def checksum(text):
    symbols = []
    group = []
    for c in text:
        v = CHARSET.find(c)
        if v < 0:
            raise ValueError("DESCRIPTOR_CHARACTER")
        symbols.append(v & 31)
        group.append(v >> 5)
        if len(group) == 3:
            symbols.append(group[0] * 9 + group[1] * 3 + group[2])
            group = []
    if group:
        symbols.append(group[0] if len(group) == 1 else group[0] * 3 + group[1])
    chk = 1
    for value in symbols + [0] * 8:
        top = chk >> 35
        chk = ((chk & 0x7FFFFFFFF) << 5) ^ value
        for i, g in enumerate(GENERATORS):
            if (top >> i) & 1:
                chk ^= g
    chk ^= 1
    return "".join(ALPHABET[(chk >> (5 * (7 - i))) & 31] for i in range(8))


def validate_origin(origin):
    if (
        not isinstance(origin, str)
        or len(origin) > 1024
        or not re.fullmatch(r"[0-9a-f]{8}(?:/[0-9]+[h\x27]?)*", origin)
    ):
        raise ValueError("DESCRIPTOR_ORIGIN")
    for element in origin.split("/")[1:]:
        if len(element) > 11 or int(element.rstrip("h'")) >= 2**31:
            raise ValueError("DESCRIPTOR_ORIGIN")


def annotated(text, require_checksum=True):
    if not isinstance(text, str) or not 1 <= len(text) <= 4096:
        raise ValueError("DESCRIPTOR_LIMIT")
    parts = text.split("#")
    if len(parts) == 2:
        if checksum(parts[0]) != parts[1]:
            raise ValueError("DESCRIPTOR_CHECKSUM")
    elif len(parts) != 1 or require_checksum:
        raise ValueError("DESCRIPTOR_CHECKSUM")
    segments = parts[0].split("?")
    if len(segments) > 2:
        raise ValueError("DESCRIPTOR_ANNOTATIONS")
    annotations = {}
    if len(segments) == 2:
        for pair in segments[1].split("&"):
            if not re.fullmatch(r"[a-z]+=(?:0|[1-9][0-9]*)", pair):
                raise ValueError("DESCRIPTOR_ANNOTATIONS")
            key, value = pair.split("=")
            if key in annotations or len(value) > 20:
                raise ValueError("DESCRIPTOR_ANNOTATIONS")
            annotations[key] = int(value)
    return segments[0], annotations


@dataclass(frozen=True, repr=False)
class Imported:
    descriptor: object
    annotations: dict
    spend_secret: int | None = None


def export(descriptor, spend_secret=None):
    a = descriptor.account
    if descriptor.network != GENESIS:
        raise ValueError("DESCRIPTOR_NETWORK")
    if spend_secret is None:
        key = encode("tspscan", ser(a.scan_secret) + a.spend_public)
    else:
        if pub(spend_secret) != a.spend_public:
            raise ValueError("DESCRIPTOR_SPEND_KEY")
        key = encode("tspspend", ser(a.scan_secret) + ser(spend_secret))
    origin = "[" + descriptor.origin + "]" if descriptor.origin else ""
    text = f"sp({origin}{key})?bh={a.birthday}&ml={max(a.labels, default=0)}"
    return text + "#" + checksum(text)


def parse(text, network=GENESIS, epoch=0):
    from ..descriptors import Descriptor

    expression, annotations = annotated(text)
    if network != GENESIS:
        raise ValueError("DESCRIPTOR_NETWORK")
    if not expression.startswith("sp(") or not expression.endswith(")"):
        raise ValueError("DESCRIPTOR_EXPRESSION")
    key = expression[3:-1]
    origin = None
    if key.startswith("["):
        end = key.find("]")
        if end < 0:
            raise ValueError("DESCRIPTOR_ORIGIN")
        origin = key[1:end]
        validate_origin(origin)
        key = key[end + 1 :]
    hrp = key.rpartition("1")[0]
    if hrp not in ("tspscan", "tspspend"):
        raise ValueError("DESCRIPTOR_UNSUPPORTED_KEY_EXPRESSION")
    raw = decode(key, hrp)
    spend = None
    if hrp == "tspscan":
        if len(raw) != 65:
            raise ValueError("DESCRIPTOR_KEY_LENGTH")
        scan = scalar(raw[:32])
        spend_public = compressed(raw[32:]).format()
    else:
        if len(raw) != 64:
            raise ValueError("DESCRIPTOR_KEY_LENGTH")
        scan, spend = scalar(raw[:32]), scalar(raw[32:])
        spend_public = pub(spend)
    maximum = annotations.get("ml", 0)
    birthday = annotations.get("bh", 0)
    if maximum > 1000:
        raise ValueError("DESCRIPTOR_LABEL_BUDGET")
    if not 0 <= birthday < 2**31:
        raise ValueError("DESCRIPTOR_BIRTHDAY")
    account = ScanAccount(epoch, scan, spend_public, max(1, birthday), tuple(range(1, maximum + 1)))
    return Imported(Descriptor(account, network, 1, origin), annotations, spend)
