"""BIP352 v0 derivation using native secp256k1 points. Experimental key custody."""

from dataclasses import dataclass
from hashlib import sha256, new
from coincurve import PrivateKey, PublicKey
from .codec import encode, decode
from .crypto import shared_point, secret_product
from .limits import DEFAULT, check_inputs

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
K_MAX = 2323
HRP = "wamrtsp"  # Unregistered draft namespace; regtest prototype only.
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def scalar(value):
    if isinstance(value, bytes):
        value = int.from_bytes(value, "big")
    if type(value) is not int or not 1 <= value < N:
        raise ValueError("INVALID_SCALAR")
    return value


def ser(value):
    return scalar(value).to_bytes(32, "big")


def tagged(tag, data):
    h = sha256(tag.encode()).digest()
    return sha256(h + h + data).digest()


def hash160(data):
    return new("ripemd160", sha256(data).digest()).digest()


def pub(secret):
    return PrivateKey(ser(secret)).public_key.format()


def compressed(key):
    if len(key) != 33 or key[0] not in (2, 3):
        raise ValueError("INVALID_PUBLIC_KEY")
    return PublicKey(key)


@dataclass(frozen=True, repr=False)
class Input:
    txid: str
    vout: int
    script: bytes
    script_sig: bytes = b""
    witness: tuple[bytes, ...] = ()
    secret: int | None = None

    def outpoint(self):
        if (
            not isinstance(self.txid, str)
            or len(self.txid) != 64
            or type(self.vout) is not int
            or not 0 <= self.vout < 2**32
        ):
            raise ValueError("INVALID_OUTPOINT")
        return bytes.fromhex(self.txid)[::-1] + self.vout.to_bytes(4, "little")

    def future_witness(self):
        s = self.script
        return 4 <= len(s) <= 42 and 0x52 <= s[0] <= 0x60 and s[1] == len(s) - 2

    def public_key(self):
        s, w = self.script, self.witness
        try:
            if len(s) == 34 and s[:2] == b"\x51\x20" and w:
                if len(w) > 1 and w[-1][:1] == b"\x50":
                    w = w[:-1]
                if len(w) > 1:
                    control = w[-1]
                    if (
                        not 33 <= len(control) <= 4129
                        or (len(control) - 33) % 32
                        or len(w[-2]) > 10000
                    ):
                        return None
                    if control[1:33] == NUMS:
                        return None
                return compressed(b"\x02" + s[2:]).format()
            if len(s) == 25 and s[:3] == b"\x76\xa9\x14" and s[-2:] == b"\x88\xac":
                for end in range(len(self.script_sig), 32, -1):
                    key = self.script_sig[end - 33 : end]
                    if hash160(key) == s[3:23]:
                        return compressed(key).format()
            if len(s) == 23 and s[:2] == b"\xa9\x14" and s[-1:] == b"\x87":
                redeem = self.script_sig[1:]
                if self.script_sig[:1] != b"\x16" or hash160(redeem) != s[2:22]:
                    return None
                s = redeem
            if len(s) == 22 and s[:2] == b"\x00\x14" and w:
                key = compressed(w[-1]).format()
                if hash160(key) == s[2:]:
                    return key
        except ValueError:
            return None
        return None


def input_context(inputs):
    check_inputs(inputs)
    if any(i.future_witness() for i in inputs):
        raise ValueError("INELIGIBLE_TRANSACTION")
    keys = [k for i in inputs if (k := i.public_key()) is not None]
    if not keys:
        raise ValueError("NO_ELIGIBLE_INPUTS")
    try:
        total = PublicKey.combine_keys([PublicKey(k) for k in keys])
    except ValueError:
        raise ValueError("INPUT_SUM_ZERO") from None
    h = scalar(tagged("BIP0352/Inputs", min(i.outpoint() for i in inputs) + total.format()))
    return total, h


def label_scalar(scan_secret, label):
    if type(label) is not int or not 0 <= label < 2**32:
        raise ValueError("INVALID_LABEL")
    return scalar(tagged("BIP0352/Label", ser(scan_secret) + label.to_bytes(4, "big")))


def address(scan_secret, spend_public, label=None, hrp=HRP):
    spend = compressed(spend_public)
    if label is not None:
        spend = spend.add(ser(label_scalar(scan_secret, label)))
    return encode(hrp, pub(scan_secret) + spend.format())


def decode_address(code, hrp=HRP):
    raw = decode(code, hrp)
    if len(raw) != 66:
        raise ValueError("INVALID_ADDRESS_LENGTH")
    return compressed(raw[:33]), compressed(raw[33:])


def send(inputs, recipients, hrp=HRP):
    """Freeze inputs/recipient order before signing ALL. Return x-only outputs in input recipient order."""
    if not recipients or len(recipients) > DEFAULT.max_outputs:
        raise ValueError("OUTPUT_LIMIT")
    total, h = input_context(inputs)
    secrets = []
    for i in inputs:
        key = i.public_key()
        if key is None:
            continue
        d = scalar(i.secret)
        p = pub(d)
        if i.script[:2] == b"\x51\x20" and p[0] == 3:
            d = N - d
        if pub(d) != key:
            raise ValueError("INPUT_KEY_MISMATCH")
        secrets.append(d)
    a = scalar(sum(secrets) % N)
    if pub(a) != total.format():
        raise ValueError("INPUT_KEY_MISMATCH")
    groups = {}
    result = []
    for code in recipients:
        scan, spend = decode_address(code, hrp)
        key = scan.format()
        if key not in groups:
            # BIP352 uses the RAW compressed shared POINT, never coincurve's hashed ECDH API.
            shared = shared_point(secret_product(ser(a), ser(h)), scan.format())
            groups[key] = [shared, 0]
        shared, k = groups[key]
        if k >= K_MAX:
            raise ValueError("RECIPIENT_LIMIT")
        t = scalar(tagged("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")))
        result.append(spend.add(ser(t)).format()[1:])
        groups[key][1] += 1
    return result


@dataclass(frozen=True, repr=False)
class Match:
    output_index: int
    public_key: bytes
    tweak: int
    label: int | None
    k: int


class Receiver:
    """Precomputed label table; bounded point work; no spending secret."""

    def __init__(self, scan_secret, spend_public, labels=(), limits=DEFAULT):
        self.scan_secret = scalar(scan_secret)
        self.spend = compressed(spend_public)
        self.limits = limits
        if len(labels) > limits.max_labels:
            raise ValueError("LABEL_LIMIT")
        self.label_points = {}
        self.bases = [(None, 0, self.spend)]
        for label in dict.fromkeys((0, *labels)):
            offset = label_scalar(scan_secret, label)
            self.label_points[pub(offset)] = (label, offset)
            self.bases.append((label, offset, self.spend.add(ser(offset))))
        self.operations = 0

    def _charge(self, n=1):
        self.operations += n
        if self.operations > self.limits.max_curve_operations:
            raise ValueError("SCAN_WORK_LIMIT")

    def scan_prepared(self, tweak_point, outputs):
        if len(outputs) > self.limits.max_outputs:
            raise ValueError("OUTPUT_LIMIT")
        self.operations = 0
        self._charge()
        shared = shared_point(ser(self.scan_secret), compressed(tweak_point).format())
        remaining = {}
        for i, output in enumerate(outputs):
            if len(output) != 32:
                raise ValueError("INVALID_OUTPUT")
            try:
                p = compressed(b"\x02" + output)
            except ValueError:
                continue
            if output not in remaining:
                remaining[output] = (p, [])
            remaining[output][1].append(i)
        found = []
        for k in range(K_MAX):
            if not remaining:
                break
            t = scalar(tagged("BIP0352/SharedSecret", shared + k.to_bytes(4, "big")))
            hit = None
            if len(self.bases) <= 2 * len(remaining):
                for label, offset, base in self.bases:
                    self._charge()
                    x = base.add(ser(t)).format()[1:]
                    if x in remaining:
                        hit = (x, (t + offset) % N, label)
                        break
            else:
                self._charge()
                point = self.spend.add(ser(t))
                x = point.format()[1:]
                if x in remaining:
                    hit = (x, t, None)
                else:
                    neg = point.format()
                    neg = PublicKey(bytes([neg[0] ^ 1]) + neg[1:])
                    for x, (output_point, _) in remaining.items():
                        raw = output_point.format()
                        for parity in (2, 3):
                            self._charge()
                            try:
                                delta = PublicKey.combine_keys(
                                    [PublicKey(bytes([parity]) + raw[1:]), neg]
                                ).format()
                            except ValueError:
                                continue
                            if delta in self.label_points:
                                label, offset = self.label_points[delta]
                                hit = (x, (t + offset) % N, label)
                                break
                        if hit:
                            break
            if hit is None:
                break
            x, tweak, label = hit
            for index in remaining.pop(x)[1]:
                found.append(Match(index, x, tweak, label, k))
        return found


def prepare(inputs):
    total, h = input_context(inputs)
    return total.multiply(ser(h)).format()


def scan(inputs, outputs, scan_secret, spend_public, labels=()):
    receiver = Receiver(scan_secret, spend_public, labels)
    try:
        tweak_point = prepare(inputs)
    except ValueError as e:
        if str(e) in {"INELIGIBLE_TRANSACTION", "NO_ELIGIBLE_INPUTS", "INPUT_SUM_ZERO"}:
            return []
        raise
    return receiver.scan_prepared(tweak_point, outputs)


def spending_key(spend_secret, match):
    secret = scalar((scalar(spend_secret) + match.tweak) % N)
    if pub(secret)[1:] != match.public_key:
        raise ValueError("SPEND_KEY_MISMATCH")
    return PrivateKey(ser(secret))
