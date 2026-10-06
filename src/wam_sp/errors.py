"""Stable public error classes. Messages carry fixed codes only."""

from enum import Enum
import re


class Category(str, Enum):
    PROTOCOL = "protocol"
    VALIDATION = "validation"
    CHAIN = "chain"
    RPC = "rpc"
    STORAGE = "storage"
    RECOVERY = "recovery"
    CRYPTO = "crypto"
    USER_INPUT = "user_input"
    COMPATIBILITY = "compatibility"


class WSPError(ValueError):
    def __init__(self, category, code):
        self.category = Category(category)
        if not isinstance(code, str) or not re.fullmatch("[A-Z][A-Z0-9_]{0,63}", code):
            code = "INTERNAL_ERROR"
        self.code = code
        super().__init__(code)


class StorageError(WSPError):
    def __init__(self, code):
        super().__init__(Category.STORAGE, code)
