"""SUMIT KEY Lightweight SDK

Single external dependency: cryptography

Usage:
    from sdk import SumitKey
    sk = SumitKey()
    key = sk.new_key()
    pkg = sk.encrypt("hello", key)
    msg = sk.decrypt(pkg, key)
"""
from sdk.core import SumitKey, SumitKeyError

__all__ = ["SumitKey", "SumitKeyError"]
__version__ = "1.0.0"
