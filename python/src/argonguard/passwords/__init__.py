"""ArgonGuard passwords — OWASP-compliant Argon2id password hashing.

Implements ArgonGuard Spec 1.0（spec/SPEC.md；行為 bit-identical 跟隨 .NET 參考實作
baseline，spec/reference/dotnet-baseline.md）。

`argonguard` 為 PEP 420 namespace package（無 __init__.py），
替未來 argonguard-tokens 等產品線預留同一 namespace。

標準升級流程（SPEC §6.1）::

    if hasher.verify_password(pw, stored):
        if hasher.needs_rehash(stored):
            store(hasher.hash_password(pw))
        login_ok()
"""

from ._errors import (
    ArgonGuardError,
    InvalidInputError,
    MalformedHashError,
    PolicyViolationError,
    UnsupportedAlgorithmError,
    UnsupportedEnvironmentError,
)
from ._hasher import ArgonGuardPasswordHasher
from ._legacy import LegacyPasswordVerifier
from ._profiles import ArgonGuardProfile

#: ArgonGuard 規格版本（SPEC §9）。
SPEC_VERSION = "1.0.0"

__all__ = [
    "SPEC_VERSION",
    "ArgonGuardPasswordHasher",
    "ArgonGuardProfile",
    "LegacyPasswordVerifier",
    "ArgonGuardError",
    "MalformedHashError",
    "UnsupportedAlgorithmError",
    "PolicyViolationError",
    "InvalidInputError",
    "UnsupportedEnvironmentError",
]
