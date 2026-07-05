"""ArgonGuard 密碼雜湊器（Python 實作；行為 bit-identical 跟隨 .NET 參考實作 baseline）。

標準升級流程（SPEC §6.1）::

    if hasher.verify_password(pw, stored):
        if hasher.needs_rehash(stored):
            store(hasher.hash_password(pw))
        login_ok()
"""

import hmac
import os
from typing import Iterable, Optional, Tuple, Union

from ._engine import Argon2CffiProvider
from ._errors import (
    InvalidInputError,
    MalformedHashError,
    PolicyViolationError,
    UnsupportedAlgorithmError,
)
from ._legacy import LegacyPasswordVerifier
from ._phc import encode, parse, try_get_algorithm
from ._policy import MAX_ENCODED_LENGTH, REQUIRED_VERSION, check
from ._profiles import ArgonGuardProfile, parameters_for
from ._reasons import (
    NOT_PHC,
    ENCODED_TOO_LONG,
    PASSWORD_CONTAINS_NUL,
    PASSWORD_EMPTY,
    PASSWORD_NOT_WELL_FORMED,
    PASSWORD_TOO_LONG,
    UNSUPPORTED_ALGORITHM,
)

_MIN_PASSWORD_BYTES = 1
_MAX_PASSWORD_BYTES = 1024


class ArgonGuardPasswordHasher(object):
    """ArgonGuard 密碼雜湊器（SPEC §6）。

    :param profile: 強度檔位（預設 :data:`ArgonGuardProfile.DEFAULT`）。
    :param legacy_verifiers: Legacy verifier 有序清單；建構時複製為不可變 tuple（SPEC L1，
        runtime 註冊在 API 形狀上即不可能）。
    """

    def __init__(self, profile=ArgonGuardProfile.DEFAULT, legacy_verifiers=()):
        # type: (Union[ArgonGuardProfile, str], Iterable[LegacyPasswordVerifier]) -> None
        self._profile = ArgonGuardProfile(profile)
        self._active = parameters_for(self._profile)
        self._legacy_verifiers = _copy_verifiers(legacy_verifiers)
        self._engine = Argon2CffiProvider()

    @property
    def active_profile(self):
        # type: () -> ArgonGuardProfile
        """現行 active 檔位。"""
        return self._profile

    def hash_password(self, password):
        # type: (str) -> str
        """以 active 檔位＋新鮮 16-byte CSPRNG salt 產生 PHC 編碼雜湊（SPEC §2、§6.1）。"""
        password_bytes = _validate_password(password)
        salt = os.urandom(self._active.salt_bytes)  # CSPRNG（SPEC §8.2）
        tag = self._engine.hash_raw(
            password_bytes, salt,
            self._active.m, self._active.t, self._active.p, self._active.tag_bytes)
        return encode(self._active.m, self._active.t, self._active.p, salt, tag)

    def verify_password(self, password, encoded_hash):
        # type: (str, str) -> bool
        """驗證密碼（SPEC §6.2 dispatch）。

        回傳 False 只有一個意思：格式正確、政策合規、但密碼不符（SPEC V1）。
        其餘情況一律拋 typed error。
        """
        password_bytes = _validate_password(password)
        if encoded_hash is None:
            raise MalformedHashError(NOT_PHC)

        # SPEC §6.2 步驟 2：解析前長度預檢
        if len(encoded_hash.encode("utf-8", "surrogatepass")) > MAX_ENCODED_LENGTH:
            raise MalformedHashError(ENCODED_TOO_LONG)

        # §6.2 3b 前置：演算法 token 判斷（非 argon2id 不套 argon2 嚴格文法；baseline §1）
        algorithm = try_get_algorithm(encoded_hash)
        if algorithm != "argon2id":
            claimed, result = self._try_legacy(password, encoded_hash)
            if claimed:
                return result
            if algorithm is None:
                raise MalformedHashError(NOT_PHC)
            raise UnsupportedAlgorithmError(UNSUPPORTED_ALGORITHM)

        try:
            parsed = parse(encoded_hash)
        except MalformedHashError:
            # §6.2 3b：argon2id 但嚴格文法解析失敗 → legacy；無人認領 → 原 MalformedHash
            claimed, result = self._try_legacy(password, encoded_hash)
            if claimed:
                return result
            raise

        violation = check(parsed)
        if violation is not None:
            # §6.2 3a：out-of-policy argon2id → 顯式註冊的 legacy 才可認領（看得見的 opt-in）
            claimed, result = self._try_legacy(password, encoded_hash)
            if claimed:
                return result
            raise PolicyViolationError(violation)

        recomputed = self._engine.hash_raw(
            password_bytes, parsed.salt, parsed.m, parsed.t, parsed.p, len(parsed.tag))
        # constant-time tag 比對（SPEC §8.1）
        return hmac.compare_digest(parsed.tag, recomputed)

    def needs_rehash(self, encoded_hash):
        # type: (str) -> bool
        """雜湊是否非以現行 active 檔位精確參數產生（SPEC §6.3；只 parse 不雜湊）。"""
        if encoded_hash is None:
            raise MalformedHashError(NOT_PHC)
        if len(encoded_hash.encode("utf-8", "surrogatepass")) > MAX_ENCODED_LENGTH:
            raise MalformedHashError(ENCODED_TOO_LONG)

        algorithm = try_get_algorithm(encoded_hash)
        if algorithm != "argon2id":
            # SPEC §6.3 N2：legacy 認領恆 True
            if self._is_claimed_by_legacy(encoded_hash):
                return True
            if algorithm is None:
                raise MalformedHashError(NOT_PHC)
            raise UnsupportedAlgorithmError(UNSUPPORTED_ALGORITHM)

        try:
            parsed = parse(encoded_hash)
        except MalformedHashError:
            # SPEC §6.3 N3：無人認領＝資料毀損，不得折疊成 True
            if self._is_claimed_by_legacy(encoded_hash):
                return True
            raise

        # 精確參數比對（baseline §5；任一欄位不同即 True——含「更強」的情況，SPEC §6.3）
        return (parsed.version != REQUIRED_VERSION
                or parsed.has_keyid or parsed.has_data
                or parsed.m != self._active.m
                or parsed.t != self._active.t
                or parsed.p != self._active.p
                or len(parsed.salt) != self._active.salt_bytes
                or len(parsed.tag) != self._active.tag_bytes)

    def _hash_password_with_salt(self, password_bytes, salt, m, t, p, tag_length):
        # type: (bytes, bytes, int, int, int, int) -> str
        """Conformance 測試專用：固定 salt 重現 deterministic 向量。非公開 API。"""
        tag = self._engine.hash_raw(password_bytes, salt, m, t, p, tag_length)
        return encode(m, t, p, salt, tag)

    def _try_legacy(self, password, encoded_hash):
        # type: (str, str) -> Tuple[bool, bool]
        for verifier in self._legacy_verifiers:
            if verifier.can_handle(encoded_hash):
                # 第一個認領者裁決（SPEC §6.2）
                return True, verifier.verify(password, encoded_hash)
        return False, False

    def _is_claimed_by_legacy(self, encoded_hash):
        # type: (str) -> bool
        for verifier in self._legacy_verifiers:
            if verifier.can_handle(encoded_hash):
                return True
        return False


def _validate_password(password):
    # type: (Optional[str]) -> bytes
    """SPEC §5 輸入規則。檢查優先序（baseline §2）：well-formed → empty → too_long → NUL。"""
    if password is None:
        raise InvalidInputError(PASSWORD_EMPTY)
    if not isinstance(password, str):
        raise TypeError("password must be str, not {0}".format(type(password).__name__))
    try:
        # lone surrogate → UnicodeEncodeError（Python str.encode 天然攔截，baseline §2）
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidInputError(PASSWORD_NOT_WELL_FORMED)
    if len(password_bytes) < _MIN_PASSWORD_BYTES:
        raise InvalidInputError(PASSWORD_EMPTY)
    if len(password_bytes) > _MAX_PASSWORD_BYTES:
        raise InvalidInputError(PASSWORD_TOO_LONG)
    if b"\x00" in password_bytes:
        raise InvalidInputError(PASSWORD_CONTAINS_NUL)
    return password_bytes


def _copy_verifiers(legacy_verifiers):
    # type: (Iterable[LegacyPasswordVerifier]) -> Tuple[LegacyPasswordVerifier, ...]
    if legacy_verifiers is None:
        return ()
    verifiers = tuple(legacy_verifiers)
    for verifier in verifiers:
        if verifier is None:
            raise ValueError("legacy_verifiers contains None")
    return verifiers
