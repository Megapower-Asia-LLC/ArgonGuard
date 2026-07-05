"""嚴格 PHC parser／encoder（SPEC §2、§4 S1–S4；baseline §1/§4）。

文法澄清（跨語言必須一致，由 baseline 文件釘死）：
- 數字欄位僅允許 [0-9]、無正負號、無前導零（單獨 "0" 除外）、位數上限 15（防溢位）
- base64 採 RFC 4648 §4 標準字元集、無 padding，且必須 canonical
  （decode 後 re-encode 必須等於原字串，封死 trailing-bit 可鍛性）；長度 mod 4 == 1 → 非法
- ``v`` 段存在時必須是第 3 段（``$alg$v=19$params$…``）且格式 ``v=<number>``
"""

import base64
import binascii
from typing import List, NamedTuple, Optional, Tuple

from ._errors import MalformedHashError
from ._reasons import BAD_BASE64, NOT_PHC, PARAMS_OUT_OF_ORDER

_LOWER_ALNUM_DASH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_DIGITS = frozenset("0123456789")


class PhcHash(NamedTuple):
    """嚴格解析後的 PHC argon2id 結構。"""

    algorithm: str
    version: Optional[int]
    m: int
    t: int
    p: int
    salt: bytes
    tag: bytes
    has_keyid: bool
    has_data: bool


def try_get_algorithm(encoded):
    # type: (str) -> Optional[str]
    """抽出 PHC 演算法 token（dispatch 前置判斷；baseline §1）。

    字串為 ``$<token>$…`` 且 token 合法（小寫英數與 '-'）時回傳 token，否則 None。
    token != "argon2id" → dispatch 走 UnsupportedAlgorithm 路徑，不套 argon2 嚴格文法。
    """
    if len(encoded) < 3 or encoded[0] != "$":
        return None
    end = encoded.find("$", 1)
    if end <= 1:
        return None
    token = encoded[1:end]
    for c in token:
        if c not in _LOWER_ALNUM_DASH:
            return None
    return token


def parse(encoded):
    # type: (str) -> PhcHash
    """嚴格解析。失敗拋 MalformedHashError（reason 依 SPEC）。長度預檢（>512）由呼叫端負責。"""
    if not encoded or encoded[0] != "$":
        raise MalformedHashError(NOT_PHC)

    parts = encoded.split("$")
    # ["", alg, "v=19", params, salt, tag]（有 v）或 ["", alg, params, salt, tag]（缺 v → 政策層 missing_version）
    if len(parts) not in (5, 6):
        raise MalformedHashError(NOT_PHC)

    algorithm = parts[1]
    if not algorithm:
        raise MalformedHashError(NOT_PHC)
    for c in algorithm:
        if c not in _LOWER_ALNUM_DASH:
            raise MalformedHashError(NOT_PHC)

    version = None  # type: Optional[int]
    params_index = 2
    if len(parts) == 6:
        if not parts[2].startswith("v="):
            raise MalformedHashError(NOT_PHC)
        version = _parse_number(parts[2][2:])
        params_index = 3

    m, t, p, has_keyid, has_data = _parse_params(parts[params_index])
    salt = _decode_canonical_base64(parts[params_index + 1])
    tag = _decode_canonical_base64(parts[params_index + 2])
    return PhcHash(algorithm, version, m, t, p, salt, tag, has_keyid, has_data)


def encode(m, t, p, salt, tag):
    # type: (int, int, int, bytes, bytes) -> str
    """產生端 encoder（SPEC §2 G1–G8）。"""
    return "$argon2id$v=19$m={0},t={1},p={2}${3}${4}".format(
        m, t, p, encode_base64_no_pad(salt), encode_base64_no_pad(tag))


def encode_base64_no_pad(data):
    # type: (bytes) -> str
    """RFC 4648 §4 標準字元集、去 padding。"""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _parse_params(param_segment):
    # type: (str) -> Tuple[int, int, int, bool, bool]
    tokens = param_segment.split(",")
    if len(tokens) < 3:
        raise MalformedHashError(
            PARAMS_OUT_OF_ORDER if _is_permuted_mtp(tokens) else NOT_PHC)

    # 前三個 token 必須依序為 m=、t=、p=（SPEC S1）
    if not (tokens[0].startswith("m=")
            and tokens[1].startswith("t=")
            and tokens[2].startswith("p=")):
        raise MalformedHashError(
            PARAMS_OUT_OF_ORDER if _is_permuted_mtp(tokens) else NOT_PHC)

    m = _parse_number(tokens[0][2:])
    t = _parse_number(tokens[1][2:])
    p = _parse_number(tokens[2][2:])

    has_keyid = False
    has_data = False
    for extra in tokens[3:]:
        if extra.startswith("keyid="):
            has_keyid = True
        elif extra.startswith("data="):
            has_data = True
        else:
            raise MalformedHashError(NOT_PHC)
    return m, t, p, has_keyid, has_data


def _is_permuted_mtp(tokens):
    # type: (List[str]) -> bool
    """前三 token 是否為 m/t/p 的重排（區分 params_out_of_order 與 not_phc）。"""
    if len(tokens) < 3:
        return False
    seen = 0
    for token in tokens[:3]:
        if token.startswith("m="):
            seen |= 1
        elif token.startswith("t="):
            seen |= 2
        elif token.startswith("p="):
            seen |= 4
        else:
            return False
    return seen == 7


def _parse_number(digits):
    # type: (str) -> int
    if len(digits) == 0 or len(digits) > 15:
        raise MalformedHashError(NOT_PHC)
    if len(digits) > 1 and digits[0] == "0":
        raise MalformedHashError(NOT_PHC)  # 禁前導零（嚴格文法）
    for c in digits:
        if c not in _DIGITS:  # 不用 str.isdigit()：它會接受非 ASCII 數字
            raise MalformedHashError(NOT_PHC)
    return int(digits)


def _decode_canonical_base64(segment):
    # type: (str) -> bytes
    if not segment:
        raise MalformedHashError(BAD_BASE64)
    for c in segment:
        if c not in _B64_ALPHABET:
            # 含 '='（padding）、base64url、其他字元一律拒絕
            raise MalformedHashError(BAD_BASE64)
    rem = len(segment) % 4
    if rem == 1:
        raise MalformedHashError(BAD_BASE64)
    padded = segment + "=" * ((4 - rem) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        raise MalformedHashError(BAD_BASE64)
    # canonical 檢查：re-encode 必須還原原字串（封死 trailing-bit 可鍛性）
    if encode_base64_no_pad(decoded) != segment:
        raise MalformedHashError(BAD_BASE64)
    return decoded
