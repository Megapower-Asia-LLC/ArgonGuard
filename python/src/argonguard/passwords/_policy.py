"""驗證端參數政策（SPEC §4）：OWASP frontier 凍結表（地板）＋天花板（DoS 防護）。

純函式、無雜湊運算。常數與 spec/engine-units.json 一致（conformance 互相印證）。
"""

from typing import Optional

from ._phc import PhcHash
from ._reasons import (
    BELOW_OWASP_FRONTIER,
    DATA_NOT_ALLOWED,
    KEYID_NOT_ALLOWED,
    M_ABOVE_CEILING,
    MISSING_VERSION,
    P_NOT_ONE,
    SALT_LENGTH_OUT_OF_RANGE,
    T_ABOVE_CEILING,
    TAG_LENGTH_OUT_OF_RANGE,
    UNSUPPORTED_VERSION,
)

MAX_M = 262144
MAX_T = 8
MIN_SALT_BYTES = 16
MAX_SALT_BYTES = 64
MIN_TAG_BYTES = 32
MAX_TAG_BYTES = 128
MAX_ENCODED_LENGTH = 512
REQUIRED_VERSION = 19


def frontier_min_m(t):
    # type: (int) -> int
    """OWASP frontier（查證 2026-07-05；spec MINOR 才可調整）。"""
    if t == 1:
        return 47104
    if t == 2:
        return 19456
    if t == 3:
        return 12288
    if t == 4:
        return 9216
    return 7168  # t >= 5


def check(parsed):
    # type: (PhcHash) -> Optional[str]
    """政策檢查。回傳 None＝通過；否則回傳 reason code（呼叫端決定 dispatch 或拋錯）。

    檢查順序（跨語言一致，baseline §3 釘死）：
    版本 → keyid/data → p → 天花板(t→m) → frontier → salt → tag。
    """
    if parsed.version is None:
        return MISSING_VERSION
    if parsed.version != REQUIRED_VERSION:
        return UNSUPPORTED_VERSION
    if parsed.has_keyid:
        return KEYID_NOT_ALLOWED
    if parsed.has_data:
        return DATA_NOT_ALLOWED
    if parsed.p != 1:
        return P_NOT_ONE
    if parsed.t > MAX_T:
        return T_ABOVE_CEILING
    if parsed.m > MAX_M:
        return M_ABOVE_CEILING
    if parsed.t < 1 or parsed.m < frontier_min_m(parsed.t):
        return BELOW_OWASP_FRONTIER
    if len(parsed.salt) < MIN_SALT_BYTES or len(parsed.salt) > MAX_SALT_BYTES:
        return SALT_LENGTH_OUT_OF_RANGE
    if len(parsed.tag) < MIN_TAG_BYTES or len(parsed.tag) > MAX_TAG_BYTES:
        return TAG_LENGTH_OUT_OF_RANGE
    return None
