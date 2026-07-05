"""強度檔位（閉集；SPEC §3）。公開 API 不暴露任何數字參數。

常數與 spec/engine-units.json 一致（conformance 測試互相印證）。
"""

from enum import Enum
from typing import NamedTuple, Union


class ArgonGuardProfile(str, Enum):
    """強度檔位（閉集）。"""

    #: m=19456 KiB, t=2, p=1 —— OWASP 等效最低配置的 canonical 一組（永久哨兵）。
    DEFAULT = "default"
    #: m=65536 KiB (64 MiB), t=2, p=1。
    HIGH = "high"
    #: m=131072 KiB (128 MiB), t=2, p=1。
    HIGHEST = "highest"


class ProfileParameters(NamedTuple):
    """檔位參數常數（KiB／bytes；與 spec/engine-units.json 一致）。"""

    m: int
    t: int
    p: int
    salt_bytes: int
    tag_bytes: int


_PROFILE_PARAMETERS = {
    ArgonGuardProfile.DEFAULT: ProfileParameters(19456, 2, 1, 16, 32),
    ArgonGuardProfile.HIGH: ProfileParameters(65536, 2, 1, 16, 32),
    ArgonGuardProfile.HIGHEST: ProfileParameters(131072, 2, 1, 16, 32),
}


def parameters_for(profile):
    # type: (Union[ArgonGuardProfile, str]) -> ProfileParameters
    """取檔位參數；未知檔位拋 ValueError（非 SPEC 錯誤類別：屬呼叫端程式錯誤）。"""
    return _PROFILE_PARAMETERS[ArgonGuardProfile(profile)]
