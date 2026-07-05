"""Internal engine provider（SPEC §8.5）：argon2 引擎藏在內部邊界，型別不得漏進公開 API。

Python 引擎＝argon2-cffi ``argon2.low_level.hash_secret_raw``
（type=Type.ID、version=19、memory_cost 單位 KiB；見 spec/engine-units.json
``python_argon2_cffi_memory_cost``）。
"""

from ._errors import UnsupportedEnvironmentError
from ._reasons import ARGON2ID_UNAVAILABLE


class Argon2CffiProvider(object):
    """argon2-cffi raw-tag provider。缺件時 fail-fast（UnsupportedEnvironment）。"""

    def __init__(self):
        # type: () -> None
        try:
            from argon2 import low_level
        except ImportError:
            raise UnsupportedEnvironmentError(ARGON2ID_UNAVAILABLE)
        self._low_level = low_level

    def hash_raw(self, password, salt, m, t, p, tag_length):
        # type: (bytes, bytes, int, int, int, int) -> bytes
        """以 Argon2id（v=19）計算 raw tag；``m`` 單位 KiB。"""
        low_level = self._low_level
        return low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=tag_length,
            type=low_level.Type.ID,
            version=19,
        )
