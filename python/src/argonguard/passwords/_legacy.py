"""Legacy 擴充點（SPEC §6.4）：verify-only、建構時注入不可變清單。

核心不出貨任何 legacy 演算法實作（SPEC L3）；文件提供完整範例（如 bcrypt）。
"""

from typing import Protocol


class LegacyPasswordVerifier(Protocol):
    """Legacy verifier 介面（SPEC L2）：``can_handle`` 為廉價前綴測試；``verify`` 做實際驗證。"""

    def can_handle(self, encoded_hash):
        # type: (str) -> bool
        """此 verifier 是否認領該編碼字串（廉價前綴測試）。"""
        ...

    def verify(self, password, encoded_hash):
        # type: (str, str) -> bool
        """驗證密碼是否符合該 legacy 雜湊。"""
        ...
