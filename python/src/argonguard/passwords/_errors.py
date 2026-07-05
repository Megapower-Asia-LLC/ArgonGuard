"""ArgonGuard typed errors（SPEC §7）。

五類別；每個錯誤帶機器可讀 ``reason``（權威：spec/reason-codes.json）。
訊息不得含密碼、salt 或 tag（OWASP Error Handling；SEC-006）。
"""


class ArgonGuardError(Exception):
    """Typed error 基底；``reason`` 為跨語言 bit-identical 的 reason code。"""

    #: 跨語言類別名（harness 協議中的 error 欄位；無 "Error" 後綴）。
    category = "ArgonGuard"

    def __init__(self, reason, message=None):
        # type: (str, str) -> None
        super(ArgonGuardError, self).__init__(message if message is not None else reason)
        self.reason = reason


class MalformedHashError(ArgonGuardError):
    """無法以嚴格文法解析為 PHC argon2id 字串（SPEC §7 MalformedHash）。"""

    category = "MalformedHash"

    def __init__(self, reason):
        # type: (str) -> None
        super(MalformedHashError, self).__init__(
            reason, "Encoded hash is malformed ({0}).".format(reason))


class UnsupportedAlgorithmError(ArgonGuardError):
    """可解析但演算法非 argon2id，且無 legacy verifier 認領（SPEC §7）。"""

    category = "UnsupportedAlgorithm"

    def __init__(self, reason):
        # type: (str) -> None
        super(UnsupportedAlgorithmError, self).__init__(
            reason, "Hash algorithm is not supported ({0}).".format(reason))


class PolicyViolationError(ArgonGuardError):
    """合法 argon2id 但參數落在驗證政策之外，且無 legacy verifier 認領（SPEC §4/§7）。"""

    category = "PolicyViolation"

    def __init__(self, reason):
        # type: (str) -> None
        super(PolicyViolationError, self).__init__(
            reason, "Hash parameters violate the verification policy ({0}).".format(reason))


class InvalidInputError(ArgonGuardError):
    """密碼輸入違反輸入正規化規則（SPEC §5/§7）。"""

    category = "InvalidInput"

    def __init__(self, reason):
        # type: (str) -> None
        super(InvalidInputError, self).__init__(
            reason, "Password input is invalid ({0}).".format(reason))


class UnsupportedEnvironmentError(ArgonGuardError):
    """執行環境無法提供 argon2id（SPEC §7；Python 引擎為 argon2-cffi，缺件時 fail-fast）。"""

    category = "UnsupportedEnvironment"

    def __init__(self, reason):
        # type: (str) -> None
        super(UnsupportedEnvironmentError, self).__init__(
            reason, "Environment cannot provide argon2id ({0}).".format(reason))
