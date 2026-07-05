"""API 形狀／規格對齊測試：SPEC_VERSION、profile 哨兵、reason code 權威對齊、
legacy 擴充點語意、錯誤訊息不外洩（SEC-006）。"""

import pytest

import argonguard.passwords as ag
from argonguard.passwords import (
    ArgonGuardError,
    ArgonGuardPasswordHasher,
    ArgonGuardProfile,
    InvalidInputError,
    MalformedHashError,
    PolicyViolationError,
    UnsupportedAlgorithmError,
    UnsupportedEnvironmentError,
)
from argonguard.passwords import _reasons
from argonguard.passwords._profiles import parameters_for

from conftest import FakeBcryptVerifier, load_spec_json

REASON_CODES = load_spec_json("reason-codes.json")
ENGINE_UNITS = load_spec_json("engine-units.json")

GOOD = ("$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
        "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE")
BCRYPT = "$2b$12$LQVkVYq1S7Ck1MQIViYyNOG3Fabe/y0BB6kJ1O8ZQNXY9nCzC1jU6"


# ---------------------------------------------------------------- 版本與哨兵

def test_spec_version():
    assert ag.SPEC_VERSION == "1.0.0"


def test_default_profile_permanent_sentinel():
    """SPEC P1：default 必須等於 (m=19456, t=2, p=1) —— 永久哨兵。"""
    params = parameters_for(ArgonGuardProfile.DEFAULT)
    assert (params.m, params.t, params.p) == (19456, 2, 1)


@pytest.mark.parametrize("profile", list(ArgonGuardProfile))
def test_profiles_match_engine_units(profile):
    """檔位常數以 spec/engine-units.json 為權威（SPEC §10 條款 4）。"""
    authoritative = ENGINE_UNITS["profiles"][profile.value]
    params = parameters_for(profile)
    assert params.m == authoritative["m_kib"]
    assert params.t == authoritative["t"]
    assert params.p == authoritative["p"]
    assert params.salt_bytes == authoritative["saltBytes"]
    assert params.tag_bytes == authoritative["tagBytes"]


def test_profile_closed_set():
    assert [p.value for p in ArgonGuardProfile] == ["default", "high", "highest"]
    with pytest.raises(ValueError):
        ArgonGuardPasswordHasher("paranoid")


# ------------------------------------------------------ reason code 權威對齊

def test_reason_constants_bit_identical_to_authority():
    """實作 emit 的每個 reason code 必須一字不差存在於 reason-codes.json。"""
    authoritative = set()
    for category in REASON_CODES["categories"].values():
        authoritative.update(category["codes"])
    emitted = {value for name, value in vars(_reasons).items()
               if name.isupper() and isinstance(value, str)}
    assert emitted == authoritative


def test_error_category_names_match_authority():
    categories = set(REASON_CODES["categories"].keys())
    classes = [MalformedHashError, UnsupportedAlgorithmError, PolicyViolationError,
               InvalidInputError, UnsupportedEnvironmentError]
    assert {cls.category for cls in classes} == categories
    for cls in classes:
        assert issubclass(cls, ArgonGuardError)


# ------------------------------------------------------------------ 核心行為

def test_hash_password_shape_and_roundtrip():
    hasher = ArgonGuardPasswordHasher()
    encoded = hasher.hash_password("password")
    assert encoded.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert len(encoded) <= 128
    assert hasher.verify_password("password", encoded) is True
    assert hasher.verify_password("wrongpass", encoded) is False
    assert hasher.needs_rehash(encoded) is False


def test_hash_password_fresh_salt_each_call():
    hasher = ArgonGuardPasswordHasher()
    assert hasher.hash_password("password") != hasher.hash_password("password")


def test_verify_none_encoded_is_malformed():
    hasher = ArgonGuardPasswordHasher()
    with pytest.raises(MalformedHashError) as excinfo:
        hasher.verify_password("password", None)
    assert excinfo.value.reason == "malformed.not_phc"


def test_needs_rehash_performs_no_input_validation_on_password():
    """needs_rehash 只收 encoded；不碰密碼、不做雜湊（SPEC N4）。"""
    hasher = ArgonGuardPasswordHasher()
    assert hasher.needs_rehash(GOOD) is False


# ------------------------------------------------------------- legacy 擴充點

class ClaimAllVerifier(object):
    def __init__(self, result):
        self.result = result
        self.calls = []

    def can_handle(self, encoded_hash):
        return True

    def verify(self, password, encoded_hash):
        self.calls.append((password, encoded_hash))
        return self.result


def test_legacy_first_claimer_decides():
    first = ClaimAllVerifier(True)
    second = ClaimAllVerifier(False)
    hasher = ArgonGuardPasswordHasher(legacy_verifiers=[first, second])
    assert hasher.verify_password("password", BCRYPT) is True
    assert len(first.calls) == 1
    assert second.calls == []


def test_legacy_claims_malformed_string():
    """§6.2 3b：解析失敗但 legacy 認領 → legacy 裁決。"""
    hasher = ArgonGuardPasswordHasher(legacy_verifiers=[ClaimAllVerifier(True)])
    assert hasher.verify_password("password", "corrupted-data") is True


def test_legacy_claims_out_of_policy_argon2id():
    """§6.2 3a／V2：out-of-policy argon2id 只能靠顯式註冊的 legacy 認領。"""
    below = ("$argon2id$v=19$m=7167,t=5,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
             "$gEkx/ZcpZoyfeXjMLmin/VppPqbqHaqxdxI5ogIawNc")
    hasher = ArgonGuardPasswordHasher(legacy_verifiers=[ClaimAllVerifier(False)])
    assert hasher.verify_password("password", below) is False


def test_legacy_does_not_intercept_in_policy_argon2id():
    """V2：in-policy argon2id 恆走核心路徑，legacy 不得攔截。"""
    claimer = ClaimAllVerifier(False)
    hasher = ArgonGuardPasswordHasher(legacy_verifiers=[claimer])
    assert hasher.verify_password("password", GOOD) is True
    assert claimer.calls == []


def test_legacy_list_copied_at_construction():
    """SPEC L1：建構時複製；事後改動原 list 不影響 hasher。"""
    verifiers = [FakeBcryptVerifier()]
    hasher = ArgonGuardPasswordHasher(legacy_verifiers=verifiers)
    verifiers.clear()  # runtime 移除不可能
    assert hasher.needs_rehash(BCRYPT) is True


def test_legacy_none_entry_rejected():
    with pytest.raises(ValueError):
        ArgonGuardPasswordHasher(legacy_verifiers=[None])


# ------------------------------------------------- 錯誤訊息不外洩（SEC-006）

def test_error_messages_do_not_leak_salt_or_tag():
    hasher = ArgonGuardPasswordHasher()
    below = ("$argon2id$v=19$m=7167,t=5,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
             "$gEkx/ZcpZoyfeXjMLmin/VppPqbqHaqxdxI5ogIawNc")
    with pytest.raises(PolicyViolationError) as excinfo:
        hasher.verify_password("s3cret-password", below)
    message = str(excinfo.value)
    assert "QXJvbkd1YXJkVjFTMDEhIQ" not in message
    assert "gEkx" not in message
    assert "s3cret-password" not in message
    assert excinfo.value.reason in message  # reason code 本身可出現


# ---------------------------------------------------------- 引擎邊界（§8.5）

def test_engine_not_exposed_in_public_api():
    public = [name for name in dir(ag) if not name.startswith("_")]
    assert "Argon2CffiProvider" not in public
    assert set(ag.__all__).issubset(set(public))
    # hasher 實例的公開屬性也不得漏出引擎型別
    hasher = ArgonGuardPasswordHasher()
    instance_public = [n for n in vars(hasher) if not n.startswith("_")]
    assert instance_public == []


def test_password_must_be_str():
    hasher = ArgonGuardPasswordHasher()
    with pytest.raises(TypeError):
        hasher.hash_password(b"password")
