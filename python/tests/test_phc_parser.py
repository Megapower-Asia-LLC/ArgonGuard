"""嚴格 PHC parser 單元測試：合法／非法路徑（SPEC §4 S1–S4；baseline §1/§4）。"""

import pytest

from argonguard.passwords import MalformedHashError
from argonguard.passwords._phc import (
    encode,
    encode_base64_no_pad,
    parse,
    try_get_algorithm,
)

GOOD = ("$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
        "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE")


# ------------------------------------------------------- try_get_algorithm（baseline §1）

@pytest.mark.parametrize("encoded,expected", [
    (GOOD, "argon2id"),
    ("$argon2i$v=19$m=1,t=1,p=1$aa$bb", "argon2i"),
    ("$2b$12$LQVkVYq1S7Ck1MQIViYyNO", "2b"),
    ("$scrypt-x$rest", "scrypt-x"),      # '-' 為合法 token 字元
    ("", None),                          # 太短
    ("$a", None),                        # 無第二個 '$'
    ("$$rest", None),                    # 空 token
    ("not-a-hash-at-all", None),         # 非 '$' 開頭
    ("corrupted-data", None),
    ("$Argon2id$rest", None),            # 大寫非法
    ("$argon2_id$rest", None),           # '_' 非法
    ("$argon2 id$rest", None),           # 空白非法
])
def test_try_get_algorithm(encoded, expected):
    assert try_get_algorithm(encoded) == expected


# ------------------------------------------------------------------- 合法路徑

def test_parse_full_form():
    parsed = parse(GOOD)
    assert parsed.algorithm == "argon2id"
    assert parsed.version == 19
    assert (parsed.m, parsed.t, parsed.p) == (19456, 2, 1)
    assert len(parsed.salt) == 16
    assert len(parsed.tag) == 32
    assert parsed.has_keyid is False
    assert parsed.has_data is False


def test_parse_missing_version_defers_to_policy():
    """缺 v 段仍可嚴格解析（version=None），由政策層回報 missing_version。"""
    parsed = parse("$argon2id$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
                   "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE")
    assert parsed.version is None
    assert (parsed.m, parsed.t, parsed.p) == (19456, 2, 1)


def test_parse_keyid_and_data_flags():
    base = "$argon2id$v=19$m=19456,t=2,p=1,{0}$QXJvbkd1YXJkVjFTMDEhIQ" \
           "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE"
    assert parse(base.format("keyid=Zm9v")).has_keyid is True
    assert parse(base.format("data=Zm9v")).has_data is True
    both = parse(base.format("keyid=Zm9v,data=Zm9v"))
    assert both.has_keyid is True and both.has_data is True


def test_parse_binary_salt_roundtrip():
    """det-ascii-default-binsalt 的非 ASCII salt 必須正確解碼。"""
    parsed = parse("$argon2id$v=19$m=19456,t=2,p=1$8f8Q4Add76ztsN6tvu8TNw"
                   "$Wep65eOPOEiDU3sNuuxocTh/0nOh8HNHDM4lzSMXkrg")
    assert parsed.salt == bytes.fromhex("f1ff10e0075defacedb0deadbeef1337")


def test_parse_zero_value_allowed_by_grammar():
    """單獨 '0' 合法（政策層才拒絕）。"""
    parsed = parse("$argon2id$v=19$m=0,t=0,p=0$QXJvbkd1YXJkVjFTMDEhIQ"
                   "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE")
    assert (parsed.m, parsed.t, parsed.p) == (0, 0, 0)


def test_encode_matches_spec_shape():
    salt = bytes.fromhex("41726f6e477561726456315330312121")
    tag = bytes(range(32))
    encoded = encode(19456, 2, 1, salt, tag)
    assert encoded.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    salt_segment, tag_segment = encoded.split("$")[4:6]
    assert "=" not in salt_segment and "=" not in tag_segment  # no padding（G5）
    assert parse(encoded).salt == salt
    assert parse(encoded).tag == tag


def test_encode_base64_no_pad():
    assert encode_base64_no_pad(b"\x00") == "AA"
    assert encode_base64_no_pad(bytes.fromhex("41726f6e477561726456315330312121")) \
        == "QXJvbkd1YXJkVjFTMDEhIQ"


# ------------------------------------------------------------------- 非法路徑

def _reason(encoded):
    with pytest.raises(MalformedHashError) as excinfo:
        parse(encoded)
    return excinfo.value.reason


@pytest.mark.parametrize("encoded", [
    "",                                     # 空字串
    "not-a-hash-at-all",                    # 非 '$' 開頭
    "$argon2id$v=19$m=19456,t=2,p=1$salt!$tag$extra",  # 段數 7
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ",  # 段數 4（缺 tag）
    "$argon2id",                            # 段數 2
    "$Argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 演算法大寫
    "$$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 空演算法
    "$argon2id$x=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # v 段格式錯
    "$argon2id$v=19$m=019456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 前導零
    "$argon2id$v=19$m=,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 空數字
    "$argon2id$v=19$m=1234567890123456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 16 位數
    "$argon2id$v=19$m=+19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 帶正號
    "$argon2id$v=19$m=١٩,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 非 ASCII 數字
    "$argon2id$v=19$m=19456,t=2$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 只有 m,t
    "$argon2id$v=19$m=19456,t=2,p=1,x=9$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 第 4 token 非 keyid/data
    "$argon2id$v=19$x=1,y=2,z=3$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 非 m/t/p token
])
def test_parse_not_phc(encoded):
    assert _reason(encoded) == "malformed.not_phc"


@pytest.mark.parametrize("encoded", [
    "$argon2id$v=19$t=2,m=19456,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # t,m,p
    "$argon2id$v=19$p=1,t=2,m=19456$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # p,t,m
    "$argon2id$v=19$m=19456,p=1,t=2$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # m,p,t
])
def test_parse_params_out_of_order(encoded):
    assert _reason(encoded) == "malformed.params_out_of_order"


@pytest.mark.parametrize("encoded", [
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ==$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # padding
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$-_ERERERERERERERERERERERERERERERERERERERERE",  # base64url
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7Zca",  # len%4==1（43→42 非，取 41）
    "$argon2id$v=19$m=19456,t=2,p=1$$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 空 salt 段
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIR$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 非 canonical trailing bits
    "$argon2id$v=19$m=19456,t=2,p=1$AB$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 非 canonical（AB→AA）
    "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJk VjFTMDEhIQ$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE",  # 空白字元
])
def test_parse_bad_base64(encoded):
    assert _reason(encoded) == "malformed.bad_base64"


def test_parse_len_mod4_check():
    """長度 mod 4 == 1 → 非法（41 字元 tag）。"""
    tag41 = "IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7Zc"
    assert len(tag41) % 4 == 1
    encoded = "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ${0}".format(tag41)
    assert _reason(encoded) == "malformed.bad_base64"
