"""政策層單元測試：每維度 reason code ＋ 裁決順序（SPEC §4；baseline §3）。

常數斷言以 spec/engine-units.json 為權威（SPEC §10 條款 4）。
"""

import pytest

from argonguard.passwords import _policy
from argonguard.passwords._phc import PhcHash

from conftest import load_spec_json

ENGINE_UNITS = load_spec_json("engine-units.json")


def make(version=19, m=19456, t=2, p=1, salt_len=16, tag_len=32,
         has_keyid=False, has_data=False):
    return PhcHash("argon2id", version, m, t, p,
                   b"\x00" * salt_len, b"\x00" * tag_len, has_keyid, has_data)


# ----------------------------------------------------------------- 每維度 reason

def test_pass_returns_none():
    assert _policy.check(make()) is None


def test_missing_version():
    assert _policy.check(make(version=None)) == "policy_violation.missing_version"


@pytest.mark.parametrize("version", [16, 18, 20])
def test_unsupported_version(version):
    assert _policy.check(make(version=version)) == "policy_violation.unsupported_version"


def test_keyid_not_allowed():
    assert _policy.check(make(has_keyid=True)) == "policy_violation.keyid_not_allowed"


def test_data_not_allowed():
    assert _policy.check(make(has_data=True)) == "policy_violation.data_not_allowed"


@pytest.mark.parametrize("p", [0, 2, 4])
def test_p_not_one(p):
    assert _policy.check(make(p=p)) == "policy_violation.p_not_one"


@pytest.mark.parametrize("t", [9, 100])
def test_t_above_ceiling(t):
    assert _policy.check(make(m=262144, t=t)) == "policy_violation.t_above_ceiling"


@pytest.mark.parametrize("m", [262145, 999999999999999])
def test_m_above_ceiling(m):
    assert _policy.check(make(m=m)) == "policy_violation.m_above_ceiling"


@pytest.mark.parametrize("m,t", [
    (47103, 1), (19455, 2), (12287, 3), (9215, 4), (7167, 5),
    (7167, 6), (7167, 7), (7167, 8),
    (0, 2),        # m=0
    (19456, 0),    # t=0 → t<1 走 frontier 拒絕
])
def test_below_owasp_frontier(m, t):
    assert _policy.check(make(m=m, t=t)) == "policy_violation.below_owasp_frontier"


@pytest.mark.parametrize("m,t", [
    (47104, 1), (19456, 2), (12288, 3), (9216, 4),
    (7168, 5), (7168, 6), (7168, 7), (7168, 8),
    (262144, 8),  # 天花板邊界本身合法
])
def test_frontier_boundaries_pass(m, t):
    assert _policy.check(make(m=m, t=t)) is None


@pytest.mark.parametrize("salt_len", [8, 15, 65, 72])
def test_salt_length_out_of_range(salt_len):
    assert _policy.check(make(salt_len=salt_len)) == "policy_violation.salt_length_out_of_range"


@pytest.mark.parametrize("salt_len", [16, 64])
def test_salt_length_boundaries_pass(salt_len):
    assert _policy.check(make(salt_len=salt_len)) is None


@pytest.mark.parametrize("tag_len", [16, 31, 129, 136])
def test_tag_length_out_of_range(tag_len):
    assert _policy.check(make(tag_len=tag_len)) == "policy_violation.tag_length_out_of_range"


@pytest.mark.parametrize("tag_len", [32, 128])
def test_tag_length_boundaries_pass(tag_len):
    assert _policy.check(make(tag_len=tag_len)) is None


# --------------------------------------------------------- 裁決順序（baseline §3）

def test_order_missing_version_first():
    """多重違規：缺 v ＋ p=2 ＋ 超天花板 → 回報 missing_version。"""
    violating = make(version=None, m=999999, t=99, p=2, salt_len=8, tag_len=16,
                     has_keyid=True, has_data=True)
    assert _policy.check(violating) == "policy_violation.missing_version"


def test_order_keyid_before_p():
    assert _policy.check(make(p=2, has_keyid=True)) == "policy_violation.keyid_not_allowed"


def test_order_p_before_t_ceiling():
    assert _policy.check(make(p=2, t=9)) == "policy_violation.p_not_one"


def test_order_t_ceiling_before_m_ceiling():
    assert _policy.check(make(m=999999, t=9)) == "policy_violation.t_above_ceiling"


def test_order_m_ceiling_before_frontier():
    """m 超天花板時（t 合法）先報 m_above_ceiling，不報 frontier。"""
    assert _policy.check(make(m=262145, t=1)) == "policy_violation.m_above_ceiling"


def test_order_frontier_before_salt():
    assert _policy.check(make(m=7167, t=5, salt_len=8)) == "policy_violation.below_owasp_frontier"


def test_order_salt_before_tag():
    assert _policy.check(make(salt_len=8, tag_len=16)) == "policy_violation.salt_length_out_of_range"


# --------------------------------------------- 常數對齊 spec/engine-units.json（權威）

def test_ceiling_constants_match_engine_units():
    ceiling = ENGINE_UNITS["verificationPolicy"]["ceiling"]
    assert _policy.MAX_M == ceiling["max_m_kib"]
    assert _policy.MAX_T == ceiling["max_t"]
    assert _policy.MAX_SALT_BYTES == ceiling["maxSaltBytes"]
    assert _policy.MAX_TAG_BYTES == ceiling["maxTagBytes"]
    assert _policy.MAX_ENCODED_LENGTH == ceiling["maxEncodedLength"]


def test_floor_constants_match_engine_units():
    floors = ENGINE_UNITS["verificationPolicy"]["floors"]
    assert _policy.MIN_SALT_BYTES == floors["minSaltBytes"]
    assert _policy.MIN_TAG_BYTES == floors["minTagBytes"]
    assert _policy.REQUIRED_VERSION == floors["requiredVersion"]


def test_frontier_matches_engine_units():
    for row in ENGINE_UNITS["verificationPolicy"]["owaspFrontier"]:
        assert _policy.frontier_min_m(row["t"]) == row["min_m_kib"]
    # t >= 5 一律 7168
    for t in (5, 6, 7, 8, 100):
        assert _policy.frontier_min_m(t) == 7168
