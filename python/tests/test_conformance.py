"""凍結向量 conformance（SPEC §10）。任一紅燈＝不合規。

逐筆跑 spec/vectors/v1 全部五類向量：
deterministic（固定 salt 重算 byte-identical ＋ verify=true）、verify、reject、
needs-rehash、input-limits。
"""

import pytest

from argonguard.passwords import (
    ArgonGuardPasswordHasher,
    ArgonGuardProfile,
    InvalidInputError,
    MalformedHashError,
    PolicyViolationError,
    UnsupportedAlgorithmError,
    UnsupportedEnvironmentError,
)

from conftest import FakeBcryptVerifier, vector_entries, vector_entry

ERROR_TYPES = {
    "MalformedHash": MalformedHashError,
    "UnsupportedAlgorithm": UnsupportedAlgorithmError,
    "PolicyViolation": PolicyViolationError,
    "InvalidInput": InvalidInputError,
    "UnsupportedEnvironment": UnsupportedEnvironmentError,
}


def _params(name):
    return pytest.mark.parametrize(
        "entry", vector_entries(name), ids=lambda e: e["id"])


# ---------------------------------------------------------------- deterministic

@_params("deterministic.json")
def test_deterministic_encoded_byte_identical(entry):
    """固定 salt 重算：encoded（含 tag）必須與凍結向量 byte-identical。"""
    hasher = ArgonGuardPasswordHasher()
    encoded = hasher._hash_password_with_salt(
        bytes.fromhex(entry["passwordHex"]),
        bytes.fromhex(entry["saltHex"]),
        entry["m"], entry["t"], entry["p"], entry["tagLen"])
    assert encoded == entry["encoded"]


@_params("deterministic.json")
def test_deterministic_verifies_true(entry):
    hasher = ArgonGuardPasswordHasher()
    password = bytes.fromhex(entry["passwordHex"]).decode("utf-8")
    assert hasher.verify_password(password, entry["encoded"]) is True


# ---------------------------------------------------------------------- verify

@_params("verify.json")
def test_verify_matches_expected(entry):
    hasher = ArgonGuardPasswordHasher()
    password = bytes.fromhex(entry["passwordHex"]).decode("utf-8")
    assert hasher.verify_password(password, entry["encoded"]) is entry["expected"]


# ---------------------------------------------------------------------- reject

@_params("reject.json")
def test_reject_raises_exact_error_and_reason(entry):
    hasher = ArgonGuardPasswordHasher()
    password = bytes.fromhex(entry["passwordHex"]).decode("utf-8")
    with pytest.raises(ERROR_TYPES[entry["expectedError"]]) as excinfo:
        hasher.verify_password(password, entry["encoded"])
    assert excinfo.value.reason == entry["expectedReason"]
    assert type(excinfo.value) is ERROR_TYPES[entry["expectedError"]]


# ---------------------------------------------------------------- needs-rehash

@_params("needs-rehash.json")
def test_needs_rehash_matches_truth_table(entry):
    legacy = (FakeBcryptVerifier(),) if entry["legacyRegistered"] else ()
    hasher = ArgonGuardPasswordHasher(
        ArgonGuardProfile(entry["activeProfile"]), legacy)
    expected = entry["expected"]

    if isinstance(expected, bool):
        assert hasher.needs_rehash(entry["encoded"]) is expected
    else:
        with pytest.raises(ERROR_TYPES[expected["error"]]) as excinfo:
            hasher.needs_rehash(entry["encoded"])
        assert excinfo.value.reason == expected["reason"]
        assert type(excinfo.value) is ERROR_TYPES[expected["error"]]


# ---------------------------------------------------------- dummy-hashes（§8.3）

@pytest.mark.parametrize(
    "entry", vector_entries("dummy-hashes.json"), ids=lambda e: e["profile"])
def test_dummy_hash_recompute_and_roundtrip(entry):
    """canonical dummy hash：固定 salt 重算 byte-identical、verify=true、
    對其 profile needs_rehash=false（等時 dummy verify 的前提）。"""
    profile = ArgonGuardProfile(entry["profile"])
    hasher = ArgonGuardPasswordHasher(profile)
    password_bytes = bytes.fromhex(entry["passwordHex"])

    parts = entry["encoded"].split("$")
    salt_b64 = parts[4]
    import base64
    salt = base64.b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
    m, t, p = (int(kv.split("=")[1]) for kv in parts[3].split(","))
    assert hasher._hash_password_with_salt(
        password_bytes, salt, m, t, p, 32) == entry["encoded"]

    assert hasher.verify_password(
        password_bytes.decode("utf-8"), entry["encoded"]) is True
    assert hasher.needs_rehash(entry["encoded"]) is False


# ---------------------------------------------------------------- input-limits

@_params("input-limits.json")
def test_input_limits_match_expected(entry):
    hasher = ArgonGuardPasswordHasher()

    if "refA" in entry:
        # NFC vs NFD：兩筆 deterministic 向量的 encoded 必須不同（不做 Unicode 正規化）
        a = vector_entry("deterministic.json", entry["refA"])["encoded"]
        b = vector_entry("deterministic.json", entry["refB"])["encoded"]
        assert a != b
        return

    if "stringInput" in entry:
        # "\\uD800ab" 標記法 → 還原為含 lone surrogate 的 Python 字串
        raw = entry["stringInput"]
        assert raw.startswith("\\uD800")
        password = "\ud800" + raw[6:]
    else:
        password = bytes.fromhex(entry["passwordHex"]).decode("utf-8")

    expected = entry["expected"]
    if expected == "ok":
        encoded = hasher.hash_password(password)
        assert hasher.verify_password(password, encoded) is True
    else:
        with pytest.raises(ERROR_TYPES[expected["error"]]) as excinfo:
            hasher.hash_password(password)
        assert excinfo.value.reason == expected["reason"]
        # hash 與 verify 必須套用相同輸入規則（SPEC I5）
        with pytest.raises(ERROR_TYPES[expected["error"]]) as excinfo_verify:
            hasher.verify_password(
                password,
                "$argon2id$v=19$m=19456,t=2,p=1$QXJvbkd1YXJkVjFTMDEhIQ"
                "$IaZP5na2KGZS16RsxjK9ytjuQLHsYJN3L1Wf5Q7ZcaE")
        assert excinfo_verify.value.reason == expected["reason"]
