"""README.md 的 Quickstart／async／遷移範例的實跑測試。

目的：讓 python/README.md 的範例程式碼與 CI 同源、防腐化。README 的範例若改動，
本檔必須同步——否則測試會抓到分歧。這裡刻意複製 README 的程式碼（而非抽共用 helper），
因為要驗證的正是「文件裡貼的那段程式碼真的能跑」。
"""

import asyncio

import pytest

from argonguard.passwords import (
    SPEC_VERSION,
    ArgonGuardPasswordHasher,
    ArgonGuardProfile,
)
from argonguard.passwords._profiles import parameters_for

PASSWORD = "correct horse battery staple"


# ---------------------------------------------------------------- Quickstart

def test_quickstart_register_and_login():
    """README Quickstart：hash -> verify -> needs_rehash 升級流程。"""
    hasher = ArgonGuardPasswordHasher()                  # 預設 default 檔位

    # 註冊：雜湊後存進資料庫
    stored = hasher.hash_password(PASSWORD)
    assert stored.startswith("$argon2id$v=19$m=19456,t=2,p=1$")

    # 登入：驗證 + 順手升級
    logged_in = False
    if hasher.verify_password(PASSWORD, stored):         # False 只有一個意思：密碼不符
        if hasher.needs_rehash(stored):                  # 剛用 active 檔位產生 -> False
            stored = hasher.hash_password(PASSWORD)
        logged_in = True
    assert logged_in is True

    # 錯密碼 -> False（而非 raise）
    assert hasher.verify_password("wrong password", stored) is False


def test_quickstart_rehash_on_profile_upgrade():
    """調高 active 檔位後，舊 default 雜湊 needs_rehash 應為 True，並可原地升級。"""
    old = ArgonGuardPasswordHasher(ArgonGuardProfile.DEFAULT)
    stored = old.hash_password(PASSWORD)

    new = ArgonGuardPasswordHasher(ArgonGuardProfile.HIGH)
    assert new.verify_password(PASSWORD, stored) is True   # 舊雜湊仍驗得過（frontier 內）
    assert new.needs_rehash(stored) is True                # 參數落後 active

    upgraded = new.hash_password(PASSWORD)                 # 重算寫回
    assert upgraded.startswith("$argon2id$v=19$m=65536,t=2,p=1$")
    assert new.needs_rehash(upgraded) is False


def test_quickstart_async_offload():
    """README async 範例：以 asyncio.to_thread 卸載同步計算，不阻塞 event loop。"""
    hasher = ArgonGuardPasswordHasher()

    async def login(password: str, stored: str) -> bool:
        ok = await asyncio.to_thread(hasher.verify_password, password, stored)
        if ok and hasher.needs_rehash(stored):
            await asyncio.to_thread(hasher.hash_password, password)
        return ok

    stored = hasher.hash_password(PASSWORD)
    assert asyncio.run(login(PASSWORD, stored)) is True
    assert asyncio.run(login("nope", stored)) is False


# --------------------------------------------------------- API 參考小節校驗

def test_spec_version_constant_matches_readme():
    assert SPEC_VERSION == "1.0.0"


def test_password_bytes_rejected_with_type_error():
    """README API 參考：hash_password 只收 str，傳 bytes 拋 TypeError。"""
    hasher = ArgonGuardPasswordHasher()
    with pytest.raises(TypeError):
        hasher.hash_password(b"password")


@pytest.mark.parametrize(
    "profile, m_kib",
    [
        (ArgonGuardProfile.DEFAULT, 19456),
        (ArgonGuardProfile.HIGH, 65536),
        (ArgonGuardProfile.HIGHEST, 131072),
    ],
)
def test_readme_strength_table_matches_impl(profile, m_kib):
    """README 強度檔位表（m/t/p）必須與實作一致，防文件漂移。"""
    params = parameters_for(profile)
    assert (params.m, params.t, params.p) == (m_kib, 2, 1)


# -------------------------------------------------- 舊系統遷移（bcrypt 範例）

class BcryptLegacyVerifier:
    """README 遷移範例：驗證舊 bcrypt 雜湊（verify-only；SPEC §6.4）。

    核心不內建任何 legacy 演算法；bcrypt 是使用者自己的相依。
    LegacyPasswordVerifier 為 typing.Protocol，duck typing 即可、不必顯式繼承。
    """

    def can_handle(self, encoded_hash: str) -> bool:
        return encoded_hash.startswith(("$2a$", "$2b$", "$2y$"))

    def verify(self, password: str, encoded_hash: str) -> bool:
        import bcrypt

        return bcrypt.checkpw(password.encode("utf-8"), encoded_hash.encode("utf-8"))


def test_migration_bcrypt_legacy_then_upgrade():
    """README 遷移範例：注入 bcrypt verifier -> 驗過舊雜湊 -> 升級成 argon2id。"""
    bcrypt = pytest.importorskip("bcrypt")   # 遷移範例的 doc 相依，非核心 runtime 相依
    legacy_stored = bcrypt.hashpw(
        PASSWORD.encode("utf-8"), bcrypt.gensalt()
    ).decode("ascii")

    hasher = ArgonGuardPasswordHasher(
        ArgonGuardProfile.DEFAULT,
        legacy_verifiers=[BcryptLegacyVerifier()],
    )

    # 舊 bcrypt 雜湊仍驗得過；錯密碼 -> False
    assert hasher.verify_password(PASSWORD, legacy_stored) is True
    assert hasher.verify_password("wrong", legacy_stored) is False

    # legacy 認領的雜湊恆需 rehash（SPEC §6.3 N2）
    assert hasher.needs_rehash(legacy_stored) is True

    # 升級成 argon2id 後走核心路徑
    upgraded = hasher.hash_password(PASSWORD)
    assert upgraded.startswith("$argon2id$")
    assert hasher.verify_password(PASSWORD, upgraded) is True
    assert hasher.needs_rehash(upgraded) is False
