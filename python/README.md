# ArgonGuard for Python

OWASP 合規的 Argon2id 密碼雜湊元件。Implements **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`；`argonguard.passwords.SPEC_VERSION == "1.0.0"`）。

- Python >= 3.9，唯一 runtime 依賴 [`argon2-cffi`](https://pypi.org/project/argon2-cffi/)（久經驗證的引擎；ArgonGuard 只做規格層）
- 與 .NET／Node.js／PHP 實作產出可互換的 PHC 字串（4×4 round-trip）

```bash
pip install argonguard-passwords
```

## Quickstart

公開 API 只有三個操作，且沒有任何數字參數——你不可能不小心產出低於 OWASP 標準的雜湊。

```python
from argonguard.passwords import ArgonGuardPasswordHasher

hasher = ArgonGuardPasswordHasher()                  # 預設 default 檔位（m=19456 KiB, t=2, p=1）

# 註冊：雜湊後存進資料庫
stored = hasher.hash_password(password)              # PHC 字串，fresh 16-byte CSPRNG salt、32-byte tag

# 登入：驗證 + 順手升級（rehash-on-login；SPEC §6.1）
if hasher.verify_password(password, stored):         # False 只有一個意思：密碼不符
    if hasher.needs_rehash(stored):                  # 參數落後 active 檔位才為 True（只 parse、不雜湊）
        stored = hasher.hash_password(password)
        save(stored)                                 # 重算後寫回，儲存庫逐步收斂到新參數
    login_ok()
else:
    login_failed()
```

`verify_password` 回 `False` 就只代表密碼不符；格式錯、演算法不支援、政策違反、輸入非法等一律拋 typed error（見 API 參考），絕不折疊成 `False`。

### async 場景（FastAPI／asyncio）

Python 版三操作是**同步**的（v1 不做假 async）。`argon2-cffi` 在實際計算 Argon2 時會**釋放 GIL**，所以在 async server 裡用 `asyncio.to_thread` 把計算卸載到 thread pool，可避免阻塞 event loop 且真正並行：

```python
import asyncio
from argonguard.passwords import ArgonGuardPasswordHasher

hasher = ArgonGuardPasswordHasher()

async def login(password: str, stored: str) -> bool:
    ok = await asyncio.to_thread(hasher.verify_password, password, stored)
    if ok and hasher.needs_rehash(stored):           # needs_rehash 不做雜湊，可直接呼叫
        new_hash = await asyncio.to_thread(hasher.hash_password, password)
        await save(new_hash)
    return ok
```

## API 參考

### 建構子

```python
ArgonGuardPasswordHasher(
    profile: ArgonGuardProfile | str = ArgonGuardProfile.DEFAULT,
    legacy_verifiers: Iterable[LegacyPasswordVerifier] = (),
)
```

- `profile`：active 強度檔位（見下表），可傳 `ArgonGuardProfile` 或其字串值（`"default"` 等）；未知值拋 `ValueError`。
- `legacy_verifiers`：舊演算法 verifier 的**有序清單**，建構時複製為不可變 tuple——runtime 註冊在 API 形狀上即不可能（SPEC L1）。清單含 `None` 拋 `ValueError`。
- `hasher.active_profile`（property）：回傳現行 active 的 `ArgonGuardProfile`。

### 三核心操作

| 操作 | 簽章 | 回傳 |
|---|---|---|
| Hash | `hash_password(password: str) -> str` | active 檔位 + fresh 16-byte CSPRNG salt 的 PHC 字串 |
| Verify | `verify_password(password: str, encoded_hash: str) -> bool` | `True`／`False`（`False` 只代表密碼不符），其餘拋 typed error |
| Needs rehash | `needs_rehash(encoded_hash: str) -> bool` | 是否非以 active 檔位精確參數產生；只 parse 比對、**不做雜湊**（SPEC §6.3） |

`hash_password` 只收 `str`（傳 `bytes` 拋 `TypeError`）。`needs_rehash` 只吃 encoded 字串、不碰密碼。

### profile 列舉

```python
from argonguard.passwords import ArgonGuardProfile

ArgonGuardProfile.DEFAULT   # "default"
ArgonGuardProfile.HIGH      # "high"
ArgonGuardProfile.HIGHEST   # "highest"
```

`ArgonGuardProfile` 是 `str` Enum（閉集），可直接與字串比較。

### 五 typed error 類別

基底為 `ArgonGuardError`；每個實例帶 `.reason`（跨語言 bit-identical 的機器可讀 reason code，權威來源 `spec/reason-codes.json`）。錯誤訊息**不含**密碼、salt、tag（SEC-006）。

| 類別 | `.reason` 前綴 | 意義（SPEC §7） |
|---|---|---|
| `MalformedHashError` | `malformed.*` | 無法以嚴格文法解析／過長／bad base64／參數順序錯 |
| `UnsupportedAlgorithmError` | `unsupported.*` | 可解析但演算法非 argon2id，且無 legacy verifier 認領 |
| `PolicyViolationError` | `policy_violation.*` | 合法 argon2id 但參數落在驗證政策外，且無 legacy verifier 認領 |
| `InvalidInputError` | `invalid_input.*` | 密碼違反 SPEC §5 輸入規則 |
| `UnsupportedEnvironmentError` | `environment.*` | 執行環境無法提供 argon2id（缺 `argon2-cffi` 時 fail-fast） |

```python
from argonguard.passwords import PolicyViolationError

try:
    hasher.verify_password(pw, stored)
except PolicyViolationError as e:
    log.warning("hash rejected: %s", e.reason)   # 例：policy_violation.below_owasp_frontier
```

### 常數

```python
from argonguard.passwords import SPEC_VERSION   # "1.0.0"（實作對齊的規格版本，SPEC §9）
```

## 強度檔位（公開 API 唯一旋鈕）

| profile | m | t | p | 用途 |
|---|---|---|---|---|
| `default` | 19456 KiB（19 MiB） | 2 | 1 | OWASP 等效最低建議；永久哨兵（CI 釘死） |
| `high` | 65536 KiB（64 MiB） | 2 | 1 | 較高記憶體成本 |
| `highest` | 131072 KiB（128 MiB） | 2 | 1 | 最高記憶體成本 |

- **公開 API 沒有任何數字 Argon2 參數**——你只能選 profile，不能傳 `m`／`t`／`p`／salt。產生端一律 ≥ OWASP 等效最低配置（SPEC §3）。
- **驗證端**接受整個 OWASP frontier（地板，防降級）到天花板（`m ≤ 256 MiB`、`t ≤ 8`，防 DoS 竄改）之間的合規雜湊，所以升級 profile 後舊雜湊仍驗得過，再靠 `needs_rehash` 逐步收斂。
- profile 是凍結閉集；強化只能**新增** profile 名稱（spec MINOR），永不修改既有 profile 參數（SPEC P2）。

## 舊系統遷移（bcrypt → argon2id）

核心**不內建**任何 legacy 演算法（SPEC L3）。要驗證舊 bcrypt 雜湊，於建構時注入一個 verifier；第一個 `can_handle()` 認領者裁決。`LegacyPasswordVerifier` 是 `typing.Protocol`（duck typing 即可，不必顯式繼承）：

```python
import bcrypt   # pip install bcrypt —— 你自己的相依，核心不出貨
from argonguard.passwords import ArgonGuardPasswordHasher, ArgonGuardProfile


class BcryptLegacyVerifier:
    """驗證舊 bcrypt 雜湊（verify-only；SPEC §6.4）。"""

    def can_handle(self, encoded_hash: str) -> bool:          # 廉價前綴測試
        return encoded_hash.startswith(("$2a$", "$2b$", "$2y$"))

    def verify(self, password: str, encoded_hash: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), encoded_hash.encode("utf-8"))


hasher = ArgonGuardPasswordHasher(
    ArgonGuardProfile.DEFAULT,
    legacy_verifiers=[BcryptLegacyVerifier()],
)

# 登入：舊 bcrypt 雜湊驗過後，順勢升級成 argon2id
if hasher.verify_password(password, legacy_stored):
    if hasher.needs_rehash(legacy_stored):        # legacy 認領的雜湊恆為 True（SPEC §6.3 N2）
        new_hash = hasher.hash_password(password)
        save(new_hash)                            # 下次登入就走 argon2id 核心路徑
    login_ok()
```

in-policy 的 argon2id 雜湊**恆走核心路徑**，legacy verifier 不會攔截（SPEC V2）；legacy 只能認領非 argon2id 或 out-of-policy 的字串——是看得見的顯式 opt-in，不是預設。

## 安全注意事項（Security Notes）

- **同步 API 與 async 卸載**：三操作同步。`argon2-cffi` 計算時釋放 GIL，async server 請用 `asyncio.to_thread`（見 Quickstart）把 `hash_password`／`verify_password` 卸載到 thread pool，避免阻塞 event loop。`needs_rehash` 不做雜湊，可直接同步呼叫。
- **輸入型別與長度**：密碼只收 `str`（傳 `bytes` 拋 `TypeError`），長度以 **UTF-8 encoded bytes** 計，範圍 1..1024（跨語言一致，SPEC §5 I2）；encoded 雜湊上限 **512 UTF-8 bytes**，於任何解析前預檢（SPEC §4 C5）。Python 以 `str.encode("utf-8")` 天然拒絕 unpaired surrogate（`invalid_input.password_not_well_formed`），無 Unicode 正規化——應用端 SHOULD 在輸入邊界自行正規化為 NFC。
- **超長輸入的 body size 上限**：長度檢查前會先對輸入做一次 O(n) 的 UTF-8 encode；惡意的數 MB 巨大字串因此仍會被掃一次。ArgonGuard 不負責限制請求大小——請在框架層設 body size 上限（FastAPI 的 `Request` size limit／反向代理 `client_max_body_size`／Django `DATA_UPLOAD_MAX_MEMORY_SIZE`），把超大 payload 擋在到達雜湊器之前。
- **`verify_password` 的單一語意**：回 `False` 只代表「格式正確、政策合規、但密碼不符」；其餘所有情況（malformed／unsupported／policy／invalid input／environment）一律 typed error，永不偽裝成 `False`（SPEC V1）。呼叫端不要把 `False` 當成「無此帳號」等其他意義。
- **不記錄任何 log**：本函式庫不寫 log；錯誤訊息與 reason code 不含密碼、salt、tag（SPEC §7／§8.6，SEC-006）。應用端只應記錄 verify 成功/失敗與時間戳，不要把密碼或雜湊寫進日誌。
- **記憶體清零為 best-effort**：Python 無法保證密碼字串在 GC 前被清零（SPEC §8.4，已知非目標）。這是 managed runtime 的本質限制。
- **帳號列舉緩解**：帳號不存在時建議以 `spec/vectors/v1/dummy-hashes.json` 的 canonical dummy hash 跑等時 dummy verify，緩解帳號列舉的計時差（SPEC §8.3）。
- **ArgonGuard 不做的事**：rate limiting、MFA、帳號鎖定、breach 檢查等仍是**應用層**責任。ArgonGuard 只保證「密碼雜湊這一步」合規且跨語言互通，不是完整的認證系統。

常數時間比對（`hmac.compare_digest`）、CSPRNG salt（`os.urandom`）、fail-fast 環境檢查等已內建，無需自行處理。

## 開發

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                                        # 單元 + 凍結向量 conformance + README 範例實跑測試
python3 ../spec/tools/run_contract.py -- .venv/bin/python tools/harness.py   # harness contract
```

`tests/test_quickstart_example.py` 把本 README 的 Quickstart 與遷移範例做成實跑測試（文件與 CI 同源、防腐化）；範例若改，該測試必須同步。

## License

MIT © Megapower Asia LLC
