---
title: "ArgonGuard design review r1"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_357156cb-fecb-4302-9e6f-ae4c41eb3747
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 35738
pplx_latency_sec: 12.57
---

# ArgonGuard design review r1

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 35738 / Latency: 12.57s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深密碼學與應用安全架構審查員。請審核以下「ArgonGuard 跨語言密碼雜湊函式庫」設計文件。

審核要求：
1. 逐節檢查安全正確性：OWASP Password Storage Cheat Sheet 完全合規（這是專案硬性約束，請以現行版本查證）、RFC 9106 一致性、PHC string format 細節正確性、downgrade/DoS 防護是否有漏洞、timing 面是否有遺漏。
2. 查證文件中的事實宣稱是否正確（例如：PHP password_hash 的 argon2id 支援與 provider 行為、libsodium p=1 限制、argon2-cffi/@node-rs/argon2/Konscious 的能力與狀態、netstandard2.0 無 FixedTimeEquals）。
3. 檢查跨語言互通設計的可行性盲點（四語言 PHC 解析/產生的一致性、測試向量策略、前向相容策略）。
4. 檢查 API 語意設計是否有誤用面或矛盾（verify dispatch 順序、NeedsRehash 語意、legacy verifier 擴充點、錯誤分類）。

輸出格式（務必遵守）：
- 【issues】每項問題標注嚴重度 BLOCKER / MAJOR / MINOR / NIT，附具體修正建議與依據（含來源 URL）
- 【verdict】最後明確給出唯一結論：「核准」（無 BLOCKER/MAJOR）或「需修改」（列出必改項）
- 用繁體中文回覆，技術名詞保留英文

====== 設計文件開始 ======
# ArgonGuard 設計文件（送審版 v1）

日期：2026-07-05。狀態：設計定案待外部審核。

## 0. 專案背景與需求

ArgonGuard 是跨語言的密碼雜湊公用函式庫（umbrella brand），供不同技術棧的專案以獨立元件方式引用。已確認需求：

1. **硬性約束：完全符合 OWASP Password Storage Cheat Sheet 建議，核心演算法固定 Argon2id**（RFC 9106）。OWASP 最低參數（m=19456 KiB、t=2、p=1）是地板，只能往上。
2. 跨語言多實作：先訂語言中立規格（格式、參數、語意、共用測試向量），四種語言實作彼此可驗證對方產生的雜湊。
3. 語言優先序：.NET/C#（第一個）→ Node.js/TypeScript → Python → PHP。
4. 發佈：公開套件庫（NuGet.org、npm、PyPI、Packagist）。GitHub monorepo：`Megapower-Asia-LLC/ArgonGuard`（公開）。
5. 舊系統遷移：核心只做 Argon2id，API 預留 legacy verifier 擴充點（登入成功後 rehash 升級）。
6. 維護團隊規模：2-3 人（MSP，一人管數十客戶專案），設計必須控制長期維護面積。

## 1. 儲存格式與參數政策

### 1.1 格式：標準 PHC string format（決策核心）

```
$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<hash-b64>
```

原始筆記提議的自訂 `<param-set-id>$<salt>$<hash>` 格式**不採用**；param-set-id 概念降格為函式庫內部強度檔位名（`default`/`high`/`highest`），永不落地到資料庫。

理由：
- 四語言主流函式庫原生互通：PHP `password_verify` 只吃 PHC；argon2-cffi、@node-rs/argon2、libsodium 全以 PHC 為原生格式。自訂格式迫使四語言各寫編解碼、PHP 繞過原生 API。
- 生態工具直接可用：hashcat、稽核工具、Django/Symfony/Laravel rehash 機制全相容；外部使用者存量 argon2id hash（政策範圍內）直接可驗。
- 自訂格式唯一實質優點（downgrade 防護）由驗證端參數政策完整取回，政策層還多擋資源 DoS 竄改。
- 前向相容：新增檔位不需四套件 lockstep 發版。

### 1.2 產生端規範（MUST）

- 演算法固定 `argon2id`；一律明確輸出 `v=19`（消除 reference impl 缺 v 時 fallback v=16 的歧義）
- 參數順序固定 `m,t,p`；禁止產生 `keyid`/`data` 欄位
- Base64：RFC 4648 §4 標準字元集、無 padding、非 base64url
- Salt：每筆 CSPRNG 隨機、固定 16 bytes；Hash（tag）：固定 32 bytes；p 固定 1
- 典型輸出 97 字元；儲存欄位建議 ≥128 字元，規格上限 512 字元

### 1.3 強度檔位（閉集、規格凍結）

| Profile | m (KiB) | t | p | salt | tag | 依據 |
|---|---|---|---|---|---|---|
| `default` | 19456 | 2 | 1 | 16 B | 32 B | OWASP 現行 minimum 逐字 |
| `high` | 65536 | 2 | 1 | 16 B | 32 B | RFC 9106 次選記憶體量 |
| `highest` | 131072 | 2 | 1 | 16 B | 32 B | 記憶體為唯一強度旋鈕 |

- 全檔位 p=1：libsodium 系實作（PHP ext-sodium、未來 .NET 換引擎選項）計算時僅支援 p=1，是四語言互通的唯一安全交集
- **公開 API 無任何數字參數**——低於 OWASP 地板的雜湊在 API 層面不可表達
- 新增檔位 = spec MINOR；修改既有檔位參數 = 禁止（要調就開新檔位名）
- 舊版驗證端因範圍政策可直接驗證新檔位 hash（前向相容），僅 NeedsRehash 需升級套件

### 1.4 驗證端參數政策（MUST，downgrade 與 DoS 雙向防護）

- **地板**：`v==19`、`m≥19456`、`t≥2`、`p==1`、salt ≥16 bytes、tag ≥32 bytes；參數序必為 `m,t,p`；出現 keyid/data 即拒
- **天花板**：`m≤262144`（256 MiB）、`t≤8`、salt ≤64 bytes、tag ≤128 bytes、整條字串 ≤512 字元（解析前預檢）——封死「竄改 DB 使每次 verify 吃巨量記憶體」的 DoS
- 政策通過後以字串內參數重算 tag，constant-time 比較
- **建置期不變式**：CI 斷言 profile 表每項 ≥ 地板、快照 append-only 比對、`default==(19456,2,1)` 永久哨兵測試

## 2. 規格層（spec/SPEC.md，英文、normative、RFC 2119）

### 2.1 密碼輸入語意

- 規格層密碼是 byte string；字串型 API 以 UTF-8 編碼、不 trim、不大小寫轉換、不做 Unicode 正規化（規格決定性；靜默改寫輸入是安全元件反模式）。應用層 SHOULD 在輸入邊界自行 NFC，文件附各語言一行範例。
- 長度 1–1024 bytes；=0 或 >1024 → `InvalidInput`
- 拒絕 U+0000、拒絕 unpaired surrogate：.NET 用 throwing `UTF8Encoding`、Node 用 `isWellFormed()`、Python encode 自然拋錯轉譯、PHP string 即 bytes 原樣使用（文件明載）
- Hash 與 Verify 套用完全相同的輸入規則

### 2.2 錯誤分類（typed error + 跨語言穩定 reason code）

| 類別 | 觸發 | reason code 範例 |
|---|---|---|
| `MalformedHash` | 無法嚴格解析、>512 字元、b64 非法、參數亂序 | `malformed.bad_base64` |
| `UnsupportedAlgorithm` | 非 argon2id 且無 legacy verifier 認領 | `unsupported.algorithm` |
| `PolicyViolation` | 低於地板/超過天花板、缺 v、含 keyid/data | `policy_violation.m_below_floor` |
| `InvalidInput` | 密碼空/超長/NUL/surrogate | `invalid_input.password_too_long` |
| `UnsupportedEnvironment` | 環境無 argon2id（主要 PHP） | `environment.argon2id_unavailable` |

鐵則：**Verify 的 false 只有一個意思——格式合法、政策合規、密碼不符**；其餘一律 typed error，不得以 false 偽裝（否則資料毀損被誤當打錯密碼）。錯誤訊息禁含密碼與 tag 內容。

### 2.3 共用測試向量（spec/vectors/v1/*.json，immutable）

五類：`deterministic.json`（固定 salt 產生端向量）、`verify.json`（含外部系統產生的合法 PHC）、`reject.json`（逐類錯誤 + reason code 斷言）、`needs-rehash.json`、`input-limits.json`（1024/1025 邊界、空密碼拒絕、NUL 拒絕、surrogate 拒絕、NFC vs NFD 產生不同 hash、emoji、CJK）。密碼以 `passwordHex` 為 normative。

**向量凍結程序**：deterministic 向量由兩個彼此獨立的既有實作（argon2 reference CLI × argon2-cffi）分別產生、byte-for-byte 比對一致才凍結；**ArgonGuard 自家實作不得作為向量來源**（杜絕自我引用式錯誤）。

### 2.4 使用者列舉緩解（informative）

spec 提供每檔位一條 canonical dummy hash 常數（凍結程序中產生），文件附「帳號不存在時跑等時 dummy verify」模式；實作 MAY 曝露輔助函式，不強制。

## 3. API 契約

### 3.1 三核心操作

```
hashPassword(password)          → PHC 字串（active profile + 16B CSPRNG salt）
verifyPassword(password, hash)  → bool
needsRehash(hash)               → bool（純解析比較，不做雜湊，無 DoS 面）
```

標準升級流程（文件必載）：verify 成功 → needsRehash 為 true → 重新 hash 並覆寫 → 完成登入。

### 3.2 Verify dispatch 順序（normative）

```
1. 輸入檢查（1–1024 bytes、無 NUL、well-formed UTF-8）
2. len(encoded) > 512 → MalformedHash
3. 嚴格 PHC 解析：
   a. 成功且 algorithm == argon2id：
      - 政策檢查通過 → 重算 tag → fixed-time compare → bool
      - 政策檢查失敗 → 依註冊順序詢問 legacy verifiers 的 canHandle()；
        第一個認領者裁決；無人認領 → PolicyViolation
   b. 解析失敗或非 argon2id：
      - 依註冊順序詢問 legacy verifiers；認領者裁決
      - 無人認領：非 argon2id → UnsupportedAlgorithm；否則 MalformedHash
```

語意：政策內的 argon2id 永遠走核心；out-of-policy argon2id（如 Django p=8 存量）可由顯式註冊的 legacy verifier 認領——降級接受是看得見的 opt-in；預設（不註冊）fail-fast。

### 3.3 NeedsRehash 語意

`NeedsRehash = 「這筆 hash 不是用現行 active profile 的精確參數產生的」`。與 active profile 任一欄位不同即 true（含高於 active 的情況——語意可預測、與 PHP `password_needs_rehash`／argon2-cffi `check_needs_rehash` 一致，儲存庫收斂到單一參數組）。legacy verifier 認領的格式恆 true；無法解析且無人認領 → 拋 `MalformedHash`（不折疊成 true，避免資料毀損不可見）。

### 3.4 組態與 Legacy 擴充點

- Hasher 建構參數：active profile（預設 `default`）+ legacy verifiers 不可變有序清單（僅限建構時注入；執行期動態註冊被明訂為治理漏洞）；建構後 immutable
- v1 不開放自由參數注入（檔位閉集是 OWASP 合規保證的一部分）
- `LegacyPasswordVerifier` 介面：`canHandle(encoded) → bool`（廉價前綴判斷）+ `verify(password, encoded) → bool`
- 核心不內建任何 legacy 演算法實作；文件提供 bcrypt verifier 完整範例碼

### 3.5 各語言慣例對映

| 面向 | .NET | Node/TS | Python | PHP |
|---|---|---|---|---|
| 方法名 | `HashPassword`/`VerifyPassword`/`NeedsRehash` | `hashPassword`/`verifyPassword`/`needsRehash` | `hash_password`/`verify_password`/`needs_rehash` | `hashPassword`/`verifyPassword`/`needsRehash` |
| 同步性 | v1 只出同步（底層引擎本質同步，不出假 async；需卸載自行 `Task.Run`） | async（Promise，真背景執行緒）；needsRehash 同步 | 同步（argon2-cffi 釋放 GIL；文件示範 `asyncio.to_thread`） | 同步 |
| 密碼型別 | `string` | `string` | `str` | `string` + `#[\SensitiveParameter]` |
| 錯誤 | `ArgonGuardException` 基底 + 五子類（含 `Reason`） | `ArgonGuardError` 子類 + `.code` | 五 exception + `reason` | 五 exception + `getReason()` |
| Profile | `enum` | 字串字面量型別 | `StrEnum` | native enum |

每實作曝露 `SPEC_VERSION` 常數；共用 reject 向量逐語言斷言錯誤類別 + reason code。

## 4. 品牌命名與各語言實作策略

ArgonGuard 為 umbrella brand，產品線後綴 `Passwords`（未來可延伸 Tokens 等）。名稱可用性已查證（2026-07-05）：NuGet `ArgonGuard.Passwords`、npm `@argonguard/passwords`、PyPI `argonguard-passwords`、Packagist `argonguard/passwords`、GitHub org `argonguard` 全部未被占用。

共同原則：**規格層自己寫**（嚴格 PHC parser＋政策檢查＋NeedsRehash，四語言 bit-level 一致）、**密碼學層委外**給久經驗證的引擎；引擎藏在 internal provider 之後（不進公開 API），可抽換。

### 4.1 .NET（第一優先，設計基準）

- 套件：NuGet `ArgonGuard.Passwords`（申請 prefix reservation）；namespace `ArgonGuard.Passwords`；公開類別 `ArgonGuardPasswordHasher`、介面 `IArgonGuardPasswordHasher`（避免與 ASP.NET Identity `PasswordHasher<TUser>` 撞名）
- 引擎：Konscious.Security.Cryptography.Argon2（純 managed、raw-bytes API、原生 net46 資產——「純 managed＋.NET Framework＋net8.0」的唯一交集）
- TFM：`netstandard2.0;net8.0`；.NET Framework 支援地板 **4.6.2**（MSP 客戶存量硬需求）；System.Memory binding redirect 疑難排解寫進 README
- netstandard2.0 無 `CryptographicOperations.FixedTimeEquals` → `#if` 自寫 XOR 累加版 + 雙 TFM 等價測試；CI 在 net8.0（Linux）+ net48（Windows）跑完整向量
- Konscious 維護停滯（2024-06 起）風險對沖：internal provider 可換（備援 Isopoh）、RFC 9106 已凍結、向量常態 CI、MIT 可 vendor
- ASP.NET Identity adapter：v1 文件內十行範例；v1.1 視需求出子套件

### 4.2 Node.js / TypeScript

- 套件：npm `@argonguard/passwords`（先註冊 org「argonguard」；備援 `argonguard-passwords`）
- 引擎：@node-rs/argon2（平台覆蓋最完整，含 Alpine musl／WASM fallback、無 postinstall、`hashRaw` 支撐向量驗證）；PHC 編碼自寫層
- provider 抽象預留：Node ≥24.7 內建 `crypto.argon2` 成熟後可切零依賴路線；備援 node-argon2
- 支援地板 Node 20 LTS；ESM + CJS 雙輸出；CI：linux x64/arm64、alpine、windows、macOS × Node 20/22/24

### 4.3 Python

- 套件：PyPI `argonguard-passwords`；import `argonguard.passwords`（namespace package，替未來 tokens 預留）
- 引擎：argon2-cffi 直接依賴（不經 passlib——已停止維護且 Python 3.13 損壞）；`hash_secret_raw` 重算 + `hmac.compare_digest`
- 支援地板 Python 3.9（abi3 wheel 下限）；`py.typed` 完整型別

### 4.4 PHP

- 套件：Packagist `argonguard/passwords`；namespace `ArgonGuard\Passwords`
- 引擎：原生 `password_hash`/`password_verify`（PASSWORD_ARGON2ID），零 runtime Composer 依賴（2026 主流發行管道全內建；全檔位 p=1 使 libargon2/sodium provider 行為一致）
- 載入時能力檢查 fail-fast（`password_algos()` 無 argon2id → `UnsupportedEnvironment` 附安裝指引），**絕不降級 bcrypt**；偵測到 ext-sodium 可走 sodium fallback（`suggest: ext-sodium`）
- 驗證：自寫嚴格 parser + 政策通過後餵 `password_verify`；`needsRehash` 用自寫 parser（不用 `password_needs_rehash`，避免 provider 漂移）
- deterministic 向量以 `sodium_crypto_pwhash` raw 重算比對（require-dev 層級）
- 支援地板 PHP 8.2

## 5. Repo 結構、CI 與發佈

### 5.1 Monorepo：`Megapower-Asia-LLC/ArgonGuard`（公開，現址不動；品牌成熟後再評估搬遷專屬 org）

```
ArgonGuard/
├── spec/          SPEC.md + vectors/v1/*.json（immutable）+ CHANGELOG
├── dotnet/ node/ python/ php/    （各含 src/ tests/ tools/harness）
├── docs/          SOT 筆記 + ADR（格式決策、p=1 鎖定、選型）
└── .github/workflows/   per-language CI + cross-lang matrix + release-*
```

理由：spec 與向量是四實作共享的第一等 artifact，變更必須原子提交；跨語言互驗 CI 只有單 repo 能在同一 commit 執行。PHP 的 Packagist 根目錄限制以 subtree split read-only mirror 解決。

### 5.2 版本策略

- Spec 版本 SemVer：MINOR = 新增檔位/向量類別/天花板調整；PATCH = 編輯性修正
- 套件各自獨立 SemVer，唯一硬規則：**套件 MAJOR = spec MAJOR**；metadata 宣告 `Implements ArgonGuard Spec 1.x`
- Git tag：`spec/v1.0.0`、`dotnet/v1.2.3`…，tag prefix 觸發對應發佈 workflow
- 發佈：NuGet 簽章、npm provenance、PyPI trusted publishing（OIDC）、Packagist hook

### 5.3 CI 守門（四道）

1. **Profile 不變式**（建置期紅燈）：OWASP 地板斷言、profile 快照 append-only 比對、`default==(19456,2,1)` 哨兵
2. **Per-language 向量 conformance**：.NET 雙 TFM（net8.0 Linux + net48 Windows）；Node 平台×版本矩陣；Python 3.9–3.14；PHP 8.2–8.5（sodium-only 自編譯 build 降為 nightly，每 PR 只跑 standard provider）
3. **跨語言 4×4 round-trip 矩陣**（擋 merge）：各實作 dev harness（stdin/stdout JSON 協議）對隨機密碼×三檔位互 hash 互驗 + needs-rehash 斷言
4. **Supply-chain**：lockfile pin、Dependabot、底層引擎升版必過完整向量迴歸

### 5.4 營運手冊

檔位切換 SOP（SHOULD）：先全 fleet 升級函式庫 → 觀察一個週期 → 再切 active profile。前向相容使違反此順序不會炸，但遵守它讓 NeedsRehash 行為全程可預測。

## 6. 安全保證（OWASP 完全合規追溯）

| OWASP 要求 | 落點 | 保證機制 |
|---|---|---|
| Use Argon2id | 核心只產/只收 argon2id | 型別層無其他選項；`$argon2i$`/`$2b$` 進 reject 向量 |
| m≥19 MiB, t≥2, p=1 | `default` 精確等於；公開 API 無數字參數 | 建置期 profile 快照 CI + 執行期驗證端地板 + reject 向量 |
| 每筆唯一隨機 salt | 16B CSPRNG，API 無 salt 參數 | 逐語言 CSPRNG 來源列名 + 同密碼連續 hash 不重複測試 |
| 升級路徑 | NeedsRehash + 登入後升級模式 | needs-rehash 向量全分支 |
| 長度 DoS 防護 | 1–1024 bytes | input-limits 向量 |
| constant-time 比較 | tag 比較 MUST fixed-time | `FixedTimeEquals`／XOR polyfill（雙 TFM 等價測試）／`timingSafeEqual`／`compare_digest`／`hash_equals` |

補充：驗證端天花板（256 MiB／t≤8）封 DB 竄改型資源 DoS；輸入 canonicalization 封 surrogate/NUL 跨語言歧義；dummy hash 常數緩解 timing 列舉；錯誤訊息不含密碼/tag；記憶體清零明載 best-effort 不作保證；OWASP Cheat Sheet 為活文件——spec 記載查證 commit/日期，年度複查，若 OWASP 升地板則 spec MINOR 新檔位 + `default` 改指。

## 7. 非目標（v1）

1. 不自創儲存格式
2. 不產生任何非 Argon2id hash（legacy 只有 verify）；FIPS/PBKDF2 場景另立專案
3. 不支援 pepper/secret/associatedData（跨語言支援不一致；需要者呼叫前自行 HMAC pre-hash，文件附模式）
4. 不開放 p>1、不開放自由參數注入
5. 不做密碼政策/強度估計/breach 檢查/rate limiting/帳號鎖定（應用層責任）
6. 不提供泛用 KDF API
7. 不做自動參數校準
8. 不保證記憶體清零、不提供 secure string 型別
9. 核心不內建框架 adapter（文件範例先行，子套件 v1.1 再評估）
10. 不出假 async（.NET/Python/PHP）、Node 的 Sync 變體 v1 不出
11. 支援地板：.NET Framework 4.6.2／.NET 8、Node 20、Python 3.9、PHP 8.2；提升地板 = 套件 MAJOR

## Search queries triggered

- OWASP Password Storage Cheat Sheet Argon2id parameters 2024 2025
- RFC 9106 Argon2id recommended parameters first second option
- PHP password_hash PASSWORD_ARGON2ID libsodium provider p parallelism
- argon2-cffi hash_secret_raw check_needs_rehash
- @node-rs/argon2 hashRaw PHC format
- Konscious.Security.Cryptography.Argon2 maintenance status
## Output

I found a **critical discrepancy**. The document's core hard constraint claim — that OWASP's minimum is "m=19456, t=2, p=1" as *the* single minimum — is now inaccurate. Let me verify the remaining PHP/libsodium and .NET details from what I have, then also flag the OWASP mismatch.

Let me consult the additional claims I need to confirm.

## Citations

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://github.com/technion/ruby-argon2/blob/master/README.md
- https://owasp.deteact.com/cheat/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://www.rfc-editor.org/rfc/rfc9106.html
- https://note.com/niti_technology/n/ne743f8a5e596
- https://note.com/niti_technology/n/ne743f8a5e596?hl=en
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://www.php.net/password-hash
- https://www.reddit.com/r/Bitwarden/comments/11zhs63/web_and_chrome_extension_memory_usage_with/
- https://github.com/OWASP/CheatSheetSeries/issues/1536
- https://github.com/charlesportwoodii/php-argon2-ext/issues/9
- https://github.com/golang/go/issues/57065
- https://github.com/mudge/argon2id/blob/main/README.md
- https://stackoverflow.com/questions/54676717/how-does-argon2id-store-salts-in-php
- https://www.reddit.com/r/crypto/comments/m9w2ea/password_storage_owasp_cheat_sheet_series/
- https://argon2-cffi.readthedocs.io/en/stable/api.html
- https://argon2-cffi.readthedocs.io/en/19.1.0/api.html
- https://argon2-cffi.readthedocs.io/en/stable/genindex.html
- https://github.com/hynek/argon2-cffi/blob/main/CHANGELOG.md
- https://tessl.io/registry/tessl/pypi-argon2-cffi/25.1.0/files/docs/index.md
- https://argon2-cffi.readthedocs.io/en/20.1.0/
- https://stackoverflow.com/questions/58431973/argon2-library-that-hashes-passwords-without-a-secret-and-with-a-random-salt-tha
- https://dlthub.com/context/source/argon2-cffi
- https://github.com/hynek/argon2-cffi
- https://github.com/jimratliff/hashing-passwords-in-python-using-argon2/blob/main/README.md
- https://pypi.org/project/argon2-cffi/18.2.0/
- https://github.com/hynek/argon2-cffi/releases
- https://github.com/hynek/argon2-cffi/blob/master/src/argon2/low_level.py
- https://pypi.org/project/argon2-cffi/16.0.0/
- https://www.youtube.com/watch?v=0rHGnpH2_h8
