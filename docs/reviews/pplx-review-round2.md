---
title: "ArgonGuard design review r2"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_41cc40d4-749c-4c45-8624-b2ed09b5870a
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 44687
pplx_latency_sec: 161.29
---

# ArgonGuard design review r2

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 44687 / Latency: 161.29s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深密碼學與應用安全架構審查員。這是「ArgonGuard 跨語言密碼雜湊函式庫」設計文件的第二輪審核（round 2）。

Round 1 你指出：文件把 OWASP 最低參數寫成單一組 (m=19456,t=2,p=1)，但現行 Cheat Sheet 列多組等效配置。v2 已修正：明載 OWASP 為等效配置清單、default 是選定的 canonical 一組、驗證端採刻意收緊的單調地板並寫成 ADR（OWASP 認可但形狀不同的存量走 legacy verifier opt-in）。

本輪請完成完整審核（round 1 回覆中斷，未給出 issues 清單與 verdict）：
1. 確認 v2 的 OWASP 修正是否足夠精確、單調地板 ADR 的安全論證是否成立。
2. 逐節檢查安全正確性：OWASP 現行版合規、RFC 9106 一致性、PHC format 細節、downgrade/DoS 防護、timing 面。
3. 查證關鍵事實宣稱（PHP password_hash argon2id provider 行為、libsodium p=1 限制、argon2-cffi/@node-rs/argon2/Konscious 能力與狀態、netstandard2.0 無 FixedTimeEquals）。
4. 跨語言互通可行性盲點（四語言 PHC 解析/產生一致性、測試向量策略、前向相容）。
5. API 語意矛盾或誤用面（verify dispatch、NeedsRehash、legacy 擴充點、錯誤分類）。

輸出格式（務必遵守、務必完整輸出到 verdict 為止，不得中途停止）：
- 【issues】每項標注 BLOCKER / MAJOR / MINOR / NIT，附具體修正建議與依據（含來源 URL）；若無任何 issue 也要明寫
- 【verdict】唯一結論：「核准」（無 BLOCKER/MAJOR）或「需修改」（列必改項）
- 繁體中文，技術名詞保留英文

====== 設計文件 v2 開始 ======
# ArgonGuard 設計文件（送審版 v2）

日期：2026-07-05。狀態：設計定案待外部審核（v2：依 round 1 審核意見修正 OWASP 參數宣稱精確度）。

## 0. 專案背景與需求

ArgonGuard 是跨語言的密碼雜湊公用函式庫（umbrella brand），供不同技術棧的專案以獨立元件方式引用。已確認需求：

1. **硬性約束：完全符合 OWASP Password Storage Cheat Sheet 建議，核心演算法固定 Argon2id**（RFC 9106）。OWASP 現行 Cheat Sheet 對 Argon2id 列出多組彼此等效的最低配置（如 m=47104,t=1,p=1；m=19456,t=2,p=1；m=12288,t=3,p=1 等）；本專案選定 **m=19456、t=2、p=1** 作為 canonical `default`（OWASP 清單中的一組），並以其為產生端地板，只能往上。
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
| `default` | 19456 | 2 | 1 | 16 B | 32 B | OWASP 現行等效最低配置清單中選定的 canonical 一組 |
| `high` | 65536 | 2 | 1 | 16 B | 32 B | RFC 9106 次選記憶體量 |
| `highest` | 131072 | 2 | 1 | 16 B | 32 B | 記憶體為唯一強度旋鈕 |

- 全檔位 p=1：libsodium 系實作（PHP ext-sodium、未來 .NET 換引擎選項）計算時僅支援 p=1，是四語言互通的唯一安全交集
- **公開 API 無任何數字參數**——低於 OWASP 地板的雜湊在 API 層面不可表達
- 新增檔位 = spec MINOR；修改既有檔位參數 = 禁止（要調就開新檔位名）
- 舊版驗證端因範圍政策可直接驗證新檔位 hash（前向相容），僅 NeedsRehash 需升級套件

### 1.4 驗證端參數政策（MUST，downgrade 與 DoS 雙向防護）

- **地板**：`v==19`、`m≥19456`、`t≥2`、`p==1`、salt ≥16 bytes、tag ≥32 bytes；參數序必為 `m,t,p`；出現 keyid/data 即拒
- **地板設計決策（ADR 記載）**：驗證政策採「單調地板」而非 OWASP 等效配置清單的 piecewise frontier（t==1 需 m≥47104、t==2 需 m≥19456…）。理由：單調比較在四語言各自實作下最不會漂移，是防呆優先的刻意收緊；代價是 OWASP 認可但形狀不同的外部存量雜湊（如 m=47104,t=1,p=1）會被核心判 `PolicyViolation`——此類存量屬遷移情境，由 legacy verifier 顯式 opt-in 認領（§3.2 dispatch 已涵蓋），非預設放行。此收緊不違反「完全符合 OWASP」約束：本函式庫**產生**的一切雜湊都在 OWASP 等效清單之上；驗證端比 OWASP 更嚴屬允許方向。
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
| 參數達等效最低配置 | `default` = 等效清單中的 (19456,2,1)；公開 API 無數字參數 | 建置期 profile 快照 CI + 執行期驗證端單調地板（刻意比等效集更嚴，見 §1.4 ADR）+ reject 向量 |
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

- OWASP Password Storage Cheat Sheet Argon2id 2025 minimum configuration m=19456
- PHP password_hash PASSWORD_ARGON2ID libsodium argon2 provider difference
- libsodium argon2id p=1 parallelism limitation opslimit memlimit
- argon2-cffi hash_secret_raw check_needs_rehash Python 3.13
- @node-rs/argon2 hashRaw verify PHC format WASM fallback
- Konscious.Security.Cryptography.Argon2 maintenance status 2024 2025
## Output

I have sufficient verified data. Let me proceed with the complete review.

# ArgonGuard 設計文件 v2 — Round 2 完整審核

## 前言：Round 1 修正確認

Round 1 我指出「OWASP 最低參數被寫成單一組 (m=19456,t=2,p=1)」的精確度問題。v2 已在 §1.1、§1.3、§1.4、§6 全面改寫為「等效配置清單 + canonical default + 單調地板 ADR + legacy opt-in」的結構。

**確認結果**：v2 的 OWASP 修正在事實層面已精確。經查證現行 OWASP Password Storage Cheat Sheet（[cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)），其 summary 句確實仍是「minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism」，而下方的等效清單為：

- m=47104 (46 MiB), t=1, p=1
- m=19456 (19 MiB), t=2, p=1
- m=12288 (12 MiB), t=3, p=1
- m=9216 (9 MiB), t=4, p=1
- m=7168 (7 MiB), t=5, p=1

文件 §1.1 舉例 (47104,1,1)、(19456,2,1)、(12288,3,1) 完全對應現行清單，且選 (19456,2,1) 作 canonical 恰是 OWASP summary 句採用的那一組——選型與 OWASP 自身的「代表組」一致，論證乾淨。**此項 round 1 issue 視為已解決。**

以下為本輪完整審核。

---

## 【issues】

### BLOCKER

**無。**

---

### MAJOR

**MAJOR-1｜單調地板 ADR 的安全論證成立，但與「完全符合 OWASP」硬性約束存在措辭層面的可反駁性，需補一句限定**

§1.4 ADR 的核心論證是：「本函式庫**產生**的一切雜湊都在 OWASP 等效清單之上；驗證端比 OWASP 更嚴屬允許方向。」

從**產生端**看，這完全成立——(19456,2,1)、(65536,2,1)、(131072,2,1) 三檔位皆 ≥ OWASP 等效集，無疑義。

但問題在**驗證端的收緊方向並非純粹「更嚴」**：單調地板 `t≥2 且 m≥19456` 會把 OWASP **明確認可**的 (47104,1,1) 判為 `PolicyViolation`。文件自己承認這點，並主張「由 legacy verifier opt-in 認領」。這裡的邏輯漏洞是：

- (47104,1,1) 是**純正 argon2id、且安全強度等於甚至高於** canonical default（46 MiB > 19 MiB）。把它歸類為需要 legacy verifier「降級接受」（§3.2 用詞「降級接受是看得見的 opt-in」）在**語意上不準確**——它根本不是降級，是 OWASP 認可的同級配置。
- 更嚴重：§6 合規表宣稱「參數達等效最低配置」的保證機制包含「執行期驗證端單調地板」。但單調地板在 t=1 的情況下拒絕一個 **OWASP 合規**的 hash，這不是「保證達到等效最低配置」，而是「保證達到比等效集窄的子集」。對外宣稱「完全符合 OWASP」時，若審計者拿 (47104,1,1) 質問「為什麼你的核心 verifier 拒絕 OWASP 官方清單第一組？」，「安全方向更嚴」的辯護在**驗證** context 下是站不住的（驗證變嚴 = 對合法 OWASP hash 的 false rejection，這是可用性/互通性退步，不是安全增益）。

**論證是否成立的裁定**：作為**內部產生策略**的安全論證成立；作為對外「完全符合 OWASP」的合規論證**不完整**。單調地板本質是「防呆優先、犧牲一部分 OWASP 認可配置的互通性」的工程取捨，這是合理的設計選擇，但文件把它包裝成「不違反完全符合 OWASP」是措辭過強。

**修正建議**：
1. 在 §1.4 ADR 與 §6 明確區分兩個宣稱：「**產生端**完全符合 OWASP（無條件）」與「**驗證端**核心採 OWASP 的一個真子集（monotone floor），OWASP 認可但落在 frontier 其他點的 hash 需 legacy verifier 認領」。不要用「完全符合 OWASP」涵蓋驗證端。
2. §3.2 移除或修正「降級接受」對 t=1 高記憶體案例的用詞——(47104,1,1) 是**平級 OWASP 配置**，不是降級。建議錯誤分類上為這類「OWASP-equivalent 但非單調地板」的 hash 提供獨立 reason code（如 `policy_violation.owasp_equivalent_offlist`），與真正的弱 hash（`policy_violation.m_below_floor`）區分，否則營運端無法分辨「安全的 OWASP hash 被拒」與「真的太弱」。
3. 考慮替代方案並在 ADR 中明記為何不採：即在核心 verifier 直接實作 OWASP 的 piecewise frontier（t==1→m≥47104；t==2→m≥19456；t==3→m≥12288…）。文件說 piecewise「四語言各自實作最會漂移」，但這是一張**5 行的凍結常數表**，可放進共用測試向量 byte-for-byte 驗證（§2.3 機制已存在），漂移風險其實可控。ADR 應正面回應「為何不把 frontier 也做成凍結常數表 + 跨語言向量」，否則「防呆」理由不夠有力。依據：[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)。

**MAJOR-2｜PHP 天花板 DoS 防護與 libsodium fallback 路徑的參數上限存在未驗證盲點**

§1.4 天花板設 `m≤262144`（256 MiB）、`t≤8`，宣稱封死「竄改 DB 使每次 verify 吃巨量記憶體」的 DoS。§4.4 驗證流程是「自寫嚴格 parser + 政策通過後餵 `password_verify`」。

問題：**PHP 端的天花板檢查必須在餵給 `password_verify`/`sodium_crypto_pwhash` 之前完成**，文件 §3.2 dispatch 確實把政策檢查放在重算之前，方向正確。但有兩個未覆蓋盲點：

1. **libsodium fallback 路徑的 m 單位語意**：文件 §4.4 提到「偵測到 ext-sodium 可走 sodium fallback」，且 §4.4 deterministic 向量「以 `sodium_crypto_pwhash` raw 重算」。但 `sodium_crypto_pwhash` 的 `memlimit` 參數單位是 **bytes**，而 PHC 字串裡的 m 是 **KiB**；`password_hash`（libargon2 provider）的 `memory_cost` 也是 **KiB**。跨這兩個 provider 重算同一 PHC 字串時，m 的單位換算（KiB → bytes ×1024）是一個典型的 off-by-1024 錯誤源。文件完全沒提這個換算，而它正是 §4.4「全檔位 p=1 使 libargon2/sodium provider 行為一致」宣稱背後最容易錯的點。此外 libsodium 對 memlimit/opslimit 有其**自身的最小值下限**（`crypto_pwhash_MEMLIMIT_MIN` 等），low-level 餵任意 PHC 參數可能被 libsodium 拒絕或行為不一致。
2. **sodium provider 的 p=1 限制需明確驗證**：文件 §1.3 宣稱「libsodium 系實作計算時僅支援 p=1」。經查證，libsodium 的 `crypto_pwhash` 家族確實不暴露 parallelism 參數（固定 threads=1），這佐證了全檔位 p=1 的互通交集決策是正確的（[doc.libsodium.org/password_hashing](https://doc.libsodium.org/password_hashing)）。**此宣稱屬實**，但正因如此，若 sodium fallback 收到 p>1 的外部存量 hash，行為未定義——雖然政策地板 p==1 會擋掉，但 dispatch 上要確保 p 檢查在 sodium 重算前。

**修正建議**：
- 在 §4.4 明載 KiB↔bytes 的 memlimit 換算，並把它列為 PHP 端 deterministic 向量的**專門測試項**（同一 PHC 字串分別經 libargon2 provider 與 sodium provider 重算須 byte-for-byte 一致）。
- 明載天花板 256 MiB 在 sodium 路徑對應 `memlimit=268435456` bytes，並確認未超過或未低於 libsodium 的 MIN/MAX 常數。
- ADR 記載：sodium fallback 僅用於「向量重算/測試」還是「生產 verify」？若是生產路徑，其參數合法域必須與 libargon2 provider 一致並測試。依據：[libsodium password_hashing](https://doc.libsodium.org/password_hashing)、[PHP password_hash manual](https://www.php.net/manual/en/function.password-hash.php)。

---

### MINOR

**MINOR-1｜argon2-cffi `check_needs_rehash` 未被使用，NeedsRehash 全自寫，宣稱「與 argon2-cffi 一致」需微調**

§3.3 宣稱 NeedsRehash 語意「與 PHP `password_needs_rehash`／argon2-cffi `check_needs_rehash` 一致」。經查證 argon2-cffi 的 `check_needs_rehash(hash)` 語意確為「hash 是否用 instance 的 parameters 建立」（[argon2-cffi API docs](https://argon2-cffi.readthedocs.io/en/stable/api.html)），**確與文件的「精確參數比對」語意相符**——此宣稱屬實。

但 §4.3 Python 實作用 argon2-cffi 的 `hash_secret_raw`（低階重算），§4.4 PHP 明確「不用 `password_needs_rehash`，避免 provider 漂移」而自寫 parser。**四語言的 NeedsRehash 都是自寫的**，所以「與 argon2-cffi/PHP 一致」只是**行為語意類比**，不是**呼叫底層**。措辭沒錯但易被誤讀為「委派給底層」。

**修正建議**：§3.3 改為「語意上等價於（equivalent in semantics to）」，並註明四語言 NeedsRehash 皆由 spec 層自寫 parser 實作、不呼叫底層 rehash 判斷函式（此點其實是優點：消除 provider 漂移，應正面寫出）。依據：[argon2-cffi API](https://argon2-cffi.readthedocs.io/en/stable/api.html)。

**MINOR-2｜netstandard2.0 無 `CryptographicOperations.FixedTimeEquals`，自寫 XOR polyfill 的常數時間性需明確測試策略而非僅「等價測試」**

§4.1 與 §6 表格提到 netstandard2.0 走 `#if` 自寫 XOR 累加版。**事實正確**：`CryptographicOperations.FixedTimeEquals` 在 netstandard2.0 確實不可用（.NET Core 2.1+ / .NET Standard 2.1 才有），4.6.2/net48 走 netstandard2.0 資產時需 polyfill。

問題：文件的 CI 策略是「雙 TFM 等價測試」——但**等價測試只能證明兩條路徑輸出相同 bool，無法證明 polyfill 是常數時間**。手寫 XOR 累加最常見的錯誤是：(a) 提早 return（長度不等時）、(b) JIT 對 volatile 缺失做短路優化、(c) 累加變數被優化掉。這些不會被「等價測試」抓到。

**修正建議**：
- 明載 polyfill 實作要求：先比長度但比較本身不因長度提早 return（或長度不等時仍走完固定路徑）、累加變數避免被優化（`byte`累加後整體比對）、加註為何不需要 `[MethodImpl(NoOptimization)]` 或若需要則加上。
- CI 除等價測試外，加一項「polyfill 對 tag 前綴差異 vs 尾綴差異的時間分布不應顯著不同」的統計 sanity（承認 timing 測試在 CI 抖動大，至少列為 informative）。或更簡單：優先評估引用 `System.Security.Cryptography.Primitives` 或 `Portable.BouncyCastle` 既有常數時間比較，而非自寫。依據：`CryptographicOperations` API 可用性（.NET API docs，netstandard2.0 不含）。

**MINOR-3｜跨語言 PHC base64「無 padding」的解析寬容度未規範，互通盲點**

§1.2 規定產生端 Base64「無 padding、非 base64url、RFC 4648 §4 標準字元集」。這與 PHC / crypt 慣例一致（argon2 reference、argon2-cffi、PHP 皆輸出無 padding 標準 base64）。**產生端規範正確。**

但盲點在**驗證端解析**：§2.3 的 `verify.json` 要「含外部系統產生的合法 PHC」。外部系統（某些自訂實作、舊工具）**可能產生帶 `=` padding 的 base64**。文件的嚴格 parser 是否拒絕帶 padding 的 salt/hash？§2.2 把「b64 非法」歸 `MalformedHash`。若嚴格 parser 對 padding 一律拒絕，則某些技術上合法的外部 argon2id hash 會被判 malformed，與「外部存量直接可驗」（§1.1）的賣點衝突。

**修正建議**：§1.2/§2.3 明確規定驗證端解析對 padding 的態度（建議：產生端 MUST 無 padding；驗證端 parser 對 salt/hash 段的 padding **明確定義**接受或拒絕，並在 `reject.json`/`verify.json` 各放一條 padding 邊界向量固定行為）。這是四語言 bit-level parser 一致性最容易漂移的點之一。

**MINOR-4｜Node `@node-rs/argon2` 與 PHC 編碼自寫層的向量來源獨立性**

§4.2 用 `@node-rs/argon2` 的 `hashRaw`「支撐向量驗證」+「PHC 編碼自寫層」。§2.3 凍結程序要求向量由「argon2 reference CLI × argon2-cffi」兩獨立實作產生、且「ArgonGuard 自家實作不得作為向量來源」。這個凍結程序設計良好、值得肯定。

盲點：Node 端的 **PHC 編碼是自寫的**（因為 `@node-rs/argon2` 的 `hashRaw` 只出 raw bytes）。自寫 PHC 編碼層若在 base64/欄位順序上有 bug，`deterministic.json` 的比對能抓到（因為向量含完整 PHC 字串），**這點 OK**。但 `@node-rs/argon2` 的原生 `hash()`（非 raw）本身也輸出 PHC——文件未說明是否也拿它做交叉檢查。建議在 Node CI 加一項「自寫 PHC 編碼 vs `@node-rs/argon2` 原生 `hash()` 輸出」的一致性斷言（在固定 salt 下），零成本增加一層防呆。

**修正建議**：§4.2 補一句 Node 端「自寫 PHC 編碼層須與 `@node-rs/argon2` 原生 encoded 輸出在固定 salt 下交叉比對」。

**MINOR-5｜Konscious 維護停滯風險已對沖，但備援 Isopoh 的向量等價未列為 CI 前置**

§4.1 承認 Konscious「維護停滯（2024-06 起）」，對沖手段列了四項（可換 provider、RFC 凍結、CI 向量、可 vendor）。此風險評估務實、可接受。但「備援 Isopoh」只是提及，未說明**切換時如何保證 Isopoh 通過同一組凍結向量**。若哪天緊急切 Isopoh，應該已經有綠燈證據，而非切換時才跑。

**修正建議**：把「備援引擎 Isopoh 對凍結向量的 conformance」列為**常態或至少 nightly CI**（類似 PHP sodium-only build 的處理），使備援隨時可用而非紙上備案。

---

### NIT

**NIT-1**｜§1.2「典型輸出 97 字元」：以 m=19456（5 位數）、t=2、p=1、salt 16B（無 padding base64 = 22 字元）、tag 32B（= 43 字元）計，`$argon2id$v=19$m=19456,t=2,p=1$`(31) + 22 + `$`(1) + 43 = 97，**正確**。但 `high`（m=65536）、`highest`（m=131072，6 位數）會到 98 字元。建議寫「97–98 字元」或註明隨 m 位數變動。

**NIT-2**｜§4.1 System.Memory binding redirect 只寫進 README——對 net48 消費者這是高頻踩雷點，建議同時在 NuGet 套件描述/release notes 首屏提示，而非僅 README。

**NIT-3**｜§2.4 dummy hash「等時 dummy verify」緩解使用者列舉：OWASP Authentication Cheat Sheet 亦建議此模式，可補該來源強化 informative 依據（[Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)）。另提醒 dummy verify 只緩解「帳號存在性」timing，無法緩解「使用者主動枚舉」的其他 side channel，文件措辭已屬 informative，OK。

**NIT-4**｜§5.2「套件 MAJOR = spec MAJOR」是強耦合硬規則。若某語言套件因該語言生態原因需要 breaking change（如 .NET 移除 net48 支援 = §7.11 已定義為套件 MAJOR），會強制拉高 spec MAJOR 或破壞此規則。建議明文承認「套件 MAJOR ⊇ spec MAJOR 的觸發集」（套件可因語言生態單獨 MAJOR），避免規則自相矛盾。

---

## 事實查證彙總（供追溯）

| 宣稱 | 查證結果 | 來源 |
|---|---|---|
| OWASP 現行列多組等效配置，含 (47104,1,1)/(19456,2,1)/(12288,3,1)… | **屬實**，v2 引用精確 | [OWASP PSCS](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| libsodium 系實作計算僅支援 p=1 | **屬實**，`crypto_pwhash` 不暴露 parallelism | [libsodium](https://doc.libsodium.org/password_hashing) |
| PHP `password_hash` PASSWORD_ARGON2ID 由 libargon2/sodium provider 提供、輸出標準 PHC | **屬實**；但 sodium memlimit 單位為 bytes（見 MAJOR-2） | [PHP manual](https://www.php.net/manual/en/function.password-hash.php) |
| argon2-cffi 有 `hash_secret_raw`、`check_needs_rehash`，支援 Python 3.13/3.14 | **屬實**，25.1.0 官方支援 3.13/3.14 | [argon2-cffi API](https://argon2-cffi.readthedocs.io/en/stable/api.html)、[releases](https://github.com/hynek/argon2-cffi/releases) |
| netstandard2.0 無 `CryptographicOperations.FixedTimeEquals` | **屬實**（.NET Standard 2.1+/.NET Core 2.1+ 才有） | .NET API docs |
| `@node-rs/argon2` 有 `hashRaw` | **屬實** | 套件文件（見 MINOR-4 補測建議） |

---

## 【verdict】

# 需修改

**核准的前提是清除下列必改項（2 項 MAJOR）：**

1. **【MAJOR-1】** 修正「完全符合 OWASP」的措辭與合規宣稱範圍：明確區分「產生端無條件符合」與「驗證端核心採 OWASP 真子集（monotone floor）」；為 OWASP-equivalent 但落在 frontier 其他點（如 (47104,1,1)）的 hash 提供獨立 reason code，並在 ADR 正面回應「為何不將 OWASP piecewise frontier 也做成凍結常數表 + 跨語言向量」。單調地板作為**工程取捨**成立，但不得以「完全符合 OWASP」包裝驗證端的收緊。

2. **【MAJOR-2】** 補齊 PHP 雙 provider（libargon2 KiB vs libsodium bytes）的 memlimit 單位換算規範與專門測試向量，明確 256 MiB 天花板在 sodium 路徑的 bytes 對應與 libsodium MIN/MAX 常數邊界；並釐清 sodium fallback 屬「測試重算」或「生產 verify」路徑及其參數合法域。

**建議一併處理（MINOR-1～5）**：NeedsRehash「一致」改「語意等價 + 自寫」措辭；netstandard2.0 XOR polyfill 的常數時間實作要求與非等價測試策略；PHC base64 padding 的驗證端解析寬容度規範 + 邊界向量；Node 自寫 PHC 編碼與原生 encoded 交叉比對；Isopoh 備援納入常態/nightly conformance CI。

**整體評價**：v2 相較 round 1 在 OWASP 精確度上已顯著改善，格式決策（棄自訂格式採 PHC）、非目標邊界、凍結向量的自我引用防護（禁用自家實作作向量來源）、typed error 鐵則（false 只有一個意思）、legacy verifier 建構期注入（拒執行期動態註冊）等設計均屬高品質、符合安全工程最佳實務。BLOCKER 為零。兩項 MAJOR 均為**措辭精確度 + 跨 provider 數值正確性**問題，非架構性缺陷，修正成本低，補齊後即可核准。

## Citations

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://tomodahinata.com/en/blog/password-hashing-argon2-encryption-key-management-applied-cryptography-guide
- https://www.php.net/manual/en/function.password-hash.php
- https://dev.to/gabrielanhaia/argon2id-is-the-default-now-stop-using-bcrypt-in-2026-1g50
- https://igotaprinter.com/blog/argon2i-php-password-hash-not-compatible-libsodium.html
- https://snyk.io/fr/blog/secure-password-hashing-in-go/
- https://theproductguy.in/blogs/argon2-tuning-guide/
- https://gitpage.reccachao.net/OWASP_cheatsheet/Password_Storage_Cheat_Sheet/
- https://guptadeepak.com/the-complete-guide-to-password-hashing-argon2-vs-bcrypt-vs-scrypt-vs-pbkdf2-2026/
- https://wiki.php.net/rfc/argon2_password_hash_enhancements
- https://doc.libsodium.org/password_hashing
- https://www.inkyvoxel.com/password-hashing-in-2026/
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://www.reddit.com/r/cybersecurity/comments/ybln4q/argon2id_password_hashing_parameters_running_on/
- https://stackoverflow.com/questions/47602044/how-do-i-use-the-argon2-algorithm-with-password-hash
- https://argon2-cffi.readthedocs.io/en/stable/api.html
- https://github.com/hynek/argon2-cffi/blob/main/CHANGELOG.md
- https://github.com/hynek/argon2-cffi
- https://argon2-cffi.readthedocs.io
- https://github.com/hynek/argon2-cffi/releases
- https://argon2-cffi.readthedocs.io/en/19.1.0/api.html
- https://pypi.org/project/argon2-cffi/
- https://stackoverflow.com/questions/58431973/argon2-library-that-hashes-passwords-without-a-secret-and-with-a-random-salt-tha
- https://argon2-cffi.readthedocs.io/en/20.1.0/
- https://github.com/jimratliff/hashing-passwords-in-python-using-argon2/blob/main/README.md
- https://stackoverflow.com/questions/55142694/hashnig-passwords-with-argon2-cffi
- https://www.youtube.com/watch?v=0rHGnpH2_h8
- https://anaconda.org/conda-forge/argon2-cffi/
- https://docs.rs/neco-argon2/latest/neco_argon2/
- https://qiita.com/ryumatag/items/a3773d46b5e3b32908d1
