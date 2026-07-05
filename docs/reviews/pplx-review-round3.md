---
title: "ArgonGuard design review r3"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_8236d998-2f43-4947-9384-594225c8909f
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 36222
pplx_latency_sec: 68.04
---

# ArgonGuard design review r3

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 36222 / Latency: 68.04s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深密碼學與應用安全架構審查員。這是「ArgonGuard 跨語言密碼雜湊函式庫」設計文件的第三輪審核（round 3）。

Round 2 你給出 verdict「需修改」：MAJOR-1（「完全符合 OWASP」措辭範圍＋單調地板拒絕 OWASP 認可配置）、MAJOR-2（PHP 雙 provider memlimit 單位盲點），另有 MINOR-1~5 與 NIT-1~4。

v3 修正對照：
- MAJOR-1：驗證端地板整個改採你建議考慮的 OWASP piecewise frontier 凍結常數表（t=1→47104、t=2→19456、t=3→12288、t=4→9216、t≥5→7168），OWASP 認可配置核心直接可驗；§0 合規宣稱明確分產生端/驗證端；ADR 記載 v2 單調地板被否決的原因；reason code 改 below_owasp_frontier 等
- MAJOR-2：§4.4 新增雙 provider memlimit 單位規範（KiB vs bytes、×1024 換算、256MiB=268435456 bytes、libsodium MIN/MAX 界內斷言）、sodium fallback 角色 ADR（require-dev 向量重算＋生產 fallback 需過同一 conformance 向量的專門 CI job）
- MINOR-1：NeedsRehash 改「語意上等價」＋明載四語言自寫 parser；MINOR-2：polyfill normative 實作要求（不提早 return、XOR 累加、NoInlining|NoOptimization）＋時間分布統計 sanity（informative）；MINOR-3：base64 padding 驗證端一律拒絕＋reject 向量釘死；MINOR-4：Node 自寫 PHC 編碼 vs 原生 hash() 交叉比對；MINOR-5：Isopoh conformance 入 nightly CI
- NIT-1：97–98 字元；NIT-2：redirect 提示進 NuGet 描述/release notes；NIT-3：補 OWASP Authentication Cheat Sheet 依據＋dummy verify 限制明載；NIT-4：版本規則改「套件 MAJOR 觸發集 ⊇ spec MAJOR」

請完成 round 3 完整審核：確認上述修正是否到位、是否引入新問題。輸出格式（務必完整輸出到 verdict 為止）：
- 【issues】每項標 BLOCKER / MAJOR / MINOR / NIT＋修正建議＋依據；無 issue 也要明寫
- 【verdict】唯一結論：「核准」（無 BLOCKER/MAJOR）或「需修改」
- 繁體中文，技術名詞保留英文

====== 設計文件 v3 開始 ======
# ArgonGuard 設計文件（送審版 v3）

日期：2026-07-05。狀態：設計定案待外部審核（v3：依 round 2 審核意見修正——MAJOR-1 驗證端地板改採 OWASP piecewise frontier 凍結常數表、MAJOR-2 補 PHP 雙 provider memlimit 單位規範、MINOR-1～5 與 NIT-1～4 全數採納）。

## 0. 專案背景與需求

ArgonGuard 是跨語言的密碼雜湊公用函式庫（umbrella brand），供不同技術棧的專案以獨立元件方式引用。已確認需求：

1. **硬性約束：完全符合 OWASP Password Storage Cheat Sheet 建議，核心演算法固定 Argon2id**（RFC 9106）。合規宣稱分兩端明確定義：**產生端**——本函式庫產生的一切雜湊無條件符合 OWASP（三檔位皆 ≥ 等效最低配置）；**驗證端**——核心 verifier 接受整個 OWASP 等效配置 frontier（凍結常數表，見 §1.4）及其以上，即 OWASP 認可的 argon2id 雜湊核心直接可驗。OWASP 現行等效最低配置清單：m=47104,t=1,p=1；m=19456,t=2,p=1；m=12288,t=3,p=1；m=9216,t=4,p=1；m=7168,t=5,p=1（全部 p=1）。本專案選定 **m=19456、t=2、p=1**（OWASP summary 句採用的代表組）作為 canonical `default`。
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
- 典型輸出 97–98 字元（依 m 位數而定：default 97、highest 98）；儲存欄位建議 ≥128 字元，規格上限 512 字元

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

- **地板（OWASP frontier 凍結常數表）**：`v==19`、`p==1`、salt ≥16 bytes、tag ≥32 bytes；參數序必為 `m,t,p`；出現 keyid/data 即拒；(m,t) 必須落在 OWASP 等效配置 frontier 之上：

  | t | m 最低（KiB） |
  |---|---|
  | 1 | 47104 |
  | 2 | 19456 |
  | 3 | 12288 |
  | 4 | 9216 |
  | ≥5 | 7168 |

  低於 frontier → `PolicyViolation`（reason code `policy_violation.below_owasp_frontier`）。
- **地板設計決策（ADR 記載）**：v2 原採「單調地板 m≥19456 且 t≥2」，round 2 審核指出其會拒絕 OWASP 明確認可的 (47104,1,1) 等配置，使「完全符合 OWASP」在驗證端不成立；且「防呆」論證擋不住「frontier 只是 5 行凍結常數表、可用共用測試向量 byte-for-byte 驗證」的反駁。故 v3 改採 **frontier 常數表**：表隨 spec 版本凍結（記載 OWASP 查證 commit/日期），四語言以共用 reject/verify 向量釘死行為；OWASP 若調整清單 → spec MINOR 更新表＋向量。p>1 的外部存量（如 Django p=8）仍為 out-of-policy → legacy verifier 顯式 opt-in（§3.2）。
- **天花板**：`m≤262144`（256 MiB）、`t≤8`、salt ≤64 bytes、tag ≤128 bytes、整條字串 ≤512 字元（解析前預檢）——封死「竄改 DB 使每次 verify 吃巨量記憶體」的 DoS
- 政策通過後以字串內參數重算 tag，constant-time 比較
- **Base64 解析寬容度（normative）**：產生端 MUST 無 padding（RFC 4648 §4 標準字元集）；**驗證端 parser 對帶 `=` padding 的 salt/hash 段一律拒絕**（`malformed.bad_base64`）——主流實作（reference CLI、argon2-cffi、PHP、node）皆輸出無 padding，嚴格拒絕使解析面最小；`reject.json` 放 padding 邊界向量釘死四語言一致行為
- **建置期不變式**：CI 斷言 profile 表每項落在 frontier 之上、frontier 表與快照 append-only 比對、`default==(19456,2,1)` 永久哨兵測試

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
| `PolicyViolation` | 低於 OWASP frontier/超過天花板/p≠1、缺 v、含 keyid/data | `policy_violation.below_owasp_frontier`、`policy_violation.m_above_ceiling`、`policy_violation.p_not_one` |
| `InvalidInput` | 密碼空/超長/NUL/surrogate | `invalid_input.password_too_long` |
| `UnsupportedEnvironment` | 環境無 argon2id（主要 PHP） | `environment.argon2id_unavailable` |

鐵則：**Verify 的 false 只有一個意思——格式合法、政策合規、密碼不符**；其餘一律 typed error，不得以 false 偽裝（否則資料毀損被誤當打錯密碼）。錯誤訊息禁含密碼與 tag 內容。

### 2.3 共用測試向量（spec/vectors/v1/*.json，immutable）

五類：`deterministic.json`（固定 salt 產生端向量）、`verify.json`（含外部系統產生的合法 PHC）、`reject.json`（逐類錯誤 + reason code 斷言）、`needs-rehash.json`、`input-limits.json`（1024/1025 邊界、空密碼拒絕、NUL 拒絕、surrogate 拒絕、NFC vs NFD 產生不同 hash、emoji、CJK）。密碼以 `passwordHex` 為 normative。

**向量凍結程序**：deterministic 向量由兩個彼此獨立的既有實作（argon2 reference CLI × argon2-cffi）分別產生、byte-for-byte 比對一致才凍結；**ArgonGuard 自家實作不得作為向量來源**（杜絕自我引用式錯誤）。

### 2.4 使用者列舉緩解（informative）

spec 提供每檔位一條 canonical dummy hash 常數（凍結程序中產生），文件附「帳號不存在時跑等時 dummy verify」模式（OWASP Authentication Cheat Sheet 同建議此模式）；實作 MAY 曝露輔助函式，不強制。明載限制：dummy verify 只緩解「帳號存在性」timing side channel，不涵蓋其他列舉管道。

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

語意：政策內的 argon2id（含整個 OWASP frontier 之上的外部存量）永遠走核心直接可驗；out-of-policy argon2id（低於 frontier、p>1 如 Django p=8、或超過天花板）可由顯式註冊的 legacy verifier 認領——接受政策外參數是看得見的 opt-in；預設（不註冊）fail-fast。

### 3.3 NeedsRehash 語意

`NeedsRehash = 「這筆 hash 不是用現行 active profile 的精確參數產生的」`。與 active profile 任一欄位不同即 true（含高於 active 的情況——語意可預測，**語意上等價於** PHP `password_needs_rehash`／argon2-cffi `check_needs_rehash` 的精確參數比對，儲存庫收斂到單一參數組）。注意：四語言的 NeedsRehash 皆由 spec 層自寫 parser 實作、不呼叫底層函式庫的 rehash 判斷——這是刻意設計，消除 provider 漂移。legacy verifier 認領的格式恆 true；無法解析且無人認領 → 拋 `MalformedHash`（不折疊成 true，避免資料毀損不可見）。

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
- netstandard2.0 無 `CryptographicOperations.FixedTimeEquals` → `#if` 自寫 constant-time polyfill。**polyfill 實作要求（normative）**：長度不等時不提早 return（仍走完固定長度比較路徑）、逐 byte XOR 累加到 int 後整體判零、標注 `[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]` 防 JIT 短路優化。測試策略：雙 TFM 等價測試（功能正確）＋ 前綴差異 vs 尾綴差異的時間分布統計 sanity（informative，承認 CI 抖動、不擋 merge）；曾評估引用既有套件（Portable.BouncyCastle 等）但為零依賴原則採自寫＋審查
- CI 在 net8.0（Linux）+ net48（Windows）跑完整向量（防 TFM 資產靜默漂移）
- Konscious 維護停滯（2024-06 起）風險對沖：internal provider 可換、RFC 9106 已凍結、向量常態 CI、MIT 可 vendor；**備援引擎 Isopoh 對凍結向量的 conformance 列入 nightly CI**（備援隨時可用，非紙上備案）
- System.Memory binding redirect 疑難排解：README＋NuGet 套件描述與 release notes 首屏同步提示（net48 消費者高頻踩雷點）
- ASP.NET Identity adapter：v1 文件內十行範例；v1.1 視需求出子套件

### 4.2 Node.js / TypeScript

- 套件：npm `@argonguard/passwords`（先註冊 org「argonguard」；備援 `argonguard-passwords`）
- 引擎：@node-rs/argon2（平台覆蓋最完整，含 Alpine musl／WASM fallback、無 postinstall、`hashRaw` 支撐向量驗證）；PHC 編碼自寫層——CI 加一項固定 salt 下「自寫 PHC 編碼 vs `@node-rs/argon2` 原生 `hash()` encoded 輸出」交叉比對斷言（零成本多一層防呆）
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
- **雙 provider memlimit 單位規範（normative，MAJOR-2 修正）**：PHC 字串與 `password_hash` 的 `memory_cost` 單位為 **KiB**；`sodium_crypto_pwhash` 的 `memlimit` 單位為 **bytes**——換算 `memlimit = m × 1024`（典型 off-by-1024 錯誤源，spec 明文＋專門測試項）。天花板 256 MiB 對應 sodium `memlimit = 268435456` bytes；frontier 最低 m=7168 KiB = 7340032 bytes ≥ libsodium `crypto_pwhash_MEMLIMIT_MIN`（8192）、t≥1 ≥ `OPSLIMIT_MIN`（1），全政策域落在 libsodium 合法界內（實作時以常數斷言驗證）
- **sodium fallback 角色（ADR 記載）**：(a) require-dev 層級的 deterministic 向量重算（常態）；(b) 生產 verify fallback——僅當 `password_algos()` 無 argon2id 且 ext-sodium 存在時啟用，以自寫 parser 解出參數→bytes 換算→`sodium_crypto_pwhash` raw 重算→`hash_equals`；此路徑必須通過與 libargon2 provider 完全相同的 conformance 向量（CI 專門 job：同一 PHC 字串經雙 provider 重算 byte-for-byte 一致）
- 驗證：自寫嚴格 parser + 政策通過後餵 `password_verify`；`needsRehash` 用自寫 parser（不用 `password_needs_rehash`，避免 provider 漂移）
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
- 套件各自獨立 SemVer；硬規則：**spec MAJOR 必觸發套件 MAJOR**，但套件可因語言生態原因單獨 MAJOR（如提升支援地板），即「套件 MAJOR 觸發集 ⊇ spec MAJOR」；metadata 宣告 `Implements ArgonGuard Spec 1.x` 為版本對應的唯一權威來源
- Git tag：`spec/v1.0.0`、`dotnet/v1.2.3`…，tag prefix 觸發對應發佈 workflow
- 發佈：NuGet 簽章、npm provenance、PyPI trusted publishing（OIDC）、Packagist hook

### 5.3 CI 守門（四道）

1. **Profile 與 frontier 不變式**（建置期紅燈）：OWASP frontier 表斷言、profile 快照 append-only 比對、`default==(19456,2,1)` 哨兵
2. **Per-language 向量 conformance**：.NET 雙 TFM（net8.0 Linux + net48 Windows）；Node 平台×版本矩陣；Python 3.9–3.14；PHP 8.2–8.5（每 PR 跑 standard provider＋雙 provider memlimit 換算專門 job；sodium-only 自編譯 build 降為 nightly）；**.NET 備援引擎 Isopoh conformance 為 nightly**
3. **跨語言 4×4 round-trip 矩陣**（擋 merge）：各實作 dev harness（stdin/stdout JSON 協議）對隨機密碼×三檔位互 hash 互驗 + needs-rehash 斷言
4. **Supply-chain**：lockfile pin、Dependabot、底層引擎升版必過完整向量迴歸

### 5.4 營運手冊

檔位切換 SOP（SHOULD）：先全 fleet 升級函式庫 → 觀察一個週期 → 再切 active profile。前向相容使違反此順序不會炸，但遵守它讓 NeedsRehash 行為全程可預測。

## 6. 安全保證（OWASP 完全合規追溯）

| OWASP 要求 | 落點 | 保證機制 |
|---|---|---|
| Use Argon2id | 核心只產/只收 argon2id | 型別層無其他選項；`$argon2i$`/`$2b$` 進 reject 向量 |
| 參數達等效最低配置 | 產生端：三檔位皆 ≥ 等效清單；驗證端：核心接受完整 OWASP frontier 之上 | 建置期 profile/frontier 快照 CI + 執行期 frontier 常數表（§1.4）+ reject/verify 向量 |
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

- OWASP Password Storage Cheat Sheet Argon2id parameters 2025
- libsodium crypto_pwhash_MEMLIMIT_MIN value
- OWASP Argon2id m=47104 t=1 m=19456 t=2 configurations
## Output

The search confirms the key technical claims. Let me verify the critical figures:

- **OWASP frontier** (verified against cheatsheetseries.owasp.org, live 2026-07-03): m=47104/t=1, m=19456/t=2, m=12288/t=3, m=9216/t=4, m=7168/t=5 — **exactly matches** the v3 frozen constant table. ✓
- **libsodium `MEMLIMIT_SENSITIVE` = 268435456 bytes (256 MiB)** confirmed (tessl libsodium doc). The v3 ceiling `m≤262144 KiB × 1024 = 268435456 bytes` computation is **arithmetically correct**. ✓
- **frontier min m=7168 KiB × 1024 = 7340032 bytes** ≥ `crypto_pwhash_MEMLIMIT_MIN` (8192) confirmed as within bounds. ✓
- **`crypto_pwhash_MEMLIMIT_INTERACTIVE` = 67108864 bytes (64 MiB)** — relevant note below.
- **OWASP Authentication Cheat Sheet** confirms the constant-time / max-input-length / type-explicit comparison guidance and the "dummy verify" enumeration pattern basis. ✓

Now the full round 3 review.

---

# ArgonGuard 設計文件 Round 3 審核

## 【issues】

### MAJOR-1（round 2）修正確認 — ✅ 到位
v3 驗證端地板已整個改採 OWASP piecewise frontier 凍結常數表（t=1→47104、t=2→19456、t=3→12288、t=4→9216、t≥5→7168）。經對照 OWASP Password Storage Cheat Sheet 現行內容（cheatsheetseries.owasp.org，查證日 2026-07-03），**五組常數 byte-for-byte 完全一致**。§0 已明確分產生端（無條件 ≥ 等效最低）／驗證端（接受完整 frontier 之上），ADR 記載 v2 單調地板被否決原因，reason code 改 `policy_violation.below_owasp_frontier`。frontier 表凍結＋共用 reject/verify 向量釘死＋OWASP 調整走 spec MINOR 的治理路徑齊備。**MAJOR-1 已解除。**

### MAJOR-2（round 2）修正確認 — ✅ 到位
§4.4 新增雙 provider memlimit 單位規範完整：KiB vs bytes、`memlimit = m × 1024`、256MiB=268435456 bytes、frontier min 7168 KiB=7340032 bytes ≥ MEMLIMIT_MIN。經查證：libsodium `MEMLIMIT_SENSITIVE`=268435456 bytes（=256MiB），v3 天花板換算算術正確；MEMLIMIT_MIN/OPSLIMIT_MIN 界內斷言方向正確。sodium fallback 角色 ADR（require-dev 向量重算＋生產 fallback 需過同一 conformance 向量的專門 CI job：同一 PHC 經雙 provider byte-for-byte）齊備。**MAJOR-2 已解除。**

### MINOR-1～5、NIT-1～4 — ✅ 全數到位
- MINOR-1：§3.3「語意上等價」措辭＋四語言自寫 parser 明載。✓
- MINOR-2：§4.1 polyfill normative（不提早 return／XOR 累加到 int 整體判零／`NoInlining|NoOptimization`）＋時間分布統計 sanity 標 informative。✓
- MINOR-3：§1.4 驗證端一律拒絕 padding（`malformed.bad_base64`）＋`reject.json` padding 邊界向量。✓
- MINOR-4：§4.2 自寫 PHC 編碼 vs `@node-rs/argon2` 原生 `hash()` 交叉比對 CI 斷言。✓
- MINOR-5：§4.1、§5.3 Isopoh conformance 入 nightly CI。✓
- NIT-1：§1.2 改「97–98 字元」。✓
- NIT-2：§4.1 redirect 提示進 NuGet 描述/release notes 首屏。✓
- NIT-3：§2.4 補 OWASP Authentication Cheat Sheet 依據（已查證該頁確實建議此模式）＋dummy verify 限制明載（僅緩解帳號存在性 timing）。✓
- NIT-4：§5.2 改「套件 MAJOR 觸發集 ⊇ spec MAJOR」。✓

---

### 新引入 / 殘留問題

**NIT-1（新）— frontier reason code 粒度與天花板 reason code 不對稱**
§2.2 表列 `policy_violation.below_owasp_frontier`、`m_above_ceiling`、`p_not_one`，但 §1.4 天花板同時含 `t≤8`、`salt≤64`、`tag≤128`、整條 ≤512。目前僅見 `m_above_ceiling` 一個天花板 reason code；`t>8`、`salt/tag 超限` 落哪個 code 未明。建議：於 §2.2 補齊天花板各維度 reason code（如 `policy_violation.t_above_ceiling`、`policy_violation.salt_too_long`），或明文規定共用一個 `policy_violation.above_ceiling` 並在向量釘死——避免四語言各自命名漂移（這正是本專案 reason code 穩定性初衷）。依據：§2.2「跨語言穩定 reason code」自身目標。

**NIT-2（新）— `below_owasp_frontier` 與 t≥5 邊界的向量覆蓋需明列**
frontier 表對 t≥5 一律用 m≥7168，隱含 t=5、t=6、t=7、t=8 皆共用同一 m 地板（且 t=8 為天花板）。建議 `reject.json`/`verify.json` 明確釘死至少 (7168, 5)（通過）、(7167, 5)（拒）、(7168, 8)（通過，t 恰在天花板）、(7168, 9)（拒，t 超天花板）四個邊界，確認「frontier 下限」與「天花板上限」在 t≥5 區段正確交疊、無縫隙也無矛盾。依據：§1.4 frontier 與天花板為兩獨立不等式，交疊區需測試證明一致。

**NIT-3（新）— sodium fallback 生產路徑的參數域斷言應明文含「≤ MEMLIMIT_MAX」**
§4.4 已斷言 frontier min ≥ MEMLIMIT_MIN、t ≥ OPSLIMIT_MIN，但天花板側只斷言 256MiB=268435456 bytes 為政策上限，未明文斷言此值 ≤ libsodium `crypto_pwhash_MEMLIMIT_MAX`／t≤8 ≤ `OPSLIMIT_MAX`。查證顯示 MEMLIMIT_SENSITIVE 即為 268435456，屬常用界內值，實務無虞，但為使「全政策域落在 libsodium 合法界內」宣稱雙向完備，建議補上上界常數斷言。依據：§4.4 該句宣稱「全政策域落在 libsodium 合法界內」須含上界。

**NIT-4（新，informative 提醒）— libsodium fallback 對 (t=1) frontier 配置的可計算性須向量驗證**
OWASP frontier 含 (47104, t=1)。歷史上 libsodium/Argon2i 曾要求 opslimit≥3；查證確認該限制**僅適用 Argon2i**，Argon2id 無此下限（OPSLIMIT_MIN=1），故 (m,t=1) 對 argon2id 合法。此處無 blocker，但既然 sodium fallback 生產路徑須過「同一 conformance 向量」，建議 conformance 向量集**明確納入一組 t=1 argon2id PHC**，實測驗證 `sodium_crypto_pwhash` 對 t=1 opslimit 不拒絕（防止未來 libsodium 版本行為漂移靜默使 fallback 對整段 frontier 失效）。依據：§3.2 語意「整個 frontier 之上核心直接可驗」對 PHP sodium fallback 路徑亦須成立。

**NIT-5（措辭）— §0 與 §1.3 canonical default 論述可再收斂**
§0 稱 default=(19456,2,1) 為「OWASP summary 句採用的代表組」，§1.3 依據欄稱「清單中選定的 canonical 一組」。措辭正確且已較 v2 收斂，惟兩處描述略異。建議統一為單一權威描述（引用 §0 定義），純編輯性。依據：文件內部一致性。

---

以上新問題**全部為 NIT 等級**（reason code 粒度、向量覆蓋完備性、上界斷言明文化、措辭收斂），均屬「使已正確的設計更防漏」的加固建議，**無一觸及正確性或安全性缺陷**，不構成 BLOCKER/MAJOR/MINOR。round 2 的 MAJOR-1、MAJOR-2 及全部 MINOR/NIT 均已確認到位，且修正未引入回歸或新的重大風險。

## 【verdict】

**核准**

（無 BLOCKER、無 MAJOR。round 2 兩項 MAJOR 及全部 MINOR/NIT 修正皆確認到位，關鍵常數與換算已對照 OWASP 現行 Cheat Sheet 及 libsodium 常數查證無誤；本輪僅提出 5 項 NIT 級加固建議，建議於實作/向量凍結時採納，但不阻擋核准。）

## Citations

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://owasp.deteact.com/cheat/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://libsodium.gitbook.io/doc/password_hashing/default_phf
- https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_pwhash/index.html
- https://zenn.dev/manase/scraps/b96e58515084bb
- https://www.reddit.com/r/crypto/comments/m9w2ea/password_storage_owasp_cheat_sheet_series/
- https://tessl.io/registry/tessl/npm-libsodium-wrappers/0.7.0/files/docs/password-hashing.md
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://community.bitwarden.com/t/argon2id-settings-higher-values-better/70073/6
- https://bellatorcyber.com/blog/best-password-hashing-algorithms-of-2023
- https://metacpan.org/release/IAMB/Crypt-Sodium-XS-0.001001/view/lib/Crypt/Sodium/XS/pwhash.pm
- https://www.reddit.com/r/Bitwarden/comments/1c2xmfr/argon2id_defaults_are_much_higher_than_owasp/
- https://snyk.io/fr/blog/secure-password-hashing-in-go/
- https://theproductguy.in/blogs/argon2-tuning-guide/
- https://tomodahinata.com/en/blog/password-hashing-argon2-encryption-key-management-applied-cryptography-guide
