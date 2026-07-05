---
title: "ArgonGuard implementation plan breakdown"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_0133dc5c-ddac-42c0-b4bb-0b6a36af8832
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 46166
pplx_latency_sec: 166.76
---

# ArgonGuard implementation plan breakdown

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 46166 / Latency: 166.76s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深軟體交付架構師。以下 ArgonGuard 設計文件已經過三輪審核達成共識（verdict「核准」）。現在進入實作規劃階段，請你協助拆解實作任務，產出具體的實作規劃建議，內容必須涵蓋：

1. **模組劃分**：monorepo 內 spec/、dotnet/、node/、python/、php/ 各自的模組切分與依賴關係；每個模組的職責邊界（PHC parser、政策檢查、引擎 provider、公開 API、legacy 擴充點）
2. **開發順序與里程碑**：建議的 milestone 切分（例如 M0 骨架、M1 spec+向量、M2 .NET 參考實作、M3 跨語言、M4 CI/發佈），每個 milestone 的完成定義（DoD）；注意設計指定 .NET 為第一優先參考實作、向量凍結程序（argon2 reference CLI × argon2-cffi 雙獨立來源）必須先於任何實作的 conformance 測試
3. **測試策略**：單元測試、共用向量 conformance、跨語言 round-trip 矩陣、negative/reject 測試、（informative）timing sanity 的落點與工具選擇；各語言測試框架建議（xUnit? Vitest? pytest? PHPUnit?）
4. **風險與依賴**：哪些任務有外部依賴（npm org 註冊、NuGet prefix reservation、PyPI/Packagist 名稱）、哪些任務可平行、哪些必須序列
5. **每個任務的粒度**：拆到「一個 PR 可完成」的層級，附驗收條件

請以可直接轉成任務清單的結構輸出（milestone → task → DoD），繁體中文，技術名詞保留英文。

====== 共識版設計文件 v3.1 ======
# ArgonGuard 設計文件（共識版 v3.1）

日期：2026-07-05。狀態：**已與 Perplexity 達成設計共識**（round 3 verdict「核准」，模型 anthropic/claude-opus-4-8 經 PPLX Agent API）。審核歷程：round 1 指出 OWASP 等效配置精確度 → v2 修正；round 2 verdict「需修改」（MAJOR-1 驗證端地板、MAJOR-2 PHP 雙 provider 單位）→ v3 全數修正（含 MINOR-1~5、NIT-1~4）；round 3 verdict「核准」，另提 5 項 NIT 級加固已併入本版（v3.1）。本文件為後續實作的 SOT。

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
| `default` | 19456 | 2 | 1 | 16 B | 32 B | canonical default（定義見 §0 需求 1） |
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
| `PolicyViolation` | 低於 OWASP frontier/超過天花板/p≠1、缺 v、含 keyid/data | `policy_violation.below_owasp_frontier`、`policy_violation.m_above_ceiling`、`policy_violation.t_above_ceiling`、`policy_violation.salt_length_out_of_range`、`policy_violation.tag_length_out_of_range`、`policy_violation.p_not_one` |

天花板每一維度都有專屬 reason code（m、t、salt、tag），四語言以 reject 向量釘死命名，禁止各自發明。
| `InvalidInput` | 密碼空/超長/NUL/surrogate | `invalid_input.password_too_long` |
| `UnsupportedEnvironment` | 環境無 argon2id（主要 PHP） | `environment.argon2id_unavailable` |

鐵則：**Verify 的 false 只有一個意思——格式合法、政策合規、密碼不符**；其餘一律 typed error，不得以 false 偽裝（否則資料毀損被誤當打錯密碼）。錯誤訊息禁含密碼與 tag 內容。

### 2.3 共用測試向量（spec/vectors/v1/*.json，immutable）

五類：`deterministic.json`（固定 salt 產生端向量）、`verify.json`（含外部系統產生的合法 PHC）、`reject.json`（逐類錯誤 + reason code 斷言）、`needs-rehash.json`、`input-limits.json`（1024/1025 邊界、空密碼拒絕、NUL 拒絕、surrogate 拒絕、NFC vs NFD 產生不同 hash、emoji、CJK）。密碼以 `passwordHex` 為 normative。

**frontier × 天花板交疊邊界向量（必含）**：(m=7168,t=5) 通過、(m=7167,t=5) 拒（below_owasp_frontier）、(m=7168,t=8) 通過（t 恰在天花板）、(m=7168,t=9) 拒（t_above_ceiling）——證明 t≥5 區段 frontier 下限與天花板上限正確交疊、無縫隙無矛盾。**t=1 向量（必含）**：一組 (m≥47104,t=1) 的 argon2id PHC 進 conformance 向量，確保 PHP sodium fallback 路徑對 t=1（OPSLIMIT_MIN=1，Argon2id 無 Argon2i 的 opslimit≥3 限制）不會靜默失效。

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
- **雙 provider memlimit 單位規範（normative，MAJOR-2 修正）**：PHC 字串與 `password_hash` 的 `memory_cost` 單位為 **KiB**；`sodium_crypto_pwhash` 的 `memlimit` 單位為 **bytes**——換算 `memlimit = m × 1024`（典型 off-by-1024 錯誤源，spec 明文＋專門測試項）。天花板 256 MiB 對應 sodium `memlimit = 268435456` bytes；frontier 最低 m=7168 KiB = 7340032 bytes ≥ `crypto_pwhash_MEMLIMIT_MIN`（8192）、t≥1 ≥ `OPSLIMIT_MIN`（1）、且上界 268435456 ≤ `crypto_pwhash_MEMLIMIT_MAX`、t=8 ≤ `OPSLIMIT_MAX`——**上下界雙向常數斷言**，全政策域落在 libsodium 合法界內（實作時以常數斷言驗證）
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

- Konscious.Security.Cryptography.Argon2 nuget latest version 2025
- @node-rs/argon2 npm hashRaw
- argon2-cffi PyPI version 2025
- NuGet package prefix reservation process
- PyPI trusted publishing OIDC GitHub Actions
- npm package provenance publish
## Output

I have enough verified context. Here is the implementation plan.

---

# ArgonGuard 實作規劃建議（v3.1 → 可執行任務清單）

## 執行摘要與關鍵序列約束

在展開之前，先鎖定四條「不可違反」的順序性約束（下游所有規劃皆依此）：

1. **向量凍結先於一切實作 conformance**：deterministic 向量必須由 argon2 reference CLI × argon2-cffi 兩個獨立來源 byte-for-byte 比對後才凍結，ArgonGuard 自家實作不得作為來源。→ 這是 M1 的硬 gate，M2+ 的所有 conformance 測試都吃這批凍結 artifact。
2. **.NET 為第一參考實作**：Node/Python/PHP 的 API 契約細節（dispatch 順序、reason code 命名、NeedsRehash 語意）以 .NET 落地後的行為為對照基準。
3. **外部命名/發佈依賴需早啟動、但不阻塞開發**：NuGet prefix reservation 是**人工審核、非同步、有排隊 SLA**（來源：Microsoft Learn，需寄 account@nuget.org），必須在 M0 就送件；npm org、PyPI、Packagist 名稱已查證未占用（設計文件 2026-07-05），M0 先佔位註冊。
4. **引擎版本已驗證可用**：Konscious 1.3.1（2024-06 後停滯，符合設計文件對沖假設）、argon2-cffi 25.1.0（活躍維護、支援 py3.9+）、@node-rs/argon2 具 `hashRaw`。無阻塞，但 Konscious 停滯風險使 Isopoh nightly 備援成為 M4 必做項而非選配。

里程碑總覽：

| Milestone | 主題 | 核心 gate |
|---|---|---|
| **M0** | Repo 骨架 + 外部依賴啟動 | monorepo 結構、CI 空殼、命名佔位、NuGet reservation 送件 |
| **M1** | spec + 凍結向量 | SPEC.md normative 完成、向量雙來源凍結、frontier 不變式 CI 綠燈 |
| **M2** | .NET 參考實作 | 全向量 conformance 通過（雙 TFM）、API 契約定型 |
| **M3** | Node / Python / PHP + 跨語言矩陣 | 4×4 round-trip 綠燈、PHP 雙 provider 一致 |
| **M4** | CI 加固 + 發佈 | 四道守門齊備、nightly 備援、四套件首發 |

---

## M0 — Repo 骨架與外部依賴啟動

**里程碑 DoD**：monorepo 目錄結構就緒、四語言各有可編譯的空 skeleton、CI 能對每個子目錄跑 lint/build（即使無實質內容）、所有外部命名依賴已送件或佔位。

| Task | 內容 | DoD（驗收條件） |
|---|---|---|
| **M0-T1** | 建立 monorepo 目錄骨架 `spec/ dotnet/ node/ python/ php/ docs/ .github/workflows/` | PR 合併後目錄結構符合 §5.1；`docs/` 內含 SOT 筆記入口與空 ADR index；README 說明 repo 佈局 |
| **M0-T2** | 送出 NuGet ID prefix reservation（`ArgonGuard.*`）申請 | 已寄 account@nuget.org，附 owner display name 與 prefix；於 `docs/ops/naming.md` 記錄送件日期與追蹤狀態（**非阻塞**：後續開發不等回覆，僅發佈前需確認） |
| **M0-T3** | 佔位註冊 npm org `argonguard`、PyPI `argonguard-passwords`（placeholder 0.0.0）、Packagist 待 repo public 後 hook | 三平台名稱確認歸屬本組織；`naming.md` 記錄佔位版本與帳號 |
| **M0-T4** | CI 空殼：per-language build job matrix（.NET net8.0+net48、Node 20/22/24、Python 3.9–3.14、PHP 8.2–8.5） | 每個 workflow 檔存在且對空 skeleton 跑綠；path filter 設定使各語言 PR 只觸發對應 job |
| **M0-T5** | 各語言 skeleton 專案（可編譯的空殼 + 一個 dummy 測試） | `dotnet build`、`npm run build`、`pytest`、`composer test` 皆綠；各語言測試框架選定並可執行：**xUnit（.NET）、Vitest（Node）、pytest（Python）、PHPUnit（PHP）** |
| **M0-T6** | ADR 樣板與初始 ADR 落檔（格式決策、p=1 鎖定、frontier 常數表、引擎選型、驗證端地板 v2→v3 變更） | `docs/adr/` 內每項決策一份 ADR，含背景/決策/後果；round 2/3 審核結論可追溯 |

> 平行性：M0-T1..T6 幾乎全可平行；M0-T4/T5 有輕微依賴（T4 的 job 需 T5 的 skeleton 才不會空跑失敗），建議同 PR 或緊鄰 PR。

---

## M1 — spec 層與凍結測試向量（最高優先，下游 gate）

**里程碑 DoD**：`spec/SPEC.md` 為 normative、RFC 2119 完整；`spec/vectors/v1/*.json` 五類向量齊備且**經雙獨立來源凍結**；frontier/profile 不變式 CI（守門 1）綠燈；`SPEC_VERSION=1.0.0` 定義。此里程碑完成前，**M2+ 不得撰寫任何 conformance 測試**。

### 模組職責邊界（spec/）
- **唯一 SOT**：格式、參數政策、錯誤分類、reason code 命名、向量。
- **immutable artifact**：`vectors/v1/` 一旦凍結即 append-only；修改既有向量 = 禁止。

| Task | 內容 | DoD |
|---|---|---|
| **M1-T1** | 撰寫 SPEC.md §格式（PHC string、§1.1/1.2）：algorithm 固定 argon2id、`v=19` 明確輸出、`m,t,p` 順序、RFC 4648 §4 無 padding、salt 16B / tag 32B / p=1 | normative 語句用 MUST/SHOULD；含輸出字元數（97–98）與儲存欄位建議；PR review 由第二人確認每條 RFC 2119 用字 |
| **M1-T2** | 撰寫 §1.3 強度檔位閉集（default/high/highest）+ §1.4 驗證端政策（frontier 常數表 + 天花板 + base64 拒 padding） | frontier 表與天花板表 byte 級明確；每維度 reason code 列名（§2.2）；記載 OWASP 查證 commit/日期 |
| **M1-T3** | 撰寫 §2.1 密碼輸入語意（1–1024 bytes、UTF-8、拒 NUL/surrogate、不做 NFC）+ §2.2 錯誤分類與 reason code 全表 | 五類錯誤 + 全 reason code 清單定型；Verify false 的唯一語意明載 |
| **M1-T4** | 撰寫 §3 API 契約：三操作、dispatch 順序（§3.2）、NeedsRehash 語意（§3.3，自寫 parser 不呼底層）、legacy 擴充點（§3.4）、§3.5 各語言慣例對映表 | dispatch 步驟 1–3 逐條 normative；legacy `canHandle/verify` 介面定義；`SPEC_VERSION` 常數要求明載 |
| **M1-T5** | 建立向量凍結工具鏈 `spec/tools/`：以 **argon2 reference CLI** 產生 deterministic 向量 | tool 可重現產出；固定 salt 輸入產出穩定；輸出 JSON schema 定義（`passwordHex` 為 normative） |
| **M1-T6** | 以 **argon2-cffi 25.1.0** 獨立產生同一批 deterministic 向量並 byte-for-byte 比對 | 兩來源比對 script 綠燈才准凍結；比對報告存 `spec/vectors/v1/PROVENANCE.md`；**ArgonGuard 自家實作零參與** |
| **M1-T7** | 產出 `deterministic.json` + `verify.json`（含外部系統合法 PHC，涵蓋 t=1 (m≥47104) 路徑） | 兩檔凍結；t=1 向量確認可被 sodium fallback 路徑處理（OPSLIMIT_MIN=1 語意驗證） |
| **M1-T8** | 產出 `reject.json`：逐類錯誤 + reason code 斷言，含 base64 padding 邊界、keyid/data、亂序、>512、`$argon2i$`/`$2b$` | 每筆含 `expectedReason`；padding 拒絕向量齊備 |
| **M1-T9** | 產出 frontier×天花板交疊邊界向量：(7168,5)✓、(7167,5)✗、(7168,8)✓、(7168,9)✗ | 四筆進 `reject.json`/`verify.json` 對應位置；證明無縫隙無矛盾 |
| **M1-T10** | 產出 `needs-rehash.json` + `input-limits.json`（1024/1025、空、NUL、surrogate、NFC≠NFD、emoji、CJK） | 全分支覆蓋；NFC vs NFD 產生不同 hash 有明確向量 |
| **M1-T11** | 產出每檔位 canonical dummy hash 常數（§2.4，使用者列舉緩解，informative） | 三檔位各一常數凍結；文件標明僅緩解帳號存在性 timing |
| **M1-T12** | 守門 1 CI（語言中立）：frontier 表斷言、profile 快照 append-only 比對、`default==(19456,2,1)` 哨兵 | 任一不變式被破壞 → 建置期紅燈；快照檔納入 repo |

> 序列：M1-T5→T6→(T7..T11) 嚴格序列（凍結 gate）。T1..T4（文字規格）可與 T5/T6（工具）平行。T12 依賴 T2 的表定案。

---

## M2 — .NET 參考實作（設計基準）

**里程碑 DoD**：`ArgonGuard.Passwords` 通過 M1 全部凍結向量（守門 2 的 .NET 雙 TFM job：net8.0 Linux + net48 Windows 綠燈）；三核心操作 + legacy 擴充點 + typed error/reason code 落地；API 契約行為定型為其他語言的對照基準。

### 模組切分（dotnet/）
```
ArgonGuard.Passwords/
├── Phc/            嚴格 PHC parser + encoder（自寫，spec 對齊）
├── Policy/         frontier 地板 + 天花板檢查（純函式，無雜湊）
├── Engine/         internal IArgon2Provider → KonsciousProvider（不進公開 API）
├── Api/            ArgonGuardPasswordHasher + IArgonGuardPasswordHasher
├── Errors/         ArgonGuardException 基底 + 五子類（含 Reason）
├── Legacy/         LegacyPasswordVerifier 介面（核心不含實作）
└── Internal/       constant-time polyfill（#if netstandard2.0）
```
依賴方向：`Api → Policy → Phc`、`Api → Engine(internal)`、`Api → Legacy(介面)`；`Phc/Policy` 不依賴 `Engine`（可純單元測試）。

| Task | 內容 | DoD |
|---|---|---|
| **M2-T1** | 專案設定：TFM `netstandard2.0;net8.0`、Framework 地板 4.6.2、Konscious 1.3.1 依賴、namespace/類別命名（避開 Identity `PasswordHasher<TUser>`） | `dotnet build` 雙 TFM 綠；套件 metadata（license 元素、非 licenseUrl）符合 NuGet prefix 最佳實務 |
| **M2-T2** | `Phc/` 嚴格 parser + encoder：`m,t,p` 順序、`v=19`、無 padding、拒 keyid/data、>512 預檢 | 單元測試覆蓋合法/非法路徑；能解出 (m,t,p,salt,tag) |
| **M2-T3** | `Policy/` frontier 地板 + 天花板 + reason code 對映 | 每維度回傳正確 reason code；純函式單元測試 |
| **M2-T4** | `Internal/` constant-time polyfill（netstandard2.0）：長度不等不提早 return、逐 byte XOR 累加、`[MethodImpl(NoInlining\|NoOptimization)]`；net8.0 走 `CryptographicOperations.FixedTimeEquals` | 雙 TFM 等價功能測試綠；polyfill 實作符合 §4.1 normative 要求 |
| **M2-T5** | `Engine/KonsciousProvider`：raw-bytes hash（`hashRaw` 等價）供重算 | 對 deterministic 向量重算一致；provider 藏於 internal |
| **M2-T6** | `Api/` 三操作 `HashPassword`/`VerifyPassword`/`NeedsRehash`（v1 僅同步）+ 輸入檢查（throwing `UTF8Encoding` 拒 NUL/surrogate） | 行為符合 §3.2 dispatch；`input-limits.json` 全綠 |
| **M2-T7** | `Errors/` 五子類 + `Reason`；Verify false 僅代表密碼不符，其餘 typed error | `reject.json` 逐筆斷言錯誤類別 + reason code 綠 |
| **M2-T8** | `Legacy/` 介面 + 建構時不可變有序注入 + bcrypt verifier 文件範例（不進核心） | 執行期動態註冊被禁止（建構後 immutable）；範例碼在 docs |
| **M2-T9** | .NET conformance 測試套件（xUnit）跑 M1 全部凍結向量 | 守門 2 .NET job：net8.0 (Linux) + net48 (Windows) 全向量綠 |
| **M2-T10** | timing sanity 統計測試（informative）：前綴 vs 尾綴差異時間分布 | 產出報告但**不擋 merge**（承認 CI 抖動） |
| **M2-T11** | dev harness（stdin/stdout JSON 協議）供 M3 跨語言矩陣使用 | harness 能對隨機密碼×三檔位 hash/verify/needs-rehash 並輸出 JSON |
| **M2-T12** | README：System.Memory binding redirect 疑難排解（net48 高頻踩雷）+ SPEC_VERSION 常數曝露 | README 首屏與 NuGet 描述同步提示；`SPEC_VERSION` 可讀取 |

> 序列：T1→(T2,T3,T4 平行)→T5→T6→(T7,T8)→T9→(T10,T11,T12)。T11 是 M3 的前置依賴。

---

## M3 — 跨語言實作與 4×4 round-trip 矩陣

**里程碑 DoD**：Node/Python/PHP 三實作各自通過 M1 凍結向量（守門 2 各自 job 綠）；PHP 雙 provider byte-for-byte 一致 job 綠；守門 3（4×4 round-trip 矩陣）**擋 merge** 綠燈。三實作以 M2 定型行為為對照。

各語言模組切分沿用 spec 分層（Phc/Policy/Engine-provider/Api/Errors/Legacy）；引擎皆藏 internal provider 之後。

### M3a — Node.js / TypeScript（Vitest）

| Task | DoD |
|---|---|
| **M3a-T1** 專案：`@argonguard/passwords`、ESM+CJS 雙輸出、Node 20 地板、@node-rs/argon2 依賴 | build 雙格式綠；平台矩陣（linux x64/arm64、alpine、win、macOS × Node 20/22/24）可跑 |
| **M3a-T2** 自寫 PHC parser/encoder + Policy（TS 型別、字串字面量 profile） | 單元測試綠 |
| **M3a-T3** 自寫 PHC 編碼 vs `@node-rs/argon2` 原生 `hash()` encoded 交叉比對斷言（固定 salt） | 交叉比對 CI 項綠（零成本防呆） |
| **M3a-T4** Api：async（真背景執行緒 Promise）、`needsRehash` 同步；輸入 `isWellFormed()` 拒 surrogate | 符合 §3.5；`.code` 錯誤碼齊備 |
| **M3a-T5** conformance（Vitest）跑全凍結向量 + dev harness | 守門 2 Node job 綠；harness JSON 協議與 M2-T11 相容 |

### M3b — Python（pytest）

| Task | DoD |
|---|---|
| **M3b-T1** 專案：`argonguard-passwords`、import `argonguard.passwords`（namespace package）、argon2-cffi 25.1.0 直接依賴、Python 3.9 地板、`py.typed` | abi3 wheel 建置綠；型別完整 |
| **M3b-T2** 自寫 PHC parser + Policy + `StrEnum` profile | 單元測試綠 |
| **M3b-T3** Api：同步（`hash_secret_raw` 重算 + `hmac.compare_digest`）；文件示範 `asyncio.to_thread` | 符合 §3.5；`reason` 屬性齊備 |
| **M3b-T4** conformance（pytest）跑全凍結向量 + dev harness | 守門 2 Python 3.9–3.14 矩陣綠；harness 相容 |

### M3c — PHP（PHPUnit）

| Task | DoD |
|---|---|
| **M3c-T1** 專案：`argonguard/passwords`、`ArgonGuard\Passwords`、PHP 8.2 地板、native enum、`#[\SensitiveParameter]`、零 runtime Composer 依賴 | `composer test` 綠 |
| **M3c-T2** 載入時能力檢查 fail-fast（`password_algos()` 無 argon2id → `UnsupportedEnvironment` 附安裝指引，絕不降級 bcrypt） | 環境無 argon2id 時正確拋錯 |
| **M3c-T3** 自寫嚴格 parser + Policy；`needsRehash` 用自寫 parser（不用 `password_needs_rehash`） | 單元測試綠；provider 漂移消除 |
| **M3c-T4** standard provider（`password_hash`/`password_verify`）Api | 全凍結向量綠 |
| **M3c-T5** **sodium fallback provider**：自寫 parser → bytes 換算 `memlimit = m×1024` → `sodium_crypto_pwhash` raw 重算 → `hash_equals`；上下界常數斷言（MEMLIMIT_MIN/MAX、OPSLIMIT_MIN/MAX） | 換算常數斷言測試綠；off-by-1024 專門測試綠 |
| **M3c-T6** 雙 provider 一致 CI job：同一 PHC 經 libargon2 與 sodium 重算 byte-for-byte 一致 | 守門 2 PHP job（standard + 雙 provider 換算專門 job）綠；sodium-only 自編譯 build 降 nightly |
| **M3c-T7** conformance + dev harness | harness 相容；PHP 8.2–8.5 矩陣綠 |

### M3d — 跨語言矩陣（守門 3）

| Task | DoD |
|---|---|
| **M3d-T1** 4×4 round-trip 矩陣 workflow：各實作 harness 對隨機密碼×三檔位互 hash 互 verify + needs-rehash 斷言 | 16 組合（含自對自）全綠；**擋 merge** |
| **M3d-T2** 矩陣涵蓋 t=1 (m≥47104) 與 frontier 邊界向量的跨語言一致驗證 | PHP sodium fallback 對 t=1 不靜默失效被證明 |

> 平行性：M3a/M3b/M3c **三語言可完全平行開發**（皆只依賴 M1 凍結向量 + M2 定型契約）。M3d 依賴三者的 harness（各自 T5/T4/T7）就緒後才能全綠。

---

## M4 — CI 加固與發佈

**里程碑 DoD**：四道守門齊備並穩定；Konscious 停滯風險對沖到位（Isopoh nightly conformance 綠）；版本策略/tag 觸發/供應鏈守門落地；四套件依語言優先序首發成功。

| Task | 內容 | DoD |
|---|---|---|
| **M4-T1** 守門 4 供應鏈：lockfile pin、Dependabot、底層引擎升版必過完整向量迴歸 | 四語言皆有 lockfile 與 Dependabot 設定；引擎升版 PR 自動跑全向量 |
| **M4-T2** .NET 備援引擎 **Isopoh** 對凍結向量 conformance（**nightly**） | nightly job 綠；Konscious 停滯（2024-06）風險對沖為「隨時可用」而非紙上（引擎版本已驗證 1.3.1 停滯） |
| **M4-T3** PHP sodium-only 自編譯 build conformance（nightly） | nightly 綠 |
| **M4-T4** 版本策略落地：Spec SemVer 規則、`Implements ArgonGuard Spec 1.x` metadata、tag prefix（`spec/v*`、`dotnet/v*`…）觸發對應 release workflow | tag 推送觸發正確 workflow；套件 metadata 宣告 spec 對應 |
| **M4-T5** 發佈 workflow：NuGet 簽章 + prefix reservation 確認（依賴 M0-T2 回覆）、npm provenance（`--provenance` + `id-token: write` + trusted publisher 設定）、PyPI trusted publishing（OIDC、`id-token: write`、gh-action-pypi-publish）、Packagist hook + subtree split read-only mirror | 各平台 dry-run 綠；npm/PyPI trusted publisher 已於平台端設定；Packagist 根目錄限制以 subtree split 解決 |
| **M4-T6** 依語言優先序首發：.NET → Node → Python → PHP（各 `v1.0.0`，spec `v1.0.0`） | 四套件在對應公開庫可安裝；安裝後 `SPEC_VERSION` 回報 1.0.0；跨語言 round-trip 對已發佈套件抽驗一致 |
| **M4-T7** 營運手冊：檔位切換 SOP（先全 fleet 升級 → 觀察一週期 → 再切 active profile）+ 升級流程文件 | `docs/ops/` 收錄；NeedsRehash 全程可預測行為說明齊備 |

> 序列：M4-T5 的 NuGet 發佈受 **M0-T2（prefix reservation 人工審核）** 回覆制約——這是全案唯一可能卡住發佈的外部依賴，故 M0 即送件。npm/PyPI/Packagist 無此阻塞。

---

## 風險與依賴總表

| 項目 | 類型 | 阻塞哪個 milestone | 緩解 |
|---|---|---|---|
| NuGet prefix reservation | **外部人工審核、非同步** | M4-T5 .NET 發佈 | M0-T2 最早送件；審核期間開發不受影響 |
| npm org / PyPI / Packagist 名稱 | 外部，已查證未占用 | M0 佔位 | M0-T3 立即註冊佔位 |
| 向量雙來源凍結 | **內部硬 gate** | M2/M3 全部 conformance | M1 為最高優先；凍結前禁寫 conformance |
| .NET 為參考基準 | 內部序列 | M3 三語言對照 | M2 先定型行為 |
| Konscious 停滯（1.3.1, 2024-06） | 供應鏈 | 長期維護 | M4-T2 Isopoh nightly + RFC 9106 凍結 + 向量常態 CI + MIT 可 vendor |
| PHP off-by-1024 換算 | 實作陷阱 | M3c 正確性 | M3c-T5 常數斷言 + 專門測試 + 雙 provider 一致 job |

**可完全平行**：M0 各 task；M1 文字規格 vs 向量工具；M3a/M3b/M3c 三語言實作。
**必須序列**：M1 凍結 gate → M2 → M3 harness → M3d 矩陣；M0-T2 → M4-T5(.NET)。

## 測試框架與落點速查

| 語言 | 框架 | 單元 | conformance | round-trip | negative/reject | timing sanity |
|---|---|---|---|---|---|---|
| .NET | **xUnit** | Phc/Policy 純函式 | M2-T9 雙 TFM | 經 harness (M2-T11) | reject.json (M2-T7) | M2-T10（informative，不擋 merge） |
| Node | **Vitest** | Phc/Policy | M3a-T5 平台矩陣 | M3d | reject.json | 建議 informative（比照 .NET） |
| Python | **pytest** | Phc/Policy | M3b-T4 3.9–3.14 | M3d | reject.json | informative |
| PHP | **PHPUnit** | Phc/Policy + 換算 | M3c-T7 + 雙 provider | M3d | reject.json | informative |

**共用 conformance 向量**為四語言唯一權威來源（M1 凍結）；**跨語言 round-trip** 由守門 3 統一執行（擋 merge）；**timing sanity** 一律 informative、承認 CI 抖動、不擋 merge。

## Citations

- https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/
- https://nuget.rza.ru/packages/konscious.security.cryptography.argon2
- https://github.com/kmaragon/Konscious.Security.Cryptography
- https://github.com/hynek/argon2-cffi
- https://anaconda.org/main/argon2_cffi
- https://github.com/hynek/argon2-cffi/releases
- https://www.piwheels.org/project/argon2-cffi/
- https://pypi.org/project/argon2-cffi/
- https://packages.gentoo.org/packages/dev-python/argon2-cffi
- https://socket.dev/nuget/package/konscious.security.cryptography.argon2
- https://libraries.io/npm/bun-argon2
- https://anaconda.org/conda-forge/argon2-cffi/files?version=25.1.0
- https://archlinux.org/packages/extra/any/python-argon2-cffi/
- https://generalistprogrammer.com/tutorials/argon2-cffi-python-package-guide
- https://argon2-cffi.readthedocs.io/_/downloads/en/16.0.0/pdf/
- https://learn.microsoft.com/en-us/nuget/nuget-org/id-prefix-reservation
- https://github.com/NuGet/Home/wiki/NuGet-Package-Identity-Verification
- https://github.com/NuGet/Home/issues/11594
- https://www.speakeasy.com/blog/pypi-trusted-publishing-security
- https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-pypi
- https://docs.pypi.org/trusted-publishers/security-model/
- https://docs.pypi.org/trusted-publishers/internals/
- https://docs.pypi.org/trusted-publishers/using-a-publisher/
- https://philna.sh/blog/2026/01/28/trusted-publishing-npm/
- https://dev.to/ghiscoding/how-to-publish-on-npm-with-provenance-using-lerna-lite-3cjf
- https://safeguard.sh/resources/blog/npm-provenance-attestations-walkthrough-2026
- https://docs.npmjs.com/trusted-publishers/
