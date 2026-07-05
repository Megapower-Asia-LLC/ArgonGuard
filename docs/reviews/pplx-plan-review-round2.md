---
title: "ArgonGuard plan review r2"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_6fc8de24-2175-495b-9ffa-66edf874e960
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 36915
pplx_latency_sec: 87.13
---

# ArgonGuard plan review r2

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 36915 / Latency: 87.13s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深軟體交付架構師與安全審查員。這是 ArgonGuard 實作計畫（master plan）的第二輪審核。Round 1 你給出「需修改」：5 項 MAJOR（A2 M2 基準凍結 gate 缺失、B1 reason code 權威清單未鎖定、B2 引擎單位對照未成 SOT、C1 constant-time 無可驗收 gate、E1 M5 severity 分級缺失）與多項 MINOR/NIT。

v2 修正對照：
- A2：M2-T10 產出 spec/harness-contract.json＋spec/reference/dotnet-baseline.md 並宣告 baseline freeze；變更須回改 SPEC 過守門 1；baseline merge 為 M3 開工 gate
- B1/B2：新增「Master 層鎖定的機器可讀權威 artifact」表——spec/reason-codes.json、spec/engine-units.json（各引擎單位＋換算＋三檔位原生單位期望常數）、MANIFEST.sha256、harness-contract.json、needs-rehash truth table 全部 M1 產出凍結、守門 1 斷言
- C1：M2-T4 constant-time 拆雙層 DoD——(a) 結構性斷言擋 merge（property 測試證明等長輸入比較次數恆等、無 early return、NoInlining|NoOptimization 存在性）；(b) 統計 timing 維持 informative
- E1：M5 明訂 severity 分級；critical/high 必修不得接受；medium/low 明文接受須記錄理由；high 以上殘餘風險知會 Aiken；報告含殘餘風險章節
- MINOR/NIT 全數採納：向量 checksum manifest＋v1→v2 重凍程序、矩陣維度公式鎖定（16 lang-pair×凍結密碼集）、擋 merge 判準可重現（隨機案例 informative）、M4-T1/T3 與 M3 並行、TFM 三層關係一句話、UTF-8 bytes 口徑＋多 byte 1024 邊界向量、API 形狀差異明文（M5 不列漂移）、harness contract test、NuGet reservation fallback、引擎切換決策準則、交付範圍明訂（發佈-ready；實際發佈為 Aiken 計畫外步驟）、PROVENANCE 記錄底層實作版本＋同源時補 RustCrypto 第三實作 spot-check、M5 回饋迴路與回 PPLX 觸發條件、每語言必做整合冒煙點名、M6 可驗收代理指標（example-test 進 CI、可執行遷移範例、CLAUDE.md 指令與 CI 同源）、LICENSE/SECURITY.md、平行 agent 只寫各自目錄

請完成 round 2 審核：確認修正到位、是否引入新問題。輸出（務必完整到 verdict）：
- 【issues】BLOCKER / MAJOR / MINOR / NIT＋建議；無 issue 也明寫
- 【verdict】「核准」或「需修改」
- 繁體中文，技術名詞保留英文

====== master plan v2 ======
# ArgonGuard 實作計畫（Master Plan v2）

> **For agentic workers:** 本計畫為 milestone 層級 master plan；每個 milestone 執行前依 superpowers:writing-plans 展開細部任務（TDD、頻繁 commit）。SOT：`docs/specs/2026-07-05-argonguard-design.md`（Perplexity 共識版 v3.1）。v2：依 Perplexity 計畫審核 round 1 修正（MAJOR A2/B1/B2/C1/E1 與全部 MINOR/NIT）。

**Goal:** 交付符合 OWASP 要求、跨語言（.NET/Node/Python/PHP）互通的 Argon2id 密碼雜湊元件，含凍結測試向量、跨語言互驗 CI 與完整文件。

**Architecture:** spec-first monorepo——語言中立規格、機器可讀權威 artifact（reason codes、單位常數、向量、harness contract）與雙工具鏈凍結向量為第一等 artifact；四語言實作共同分層（Phc parser／Policy／internal Engine provider／Api／Errors／Legacy），規格層自寫、密碼學層委外。

**Tech Stack:** .NET（Konscious 1.3.1、xUnit）、Node（@node-rs/argon2、Vitest、Node 20+）、Python（argon2-cffi 25.1.0、pytest、3.9+）、PHP（原生 password_hash＋sodium fallback、PHPUnit、8.2+）、GitHub Actions。

## Global Constraints（逐字承襲共識設計 v3.1）

- 演算法固定 argon2id、`v=19` 明確輸出、參數序 `m,t,p`、禁 keyid/data、base64 無 padding（驗證端拒 padding）
- 檔位：`default`(19456,2,1)／`high`(65536,2,1)／`highest`(131072,2,1)；salt 16B、tag 32B、全 p=1
- 驗證端：OWASP frontier 凍結表（t=1→47104、t=2→19456、t=3→12288、t=4→9216、t≥5→7168）＋天花板（m≤262144、t≤8、salt≤64B、tag≤128B、字串≤512）
- 密碼輸入 1–1024 bytes（**以 UTF-8 編碼後 byte 數計**，四語言同一口徑）、拒空/NUL/unpaired surrogate、不做 NFC
- 五類 typed error＋跨語言 bit-identical reason code；verify false 只代表密碼不符
- 向量凍結：兩獨立工具鏈（argon2 reference CLI × argon2-cffi）產生比對，ArgonGuard 自家實作不得參與
- **TFM 三層關係**：build TFM = `netstandard2.0;net8.0`；驗證矩陣 = net48（Windows runner）＋net8.0（Linux）；對外宣稱支援地板 = .NET Framework 4.6.2
- 其他支援地板：Node 20、Python 3.9、PHP 8.2
- 套件名：`ArgonGuard.Passwords`／`@argonguard/passwords`／`argonguard-passwords`／`argonguard/passwords`
- **跨語言 API 形狀差異（刻意設計，非 drift）**：Node 為 async（Promise、needsRehash 同步），.NET/Python/PHP 為同步（不出假 async）——M5 對抗審查不得將此列為漂移

## Master 層鎖定的機器可讀權威 artifact（細部層不得再議，均於 M1 產出並凍結）

| Artifact | 內容 | 權威性 |
|---|---|---|
| `spec/reason-codes.json` | 全部 reason code 權威枚舉 | SPEC.md 散文與四語言輸出字串均以此為準；守門 1 CI 斷言實作輸出 == 清單 |
| `spec/engine-units.json` | 各引擎 memory 參數單位對照＋換算公式＋三檔位在各引擎原生單位的期望常數（如 sodium：default=19456×1024=19922944 bytes） | off-by-1024 斷言的權威基準（斷言「權威值」而非「自己算的值」） |
| `spec/vectors/v1/*.json`＋`MANIFEST.sha256` | 五類向量＋checksum manifest | 守門 1 CI 斷言 checksum；凍結後發現錯誤→走 `v1→v2` 新目錄重凍程序（保留 v1 PROVENANCE），禁止原地修改 |
| `spec/harness-contract.json` | dev harness I/O 凍結 fixture（含 schema version） | 四語言 harness 各自跑 contract test 為 conformance DoD 一部分 |
| `spec/vectors/v1/needs-rehash.json` | NeedsRehash truth table（低於/等於/高於 active、跨檔位、legacy、malformed） | 四語言 bit-identical 判定的獨立向量（不只 round-trip 附帶斷言） |

## 分工與環境前提

- **技術決策**：與 Perplexity 共識後由 Claude 自決執行；**Aiken 只做業務/產品決策**。
- **需 Aiken 帳號的外部動作**（非開發阻塞）：NuGet prefix reservation（若被拒→fallback：以完整套件 id 直接發佈，發佈 workflow 不因無 reservation 而 fail）、npm org、PyPI/Packagist 與 trusted publishing 設定。
- **交付範圍明訂**：本計畫 DoD 為「發佈-ready」＝dry-run 綠＋Aiken 執行清單就緒；實際 registry 發佈為 Aiken 執行的計畫外步驟。
- **本地環境**：macOS 開發；本地綠只涵蓋 netstandard2.0/net8.0，net48 綠由 CI Windows runner 判定；argon2 CLI（brew）、argon2-cffi（venv）、PHP 8.5（brew，argon2id＋sodium 雙 provider 已驗證）。
- **執行模式**：inline 逐 milestone；M3 三語言以 Workflow 多 agent 平行——**平行 agent 只寫各自語言目錄**，共用檔（spec/ 唯讀；workflows、根 README 等）由主 agent 序列化收攏。

---

## Milestone 總覽與硬性順序約束

| Milestone | 主題 | 核心 gate（DoD） |
|---|---|---|
| **M0** | Repo 骨架＋外部依賴啟動 | 結構就緒、四語言 skeleton 本地綠（.NET 限 netstandard2.0/net8.0）、CI 空殼綠、Aiken 命名清單就緒 |
| **M1** | spec＋權威 artifact＋凍結向量（**最高優先硬 gate**） | SPEC.md normative；上表五類權威 artifact 凍結（含 MANIFEST.sha256）；守門 1 綠；完成前 M2+ 禁寫 conformance |
| **M2** | .NET 參考實作＋**基準凍結 gate** | 全向量 conformance 綠（雙 TFM）；**產出 `spec/reference/dotnet-baseline.md`＋golden harness fixture，宣告 baseline freeze**：M3 啟動後 harness 協議與 reason code 映射變更須回改 SPEC 並過守門 1 |
| **M3** | Node／Python／PHP＋跨語言矩陣 | 三實作 conformance＋harness contract test 綠；PHP 雙 provider byte-for-byte 一致；守門 3 矩陣擋 merge 綠 |
| **M4** | CI 加固＋發佈準備 | 四道守門齊備；nightly 備援；發佈 workflow dry-run 綠（M4-T1/T3 可與 M3 並行縮短關鍵路徑） |
| **M5** | 對抗式審查與驗證 | severity 分級處置（見 M5 節）；報告含殘餘風險章節；全 CI 綠 |
| **M6** | 文件與交付 | 可驗收文件代理指標（見 M6 節）＋LICENSE/SECURITY.md；最終 commit＋push |

**硬性序列**：M1 → M2（含 baseline freeze）→ M3（三語言平行）→ M3d；M4-T1/T3 可提前並行。
**M5 回饋迴路**：若對抗審查導致 normative spec 變更 → spec 版本升＋向量 `v1→v2` 重凍＋全語言 conformance 重跑；「回 Perplexity」觸發條件＝spec/實作漂移爭議或安全爭議無法內部裁決。

---

## M0 — Repo 骨架與外部依賴啟動

| Task | 內容 | DoD |
|---|---|---|
| M0-T1 | monorepo 骨架 `spec/ dotnet/ node/ python/ php/ docs/ .github/workflows/`＋README 佈局 | 結構符合設計 §5.1 |
| M0-T2 | Aiken 外部動作清單：NuGet reservation 信件草稿（含被拒 fallback 說明）、npm org／PyPI／Packagist 步驟 | `docs/ops/naming.md` 記錄；開發不等回覆 |
| M0-T3 | 四語言 skeleton＋dummy 測試（xUnit／Vitest／pytest／PHPUnit） | 本地綠（.NET：netstandard2.0/net8.0；net48 由 CI 判定） |
| M0-T4 | CI 空殼：per-language matrix＋path filter | push 後全綠 |
| M0-T5 | 初始 ADR：PHC 格式、p=1、frontier（v2→v3 歷程）、引擎選型、**引擎單位對照（各 provider memory 單位＋換算公式＋常數斷言值，對應 `spec/engine-units.json`）** | 每決策一份、可追溯審核紀錄 |

## M1 — spec 層、權威 artifact 與凍結向量

| Task | 內容 | DoD |
|---|---|---|
| M1-T1 | `spec/SPEC.md`（RFC 2119）：格式／檔位／frontier＋天花板／輸入語意（UTF-8 bytes 口徑）／錯誤分類／API 契約與 dispatch／NeedsRehash／legacy 介面 | 對照設計 v3.1 逐節覆蓋 |
| M1-T2 | `spec/reason-codes.json`＋`spec/engine-units.json` 權威 artifact | SPEC.md 引用之；守門 1 斷言 |
| M1-T3 | 向量產生：argon2 reference CLI 工具鏈 | 可重現；JSON schema（passwordHex normative）定義 |
| M1-T4 | argon2-cffi 獨立產生＋byte-for-byte 比對；`PROVENANCE.md` **記錄兩來源底層實作版本；若同源（皆綁 phc-winner-argon2 C library）須誠實標註並補第三獨立實作（RustCrypto argon2）spot-check** | 比對綠才凍結；ArgonGuard 自家實作零參與 |
| M1-T5 | 凍結五類向量＋`MANIFEST.sha256`：deterministic／verify（t=1 m≥47104、外部 PHC）／reject（padding、keyid/data、亂序、>512、$argon2i$、$2b$、逐 reason code）／needs-rehash **truth table**（低於/等於/高於/跨檔位/legacy/malformed 全分支）／input-limits（**1024 bytes 恰由多 byte 字元組成**的案例、1025、空、NUL、surrogate、NFC≠NFD、emoji、CJK）；frontier×天花板交疊 (7168,5)✓(7167,5)✗(7168,8)✓(7168,9)✗ | 五檔＋manifest 凍結；重凍走 v1→v2 程序 |
| M1-T6 | 每檔位 canonical dummy hash 常數 | 三常數凍結 |
| M1-T7 | 守門 1 CI：frontier/profile 斷言、MANIFEST.sha256 斷言、reason-codes/engine-units 一致斷言、default==(19456,2,1) 哨兵 | 破壞不變式＝紅燈 |

## M2 — .NET 參考實作（模組：Phc／Policy／Engine／Api／Errors／Legacy／Internal）

| Task | 內容 | DoD |
|---|---|---|
| M2-T1 | 專案設定：TFM `netstandard2.0;net8.0`、Konscious 1.3.1、命名 | 雙 TFM build 綠 |
| M2-T2 | Phc parser＋encoder | 合法/非法全路徑單元測試 |
| M2-T3 | Policy：frontier＋天花板＋reason code（引 `reason-codes.json`） | 每維度 code == 權威清單 |
| M2-T4 | constant-time：net8.0 用 FixedTimeEquals；netstandard2.0 polyfill——**雙層 DoD：(a) 結構性斷言（擋 merge）＝property 測試證明任意兩等長輸入走全長度路徑、無 early return（比較次數恆等）＋NoInlining\|NoOptimization 存在性斷言；(b) 統計 timing（informative）** | (a) 綠才可 merge |
| M2-T5 | Engine/KonsciousProvider raw-bytes 重算（單位斷言引 `engine-units.json`） | deterministic 向量一致 |
| M2-T6 | Api 三操作（同步）＋輸入檢查（throwing UTF8Encoding、UTF-8 bytes 口徑） | dispatch 全行為；input-limits 綠 |
| M2-T7 | Errors 五子類＋Reason | reject.json 逐筆綠 |
| M2-T8 | Legacy 介面＋建構時不可變注入＋bcrypt 文件範例 | 執行期註冊不可能 |
| M2-T9 | conformance（xUnit）＋CI 雙 TFM job | net8.0 Linux＋net48 Windows 全向量綠 |
| M2-T10 | dev harness＋**契約凍結**：產出 `spec/harness-contract.json`（schema 版本化 I/O fixture）＋`spec/reference/dotnet-baseline.md`，**宣告 baseline freeze** | harness 過 contract test；baseline 文件 merge＝M3 開工 gate |
| M2-T11 | README（System.Memory redirect；NuGet 描述同步）＋SPEC_VERSION 曝露＋timing sanity（informative） | 齊備 |

## M3 — 三語言實作與跨語言矩陣（M3a/b/c 平行，只寫各自目錄）

**每語言共同 DoD**：全凍結向量 conformance 綠＋harness contract test 綠＋reason code 輸出 == `reason-codes.json`。

- **M3a Node**：`@argonguard/passwords`、ESM+CJS、@node-rs/argon2；自寫 PHC 層 vs 原生 `hash()` 交叉比對；async Api；Vitest。
- **M3b Python**：`argonguard-passwords`（`argonguard.passwords` namespace）、argon2-cffi；`hash_secret_raw`＋`hmac.compare_digest`；pytest 3.9–3.14。
- **M3c PHP**：`argonguard/passwords`；能力檢查 fail-fast 絕不降級 bcrypt；standard＋sodium fallback（`memlimit` 期望值斷言引 `engine-units.json`、off-by-1024 專門測試、上下界常數斷言）；雙 provider byte-for-byte 一致 job；PHPUnit。
- **M3d 矩陣（守門 3，擋 merge）**：**維度公式鎖定＝16 個 lang-pair（4 hash × 4 verify，含自對自）× 凍結固定密碼集（含 t=1 與 frontier 邊界）× 三檔位**；擋 merge 判準完全可重現（固定 seed 派生的隨機案例列 informative 不擋 merge）＋needs-rehash truth table 跨語言斷言。

## M4 — CI 加固與發佈準備（T1/T3 可與 M3 並行）

| Task | 內容 | DoD |
|---|---|---|
| M4-T1 | 供應鏈：lockfile pin、Dependabot、引擎升版必過全向量 | 四語言齊備 |
| M4-T2 | Isopoh 備援 nightly＋PHP sodium-only 自編譯 nightly | nightly 綠 |
| M4-T3 | 版本策略：tag prefix 觸發 release workflow；`Implements ArgonGuard Spec 1.x` metadata | tag 觸發正確 |
| M4-T4 | 發佈 workflow：NuGet 簽章（**無 reservation 亦可發佈**）／npm provenance／PyPI trusted publishing／Packagist subtree split | dry-run 綠；Aiken 清單就緒 |
| M4-T5 | 營運手冊：檔位切換 SOP、升級流程、**引擎切換決策準則與 SOP**（Konscious→Isopoh 觸發條件：向量不符無法修復、安全公告、建置失效） | `docs/ops/` 收錄 |

## M5 — 對抗式審查與驗證

- 多視角對抗審查（Workflow 多 agent）：誤用情境、邊界案例、安全風險（timing、DoS、降級、解析歧義）、spec/實作漂移（對照權威 artifact；跨語言 sync/async 形狀差異為刻意設計不列漂移）。
- **必做整合冒煙（每語言一個代表點）**：.NET＝ASP.NET Core Identity custom hasher 接入；PHP＝與原生 `password_verify` 互通；Node＝最小 HTTP handler 登入流程；Python＝最小 FastAPI/WSGI handler 登入流程。其餘整合為可選。
- **severity 分級處置（DoD）**：發現項分 critical/high/medium/low；**critical/high 必須修復、不得「接受」**；medium/low 可明文接受但須記錄理由；**high 以上的殘餘風險決策須知會 Aiken**（業務風險知情權）；報告含「已知限制/殘餘風險」章節，歸檔 `docs/reviews/`。
- 回饋迴路：normative spec 變更 → spec 版本升＋向量 v1→v2 重凍＋conformance 全重跑；內部無法裁決的安全爭議 → 回 Perplexity。
- DoD：上述處置完畢＋全 CI 綠。

## M6 — 文件與交付

- 技術文件與使用說明：設計理念、四語言 API 文件、**可執行的 quickstart 範例（CI 以 example-test 實跑，文件與 CI 同源防腐化）**、安全注意事項、**bcrypt→ArgonGuard 可執行遷移範例**、未來擴充建議（Tokens 產品線、參數演進）。
- 交付清單補齊：**LICENSE（MIT）、SECURITY.md（responsible disclosure 流程）**、供應鏈 provenance 聲明。
- CLAUDE.md 更新（build/test 指令，**與 CI 使用同一組指令**）；README 完稿；最終 commit＋push。
- DoD：quickstart example-test 於 CI 綠＋遷移範例可執行＋LICENSE/SECURITY.md 在列＋repo 推送完成（實際 registry 發佈＝Aiken 計畫外步驟）。

---

## 自我審查紀錄（v2）

- Round 1 審核 5 MAJOR（A2 baseline freeze、B1 reason-codes SOT、B2 engine-units SOT、C1 constant-time 結構性驗收、E1 M5 severity）全數落入 M1/M2/M5 任務與「Master 層鎖定 artifact」表。
- 全部 MINOR（A1 checksum/重凍程序、A3 矩陣維度公式、A4 可重現擋 merge、B3 TFM 三層、B4 UTF-8 bytes 口徑、C2 harness contract、C3 truth table、D1 reservation fallback、D2 引擎切換準則、D4 交付範圍、D5 同源標註＋第三實作 spot-check、E2 回饋迴路、E3 必做冒煙、E4 可驗收文件指標）與 NIT（A5 並行、C4 本地綠口徑、B5 API 形狀差異、E5 LICENSE/SECURITY、F1 平行邊界）均已納入對應章節。
- 型別/命名與設計 v3.1 及權威 artifact 命名一致。

## Search queries triggered

- OWASP Argon2id password hashing recommended parameters 2025
- argon2-cffi phc-winner-argon2 C library binding
- @node-rs argon2 rust implementation
- Konscious.Security.Cryptography argon2 version
- PHP password_hash argon2id memory_cost unit KiB
- sodium crypto_pwhash argon2id memlimit bytes
## Output

I have enough verified technical grounding to complete the review. Key confirmations:

- OWASP frontier table (t=1→m=47104, t=2→19456, t=3→12288, t=4→9216, t=5→7168) — **correct**.
- Konscious.Security.Cryptography.Argon2 **1.3.1** exists, implements Argon2 1.3 spec, has net48/System.Memory dependency — **plan's TFM/redirect handling is sound**.
- PHP `password_hash` (libargon2) `memory_cost` is in **KiB**; libsodium `crypto_pwhash` `memlimit` is in **bytes** — **this is exactly the off-by-1024 hazard B2/engine-units.json targets; plan's premise is verified correct**.
- @node-rs/argon2 `memoryCost` is in **KiB**; argon2-cffi is a phc-winner-argon2 C-library binding — **confirms the "possibly same underlying C lib" concern that D5's RustCrypto third-implementation spot-check addresses**.

Now the Round 2 review.

---

# ArgonGuard Master Plan v2 — Round 2 審核

## 一、Round 1 MAJOR 修正確認（逐項）

| # | Round 1 issue | v2 落點 | 判定 |
|---|---|---|---|
| A2 | M2 baseline freeze gate 缺失 | M2-T10 產 `harness-contract.json`＋`spec/reference/dotnet-baseline.md`＋宣告 freeze；變更回改 SPEC 過守門 1；baseline merge=M3 開工 gate | ✅ 到位。因果閉環完整（凍結→變更需回改 SPEC→守門 1 攔截），且明確排序在 M3 前。 |
| B1 | reason code 權威清單未鎖定 | `spec/reason-codes.json` 列入 Master 層 artifact 表，SPEC 散文與四語言輸出均以此為準，守門 1 斷言「實作輸出==清單」 | ✅ 到位。SOT 唯一性與 CI 斷言雙重鎖定。 |
| B2 | 引擎單位對照未成 SOT | `spec/engine-units.json` 含各引擎單位＋換算＋三檔位原生單位期望常數；斷言「權威值」而非「自己算的值」 | ✅ 到位，且技術上正確——已查證 PHP libargon2=KiB vs libsodium=bytes、node-rs=KiB 的異質單位確實存在，此 artifact 正對準真實危害。M0-T5 ADR 亦交叉記錄。 |
| C1 | constant-time 無可驗收 gate | M2-T4 拆雙層：(a) 結構性斷言擋 merge（等長輸入比較次數恆等、無 early return、NoInlining\|NoOptimization 存在性）；(b) 統計 timing informative | ✅ 到位。把不穩定的 timing 量測從 merge gate 剝離，改用可決定性的結構性 property 為擋 merge 判準——方法論正確。 |
| E1 | M5 severity 分級缺失 | critical/high 必修不得接受；medium/low 明文接受須記錄理由；high 以上殘餘風險知會 Aiken；報告含殘餘風險章節 | ✅ 到位。分級、處置紅線、業務知情權、歸檔位置齊備。 |

**5 項 MAJOR 全數實質修正到位，非形式性補字。**

## 二、Round 1 MINOR / NIT 修正確認

抽樣核對關鍵項：checksum manifest＋v1→v2 重凍（A1，禁原地改、保留 v1 PROVENANCE）✅；矩陣維度公式=16 lang-pair×凍結密碼集×三檔位（A3）✅；擋 merge 可重現、隨機案例僅 informative（A4）✅；TFM 三層一句話（B3）✅；UTF-8 bytes 口徑＋1024 多 byte 邊界向量（B4/M1-T5）✅；harness contract test（C2）✅；needs-rehash truth table 獨立向量（C3）✅；reservation fallback「不因無 reservation 而 fail」（D1）✅；引擎切換 SOP（D2）✅；交付範圍=發佈-ready（D4）✅；**同源標註＋RustCrypto 第三實作 spot-check（D5）✅ 且技術必要性經查證屬實**（argon2-cffi 綁 phc-winner-argon2 C lib，若 reference CLI 亦同源則雙工具鏈獨立性形同虛設，第三實作補強是對的）；回饋迴路＋回 PPLX 觸發（E2）✅；必做冒煙點名（E3）✅；文件可驗收代理指標（E4，example-test 進 CI）✅；LICENSE/SECURITY.md（E5）✅；平行 agent 只寫各自目錄（F1）✅。

**全部 MINOR/NIT 均已落入具體任務或章節，非僅列於自我審查表。**

## 三、v2 是否引入新問題

### 【issues】

**BLOCKER**：無。

**MAJOR**：無。

**MINOR**

- **M-1（新增／驗收縫隙）：C1(a) 「比較次數恆等」的量測手段未指定，恐使擋 merge 判準本身不可重現。** property 測試要證明「任意兩等長輸入走全長度、比較次數恆等」，但沒說用什麼觀測比較次數——若靠 timing/counter 探針，本身可能受 JIT/最佳化干擾而 flaky，與 C1 想脫離 timing 不穩的初衷矛盾。建議明訂：以「原始碼/IL 層級的結構斷言」（無 early-return branch、迴圈上界為 length、`FixedTimeEquals` 委派或 polyfill 走 XOR-accumulate 無短路）＋屬性以「注入式計數器包裹比較運算子」在 debug build 斷言，避免用真實 timing 當結構證據。此為驗收精度問題，不阻塞整體。

- **M-2（新增／net48 覆蓋盲點）：constant-time 的 (a) 結構斷言在 netstandard2.0 polyfill 路徑上，其 net48 執行期行為（JIT 可能重排）未納 CI 判定範圍。** 計畫述「net48 綠由 CI Windows runner 判定」，但 M2-T4 未明言結構斷言 property 測試是否於 net48 job 亦跑。polyfill 是 netstandard2.0 消費於 net48 的關鍵路徑，constant-time 保證最脆弱處恰在此。建議 M2-T4 DoD 補一句「結構性斷言於 net8.0 與 net48 兩 job 皆須綠」。

**NIT**

- **N-1：M3d 「凍結固定密碼集」與 M1 向量的關係未點名。** 矩陣用的固定密碼集應是 M1 凍結向量的子集/衍生並列入 MANIFEST，否則會出現「第二份未凍結的準向量」。建議一句話註明密碼集來源即 `spec/vectors/v1/`。

- **N-2：Konscious 1.3.1 於 net8.0 是否仍需 System.Memory redirect 未明。** 查證顯示該套件 net48 依賴 System.Memory、net8.0 有原生 target；M2-T11 只提 README redirect。建議註明 redirect 僅適用於 net48/netstandard2.0 消費路徑，避免文件對 net8.0 使用者誤導。（純文件精度）

- **N-3：M5 「回 Perplexity」與本審核鏈的版本語意。** 觸發條件已明訂，但未說回 PPLX 後若 spec 變更是否需重跑本 round 類審核。建議一句 SOP：normative 變更後 master plan 亦升版並重新過計畫審核。（流程完備性）

- **N-4：SPEC_VERSION（M2-T11）與 `Implements ArgonGuard Spec 1.x`（M4-T3）與向量 v1/v2 版號三者對應關係未明。** 三個版本軸（spec 語意版、套件 metadata 宣稱版、向量凍結目錄版）建議在 Global Constraints 補一句對應規則，避免 M5 漂移審查時各說各話。（此為 B3 同類「一句話鎖關係」風格的延伸，不阻塞）

### 未發現的新問題（明寫）

- 硬性序列（M1→M2 baseline freeze→M3→M3d，M4-T1/T3 並行）**無循環依賴、無 gate 倒置**；baseline freeze 置於 M3 前正確。
- Master 層 artifact 表與各 milestone 任務**命名一致、無孤兒引用**（reason-codes/engine-units/harness-contract/MANIFEST/needs-rehash 均有產出任務＋守門 1 斷言）。
- API 形狀差異（Node async／其餘 sync）明文排除於 M5 漂移，**未與任何 conformance 斷言衝突**（矩陣比對的是 hash/verify 結果 byte-identity，非 API 形狀）。
- 交付範圍與 Aiken 邊界清晰，**未把計畫外發佈步驟誤設為 DoD**。

## 四、綜合判斷

Round 1 的 5 項 MAJOR 全部獲得**因果閉環式**修正（尤其 A2 的「變更→回改 SPEC→守門 1 攔截」與 C1 的「結構性斷言取代 timing 當 merge gate」為方法論正確的修法），全部 MINOR/NIT 均落入具體任務。v2 引入的新問題僅為 **2 MINOR＋4 NIT 等級的驗收精度與文件對應縫隙**，皆不觸及安全正確性或計畫可執行性，可於各 milestone 細部 plan 展開時吸收，**不需再開一輪 master plan 審核**。

---

## 【verdict】**核准**

**附帶建議（非阻塞，於細部 plan 吸收）**：
1. M2-T4 明訂結構性斷言的觀測手段（原始碼/IL 層 + 注入式計數器，勿用真實 timing 當結構證據），並要求該斷言於 **net8.0 與 net48 兩 job 皆綠**（M-1、M-2）。
2. M3d 註明固定密碼集來源為 `spec/vectors/v1/` 凍結子集（N-1）。
3. Global Constraints 補一句「spec 語意版 / 套件 metadata 宣稱版 / 向量 v1→v2 目錄版」三軸對應規則，並將「normative 變更後 master plan 升版重審」納 M5 回饋迴路 SOP（N-3、N-4）。
4. M2-T11 註明 System.Memory redirect 僅適用 net48/netstandard2.0 消費路徑（N-2）。

## Citations

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://tomodahinata.com/en/blog/password-hashing-argon2-encryption-key-management-applied-cryptography-guide
- https://toolsana.com/blog/password-hashing-2026-bcrypt-argon2-scrypt-pbkdf2-guide/
- https://pmc.ncbi.nlm.nih.gov/articles/PMC12664386/table/tbl0010/
- https://github.com/OWASP/ASVS/issues/2535
- https://docs.rs/argon2/latest/argon2/
- https://www.cnblogs.com/pcat/p/11507594.html
- https://medium.com/@felixtwoli21/why-developers-should-stop-hashing-passwords-and-start-using-kdfs-0be0da663393
- https://www.inkyvoxel.com/password-hashing-in-2026/
- https://argon2-cffi.readthedocs.io/_/downloads/en/16.0.0/pdf/
- https://datatracker.ietf.org/doc/html/rfc9106
- https://arxiv.org/html/2504.17121v2
- https://dev.to/gabrielanhaia/argon2id-is-the-default-now-stop-using-bcrypt-in-2026-1g50
- https://nextool.app/blog/password-security-best-practices.html
- https://www.npmjs.com/package/@node-rs/argon2
- https://www.php.net/manual/en/function.password-hash.php
- https://github.com/kmaragon/Konscious.Security.Cryptography
- https://github.com/kmaragon/Konscious.Security.Cryptography/blob/master/Konscious.Security.Cryptography.Argon2/Konscious.Security.Cryptography.Argon2.csproj
- https://wiki.php.net/rfc/argon2_password_hash
- https://wiki.linux.se/index.php/sodium_crypto_pwhash()
- https://fossies.org/dox/libsodium-1.0.21-RELEASE/crypto__pwhash__argon2id_8h.html
- https://stackoverflow.com/questions/47602044/how-do-i-use-the-argon2-algorithm-with-password-hash
- https://www.php.net/manual/ja/function.openssl-password-hash.php
- https://libsodium.gitbook.io/doc/password_hashing/default_phf
- https://github.com/java-crypto/cross_platform_crypto/blob/main/docs/argon2_parameter.md
- https://nuget.rza.ru/packages/konscious.security.cryptography.argon2/1.1.1
- https://www.php.net/function.openssl-password-hash.php
- https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/
- https://cloud.tencent.com/developer/ask/sof/105550587
- https://github.com/kmaragon/Konscious.Security.Cryptography/issues/30
