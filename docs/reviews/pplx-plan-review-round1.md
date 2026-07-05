---
title: "ArgonGuard plan review r1"
type: knowledge
status: draft
date_created: 2026-07-05
date_modified: 2026-07-05
project: "PPLX Agent API 整合"
tags:
  - research
pplx_response_id: resp_43d77684-b48e-4860-b482-7d31de7c4477
pplx_endpoint: agent
pplx_model: anthropic/claude-opus-4-8
pplx_preset: 
pplx_task_type: research
pplx_rigour: high
pplx_tokens: 32336
pplx_latency_sec: 169.74
---

# ArgonGuard plan review r1

> [!info]+ PPLX call meta
> Endpoint: agent / Model: anthropic/claude-opus-4-8 / Preset:  / Tokens: 32336 / Latency: 169.74s
> Selection reason: research/high + --prefer-opus → Claude Opus 4-8 + tools (手動 escalation)

## Query

你是資深軟體交付架構師與安全審查員。ArgonGuard 設計文件已達成共識（你 round 3 核准）；你隨後協助拆解了實作任務（M0-M4 milestone 結構）。現在請審核正式的實作計畫（master plan）——它以你的拆解為基礎，加上：M5 對抗式審查與驗證、M6 文件與交付兩個階段（業主指定流程）、分工前提（需業主帳號的外部動作清單化為非阻塞項）、本地環境調整（macOS 開發、net48 走 GitHub Actions Windows runner、M3 三語言以多 agent 平行實作）、以及「master plan＋各 milestone 執行前再展開細部 TDD 任務」的兩層規劃結構。

審核要求：
1. milestone 切分、順序約束與 gate（特別是 M1 向量凍結 gate、M2 參考實作定型、M3d 擋 merge 矩陣）是否正確完整
2. 兩層規劃結構（master plan 共識 → 逐 milestone 細部展開）是否可行、是否有應該在 master 層就鎖定卻遺漏的決策
3. 測試策略與 DoD 是否可驗收、有無漏洞
4. 風險與依賴處理（NuGet reservation、Konscious 停滯、off-by-1024、Aiken 帳號依賴）是否到位
5. M5 對抗式審查與 M6 交付的完成定義是否足夠明確

輸出格式（務必完整輸出到 verdict 為止）：
- 【issues】每項標 BLOCKER / MAJOR / MINOR / NIT＋具體修正建議；無 issue 也要明寫
- 【verdict】唯一結論：「核准」（無 BLOCKER/MAJOR）或「需修改」
- 繁體中文，技術名詞保留英文

====== 實作計畫 master plan ======
# ArgonGuard 實作計畫（Master Plan）

> **For agentic workers:** 本計畫為 milestone 層級 master plan；每個 milestone 執行前依 superpowers:writing-plans 展開細部任務（TDD、頻繁 commit）。SOT：`docs/specs/2026-07-05-argonguard-design.md`（Perplexity 共識版 v3.1）。

**Goal:** 交付符合 OWASP 要求、跨語言（.NET/Node/Python/PHP）互通的 Argon2id 密碼雜湊元件，含凍結測試向量、跨語言互驗 CI 與完整文件。

**Architecture:** spec-first monorepo——語言中立規格與雙獨立來源凍結向量為第一等 artifact；四語言實作共同分層（Phc parser／Policy／internal Engine provider／Api／Errors／Legacy），規格層自寫、密碼學層委外。

**Tech Stack:** .NET（Konscious 1.3.1、xUnit、TFM netstandard2.0+net8.0）、Node（@node-rs/argon2、Vitest、Node 20+）、Python（argon2-cffi 25.1.0、pytest、3.9+）、PHP（原生 password_hash＋sodium fallback、PHPUnit、8.2+）、GitHub Actions。

## Global Constraints（逐字承襲共識設計 v3.1）

- 演算法固定 argon2id、`v=19` 明確輸出、參數序 `m,t,p`、禁 keyid/data、base64 無 padding（驗證端拒 padding）
- 檔位：`default`(19456,2,1)／`high`(65536,2,1)／`highest`(131072,2,1)；salt 16B、tag 32B、全 p=1
- 驗證端：OWASP frontier 凍結表（t=1→47104、t=2→19456、t=3→12288、t=4→9216、t≥5→7168）＋天花板（m≤262144、t≤8、salt≤64B、tag≤128B、字串≤512）
- 密碼輸入 1–1024 bytes、拒空/NUL/unpaired surrogate、不做 NFC
- 五類 typed error＋跨語言 bit-identical reason code；verify false 只代表密碼不符
- 向量凍結：argon2 reference CLI × argon2-cffi 雙獨立來源，ArgonGuard 自家實作不得參與
- 支援地板：.NET Framework 4.6.2／net8.0、Node 20、Python 3.9、PHP 8.2
- 套件名：`ArgonGuard.Passwords`／`@argonguard/passwords`／`argonguard-passwords`／`argonguard/passwords`

## 分工與環境前提

- **技術決策**：與 Perplexity 共識後由 Claude 自決執行；**Aiken 只做業務/產品決策**。
- **需 Aiken 帳號的外部動作**（非開發阻塞，發佈前完成即可）：NuGet prefix reservation（寄 account@nuget.org）、npm org `argonguard` 註冊、PyPI/Packagist 帳號與 trusted publishing 設定。到達對應時點由 Claude 準備好內容清單交 Aiken 執行。
- **本地環境**：macOS 開發；net48 向量測試走 GitHub Actions Windows runner（備援：Tailscale `pc`）；argon2 reference CLI 用 brew、argon2-cffi 用 pip、PHP 用 brew 安裝。
- **執行模式**：inline 逐 milestone 執行；可平行的部分（M3 三語言）以 Workflow 多 agent 平行實作，凍結向量為唯一權威對照。

---

## Milestone 總覽與硬性順序約束

| Milestone | 主題 | 核心 gate（DoD） |
|---|---|---|
| **M0** | Repo 骨架＋外部依賴啟動 | monorepo 結構、四語言可編譯 skeleton、CI 空殼綠、命名依賴清單交 Aiken |
| **M1** | spec＋凍結向量（**最高優先，下游硬 gate**） | SPEC.md normative 完成；五類向量雙來源凍結（PROVENANCE 記錄）；守門 1 不變式 CI 綠；M1 完成前 M2+ 禁寫 conformance 測試 |
| **M2** | .NET 參考實作 | 全凍結向量 conformance 綠（net8.0 Linux＋net48 Windows 雙 TFM）；API 行為定型為三語言對照基準；dev harness 就緒 |
| **M3** | Node／Python／PHP＋跨語言矩陣 | 三實作各自向量 conformance 綠；PHP 雙 provider byte-for-byte 一致；守門 3（4×4 round-trip 矩陣）擋 merge 綠 |
| **M4** | CI 加固＋發佈準備 | 四道守門齊備；Isopoh／sodium-only nightly；版本/tag/發佈 workflow 落地（實際發佈待 Aiken 帳號步驟） |
| **M5** | 對抗式審查與驗證 | 多視角對抗審查（誤用情境、邊界、安全風險）＋端對端實測；發現項全數處置；必要時回 Perplexity 補強 |
| **M6** | 文件與交付 | 完整技術文件與使用說明（設計理念、API、範例、安全注意事項、擴充建議）；最終整理 commit＋push |

**硬性序列**：M1 凍結 gate → M2 → M3（三語言彼此平行）→ M3d 矩陣；M0 內各 task 可平行。
**關鍵風險**（詳見設計 v3.1 與 PPLX 拆解）：NuGet reservation 人工審核（M0 送件、只卡發佈）；Konscious 停滯（Isopoh nightly 對沖）；PHP off-by-1024（常數斷言＋專門測試）。

---

## M0 — Repo 骨架與外部依賴啟動

| Task | 內容 | DoD |
|---|---|---|
| M0-T1 | monorepo 目錄骨架 `spec/ dotnet/ node/ python/ php/ docs/ .github/workflows/`＋README 佈局說明 | 結構符合設計 §5.1；docs/ 含 ADR index |
| M0-T2 | 外部命名依賴清單交 Aiken（NuGet reservation 信件草稿、npm org／PyPI／Packagist 註冊步驟） | `docs/ops/naming.md` 記錄狀態；開發不等回覆 |
| M0-T3 | 四語言可編譯 skeleton＋dummy 測試（xUnit／Vitest／pytest／PHPUnit） | 本地四語言 build+test 綠 |
| M0-T4 | CI 空殼：per-language job matrix＋path filter | push 後全 workflow 綠 |
| M0-T5 | 初始 ADR 落檔：PHC 格式決策、p=1 鎖定、frontier 表（v2→v3 歷程）、引擎選型、單位換算 | `docs/adr/` 每決策一份，可追溯 round 2/3 審核 |

## M1 — spec 層與凍結測試向量

| Task | 內容 | DoD |
|---|---|---|
| M1-T1 | `spec/SPEC.md`：格式／檔位／frontier＋天花板／輸入語意／錯誤與 reason code 全表／API 契約與 dispatch／NeedsRehash／legacy 介面（RFC 2119） | 對照設計 v3.1 逐節覆蓋，無 TBD |
| M1-T2 | 向量產生工具：argon2 reference CLI（brew）路線 | 固定輸入可重現產出；JSON schema（passwordHex normative）定義 |
| M1-T3 | argon2-cffi 獨立產生同批向量＋byte-for-byte 比對 script | 比對綠才凍結；`spec/vectors/v1/PROVENANCE.md` 記錄雙來源與日期 |
| M1-T4 | 凍結五類向量：deterministic／verify（含 t=1 m≥47104、外部合法 PHC）／reject（padding、keyid/data、亂序、>512、$argon2i$、$2b$、逐 reason code）／needs-rehash／input-limits（1024/1025、空、NUL、surrogate、NFC≠NFD、emoji、CJK） | 五檔齊備；frontier×天花板交疊四向量 (7168,5)✓(7167,5)✗(7168,8)✓(7168,9)✗ 在列 |
| M1-T5 | 每檔位 canonical dummy hash 常數（凍結程序中產生） | 三常數凍結入 spec |
| M1-T6 | 守門 1 CI：frontier 表斷言、profile 快照 append-only、default==(19456,2,1) 哨兵 | 破壞不變式＝建置紅燈 |

## M2 — .NET 參考實作（`dotnet/`，模組：Phc／Policy／Engine／Api／Errors／Legacy／Internal）

依賴方向：`Api → Policy → Phc`、`Api → Engine(internal)`；Phc/Policy 純函式可獨測。

| Task | 內容 | DoD |
|---|---|---|
| M2-T1 | 專案設定：TFM `netstandard2.0;net8.0`、Konscious 1.3.1、命名（ArgonGuardPasswordHasher／IArgonGuardPasswordHasher） | 雙 TFM build 綠 |
| M2-T2 | Phc 嚴格 parser＋encoder | 單元測試覆蓋合法/非法全路徑 |
| M2-T3 | Policy：frontier＋天花板＋reason code 對映 | 純函式測試綠、每維度 code 正確 |
| M2-T4 | Internal constant-time polyfill（`#if netstandard2.0`：不提早 return、XOR 累加、NoInlining\|NoOptimization；net8.0 用 FixedTimeEquals） | 雙 TFM 等價測試綠 |
| M2-T5 | Engine/KonsciousProvider raw-bytes 重算 | deterministic 向量重算一致 |
| M2-T6 | Api 三操作（v1 僅同步）＋輸入檢查（throwing UTF8Encoding） | §3.2 dispatch 全行為；input-limits 綠 |
| M2-T7 | Errors 五子類＋Reason；reject.json 逐筆斷言 | 全 reject 向量綠 |
| M2-T8 | Legacy 介面＋建構時不可變注入；bcrypt 範例入 docs | 執行期註冊不可能（API 形狀） |
| M2-T9 | conformance 套件（xUnit）＋CI 雙 TFM job | net8.0 Linux＋net48 Windows 全向量綠 |
| M2-T10 | timing sanity 統計（informative 不擋 merge）＋dev harness（stdin/stdout JSON）＋README（System.Memory redirect） | harness 協議文件化，供 M3 對接 |

## M3 — 三語言實作與跨語言矩陣（M3a/b/c 平行，各語言沿用六模組分層）

**M3a Node**：`@argonguard/passwords`、ESM+CJS、@node-rs/argon2；自寫 PHC 層 vs 原生 `hash()` 交叉比對；async Api（needsRehash 同步）；Vitest conformance＋harness。
**M3b Python**：`argonguard-passwords`（namespace package `argonguard.passwords`）、argon2-cffi 直依；`hash_secret_raw`＋`hmac.compare_digest`；pytest 3.9–3.14 conformance＋harness。
**M3c PHP**：`argonguard/passwords`；能力檢查 fail-fast 絕不降級 bcrypt；standard provider＋sodium fallback（`memlimit=m×1024`、上下界常數斷言、off-by-1024 專門測試）；雙 provider byte-for-byte 一致 job；PHPUnit conformance＋harness。
**M3d 矩陣（守門 3）**：4×4 round-trip workflow（隨機密碼×三檔位互 hash 互驗＋needs-rehash 斷言），含 t=1 與 frontier 邊界跨語言一致；擋 merge。

每語言 DoD：全凍結向量 conformance 綠＋harness 與 M2 協議相容。M3d DoD：16 組合全綠。

## M4 — CI 加固與發佈準備

| Task | 內容 | DoD |
|---|---|---|
| M4-T1 | 供應鏈守門：lockfile pin、Dependabot、引擎升版必過全向量 | 四語言齊備 |
| M4-T2 | Isopoh 備援 conformance nightly＋PHP sodium-only 自編譯 nightly | nightly 綠 |
| M4-T3 | 版本策略落地：tag prefix（spec/v*、dotnet/v*…）觸發 release workflow；`Implements ArgonGuard Spec 1.x` metadata | tag 觸發正確 |
| M4-T4 | 發佈 workflow：NuGet 簽章／npm provenance／PyPI trusted publishing（OIDC）／Packagist subtree split mirror | dry-run 綠；實際發佈待 Aiken 帳號步驟（M0-T2 清單） |
| M4-T5 | 營運手冊：檔位切換 SOP、升級流程 | `docs/ops/` 收錄 |

## M5 — 對抗式審查與驗證（Goal 第三階段收尾）

- 多視角對抗審查（Workflow 多 agent）：誤用情境（錯誤 API 使用、假 async、驗證繞過）、邊界案例（向量未覆蓋的輸入）、安全風險（timing、DoS、降級、解析歧義）、規格與實作漂移。
- 端對端實測：實際跑四語言互驗、破壞性輸入、（可行處）真實框架整合冒煙測試。
- 發現項全數處置（修復或明文接受）；重大議題回 Perplexity 補強討論。
- DoD：對抗審查報告歸檔 `docs/reviews/`；所有 CONFIRMED 項處置完畢；全 CI 綠。

## M6 — 文件與交付（Goal 第四階段）

- 完整技術文件與使用說明：設計理念、四語言 API 文件與使用範例、安全注意事項、遷移指南（legacy verifier）、未來擴充建議（Tokens 產品線、參數演進）。
- 最終整理：CLAUDE.md 更新（build/test 指令）、README 完稿、commit＋push 正式交付。
- DoD：新開發者僅憑 repo 文件可完成四語言接入；repo 推送完成。

---

## 自我審查紀錄

- Spec 覆蓋：設計 v3.1 §1–§7 逐節對映 M0–M6 任務，無缺口（frontier 向量→M1-T4；polyfill→M2-T4；雙 provider→M3c；dummy hash→M1-T5；營運手冊→M4-T5；非目標不產生任務，正確）。
- Placeholder 掃描：無 TBD/TODO；milestone 層級任務皆附 DoD；細部程式碼於各 milestone 執行前依 writing-plans 展開（本文件明載此分層）。
- 一致性：任務中的命名（類別、套件、reason code、向量檔名）與設計 v3.1 逐字一致。

## Search queries triggered

- OWASP Argon2id password storage cheat sheet recommended parameters 2025
- Konscious.Security.Cryptography.Argon2 nuget latest version
- argon2-cffi 25.1.0 pypi
- node-rs argon2 latest version
- PHP sodium argon2 memlimit bytes vs KiB off by 1024
- NuGet package id prefix reservation process
## Output

Facts verified. Now I have enough to conduct the review. Key confirmations: OWASP frontier table matches exactly (t=1→47104, t=2→19456, t=3→12288, t=4→9216, t=5→7168); Konscious uses KiB for MemorySize (relevant to unit conversion ADR); argon2-cffi 25.1.0 exists; @node-rs/argon2 defaults to v=19 (V0x13). Proceeding to review.

---

# ArgonGuard 實作計畫（Master Plan）審核

審核基準：設計 v3.1（round 3 已核准）＋ M0-M4 拆解 ＋ 本次新增 M5/M6、分工前提、本地環境、兩層規劃結構。以下逐審核維度展開。

---

## 【issues】

### A. Milestone 切分、順序約束與 gate（審核要求 1）

**A1. [MINOR] M1 凍結 gate 缺「凍結後不可變更」的封存機制（append-only 保證的執行細節）**
M1-T6 有「profile 快照 append-only」與哨兵，但整個凍結向量集（`spec/vectors/v1/`）本身在 M2/M3 開發過程一旦被發現有錯，如何處置未定義。凍結 gate 的價值在於「下游不能為了讓自己 conformance 綠而偷改向量」。
修正建議：於 M1-T3/T6 明訂——(a) 向量檔加 checksum manifest（SHA-256）並由守門 1 CI 斷言；(b) 若凍結後發現向量錯誤，須走 `v1→v2` 新目錄重凍程序（保留 v1 PROVENANCE），而非原地改。此規則應在 master 層鎖定（見 B 區）。

**A2. [MAJOR] M2「參考實作定型」作為 M3 對照基準，但基準的「定型（freeze）」缺少明確 gate 動作**
DoD 寫「API 行為定型為三語言對照基準」，但沒有一個可驗收的「基準凍結」artifact。M3 三語言平行開發時，若 M2 的 harness 協議或錯誤映射之後又微調，三個平行 agent 會對到浮動基準，產生難以定位的 drift。
修正建議：M2 增列 gate task——產出 `spec/reference/dotnet-baseline.md`（或機器可讀的 golden harness I/O fixture），明訂「M3 啟動時 M2 harness 協議與 reason code 映射進入 freeze，變更須回改 SPEC.md 並觸發 M1 守門」。這是 M2→M3 順序約束的實質內容，目前只有名義 gate。此為 MAJOR，因平行多 agent 是本計畫明確採用的執行模式，浮動基準會放大成本。

**A3. [MINOR] M3d「4×4 round-trip 矩陣」的組合語意需釐清**
「4×4」＝四語言 hash × 四語言 verify＝16 組合，DoD「16 組合全綠」一致，正確。但「隨機密碼×三檔位」＋「t=1 與 frontier 邊界跨語言一致」若對每組合都全展開，實際 job 數遠超 16。
修正建議：明訂矩陣維度定義（16 個 lang-pair × 各自跑固定的密碼/檔位/邊界子集），避免展開細部 TDD 時對「16 組合全綠」的驗收口徑理解不一。NIT 級可接受，但建議在 master 層寫死維度公式。

**A4. [MINOR] M3d 擋 merge 的「隨機密碼」與 CI 可重現性衝突**
round-trip 用隨機密碼提升覆蓋是好的，但擋 merge 的 gate 用非決定性輸入，會造成偶發紅燈（flaky）且失敗不可重現。
修正建議：隨機密碼須以固定 seed 派生（記錄於 log），或隨機案例列為 informative、擋 merge 部分改用凍結的固定密碼集。凍結向量已是唯一權威對照，round-trip 的擋 merge 判準應可重現。

**A5. [NIT] M4 依賴 M3 完成，但 M4-T1（供應鏈守門）與 M4-T3（版本策略）其實無需等 M3d 綠**
順序上可讓 M4-T1/T3 與 M3 部分並行以縮短關鍵路徑。非阻塞，列 NIT。

---

### B. 兩層規劃結構：master 層應鎖定卻遺漏的決策（審核要求 2）

兩層結構（master 共識 → 逐 milestone 展開細部 TDD）本身**可行且合理**，符合 writing-plans 慣例。但「master 層鎖定、細部層不得再議」的決策清單有以下遺漏——這些若留到細部層才定，會造成跨 milestone / 跨 agent 不一致：

**B1. [MAJOR] Cross-language reason code 的「權威枚舉清單」未在 master 層鎖定為單一 SOT artifact**
設計要求「跨語言 bit-identical reason code」，M1-T1 說「錯誤與 reason code 全表」在 SPEC.md。但 M2-T7/M3 各自「逐筆斷言 reject.json」。問題：reason code 字串的**唯一權威來源**是 SPEC.md 散文，還是 `spec/vectors/.../reject.json`？兩者若不一致由誰勝出未定。四個平行 agent 各自解讀散文會產生 code 文字差異（例如 `ERR_PADDING` vs `err_b64_padding`）。
修正建議：master 層鎖定「reason code 權威清單 = `spec/reason-codes.json`（機器可讀，M1 產出並凍結）」，SPEC.md 與各語言測試均引用之；守門 1 CI 斷言四語言實際輸出字串 == 清單。這正是「應在 master 層鎖定卻遺漏」的典型項，故列 MAJOR。

**B2. [MAJOR] 單位換算（KiB vs bytes）的權威定義未在 master 層明文化為常數表**
設計核心風險之一是 off-by-1024（PHP sodium `memlimit=m×1024`）。已驗證 Konscious `MemorySize` 單位為 KiB、argon2-cffi `memory_cost` 為 KiB、PHP password_hash `memory_cost` 為 KiB、但 libsodium `crypto_pwhash` 的 `memlimit` 為 **bytes**。這是四語言中唯一的單位歧異點。M3c 有處理，但 master 層 Global Constraints 只寫參數值（19456 等），未把「各引擎 API 的單位語意對照表」列為鎖定 artifact。
修正建議：master 層新增「引擎單位對照表」ADR（M0-T5 已列「單位換算」ADR，需補強其內容為：每個 provider 的 memory 參數單位 + 換算公式 + 常數斷言值），並讓 M1 凍結 default 檔位在**每個引擎的原生單位**下的期望常數值（例如 sodium 應為 19456×1024=19922944 bytes）。目前 off-by-1024 只在 M3c 用「常數斷言」處理，缺少 spec 層的權威期望值供斷言比對，屬應在 master/M1 鎖定卻下放到實作層。列 MAJOR。

**B3. [MINOR] TFM 地板不一致：Global Constraints 寫「net4.6.2／net8.0」，M2-T1 TFM 寫 `netstandard2.0;net8.0`，環境前提又講「net48 走 Windows runner」**
三處出現 net4.6.2（支援地板）、netstandard2.0（build target）、net48（測試 runner）。技術上 netstandard2.0 可涵蓋 4.6.2+，net48 測試是驗證下限的合理選擇——邏輯自洽，但文件用詞混用易誤導細部展開的 agent。
修正建議：master 層明訂「build TFM = netstandard2.0+net8.0；驗證矩陣 = net48(Windows runner) + net8.0(Linux)；宣稱支援地板 = 4.6.2」三者關係一句話寫清。

**B4. [MINOR] 「密碼輸入 1–1024 bytes」的邊界計數口徑（bytes 而非 chars）跨語言鎖定，但 surrogate/emoji/CJK 的 byte 計數基準（UTF-8）未在 master 層明講**
M1-T4 input-limits 有 1024/1025、surrogate、emoji、CJK，M2-T6 用 throwing UTF8Encoding。但「1024 是 UTF-8 編碼後 bytes」這個口徑須是四語言共識常數（PHP 字串本就是 bytes、Python str 需 encode、JS 需 TextEncoder、.NET 需 GetBytes）。
修正建議：master 層鎖定「長度限制以 UTF-8 編碼後 byte 數計」，並在 M1 向量中以「1024 bytes 恰好由多 byte 字元組成」的案例驗證（不只 ASCII 邊界）。

**B5. [NIT] v1（sync-only）vs 未來 async 的 API 表面在 master 層已隱含（M2「v1 僅同步」、Node「async Api」），但「Node async 而 .NET/Python/PHP sync」的跨語言 API 形狀差異未在 master 層明文對照**
Node 天生 async、其餘 sync 是合理的語言慣例決策，但屬應在 master 層明寫的「刻意的跨語言 API 差異」，以免 M5 對抗審查把它當 drift。列 NIT，建議補一行說明。

---

### C. 測試策略與 DoD 可驗收性（審核要求 3）

**C1. [MAJOR] 「constant-time / timing」測試在整個計畫中全部為 informative（不擋 merge），對一個安全元件而言 DoD 缺少可驗收的正確性下限**
M2-T10 timing sanity「informative 不擋 merge」、M5 才做 timing 風險審查。timing 統計不穩、不宜擋 merge 是對的；但 constant-time **實作正確性**（M2-T4 polyfill：不提早 return、XOR 累加、NoInlining|NoOptimization）目前只有「雙 TFM 等價測試綠」——等價測試驗的是**結果正確**，不是**時間恆定**。整個計畫沒有任何一道 gate 能驗收 constant-time 屬性，只靠 code review + M5 人工審查。
修正建議：把 constant-time 拆成兩層 DoD——(a) **結構性斷言**（可擋 merge）：以測試或 lint 斷言 polyfill 走全長度迴圈、無 early return（例如對 polyfill 做 mutation/property 測試：任意兩等長輸入的比較路徑指令數相同）；(b) 統計 timing（維持 informative）。至少 (a) 應可驗收且擋 merge。列 MAJOR，因這是安全元件的核心屬性卻無驗收 gate。

**C2. [MINOR] 「dev harness 協議」缺少 schema 版本化與相容性測試**
M2-T10 harness 協議文件化供 M3 對接，M3 各語言「harness 與 M2 協議相容」。但沒有一個 harness contract test（給定輸入 JSON → 期望輸出 JSON 的凍結 fixture）讓四語言各自跑。相容靠人工核對協議文件易漂移。
修正建議：M2 產出 `harness-contract.json`（凍結 I/O fixture），四語言 harness 各跑此 contract test 為 DoD 一部分；M3d 矩陣即建構於此之上。

**C3. [MINOR] NeedsRehash 的跨語言語意測試僅在 M3d「needs-rehash 斷言」提及，缺獨立向量**
M1-T4 列 needs-rehash 向量、各語言 conformance 涵蓋，尚可。但「參數低於當前 frontier → true」「等於 → false」「高於 → false」「不同檔位間」的判定表是否四語言 bit-identical，建議在向量層有明確的 truth table 而非僅 round-trip 附帶斷言。列 MINOR。

**C4. [NIT] M0-T3 dummy 測試「本地四語言 build+test 綠」在 macOS 開發但 net48 只能 Windows runner——M0 階段 .NET dummy 的 net48 部分本地無法綠**
需明訂 M0 本地綠只涵蓋 netstandard2.0/net8.0，net48 綠由 CI（Windows runner）判定，否則 DoD 在 macOS 本地不可達。列 NIT（與環境前提一致，只需 DoD 措辭對齊）。

---

### D. 風險與依賴處理（審核要求 4）

**D1. [MINOR] NuGet reservation：處理方向正確（M0 送件、只卡發佈、非開發阻塞），但缺「若 reservation 被拒/延遲」的退路**
`account@nuget.org` 人工審核可能被拒（prefix `ArgonGuard` 若被認定不夠獨特）。目前只有「送件」沒有「被拒怎麼辦」。
修正建議：M0-T2 或 M4 補一句 fallback（改用已擁有的既存 owner prefix，或接受無 reservation 直接以完整 id 發佈）；並確認發佈 workflow 不因無 reservation 而 fail。

**D2. [OK→MINOR] Konscious 停滯以 Isopoh nightly 對沖——已到位，但缺「切換觸發條件」**
M4-T2 有 Isopoh 備援 nightly，屬合理對沖。但「什麼情況下真的從 Konscious 切到 Isopoh」的決策條件（例如 Konscious 出現無法修復的向量不符、或安全公告）未定義，nightly 只是偵測不是決策。
修正建議：M4-T5 營運手冊補「引擎切換決策準則與 SOP」。（切換屬技術決策，依分工由 Claude 自決，正確。）

**D3. [已到位] off-by-1024：M3c 常數斷言＋專門測試＋雙 provider byte-for-byte 一致 job，方向正確。**
唯需搭配 B2 補齊「spec 層期望常數」作為斷言基準，否則斷言的是「自己算的值」而非「權威值」。

**D4. [MINOR] Aiken 帳號依賴清單化為非阻塞——結構正確，但「發佈前完成即可」與 M4 DoD「dry-run 綠」之間，缺一個明確的「發佈 readiness gate」**
M4 到 M6 之間，實際發佈動作（需 Aiken）散落。建議明訂：交付（M6）的 DoD 是否包含「已實際發佈到四個 registry」，還是「dry-run 綠 + 待 Aiken 執行清單」即算完成？目前 M6 DoD 是「repo 推送完成」，暗示**不含實際發佈**。這與 Goal「交付…元件」可能有落差。
修正建議：master 層明訂交付範圍——「本計畫 DoD 為發佈-ready（含 dry-run 綠 + Aiken 清單），實際 registry 發佈為 Aiken 執行的計畫外步驟」，避免驗收時對「交付」定義爭議。列 MINOR。

**D5. [MINOR] argon2 reference CLI（brew）與 argon2-cffi 的「雙獨立來源」實際上可能共用同一 C 參考實作 upstream**
brew 的 argon2 CLI 與 argon2-cffi 都可能綁定 P-H-C `phc-winner-argon2` C library。若如此，兩者並非真正「雙獨立來源」，共同 bug 不會被互驗抓到。
修正建議：M1-T3 PROVENANCE 須記錄兩來源的**底層實作版本**；若確認同源，則「雙來源」的價值降為「雙工具鏈重現性」，應在 PROVENANCE 誠實標註，並考慮補第三來源（如 Node @node-rs 用的 RustCrypto argon2，屬獨立實作）做 spot-check。注意：ArgonGuard 自家實作不得參與凍結（此約束正確保留）。列 MINOR。

---

### E. M5 對抗式審查與 M6 交付的完成定義（審核要求 5）

**E1. [MAJOR] M5 DoD「所有 CONFIRMED 項處置完畢」缺少 severity 分級與「可接受」的決策權歸屬**
M5 允許「修復或明文接受」，但誰有權「接受」一個 CONFIRMED 安全風險？依分工，安全屬技術決策（Claude 自決），但「接受殘餘安全風險」通常需業主知情。且無 severity 分級時，「全數處置」可能被 low 噪音稀釋，或反之被迫修無關緊要項。
修正建議：M5 DoD 明訂——(a) 發現項分 severity（critical/high/medium/low）；(b) critical/high 必須修復不得「接受」；(c) 「明文接受」需記錄理由且 high 以上須 Aiken 知情（業務風險決策）；(d) 對抗審查報告須含「已知限制/殘餘風險」章節。目前 DoD 太寬鬆到不可驗收，列 MAJOR。

**E2. [MINOR] M5「必要時回 Perplexity 補強」是好機制，但「必要」無觸發條件，且回 PPLX 的結果若推翻設計 v3.1（SOT）會衝擊已凍結的 spec/向量**
若 M5 對抗審查發現設計缺陷需改 spec，會觸發 M1 重凍（依 A1 的 v1→v2 程序）。這條回饋路徑未在計畫中畫出。
修正建議：明訂「M5 若導致 normative spec 變更 → 觸發 SPEC 版本升與向量重凍程序 → 相關 conformance 重跑」的迴路，並定義觸發回 PPLX 的條件（例如出現 spec/實作漂移或安全爭議無法內部裁決）。

**E3. [MINOR] M5「真實框架整合冒煙測試（可行處）」措辭過軟，不可驗收**
「可行處」給了無限逃生口。建議至少指定每語言一個代表性整合點（例如 .NET 的 ASP.NET Core Identity custom hasher、PHP 的 password_verify 互通、Node/Python 的最小 web handler）為必做冒煙，其餘為可選。列 MINOR。

**E4. [MINOR] M6 DoD「新開發者僅憑 repo 文件可完成四語言接入」不可客觀驗收**
這是好的意圖但無驗收方法。
修正建議：以「可驗收代理指標」替代——(a) 每語言 quickstart 有可複製貼上並執行的最小範例（CI 中以 doctest/example-test 實跑）；(b) 遷移指南含一個 bcrypt→ArgonGuard 的可執行範例；(c) CLAUDE.md 的 build/test 指令在 CI 上被實際使用（即文件與 CI 同源，防文件腐化）。列 MINOR。

**E5. [NIT] M6 未列「授權 LICENSE、SECURITY.md（漏洞回報流程）、SBOM/供應鏈聲明」**
一個公開發佈的安全元件，交付物通常含 LICENSE、SECURITY.md（responsible disclosure）、以及 M4 供應鏈守門對應的 provenance 聲明。建議 M6 交付清單補齊。列 NIT。

---

### F. 其他（跨維度）

**F1. [NIT] 平行多 agent（M3a/b/c）的「合流順序與衝突邊界」未定義**
三 agent 平行改同一 monorepo，雖各自語言目錄隔離，但共用 `spec/`（唯讀，正確）、`.github/workflows/`（可能衝突）、根 README/CLAUDE.md。建議明訂平行 agent 只寫各自語言目錄，共用檔的變更序列化（由主 agent 收攏），避免 merge 衝突。列 NIT。

**F2. [OK] Global Constraints 的 frontier 表與 OWASP 官方（t=1→47104、t=2→19456、t=3→12288、t=4→9216、t≥5→7168）逐值相符；default/high/highest 檔位與 salt16/tag32/p=1 亦與 OWASP 最小配置一致。** 已外部查證，無 issue。

**F3. [OK] `v=19`(0x13) 為 @node-rs/argon2 預設、argon2-cffi/Konscious 亦支援；「明確輸出 v=19、拒 v=16」的跨語言一致性可達成。** 無 issue。

---

## 【verdict】

# **需修改**

存在 MAJOR 項（無 BLOCKER），須先處理後方可核准。彙整必須處理的 MAJOR：

- **A2** — M2 參考實作缺可驗收的「基準凍結」artifact，浮動基準會放大平行多 agent 的 drift 成本。
- **B1** — reason code 權威清單未在 master 層鎖定為單一機器可讀 SOT，四語言 bit-identical 難保證。
- **B2** — 引擎 memory 單位（KiB vs sodium 的 bytes）對照與 spec 層權威期望常數未鎖定，off-by-1024 的斷言缺權威基準。
- **C1** — constant-time 屬性全計畫無可擋 merge 的驗收 gate（僅 informative timing + 人工審查），對安全元件不足。
- **E1** — M5「所有 CONFIRMED 項處置完畢」缺 severity 分級與殘餘風險接受的決策權歸屬，DoD 不可驗收。

MINOR/NIT（A1、A3、A4、A5、B3、B4、B5、C2、C3、C4、D1、D2、D4、D5、E2、E3、E4、E5、F1）建議一併於各 milestone 細部展開前吸收，其中 A1（向量重凍 v1→v2 程序）與 D5（雙來源是否真獨立）雖列 MINOR，因牽動凍結 gate 的可信度，建議優先處理。

整體評價：milestone 骨架、硬性序列、四道守門與兩層規劃結構**方向正確且與設計 v3.1 高度對齊**；問題集中在「應在 master 層鎖定為單一 SOT 的跨語言一致性 artifact（reason code、單位、基準）」以及「安全屬性與收尾階段（M5/M6）的 DoD 可驗收性」。上述 5 個 MAJOR 修正後，即可核准。

## Citations

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://argon2-cffi.readthedocs.io/en/stable/installation.html
- https://zenn.dev/manase/scraps/b96e58515084bb
- https://argon2-cffi.readthedocs.io/en/stable/api.html
- https://dev.to/gabrielanhaia/argon2id-is-the-default-now-stop-using-bcrypt-in-2026-1g50
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://github.com/kmaragon/Konscious.Security.Cryptography
- https://toolsana.com/blog/password-hashing-2026-bcrypt-argon2-scrypt-pbkdf2-guide/
- https://www.npmjs.com/package/@node-rs/argon2
- https://www.npmjs.com/package/@node-rs/argon2-linux-x64-musl?activeTab=versions
- https://intel.aikido.dev/packages/npm/@node-rs/argon2
- https://github.com/ranisalt/node-argon2/releases
- https://www.npmjs.com/package/@node-rs/argon2-wasm32-wasi
- https://github.com/napi-rs/node-rs
- https://jsr.io/@felix/argon2
- https://www.jsdelivr.com/package/npm/@node-rs/argon2-linux-x64-gnu
