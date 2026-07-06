# Vector Provenance — v1

**Frozen:** 2026-07-06
**Generator:** `spec/tools/gen_vectors.py`（ArgonGuard 自家實作零參與）

**增補紀錄（append，非修改既有 entry）：**
- 2026-07-06：M5 對抗式審查發現 C5 長度單位跨語言不一致，spec PATCH 釘死「512 UTF-8 bytes」後，於 `reject.json` append 一筆 `rej-too-long-utf8`（非 ASCII 撐爆 byte 長度但 code-point/UTF-16 長度 <512）作迴歸向量。其餘五檔重產後 sha256 byte-identical（既有 entry 零改動），僅 `reject.json` sha 變動；符合 append-only（新增 entry 允許、既有 entry 不改）。

## 來源獨立性揭露（計畫 M1-T4 同源條款）

原計畫的雙來源為 argon2 reference CLI × argon2-cffi。查證發現**兩者同綁 phc-winner-argon2 參考 C 實作**（非彼此獨立）：

| 工具 | 版本 | 底層實作 |
|---|---|---|
| argon2 CLI（Homebrew） | 20190702 | phc-winner-argon2（reference C） |
| argon2-cffi | 25.1.0（argon2-cffi-bindings vendored） | phc-winner-argon2（reference C） |
| **@node-rs/argon2** | **repo 內 spec/tools/package.json 鎖定** | **RustCrypto argon2（獨立實作）** |

依同源條款，凍結規則升級為：

1. **獨立雙實作 gate（每筆必過）**：raw tag 由 argon2-cffi × RustCrypto argon2 分別計算，byte-for-byte 一致才凍結。
2. **encoded 欄位機械回解**：v=19、`m,t,p` 順序、無 padding base64、salt/tag bytes 逐欄驗證（結構驗證，非第二實作）。
3. **reference CLI 第三重交叉比對**：能力範圍內子集（密碼 ≤127 bytes——CLI 密碼緩衝上限；salt 無 NUL）。本次凍結 77 筆中 **36 筆**通過 CLI 比對。
4. **凍結後 PHP 抽驗**（第四路徑，非凍結條件）：`password_verify`（libargon2 provider）對全部 25 筆 deterministic 向量驗證通過；`sodium_crypto_pwhash_str_verify`（libsodium 實作）抽驗通過。

## 檔案與規則

- `MANIFEST.sha256`：全部向量檔的 SHA-256，守門 1 CI 斷言。
- 凍結後發現錯誤 → 開 `v2/` 新目錄重凍（保留本目錄與本紀錄），禁止原地修改。
- M3d 跨語言矩陣的固定密碼集 = 本目錄凍結向量子集（不得另立第二份準向量）。
- reject 類中标注 "(crafted)" 的字串為手工構造（政策在重算前拒絕，tag 真實性無關）；argon2i/argon2d 案例由 argon2-cffi 產生（演算法即拒絕理由）。

## Append: engine-raw.json（2026-07-06，Edge/WASM 平台支援）

engine-level raw hash 向量（append-only 新檔，不動既有向量）。補足 deterministic.json 的
覆蓋缺口（PPLX edge 審核 #4）：deterministic.json 為 profile 導向（tagLen 恆 32），本檔測
`provider.hashRaw` 對「非檔位」參數的產出——`tagLen≠32`（64）與低記憶體 edge-safe（`m=4096`，
避免 Miniflare CI OOM，並驗證 edge 引擎於低記憶體下與四語言一致）。

- 產生器：`spec/tools/gen_engine_raw.py`（沿用 `gen_vectors.dual` 的三來源 freeze gate）。
- 3 筆：`eng-taglen64-high`(m=65536,tagLen=64)、`eng-lowmem-edge-safe`(m=4096,t=3,tagLen=32)、
  `eng-lowmem-taglen64`(m=4096,t=3,tagLen=64)。
- 凍結門同 deterministic：argon2-cffi × RustCrypto raw tag byte-for-byte 一致 + encoded 機械回解
  + argon2 CLI 第三重（密碼 "password" ≤127 bytes，全數通過）。
- 額外驗證：`@argonguard/passwords-edge` 的 argon2id（Emscripten C 參考實作，第 5 個獨立引擎）
  對 3 筆全數 bit-identical（edge conformance 測試）。
