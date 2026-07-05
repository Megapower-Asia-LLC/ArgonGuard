# ADR 0004：各語言底層引擎選型

**狀態**：Accepted（設計審核 round 3 共識，2026-07-05）

## 原則

規格層自己寫（PHC parser、政策檢查、NeedsRehash——四語言 bit-level 一致）、密碼學層委外給久經驗證的引擎；引擎藏在 internal provider 之後可抽換，不進公開 API。**永不自行實作 Argon2 原語。**

## 決策與理由

| 語言 | 引擎 | 理由 | 備援 |
|---|---|---|---|
| .NET | Konscious.Security.Cryptography.Argon2 1.3.1 | 「純 managed＋原生 net46 資產＋net8.0」唯一交集；raw-bytes API；MIT；7.5M 下載無正確性 issue | Isopoh（nightly conformance，見切換準則） |
| Node | @node-rs/argon2 | 平台覆蓋最完整（Alpine musl／WASM fallback）、無 postinstall、`hashRaw` 支撐向量 | node-argon2；未來 Node ≥24.7 內建 `crypto.argon2` |
| Python | argon2-cffi 25.1.0（直接依賴） | 活躍維護、abi3 wheel、`hash_secret_raw`；不經 passlib（已停維護且 3.13 損壞） | PyNaCl（libsodium） |
| PHP | 原生 `password_hash`（PASSWORD_ARGON2ID） | 零 runtime 依賴；2026 主流發行管道全內建 | ext-sodium fallback（生產路徑需過同一 conformance 向量） |

## 已知風險

Konscious 維護停滯（2024-06 起）。對沖：(a) internal provider 可換；(b) RFC 9106 已凍結，正確實作不過期；(c) 凍結向量常態 CI；(d) MIT 可 vendor/fork。切換觸發準則見營運手冊（M4-T5）。
