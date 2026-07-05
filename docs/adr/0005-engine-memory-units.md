# ADR 0005：引擎 memory 參數單位對照與換算

**狀態**：Accepted（設計審核 round 2 MAJOR-2 修正共識，2026-07-05）

## 背景

四語言引擎中，memory 參數單位存在唯一歧異點：libsodium 的 `memlimit` 用 **bytes**，其餘全部用 **KiB**。`×1024` 是典型 off-by-1024 錯誤源，必須以權威常數表釘死（Perplexity 計畫審核 round 1 MAJOR B2：斷言「權威值」而非「自己算的值」）。

## 單位對照表（權威，對應 `spec/engine-units.json`）

| 引擎 API | 參數名 | 單位 |
|---|---|---|
| PHC 字串 `m=` | m | KiB |
| .NET Konscious | `MemorySize` | KiB |
| Node @node-rs/argon2 | `memoryCost` | KiB |
| Python argon2-cffi | `memory_cost` | KiB |
| PHP `password_hash` | `memory_cost` | KiB |
| **PHP `sodium_crypto_pwhash`** | **`memlimit`** | **bytes（= m × 1024）** |

## 三檔位在 sodium 原生單位的期望常數（斷言基準）

| Profile | m (KiB) | sodium memlimit (bytes) |
|---|---|---|
| default | 19456 | 19,922,944 |
| high | 65536 | 67,108,864 |
| highest | 131072 | 134,217,728 |

政策域邊界斷言（上下雙向）：frontier 最低 7168 KiB = 7,340,032 bytes ≥ `crypto_pwhash_MEMLIMIT_MIN`；天花板 262144 KiB = 268,435,456 bytes ≤ `crypto_pwhash_MEMLIMIT_MAX`；t∈[1,8] ⊆ [`OPSLIMIT_MIN`, `OPSLIMIT_MAX`]。

## 後果

- `spec/engine-units.json` 於 M1 凍結，為所有換算斷言的唯一權威來源。
- PHP 雙 provider（libargon2 KiB vs sodium bytes）同一 PHC 重算 byte-for-byte 一致為專門 CI job。
