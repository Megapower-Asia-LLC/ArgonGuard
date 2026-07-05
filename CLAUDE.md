# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案現況

ArgonGuard 是一個規劃中的 .NET 密碼雜湊公用函式庫（greenfield，尚未有任何程式碼）。目前 repo 內只有一份設計文件：

- `docs/寫個符合 OWASP 要求的密碼雜湊公用函式.md` — 本專案的設計規格單一真相來源（SOT）

尚無 build / test / lint 指令可用。建立 .NET 專案骨架（`.csproj`、solution、測試專案）之後，請回頭更新本檔案補上對應指令。

## 設計規格（實作時必須遵守）

以下約束來自設計文件，實作任何程式碼前請先讀完該文件全文：

**核心元件**：`Argon2idPasswordHasher`，統一對外提供三個介面：

- `HashPasswordAsync()` — 產生密碼雜湊
- `VerifyPasswordAsync()` — 驗證密碼
- `NeedsRehash()` — 偵測舊雜湊是否使用較弱參數組，供登入成功後平滑升級（rehash-on-login），不強迫使用者重設密碼

**演算法與參數**：

- 只使用 Argon2id（RFC 9106），基於 `Konscious.Security.Cryptography.Argon2` 套件實作
- OWASP 最低參數為安全基準線，只能往上調、不可往下調：記憶體 ≥ 19 MiB、迭代 ≥ 2、並行度 1
- 以強度檔位管理參數：`Default`（19 MiB / 2 iterations / parallelism 1，對齊 OWASP 最低建議）、`High`（64 MiB）、`Highest`（128 MiB，可視情況增加迭代）

**Salt、Hash 與比對**：

- Salt 每筆密碼獨立隨機產生，用 `RandomNumberGenerator.GetBytes()`，至少 16 bytes；禁止固定常數或從帳號等可預測資料推導
- 雜湊輸出固定長度 32 bytes；密碼字串先轉 UTF-8 bytes 再運算
- 比對一律用 constant-time compare（`CryptographicOperations.FixedTimeEquals`），禁止一般字串或陣列比較

**儲存格式**：自我描述格式 `<param-set-id>$<salt>$<hash>`，驗證時從字串解析出參數代碼與 Salt 重算，不依賴外部設定猜測當初參數。
