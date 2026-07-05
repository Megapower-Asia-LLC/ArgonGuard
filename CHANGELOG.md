# Changelog

本檔記錄 ArgonGuard 各語言套件的顯著變更。格式依循 [Keep a Changelog](https://keepachangelog.com/)，版本依循 [SemVer](https://semver.org/)。

各套件版本獨立，但硬規則：套件 MAJOR ⊇ spec MAJOR（見 `docs/plans` Global Constraints）。metadata `Implements ArgonGuard Spec X.Y` 為版本對應的權威來源。

## [1.0.0] — 待發佈

首個公開版本，實作 **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`）。四語言套件同時發佈：`ArgonGuard.Passwords`（NuGet）、`@argonguard/passwords`（npm）、`argonguard-passwords`（PyPI）、`argonguard/passwords`（Packagist）。

### 新增

- **核心**：Argon2id 密碼雜湊，三核心操作 `hashPassword` / `verifyPassword` / `needsRehash`。
- **儲存格式**：標準 PHC string format `$argon2id$v=19$m=<m>,t=<t>,p=1$<salt>$<hash>`（no padding），四語言互通。
- **強度檔位**（公開 API 唯一旋鈕，無數字參數）：`default`（19 MiB／2／1，OWASP 最低建議）、`high`（64 MiB）、`highest`（128 MiB）。
- **驗證政策**：OWASP frontier 凍結表（地板，防降級）＋天花板（防 DoS 竄改）；salt 每筆 16 bytes CSPRNG、tag 32 bytes、constant-time 比對。
- **升級**：`needsRehash` + 登入後 rehash，逐步收斂儲存庫到 active 參數。
- **舊系統遷移**：`LegacyPasswordVerifier` 擴充點（建構時注入不可變清單），核心絕不產生非 Argon2id 雜湊。
- **錯誤**：五類 typed error，跨語言 bit-identical reason code；`verify` 回 `false` 只代表密碼不符。

### 各語言引擎與支援範圍

- .NET：Konscious.Security.Cryptography.Argon2；`netstandard2.0;net8.0`（.NET Framework 4.6.2+ 到 .NET 8）。
- Node.js：@node-rs/argon2；Node ≥ 20；ESM + CJS 雙輸出；`hashPassword`/`verifyPassword` 為 async。
- Python：argon2-cffi；Python ≥ 3.9；`py.typed`；namespace package（`argonguard.passwords`）。
- PHP：原生 `password_hash`（PASSWORD_ARGON2ID）＋ ext-sodium fallback；PHP ≥ 8.2；零 runtime 依賴。

### 安全

- 三來源凍結測試向量（argon2-cffi × RustCrypto 獨立雙實作 + reference CLI 第三重）。
- 對抗式安全審查（M5）通過，發現項全數處置；報告見 `docs/reviews/m5-adversarial-review.md`。
- 完全符合 OWASP Password Storage Cheat Sheet；追溯表見 `spec/SPEC.md` Appendix A。

[1.0.0]: https://github.com/Megapower-Asia-LLC/ArgonGuard/releases
