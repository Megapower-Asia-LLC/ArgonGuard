# ArgonGuard

OWASP-compliant, cross-language **Argon2id** password hashing components.

一套跨語言（.NET／Node.js／Python／PHP）互通的密碼雜湊元件：同一份語言中立規格、同一批凍結測試向量，四種語言實作彼此可驗證對方產生的雜湊。核心演算法固定 **Argon2id**（RFC 9106），參數政策完全符合 **OWASP Password Storage Cheat Sheet**。

[![guard](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/guard.yml/badge.svg)](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/guard.yml)
[![cross-lang-matrix](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/matrix.yml/badge.svg)](https://github.com/Megapower-Asia-LLC/ArgonGuard/actions/workflows/matrix.yml)

## 為什麼用 ArgonGuard

- **完全符合 OWASP**：產生端一律 ≥ OWASP 等效最低配置；驗證端接受整個 OWASP frontier。公開 API 沒有任何數字參數，你不可能不小心產出低於標準的雜湊。
- **跨語言互通**：`$argon2id$v=19$…` 標準 PHC 格式；.NET 產的雜湊 Node/Python/PHP 都能驗，反之亦然（4×4 矩陣 CI 擋 merge）。
- **升級無痛**：`needsRehash` + 登入後 rehash，逐步把儲存庫收斂到新參數，不必強迫使用者改密碼。
- **舊系統遷移**：建構時注入 legacy verifier（bcrypt 等），核心絕不產生非 Argon2id 雜湊。
- **站在成熟引擎上**：各語言委外給久經驗證的引擎（Konscious／@node-rs/argon2／argon2-cffi／PHP 原生），ArgonGuard 只負責規格層（PHC 解析、政策、格式），從不自行實作密碼學原語。

## 安裝與快速上手

| 語言 | 安裝 | 套件 |
|---|---|---|
| .NET | `dotnet add package ArgonGuard.Passwords` | [`ArgonGuard.Passwords`](dotnet/) |
| Node.js | `npm install @argonguard/passwords` | [`@argonguard/passwords`](node/) |
| Python | `pip install argonguard-passwords` | [`argonguard-passwords`](python/) |
| PHP | `composer require argonguard/passwords` | [`argonguard/passwords`](php/) |

```csharp
// .NET
var hasher = new ArgonGuardPasswordHasher();          // 預設 Default 檔位
string stored = hasher.HashPassword(password);
if (hasher.VerifyPassword(password, stored)) {
    if (hasher.NeedsRehash(stored)) Save(hasher.HashPassword(password));
}
```

```ts
// Node.js —— verifyPassword 是 async，務必 await（見各語言 README 安全注意事項）
const hasher = new ArgonGuardPasswordHasher();
const stored = await hasher.hashPassword(password);
if (await hasher.verifyPassword(password, stored)) {
  if (hasher.needsRehash(stored)) await save(await hasher.hashPassword(password));
}
```

各語言完整用法、遷移範例與安全注意事項見各目錄 README。

## 核心設計（摘要）

- **儲存格式**：標準 PHC `$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<hash-b64>`（no padding）
- **強度檔位**（公開 API 唯一旋鈕）：`default`（19 MiB／2／1，OWASP 最低建議）、`high`（64 MiB）、`highest`（128 MiB），全部 p=1
- **驗證政策**：OWASP frontier 凍結表（地板，防降級）＋天花板（防 DoS 竄改）；salt 每筆 16B CSPRNG、tag 32B、constant-time 比對
- **三核心操作**：`hashPassword` / `verifyPassword` / `needsRehash`；`verifyPassword` 回 `false` 只代表密碼不符，其餘一律 typed error（帶跨語言一致 reason code）

完整 normative 規格見 [`spec/SPEC.md`](spec/SPEC.md)；設計理念與決策見 [`docs/`](docs/)。

## Repo 佈局

```
spec/       語言中立規格（SPEC.md）、權威 artifact（reason-codes/engine-units/harness-contract）、
            凍結測試向量（vectors/v1，三來源凍結）、守門/矩陣工具（tools/）
dotnet/ node/ python/ php/    四語言實作（各含 src/ tests/ tools/harness）
docs/
├── specs/    共識版設計文件（SOT）
├── plans/    實作計畫（master plan）
├── adr/      架構決策紀錄（ADR 0001-0005）
├── reviews/  外部審核紀錄（Perplexity 設計三輪＋計畫兩輪）＋M5 對抗式審查報告
└── ops/      命名/發佈/營運手冊
.github/workflows/  per-language CI、守門 1（spec 不變式）、守門 3（4×4 矩陣）、nightly、release
```

## 開發

```bash
cd dotnet && dotnet test                                              # .NET（net8.0；net48 由 CI Windows runner）
cd node   && npm ci && npm run build && npm test                      # Node
cd python && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest
cd php    && composer install && composer test                        # PHP

python3 spec/tools/guard.py     # 守門 1：spec 不變式
python3 spec/tools/matrix.py    # 守門 3：4×4 跨語言 round-trip（需先 build 各語言 harness）
```

品質保證流程（設計 → 審核共識 → 實作 → 對抗式審查）記錄在 `docs/`；貢獻請先讀 [`SECURITY.md`](SECURITY.md)。

## License

MIT © Megapower Asia LLC
