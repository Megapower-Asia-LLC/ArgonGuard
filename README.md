# ArgonGuard

OWASP-compliant, cross-language **Argon2id** password hashing components.

一套跨語言（.NET／Node.js／Python／PHP）互通的密碼雜湊元件：同一份語言中立規格、同一批凍結測試向量，四種語言實作彼此可驗證對方產生的雜湊。核心演算法固定 **Argon2id**（RFC 9106），參數政策完全符合 **OWASP Password Storage Cheat Sheet**。

> 狀態：開發中（M0 骨架階段）。設計與實作計畫皆已完成外部審核共識，見 `docs/`。

## Repo 佈局

```
spec/       語言中立規格（SPEC.md）、機器可讀權威 artifact、凍結測試向量（M1）
dotnet/     ArgonGuard.Passwords（NuGet）— .NET 參考實作
node/       @argonguard/passwords（npm）
python/     argonguard-passwords（PyPI）
php/        argonguard/passwords（Packagist）
docs/
├── specs/      共識版設計文件（SOT）
├── plans/      實作計畫（master plan）
├── adr/        架構決策紀錄
├── reviews/    Perplexity 審核紀錄（設計三輪＋計畫兩輪）
└── ops/        命名/發佈/營運手冊
.github/workflows/   per-language CI＋（M1 起）守門不變式＋（M3 起）跨語言矩陣
```

## 核心設計（摘要）

- **儲存格式**：標準 PHC string format `$argon2id$v=19$m=…,t=…,p=1$<salt>$<hash>`
- **強度檔位**：`default`（19 MiB/2/1，OWASP 最低建議）／`high`（64 MiB）／`highest`（128 MiB）；公開 API 無任何數字參數
- **驗證政策**：OWASP frontier 凍結常數表（地板）＋天花板（DoS 防護）；verify `false` 只代表密碼不符，其餘一律 typed error
- **三核心介面**：`hashPassword`／`verifyPassword`／`needsRehash`（登入後平滑升級）
- **Legacy 擴充點**：建構時注入舊格式 verifier（bcrypt 等），核心絕不產生非 Argon2id 雜湊

完整設計：`docs/specs/2026-07-05-argonguard-design.md`。

## 開發

各語言目錄內：

```bash
# .NET
cd dotnet && dotnet test

# Node
cd node && npm ci && npm test

# Python
cd python && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest

# PHP
cd php && composer install && composer test
```

## License

MIT
