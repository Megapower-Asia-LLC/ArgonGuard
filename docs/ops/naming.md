# 套件命名與外部註冊狀態

品牌：**ArgonGuard**（umbrella brand）；產品線後綴 `Passwords`（未來可延伸 `Tokens` 等）。
名稱可用性查證日：2026-07-05（全部未被占用）。

## 狀態表

| 平台 | 名稱 | 狀態 | 需要的動作（Aiken） |
|---|---|---|---|
| NuGet | `ArgonGuard.Passwords` | 未註冊 | 首次 push 套件即佔名；另建議申請 prefix reservation（見下） |
| npm | `@argonguard/passwords` | scope 未占用 | 於 npmjs.com 註冊 org「argonguard」（免費）；若名稱註冊不到 → fallback `argonguard-passwords` |
| PyPI | `argonguard-passwords` | 未占用 | 建 PyPI 帳號後設定 trusted publishing（OIDC，指向本 repo release workflow）即可，毋須先發佔位版 |
| Packagist | `argonguard/passwords` | vendor 未占用 | 以 GitHub 帳號登入 packagist.org submit 本 repo 的 php subtree mirror（M4 建立後） |

## NuGet prefix reservation 信件草稿（寄 account@nuget.org）

> Subject: Package ID prefix reservation request: ArgonGuard.*
>
> Hello, we would like to reserve the package ID prefix `ArgonGuard.*` for our organization.
> - NuGet.org owner account: （Aiken 的 NuGet 帳號）
> - GitHub organization: https://github.com/Megapower-Asia-LLC
> - Project: https://github.com/Megapower-Asia-LLC/ArgonGuard — an OWASP-compliant, cross-language Argon2id password hashing component. The first package will be `ArgonGuard.Passwords`, with future packages planned under the same prefix (e.g. `ArgonGuard.Tokens`).
> Thank you.

**Fallback（若 reservation 被拒或延遲）**：不影響發佈——直接以完整 id `ArgonGuard.Passwords` 發佈（發佈 workflow 不依賴 reservation），僅少一個 verified 勾勾；日後可再申請。

## 原則

- 這些動作全部**非開發阻塞**：M0–M3 開發不等任何回覆；只有 M4 實際發佈需要帳號就緒。
- 到達 M4 時 Claude 會把每一平台的逐步操作清單整理好交 Aiken 執行。
