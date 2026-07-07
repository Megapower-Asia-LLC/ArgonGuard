# 套件命名與外部註冊狀態

品牌：**ArgonGuard**（umbrella brand）；產品線後綴 `Passwords`（未來可延伸 `Tokens` 等）。
名稱可用性查證日：2026-07-05（全部未被占用）。

## 狀態表（五平台）

| 平台 | 套件名 | 狀態 | 需要的動作（Aiken） |
|---|---|---|---|
| NuGet | `ArgonGuard.Passwords` | 未註冊 | 首次 push 即佔名；建議首發後 email 申請 `ArgonGuard.*` prefix reservation（見下） |
| npm（node） | `@argonguard/passwords` | scope 未占用 | 於 npmjs.com 建免費 org「argonguard」（Unlimited public packages，$0） |
| npm（edge） | `@argonguard/passwords-edge` | scope 未占用 | 同一 org／scope，與 node 共用同一發佈憑證，一併發佈 |
| PyPI | `argonguard-passwords` | 未占用 | 建帳號＋強制 2FA → 設 Trusted Publishing（OIDC 指向 `release.yml`）；用 pending publisher 預註冊名稱 |
| Packagist | `argonguard/passwords` | vendor 未占用 | GitHub 登入 packagist.org，submit php subtree 鏡像 repo `Megapower-Asia-LLC/argonguard-php` |

> **`@argonguard/core`（JS/TS 規格層）不發佈到 npm**（ADR 0006）：透過 tsup `noExternal` 把 runtime 打包進 node/edge 的 `dist`、api-extractor `bundledPackages` 把型別 inline 進 `.d.ts`；套件標 `"private": true` 防誤發。node/edge 消費者零感知，安裝樹只含各自真正的 runtime 依賴（`@node-rs/argon2`／`argon2id`）。逐平台完整操作步驟見 [`release-registration.md`](release-registration.md)。

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
