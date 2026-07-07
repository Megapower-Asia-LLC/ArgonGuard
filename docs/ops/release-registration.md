# ArgonGuard 發佈註冊與申請指南（給 Aiken）

五平台套件的帳號註冊、認證設定與首次發佈逐步操作。**技術面（CI、manifest、依賴、build、型別）Claude 已全部備妥並實證驗證**；本文件只列需要 **Aiken 帳號權限**的一次性步驟。步驟以 2026 當前各套件庫政策為準（Perplexity `-t research -r high` 校對，見 `docs/reviews/`）。

## 全局

| 項目 | 內容 |
|---|---|
| 發佈目標 | NuGet（.NET）／npm ×2（node、edge）／PyPI（Python）／Packagist（PHP） |
| 不發佈 | `@argonguard/core` — bundled 進 node/edge，標 `private`（見 `naming.md`） |
| 總開關 | repo variable **`PUBLISH_ENABLED=true`**；未設時 CI 只 dry-run pack，不推送 |
| 版本來源 | git tag（如 `dotnet/v1.0.0`）覆寫 manifest 的 `0.1.0-dev` 佔位；tag 名即發佈版本 |
| 認證主軸 | NuGet／npm／PyPI 均支援 **OIDC Trusted Publishing（tokenless）**；Packagist 用 `MIRROR_PAT` |

**建議順序**：① 各平台帳號＋認證（一次性）→ ② 設 `PUBLISH_ENABLED=true` → ③ npm 首發 bootstrap（見下）→ ④ 各平台 push tag 發佈 → ⑤ 驗證。

---

## 1 · NuGet（`ArgonGuard.Passwords`）

**帳號**
1. 先在要登入的 Microsoft 帳號（個人 MSA 如 `aiken79@gmail.com`，或工作 Entra `aiken@megapower.asia`）**開啟 2FA**——nuget.org 沒有自己的 2FA，委任 Microsoft 帳號。
2. nuget.org →「Sign in with Microsoft」→ 授權 → 註冊 **username**（⚠️ 大小寫敏感、永久不可改，慎選，如 `MegapowerAsia`）。

**認證（二擇一）**
- **A · Trusted Publishing（推薦，keyless）**：nuget.org → username → **Trusted Publishing** → Add policy：`Repository Owner=Megapower-Asia-LLC`、`Repository=ArgonGuard`、`Workflow File=release.yml`（只檔名，不含路徑）、`Environment=`空。這需要 `release.yml` 的 dotnet job 補 `id-token: write` ＋ `NuGet/login@v1`（告知 Claude 走 OIDC 即代改）＋ repo secret `NUGET_USER`=你的 username。
- **B · API key（fallback，最省事，現有 workflow 直接支援）**：nuget.org → API Keys → Create：`Scope=Push`、`Glob Pattern=ArgonGuard.*`（授權全新 ID 首發）、期限 ≤365 天 → 複製一次（不可回復）→ repo secret **`NUGET_API_KEY`**。無需改 workflow。

**發佈**：`git tag dotnet/v1.0.0 && git push origin dotnet/v1.0.0` → CI 跑 test → pack →（OIDC login →）push。首次 push 全新且唯一的 ID 自動佔名歸屬發佈帳號，無需預註冊。約 <15 分鐘索引完成、寄「successfully published」信。

**首發後（選配）**：email `account@nuget.org` 附上你的 nuget.org owner 顯示名，申請 `ArgonGuard.*` prefix reservation（拿 verified 勾勾；純 email、無自助入口；被拒不影響發佈）。草稿見 `naming.md`。

---

## 2 · npm（`@argonguard/passwords` ＋ `@argonguard/passwords-edge`）

**帳號 ＋ 組織**
1. 建 npm 帳號（建議 `aiken@megapower.asia`）→ 驗證 email → **開 2FA**（TOTP 或 passkey，存 recovery code）。
2. 建 **免費** org **`argonguard`**（選 $0「Unlimited public packages」方案，**不是** $7 私有方案）——保留 `@argonguard` scope，越早越好防搶註。

**首發 bootstrap（一次性，重要）**
npm 的 OIDC／Trusted Publishing **無法建立全新套件名**（[npm/cli#8544](https://github.com/npm/cli/issues/8544)），所以每個套件第一次必須手動發一次：
```bash
# 乾淨 checkout；core 先 build（node/edge 的 bundle 與 dts rollup 都需要）
cd core && npm ci && npm run build
cd ../node && npm ci && npm run build && npm publish --access public
cd ../edge && npm ci && npm run build && npm publish --access public
```
認證用 `npm login`（2 小時 session + OTP）或**短期 granular token**（Read+Write、限 `@argonguard` scope、勾 Bypass 2FA）。（classic automation token 已於 2025-12 廢除。）

**之後 steady-state（tokenless）**
- npmjs.com → 各套件 Settings → **Trusted Publisher**：`org/user=Megapower-Asia-LLC`、`repo=ArgonGuard`、`workflow=release.yml`、Environment 空、**Allowed actions 勾選 `npm publish`**（2026-05 後建立的設定必選；若只留 `npm stage publish`，CI 的 OIDC 發佈會進人工 2FA staging queue，OIDC 無法核准 → 永遠不上線）。
- 設好後**刪掉 bootstrap token**。
- 之後 `git tag node/v1.0.0`（或 `edge/v1.0.0`）→ CI tokenless 發佈、自動 provenance（public repo + `id-token: write`）。

**若偏好 token 路徑（省 bootstrap）**：granular token 可發全新名，設 repo secret **`NPM_TOKEN`**（scope 限 `@argonguard`、≤90 天）→ 首發也能直接走 CI（`release.yml` 的 node/edge job 已含 `NODE_AUTH_TOKEN`）。

---

## 3 · PyPI（`argonguard-passwords`）

**帳號**：pypi.org 註冊 → 驗證 email → **強制 2FA**（2024 起全站強制；TOTP／passkey + recovery code）。

**認證（Trusted Publishing，零 token）**
- pypi.org → Account settings → **Publishing** → Add a **pending publisher**（GitHub 分頁）：`PyPI Project Name=argonguard-passwords`、`Owner=Megapower-Asia-LLC`、`Repository=ArgonGuard`、`Workflow name=release.yml`（只檔名）、`Environment name=`空。
- **不要建任何 API token**（會停用 PEP 740 attestation，且是安全降級）。PyPI 不使用 repo secret。

**發佈**：`git tag python/v1.0.0 && git push origin python/v1.0.0` → CI 做 OIDC 交換 → 上傳正式 PyPI → 自動建 project → pending publisher 自動轉正 → 自動產出並上傳 PEP 740 attestation。名稱 `argonguard-passwords`／`argonguard_passwords`／`ArgonGuard.Passwords` 都正規化為同一名。（選配：先在 test.pypi.org 設對應 pending publisher 演練。）

---

## 4 · Packagist（`argonguard/passwords`）

Packagist 要求 `composer.json` 在 repo 根，但本專案是 monorepo，故 PHP 透過 **subtree split 鏡像 repo** 發佈（`php-mirror.yml` 已自動化）。

**帳號**
1. packagist.org →「Log in with GitHub」（用 Megapower-Asia-LLC 成員／owner 的 GitHub 帳號）。
2. GitHub 帳號**與** Packagist 帳號**都開 MFA**（Packagist 2026 已建議並計畫強制）。
3. 授權 Packagist OAuth app 存取 `Megapower-Asia-LLC` org（GitHub → Settings → Applications），讓它能在鏡像自裝 push webhook。

**一次性設定**
- 建**空的 public repo** `Megapower-Asia-LLC/argonguard-php`（預設分支 `main`——`php-mirror.yml` 推 `refs/heads/main`，Packagist 讀 default 分支的 README）。
- 建 **fine-grained PAT**（scope 限 `argonguard-php`、`Contents: Read and write`）→ ArgonGuard repo secret **`MIRROR_PAT`**（唯一 CI 憑證，Packagist 端無發佈 token）。

**發佈**：`git tag php/v1.0.0 && git push origin php/v1.0.0` → `php-mirror.yml` subtree split → force push 鏡像 + 同名 tag。首次：packagist.org →「Submit」→ 貼 `https://github.com/Megapower-Asia-LLC/argonguard-php` → Check → Submit（建 `argonguard/passwords`、claim vendor `argonguard`）。確認 auto-update webhook 已自裝（否則手動加，Payload URL `https://packagist.org/api/github?username=<USERNAME>`）。
> ⚠️ 2026 起 Packagist.org stable 版本 **immutable**——不可重用版本號修，只能 bump 新版。

---

## 5 · 全平台總開關

repo variable **`PUBLISH_ENABLED=true`**（Settings → Secrets and variables → Actions → **Variables** 分頁）。這道 gate 管所有平台的真正推送；未設時 `release.yml` 與 `php-mirror.yml` 只 dry-run，不外送。

---

## 發佈就緒現況（Claude 已備妥並驗證）

- ✅ 五套件 manifest 完整（LICENSE 六目錄齊備、description／keywords／authors／homepage／urls）。
- ✅ **npm bundled-core 修復**（ADR 0006 Option B）：`@argonguard/core` 移 `devDependencies` + `private`；runtime 由 tsup `noExternal` bundle、型別由 api-extractor `bundledPackages` inline 進 `.d.ts`。實證：`arethetypeswrong` 綠、tarball 依賴乾淨（node=`@node-rs/argon2`、edge=`argon2id`，無 `file:`）、乾淨環境安裝 runtime＋型別皆通過、node 158＋edge 75＋workerd 3 測試全綠。
- ✅ `release.yml`：dotnet／node／**edge**／python 四 job ＋ `edge/v*` 觸發；node/edge job 先 build core。PHP 走 `php-mirror.yml`（`php/v*`）。
- ✅ 版本由 tag 覆寫佔位，不會誤發 `0.1.0-dev`。
- ✅ CI 九條 workflow 全綠。

**尚需 Aiken 的只有上述各平台帳號／token／variable 步驟**——完成後 push 對應 tag 即發佈。
