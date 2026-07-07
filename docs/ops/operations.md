# ArgonGuard 營運手冊（M4-T5）

## 檔位切換 SOP（SHOULD）

1. **先全 fleet 升級函式庫**到包含新檔位常數的版本（前向相容設計使舊版本本來就能驗證新檔位 hash，違反順序不會炸，但遵守可讓 NeedsRehash 行為全程可預測）。
2. 觀察一個發佈週期（登入延遲、錯誤率）。
3. 再把各專案的 active profile 切到新檔位；使用者下次登入成功時 NeedsRehash 自動升級。
4. 禁止修改既有檔位參數——要調整就等 spec MINOR 的新檔位名。

## 引擎切換決策準則（Konscious → Isopoh，ADR 0004）

**觸發條件（任一成立即評估切換）**：
- Konscious 出現凍結向量不符且上游無回應修復
- Konscious 相關安全公告（CVE）
- 新 .NET 版本使 Konscious 無法建置且上游停滯（最後 release 2024-06）

**切換依據**：nightly `isopoh-backup-conformance` 持續綠＝備援隨時可用。
**切換步驟**：Engine/ 內以 IsopohProvider 取代 KonsciousProvider → 全向量 conformance＋4×4 矩陣綠 → 套件 PATCH 發佈（引擎屬 internal，不動公開 API）。
**最壞情況**：兩者皆不可用時，MIT 授權允許 vendor/fork Konscious 原始碼入 repo。

## 發佈 runbook

版本軸：spec SemVer＝各套件 `SPEC_VERSION`＝metadata `Implements ArgonGuard Spec X.Y`；git tag `dotnet/vX.Y.Z`、`node/vX.Y.Z`、`edge/vX.Y.Z`、`python/vX.Y.Z`、`spec/vX.Y.Z` 觸發 `release.yml`（PHP 另走 `php/vX.Y.Z` → `php-mirror.yml`）；repository variable `PUBLISH_ENABLED=true` 才會真正推送（否則只 pack＋上傳 artifact＝dry-run）。**`@argonguard/core` 不發佈**（bundled 進 node/edge，見 [`naming.md`](naming.md)）——無 core tag、無 core release job；但 node/edge 的 release job 會先 build core（bundle + dts rollup 皆需 `core/dist`）。

### Aiken 帳號步驟（發佈前一次性）

> 逐平台的 2026 完整操作（2FA、OIDC/Trusted Publishing 設定、npm 首發 bootstrap、驗證指令）見 [`release-registration.md`](release-registration.md)。下表為速查。

| 平台 | 動作（速查） |
|---|---|
| NuGet | Microsoft 帳號開 2FA → 登入 nuget.org 註冊 username（**大小寫敏感、不可改**）→ 推薦 **Trusted Publishing（OIDC）**：設 policy（owner=`Megapower-Asia-LLC`／repo=`ArgonGuard`／workflow=`release.yml`／env 空）＋補 dotnet job 的 `id-token: write`＋`NuGet/login@v1`（secret `NUGET_USER`）；**或** API key fallback → secret `NUGET_API_KEY`（現有 push 已支援）。首發後 email `account@nuget.org` 申請 `ArgonGuard.*` prefix reservation |
| npm（node＋edge） | 建**免費** org `argonguard`＋帳號 2FA →（classic token 已於 2025-12 廢除）**首發 bootstrap**：OIDC 無法建全新套件名，故 `@argonguard/passwords`、`@argonguard/passwords-edge` 各先手動 `npm publish --access public` 一次（`npm login` 或短期 granular token）→ 之後為兩套件設 Trusted Publisher（repo=`ArgonGuard`／workflow=`release.yml`／Allowed action 勾 `npm publish`）→ steady-state tokenless。token 路徑則設 secret `NPM_TOKEN`（granular、scope 限 `@argonguard`、≤90 天） |
| PyPI | 建帳號＋**強制 2FA** → 設 pending publisher（project=`argonguard-passwords`／owner=`Megapower-Asia-LLC`／repo=`ArgonGuard`／workflow=`release.yml`／env 空）→ **零 token**（勿建 API token，否則停用 PEP 740 attestation） |
| Packagist | GitHub＋Packagist 帳號**都開 MFA** → 建空 public repo `Megapower-Asia-LLC/argonguard-php`（預設分支 `main`）→ 授權 Packagist OAuth app 存取 org → secret `MIRROR_PAT`（fine-grained、對 `argonguard-php` 有 Contents 讀寫）→ 首發後於 packagist.org submit 鏡像 URL |
| GitHub | repo variable `PUBLISH_ENABLED=true`（Settings → Secrets and variables → Actions → Variables）——gate 全平台真正推送 |

### 版本一致性

各套件 manifest 的 `version` 是 `0.1.0-dev` 佔位；`release.yml` 從 tag（如 `dotnet/v1.0.0`）解析版本並注入打包（`-p:Version`／`npm version`／`sed` pyproject），tag 名即發佈版本，不會誤發佔位版。

### PHP subtree 鏡像（Packagist 根目錄限制，已自動化）

`.github/workflows/php-mirror.yml` 於推 `php/v*` tag 時自動把 `php/` subtree split 並 force push 到 `argonguard-php` 鏡像（含同名 tag），Packagist webhook 隨即更新。前置：上表 Packagist 列的 repo＋secret＋`PUBLISH_ENABLED=true`。手動觸發可用 `workflow_dispatch`。

本地手動備援：

```bash
SPLIT=$(git subtree split --prefix=php HEAD)
git push git@github.com:Megapower-Asia-LLC/argonguard-php.git "$SPLIT:main" --force
```

## Nightly 守門

- `isopoh-backup-conformance`：.NET 備援引擎對 25 筆 deterministic 向量 raw 重算
- `php-sodium-only-conformance`：PHP sodium fallback provider 全套 conformance（`ARGONGUARD_TEST_FORCE_PROVIDER=sodium`，只允許切 sodium、非降級面；已知限制 SPEC §8.7：非 16B salt 外部雜湊拋 UnsupportedEnvironment）

## 日誌準則（SPEC §8.6）

函式庫本身不寫日誌；應用層只記「驗證成功/失敗＋時間戳」，禁記密碼、salt、hash。
