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

版本軸：spec SemVer＝各套件 `SPEC_VERSION`＝metadata `Implements ArgonGuard Spec X.Y`；git tag `dotnet/vX.Y.Z`、`node/vX.Y.Z`、`python/vX.Y.Z`、`spec/vX.Y.Z` 觸發 release workflow；repository variable `PUBLISH_ENABLED=true` 才會真正推送（否則只 pack＋上傳 artifact＝dry-run）。

### Aiken 帳號步驟（發佈前一次性）

| 平台 | 動作 |
|---|---|
| NuGet | 建帳號 → 產 API key → repo secret `NUGET_API_KEY`；（選配）寄 prefix reservation（草稿見 naming.md；被拒不影響發佈） |
| npm | 註冊 org `argonguard` → granular token 或 trusted publisher → repo secret `NPM_TOKEN` |
| PyPI | 建帳號 → 專案 `argonguard-passwords` 設 trusted publisher（指向本 repo `release.yml`，environment 不限）——之後零 token |
| Packagist | 以 GitHub 登入 → 需先建 php subtree 鏡像 repo（`argonguard-php`，composer.json 在根目錄）→ submit |
| GitHub | repo variable `PUBLISH_ENABLED=true` |

### PHP subtree 鏡像（Packagist 根目錄限制）

```bash
git subtree split --prefix=php -b php-mirror
git push git@github.com:Megapower-Asia-LLC/argonguard-php.git php-mirror:main
```
（v1.1 可自動化為 workflow；目前手動或由 Claude 執行。）

## Nightly 守門

- `isopoh-backup-conformance`：.NET 備援引擎對 25 筆 deterministic 向量 raw 重算
- `php-sodium-only-conformance`：PHP sodium fallback provider 全套 conformance（`ARGONGUARD_TEST_FORCE_PROVIDER=sodium`，只允許切 sodium、非降級面；已知限制 SPEC §8.7：非 16B salt 外部雜湊拋 UnsupportedEnvironment）

## 日誌準則（SPEC §8.6）

函式庫本身不寫日誌；應用層只記「驗證成功/失敗＋時間戳」，禁記密碼、salt、hash。
