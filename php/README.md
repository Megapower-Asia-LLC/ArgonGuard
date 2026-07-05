# ArgonGuard for PHP

OWASP 合規的 Argon2id 密碼雜湊元件。Implements **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`；`SpecVersion::VALUE === '1.0.0'`）。

- PHP >= 8.2，**零 runtime Composer 依賴**（`vendor/` 僅供 dev 測試）
- 與 .NET／Node.js／Python 實作產出可互換的 PHC 字串（4×4 round-trip）

## 使用

```php
use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\ArgonGuardProfile;

$hasher = new ArgonGuardPasswordHasher();               // 預設 Default 檔位（m=19456 KiB, t=2, p=1）
$encoded = $hasher->hashPassword($password);            // fresh 16-byte CSPRNG salt、32-byte tag
$ok = $hasher->verifyPassword($password, $encoded);     // false 只有一個意思：密碼不符
$stale = $hasher->needsRehash($encoded);                // 只 parse 比對，不做雜湊
```

標準升級流程（rehash-on-login；SPEC §6.1）：

```php
if ($hasher->verifyPassword($pw, $stored)) {
    if ($hasher->needsRehash($stored)) {
        store($hasher->hashPassword($pw));
    }
    loginOk();
}
```

其餘一律 typed error（`ArgonGuardException` 基底、`getReason()` 回傳 `spec/reason-codes.json` 的機器可讀 reason code）：
`MalformedHashException`／`UnsupportedAlgorithmException`／`PolicyViolationException`／`InvalidInputException`／`UnsupportedEnvironmentException`。

## 引擎（internal provider；不進公開 API）

建構期能力檢查 fail-fast，**絕不降級 bcrypt**：

1. `password_algos()` 有 `argon2id` → **標準 provider**：`password_hash`/`password_verify`（`PASSWORD_ARGON2ID`；`memory_cost` 單位 KiB）
2. 否則有 ext-sodium → **sodium fallback provider**：自寫 parser 解出參數 → `memlimit = m(KiB) × 1024`（bytes；權威 `spec/engine-units.json`）→ `sodium_crypto_pwhash(..., SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)` raw 重算 → `hash_equals` 常數時間比對
3. 都沒有 → `UnsupportedEnvironmentException`（`environment.argon2id_unavailable`）

`needsRehash` 一律用自寫 spec-layer parser 精確比對，**不用** `password_needs_rehash`（避免 provider 漂移）。

### 已知邊角（文件註明）

- **PHP string 即 byte string（SPEC §5 I4）**：密碼位元組原樣使用、無 Unicode 正規化；unpaired-surrogate well-formed 檢查不適用於 PHP（僅 UTF-16 字串語意的 .NET/Node 適用），`il-surrogate` 向量依規跳過。長度限制 1..1024 以 bytes 計。
- **sodium fallback 的 salt 限制**：libsodium `crypto_pwhash` API 只接受 16-byte salt；fallback 環境下驗證非 16-byte salt 的外來雜湊會拋 `UnsupportedEnvironmentException`（不會誤回 `false`）。
- **sodium-backed 原生 argon2id**：若 PHP 編譯時無 libargon2、以 sodium 補位提供 `password_hash` 的 argon2id，`password_verify` 僅支援 16-byte salt／32-byte tag。主流發行版（Homebrew／apt／官方 Docker）皆為 libargon2-backed，無此限制。

## Legacy 驗證擴充點（verify-only；SPEC §6.4）

核心不內建任何 legacy 演算法。只能在建構時注入有序清單（之後不可變、無 runtime 註冊）；第一個 `canHandle()` 認領者裁決。bcrypt 完整範例：

```php
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;

final class BcryptLegacyVerifier implements LegacyPasswordVerifier
{
    public function canHandle(string $encodedHash): bool
    {
        return str_starts_with($encodedHash, '$2y$') || str_starts_with($encodedHash, '$2b$');
    }

    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        return password_verify($password, $encodedHash);
    }
}

$hasher = new ArgonGuardPasswordHasher(ArgonGuardProfile::Default, [new BcryptLegacyVerifier()]);
```

legacy 命中的字串 `needsRehash()` 恆為 `true` → 走上面的升級流程收斂到 argon2id。

## 安全備註

- 本函式庫**不記錄任何 log**；錯誤訊息不含密碼、salt、tag（SPEC §7/§8.6）。應用端只應記錄 verify 成功/失敗與時間戳。
- 帳號不存在時建議以 `spec/vectors/v1/dummy-hashes.json` 的 canonical dummy hash 跑等時 dummy verify，緩解帳號列舉計時差（SPEC §8.3）。

## 開發

```bash
composer install
composer test                                   # PHPUnit（含凍結向量 conformance、雙 provider off-by-1024 專測）
python3 ../spec/tools/run_contract.py -- php tools/harness.php   # harness contract 12/12
```

harness 啟動指令＝`php/HARNESS_CMD`。
