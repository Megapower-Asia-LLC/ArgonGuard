# ArgonGuard for PHP

OWASP 合規、跨語言互通的 **Argon2id** 密碼雜湊元件；公開 API 無任何數字參數，你不可能不小心產出低於標準的雜湊。Implements **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`；`SpecVersion::VALUE === '1.0.0'`）。

```bash
composer require argonguard/passwords
```

- PHP >= 8.2，**零 runtime Composer 依賴**（`vendor/` 僅供 dev 測試）
- 與 .NET／Node.js／Python 實作產出可互換的 PHC 字串（4×4 跨語言 round-trip CI 擋 merge）
- 委外給 PHP 原生 argon2id 引擎（`password_hash`／`password_verify`），ArgonGuard 只負責規格層（PHC 解析、政策、格式），從不自行實作密碼學原語

## Quickstart

最小登入流程——`hashPassword` → `verifyPassword` →（需要時）`needsRehash` 升級，可直接複製貼上：

```php
use ArgonGuard\Passwords\ArgonGuardPasswordHasher;

$hasher = new ArgonGuardPasswordHasher();               // 預設 Default 檔位（m=19456 KiB, t=2, p=1）

// 註冊：以 active 檔位＋fresh 16-byte CSPRNG salt 產生 PHC 字串，存進資料庫
$stored = $hasher->hashPassword($password);             // 例：$argon2id$v=19$m=19456,t=2,p=1$…（97–98 chars）

// 登入：verifyPassword 回 false 只有一個意思——密碼不符；其餘狀況一律拋 typed error
if ($hasher->verifyPassword($password, $stored)) {
    // 成功登入後才做 rehash 判斷：needsRehash 只 parse 比對、不做任何雜湊
    if ($hasher->needsRehash($stored)) {
        $stored = $hasher->hashPassword($password);      // 參數已升級，回存新雜湊
        save($stored);
    }
    loginOk();
}
```

`needsRehash` 讓你不必強迫使用者改密碼，就能把整個儲存庫逐步收斂到目前的 active 檔位（SPEC §6.1 canonical upgrade flow）。此段程式碼的實跑版本見 `tests/QuickstartExampleTest.php`（文件與 CI 同源，防止範例腐化）。

## API 參考

### 建構子

```php
public function __construct(
    ArgonGuardProfile $profile = ArgonGuardProfile::Default,   // 強度檔位（唯一旋鈕）
    iterable $legacyVerifiers = [],                            // legacy verifier 有序清單；建構時複製為不可變
)
```

- `$profile`：選 `ArgonGuardProfile::Default`／`High`／`Highest`（見下方檔位表）。**公開 API 不接受任何數字參數。**
- `$legacyVerifiers`：舊系統遷移用的 verify-only 擴充點（SPEC §6.4）；建構時複製，之後不可變、無 runtime 註冊。清單內非 `LegacyPasswordVerifier` 實例會拋 `\InvalidArgumentException`。
- 建構期做能力檢查 fail-fast：環境無法提供 argon2id（無原生亦無 sodium）→ 立即拋 `UnsupportedEnvironmentException`，**絕不降級 bcrypt**。

### 三核心操作

```php
public function hashPassword(#[\SensitiveParameter] string $password): string
public function verifyPassword(#[\SensitiveParameter] string $password, string $encodedHash): bool
public function needsRehash(string $encodedHash): bool
```

| 操作 | 回傳 | 語意 |
|---|---|---|
| `hashPassword($password)` | PHC encoded `string` | active 檔位＋fresh 16-byte CSPRNG salt、32-byte tag；每次輸出必不同 |
| `verifyPassword($password, $encoded)` | `bool` | `true`＝密碼相符；`false`＝**格式正確、政策合規但密碼不符**（V1 單一意義）；其餘一律 typed error |
| `needsRehash($encoded)` | `bool` | 只 parse 與比對、**不做任何雜湊**；任一參數（含 salt/tag 長度）不同於 active 檔位即 `true`——包含比 active「更強」的雜湊（收斂到單一參數集） |

PHP 為同步（v1 不做假 async；此為跨語言刻意的形狀差異，非漂移——Node.js 版才是 Promise-based async）。

### profile 列舉

```php
enum ArgonGuardProfile {
    case Default;   // m=19456 KiB (19 MiB), t=2, p=1 —— OWASP 等效最低配置
    case High;      // m=65536 KiB (64 MiB), t=2, p=1
    case Highest;   // m=131072 KiB (128 MiB), t=2, p=1
}
```

### 五 typed error 類別

全部繼承 `ArgonGuardException`（`\RuntimeException` 子類）；`getReason()` 回傳 `spec/reason-codes.json` 的機器可讀 reason code，四語言 bit-identical（SPEC §7）。

| 類別 | 何時拋出 | reason code 範例 |
|---|---|---|
| `MalformedHashException` | 無法以嚴格文法解析／過長／bad base64／參數順序錯 | `malformed.not_phc`、`malformed.bad_base64`、`malformed.encoded_too_long` |
| `UnsupportedAlgorithmException` | 可解析但演算法非 argon2id，且無 legacy verifier 認領 | `unsupported.algorithm` |
| `PolicyViolationException` | 合法 argon2id 但參數落在驗證政策之外，且無人認領 | `policy_violation.below_owasp_frontier`、`policy_violation.p_not_one` |
| `InvalidInputException` | 密碼違反 §5 輸入規則 | `invalid_input.password_empty`、`invalid_input.password_too_long`、`invalid_input.password_contains_nul` |
| `UnsupportedEnvironmentException` | 執行環境無法提供 argon2id（建構期 fail-fast） | `environment.argon2id_unavailable` |

```php
use ArgonGuard\Passwords\PolicyViolationException;

try {
    $hasher->verifyPassword($pw, $legacyStored);
} catch (PolicyViolationException $e) {
    error_log('argonguard reason=' . $e->getReason());   // 只記 reason code，絕不記密碼/salt/tag
}
```

### SPEC_VERSION 常數

```php
use ArgonGuard\Passwords\SpecVersion;

SpecVersion::VALUE;   // '1.0.0'——實作的 ArgonGuard 規格版本（SPEC §9）
```

## 強度檔位表

檔位是公開 API 的**唯一旋鈕**（SPEC §3，閉集、隨 spec 版本凍結）。三檔全部 `p=1`（ADR 0002），差別只在記憶體成本 `m`：

| Profile | m (KiB) | m (MiB) | t | p | 用途 |
|---|---|---|---|---|---|
| `Default` | 19456 | 19 | 2 | 1 | OWASP 等效最低配置；永久哨兵（CI 斷言 `default === m=19456,t=2,p=1`） |
| `High` | 65536 | 64 | 2 | 1 | 較高安全需求 |
| `Highest` | 131072 | 128 | 2 | 1 | 最高安全需求（仍在驗證天花板 256 MiB 內，確保舊 verifier 前向相容） |

**公開 API 無任何數字參數。** 你只選檔位名稱，`m`／`t`／`p`／salt 長度／tag 長度全由規格凍結。這保證：(a) 產生端一律 ≥ OWASP 等效最低配置，不可能不小心產出低於標準的雜湊；(b) 強化參數的方式是新增檔位名稱（spec MINOR），既有檔位參數永不可改（SPEC §3 P2）。

## 舊系統遷移（legacy verifier）

核心不內建任何 legacy 演算法（SPEC §6.4 L3）。要遷移 bcrypt／舊雜湊的既有使用者，於建構時注入一個 `LegacyPasswordVerifier`：

```php
interface LegacyPasswordVerifier {
    public function canHandle(string $encodedHash): bool;                                    // 便宜的前綴測試
    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool;
}
```

完整可執行 bcrypt 範例——建構時注入，登入成功後 rehash 升級到 argon2id：

```php
use ArgonGuard\Passwords\ArgonGuardPasswordHasher;
use ArgonGuard\Passwords\ArgonGuardProfile;
use ArgonGuard\Passwords\Legacy\LegacyPasswordVerifier;

final class BcryptLegacyVerifier implements LegacyPasswordVerifier
{
    public function canHandle(string $encodedHash): bool
    {
        return str_starts_with($encodedHash, '$2y$')
            || str_starts_with($encodedHash, '$2b$')
            || str_starts_with($encodedHash, '$2a$');
    }

    public function verify(#[\SensitiveParameter] string $password, string $encodedHash): bool
    {
        return password_verify($password, $encodedHash);   // 委外給 PHP 原生 bcrypt
    }
}

// 建構時注入（清單即刻複製為不可變；之後無法 runtime 追加）
$hasher = new ArgonGuardPasswordHasher(
    ArgonGuardProfile::Default,
    [new BcryptLegacyVerifier()],
);

// 登入流程：verifyPassword 內部先試 argon2id 核心路徑，非 argon2id 或出政策才問 legacy verifier
if ($hasher->verifyPassword($password, $stored)) {
    // legacy 命中的字串 needsRehash() 恆為 true（SPEC §6.3 N2）→ 這裡一定會升級
    if ($hasher->needsRehash($stored)) {
        $stored = $hasher->hashPassword($password);   // 產生 argon2id，回存
        save($stored);
    }
    loginOk();
}
```

只要每個舊使用者登入一次，儲存庫就逐步收斂到 argon2id；核心**絕不產生**任何非 argon2id 雜湊。此段的實跑版本見 `tests/QuickstartExampleTest.php`。

> 出政策的 argon2id（例如 `p>1` 的舊 argon2 store）只能由**顯式註冊**的 legacy verifier 認領（看得見的 opt-in，永不預設；SPEC §6.2 V2）。

## 引擎選擇（internal provider；不進公開 API）

建構期能力檢查 fail-fast，**絕不降級 bcrypt**：

1. `password_algos()` 有 `argon2id` → **標準 provider**：`password_hash`／`password_verify`（`PASSWORD_ARGON2ID`；`memory_cost` 單位 KiB）
2. 否則有 ext-sodium → **sodium fallback provider**：自寫 parser 解出參數 → `memlimit = m(KiB) × 1024`（bytes；權威 `spec/engine-units.json`）→ `sodium_crypto_pwhash(..., SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13)` raw 重算 → `hash_equals` 常數時間比對
3. 都沒有 → `UnsupportedEnvironmentException`（`environment.argon2id_unavailable`）

`needsRehash` 一律用自寫 spec-layer parser 精確比對，**不用** `password_needs_rehash`（避免 provider 漂移）。

## 安全注意事項（Security Notes）

### PHP byte 語意（SPEC §5 I4）——混語言 fleet 必讀

規格層將密碼定義為 **byte string**。PHP string 本身即 byte string，故 PHP 端**不做**（也無從做）well-formed Unicode 檢查：

- **lone surrogate（WTF-8）與 overlong NUL 在 PHP 端會被當一般 bytes 雜湊**，`hashPassword`／`verifyPassword` 照常運作；而 .NET／Node.js／Python 會**拒絕**同一組輸入（拋 `invalid_input.password_not_well_formed`），因為那些語言以 UTF-16／well-formed 字串語意檢查輸入。
- 這是 **SPEC I4 明文決定的已知設計取捨**（M5 對抗式審查 #6 記錄在案），**非安全降級**——PHP 端仍正確雜湊它收到的每一個 byte，且長度限制 1..1024 一律以 bytes 計（`strlen`）。
- **若你跑的是混語言 fleet**（同一使用者可能在 PHP 節點與 .NET／Node／Python 節點間登入），需知悉此差異：一個含 lone surrogate 的密碼在 PHP 註冊得了，換到 .NET 節點卻會被拒。建議在應用層輸入邊界統一做 well-formed／NFC 正規化（ArgonGuard 依規**不**靜默改寫輸入）。
- 對應地，`il-surrogate` 這類 well-formed 向量在 PHP conformance 依規**跳過**（僅 UTF-16 字串語意的語言適用）。

### 密碼參數已標 `#[\SensitiveParameter]`

`hashPassword`／`verifyPassword`／`LegacyPasswordVerifier::verify` 的 `$password` 參數皆標註 `#[\SensitiveParameter]`，stack trace 與錯誤輸出中會以 `Object(SensitiveParameterValue)` 遮蔽，降低密碼意外進入日誌的風險。

### sodium fallback 的環境限制（SPEC §8.7）

sodium fallback **僅在無原生 argon2id 時啟用**。libsodium `crypto_pwhash` API 只接受 **16-byte salt**——在此降級環境下，驗證一個 salt 長度非 16 bytes 的**外來**雜湊時，實作會拋 `UnsupportedEnvironmentException`（`environment.argon2id_unavailable`），**而非誤回 `false`**（保住 V1 單一意義規則）。ArgonGuard 自身產生的雜湊一律用 16-byte salt，不受影響。主流發行版（Homebrew／apt／官方 Docker）皆為 libargon2-backed，走標準 provider，無此限制。

### 共通安全準則

- **`verifyPassword` 回 `false` 只代表密碼不符**——所有其他狀況（格式錯、政策不合、輸入非法、環境不支援）一律 typed error，絕不被遮蔽成 `false`（SPEC §6.2 V1）。呼叫端別把 exception 攔下來當成登入失敗。
- **錯誤訊息／日誌絕不含密碼、salt、tag**（SPEC §7／§8.6，OWASP Error Handling／Logging CS）。本函式庫**自身不寫任何 log**；應用端只應記錄 verify 成功／失敗與時間戳，且只記 `getReason()` 的 reason code。
- **記憶體清零是 best-effort，不保證**（SPEC §8.4，明列的 non-goal）。PHP 執行期不提供可靠的密碼位元組清除保證。
- **常數時間比對**：tag 比對用 `hash_equals`（SPEC §8.1）；salt 每筆 16-byte CSPRNG（`random_bytes`，SPEC §8.2）。
- **帳號列舉緩解**（informative）：帳號不存在時，建議以 `spec/vectors/v1/dummy-hashes.json` 的 canonical dummy hash 跑等時 dummy verify，緩解帳號存在與否的計時差（SPEC §8.3）。此僅緩解帳號存在性計時，不涵蓋其他側信道。
- **ArgonGuard 只做密碼雜湊**：rate limiting、MFA、帳號鎖定、密碼強度政策等**都不在範圍內**，應用層仍須自行實作。這些是防線的其餘部分，缺一不可。

## 開發

```bash
composer install
composer test                                   # PHPUnit（含凍結向量 conformance、雙 provider off-by-1024 專測、quickstart 範例實跑）
python3 ../spec/tools/run_contract.py -- php tools/harness.php   # harness contract 12/12
```

harness 啟動指令＝`php/HARNESS_CMD`。

## License

MIT © Megapower Asia LLC
