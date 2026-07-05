# ArgonGuard for .NET

OWASP 合規的 Argon2id 密碼雜湊元件。Implements **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`；`SpecVersion.Value == "1.0.0"`）。

```bash
dotnet add package ArgonGuard.Passwords
```

- Target framework：`net8.0` 與 `netstandard2.0`（涵蓋 .NET Framework 4.8）
- 引擎委外給 [Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2)（純 managed，無原生相依）
- 與 Node.js／Python／PHP 實作產出可互換的 PHC 字串（4×4 round-trip CI 擋 merge）

## Quickstart

公開 API 只有三個操作：`HashPassword`／`VerifyPassword`／`NeedsRehash`。以下即完整最小登入流程（可直接複製）：

```csharp
using ArgonGuard.Passwords;

var password = "correct horse battery staple";

var hasher = new ArgonGuardPasswordHasher();        // 預設 Default 檔位（m=19456 KiB, t=2, p=1）

// 註冊時：雜湊並存進 DB
string stored = hasher.HashPassword(password);      // 每次新產 16-byte CSPRNG salt、32-byte tag

// 登入時：驗證＋（需要時）就地 rehash 升級
if (hasher.VerifyPassword(password, stored))
{
    if (hasher.NeedsRehash(stored))
        stored = hasher.HashPassword(password);     // 用新參數重雜湊後寫回 DB
    // loginOk();
}
```

`VerifyPassword` 回傳 `false` **只有一個意思**：格式合法、政策合規、但密碼不符（SPEC V1）。其餘任何狀況（格式毀損、非 argon2id、政策違規、輸入非法、環境不支援）一律拋 typed error，絕不折疊成 `false`。

> 這段程式碼是 `tests/ArgonGuard.Passwords.Tests/QuickstartExampleTest.cs` 的可執行副本（doc-as-test），隨 `dotnet test` 一起跑，確保文件不會與實作漂移。

## API 參考

命名空間 `ArgonGuard.Passwords`。

### 建構

```csharp
public ArgonGuardPasswordHasher(
    ArgonGuardProfile profile = ArgonGuardProfile.Default,
    IEnumerable<ILegacyPasswordVerifier>? legacyVerifiers = null);

public ArgonGuardProfile ActiveProfile { get; }     // 現行 active 檔位
```

- `profile`：強度檔位（見下表）。省略即 `Default`。
- `legacyVerifiers`：舊格式 verifier 有序清單，建構時複製為不可變——**runtime 無法再註冊**（SPEC §6.4，API 形狀而非約定）。省略即無 legacy 支援，核心絕不產生非 argon2id 雜湊。

### 三核心操作（介面 `IArgonGuardPasswordHasher`）

```csharp
string HashPassword(string password);                     // active 檔位 ＋ 每次新產 16-byte CSPRNG salt → PHC 字串
bool   VerifyPassword(string password, string encodedHash);
bool   NeedsRehash(string encodedHash);                   // 純 parse 比對，不做任何雜湊
```

- `HashPassword` 回傳標準 PHC 字串 `$argon2id$v=19$m=<m>,t=<t>,p=1$<salt-b64>$<tag-b64>`（Base64 no padding）。
- `NeedsRehash` 回 `true` iff 雜湊**不是**以現行 active 檔位的精確參數產生（任一欄位不同即 `true`，含比 active 更強者；儲存庫因此收斂到單一參數集）。legacy verifier 認領的字串恆為 `true`（SPEC §6.3 N2）。此操作不做雜湊、無 DoS 面。

### 強度檔位（列舉 `ArgonGuardProfile`）

| 檔位 | m (KiB) | t | p | 說明 |
|---|---|---|---|---|
| `Default` | 19456（19 MiB） | 2 | 1 | OWASP 等效最低配置的 canonical 一組（永久哨兵） |
| `High` | 65536（64 MiB） | 2 | 1 | |
| `Highest` | 131072（128 MiB） | 2 | 1 | |

**公開 API 沒有任何數字參數**——你只能選檔位，不可能不小心產出低於 OWASP 標準的雜湊。加強 = 新增檔位名稱（spec MINOR），既有檔位的參數永久凍結。

### 五類 typed error

全部繼承抽象基底 `ArgonGuardException`，各帶跨語言 bit-identical 的 `Reason`（機器可讀，字串以 `spec/reason-codes.json` 為權威）：

```csharp
public abstract class ArgonGuardException : Exception
{
    public string Reason { get; }   // e.g. "policy_violation.below_owasp_frontier"
}
```

| 例外類別 | 意義 |
|---|---|
| `MalformedHashException` | 無法以嚴格文法解析／超長（>512 UTF-8 bytes）／bad base64／參數順序錯 |
| `UnsupportedAlgorithmException` | 可解析但非 argon2id，且無 legacy verifier 認領 |
| `PolicyViolationException` | 合法 argon2id 但參數落在驗證政策外（低於 OWASP frontier、超天花板、p≠1…），且無人認領 |
| `InvalidInputException` | 密碼輸入違反 §5（空／>1024 bytes／含 NUL／非 well-formed Unicode） |
| `UnsupportedEnvironmentException` | 執行環境無法提供 argon2id（.NET 引擎為純 managed，正常情況不會發生） |

錯誤訊息（`Message`）與 `Reason` **絕不含**密碼、salt、tag（SPEC §7／§8.6）。

### 規格版本常數

```csharp
ArgonGuard.Passwords.SpecVersion.Value    // "1.0.0"
```

## 舊系統遷移（legacy verify-only）

核心不內建任何 legacy 演算法。只能在**建構時**注入有序清單（之後不可變、無 runtime 註冊）；驗證時第一個 `CanHandle()` 認領者裁決。legacy 命中的字串 `NeedsRehash()` 恆為 `true`，配合登入後 rehash 即可把儲存庫逐步收斂到 argon2id，不必強迫使用者改密碼。

.NET 慣例以 [BCrypt.Net-Next](https://www.nuget.org/packages/BCrypt.Net-Next) 驗 bcrypt：

```csharp
using System;
using ArgonGuard.Passwords;
using BCryptNet = BCrypt.Net.BCrypt;

// 1) 實作 LegacyPasswordVerifier：cheap 前綴 CanHandle ＋ Verify
public sealed class BcryptLegacyVerifier : ILegacyPasswordVerifier
{
    public bool CanHandle(string encodedHash) =>
        encodedHash.StartsWith("$2a$", StringComparison.Ordinal) ||
        encodedHash.StartsWith("$2b$", StringComparison.Ordinal) ||
        encodedHash.StartsWith("$2y$", StringComparison.Ordinal);

    public bool Verify(string password, string encodedHash) =>
        BCryptNet.Verify(password, encodedHash);
}

// 2) 建構時注入（不可變有序清單）
var hasher = new ArgonGuardPasswordHasher(
    ArgonGuardProfile.Default,
    new ILegacyPasswordVerifier[] { new BcryptLegacyVerifier() });

// 3) 登入：舊 bcrypt 使用者無痛升級到 argon2id
string stored = storedBcryptHash;                   // DB 內既有的 $2b$… 字串
if (hasher.VerifyPassword(password, stored))        // 由 BcryptLegacyVerifier 認領並裁決
{
    if (hasher.NeedsRehash(stored))                 // legacy 命中 → 恆為 true
        stored = hasher.HashPassword(password);     // 就地升級；寫回 DB
    // loginOk();  下次即以 argon2id 驗證
}
```

> 注入契約與升級機制由 `QuickstartExampleTest.LegacyMigration_*` 鎖住（測試以自足的 stand-in verifier 涵蓋相同的 `ILegacyPasswordVerifier` 形狀，避免 doc-sync 測試引入外部相依）。上例的 bcrypt 換成任何舊格式同理。

## 安全注意事項（Security Notes）

**長度上限與第一道防線。** encoded hash 上限 512 **UTF-8 bytes**，於任何解析**之前**檢查（SPEC §4 C5；超長 → `MalformedHashException`／`malformed.encoded_too_long`）；密碼上限 1024 **UTF-8 bytes**（`InvalidInputException`／`invalid_input.password_too_long`）。這兩道是防 DoS 的地板，但**超長輸入的第一道防線應在傳輸層**：在 ASP.NET Core 以 `MaxRequestBodySize`（或反向代理的 body-size 限制）先擋掉異常大的 request body，避免把 MB 級輸入一路帶到雜湊層才被 O(n) 掃描拒絕（M5 #5）。

**System.Memory binding redirect（僅 .NET Framework 消費路徑）。** 只有 `net48`／`netstandard2.0` 的消費路徑可能需要 `System.Memory` 的 binding redirect；`net8.0` 不需要。若在 .NET Framework 專案遇到 `System.Memory` 版本載入衝突，於 `app.config`／`web.config` 加對應 assembly binding redirect 即可（新式 SDK 專案通常由 `dotnet` build 自動產生）。

**v1 只有同步 API。** `HashPassword`／`VerifyPassword`／`NeedsRehash` 皆同步——v1 刻意不出假 async（不包一層 `Task.FromResult`）。Argon2 是 CPU＋記憶體密集運算，在高併發伺服器上若要避免佔用請求執行緒，請自行以 `Task.Run(() => hasher.VerifyPassword(...))` 卸載到執行緒池。（Node.js 版才有真背景執行緒的 async；跨語言形狀差異是刻意設計，非漂移。）

**`verify false` 的唯一意義。** `VerifyPassword` 回 `false` 僅代表密碼不符；格式毀損、非 argon2id、政策違規、非法輸入一律 typed error，不會被遮蔽成 `false`（SPEC V1）。請據此區分「密碼錯」與「資料/環境有問題」。

**不記 log、不外洩敏感值。** 本函式庫**不記錄任何 log**；其吐出的任何東西（例外訊息、`Reason`）都不含密碼、salt、tag（SPEC §7／§8.6）。應用端記錄時也只應記 verify 成功/失敗與時間戳，切勿把密碼/salt/tag 寫進 log。

**記憶體清零為 best-effort。** 受控環境（GC、字串不可變、記憶體搬移）使敏感位元組的清零**無法保證**，屬已知非目標（SPEC §8.4），不要據此假設密碼絕不殘留於記憶體。

**ArgonGuard 不做的事——仍需應用層防護。** 本元件只負責雜湊/驗證/升級，**不提供** rate limiting、MFA、帳號鎖定、帳號列舉緩解等。這些必須由應用層自行實作（帳號不存在時建議以 `spec/vectors/v1/dummy-hashes.json` 的 canonical dummy hash 跑等時 dummy verify，緩解帳號列舉計時差；SPEC §8.3）。

**輸入正規化（§5）。** 密碼以 UTF-8 位元組計，不 trim、不 case-fold、**不做 Unicode 正規化**（應用端 SHOULD 在輸入邊界正規化為 NFC）；含 U+0000 → `invalid_input.password_contains_nul`；非 well-formed Unicode（unpaired surrogate）以 throwing `UTF8Encoding` 拒絕 → `invalid_input.password_not_well_formed`。混語言 fleet 注意：PHP 端以 byte string 處理、不做 well-formed 檢查，同一 lone-surrogate 密碼在 .NET 會被拒、在 PHP 會原樣雜湊（SPEC §5 I4 明文決定，M5 #6 已知取捨）。

## 引擎（internal provider；不進公開 API）

`Konscious.Security.Cryptography.Argon2` 藏在 internal provider boundary 後，引擎型別不外洩到公開 API（SPEC §8.5）。tag 比對用 constant-time：`net8.0` 走 `CryptographicOperations.FixedTimeEquals`，`netstandard2.0` 走 full-length XOR-accumulate polyfill（`NoInlining｜NoOptimization`、無 early return）。`NeedsRehash` 一律用自寫 spec-layer parser 精確比對，**不**委派引擎的 rehash helper（避免 provider 漂移）。

## 開發

```bash
cd dotnet && dotnet test          # net8.0（本地）；net48 由 CI Windows runner
```

harness 啟動指令＝`dotnet/HARNESS_CMD`（`dotnet run --project dotnet/tools/Harness --no-build`；由 repo 根跑，接 `spec/harness-contract.json` 協議）。

## License

MIT © Megapower Asia LLC
