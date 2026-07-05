# ArgonGuard for Node.js

OWASP 合規的 **Argon2id** 密碼雜湊元件。Implements **ArgonGuard Spec 1.0.0**（`spec/SPEC.md`；`SPEC_VERSION === "1.0.0"`）。

```bash
npm install @argonguard/passwords
```

- Node.js **>= 20**（需 `String.prototype.isWellFormed()`），ESM／CJS 雙格式，內建 TypeScript 型別
- `hashPassword` / `verifyPassword` 為真背景執行緒 async（引擎 `@node-rs/argon2`，藏在內部 provider 邊界、不進公開 API）；`needsRehash` 同步
- 與 .NET／Python／PHP 實作產出可互換的 PHC 字串（4×4 cross-language round-trip）

> [!IMPORTANT]
> **`verifyPassword` 與 `hashPassword` 回傳 `Promise`，一定要 `await`。** 忘記 `await` 會讓 `if (hasher.verifyPassword(...))` 拿到一個永遠 truthy 的 Promise 物件 → **靜默驗證繞過**（任何密碼都放行）。詳見下方 [Security Notes](#security-notes)，並務必啟用 ESLint `no-floating-promises` / `no-misused-promises`。

## Quickstart

最小登入流程（hash → verify → needsRehash 升級）。這段程式碼有對應的實跑測試 `tests/quickstart-example.test.ts`（文件與 CI 同源、防腐化）。

```ts
import { ArgonGuardPasswordHasher } from "@argonguard/passwords";

const hasher = new ArgonGuardPasswordHasher(); // 預設 default 檔位（m=19456 KiB, t=2, p=1）

// 註冊時：把 PHC 字串存進資料庫（每筆獨立 16-byte CSPRNG salt）
const stored = await hasher.hashPassword(password);

// 登入時：務必 await（見 Security Notes）
if (await hasher.verifyPassword(password, stored)) {
  // needsRehash 是同步的，不要 await
  if (hasher.needsRehash(stored)) {
    await saveToDb(await hasher.hashPassword(password)); // 用現行 active 檔位重新雜湊、寫回
  }
  loginOk();
}
```

`verifyPassword` 回傳 `false` 只有一個意思：**格式合法、政策合規、但密碼不符**。其餘所有情況（格式壞、演算法不支援、參數違反政策、輸入非法）一律是 typed error，絕不會被折疊成 `false`（SPEC V1）。

## API 參考

### 建構子

```ts
new ArgonGuardPasswordHasher(options?: {
  profile?: "default" | "high" | "highest";   // 預設 "default"
  legacyVerifiers?: LegacyPasswordVerifier[];  // 建構時複製為不可變、有序；runtime 無法再註冊（SPEC §6.4 L1）
})
```

- 選項以物件傳入（與 .NET／PHP 的位置引數不同，屬刻意的語言慣例差異，非 drift）。
- `legacyVerifiers` 陣列在建構時被凍結複製；事後修改原陣列不影響 hasher（無 runtime 動態註冊）。
- 未知 `profile`（含 `__proto__` 等原型鏈鍵）→ 拋 `RangeError`（使用錯誤，非 typed error）。
- 唯讀屬性 `hasher.activeProfile` 回傳現行檔位名稱。

### 三核心操作

| 操作 | 簽章 | 說明 |
|---|---|---|
| hash | `hashPassword(password: string): Promise<string>` | active 檔位 ＋ 每筆 fresh 16-byte CSPRNG salt，回 PHC 字串。**async** |
| verify | `verifyPassword(password: string, encodedHash: string): Promise<boolean>` | `false`＝密碼不符（單一語意）；其餘 typed error。constant-time 比對。**async** |
| rehash | `needsRehash(encodedHash: string): boolean` | 只 parse 比對、不做雜湊、無 DoS 面。**同步** |

`needsRehash` 為 `true` 當且僅當該雜湊**不是**用現行 active 檔位的精確參數產生（任一欄位不同即算，包含比 active「更強」的參數——儲存庫收斂到單一參數集，語意同 PHP `password_needs_rehash` 與 argon2-cffi `check_needs_rehash`）。legacy verifier 認領的字串 `needsRehash` 恆為 `true`。

### Profile 列舉

```ts
type ArgonGuardProfile = "default" | "high" | "highest";
```

閉集、每個 spec 版本凍結。公開 API 不暴露任何數字 Argon2 參數，只能選檔位（見 [強度檔位](#強度檔位)）。

### 五 typed error 類別 ＋ `.reason`

全部繼承 `ArgonGuardError`（`extends Error`），皆帶唯讀 `reason: string`——跨語言 bit-identical 的機器可讀 reason code（權威來源 `spec/reason-codes.json`）。錯誤訊息與 reason 都不含密碼、salt、tag。

```ts
import {
  ArgonGuardError,            // 基底類別（.reason）
  MalformedHashError,         // 無法嚴格解析／too long／bad base64／params 順序錯
  UnsupportedAlgorithmError,  // 可解析但非 argon2id、且無 legacy 認領
  PolicyViolationError,       // 合法 argon2id 但參數落在驗證政策之外、且無 legacy 認領
  InvalidInputError,          // 密碼違反輸入規則（SPEC §5）
  UnsupportedEnvironmentError,// 執行環境無法提供 argon2id（Node 為預編譯原生模組，正常不會發生）
} from "@argonguard/passwords";

try {
  await hasher.verifyPassword(pw, stored);
} catch (e) {
  if (e instanceof ArgonGuardError) console.error(e.reason); // 例：policy_violation.below_owasp_frontier
}
```

reason code 範例：`invalid_input.password_empty`、`invalid_input.password_too_long`、`malformed.encoded_too_long`、`malformed.bad_base64`、`policy_violation.below_owasp_frontier`、`unsupported.algorithm`。

### `SPEC_VERSION`

```ts
import { SPEC_VERSION } from "@argonguard/passwords"; // "1.0.0"
```

## 強度檔位

| Profile | m (KiB) | t | p | salt | tag | 說明 |
|---|---|---|---|---|---|---|
| `default` | 19456（19 MiB） | 2 | 1 | 16 B | 32 B | OWASP 等效最低建議（永久哨兵，SPEC §3 P1） |
| `high` | 65536（64 MiB） | 2 | 1 | 16 B | 32 B | |
| `highest` | 131072（128 MiB） | 2 | 1 | 16 B | 32 B | |

**公開 API 無任何數字參數**——你不可能不小心產出低於 OWASP 標準的雜湊。強化只能新增檔位名稱（spec MINOR），既有檔位參數永久凍結（SPEC §3 P2）。產生端一律 ≥ OWASP 等效最低配置；驗證端接受整個 OWASP frontier（地板防降級）＋天花板（防 DoS 竄改）。

## 舊系統遷移（legacy verify-only）

核心**不內建**任何 legacy 演算法，也不會產生非 argon2id 雜湊。只能在建構時注入實作 `LegacyPasswordVerifier` 的有序清單（之後不可變、無 runtime 註冊），第一個 `canHandle()` 認領者裁決：

```ts
interface LegacyPasswordVerifier {
  canHandle(encodedHash: string): boolean;                         // 廉價前綴判斷，不做昂貴運算
  verify(password: string, encodedHash: string): boolean | Promise<boolean>; // 可同步或非同步
}
```

以 bcrypt 舊庫遷移到 argon2id 的完整範例（`bcryptjs` 為純 JS、免原生編譯；`bcrypt.compare` 回 `Promise<boolean>`，正好符合 `verify` 允許回 Promise）：

```ts
import bcrypt from "bcryptjs";
import { ArgonGuardPasswordHasher, type LegacyPasswordVerifier } from "@argonguard/passwords";

const bcryptVerifier: LegacyPasswordVerifier = {
  canHandle: (encoded) => /^\$2[aby]\$/.test(encoded),
  verify: (password, encoded) => bcrypt.compare(password, encoded),
};

// 建構時注入（唯一入口；runtime 無法再註冊）
const hasher = new ArgonGuardPasswordHasher({
  profile: "default",
  legacyVerifiers: [bcryptVerifier],
});

// 登入時：舊的 bcrypt 雜湊由 legacy 驗；成功後 rehash 升級成 argon2id
if (await hasher.verifyPassword(password, storedBcrypt)) {
  if (hasher.needsRehash(storedBcrypt)) {           // legacy 命中的字串恆為 true
    await saveToDb(await hasher.hashPassword(password)); // 收斂到 argon2id
  }
  loginOk();
}
```

登入一次、升級一次，逐步把整個儲存庫收斂到 argon2id，不必強迫使用者改密碼。

> 上述機制（建構時注入 → 第一個認領者裁決 → legacy 命中 `needsRehash` 恆 `true` → 登入後 rehash 升級）有可執行的迴歸測試 `tests/quickstart-example.test.ts`；為免額外依賴，該測試以 Node 內建 `scryptSync` 作為「舊格式」stand-in，驗證的是與上面完全相同的 ArgonGuard API 路徑。

## Security Notes

**（最重要）忘記 `await` = 靜默驗證繞過。** `verifyPassword` 與 `hashPassword` 回傳 `Promise`。若寫成 `if (hasher.verifyPassword(pw, stored)) { ... }`（少了 `await`），`if` 判斷的是一個 Promise 物件——**永遠 truthy**，於是任何密碼都放行。務必：

- 每次呼叫都 `await`（或妥善接上 `.then`／回傳）。
- 啟用 ESLint `@typescript-eslint/no-floating-promises` 與 `@typescript-eslint/no-misused-promises`（後者專門抓「把 Promise 當 boolean 用在條件式」），把這類疏漏在 CI 擋下。
- 反之，`needsRehash` 是**同步**的，回傳 `boolean`，**不要** `await`（`await` 一個非 Promise 值雖無害，但會誤導讀者以為它有 async 成本）。

**輸入長度上限（皆以 UTF-8 bytes 計，跨語言一致）。**

- 密碼 ≤ **1024** UTF-8 bytes（`invalid_input.password_too_long`），非空（`invalid_input.password_empty`），不得含 U+0000（`invalid_input.password_contains_nul`），且須為 well-formed Unicode（unpaired surrogate 拒絕，`invalid_input.password_not_well_formed`）。ArgonGuard **不做** trimming、case folding 或 Unicode 正規化——應用端應在輸入邊界自行正規化到 NFC。
- encoded 雜湊 ≤ **512** UTF-8 bytes，且在**任何解析之前**先檢查（`malformed.encoded_too_long`），封住超長輸入的解析成本。
- 這兩個上限保護的是**單筆值**；HTTP request body 的整體大小限制屬框架層（Express `express.json({ limit })`、Fastify `bodyLimit` 等），ArgonGuard 不涉入。

**其餘（與各語言實作共通）。**

- `verifyPassword` 回 `false` 只代表密碼不符；其餘情況一律 typed error，不會被偽裝成 `false`（SPEC V1）。out-of-policy 的 argon2id（例如 `p>1` 的舊庫）只能透過**顯式註冊**的 legacy verifier 接受，絕非預設。
- 本函式庫**不記錄任何 log**；錯誤訊息與 reason code 都不含密碼、salt、tag（SPEC §7／§8.6）。應用端只應記錄 verify 成功／失敗與時間戳，不要把密碼或雜湊值寫進 log。
- 記憶體清零為 **best-effort、不保證**（documented non-goal，SPEC §8.4）——JS 的 string／Buffer GC 時機不可控。
- ArgonGuard **只做**密碼雜湊與驗證政策層。**rate limiting、MFA、帳號鎖定、暴力破解防護、帳號列舉緩解**都在應用層，ArgonGuard 不代勞（帳號不存在時建議以 `spec/vectors/v1/dummy-hashes.json` 的 canonical dummy hash 跑等時 dummy verify，緩解帳號列舉計時差，SPEC §8.3）。

## 開發

```bash
npm ci
npm run build      # tsup：ESM + CJS + d.ts
npm test           # vitest（含凍結向量 conformance、cross-check、quickstart 範例實跑）
npm run typecheck  # tsc --noEmit
```

harness 啟動指令＝`node/HARNESS_CMD`。

## License

MIT © Megapower Asia LLC
