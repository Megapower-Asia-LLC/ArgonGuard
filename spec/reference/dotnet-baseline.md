# .NET Reference Implementation Baseline（M2 定型宣告）

**Baseline frozen: 2026-07-06**。本文件 merge 即為 M3 開工 gate。M3 期間變更本文件所載行為必須回改 `spec/SPEC.md` 並通過守門 1——不得只改實作。

.NET 參考實作已通過：全部 77 筆凍結向量 conformance（109 測試綠）＋ `spec/harness-contract.json` 12/12。以下為 SPEC 未逐字寫死、由參考實作定型、三語言必須 bit-identical 跟隨的行為細節。

## 1. Verify / NeedsRehash dispatch 前置：演算法 token 判斷

嚴格 argon2 文法只套用在 `argon2id` 字串上。dispatch 第一步抽出 `$<token>$` 演算法 token：

- token 合法字元＝小寫英數與 `-`；字串非 `$…$…` 形或 token 含非法字元 → token = null
- token == null → （legacy 詢問後）`MalformedHash` / `malformed.not_phc`
- token != "argon2id"（如 `2b`、`argon2i`）→ （legacy 詢問後）`UnsupportedAlgorithm`——**即使其餘部分不符合任何文法**
- token == "argon2id" → 進入嚴格解析，解析失敗才回報 malformed 類 reason

長度預檢（>512 → `malformed.encoded_too_long`）先於 token 判斷。

## 2. 輸入檢查優先序（SPEC §5 的裁決順序）

`well-formed（unpaired surrogate）→ empty → too_long（>1024 UTF-8 bytes）→ contains NUL`

（.NET：throwing UTF8Encoding 在編碼階段攔 surrogate，故天然最先。三語言必須產生相同優先序。）

## 3. 政策檢查順序與 reason 裁決（多重違規時回報第一個命中者）

`missing_version → unsupported_version → keyid_not_allowed → data_not_allowed → p_not_one → t_above_ceiling → m_above_ceiling → below_owasp_frontier → salt_length_out_of_range → tag_length_out_of_range`

## 4. 嚴格文法澄清（SPEC §4 S1–S4 的具體化）

- 數字欄位：僅 `[0-9]`、無正負號、**無前導零**（單獨 `0` 除外）、位數 ≤15；違反 → `malformed.not_phc`
- params 段：前三 token 必須依序 `m=`,`t=`,`p=`；若前三 token 是 m/t/p 的重排 → `malformed.params_out_of_order`，否則 → `malformed.not_phc`；第 4 個起僅允許 `keyid=`／`data=` 前綴 token（→ 政策層拒絕），其他 → `malformed.not_phc`
- base64：RFC 4648 §4 標準字元集、無 `=`、**canonical**（decode 後 re-encode 必須等於原字串，封死 trailing-bit 可鍛性）；長度 mod 4 == 1 → 非法。違反一律 `malformed.bad_base64`
- `v` 段：有 v 時必須是第 3 段（`$alg$v=19$params$…`）且格式 `v=<number>`

## 5. NeedsRehash 精確比對欄位

`version==19 ∧ 無 keyid/data ∧ m ∧ t ∧ p ∧ salt bytes 長度 ∧ tag bytes 長度` 全部等於 active profile 才回 false。

## 6. Harness 協議（spec/harness-contract.json schemaVersion 1）

- stdin 單一 JSON：`{"schemaVersion":1,"commands":[…]}`；stdout 單行 JSON：`{"schemaVersion":1,"results":[…]}`
- ops：`hash{profile,passwordHex}`／`verify{passwordHex,encoded}`／`needsRehash{activeProfile,encoded,legacyRegistered?}`
- 結果：成功 `{"ok":true,"encoded":…}` 或 `{"ok":true,"value":bool}`；typed error `{"ok":false,"error":"<類別名>","reason":"<reason code>"}`（error 名＝五類別名，無 "Exception" 後綴）
- `legacyRegistered:true` ＝註冊一個 `CanHandle = startsWith("$2b$")`、`Verify = false` 的認領器（與向量語意一致）

## 7. 公開 API 形狀（.NET；各語言依 SPEC §3.5 對映）

```csharp
new ArgonGuardPasswordHasher(ArgonGuardProfile profile = Default,
                             IEnumerable<ILegacyPasswordVerifier>? legacyVerifiers = null)
string HashPassword(string password)
bool VerifyPassword(string password, string encodedHash)
bool NeedsRehash(string encodedHash)
// ILegacyPasswordVerifier: bool CanHandle(string), bool Verify(string, string)
// 例外：ArgonGuardException(Reason) 基底 + MalformedHash/UnsupportedAlgorithm/PolicyViolation/InvalidInput/UnsupportedEnvironment
// SpecVersion.Value == "1.0.0"
```
