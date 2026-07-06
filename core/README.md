# @argonguard/core

ArgonGuard 的**平台無關規格層**（JS/TS 生態）。Implements **ArgonGuard Spec 1.0.0**。

> **這不是給終端使用者的套件。** 要在應用裡雜湊密碼，請裝平台套件：
> [`@argonguard/passwords`](../node)（Node.js）或 [`@argonguard/passwords-edge`](../edge)（Cloudflare Workers／Vercel Edge／瀏覽器）。
> 本套件是它們共用的規格層，只有「要新增一個 JS 平台」時才會直接依賴它。

## 為什麼存在

ArgonGuard 的核心原則（ADR 0004）：規格層自寫、密碼學引擎委外、引擎藏在 provider 之後可抽換。JS/TS 有兩個部署形態——Node.js（原生模組）與 Edge/WASM（Cloudflare Workers 不支援 NAPI／WASI）。為了讓兩者 **bit-identical 互通又不重複維護規格層**，把規格層抽成這個零平台依賴的套件（ADR 0006）：

```
@argonguard/core          規格層（本套件）：PHC parser/encoder、OWASP frontier 政策、
                          needsRehash、input 驗證、base64（RFC 4648 no-pad）、constant-time
                          ＋ Argon2Provider / CryptoPrimitives 兩個注入介面
  ├─ @argonguard/passwords        注入 @node-rs/argon2 + node:crypto
  └─ @argonguard/passwords-edge   注入 argon2id(WASM) + Web Crypto
```

規格層邏輯與 .NET／Python／PHP 逐行對應（同一 `spec/SPEC.md`、同一批凍結向量），四語言的 conformance 就是這層正確性的交叉證明。

## 提供什麼

- **核心 hasher**：`ArgonGuardCoreHasher`（吃注入的 `CoreHasherDeps` = `Argon2Provider` + `CryptoPrimitives`）。平台套件把它 wrap 成只吃 `{ profile, legacyVerifiers }` 的公開建構子——**core 本身不對終端暴露公開 API**。
- **兩個注入介面**：
  - `Argon2Provider`：`hashRaw(password, salt, m, t, p, tagLength): Promise<Uint8Array>`（引擎只回 raw tag，PHC 由規格層組裝）
  - `CryptoPrimitives`：`randomBytes(n)` / `timingSafeEqual(a, b)`；附 `webCryptoPrimitives`（Web Crypto 實作，edge 與現代 Node 通用）
- **規格層工具**（平台套件的 provider／conformance harness 需要，非終端 API）：`parsePhc`／`encodePhc`／`tryGetAlgorithm`、`checkPolicy`、`validatePassword`／`utf8ByteLength`、`profileParameters`、`encodeBase64NoPad`／`decodeCanonicalBase64`、`timingSafeEqual`
- **型別與常數**：`ArgonGuardProfile`、`ProfileParameters`、`LegacyPasswordVerifier`、`ReasonCodes`、`SPEC_VERSION`
- **五 typed error**：`ArgonGuardError` 基底 ＋ `MalformedHashError`／`UnsupportedAlgorithmError`／`PolicyViolationError`／`InvalidInputError`／`UnsupportedEnvironmentError`（`.reason` 為 `spec/reason-codes.json` 的 bit-identical 字串）

## 新增一個 JS 平台的最小步驟

1. 實作 `Argon2Provider.hashRaw`（你的引擎回 raw tag）
2. 提供 `CryptoPrimitives`（多數環境直接用 `webCryptoPrimitives`）
3. `new ArgonGuardCoreHasher({ provider, crypto })`，再 wrap 成公開建構子
4. 跑 `spec/vectors/v1` 全部凍結向量與 harness 契約（守門 3 的 harness）——通過即代表與其他平台 bit-identical

## 開發

```bash
npm ci && npm test          # vitest 對 src
npm run build               # tsup ESM+CJS+DTS（node/edge 依賴此 dist）
npm run typecheck
```

## License

MIT © Megapower Asia LLC
