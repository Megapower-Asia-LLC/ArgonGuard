# ArgonGuard for Edge/WASM

OWASP 合規的 **Argon2id** 密碼雜湊元件，用於 **Cloudflare Workers / Vercel Edge / 瀏覽器** 等純 WebAssembly 環境。Implements **ArgonGuard Spec 1.0.0**，與 .NET／Node／Python／PHP 實作產出 **bit-identical** 互通。

```bash
npm install @argonguard/passwords-edge
```

- 引擎：`argon2id`（純 WASM，Emscripten 編譯自 argon2 參考實作），CSPRNG／constant-time 用 Web Crypto
- `hashPassword` / `verifyPassword` async；`needsRehash` 同步
- 與四語言 + Node 版（`@node-rs/argon2`）產出可互驗（凍結向量 conformance + 真 workerd 驗證）

## Quickstart（Cloudflare Workers）

```ts
import { ArgonGuardPasswordHasher } from "@argonguard/passwords-edge";

const hasher = new ArgonGuardPasswordHasher(); // 預設 default 檔位

export default {
  async fetch(request: Request): Promise<Response> {
    const stored = await hasher.hashPassword("correct horse battery staple");
    const ok = await hasher.verifyPassword("correct horse battery staple", stored);
    return Response.json({ ok });
  },
};
```

`wrangler.toml`（argon2id wasm 靜態 import → 預編譯 `WebAssembly.Module`）：

```toml
[[rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
```

## ⚠️ 記憶體：檔位 vs runtime 上限

argon2id 把 `m` KiB 的 block 放進 WASM 線性記憶體。各檔位所需 WASM 記憶體：

| Profile | m (KiB) | WASM 頁數（64 KiB/頁） | WASM 記憶體 | Cloudflare Workers（128 MiB isolate） |
|---|---|---|---|---|
| `default` | 19456 | 305 | ~19 MiB | ✅ |
| `high` | 65536 | 1025 | ~64 MiB | ✅ |
| `highest` | 131072 | 2049 | ~128.06 MiB | ❌ **超過 128 MiB isolate 上限** |

**`highest` 不相容 Cloudflare Workers**（需 2049 頁 > 2048 頁上限）。本套件預設上限 2048 頁：在 Workers 上以 `highest` 雜湊、或**驗證他平台以 `highest`／高 `m` 產生的雜湊**，會拋 `UnsupportedEnvironmentError`（typed error，而非不透明的 isolate OOM 崩潰）。**Workers 建議用 `high`**（64 MiB）。

高記憶體環境（瀏覽器、Vercel Edge 等）可調高上限以啟用 `highest`：

```ts
// 瀏覽器/Vercel：提高 WASM 頁上限（highest 需 ≥2049）
const hasher = new ArgonGuardPasswordHasher({ profile: "highest", maxWasmPages: 4096 });
```

## 自訂 wasm loader（非 wrangler 打包環境）

wrangler 以 `CompiledWasm` 規則處理 wasm 靜態 import。Vite／自訂打包可傳入 loaders：

```ts
import { ArgonGuardPasswordHasher, type WasmInstanceLoader } from "@argonguard/passwords-edge";

const simd: WasmInstanceLoader = imp => WebAssembly.instantiate(mySimdBytes, imp);
const nonSimd: WasmInstanceLoader = imp => WebAssembly.instantiate(myNonSimdBytes, imp);
const hasher = new ArgonGuardPasswordHasher({ wasmLoaders: { simd, nonSimd } });
```

## API

與四語言 baseline 一致：`hashPassword(password): Promise<string>`、`verifyPassword(password, encoded): Promise<boolean>`（false＝密碼不符，其餘 typed error）、`needsRehash(encoded): boolean`。五 typed error（`ArgonGuardError` 基底 + `MalformedHashError` / `UnsupportedAlgorithmError` / `PolicyViolationError` / `InvalidInputError` / `UnsupportedEnvironmentError`）與 `LegacyPasswordVerifier` 見根 README 與 `spec/SPEC.md`。

## License

MIT © Megapower Asia LLC
