/**
 * @argonguard/passwords-edge — ArgonGuard edge/WASM 平台套件（Cloudflare Workers /
 * Vercel Edge / 瀏覽器）。規格層委由 @argonguard/core，引擎為 argon2id（純 WASM）、
 * CSPRNG／constant-time 為 Web Crypto。產出與四語言 bit-identical。
 *
 * WASM 靜態 import（wrangler `[[rules]] type="CompiledWasm"` → WebAssembly.Module）→
 * WebAssembly.instantiate(module)（PPLX：禁 WebAssembly.compile 的 runtime 動態路徑）。
 *
 * 記憶體上限：預設 2048 頁（128 MiB，Cloudflare Workers isolate 上限）。highest 檔位
 * （m=131072）需 2049 頁 → 在 Workers 會拋 UnsupportedEnvironmentError（而非 isolate OOM）；
 * 瀏覽器 / Vercel Edge 等高記憶體環境可經 options.maxWasmPages 調高以啟用 highest。
 */
import simdWasm from "argon2id/dist/simd.wasm";
import nonSimdWasm from "argon2id/dist/no-simd.wasm";
import {
  ArgonGuardCoreHasher,
  webCryptoPrimitives,
  type ArgonGuardProfile,
  type CoreHasherDeps,
  type LegacyPasswordVerifier,
} from "@argonguard/core";
import { createWasmArgon2Provider, WORKERS_MAX_WASM_PAGES, type WasmInstanceLoader } from "./engine/wasmArgon2Provider.js";

// 內建靜態 wasm loaders（workerd/bundler：wrangler CompiledWasm → WebAssembly.Module）
const builtinSimd: WasmInstanceLoader = imp =>
  WebAssembly.instantiate(simdWasm, imp).then(instance => ({ instance, module: simdWasm }));
const builtinNonSimd: WasmInstanceLoader = imp =>
  WebAssembly.instantiate(nonSimdWasm, imp).then(instance => ({ instance, module: nonSimdWasm }));

// 模組作用域 lazy 引擎（PPLX 致命 #1：非 per-request instantiate）。Workers 預設上限。
const defaultEngine = createWasmArgon2Provider(builtinSimd, builtinNonSimd);

/** ArgonGuardPasswordHasher 建構選項（SPEC §6.4 L1）。 */
export interface ArgonGuardPasswordHasherOptions {
  profile?: ArgonGuardProfile;
  legacyVerifiers?: LegacyPasswordVerifier[];
  /** 自訂 wasm loaders（非 wrangler 打包環境，如 Vite / 瀏覽器）。預設用套件內建靜態 import。 */
  wasmLoaders?: { simd: WasmInstanceLoader; nonSimd: WasmInstanceLoader };
  /** WASM 記憶體頁上限。預設 2048（128 MiB Workers-safe，拒 highest 的 OOM）；
   *  瀏覽器 / Vercel Edge 等高記憶體環境可調高（highest 需 ≥2049）以啟用 highest。 */
  maxWasmPages?: number;
}

/**
 * ArgonGuard 密碼雜湊器（edge 平台套件）。公開 API 與語意與四語言 baseline 一致。
 * verifyPassword 回 false 只代表密碼不符；needsRehash 同步。引擎型別不進公開 API（SPEC §8.5）。
 */
export class ArgonGuardPasswordHasher {
  readonly #core: ArgonGuardCoreHasher;

  constructor(options?: ArgonGuardPasswordHasherOptions) {
    // 僅在自訂 loaders / 上限時建 per-instance 引擎，否則用模組共用引擎（wasm 只 setup 一次）
    const engine =
      options?.wasmLoaders || options?.maxWasmPages !== undefined
        ? createWasmArgon2Provider(
            options.wasmLoaders?.simd ?? builtinSimd,
            options.wasmLoaders?.nonSimd ?? builtinNonSimd,
            options.maxWasmPages ?? WORKERS_MAX_WASM_PAGES,
          )
        : defaultEngine;
    const deps: CoreHasherDeps = { engine, crypto: webCryptoPrimitives };
    if (options?.profile !== undefined) deps.profile = options.profile;
    if (options?.legacyVerifiers !== undefined) deps.legacyVerifiers = options.legacyVerifiers;
    this.#core = new ArgonGuardCoreHasher(deps);
  }

  get activeProfile(): ArgonGuardProfile {
    return this.#core.activeProfile;
  }

  hashPassword(password: string): Promise<string> {
    return this.#core.hashPassword(password);
  }

  verifyPassword(password: string, encodedHash: string): Promise<boolean> {
    return this.#core.verifyPassword(password, encodedHash);
  }

  needsRehash(encodedHash: string): boolean {
    return this.#core.needsRehash(encodedHash);
  }
}

export { SPEC_VERSION } from "@argonguard/core";
export type { ArgonGuardProfile, LegacyPasswordVerifier } from "@argonguard/core";
export {
  ArgonGuardError,
  MalformedHashError,
  UnsupportedAlgorithmError,
  PolicyViolationError,
  InvalidInputError,
  UnsupportedEnvironmentError,
} from "@argonguard/core";
// 自訂 wasm loader 的型別（供 options.wasmLoaders）。引擎型別 Argon2Provider 不匯出（SPEC §8.5）。
export type { WasmInstanceLoader } from "./engine/wasmArgon2Provider.js";
