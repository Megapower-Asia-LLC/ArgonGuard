/**
 * @argonguard/passwords-edge — ArgonGuard edge/WASM 平台套件（Cloudflare Workers /
 * Vercel Edge / 瀏覽器）。規格層委由 @argonguard/core，引擎為 argon2id（純 WASM）、
 * CSPRNG／constant-time 為 Web Crypto。產出與四語言 bit-identical。
 *
 * WASM 靜態 import（wrangler `[[rules]] type="CompiledWasm"` → WebAssembly.Module）→
 * WebAssembly.instantiate(module)（PPLX：禁 WebAssembly.compile 的 runtime 動態路徑）。
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
import { createWasmArgon2Provider } from "./engine/wasmArgon2Provider.js";

// 模組作用域 lazy 引擎（PPLX 致命 #1：非 per-request instantiate）。SIMD 優先、workerd
// 不支援時 argon2id 自動 fallback non-SIMD；兩者輸出 bit-identical（僅速度差異）。
const engine = createWasmArgon2Provider(
  imp => WebAssembly.instantiate(simdWasm, imp).then(instance => ({ instance, module: simdWasm })),
  imp => WebAssembly.instantiate(nonSimdWasm, imp).then(instance => ({ instance, module: nonSimdWasm })),
);

/** ArgonGuardPasswordHasher 建構選項（SPEC §6.4 L1）。 */
export interface ArgonGuardPasswordHasherOptions {
  profile?: ArgonGuardProfile;
  legacyVerifiers?: LegacyPasswordVerifier[];
}

/**
 * ArgonGuard 密碼雜湊器（edge 平台套件）。公開 API 與語意與四語言 baseline 一致。
 * verifyPassword 回 false 只代表密碼不符；needsRehash 同步。
 */
export class ArgonGuardPasswordHasher {
  readonly #core: ArgonGuardCoreHasher;

  constructor(options?: ArgonGuardPasswordHasherOptions) {
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
// 供自訂 wasm loader（非 wrangler 打包環境）
export { createWasmArgon2Provider, type WasmInstanceLoader } from "./engine/wasmArgon2Provider.js";
