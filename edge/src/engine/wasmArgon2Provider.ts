import setupWasm, { type computeHash } from "argon2id/lib/setup.js";
import type { Argon2Provider } from "@argonguard/core";

/** WASM 實例載入器（平台特定）：workerd 傳靜態 import 的 Module，Node 傳 fs.readFileSync 的 bytes。 */
export type WasmInstanceLoader = (
  importObject: WebAssembly.Imports,
) => WebAssembly.WebAssemblyInstantiatedSource | Promise<WebAssembly.WebAssemblyInstantiatedSource>;

/**
 * 以 argon2id（純 WASM）引擎建立 core Argon2Provider。
 *
 * lazy singleton：wasm 只 setup 一次（PPLX 致命 #1——模組作用域 instantiate，非 per-hash，
 * 避免每次雜湊重建 wasm 實例）。argon2id 參數對照 core hashRaw：
 * m→memorySize(KiB)、t→passes、p→parallelism、tagLength→tagLength。
 */
export function createWasmArgon2Provider(getSIMD: WasmInstanceLoader, getNonSIMD: WasmInstanceLoader): Argon2Provider {
  let ready: Promise<computeHash> | null = null;
  const load = (): Promise<computeHash> => (ready ??= setupWasm(getSIMD, getNonSIMD));
  return {
    async hashRaw(password, salt, m, t, p, tagLength): Promise<Uint8Array> {
      const argon2id = await load();
      return argon2id({ password, salt, parallelism: p, passes: t, memorySize: m, tagLength });
    },
  };
}
